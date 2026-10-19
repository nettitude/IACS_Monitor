"""
NAT along access paths (NAT tabletop P-02, P-03, P-09).

The access-path walk joins one permitting policy per firewall by
intersecting what each lets through.  NAT changes the addresses between two
firewalls:

* source NAT (FortiOS ``set nat enable`` / an IP pool on the policy, or a
  central SNAT entry): the next firewall sees the translated source - FG-L3
  hides IT behind its inside address, and FG-L2's policy names that address;
* destination NAT on the NEXT firewall (a VIP whose external address is the
  destination so far): its policies name the VIP's mapped address - a VIP
  that points at another firewall's VIP is double NAT.

``NatIndex`` answers both for the walk, and names the VIP a policy publishes
(the policy's own destination is already the mapped address on FortiOS).
The row keeps the ORIGINAL source (accountability: who really connects) and
the FINAL destination; ``row["nat"]`` lists every translation.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.parsers import rule_match as rm

log = logging.getLogger(__name__)


def _ids(text) -> list:
    return [x.strip() for x in str(text or "").split(",") if x.strip()]


def _is_concrete(spec) -> bool:
    return spec is not None and spec != rm.ANY and not isinstance(spec, rm.Unresolved)


class NatIndex:
    def __init__(self):
        self.snat: dict = {}          # (firewall_id, policy_id) -> [entry]
        self.central: dict = {}       # firewall_id -> [entry] (no policy binding)
        self.dnat: dict = {}          # firewall_id -> [entry]
        self.published: dict = {}     # (firewall_id, policy_id) -> [entry]
        self.ext_ips: dict = {}       # VIP external spec text -> entry (P-04)

    @classmethod
    def build(cls, db) -> "NatIndex":
        from app.models import FirewallInterface, NatRule
        idx = cls()
        ips = {}
        for fid, name, ip in db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                                      FirewallInterface.ip_address):
            if ip and name:
                ips[(fid, str(name).strip().lower())] = str(ip).strip()
        for r in db.query(NatRule).filter(NatRule.enabled.is_(True)):
            kind = str(r.nat_type or "").lower()
            if getattr(r, "nat_exempt", False):
                continue
            mapped_text = str(r.mapped_ip or "")
            if mapped_text.startswith("interface:"):
                ip = ips.get((r.firewall_id, mapped_text[10:].strip().lower()))
                mapped_text = ip or ""
            try:
                mapped = rm.parse_address(mapped_text, v6_default_is_any=False) if mapped_text else None
            except Exception:
                mapped = None
            from app.parsers.reachability import _nat_policy_mode
            e = {"row": r, "kind": kind, "mode": _nat_policy_mode(r.device_type), "name": r.name, "firewall_id": r.firewall_id,
                 "firewall": r.device_name, "mapped": mapped, "mapped_text": mapped_text or r.mapped_ip,
                 "policy_ids": _ids(r.policy_id), "vdom": getattr(r, "vdom", None)}
            try:
                e["mapped_ports"] = rm.parse_ports(r.mapped_port)
                e["ext_ports"] = rm.parse_ports(r.ext_port)
                e["ext"] = rm.parse_address(r.ext_ip, v6_default_is_any=False) if r.ext_ip else None
                e["orig_src"] = rm.parse_address(r.orig_src or "any", v6_default_is_any=False)
            except Exception:
                continue
            if kind == "snat":
                if not _is_concrete(mapped):
                    continue
                if e["policy_ids"]:
                    for pid in e["policy_ids"]:
                        idx.snat.setdefault((r.firewall_id, e["vdom"], pid), []).append(e)
                else:
                    idx.central.setdefault(r.firewall_id, []).append(e)
            elif kind == "dnat":
                if not (_is_concrete(e["ext"]) and _is_concrete(mapped)):
                    continue
                idx.dnat.setdefault(r.firewall_id, []).append(e)
                idx.ext_ips[str(r.ext_ip)] = e
                for pid in e["policy_ids"]:
                    idx.published.setdefault((r.firewall_id, e["vdom"], pid), []).append(e)
        return idx

    def __bool__(self):
        return bool(self.snat or self.central or self.dnat)

    # ---- walk hooks
    def apply_snat(self, pol: dict, src):
        """(translated src spec, event) when the policy (or a central SNAT
        entry of its firewall covering ``src``) translates the source."""
        # AU full review C5: policy ids repeat per VDOM (N-24) - key on the VDOM too
        fid, pid = pol.get("firewall_id"), str(pol.get("policy_id") or "")
        for e in self.snat.get((fid, pol.get("vdom"), pid), []):
            return e["mapped"], self._event("snat", e, pol, before=src)
        for e in self.central.get(fid, []):
            if _is_concrete(src) and (e["orig_src"] == rm.ANY or rm.addr_contains(e["orig_src"], src) is True):
                return e["mapped"], self._event("snat", e, pol, before=src)
        return None

    def apply_dnat(self, firewall_id, dst, ports, mode=None):
        """(mapped dst spec, mapped ports, event) when the destination so far
        lies inside one of ``firewall_id``'s VIP external addresses."""
        if not _is_concrete(dst):
            return None
        for e in self.dnat.get(firewall_id, []):
            if mode is not None and e["mode"] != mode:
                continue
            if rm.addr_contains(e["ext"], dst) is not True:
                continue
            new_ports = ports
            if e["ext_ports"] != rm.ANY and not isinstance(e["ext_ports"], rm.Unresolved):
                if ports == rm.ANY:
                    new_ports = e["mapped_ports"]
                elif isinstance(ports, rm.Unresolved):
                    new_ports = ports
                else:
                    inter = rm.ranges_intersect(ports, e["ext_ports"])
                    if not inter:
                        continue
                    new_ports = _shift(inter, e["ext_ports"], e["mapped_ports"])
            return e["mapped"], new_ports, self._event("dnat", e, None, before=dst)
        return None

    def published_by(self, pol: dict) -> list:
        """VIPs the policy itself publishes (its destination is their mapped
        address)."""
        return [self._event("dnat", e, pol, before=e["ext"])
                for e in self.published.get((pol.get("firewall_id"), pol.get("vdom"),
                                             str(pol.get("policy_id") or "")), [])]

    @staticmethod
    def _event(kind, e, pol, before=None) -> dict:
        r = e["row"]
        ev = {"type": kind, "name": r.name, "firewall": r.device_name, "firewall_id": r.firewall_id,
              "nat_rule_id": r.id}
        if kind == "dnat":
            ev.update({"external": r.ext_ip + (f":{r.ext_port}" if r.ext_port and r.ext_port != "any" else ""),
                       "mapped": r.mapped_ip + (f":{r.mapped_port}" if r.mapped_port and r.mapped_port != "any" else "")})
        else:
            ev.update({"translated_to": e["mapped_text"],
                       "policy_id": pol.get("policy_id") if pol else None})
        return ev


def _shift(ranges, frm, to):
    """Map port ranges inside ``frm`` onto ``to`` (offset when both are one
    same-sized range, else ``to``)."""
    if to == rm.ANY or isinstance(to, rm.Unresolved):
        return ranges
    if len(frm) == 1 and len(to) == 1 and frm[0][1] - frm[0][0] == to[0][1] - to[0][0]:
        off = to[0][0] - frm[0][0]
        return [(lo + off, hi + off) for lo, hi in ranges]
    return to
