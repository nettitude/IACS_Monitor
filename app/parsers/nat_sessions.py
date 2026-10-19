"""
NAT'd sessions (NAT tabletop P-04, P-05, P-06).

A capture taken in front of a firewall sees a flow to the VIP's EXTERNAL
address; one taken behind it sees the mapped host - and, with source NAT,
the firewall's address instead of the real client.  Owner decision: the
session BEFORE translation is the accountable record (it carries the real
source), and it is judged as what it really reaches.

``reconcile(db)`` (run at the start of every review run) rewrites the
bound site's sessions in place:

* DNAT: a session to a VIP external address (VIPs followed through other
  firewalls' VIPs - double NAT) gets the mapped host as its destination;
  ``nat_orig_dst_ip`` keeps the address it was sent to.
* SNAT: a session whose source is a translated address of a source-NAT
  policy whose destination covers the session gets the real source of its
  pre-NAT twin (same destination and port, a source the policy admits,
  first seen within ``TWIN_WINDOW`` seconds); ``nat_orig_src_ip`` keeps the
  translated source.  Without a twin the session keeps the firewall's
  address and ``nat["unattributed"]`` names the policy and the sources it
  hides - the accountability gap ``nat_hides_source_into_ot`` reports.
* a rewrite onto a 5-tuple that already exists merges the two rows
  (counts, first / last seen, protocol details and findings move over).
* VIP external addresses are firewall-owned: their Host rows lose any
  inferred device type / level (not manual ones) and are known
  infrastructure (never an unknown device).
* annotations whose NAT is gone are reverted (rows that were merged stay
  merged).
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.parsers import rule_match as rm

log = logging.getLogger(__name__)

TWIN_WINDOW = 300          # seconds between the pre- and post-NAT capture of one flow
VIP_DEVICE_TYPE = "firewall_vip"


def _single(spec) -> Optional[str]:
    from app.parsers.access_paths import _single_host
    return _single_host(spec)


class _Ctx:
    def __init__(self, db):
        from app.models import FirewallRule, Host
        from app.parsers.nat_paths import NatIndex
        self.db = db
        self.idx = NatIndex.build(db)
        self.hosts = {h.ip: h for h in db.query(Host).filter(Host.ip.isnot(None))}
        self.snat = []            # (entry, [FirewallRule])
        rules = {}
        for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(True)):
            rules.setdefault((r.firewall_id, getattr(r, "vdom", None), str(r.policy_id)), []).append(r)
        for (fid, vdom, pid), entries in self.idx.snat.items():          # C5: per VDOM
            for e in entries:
                self.snat.append((e, rules.get((fid, vdom, pid), [])))
        for fid, entries in self.idx.central.items():
            for e in entries:
                self.snat.append((e, []))

    # ---- addresses
    def vip_hit(self, ip: str) -> bool:
        for entries in self.idx.dnat.values():
            for e in entries:
                if rm.ip_in_addr(ip, e["ext"]):
                    return True
        return False

    def dnat_chain(self, ip: str, port):
        """(final ip, final port, events) through every VIP in the chain."""
        events, cur_ip, cur_port, used = [], ip, port, set()
        for _ in range(4):
            hit = None
            for fid, entries in self.idx.dnat.items():
                for e in entries:
                    if id(e) in used or not rm.ip_in_addr(cur_ip, e["ext"]):
                        continue
                    if cur_port is not None and e["ext_ports"] != rm.ANY \
                            and not isinstance(e["ext_ports"], rm.Unresolved) \
                            and not rm.port_in(cur_port, e["ext_ports"]):
                        continue
                    hit = e
                    break
                if hit:
                    break
            if hit is None:
                break
            used.add(id(hit))
            from app.parsers.reachability import _map_ip, _map_port
            new_ip = _map_ip(cur_ip, hit["ext"], hit["mapped"])
            if new_ip is None:
                break
            new_port = _map_port(cur_port, hit["ext_ports"], hit["mapped_ports"])
            events.append(self.idx._event("dnat", hit, None))
            cur_ip, cur_port = new_ip, new_port
        return (cur_ip, cur_port, events) if events else None

    def snat_policies(self, src_ip, dst_ip, port):
        """[(entry, rule)] source-NAT policies whose translated address is
        ``src_ip`` and whose destination covers dst_ip[:port]."""
        out = []
        for e, rows in self.snat:
            if not rm.ip_in_addr(src_ip, e["mapped"]):
                continue
            if not rows:
                out.append((e, None))
                continue
            for r in rows:
                try:
                    dspec = rm.parse_address(r.dst, v6_default_is_any=False)
                    ports = rm.parse_ports(r.dst_port)
                except Exception:
                    continue
                if isinstance(dspec, rm.Unresolved) or not rm.ip_in_addr(dst_ip, dspec):
                    continue
                if port is not None and ports != rm.ANY and not isinstance(ports, rm.Unresolved) \
                        and not rm.port_in(port, ports):
                    continue
                out.append((e, r))
        return out

    def host(self, ip, site_id):
        from app.models import Host
        h = self.hosts.get(ip)
        if h is None:
            h = Host(ip=ip, site_id=site_id, sources=["nat"])
            self.db.add(h)
            self.db.flush()
            self.hosts[ip] = h
        return h


def _merge(db, src, dst) -> None:
    from app.models import Finding, ProtocolDetail
    dst.packet_count = int(dst.packet_count or 0) + int(src.packet_count or 0)
    dst.byte_count = int(dst.byte_count or 0) + int(src.byte_count or 0)
    if src.first_seen and (dst.first_seen is None or src.first_seen < dst.first_seen):
        dst.first_seen = src.first_seen
    if src.last_seen and (dst.last_seen is None or src.last_seen > dst.last_seen):
        dst.last_seen = src.last_seen
    if dst.carrier_mac is None and src.carrier_mac:
        dst.carrier_mac = src.carrier_mac
    db.query(ProtocolDetail).filter(ProtocolDetail.session_id == src.id).update(
        {ProtocolDetail.session_id: dst.id}, synchronize_session=False)
    db.query(Finding).filter(Finding.session_id == src.id).update(
        {Finding.session_id: dst.id}, synchronize_session=False)
    db.delete(src)
    db.flush()


def _move(db, ns, *, src_host_id=None, dst_host_id=None, dst_port="keep"):
    """Re-point ``ns``; merge into an existing row with the new 5-tuple.
    Returns the row that now carries the flow."""
    from app.models import NetworkSession
    s_id = src_host_id if src_host_id is not None else ns.src_host_id
    d_id = dst_host_id if dst_host_id is not None else ns.dst_host_id
    d_port = ns.dst_port if dst_port == "keep" else dst_port
    other = db.query(NetworkSession).filter(
        NetworkSession.id != ns.id, NetworkSession.src_host_id == s_id,
        NetworkSession.dst_host_id == d_id,
        (NetworkSession.src_port == ns.src_port) if ns.src_port is not None else NetworkSession.src_port.is_(None),
        (NetworkSession.dst_port == d_port) if d_port is not None else NetworkSession.dst_port.is_(None),
        NetworkSession.transport == ns.transport).first()
    if other is not None and ns.dst_port is not None and ns.src_port is not None:
        for k in ("nat_orig_src_ip", "nat_orig_dst_ip"):
            if getattr(ns, k) and not getattr(other, k):
                setattr(other, k, getattr(ns, k))
        other.nat = _merge_nat(other.nat, ns.nat)
        _merge(db, ns, other)
        return other
    ns.src_host_id, ns.dst_host_id, ns.dst_port = s_id, d_id, d_port
    return ns


def _merge_nat(a, b):
    if not a:
        return dict(b or {}) or None
    if not b:
        return a
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, list):
            out[k] = list(out.get(k) or []) + [x for x in v if x not in (out.get(k) or [])]
        elif k not in out:
            out[k] = v
    return out


def reconcile(db: DBSession) -> dict:
    """Rewrite the bound site's NAT'd sessions (see module doc).  Flushes."""
    from app.models import Host, NetworkSession
    stats = {"vip_hosts": 0, "dnat_rewritten": 0, "snat_attributed": 0, "snat_unattributed": 0,
             "merged": 0, "reverted": 0}
    ctx = _Ctx(db)
    by_id = {h.id: h for h in ctx.hosts.values()}

    def ip_of(hid):
        h = by_id.get(hid)
        if h is None:
            h = db.get(Host, hid)
            if h is not None:
                by_id[hid] = h
        return h.ip if h is not None else None

    # 1. VIP external addresses are the firewall's
    for ip, h in ctx.hosts.items():
        if ctx.vip_hit(ip) and h.classification_source != "manual":
            if h.device_type != VIP_DEVICE_TYPE or h.purdue_level is not None:
                h.device_type, h.purdue_level, h.classification_source = VIP_DEVICE_TYPE, None, "nat"
                stats["vip_hosts"] += 1

    sessions = db.query(NetworkSession).order_by(NetworkSession.id).all()
    gone = set()
    # 0. revert annotations whose translation no longer exists
    for ns in sessions:
        nat = ns.nat or {}
        if ns.nat_orig_dst_ip and ctx.dnat_chain(ns.nat_orig_dst_ip, nat.get("orig_dst_port", ns.dst_port)) is None:
            h = ctx.host(ns.nat_orig_dst_ip, by_id[ns.src_host_id].site_id if ns.src_host_id in by_id else None)
            keep = _move(db, ns, dst_host_id=h.id, dst_port=nat.get("orig_dst_port", ns.dst_port))
            keep.nat_orig_dst_ip, keep.nat = None, None
            stats["reverted"] += 1
            if keep is not ns:
                gone.add(ns.id)
    sessions = [s for s in sessions if s.id not in gone]

    # 2. DNAT: the session was sent to a VIP
    for ns in sessions:
        if ns.id in gone:
            continue
        dip = ip_of(ns.dst_host_id)
        if not dip:
            continue
        chain = ctx.dnat_chain(dip, ns.dst_port)
        if chain is None:
            continue
        final_ip, final_port, events = chain
        if final_ip == dip:
            continue
        src_h = by_id.get(ns.src_host_id) or db.get(Host, ns.src_host_id)
        mh = ctx.host(final_ip, src_h.site_id if src_h is not None else None)
        by_id[mh.id] = mh
        ns.nat = _merge_nat(ns.nat, {"events": events, "orig_dst_port": ns.dst_port})
        ns.nat_orig_dst_ip = dip
        keep = _move(db, ns, dst_host_id=mh.id, dst_port=final_port)
        stats["dnat_rewritten"] += 1
        if keep is not ns:
            gone.add(ns.id)
            stats["merged"] += 1
    db.flush()
    sessions = [s for s in sessions if s.id not in gone]

    # 3. SNAT: the session arrived from a translated address.  AU full review
    # C6: candidate twins come from an index on (destination, port), and the
    # SNAT lookup per (src, dst, port) is memoised - the scan used to be
    # O(sessions^2) behind a source-NAT firewall.
    by_dst: dict = {}
    for o in sessions:
        by_dst.setdefault((o.dst_host_id, o.dst_port), []).append(o)
    _snat_memo: dict = {}

    def snat_pols(a, b, port):
        k = (a, b, port)
        if k not in _snat_memo:
            _snat_memo[k] = ctx.snat_policies(a, b, port)
        return _snat_memo[k]

    for ns in sessions:
        if ns.id in gone or ns.nat_orig_src_ip:
            continue
        sip, dip = ip_of(ns.src_host_id), ip_of(ns.dst_host_id)
        if not sip or not dip:
            continue
        cands = snat_pols(sip, dip, ns.dst_port)
        if not cands:
            continue
        twin, best = None, None
        for e, r in cands:
            try:
                orig = rm.parse_address(r.src, v6_default_is_any=False) if r is not None else e["orig_src"]
            except Exception:
                continue
            for o in by_dst.get((ns.dst_host_id, ns.dst_port), ()):
                if o.id in gone or o.id == ns.id or o.nat_orig_src_ip:
                    continue
                oip = ip_of(o.src_host_id)
                if not oip or oip == sip or isinstance(orig, rm.Unresolved) \
                        or not (orig == rm.ANY or rm.ip_in_addr(oip, orig)):
                    continue
                if snat_pols(oip, dip, ns.dst_port):
                    continue            # another translated view, not the real client
                if o.first_seen is None or ns.first_seen is None:
                    continue
                dt = abs((o.first_seen - ns.first_seen).total_seconds())
                if dt <= TWIN_WINDOW and (best is None or dt < best):
                    twin, best = (o, e, r), dt
        e0, r0 = cands[0]
        rule_ids = sorted({r.id for _e, r in cands if r is not None})
        if twin is not None:
            o, e, r = twin
            ns.nat = _merge_nat(ns.nat, {"events": [ctx.idx._event("snat", e, {"policy_id": r.policy_id if r else None})],
                                         "snat_rule_ids": rule_ids, "attributed_from_session": o.id})
            ns.nat_orig_src_ip = sip
            keep = _move(db, ns, src_host_id=o.src_host_id)
            stats["snat_attributed"] += 1
            if keep is not ns:
                gone.add(ns.id)
                stats["merged"] += 1
        else:
            ns.nat = _merge_nat(ns.nat, {
                "events": [ctx.idx._event("snat", e0, {"policy_id": r0.policy_id if r0 else None})],
                "snat_rule_ids": rule_ids,
                "unattributed": {"firewall": e0["row"].device_name, "firewall_id": e0["firewall_id"],
                                 "policy_id": r0.policy_id if r0 is not None else None,
                                 "policy_name": r0.policy_name if r0 is not None else e0["name"],
                                 "original_sources": (r0.src if r0 is not None else e0["row"].orig_src) or "any"}})
            stats["snat_unattributed"] += 1
    db.flush()
    return stats


def known_vip_ips(db: DBSession) -> set:
    """Single-address VIP external addresses of the bound site (P-04)."""
    from app.models import NatRule
    out = set()
    for (ext,) in db.query(NatRule.ext_ip).filter(NatRule.enabled.is_(True), NatRule.nat_type == "dnat",
                                                   NatRule.ext_ip.isnot(None)):
        try:
            ip = _single(rm.parse_address(ext, v6_default_is_any=False))
        except Exception:
            ip = None
        if ip:
            out.add(ip)
    return out


def snat_rule_ids_seen(db: DBSession) -> set:
    """Rule ids of source-NAT policies whose translated traffic is in the
    capture (P-06: such a policy is not unused)."""
    from app.models import NetworkSession
    out = set()
    for (nat,) in db.query(NetworkSession.nat).filter(NetworkSession.nat.isnot(None)):
        for rid in (nat or {}).get("snat_rule_ids") or []:
            out.add(rid)
    return out


# Multi-site: reconcile(db, site_id=...) runs scoped to that site (ingest).
from app.parsers.site_scope import scope_module  # noqa: E402
scope_module(globals(), ("reconcile",))
