"""IEC 62443-3-2 zones and conduits - a documentation view.

A zone (``IecZone``) is a named grouping of assets with common security
requirements and an optional target security level (SL-T).  It is NOT tied
to the Purdue model or to addressing: its members (``IecZoneMember``) can be
hosts, subnets, firewall interfaces / VLAN sub-interfaces and FortiGate
zones, at any mix of Purdue levels.  An asset belongs to one zone.

A conduit (``IecConduit``) is declared between two zones.  The policies that
permit traffic between the zones and the traffic the captures show are
derived at read time, per direction, so the page can show documented
conduits, zone pairs that talk without a documented conduit, and conduits
with no policy or traffic behind them.

Documentation only (owner, 2026-10-10): nothing here feeds the findings
engine, the Purdue classification or the report.  The engine never imports
this module; ``tests/test_iec_zones.py`` checks that findings are identical
with and without zones.

Resolution of a host to a zone, strongest first:
  1. a ``host`` member naming its MAC or address;
  2. the most specific network among the ``subnet`` members, the networks
     of ``interface`` members and of the member interfaces of ``fw_zone``
     members (a firewall's own interface address is the firewall's, not a
     zone member).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
from collections import Counter, defaultdict
from typing import Optional

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

KINDS = ("host", "subnet", "interface", "fw_zone")
KIND_LABEL = {"host": "Host", "subnet": "Subnet", "interface": "Firewall interface",
              "fw_zone": "FortiGate zone"}
NO_ZONE = "(not in a zone)"
EXTERNAL = "External / Internet"
_MAX_SAMPLES = 5


class ZoneError(ValueError):
    """Bad input (422) - ``status`` 404 / 409 for not found / conflict."""

    def __init__(self, msg: str, status: int = 422):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------- members --
def normalize_ref(kind: str, ref: str) -> str:
    """Canonical member reference for ``kind`` (ZoneError when invalid)."""
    from app.parsers.common import normalize_mac
    kind = str(kind or "").strip()
    ref = str(ref or "").strip()
    if kind not in KINDS:
        raise ZoneError(f"kind must be one of {', '.join(KINDS)}")
    if not ref:
        raise ZoneError("ref is required")
    if kind == "host":
        body = ref.split(":", 1)[1] if ref.lower().startswith(("mac:", "ip:")) else ref
        try:
            return "ip:" + str(ipaddress.ip_address(body))
        except ValueError:
            pass
        mac = normalize_mac(body)
        if mac:
            return "mac:" + mac.lower()
        raise ZoneError(f"host: '{ref}' is neither an IP address nor a MAC address")
    if kind == "subnet":
        try:
            n = ipaddress.ip_network(ref, strict=False)
        except ValueError:
            raise ZoneError(f"subnet: '{ref}' is not an IPv4 / IPv6 network")
        if n.prefixlen == 0:
            raise ZoneError("subnet: a default route (/0) is not a zone member")
        return str(n)
    parts = [p.strip() for p in ref.split("/")]
    if kind == "interface":
        if len(parts) != 2 or not all(parts):
            raise ZoneError("interface: use '<firewall name>/<interface name>'")
        return f"{parts[0]}/{parts[1]}"
    if len(parts) == 2:
        parts = [parts[0], "", parts[1]]
    if len(parts) != 3 or not parts[0] or not parts[2]:
        raise ZoneError("fw_zone: use '<firewall name>/<zone name>' or '<firewall name>/<vdom>/<zone name>'")
    return f"{parts[0]}/{parts[1]}/{parts[2]}"


def _net(cidr) -> Optional[ipaddress._BaseNetwork]:
    try:
        n = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except (ValueError, TypeError):
        return None
    return n if n.prefixlen > 0 else None


class _Infra:
    """The site's firewalls, interfaces and FortiOS zone definitions."""

    def __init__(self, db: DBSession, site_id: int):
        from app.models import Firewall, FirewallInterface, FirewallZoneDef
        self.fws = {fw.id: fw for fw in db.query(Firewall).filter(Firewall.site_id == site_id)}
        self.fw_by_name = {}
        for fw in self.fws.values():
            for n in (fw.name, fw.device_name):
                if n:
                    self.fw_by_name.setdefault(n.lower(), fw)
        self.ifaces = []
        self.iface_by_key = {}
        self.iface_ips = set()
        if self.fws:
            for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id.in_(list(self.fws))):
                self.ifaces.append(i)
                self.iface_by_key[(i.firewall_id, (i.name or "").lower())] = i
                if i.ip_address:
                    self.iface_ips.add(i.ip_address)
        self.zdefs = defaultdict(list)            # (fw_id, vdom or "", name lower) -> [member names lower]
        self.zdef_names = {}                      # same key -> (vdom, name) as configured
        if self.fws:
            for z in db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id.in_(list(self.fws))):
                key = (z.firewall_id, (z.vdom or "").lower(), (z.name or "").lower())
                self.zdefs[key] = [str(m).strip().lower() for m in (z.members or []) if str(m).strip()]
                self.zdef_names[key] = (z.vdom or "", z.name or "")

    def fw(self, name: str):
        return self.fw_by_name.get((name or "").lower())

    def fw_label(self, fw_id) -> str:
        fw = self.fws.get(fw_id)
        return (fw.name or fw.device_name) if fw else f"#{fw_id}"

    def zone_def(self, fw_id: int, vdom: str, name: str):
        key = (fw_id, (vdom or "").lower(), (name or "").lower())
        if key in self.zdefs:
            return self.zdefs[key]
        if not vdom:                       # a single-VDOM config stores its zones under any vdom
            hits = [v for (f, _v, n), v in self.zdefs.items() if f == fw_id and n == key[2]]
            if len(hits) == 1:
                return hits[0]
        return None


def _resolve_member(m, infra: _Infra) -> dict:
    """{networks, interfaces [(fw_id, name lower)], host_keys, found, detail}."""
    out = {"networks": [], "interfaces": [], "host_keys": [], "found": True, "detail": None}
    if m.kind == "host":
        out["host_keys"].append(m.ref.lower())
        return out
    if m.kind == "subnet":
        n = _net(m.ref)
        out["networks"] = [n] if n else []
        out["found"] = n is not None
        return out
    parts = m.ref.split("/")
    fw = infra.fw(parts[0])
    if fw is None:
        out.update(found=False, detail=f"firewall '{parts[0]}' not found in this site")
        return out
    if m.kind == "interface":
        names = [parts[1].lower()]
    else:
        names = infra.zone_def(fw.id, parts[1], parts[2])
        if names is None:
            out.update(found=False, detail=f"FortiGate zone '{parts[2]}' not found on {parts[0]}")
            return out
    nets, missing = [], []
    for nm in names:
        i = infra.iface_by_key.get((fw.id, nm))
        if i is None:
            missing.append(nm)
            continue
        out["interfaces"].append((fw.id, nm))
        n = _net(i.network_cidr)
        if n is not None:
            nets.append(n)
    out["networks"] = nets
    if m.kind == "interface" and missing:
        out.update(found=False, detail=f"interface '{parts[1]}' not found on {parts[0]}")
    elif missing:
        out["detail"] = f"member interface(s) not found: {', '.join(missing)}"
    return out


# --------------------------------------------------------------- model --
class ZoneModel:
    """Zones, their resolved members and the host -> zone assignment."""

    def __init__(self, db: DBSession, site_id: int):
        from app.models import Host, IecZone, IecZoneMember, real_host_clause
        self.site_id = site_id
        self.infra = _Infra(db, site_id)
        self.zones = {z.id: z for z in db.query(IecZone).filter(IecZone.site_id == site_id)}
        self.members = defaultdict(list)                  # zone id -> [(member, resolution)]
        for m in db.query(IecZoneMember).filter(IecZoneMember.site_id == site_id).order_by(IecZoneMember.id):
            if m.zone_id in self.zones:
                self.members[m.zone_id].append((m, _resolve_member(m, self.infra)))
        # network claims: (network, zone id, basis)
        self.net_claims = []
        self.host_claims = defaultdict(list)              # host key -> [(zone id, basis)]: a host may be in several zones
        self.iface_zone = {}                              # (fw_id, iface lower) -> zone id
        for zid, ms in self.members.items():
            for m, r in ms:
                for k in r["host_keys"]:
                    if all(z != zid for z, _b in self.host_claims[k]):
                        self.host_claims[k].append((zid, f"host member {m.ref}"))
                basis = {"subnet": f"subnet {m.ref}", "interface": f"interface {m.ref}",
                         "fw_zone": f"FortiGate zone {m.ref}"}.get(m.kind)
                for n in r["networks"]:
                    self.net_claims.append((n, zid, basis))
                for key in r["interfaces"]:
                    self.iface_zone.setdefault(key, zid)
        self.net_claims.sort(key=lambda c: (-c[0].prefixlen, str(c[0])))
        self.overlaps = self._overlaps()
        self.hosts = [h for h in db.query(Host).filter(Host.site_id == site_id, real_host_clause(),
                                                       Host.ip.isnot(None))]
        self.host_zone = {}                               # host id -> (zone id | None, basis): the address's own zone
        self.addr_zones = {}                              # host id -> [(zone id, basis)] of that address
        for h in self.hosts:
            self.addr_zones[h.id] = self.zones_of(h.ip, h.mac)
            self.host_zone[h.id] = self.addr_zones[h.id][0] if self.addr_zones[h.id] else self.zone_of(h.ip, h.mac)
        # a device = every address row sharing a MAC (a MAC-less row is its own device)
        self.device_rows = defaultdict(list)              # device key -> [host rows]
        for h in self.hosts:
            self.device_rows[self._device_key(h)].append(h)
        self.multi_zone = self._multi_zone_hosts()

    @staticmethod
    def _device_key(h) -> str:
        return f"mac:{h.mac.lower()}" if h.mac else f"ip:{h.ip}"

    def device_zones(self, h) -> list:
        """Every zone the device of ``h`` is in, over all its addresses:
        [(zone id, basis, address)], first = this address's own zone."""
        out = []
        rows = [h] + [x for x in self.device_rows.get(self._device_key(h), []) if x.id != h.id]
        for row in rows:
            for zid, basis in self.addr_zones.get(row.id, []):
                if all(z != zid for z, _b, _a in out):
                    out.append((zid, basis, row.ip))
        return out

    def _multi_zone_hosts(self) -> list:
        """Devices (by MAC) whose addresses resolve to two or more zones:
        dual-homed hosts, hosts tagged in several VLANs, or a host member
        placed in several zones on purpose."""
        out = []
        for key, rows in self.device_rows.items():
            zones = {}
            for row in rows:
                for zid, basis in self.addr_zones.get(row.id, []):
                    zones.setdefault(zid, []).append({"ip": row.ip, "host_id": row.id, "basis": basis})
            if len(zones) >= 2:
                lead = rows[0]
                out.append({"key": key, "mac": lead.mac, "hostname": next((r.hostname for r in rows if r.hostname), None),
                            "device_type": next((r.device_type for r in rows if r.device_type), None),
                            "purdue_level": next((r.purdue_level for r in rows if r.purdue_level is not None), None),
                            "addresses": sorted({r.ip for r in rows}, key=_ip_key),
                            "zones": [{"id": zid, "name": self.zones[zid].name, "sl_t": self.zones[zid].sl_t,
                                       "addresses": v} for zid, v in zones.items()]})
        out.sort(key=lambda d: _ip_key(d["addresses"][0]))
        return out

    def zones_of(self, ip: Optional[str], mac: Optional[str] = None) -> list:
        """Every zone an address is in: its explicit host members (by address,
        then by MAC); with none, the zone of its network.  [(zone id, basis)]."""
        out = []
        a = None
        if ip:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                a = None
        if a is not None:
            out += self.host_claims.get(f"ip:{a}", [])
        if mac:
            for zid, basis in self.host_claims.get(f"mac:{mac.lower()}", []):
                if all(z != zid for z, _b in out):
                    out.append((zid, basis))
        if out or a is None or ip in self.infra.iface_ips:
            return out
        for n, zid, basis in self.net_claims:
            if n.version == a.version and a in n:
                return [(zid, basis)]
        return out

    def _overlaps(self) -> list:
        seen = {}
        out = []
        for n, zid, basis in self.net_claims:
            prev = seen.get(n)
            if prev is not None and prev[0] != zid:
                out.append({"network": str(n), "zones": [self.zones[prev[0]].name, self.zones[zid].name],
                            "members": [prev[1], basis],
                            "note": "the same network is a member of two zones; the first one listed wins "
                                    "(reported by network_in_multiple_zones)"})
            else:
                seen.setdefault(n, (zid, basis))
        return out

    def zone_of(self, ip: Optional[str], mac: Optional[str] = None):
        """(zone id | None, basis) of an address (and its MAC): the first of
        ``zones_of`` (a host member by address, then by MAC, then the
        network); a firewall's own interface address belongs to no zone."""
        zs = self.zones_of(ip, mac)
        if zs:
            return zs[0]
        if ip and ip in self.infra.iface_ips:
            return None, "firewall interface address"
        return None, None

    def zone_specs(self) -> dict:
        """zone id -> parse_address spec list (networks and host addresses) for policy matching."""
        out = defaultdict(list)
        for n, zid, _b in self.net_claims:
            out[zid].append(n)
        for k, claims in self.host_claims.items():
            for zid, _b in claims:
                if k.startswith("ip:"):
                    out[zid].append(ipaddress.ip_network(k[3:]))
                else:
                    for h in self.hosts:
                        if h.mac and h.mac.lower() == k[4:] and h.ip:
                            try:
                                out[zid].append(ipaddress.ip_network(h.ip))
                            except ValueError:
                                pass
        return out


def _zone_ref(model: ZoneModel, zid) -> dict:
    if zid is None:
        return {"id": None, "name": NO_ZONE, "sl_t": None}
    if zid == "external":
        return {"id": None, "name": EXTERNAL, "sl_t": None, "external": True}
    z = model.zones[zid]
    return {"id": z.id, "name": z.name, "sl_t": z.sl_t}


def zone_summary(model: ZoneModel) -> list:
    """Every zone with members (resolution status), hosts and the Purdue levels it spans."""
    by_zone = defaultdict(list)
    for h in model.hosts:
        for zid, basis in model.addr_zones.get(h.id, []):
            by_zone[zid].append((h, basis))
    out = []
    for z in sorted(model.zones.values(), key=lambda z: z.name.lower()):
        hosts = by_zone.get(z.id, [])
        levels = Counter(h.purdue_level for h, _b in hosts if h.purdue_level is not None)
        for _m, r in model.members[z.id]:
            for key in r["interfaces"]:
                i = model.infra.iface_by_key.get(key)
                if i is not None and i.purdue_level is not None:
                    levels.setdefault(i.purdue_level, 0)
        members = []
        for m, r in model.members[z.id]:
            members.append({
                "id": m.id, "kind": m.kind, "kind_label": KIND_LABEL[m.kind], "ref": m.ref, "note": m.note,
                "found": r["found"] and (m.kind != "host" or any(
                    (h.mac and f"mac:{h.mac.lower()}" == m.ref) or f"ip:{h.ip}" == m.ref for h in model.hosts)),
                "detail": r["detail"],
                "networks": [str(n) for n in r["networks"]],
                "hosts": sum(1 for h, b in hosts if b and m.ref in b),
            })
        out.append({
            "id": z.id, "name": z.name, "sl_t": z.sl_t, "description": z.description, "owner": z.owner,
            "sl_a": z.sl_a, "sl_a_note": z.sl_a_note, "sl_a_status": sl_a_status(z.sl_a, z.sl_t),
            "created_by": z.created_by, "created_at": z.created_at, "updated_at": z.updated_at,
            "members": members,
            "purdue_levels": sorted(float(l) for l in levels),
            "host_count": len(hosts),
            "hosts": [{"id": h.id, "ip": h.ip, "mac": h.mac, "hostname": h.hostname,
                       "device_type": h.device_type, "purdue_level": h.purdue_level, "basis": b,
                       "sl_c": h.sl_c, "sl_c_source": h.sl_c_source,
                       "below_target": sl_below(h.sl_c, z.sl_t),
                       "other_zones": [{"name": model.zones[oz].name, "ip": oip}
                                       for oz, _ob, oip in model.device_zones(h) if oz != z.id]}
                      for h, b in sorted(hosts, key=lambda t: _ip_key(t[0].ip))],
            "sl_c": sl_c_summary([h for h, _b in hosts], z.sl_t),
        })
    return out


def sl_a_status(sl_a, target) -> Optional[str]:
    """SL-A against a target: ``meets`` / ``below`` / ``not_assessed`` (None
    when there is no target).  IEC 62443-3-2: an achieved level below the
    target is a gap to close or to cover with compensating countermeasures.
    Documentation only."""
    if target is None:
        return None
    if sl_a is None:
        return "not_assessed"
    return "meets" if sl_a >= target else "below"


def sl_c_summary(hosts, sl_t) -> dict:
    """SL-C of a zone's hosts against its SL-T (IEC 62443-3-2: components
    whose capability is below the target need compensating countermeasures).
    Documentation only."""
    assessed = [h for h in hosts if h.sl_c is not None]
    below = [h for h in assessed if sl_below(h.sl_c, sl_t)]
    notes = []
    if below:
        notes.append(f"{len(below)} host(s) with SL-C below the zone's SL-T {sl_t} "
                     f"({', '.join(f'{h.ip} SL-C {h.sl_c}' for h in sorted(below, key=lambda h: _ip_key(h.ip))[:6])}"
                     f"{' …' if len(below) > 6 else ''}): document compensating countermeasures")
    if sl_t is not None and hosts and len(assessed) < len(hosts):
        notes.append(f"{len(hosts) - len(assessed)} of {len(hosts)} host(s) have no SL-C recorded")
    return {"assessed": len(assessed), "not_assessed": len(hosts) - len(assessed),
            "below_target": [{"id": h.id, "ip": h.ip, "sl_c": h.sl_c} for h in below],
            "min": min((h.sl_c for h in assessed), default=None), "notes": notes}


def _ip_key(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except (ValueError, TypeError):
        return (9, 0)


def unassigned_hosts(model: ZoneModel) -> list:
    out = []
    for h in sorted(model.hosts, key=lambda h: _ip_key(h.ip)):
        zid, basis = model.host_zone[h.id]
        if zid is None and basis != "firewall interface address" and not _public(h.ip):
            out.append({"id": h.id, "ip": h.ip, "mac": h.mac, "hostname": h.hostname,
                        "device_type": h.device_type, "purdue_level": h.purdue_level, "sl_c": h.sl_c})
    return out


def _public(ip) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return a.is_global


# ------------------------------------------------------------- conduits --
def _service(proto, port) -> str:
    from app.api.routes import _protocol_label            # readable service names (shared with topology)
    lbl = _protocol_label(proto, port)
    return lbl if port is None or str(port) in lbl else f"{lbl} ({port})"


def _pair_key(a, b):
    """Stable key and orientation of a zone pair; pseudo zones sort last."""
    def k(z):
        return (0, z) if isinstance(z, int) else (1, str(z))
    return (a, b, False) if k(a) <= k(b) else (b, a, True)


def derive_flows(db: DBSession, model: ZoneModel) -> dict:
    """{(zone x, zone y): {"x_to_y": {...}, "y_to_x": {...}}} from permitting
    policies and observed sessions; zone = id, None (not in a zone) or
    "external".  Intra-zone traffic is counted per zone separately."""
    from app.models import FirewallRule, Host, NetworkSession
    from app.parsers.fortios_zones import ZoneDefIndex, zone_tokens
    from app.parsers.rule_match import addr_overlaps, parse_address
    pairs: dict = {}
    intra = Counter()

    def slot(src, dst):
        x, y, flipped = _pair_key(src, dst)
        e = pairs.setdefault((x, y), {"x_to_y": _empty(), "y_to_x": _empty()})
        return e["y_to_x" if flipped else "x_to_y"]

    # --- policies -----------------------------------------------------
    specs = model.zone_specs()
    zdi = ZoneDefIndex(db, list(model.infra.fws))
    iface_nets = {(i.firewall_id, (i.name or "").lower()): _net(i.network_cidr) for i in model.infra.ifaces}

    from app.parsers.rule_match import Unresolved, is_family_wide
    outside = {(i.firewall_id, (i.name or "").lower()) for i in model.infra.ifaces
               if (i.purdue_level is not None and float(i.purdue_level) >= 5) or (i.side or "") == "outside"}

    def side_zones(fw_id, vdom, zone_value, addr_value) -> set:
        """Zones on one side of a policy: the zones of its interfaces (an
        interface member, a FortiGate zone member, or zone networks on the
        interface's network) plus the zones holding its concrete addresses,
        narrowed to the zones its addresses overlap.  An unzoned outside /
        L5 interface is the Internet ("external"); other unzoned sides are
        None (not in a zone)."""
        names, _ok = zdi.expand(fw_id, vdom, zone_value) if zdi else (zone_tokens(zone_value), True)
        spec = parse_address(addr_value)
        concrete = spec != "any" and not isinstance(spec, Unresolved) and not is_family_wide(spec)
        cand = set()
        ext = False
        if names is None:
            cand = set(model.zones)
        else:
            for nm in names:
                zid = model.iface_zone.get((fw_id, nm))
                if zid is not None:
                    cand.add(zid)
                    continue
                inet = iface_nets.get((fw_id, nm))
                hit = False
                if inet is not None:
                    for zid2, sp in specs.items():
                        if any(n.version == inet.version and n.overlaps(inet) for n in sp):
                            cand.add(zid2)
                            hit = True
                if not hit and (fw_id, nm) in outside:
                    ext = True
        if concrete:
            for zid2, sp in specs.items():
                if any(addr_overlaps(spec, n) for n in sp):
                    cand.add(zid2)
        out = set()
        for zid in cand:
            sp = specs.get(zid) or []
            if not sp:
                if names is not None:
                    out.add(zid)      # an interface-only zone with no network: the interface decides
                continue
            if any(addr_overlaps(spec, n) is not False for n in sp):
                out.add(zid)
        if ext and not (concrete and out):
            out.add("external")
        if not out and names is not None:
            out.add(None)
        return out

    policies = {}
    for r in db.query(FirewallRule).filter(FirewallRule.site_id == model.site_id, FirewallRule.enabled.is_(True),
                                           FirewallRule.firewall_id.in_(list(model.infra.fws) or [-1])):
        if str(r.action or "").lower() not in ("accept", "permit", "allow", "pass"):
            continue
        key = (r.firewall_id, r.vdom or "", r.policy_id or str(r.id))
        p = policies.setdefault(key, {"src": set(), "dst": set(), "services": set()})
        try:
            p["src"] |= side_zones(r.firewall_id, r.vdom, r.src_zone, r.src)
            p["dst"] |= side_zones(r.firewall_id, r.vdom, r.dst_zone, r.dst)
        except Exception:                                   # noqa: BLE001 - documentation view, never fails
            log.debug("zone mapping of rule %s failed", r.id, exc_info=True)
        proto = str(r.protocol or "any").lower()
        port = str(r.dst_port or "any")
        p["services"].add("any" if proto in ("any", "all", "ip") and port == "any" else f"{proto}/{port}")
    policy_pairs = {}                                        # SF-6: label -> the zone pairs one policy serves
    for (fw_id, vdom, pid), p in policies.items():
        label = f"{model.infra.fw_label(fw_id)} policy {pid}" + (f" (vdom {vdom})" if vdom else "")
        policy_pairs[label] = {"firewall_id": fw_id, "policy_id": pid, "vdom": vdom,
                               "pairs": {_pair_key(s, d) for s in p["src"] for d in p["dst"] if s != d},
                               "services": sorted(p["services"])[:12]}
        for s in p["src"]:
            for d in p["dst"]:
                if s == d:
                    continue
                e = slot(s, d)
                e["policies"].append({"policy": label, "firewall_id": fw_id, "policy_id": pid, "vdom": vdom,
                                      "services": sorted(p["services"])[:12]})

    # --- observed sessions -----------------------------------------------
    hz = {h.id: model.host_zone[h.id][0] for h in model.hosts}
    ips = {h.id: h.ip for h in model.hosts}
    ext_ids = {h.id for h in model.hosts if _public(h.ip) and hz.get(h.id) is None}
    q = (db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id, NetworkSession.dst_port,
                  NetworkSession.transport, NetworkSession.protocol, NetworkSession.last_seen)
         .join(Host, Host.id == NetworkSession.src_host_id).filter(Host.site_id == model.site_id))
    for sid, did, port, tr, proto, last in q.yield_per(2000):
        if sid not in hz or did not in hz:
            continue
        s = "external" if sid in ext_ids else hz[sid]
        d = "external" if did in ext_ids else hz[did]
        if s == d:
            if s is not None and s != "external":
                intra[s] += 1
            continue
        if s is None and d is None:
            continue
        e = slot(s, d)
        e["sessions"] += 1
        e["services"][_service(proto, port)] += 1
        if last and (e["last_seen"] is None or last > e["last_seen"]):
            e["last_seen"] = last
        if len(e["samples"]) < _MAX_SAMPLES:
            smp = f"{ips[sid]} → {ips[did]}:{port}" + (f"/{tr}" if tr and tr != "tcp" else "")
            if smp not in e["samples"]:
                e["samples"].append(smp)
    return {"pairs": pairs, "intra": intra, "policy_pairs": policy_pairs}


def _empty() -> dict:
    return {"policies": [], "sessions": 0, "services": Counter(), "samples": [], "last_seen": None}


def _dir_out(e: dict) -> dict:
    return {"policies": e["policies"], "policy_count": len(e["policies"]), "sessions": e["sessions"],
            "services": [f"{k} ×{v}" for k, v in e["services"].most_common(10)],
            "samples": e["samples"], "last_seen": e["last_seen"]}


def conduit_view(db: DBSession, model: ZoneModel) -> dict:
    """Declared conduits with what flows through them, and the zone pairs
    with policies or traffic but no documented conduit."""
    from app.models import IecConduit
    flows = derive_flows(db, model)
    pairs = flows["pairs"]
    declared = {}
    for c in db.query(IecConduit).filter(IecConduit.site_id == model.site_id):
        if c.zone_a_id in model.zones and c.zone_b_id in model.zones:
            declared[(c.zone_a_id, c.zone_b_id)] = c
    rows = []
    attached = conduit_rules(db, model, list(declared.values()), flows["policy_pairs"])
    for (a, b), c in sorted(declared.items(), key=lambda kv: (model.zones[kv[0][0]].name.lower(),
                                                              model.zones[kv[0][1]].name.lower())):
        f = pairs.get((a, b)) or {"x_to_y": _empty(), "y_to_x": _empty()}
        za, zb = model.zones[a], model.zones[b]
        notes = []
        if not (f["x_to_y"]["policies"] or f["y_to_x"]["policies"] or f["x_to_y"]["sessions"]
                or f["y_to_x"]["sessions"]):
            notes.append("no permitting policy and no traffic found between these zones")
        hi = sl_max(za.sl_t, zb.sl_t)
        if sl_below(c.sl_t, hi):
            notes.append(f"conduit SL-T {c.sl_t} is below the zones it connects (SL-T {_sl_txt(za.sl_t)} / "
                         f"{_sl_txt(zb.sl_t)}); 62443-3-2 expects a conduit to meet the higher zone's target")
        target = c.sl_t if c.sl_t is not None else hi
        if sl_below(c.sl_a, target):
            notes.append(f"achieved SL-A {c.sl_a} is below the target SL-T {target}")
        fws = _conduit_firewalls(model, f)
        for fw in fws:
            if sl_below(fw["sl_c"], target):
                notes.append(f"{fw['name']} carries this conduit with SL-C {fw['sl_c']}, below its target SL-T "
                             f"{target}: document compensating countermeasures")
        rows.append({"id": c.id, "declared": True, "name": c.name, "sl_t": c.sl_t, "description": c.description,
                     "zone_a": _zone_ref(model, a), "zone_b": _zone_ref(model, b),
                     "a_to_b": _dir_out(f["x_to_y"]), "b_to_a": _dir_out(f["y_to_x"]), "notes": notes,
                     "target_sl": target, "firewalls": fws,
                     "sl_a": c.sl_a, "sl_a_note": c.sl_a_note, "sl_a_status": sl_a_status(c.sl_a, target),
                     "services": c.services, "sources": c.sources,
                     "created_by": c.created_by, "updated_at": c.updated_at,
                     **_rules_view(model, attached.get(c.id, []), f)})
    undocumented = []
    for (x, y), f in pairs.items():
        if isinstance(x, int) and isinstance(y, int) and (x, y) in declared:
            continue
        both_real = isinstance(x, int) and isinstance(y, int)
        undocumented.append({
            "declared": False, "declarable": both_real,
            "zone_a": _zone_ref(model, x), "zone_b": _zone_ref(model, y),
            "a_to_b": _dir_out(f["x_to_y"]), "b_to_a": _dir_out(f["y_to_x"]),
            "policy_count": len(f["x_to_y"]["policies"]) + len(f["y_to_x"]["policies"]),
            "sessions": f["x_to_y"]["sessions"] + f["y_to_x"]["sessions"],
        })
    undocumented.sort(key=lambda r: (not r["declarable"], -r["sessions"], -r["policy_count"],
                                     r["zone_a"]["name"].lower(), r["zone_b"]["name"].lower()))
    intra = [{"zone": _zone_ref(model, zid), "sessions": n} for zid, n in flows["intra"].most_common()]
    return {"conduits": rows, "undocumented": undocumented, "intra_zone": intra,
            "devices": device_summary(model, rows)}


# ------------------------------------------------ conduit firewall rules --
# Owner 2026-10-13: a conduit is named to its zones AND the firewall rule numbers
# that implement it; hovering a rule shows source, destination, allow / deny and
# the protocols / ports.  Documentation only (never read by the findings engine).
# The policies found automatically between the zones stay listed; one that is
# not attached carries a note.

def _norm_vdom(v) -> str:
    return (v or "").strip()


def policy_details(db: DBSession, model: ZoneModel, keys) -> dict:
    """(firewall id, vdom, policy id) -> what the policy does, from its
    FirewallRule rows: name, action (allow / deny), enabled, interfaces,
    source / destination values, services (proto/port), last hit."""
    from app.models import FirewallRule
    from app.parsers.fortios_zones import zone_tokens
    keys = {(fid, _norm_vdom(vd), str(pid)) for fid, vd, pid in keys}
    if not keys:
        return {}
    fids = sorted({k[0] for k in keys})
    pids = sorted({k[2] for k in keys})
    out = {}
    q = (db.query(FirewallRule).filter(FirewallRule.firewall_id.in_(fids), FirewallRule.policy_id.in_(pids))
         .order_by(FirewallRule.id))
    for r in q:
        k = (r.firewall_id, _norm_vdom(r.vdom), str(r.policy_id))
        if k not in keys:
            continue
        d = out.setdefault(k, {"policy_name": r.policy_name, "actions": set(), "enabled": False,
                               "src_intf": set(), "dst_intf": set(), "src": set(), "dst": set(),
                               "services": set(), "last_matched": None, "rows": 0})
        d["rows"] += 1
        d["policy_name"] = d["policy_name"] or r.policy_name
        d["actions"].add(str(r.action or "").lower())
        d["enabled"] = d["enabled"] or bool(r.enabled)
        for side, val in (("src_intf", r.src_zone), ("dst_intf", r.dst_zone)):
            if val:
                d[side].update(t for t in zone_tokens(val) if t)
        d["src"].add(r.src or "any")
        d["dst"].add(r.dst or "any")
        proto = str(r.protocol or "any").lower()
        port = str(r.dst_port or "any")
        d["services"].add("any" if proto in ("any", "all", "ip") and port in ("any", "", "None") else
                          (proto if port in ("any", "", "None") else f"{proto}/{port}"))
        if r.last_matched and (d["last_matched"] is None or r.last_matched > d["last_matched"]):
            d["last_matched"] = r.last_matched
    for d in out.values():
        acts = d.pop("actions")
        allow = acts & {"accept", "permit", "allow", "pass"}
        d["action"] = "allow" if allow and len(allow) == len(acts) else ("deny" if not allow else "mixed")
        for side in ("src_intf", "dst_intf", "src", "dst", "services"):
            vals = sorted(d[side], key=str)
            d[side] = vals[:40] + ([f"… +{len(vals) - 40}"] if len(vals) > 40 else [])
    return out


def conduit_rules(db: DBSession, model: ZoneModel, conduits, policy_pairs: dict) -> dict:
    """conduit id -> attached rules with their details and whether the policy
    connects the conduit's two zones (None for a deny rule / not judged)."""
    from app.models import IecConduitRule
    ids = [c.id for c in conduits]
    if not ids:
        return {}
    rows = (db.query(IecConduitRule).filter(IecConduitRule.site_id == model.site_id,
                                            IecConduitRule.conduit_id.in_(ids))
            .order_by(IecConduitRule.firewall_name, IecConduitRule.id).all())
    fw_by_name = {}
    for fw in model.infra.fws.values():
        fw_by_name.setdefault((fw.name or "").lower(), fw.id)
    keyed = []
    for r in rows:
        fid = fw_by_name.get((r.firewall_name or "").lower())
        keyed.append((r, fid, (fid, _norm_vdom(r.vdom), str(r.policy_id))))
    details = policy_details(db, model, [k for _r, fid, k in keyed if fid is not None])
    serves = {}
    for v in policy_pairs.values():
        serves[(v["firewall_id"], _norm_vdom(v["vdom"]), str(v["policy_id"]))] = {pk[:2] for pk in v["pairs"]}
    pair_of = {c.id: _pair_key(c.zone_a_id, c.zone_b_id)[:2] for c in conduits}     # either direction
    out = defaultdict(list)
    for r, fid, k in keyed:
        d = details.get(k)
        item = {"id": r.id, "firewall": r.firewall_name, "firewall_id": fid, "vdom": r.vdom or "",
                "policy_id": r.policy_id, "note": r.note, "found": d is not None,
                "firewall_found": fid is not None}
        if d is not None:
            item.update(d)
            if d["action"] == "allow" and d["enabled"]:
                item["connects_zones"] = pair_of[r.conduit_id] in serves.get(k, set())
            else:
                item["connects_zones"] = None
        out[r.conduit_id].append(item)
    return out


def _rules_view(model: ZoneModel, rules: list, f: dict) -> dict:
    """The conduit's attached rules, and the policies found between its zones
    marked attached / not attached (with a note for the latter)."""
    att = {(r["firewall_id"], _norm_vdom(r["vdom"]), str(r["policy_id"])) for r in rules if r.get("firewall_id")}
    not_attached = []
    for d in ("x_to_y", "y_to_x"):
        for p in f[d]["policies"]:
            k = (p.get("firewall_id"), _norm_vdom(p.get("vdom")), str(p.get("policy_id")))
            p["attached"] = k in att
            if not p["attached"] and p["policy"] not in not_attached:
                not_attached.append(p["policy"])
    notes = []
    if rules and not_attached:
        notes.append(f"{len(not_attached)} polic{'y' if len(not_attached) == 1 else 'ies'} found between these zones "
                     f"{'is' if len(not_attached) == 1 else 'are'} not attached to the conduit: "
                     + ", ".join(not_attached[:6]) + (" …" if len(not_attached) > 6 else ""))
    for r in rules:
        label = f"{r['firewall']} #{r['policy_id']}"
        if not r["firewall_found"]:
            notes.append(f"{label}: no firewall named {r['firewall']} in this site")
        elif not r["found"]:
            notes.append(f"{label}: the policy is not in the firewall's configuration (removed or renumbered?)")
        elif r.get("connects_zones") is False:
            notes.append(f"{label}: the policy does not connect these two zones")
    return {"rules": rules, "rule_notes": notes, "unattached_policies": not_attached}


def add_conduit_rules(db, site_id, conduit_id, firewall, policy_ids, vdom="", note=None, created_by=None) -> list:
    """Attach firewall policies (numbers) to a conduit.  ``firewall`` is the
    firewall name (or id); every policy must exist on it.  Returns the rows
    (existing ones included)."""
    from app.models import Firewall, FirewallRule, IecConduitRule
    c = get_conduit(db, site_id, conduit_id)
    fw = None
    if isinstance(firewall, int) or (isinstance(firewall, str) and firewall.strip().isdigit()):
        fw = db.query(Firewall).filter(Firewall.site_id == site_id, Firewall.id == int(firewall)).first()
    if fw is None and isinstance(firewall, str):
        from sqlalchemy import func as _func
        wanted = firewall.strip().lower()           # exact name, case-insensitive (no LIKE wildcards)
        fw = (db.query(Firewall).filter(Firewall.site_id == site_id)
              .filter((_func.lower(Firewall.name) == wanted) | (_func.lower(Firewall.device_name) == wanted)).first())
    if fw is None:
        raise ZoneError(f"no firewall {firewall!r} in this site")
    if isinstance(policy_ids, str):
        policy_ids = [t for t in re.split(r"[\s,;]+", policy_ids) if t]
    pids = []
    for t in policy_ids or []:
        t = str(t).strip().lstrip("#")
        if t and t not in pids:
            pids.append(t)
    if not pids:
        raise ZoneError("give at least one policy number")
    vdom = _norm_vdom(vdom)
    have = {}
    for r in db.query(FirewallRule.policy_id, FirewallRule.vdom).filter(FirewallRule.firewall_id == fw.id,
                                                                       FirewallRule.policy_id.in_(pids)):
        have.setdefault(str(r.policy_id), set()).add(_norm_vdom(r.vdom))
    missing = [p for p in pids if p not in have]
    if missing:
        raise ZoneError(f"{fw.name} has no polic{'y' if len(missing) == 1 else 'ies'} {', '.join(missing)}")
    out = []
    for pid in pids:
        if vdom and vdom not in have[pid]:
            raise ZoneError(f"{fw.name} policy {pid} is not in vdom {vdom}")
        if not vdom and len(have[pid]) > 1:
            raise ZoneError(f"{fw.name} has policy {pid} in several VDOMs ({', '.join(sorted(have[pid]))}): give the vdom")
        vd = vdom or next(iter(have[pid]))
        ex = (db.query(IecConduitRule).filter(IecConduitRule.conduit_id == c.id, IecConduitRule.firewall_name == fw.name,
                                              IecConduitRule.vdom == vd, IecConduitRule.policy_id == pid).first())
        if ex is None:
            ex = IecConduitRule(site_id=site_id, conduit_id=c.id, firewall_name=fw.name, vdom=vd, policy_id=pid,
                                note=_note(note) or None, created_by=created_by)
            db.add(ex)
            db.flush()
        out.append(ex)
    return out


def remove_conduit_rule(db, site_id, conduit_id, rule_id):
    from app.models import IecConduitRule
    r = (db.query(IecConduitRule).filter(IecConduitRule.id == rule_id, IecConduitRule.conduit_id == conduit_id,
                                         IecConduitRule.site_id == site_id).first())
    if r is None:
        raise ZoneError("rule not attached to this conduit", 404)
    db.delete(r)
    db.flush()
    return r


def _conduit_firewalls(model: ZoneModel, f: dict) -> list:
    ids = []
    for d in ("x_to_y", "y_to_x"):
        for p in f[d]["policies"]:
            if p.get("firewall_id") is not None and p["firewall_id"] not in ids:
                ids.append(p["firewall_id"])
    out = []
    for fid in ids:
        fw = model.infra.fws.get(fid)
        if fw is not None:
            out.append({"id": fw.id, "name": model.infra.fw_label(fw.id), "sl_c": fw.sl_c,
                        "sl_c_source": fw.sl_c_source})
    return out


def device_summary(model: ZoneModel, conduit_rows: list) -> list:
    """Every firewall / routing switch of the site with its SL-C and the
    documented conduits it carries (and the highest target among them)."""
    carries = defaultdict(list)
    for r in conduit_rows:
        for fw in r.get("firewalls") or []:
            carries[fw["id"]].append({"conduit": r.get("name") or f"{r['zone_a']['name']} ⇄ {r['zone_b']['name']}",
                                      "target_sl": r.get("target_sl")})
    out = []
    for fw in sorted(model.infra.fws.values(), key=lambda f: (f.name or "").lower()):
        cs = carries.get(fw.id, [])
        top = sl_max(*(c["target_sl"] for c in cs))
        out.append({"id": fw.id, "name": model.infra.fw_label(fw.id), "vendor": fw.vendor, "sl_c": fw.sl_c,
                    "sl_c_source": fw.sl_c_source, "conduits": cs, "highest_target": top,
                    "below_target": sl_below(fw.sl_c, top)})
    return out


# --------------------------------------------- conduit services / sources --
# Option 3 (owner, 2026-10-11): a documented conduit says what it is for.
# A finding on that conduit whose service - and source, when the conduit
# lists sources - is covered is shown one severity step lower, with the
# reason.  View-time only; never for the OT-egress checks.
SERVICE_PORTS = {
    "s7comm": ("tcp", 102), "s7": ("tcp", 102), "modbus": ("tcp", 502), "enip": ("tcp", 44818),
    "ethernet/ip": ("tcp", 44818), "ethernet_ip": ("tcp", 44818), "cip": ("tcp", 44818), "dnp3": ("tcp", 20000),
    "opcua": ("tcp", 4840), "opc-ua": ("tcp", 4840), "opc ua": ("tcp", 4840), "bacnet": ("udp", 47808),
    "iec104": ("tcp", 2404), "profinet": ("udp", 34964), "rdp": ("tcp", 3389), "ssh": ("tcp", 22),
    "telnet": ("tcp", 23), "vnc": ("tcp", 5900), "https": ("tcp", 443), "http": ("tcp", 80),
    "ftp": ("tcp", 21), "smb": ("tcp", 445), "ldap": ("tcp", 389), "ldaps": ("tcp", 636), "dns": ("udp", 53),
    "ntp": ("udp", 123), "snmp": ("udp", 161), "syslog": ("udp", 514), "winrm": ("tcp", 5985),
    "mqtt": ("tcp", 1883), "sql": ("tcp", 1433), "mssql": ("tcp", 1433), "kerberos": ("tcp", 88),
}
SEVERITY_STEP = {"critical": "high", "high": "medium", "medium": "low"}       # low / info stay


def parse_services(text) -> list:
    """'s7comm, enip, tcp/3389, 502, any' -> [(proto|None, port|None), ...];
    ('any', None) covers everything.  ZoneError on an unknown token."""
    out = []
    for tok in [t.strip() for t in str(text or "").split(",") if t.strip()]:
        low = tok.lower()
        if low in ("any", "all", "*"):
            out.append(("any", None))
            continue
        if low in SERVICE_PORTS:
            out.append(SERVICE_PORTS[low])
            continue
        proto, _, port = low.rpartition("/")
        proto = proto or None
        if proto not in (None, "tcp", "udp"):
            raise ZoneError(f"unknown service '{tok}': use a name (s7comm, modbus, rdp ...), tcp/PORT, udp/PORT, PORT or any")
        if port.isdigit() and 0 < int(port) < 65536:
            out.append((proto, int(port)))
            continue
        if port.lower() in SERVICE_PORTS:
            out.append((proto, SERVICE_PORTS[port.lower()][1]))
            continue
        raise ZoneError(f"unknown service '{tok}': use a name (s7comm, modbus, rdp ...), tcp/PORT, udp/PORT, PORT or any")
    return out


def parse_sources(text) -> list:
    out = []
    for tok in [t.strip() for t in str(text or "").split(",") if t.strip()]:
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            raise ZoneError(f"bad source '{tok}': use an address or CIDR")
    return out


def _check_services(text):
    text = (text or "").strip() if isinstance(text, str) or text is None else str(text)
    if not text:
        return None
    parse_services(text)
    return ", ".join(t.strip() for t in text.split(",") if t.strip())


def _check_sources(text):
    text = (text or "").strip() if isinstance(text, str) or text is None else str(text)
    if not text:
        return None
    return ", ".join(str(n) for n in parse_sources(text))


def service_covered(services: list, proto, port) -> bool:
    """Is (proto, port) of a finding inside the conduit's service list?  A
    finding with no port is covered only by 'any'."""
    if any(p == "any" for p, _ in services):
        return True
    if port is None:
        return False
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    proto = (str(proto).lower() if proto else None)
    if proto not in ("tcp", "udp"):
        proto = None
    for sp, spt in services:
        if spt == port and (sp is None or proto is None or sp == proto):
            return True
    return False


def _finding_service(d: dict):
    """(transport, port) of a finding's evidence, when it names one port."""
    port = None
    for k in ("dst_port", "port", "server_port"):
        v = d.get(k)
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            port = int(v)
            break
    tr = None
    for k in ("transport", "protocol", "proto"):
        v = str(d.get(k) or "").lower()
        if v in ("tcp", "udp"):
            tr = v
            break
    return tr, port


# ------------------------------------------------------ finding judgement --
# Device findings judged against the SL-T of the zone (or conduit) the device
# sits in.  View-time only: the finding row, its severity and whether it is
# raised are never touched (the engine does not import this module); the
# judgement is shown next to the finding and can be filtered on.
_FINDING_IP_KEYS = ("src_ip", "dst_ip", "ot_host_ip", "it_host_ip", "ntp_server_ip", "host_ip", "ip")
_FINDING_ADDR_KEYS = ("src", "dst")                     # policy addresses: used only when a single IP
VERDICT_LABEL = {"applies": "applies at the zone SL-T", "beyond": "beyond the zone SL-T",
                 "no_sl_t": "zone has no SL-T"}
# Owner rule (G4): no OT device may have direct Internet access.  These
# checks apply in every zone whatever its SL-T.
SITE_POLICY_CHECKS = frozenset({"session_ot_internet_egress", "path_ot_internet_egress",
                                "ot_internet_egress"})
SITE_POLICY_NOTE = "site policy: no OT device has direct Internet access (applies at every SL-T)"
# Documentation status of a finding with two ends (owner decision 2026-10-11,
# "option 2"): was this path designed and documented in the zone model?
DOC_LABEL = {"intra_zone": "inside one zone", "documented": "documented conduit",
             "undocumented": "no documented conduit", "partial": "other end in no zone",
             "external": "other end outside the site"}


def _single_ip(v) -> Optional[str]:
    if isinstance(v, list):
        v = v[0] if len(v) == 1 else None
    if not isinstance(v, str):
        return None
    v = v.strip()
    if v.endswith("/32"):
        v = v[:-3]
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return None


class FindingJudge:
    """Resolve a finding's device(s) to a zone and judge the finding's check
    level (lowest 62443-3-3 SL of its SRs) against that zone's SL-T.

    * one zone -> that zone's SL-T;
    * two zones (source / destination) -> the documented conduit's target
      (its SL-T, else the higher zone SL-T), else the higher zone SL-T;
    * a firewall finding (no host address, ``device_name`` is a firewall of
      the site) -> the highest target among the documented conduits it
      carries.

    ``verdict``: ``applies`` (check SL <= SL-T, or the check has no 3-3 SR),
    ``beyond`` (the requirement first applies above the zone's SL-T) or
    ``no_sl_t``.  None when the device is in no zone."""

    def __init__(self, db: DBSession, site_id: int):
        from app.models import IecConduit, IecZone
        self.db, self.site_id = db, site_id
        self.active = db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is not None
        self.model = ZoneModel(db, site_id) if self.active else None
        self.conduits = {}
        if self.active:
            for c in db.query(IecConduit).filter(IecConduit.site_id == site_id):
                if c.zone_a_id in self.model.zones and c.zone_b_id in self.model.zones:
                    self.conduits[(c.zone_a_id, c.zone_b_id)] = c
        self._devices = None
        self._host_by_ip = None

    def _device_targets(self) -> dict:
        if self._devices is None:
            view = conduit_view(self.db, self.model)
            self._devices = {d["id"]: d for d in view["devices"]}
        return self._devices

    def _conduit_target(self, a, b):
        za, zb = self.model.zones[a], self.model.zones[b]
        hi = sl_max(za.sl_t, zb.sl_t)
        c = self.conduits.get(tuple(sorted((a, b))))
        if c is None:
            return None, hi
        return (c.name or f"{za.name} ↔ {zb.name}"), (c.sl_t if c.sl_t is not None else hi)

    def _zone_of_address(self, ip, mac=None):
        """Zone of an address in a finding: the known host with that address
        (so a host member given by MAC counts), else the address itself."""
        if mac:
            return self.model.zone_of(ip, mac)[0]
        if self._host_by_ip is None:
            self._host_by_ip = {}
            for h in self.model.hosts:
                try:
                    self._host_by_ip.setdefault(str(ipaddress.ip_address(h.ip)), h)
                except ValueError:
                    pass
        try:
            h = self._host_by_ip.get(str(ipaddress.ip_address(ip)))
        except ValueError:
            h = None
        if h is not None:
            return self.model.host_zone.get(h.id, (None, None))[0]
        return self.model.zone_of(ip)[0]

    def _adjust(self, c, d: dict, check_name, addrs: list):
        """Reason the finding is lowered one step on conduit ``c`` (option
        3), or None.  Needs the conduit's services to cover the finding's
        service, and its sources (when set) to cover the finding's source;
        the OT-egress checks are never lowered."""
        if c is None or not c.services or check_name in SITE_POLICY_CHECKS:
            return None
        try:
            svcs = parse_services(c.services)
        except ZoneError:
            return None
        tr, port = _finding_service(d)
        if not service_covered(svcs, tr, port):
            return None
        if c.sources:
            src = _single_ip(d.get("src_ip")) or (addrs[0] if addrs else None)
            if not src:
                return None
            try:
                a = ipaddress.ip_address(src)
                if not any(a.version == n.version and a in n for n in parse_sources(c.sources)):
                    return None
            except (ValueError, ZoneError):
                return None
        name = c.name or "conduit"
        what = f"{tr or ''}/{port}".strip("/") if port else "any service"
        return (f"documented conduit '{name}' covers {what}" + (f" from {src}" if c.sources else "")
                + f" (services: {c.services}" + (f"; sources: {c.sources}" if c.sources else "") + ")")

    def _documentation(self, ends: list, zids: list):
        """intra_zone / documented / undocumented / partial / external for a
        finding whose evidence names two ends; None otherwise."""
        if len(ends) < 2 or not zids:
            return None
        if len(zids) >= 2:
            return "documented" if tuple(sorted(zids[:2])) in self.conduits else "undocumented"
        if all(e == zids[0] for e in ends):
            return "intra_zone"
        return "external" if "external" in ends else "partial"

    def _iface_sides(self, d: dict, device_name) -> tuple:
        """(source zone ids, destination zone ids) of a policy / path finding,
        from the firewall interfaces or FortiGate zones it names on each side.
        SF-6: a side naming several interfaces ("port1,port2") resolves to
        every zone among them."""
        from app.parsers import fortios_zones as _fz
        infra = self.model.infra
        fw = infra.fw(d.get("firewall_name") or d.get("device_name") or device_name or "")
        if fw is None:
            return [], []
        path = d.get("path") if isinstance(d.get("path"), dict) else {}
        sides = []
        for side, keys in (("src", ("src_zone", "srcintf", "source_zone")), ("dst", ("dst_zone", "dstintf", "dest_zone"))):
            v = next((d.get(k) for k in keys if d.get(k)), None)
            if v is None and isinstance(path.get(side), dict):
                v = path[side].get("zone")
            vals = v if isinstance(v, list) else [v]
            names = [t for x in vals if x not in (None, "") for t in _fz.zone_list(str(x))]
            zs = []
            for n in names:
                zid = self.model.iface_zone.get((fw.id, n.lower()))
                if zid is None:
                    members = infra.zone_def(fw.id, "", n) or []
                    found = {self.model.iface_zone.get((fw.id, m)) for m in members} - {None}
                    if not found:          # member interfaces' networks
                        found = {self._net_zone(fw.id, m) for m in members} - {None}
                    zid = found.pop() if len(found) == 1 else None
                if zid is None:            # SF-6: an interface that is no member - the zone of its network
                    zid = self._net_zone(fw.id, n)
                if zid is not None and zid not in zs:
                    zs.append(zid)
            sides.append(zs)
        return sides[0], sides[1]

    def _net_zone(self, fw_id, iface_name):
        """Zone whose network member covers the interface's network."""
        i = self.model.infra.iface_by_key.get((fw_id, (iface_name or "").lower()))
        n = _net(i.network_cidr) if i is not None else None
        if n is None:
            return None
        for net, zid, _basis in self.model.net_claims:          # most specific first
            if net.version == n.version and n.subnet_of(net):
                return zid
        return None

    def _iface_zones(self, d: dict, device_name) -> list:
        """Zones of the single-zone sides, source first (a multi-zone side is
        handled by ``judge`` as several conduits)."""
        out = []
        for side in self._iface_sides(d, device_name):
            if len(side) == 1 and side[0] not in out:
                out.append(side[0])
        return out

    def _multi(self, src: list, dst: list) -> dict:
        """SF-6: a policy whose side spans several zones is several conduits;
        judged against the strictest target, documented only if every pair is."""
        pairs = [(a, b) for a in src for b in dst if a != b]
        out_pairs, targets, documented = [], [], True
        for a, b in pairs:
            name, target = self._conduit_target(a, b)
            documented = documented and bool(name)
            targets.append(target)
            out_pairs.append({"zones": [self.model.zones[a].name, self.model.zones[b].name],
                              "conduit": name, "sl_t": target})
        if not pairs:
            targets = [self.model.zones[z].sl_t for z in src + dst]
        order = []
        for z in src + dst:
            if z not in order:
                order.append(z)
        return {"zones": [self.model.zones[z].name for z in order], "via": "conduits",
                "conduit": (", ".join(p["conduit"] for p in out_pairs) if pairs and documented else None),
                "zone_sl_t": sl_max(*targets), "pairs": out_pairs,
                "documentation": (None if not pairs else "documented" if documented else "undocumented")}

    def judge(self, detail, device_name=None, sr_text=None, check_name=None) -> Optional[dict]:
        if not self.active:
            return None
        from app.security_levels import security_level
        d = detail if isinstance(detail, dict) else {}
        addrs = []
        for k in _FINDING_IP_KEYS:
            ip = _single_ip(d.get(k))
            if ip and ip not in addrs:
                addrs.append(ip)
        policy_sides = None
        if not addrs:
            # a policy finding: each side from its single address, else from its interfaces
            pol = [_single_ip(d.get(k)) for k in _FINDING_ADDR_KEYS]
            if any(pol) and (d.get("src_zone") or d.get("dst_zone")):
                src_z, dst_z = self._iface_sides(d, device_name)
                sides = []
                for ip, side in zip(pol, (src_z, dst_z)):
                    zid = self._zone_of_address(ip) if ip else None
                    sides.append([zid] if isinstance(zid, int) else side)
                if sides[0] or sides[1]:
                    policy_sides = sides
            if policy_sides is None:
                for ip in pol:
                    if ip and ip not in addrs:
                        addrs.append(ip)
        macs = {d.get("src_ip"): d.get("src_mac"), d.get("dst_ip"): d.get("dst_mac")}
        zids = []
        ends = []                                   # per end: zone id | "external" | None
        for ip in addrs:
            zid = self._zone_of_address(ip, macs.get(ip))
            ends.append("external" if zid is None and _public(ip) else zid)
            if isinstance(zid, int) and zid not in zids:
                zids.append(zid)
        multi = None
        if not addrs:
            # policy / path findings: the firewall interfaces (or FortiGate
            # zones) on each side, resolved through interface members
            src_z, dst_z = policy_sides if policy_sides is not None else self._iface_sides(d, device_name)
            if len(src_z) > 1 or len(dst_z) > 1:
                multi = self._multi(src_z, dst_z)
            iface = [z for side in (src_z, dst_z) if len(side) == 1 for z in side]
            for zid in iface:
                if zid not in zids:
                    zids.append(zid)
            if iface:
                ends = iface
        out = {"zones": [], "conduit": None, "firewall": None, "via": None, "zone_sl_t": None,
               "documentation": self._documentation(ends, zids)}
        if multi is not None:
            out.update(multi)
        elif len(zids) == 1:
            z = self.model.zones[zids[0]]
            out.update(zones=[z.name], via="zone", zone_sl_t=z.sl_t)
        elif len(zids) >= 2:
            a, b = zids[0], zids[1]
            name, target = self._conduit_target(a, b)
            out.update(zones=[self.model.zones[a].name, self.model.zones[b].name],
                       via="conduit" if name else "zones", conduit=name, zone_sl_t=target)
        elif not addrs and device_name and self.model.infra.fw(device_name) is not None:
            fw = self.model.infra.fw(device_name)
            dev = self._device_targets().get(fw.id) or {}
            if not dev.get("conduits"):
                return None
            out.update(firewall=self.model.infra.fw_label(fw.id), via="firewall",
                       zones=[c["conduit"] for c in dev["conduits"]], zone_sl_t=dev.get("highest_target"))
        else:
            return None
        out["adjusted_severity"] = None
        out["adjustment"] = None
        if out["documentation"] == "documented" and multi is None:
            c = self.conduits.get(tuple(sorted(zids[:2])))
            out["adjustment"] = self._adjust(c, d, check_name, addrs)
        sl = security_level(sr_text)
        out["check_sl"] = sl
        t = out["zone_sl_t"]
        out["verdict"] = "no_sl_t" if t is None else ("applies" if sl is None or sl <= t else "beyond")
        out["note"] = None
        if check_name in SITE_POLICY_CHECKS:
            out["verdict"], out["note"] = "applies", SITE_POLICY_NOTE
        return out


def adjusted_severity(severity, judgement) -> str:
    """The severity to show: one step lower when the judgement carries an
    adjustment (option 3), else the stored severity."""
    sev = (severity or "info").lower()
    if judgement and judgement.get("adjustment"):
        return SEVERITY_STEP.get(sev, sev)
    return sev


def judge_findings(db: DBSession, rows) -> dict:
    """{finding id: judgement | None} for Finding rows (any mix of sites)."""
    judges, out = {}, {}
    for f in rows:
        sid = f.site_id
        if sid is None:
            out[f.id] = None
            continue
        if sid not in judges:
            judges[sid] = FindingJudge(db, sid)
        out[f.id] = judges[sid].judge(f.detail, f.device_name, f.isa62443_sr, f.check_name)
    return out


# ------------------------------------------------------------ candidates --
def candidates(db: DBSession, model: ZoneModel) -> dict:
    """What can be added as a member, with the zone each already belongs to."""
    from app.models import IecZoneMember, SubnetZone
    taken = {(m.kind, m.ref.lower()): m.zone_id for ms in model.members.values() for m, _r in ms}

    def zname(kind, ref):
        zid = taken.get((kind, ref.lower()))
        return model.zones[zid].name if zid in model.zones else None
    ifaces = []
    for i in sorted(model.infra.ifaces, key=lambda i: (model.infra.fw_label(i.firewall_id), i.name or "")):
        if (i.iface_type or "") in ("vdom-link", "npu-vlink", "vdom_link"):
            continue
        ref = f"{model.infra.fw_label(i.firewall_id)}/{i.name}"
        ifaces.append({"ref": ref, "network": i.network_cidr, "vlan_id": i.vlan_id, "purdue_level": i.purdue_level,
                       "type": i.iface_type, "zone_label": i.zone_label, "zone": zname("interface", ref)})
    fwz = []
    for key, members in sorted(model.infra.zdefs.items(), key=lambda kv: kv[0]):
        fw_id = key[0]
        vdom, name = model.infra.zdef_names.get(key, (key[1], key[2]))
        ref = f"{model.infra.fw_label(fw_id)}/{vdom}/{name}"
        fwz.append({"ref": ref, "members": members, "zone": zname("fw_zone", ref)})
    nets = set()
    for z in db.query(SubnetZone.cidr).filter(SubnetZone.site_id == model.site_id):
        if _net(z[0]):
            nets.add(str(_net(z[0])))
    for i in model.infra.ifaces:
        if _net(i.network_cidr):
            nets.add(str(_net(i.network_cidr)))
    subnets = [{"ref": n, "zone": zname("subnet", n)} for n in sorted(nets, key=lambda n: _ip_key(n.split("/")[0]))]
    hosts = []
    for h in sorted(model.hosts, key=lambda h: _ip_key(h.ip)):
        if _public(h.ip) or h.ip in model.infra.iface_ips:
            continue
        zid, basis = model.host_zone[h.id]
        hosts.append({"ref": f"mac:{h.mac.lower()}" if h.mac else f"ip:{h.ip}", "ip": h.ip, "mac": h.mac,
                      "hostname": h.hostname, "device_type": h.device_type, "purdue_level": h.purdue_level,
                      "zone": model.zones[zid].name if zid in model.zones else None, "basis": basis})
    return {"interfaces": ifaces, "fw_zones": fwz, "subnets": subnets, "hosts": hosts}


# ----------------------------------------------------------------- writes --
# IEC 62443 security levels (owner 2026-10-13): SL0 is a real level ("no
# requirements"), distinct from "not set" (None).  An SL-T of 0 is never a target
# anything falls below; an SL-C / SL-A of 0 is below any SL-T of 1 or more.
from app.security_levels import SL_LABELS, SL_VALUE_ERROR as _SL_ERROR, parse_level_value  # noqa: E402


def _sl_number(v) -> int:
    try:
        return parse_level_value(v)
    except ValueError:
        raise ZoneError(_SL_ERROR)


def parse_sl(v) -> int:
    """'3', 3, 'SL3', 'SL-C 3', 'SL0 - No Requirements' -> 3 / 0 (ZoneError unless 0-4)."""
    try:
        return _sl_number(v)
    except (ValueError, TypeError):
        raise ZoneError(_SL_ERROR)


def sl_set(v) -> bool:
    """A level is recorded (0 counts; None = not set)."""
    return v is not None


def sl_max(*vals) -> Optional[int]:
    """Highest recorded level, None when none is recorded (0 counts)."""
    vs = [v for v in vals if v is not None]
    return max(vs) if vs else None


def sl_below(value, target) -> bool:
    """``value`` (SL-C / SL-A) is below ``target`` (SL-T): both recorded and
    value < target - an SL-T of 0 is never a target anything falls below."""
    return value is not None and target is not None and value < target


def _sl_txt(v) -> str:
    return "-" if v is None else str(v)


def _sl_csv(v):
    return "" if v is None else v


def _check_sl(v, field="sl_t"):
    if v in (None, "") or (isinstance(v, str) and v.strip().lower() in ("none", "not assessed", "not set")):
        return None
    try:
        return _sl_number(v)
    except ZoneError:
        raise ZoneError(f"{field}: {_SL_ERROR}")


def _note(v):
    v = (v or "").strip() if isinstance(v, str) or v is None else str(v)
    if len(v) > 255:
        raise ZoneError("sl_a_note is limited to 255 characters")
    return v or None


def create_zone(db, site_id, name, sl_t=None, description=None, owner=None, created_by=None,
                sl_a=None, sl_a_note=None):
    from app.models import IecZone
    name = (name or "").strip()
    if not name:
        raise ZoneError("name is required")
    if db.query(IecZone).filter(IecZone.site_id == site_id, IecZone.name == name).first():
        raise ZoneError(f"a zone named '{name}' already exists", 409)
    z = IecZone(site_id=site_id, name=name, sl_t=_check_sl(sl_t), description=description, owner=owner,
                created_by=created_by, sl_a=_check_sl(sl_a, "sl_a"), sl_a_note=_note(sl_a_note))
    db.add(z)
    db.flush()
    return z


def update_zone(db, site_id, zone_id, fields: dict):
    from app.models import IecZone
    z = get_zone(db, site_id, zone_id)
    if "name" in fields and fields["name"] is not None:
        nm = fields["name"].strip()
        if not nm:
            raise ZoneError("name cannot be empty")
        dup = db.query(IecZone).filter(IecZone.site_id == site_id, IecZone.name == nm, IecZone.id != z.id).first()
        if dup:
            raise ZoneError(f"a zone named '{nm}' already exists", 409)
        z.name = nm
    if "sl_t" in fields:
        z.sl_t = _check_sl(fields["sl_t"])
    if "sl_a" in fields:
        z.sl_a = _check_sl(fields["sl_a"], "sl_a")
    if "sl_a_note" in fields:
        z.sl_a_note = _note(fields["sl_a_note"])
    for k in ("description", "owner"):
        if k in fields:
            setattr(z, k, fields[k])
    db.flush()
    return z


def get_zone(db, site_id, zone_id):
    from app.models import IecZone
    z = db.query(IecZone).filter(IecZone.id == zone_id, IecZone.site_id == site_id).first()
    if z is None:
        raise ZoneError("zone not found", 404)
    return z


def add_member(db, site_id, zone_id, kind, ref, note=None, created_by=None, move=False):
    from app.models import IecZoneMember
    z = get_zone(db, site_id, zone_id)
    ref = normalize_ref(kind, ref)
    existing = db.query(IecZoneMember).filter(IecZoneMember.site_id == site_id, IecZoneMember.kind == kind,
                                              IecZoneMember.ref == ref).all()
    same = next((e for e in existing if e.zone_id == z.id), None)
    if same is not None and not (move and len(existing) > 1):
        return same, False
    if existing:
        if move:                       # relocate (every placement of the asset) into this zone
            ex = same or existing[0]
            for extra in existing:
                if extra is not ex:
                    db.delete(extra)
            ex.zone_id = z.id
            if note is not None:
                ex.note = note
            db.flush()
            return ex, True
        # owner (2026-10-11): an asset in several zones is never refused - it is a zone
        # documentation error reported by host_in_multiple_zones / network_in_multiple_zones
    m = IecZoneMember(site_id=site_id, zone_id=z.id, kind=kind, ref=ref, note=note, created_by=created_by)
    db.add(m)
    db.flush()
    return m, True


def remove_member(db, site_id, member_id):
    from app.models import IecZoneMember
    m = db.query(IecZoneMember).filter(IecZoneMember.id == member_id, IecZoneMember.site_id == site_id).first()
    if m is None:
        raise ZoneError("member not found", 404)
    db.delete(m)
    db.flush()
    return m


def delete_zone(db, site_id, zone_id):
    from app.models import IecConduit, IecConduitRule, IecZoneMember
    z = get_zone(db, site_id, zone_id)
    db.query(IecZoneMember).filter(IecZoneMember.zone_id == z.id).delete(synchronize_session=False)
    gone = [c.id for c in db.query(IecConduit.id).filter((IecConduit.zone_a_id == z.id) | (IecConduit.zone_b_id == z.id))]
    if gone:
        db.query(IecConduitRule).filter(IecConduitRule.conduit_id.in_(gone)).delete(synchronize_session=False)
    db.query(IecConduit).filter((IecConduit.zone_a_id == z.id) | (IecConduit.zone_b_id == z.id)).delete(
        synchronize_session=False)
    db.delete(z)
    db.flush()
    return z


def upsert_conduit(db, site_id, zone_a_id, zone_b_id, name=None, sl_t=None, description=None, created_by=None,
                   sl_a=None, sl_a_note=None, services=None, sources=None):
    from app.models import IecConduit
    if zone_a_id == zone_b_id:
        raise ZoneError("a conduit joins two different zones")
    a, b = sorted((int(zone_a_id), int(zone_b_id)))
    get_zone(db, site_id, a)
    get_zone(db, site_id, b)
    c = db.query(IecConduit).filter(IecConduit.site_id == site_id, IecConduit.zone_a_id == a,
                                    IecConduit.zone_b_id == b).first()
    created = c is None
    if created:
        c = IecConduit(site_id=site_id, zone_a_id=a, zone_b_id=b, created_by=created_by)
        db.add(c)
    c.name = (name or "").strip() or c.name
    c.sl_t = _check_sl(sl_t) if sl_t is not None else c.sl_t
    c.sl_a = _check_sl(sl_a, "sl_a") if sl_a is not None else c.sl_a
    if sl_a_note is not None:
        c.sl_a_note = _note(sl_a_note)
    if services is not None:
        c.services = _check_services(services)
    if sources is not None:
        c.sources = _check_sources(sources)
    if description is not None:
        c.description = description
    db.flush()
    return c, created


def update_conduit(db, site_id, conduit_id, fields: dict):
    c = get_conduit(db, site_id, conduit_id)
    if "name" in fields:
        c.name = (fields["name"] or "").strip() or None
    if "sl_t" in fields:
        c.sl_t = _check_sl(fields["sl_t"])
    if "sl_a" in fields:
        c.sl_a = _check_sl(fields["sl_a"], "sl_a")
    if "sl_a_note" in fields:
        c.sl_a_note = _note(fields["sl_a_note"])
    if "services" in fields:
        c.services = _check_services(fields["services"])
    if "sources" in fields:
        c.sources = _check_sources(fields["sources"])
    if "description" in fields:
        c.description = fields["description"]
    db.flush()
    return c


def get_conduit(db, site_id, conduit_id):
    from app.models import IecConduit
    c = db.query(IecConduit).filter(IecConduit.id == conduit_id, IecConduit.site_id == site_id).first()
    if c is None:
        raise ZoneError("conduit not found", 404)
    return c


def assign_from_inventory(db, site_id, host, zone_name: str, created_by: str = "asset inventory") -> str:
    """Asset Inventory CSV ``zone`` column: put ``host`` in the zone of that
    name (created when missing) as a host member (MAC, else address).
    Returns ``created`` (zone created, host added) / ``added`` / ``already`` (in that zone) /
    ``also_in:<zone>`` (added; the host was already a member of another zone and now sits in both -
    the host_in_multiple_zones check reports it) / ``skipped`` (no identity)."""
    from app.models import IecZone, IecZoneMember
    name = (zone_name or "").strip()[:128]
    if not name:
        return "skipped"
    if host.mac:
        ref = "mac:" + host.mac.lower()
    elif host.ip:
        try:
            ref = "ip:" + str(ipaddress.ip_address(host.ip))
        except ValueError:
            return "skipped"
    else:
        return "skipped"
    z = db.query(IecZone).filter(IecZone.site_id == site_id, IecZone.name == name).first()
    keys = [ref] + ([f"ip:{host.ip}"] if host.mac and host.ip else [])
    existing = (db.query(IecZoneMember).filter(IecZoneMember.site_id == site_id, IecZoneMember.kind == "host",
                                               IecZoneMember.ref.in_(keys)).all())
    if z is not None and any(e.zone_id == z.id for e in existing):
        return "already"
    created = z is None
    if created:
        z = IecZone(site_id=site_id, name=name, created_by=created_by,
                    description="Created from the Asset Inventory CSV")
        db.add(z)
        db.flush()
    db.add(IecZoneMember(site_id=site_id, zone_id=z.id, kind="host", ref=ref, created_by=created_by,
                         note="from the Asset Inventory CSV"))
    db.flush()
    if existing:                       # the host is now in several zones (dual-homed / multi-VLAN): reported, and a finding
        other = db.get(IecZone, existing[0].zone_id)
        return f"also_in:{other.name if other else existing[0].zone_id}"
    return "created" if created else "added"


def set_host_zone(db, site_id, host, zone_name: str, created_by: str = "inventory page") -> str:
    """Asset Inventory zone field (owner 2026-10-13): make ``zone_name`` the
    host's own IEC 62443 zone.  Its existing host-member placements (by MAC or
    address) are removed first, then it is added to the named zone (created
    when missing).  An empty name only removes them - a zone the address
    inherits from a subnet / interface / FortiGate zone member stays.
    Returns ``removed`` / ``created`` / ``added`` / ``already`` / ``skipped``."""
    from app.models import IecZone, IecZoneMember
    name = (zone_name or "").strip()[:128]
    keys = []
    if host.mac:
        keys.append("mac:" + host.mac.lower())
    if host.ip:
        try:
            keys.append("ip:" + str(ipaddress.ip_address(host.ip)))
        except ValueError:
            pass
    if not keys:
        return "skipped"
    own = (db.query(IecZoneMember).filter(IecZoneMember.site_id == site_id, IecZoneMember.kind == "host",
                                          IecZoneMember.ref.in_(keys)).all())
    if name:
        z = db.query(IecZone).filter(IecZone.site_id == site_id, IecZone.name == name).first()
        if z is not None and own and all(m.zone_id == z.id for m in own):
            return "already"
    for m in own:
        db.delete(m)
    db.flush()
    if not name:
        return "removed"
    status = assign_from_inventory(db, site_id, host, name, created_by=created_by)
    return "added" if status.startswith("also_in:") else status


def host_zone_index(db, hosts) -> dict:
    """host id -> [{"id", "name", "sl_t", "basis"}]: the IEC 62443 zones of each
    address (its own host member first, else the zone of its network), for the
    Asset Inventory.  One ZoneModel per site that has zones."""
    from app.models import IecZone
    out = {}
    by_site = defaultdict(list)
    for h in hosts:
        if h.site_id is not None:
            by_site[h.site_id].append(h)
    for sid, rows in by_site.items():
        if not db.query(IecZone.id).filter(IecZone.site_id == sid).first():
            continue
        model = ZoneModel(db, sid)
        for h in rows:
            zs = model.addr_zones.get(h.id)
            if zs is None:
                zid, basis = model.zone_of(h.ip, h.mac)
                zs = [(zid, basis)] if zid is not None else []
            out[h.id] = [{"id": zid, "name": model.zones[zid].name, "sl_t": model.zones[zid].sl_t, "basis": basis}
                         for zid, basis in zs if zid in model.zones]
    return out


def import_zones(db, site_id, source: str, created_by=None) -> dict:
    """Seed zones: ``subnet_zones`` (one zone per zone name on Subnets &
    Zones, its subnets as members) or ``fortigate`` (one zone per FortiOS
    zone, the zone as member).  Existing zones / members are kept; an
    asset already in a zone is skipped."""
    from app.models import IecZone, IecZoneMember, SubnetZone
    stats = {"zones_created": 0, "members_added": 0, "members_skipped": 0}
    existing = {z.name: z for z in db.query(IecZone).filter(IecZone.site_id == site_id)}
    taken = {(m.kind, m.ref) for m in db.query(IecZoneMember).filter(IecZoneMember.site_id == site_id)}
    plan = []
    if source == "subnet_zones":
        for sz in db.query(SubnetZone).filter(SubnetZone.site_id == site_id).order_by(SubnetZone.cidr):
            if _net(sz.cidr) is None:
                continue
            name = sz.zone_name or (f"L{sz.purdue_level} {sz.cidr}" if sz.purdue_level is not None else sz.cidr)
            plan.append((name, "subnet", str(_net(sz.cidr))))
    elif source == "fortigate":
        infra = _Infra(db, site_id)
        from app.models import FirewallZoneDef
        for z in db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id.in_(list(infra.fws) or [-1])):
            fwl = infra.fw_label(z.firewall_id)
            plan.append((z.name if (z.kind or "zone") == "zone" else f"{z.name} ({z.kind})", "fw_zone",
                         f"{fwl}/{z.vdom or ''}/{z.name}"))
    else:
        raise ZoneError("source must be 'subnet_zones' or 'fortigate'")
    for name, kind, ref in plan:
        z = existing.get(name)
        if z is None:
            z = IecZone(site_id=site_id, name=name[:128], created_by=created_by,
                        description=f"Imported from {'Subnets & Zones' if source == 'subnet_zones' else 'the FortiGate config'}")
            db.add(z)
            db.flush()
            existing[name] = z
            stats["zones_created"] += 1
        if (kind, ref) in taken:
            stats["members_skipped"] += 1
            continue
        db.add(IecZoneMember(site_id=site_id, zone_id=z.id, kind=kind, ref=ref, created_by=created_by))
        taken.add((kind, ref))
        stats["members_added"] += 1
    db.flush()
    return stats


# ----------------------------------------------------------------- export --
def export_csv(db: DBSession, model: ZoneModel, table: str) -> str:
    """CSV of ``zones`` (one row per member), ``assets`` (one row per host
    with its zone) or ``conduits`` (one row per conduit / undocumented pair
    and direction)."""
    from app.api.routes import _csv_safe_row
    out = io.StringIO()
    if table == "zones":
        cols = ["zone", "sl_t", "sl_a", "sl_a_status", "sl_a_note", "description", "owner", "purdue_levels",
                "host_count", "sl_c_assessed",
                "sl_c_below_target", "member_kind", "member", "member_found", "member_networks", "member_note"]
        w = csv.DictWriter(out, fieldnames=cols, lineterminator="\r\n")
        w.writeheader()
        for z in zone_summary(model):
            base = {"zone": z["name"], "sl_t": _sl_csv(z["sl_t"]), "sl_a": _sl_csv(z["sl_a"]),
                    "sl_a_status": (z["sl_a_status"] or "").replace("_", " "), "sl_a_note": z["sl_a_note"] or "",
                    "description": z["description"] or "",
                    "owner": z["owner"] or "", "purdue_levels": " ".join(f"L{l:g}" for l in z["purdue_levels"]),
                    "host_count": z["host_count"], "sl_c_assessed": z["sl_c"]["assessed"],
                    "sl_c_below_target": " ".join(f"{b['ip']}=SL-C{b['sl_c']}" for b in z["sl_c"]["below_target"])}
            if not z["members"]:
                w.writerow(_csv_safe_row({**base, "member_kind": "", "member": "", "member_found": "",
                                          "member_networks": "", "member_note": ""}))
            for m in z["members"]:
                w.writerow(_csv_safe_row({**base, "member_kind": m["kind"], "member": m["ref"],
                                          "member_found": "yes" if m["found"] else "no",
                                          "member_networks": " ".join(m["networks"]), "member_note": m["note"] or ""}))
    elif table == "assets":
        cols = ["ip", "mac", "hostname", "device_type", "purdue_level", "zone", "sl_t", "other_zones", "sl_c",
                "sl_c_source", "sl_c_below_sl_t", "basis"]
        w = csv.DictWriter(out, fieldnames=cols, lineterminator="\r\n")
        w.writeheader()
        for h in sorted(model.hosts, key=lambda h: _ip_key(h.ip)):
            zid, basis = model.host_zone[h.id]
            z = model.zones.get(zid)
            w.writerow(_csv_safe_row({"ip": h.ip, "mac": h.mac or "", "hostname": h.hostname or "",
                                      "device_type": h.device_type or "",
                                      "purdue_level": "" if h.purdue_level is None else h.purdue_level,
                                      "zone": z.name if z else ("" if basis else NO_ZONE),
                                      "sl_t": _sl_csv(z.sl_t) if z else "",
                                      "other_zones": "; ".join(f"{model.zones[oz].name} ({oip})"
                                                               for oz, _ob, oip in model.device_zones(h) if oz != zid),
                                      "sl_c": _sl_csv(h.sl_c), "sl_c_source": h.sl_c_source or "",
                                      "sl_c_below_sl_t": ("yes" if z and sl_below(h.sl_c, z.sl_t)
                                                          else "no" if z and z.sl_t is not None and h.sl_c is not None
                                                          else ""),
                                      "basis": basis or ""}))
    elif table == "conduits":
        view = conduit_view(db, model)
        cols = ["conduit", "documented", "sl_t", "sl_a", "sl_a_status", "conduit_services", "conduit_sources", "from_zone", "from_sl_t", "to_zone", "to_sl_t", "policies",
                "sessions", "services", "firewalls_sl_c", "notes", "description"]
        w = csv.DictWriter(out, fieldnames=cols, lineterminator="\r\n")
        w.writeheader()
        for r in view["conduits"] + view["undocumented"]:
            for fz, tz, d in ((r["zone_a"], r["zone_b"], r["a_to_b"]), (r["zone_b"], r["zone_a"], r["b_to_a"])):
                if r["declared"] or d["policy_count"] or d["sessions"]:
                    w.writerow(_csv_safe_row({
                        "conduit": r.get("name") or "", "documented": "yes" if r["declared"] else "no",
                        "sl_t": _sl_csv(r.get("sl_t")), "sl_a": _sl_csv(r.get("sl_a")),
                        "sl_a_status": (r.get("sl_a_status") or "").replace("_", " "),
                        "conduit_services": r.get("services") or "", "conduit_sources": r.get("sources") or "",
                        "from_zone": fz["name"], "from_sl_t": _sl_csv(fz.get("sl_t")),
                        "to_zone": tz["name"], "to_sl_t": _sl_csv(tz.get("sl_t")),
                        "policies": "; ".join(p["policy"] + " [" + ", ".join(p["services"]) + "]"
                                              for p in d["policies"]),
                        "sessions": d["sessions"], "services": "; ".join(d["services"]),
                        "firewalls_sl_c": "; ".join(f"{fw['name']}=" + (f"SL-C{fw['sl_c']}" if fw["sl_c"] is not None else "not assessed")
                                                    for fw in (r.get("firewalls") or [])),
                        "notes": " | ".join(r.get("notes") or []), "description": r.get("description") or ""}))
    else:
        raise ZoneError("table must be zones, assets or conduits")
    return "﻿" + out.getvalue()
