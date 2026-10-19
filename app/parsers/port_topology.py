"""
Firewall Ports (owner 2026-10-17): every firewall / routing switch of a site as
its front: the physical ports (aggregates as one port naming their members),
what rides on each - the untagged subnet, the VLAN sub-interfaces with their
subnets, zone, Purdue label / declaration, alias, host count - and the
permitted services between ports from the enabled permit rules (hover on the
page).  View only: nothing here changes a rule, a host or a finding.

Audit 2026-10-17: runs under the site's analysis scope; zones come from the
zone definitions (every vendor, keyed by firewall id); policies naming several
interfaces, a zone, ``any`` or nothing (ASA inbound ACLs) are expanded;
cleartext / management ports inside multi-port services are flagged; hosts on
a network two firewalls share count on both.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from sqlalchemy.orm import Session as DBSession

_AGG_TYPES = ("aggregate", "redundant", "lag", "port-channel", "etherchannel")
_SWITCH_TYPES = ("hard-switch", "switch")
_SUB_TYPES = ("vlan", "subinterface", "sub-interface")
_OTHER_TYPES = ("loopback", "tunnel", "vdom-link", "npu-vlink", "ssl", "ipsec", "emac-vlan")
_SUB_ALIAS_RE = re.compile(r"^([A-Za-z][\w/-]*?)\.(\d+)\b")      # "GigabitEthernet0/1.100 (security-level 50)"


def _aggregate_members(text: str) -> dict:
    """{member interface name (lower): aggregate / switch name} from a stored FortiOS config."""
    out, cur, in_sec, depth, kind, members = {}, None, False, 0, None, []
    for raw in (text or "").splitlines():
        t = raw.strip()
        tl = t.lower()
        if not in_sec:
            if tl == "config system interface":
                in_sec, depth = True, 1
            continue
        if tl.startswith("config "):
            depth += 1
        elif tl == "end":
            depth -= 1
            if depth == 0:
                in_sec = False
            continue
        if depth != 1:
            continue
        if tl.startswith("edit "):
            cur, kind, members = t[5:].strip().strip('"'), None, []
        elif tl.startswith("set type "):
            kind = tl[9:].strip().strip('"')
        elif tl.startswith("set member "):
            members = [m.strip().strip('"') for m in re.findall(r'"[^"]*"|\S+', t[11:]) if m.strip().strip('"')]
        elif tl == "next" and cur is not None:
            if kind in _AGG_TYPES or kind in _SWITCH_TYPES:
                for m in members:
                    out[m.lower()] = cur
            cur = None
    return out


def _svc(protocol, dst_port) -> str:
    p = str(protocol or "any").lower()
    port = str(dst_port or "any").lower()
    if p in ("any", "all", "ip", "") and port in ("any", "all", ""):
        return "ALL"
    if port in ("any", "all", ""):
        return p
    return f"{p}/{port}"


def _ports_of(svc: str) -> list:
    """[(lo, hi)] of a tcp/udp service, [] for anything else."""
    m = re.match(r"^(tcp|udp)/(.+)$", svc)
    if not m:
        return []
    try:
        from app.parsers.rule_match import parse_ports
        return list(parse_ports(m.group(2)) or [])
    except Exception:
        return []


def _svc_kind(svc: str, cleartext: set, mgmt: set) -> str:
    """cleartext-mgmt / cleartext / mgmt when any port of the service is one; wide for
    spans over 1024 ports; any for ALL; icmp; else ok."""
    if svc == "ALL":
        return "any"
    if svc.startswith("icmp"):
        return "icmp"
    ranges = _ports_of(svc)
    if not ranges:
        return "ok"
    if any(hi - lo >= 1024 for lo, hi in ranges):
        return "wide"
    hit_c = any(lo <= p <= hi for lo, hi in ranges for p in cleartext)
    hit_m = any(lo <= p <= hi for lo, hi in ranges for p in mgmt)
    if hit_c and hit_m:
        return "cleartext-mgmt"
    return "cleartext" if hit_c else "mgmt" if hit_m else "ok"


def zone_memberships(db, fws: list, ifaces: list) -> dict:
    """{(firewall id, zone name lower): {interface name lower}} from the zone
    definitions (FortiOS, PAN-OS, ASA; keyed by firewall id, VDOM-qualified
    names included).  A firewall without zone definitions (older uploads, the
    demo seed) falls back to the legacy per-interface zone rows of its own
    site, matched by the firewall's name or device name and only for
    interfaces the firewall actually has - so two firewalls sharing a name
    cannot swap zones."""
    from app.models import FirewallZone, FirewallZoneDef
    out: dict = defaultdict(set)
    fw_ids = [f.id for f in fws]
    have = set()
    for z in db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id.in_(fw_ids) if fw_ids else False):
        have.add(z.firewall_id)
        for m in (z.members or []):
            out[(z.firewall_id, str(z.name).lower())].add(str(m).lower())
            if z.vdom:
                out[(z.firewall_id, f"{z.vdom}/{z.name}".lower())].add(str(m).lower())
    rest = [f for f in fws if f.id not in have]
    if rest:
        names_of = defaultdict(set)
        for i in ifaces:
            names_of[i.firewall_id].add(str(i.name).lower())
        by_name = defaultdict(list)
        for f in rest:
            for n in (f.name, f.device_name):
                if n:
                    by_name[(f.site_id, str(n).lower())].append(f)
        sites = {f.site_id for f in rest}
        for z in db.query(FirewallZone).filter(FirewallZone.site_id.in_(list(sites))):
            if not z.zone_name or not z.interface_name:
                continue
            iname, zname = str(z.interface_name).lower(), str(z.zone_name).lower()
            if iname == zname:
                continue                        # no zone: the row just repeats the interface
            for f in by_name.get((z.site_id, str(z.device_name or "").lower()), ()):
                if iname in names_of.get(f.id, ()):
                    out[(f.id, zname)].add(iname)
    return out


def _level(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _vlan_sort(v):
    try:
        return (0, int(str(v)))
    except (TypeError, ValueError):
        return (1, 0)


def build(db: DBSession, site_id: int, session_limit: int = 50000) -> dict:
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, site_id):
        return _build(db, site_id, session_limit)


def _build(db: DBSession, site_id: int, session_limit: int) -> dict:
    from app import config_store
    from app.models import (Firewall, FirewallInterface, FirewallRule, FirewallZone, FirewallZoneDef, Host,
                            NetworkSession, SubnetZone, real_host_clause)
    from app.parsers.alert_engine import _CLEARTEXT_PROTO_PORTS, _MGMT_PROTO_PORTS
    from app.parsers.l3_switch import VENDOR as _SWITCH_VENDOR
    from app.parsers.rule_match import format_ports, parse_ports

    cleartext, mgmt = set(_CLEARTEXT_PROTO_PORTS), set(_MGMT_PROTO_PORTS)
    fws = db.query(Firewall).filter(Firewall.site_id == site_id).order_by(Firewall.id).all()
    if not fws:
        return {"site_id": site_id, "firewalls": [], "links": [], "hosts_counted": 0, "sessions_truncated": False}
    fw_ids = [f.id for f in fws]
    switch_ids = {f.id for f in fws if f.vendor == _SWITCH_VENDOR}
    ifaces = db.query(FirewallInterface).filter(FirewallInterface.firewall_id.in_(fw_ids)).order_by(FirewallInterface.id).all()
    by_id = {i.id: i for i in ifaces}
    # zones -> member interfaces (zone definitions, else the legacy zone rows), keyed by firewall id
    zone_members = zone_memberships(db, fws, ifaces)      # (fw id, zone name lower) -> {iface name lower}
    zones_of_iface: dict = defaultdict(list)              # (fw id, iface name lower) -> [zone names]
    zone_display: dict = {}
    for z in db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id.in_(fw_ids)):
        zone_display[(z.firewall_id, str(z.name).lower())] = str(z.name)
    for z in db.query(FirewallZone).filter(FirewallZone.site_id == site_id):
        if z.zone_name:
            zone_display.setdefault(("*", str(z.zone_name).lower()), str(z.zone_name))
    for (fid, zl), members in sorted(zone_members.items()):
        if "/" in zl and (fid, zl.split("/", 1)[1]) in zone_members:
            continue                                      # the VDOM-qualified twin of a zone
        shown = zone_display.get((fid, zl)) or zone_display.get(("*", zl)) or zl
        for ml in members:
            if shown not in zones_of_iface[(fid, ml)]:
                zones_of_iface[(fid, ml)].append(shown)
    # declarations
    decl = []
    for z in db.query(SubnetZone).filter(SubnetZone.site_id == site_id):
        try:
            decl.append((ipaddress.ip_network(z.cidr, strict=False), z))
        except (ValueError, TypeError):
            pass
    decl.sort(key=lambda x: -x[0].prefixlen)
    # interface networks, most specific first; a network two firewalls share counts its hosts on both
    nets = []
    for i in ifaces:
        try:
            n = ipaddress.ip_network(i.network_cidr, strict=False) if i.network_cidr else None
        except ValueError:
            n = None
        if n is not None and 0 < n.prefixlen < n.max_prefixlen:
            nets.append((n, i.id))
    nets.sort(key=lambda x: -x[0].prefixlen)
    host_ifaces: dict = {}             # host id -> [interface ids] (every interface of the most specific network)
    host_count: dict = defaultdict(int)
    for h in db.query(Host).filter(real_host_clause(), Host.site_id == site_id, Host.ip.isnot(None),
                                   Host.inventory_excluded.is_not(True)):
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            continue
        best = None
        ids = []
        for n, iid in nets:
            if n.version != a.version or a not in n:
                continue
            if best is None:
                best = n
            if n == best:
                ids.append(iid)
        if ids:
            host_ifaces[h.id] = ids
            for iid in ids:
                host_count[iid] += 1
    # aggregate / switch membership from the stored FortiOS configs
    agg_of: dict = {}
    for f in fws:
        row = config_store.get_config(db, f.id)
        if row is not None and (row.vendor or f.vendor or "").lower() in ("fortigate", "fortinet", ""):
            agg_of[f.id] = _aggregate_members(config_store.config_text(row))

    def _declared(i):
        try:
            n = ipaddress.ip_network(i.network_cidr, strict=False) if i.network_cidr else None
        except ValueError:
            n = None
        if n is None:
            return None
        for dn, z in decl:
            if dn.version == n.version and n.subnet_of(dn):
                return {"cidr": str(dn), "purdue_level": z.purdue_level, "zone_name": z.zone_name}
        return None

    def _iface_dict(i, fid):
        zones = [z for z in zones_of_iface.get((fid, str(i.name).lower()), []) if z.lower() != str(i.name).lower()]
        return {"interface_id": i.id, "name": i.name, "type": i.iface_type, "vlan": i.vlan_id, "ip": i.ip_cidr,
                "cidr": i.network_cidr, "alias": i.alias, "zone": zones[0] if zones else None, "zones": zones,
                "zone_label": i.zone_label, "purdue_level": i.purdue_level, "declared": _declared(i),
                "hosts": host_count.get(i.id, 0), "status": i.status or "up", "role": i.role,
                "is_ha": bool(i.is_ha), "is_mgmt_only": bool(i.is_mgmt_only), "vdom": i.vdom,
                "parent": by_id[i.parent_interface_id].name if i.parent_interface_id in by_id else None}

    # owner 2026-10-19: FortiLink-managed switches hang off the FortiGate port their uplink names
    from app.models import SwitchInterface
    fsw_by_port: dict = defaultdict(list)       # (fw id, lower interface name) -> [switch names]
    fw_names = {}
    for f in fws:
        for n in (f.name, f.device_name):
            if n:
                fw_names[str(n).lower()] = f.id
    for r in db.query(SwitchInterface).filter(SwitchInterface.site_id == site_id, SwitchInterface.uplink.is_(True),
                                              SwitchInterface.source_file.like("fortilink:%")):
        fid = fw_names.get(str(r.neighbor_device or "").lower())
        if fid is not None and r.neighbor_port and r.device_name not in fsw_by_port[(fid, str(r.neighbor_port).lower())]:
            fsw_by_port[(fid, str(r.neighbor_port).lower())].append(r.device_name)
    firewalls_out = []
    port_of_iface: dict = {}        # interface id -> port key
    for f in fws:
        mine = [i for i in ifaces if i.firewall_id == f.id]
        members = agg_of.get(f.id, {})
        is_switch = f.id in switch_ids
        ports: dict = {}
        order: list = []

        def _port(key, name, kind):
            if key not in ports:
                ports[key] = {"key": key, "name": name, "kind": kind, "members": [], "subnets": [], "status": "up",
                              "role": None, "is_ha": False, "is_mgmt_only": False, "interface_id": None, "alias": None}
                order.append(key)
            return ports[key]

        # 1. the physical / aggregate / switch ports
        for i in mine:
            t = str(i.iface_type or "physical").lower()
            if t in _OTHER_TYPES or t in _SUB_TYPES:
                continue
            agg = members.get(str(i.name).lower())
            if agg:
                p = _port(f"{f.id}:{agg}", agg, "aggregate")
                p["members"].append(i.name)
                continue
            kind = "aggregate" if t in _AGG_TYPES else "switch" if t in _SWITCH_TYPES else "physical"
            p = _port(f"{f.id}:{i.name}", i.name, kind)
            p.update({"status": i.status or "up", "role": i.role, "is_ha": bool(i.is_ha), "is_mgmt_only": bool(i.is_mgmt_only),
                      "interface_id": i.id, "alias": i.alias})
            if i.network_cidr or i.ip_cidr:
                p["subnets"].append({**_iface_dict(i, f.id), "tagged": False})
            port_of_iface[i.id] = p["key"]
        # 2. VLAN sub-interfaces on their parent port: parent link, else the "name.tag" / alias "name.tag" prefix;
        #    a routing switch's SVI (no physical parent) is a port of its own
        for i in mine:
            t = str(i.iface_type or "").lower()
            if t not in _SUB_TYPES:
                continue
            parent = by_id.get(i.parent_interface_id)
            pname = parent.name if parent is not None else None
            if pname is None:
                m = _SUB_ALIAS_RE.match(str(i.name)) or _SUB_ALIAS_RE.match(str(i.alias or ""))
                if m:
                    pname = m.group(1)
            if pname is not None and members.get(str(pname).lower()):
                pname = members[str(pname).lower()]
            if pname is None:
                key = f"{f.id}:{i.name}"
                p = _port(key, i.name, "svi" if is_switch else "physical")
                p.update({"status": i.status or "up", "role": i.role, "interface_id": i.id, "alias": i.alias})
                p["subnets"].append({**_iface_dict(i, f.id), "tagged": not is_switch})
            else:
                key = f"{f.id}:{pname}"
                p = _port(key, pname, "physical")
                p["subnets"].append({**_iface_dict(i, f.id), "tagged": True})
            port_of_iface[i.id] = key
        # 3. kind labels
        for p in ports.values():
            tagged = [s for s in p["subnets"] if s["tagged"]]
            untagged = [s for s in p["subnets"] if not s["tagged"]]
            nv = f"{len(tagged)} VLAN{'s' if len(tagged) != 1 else ''}"
            if p["kind"] == "svi":
                p["kind_label"] = f"SVI · VLAN {p['subnets'][0]['vlan'] or '?'}" if p["subnets"] else "SVI"
            elif p["kind"] in ("aggregate", "switch"):
                p["kind_label"] = f"{p['kind']} · {' + '.join(p['members']) if p['members'] else 'no members'}" + (f" · {nv}" if tagged else "")
            elif p["role"] == "wan":
                p["kind_label"] = "WAN · egress leg"
            elif p["is_ha"]:
                p["kind_label"] = "HA heartbeat"
            elif p["is_mgmt_only"]:
                p["kind_label"] = "dedicated management"
            elif tagged and not untagged:
                p["kind_label"] = f"trunk · {nv}"
            elif tagged and untagged:
                p["kind_label"] = f"access + {nv}"
            elif untagged:
                p["kind_label"] = "untagged · access"
            else:
                p["kind_label"] = "unused"
            p["subnets"].sort(key=lambda s: (s["tagged"], _vlan_sort(s["vlan"])))
            p["hosts"] = sum(s["hosts"] for s in p["subnets"])
            p["fortiswitches"] = sorted(fsw_by_port.get((f.id, p["name"].lower()), []) + [
                x for m in p["members"] for x in fsw_by_port.get((f.id, str(m).lower()), [])])
        firewalls_out.append({"firewall_id": f.id, "name": f.name, "device_name": f.device_name, "vendor": f.vendor,
                              "switch": is_switch, "ha_mode": f.ha_mode, "ports": [ports[k] for k in order]})

    # --- permitted services between interfaces, from the enabled permit rules
    name_to_ifaces: dict = defaultdict(set)      # (fw id, lower interface / alias / zone name) -> interface ids
    all_ifaces: dict = defaultdict(set)          # fw id -> every interface id (for any / unnamed sides)
    for i in ifaces:
        all_ifaces[i.firewall_id].add(i.id)
        name_to_ifaces[(i.firewall_id, str(i.name).lower())].add(i.id)
        if i.alias:
            name_to_ifaces[(i.firewall_id, str(i.alias).lower())].add(i.id)
    for (fid, zname), inames in zone_members.items():
        for iname in inames:
            for iid in name_to_ifaces.get((fid, iname), ()):
                name_to_ifaces[(fid, zname)].add(iid)

    def _side(fid, value) -> tuple:
        """(interface ids, unbound): a side names interfaces / zones ("port2,port3"), any, or nothing."""
        toks = [t.strip().lower() for t in str(value or "").split(",") if t.strip()]
        if not toks or "any" in toks:
            return set(all_ifaces.get(fid, ())), True
        out = set()
        for t in toks:
            out |= name_to_ifaces.get((fid, t), set())
        return out, False

    links: dict = {}
    rules = db.query(FirewallRule).filter(FirewallRule.site_id == site_id, FirewallRule.action == "permit",
                                          FirewallRule.enabled.is_not(False), FirewallRule.firewall_id.in_(fw_ids)).all()
    for r in rules:
        srcs, s_any = _side(r.firewall_id, r.src_zone)
        dsts, d_any = _side(r.firewall_id, r.dst_zone)
        if not srcs or not dsts:
            continue
        try:
            svc = _svc(r.protocol, format_ports(parse_ports(r.dst_port)) if r.dst_port not in (None, "", "any") else "any")
        except Exception:
            svc = _svc(r.protocol, r.dst_port)
        pid = str(r.policy_id if r.policy_id is not None else r.id)
        for s_id in srcs:
            for d_id in dsts:
                if s_id == d_id:
                    continue
                L = links.setdefault((r.firewall_id, s_id, d_id), {"policies": set(), "services": {}, "any_side": False})
                L["policies"].add(pid)
                L["any_side"] = L["any_side"] or s_any or d_any
                L["services"].setdefault(svc, {"policies": set(), "sessions": 0})["policies"].add(pid)
    # observed sessions per (src iface, dst iface, transport/port) for "allowed vs used"
    seen: dict = defaultdict(int)
    fetched = 0
    if host_ifaces:
        ids = list(host_ifaces)
        q = (db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id, NetworkSession.transport, NetworkSession.dst_port)
             .filter(NetworkSession.src_host_id.in_(ids), NetworkSession.dst_host_id.in_(ids))
             .order_by(NetworkSession.packet_count.desc()).limit(session_limit))
        for sid_, did_, transport, port in q:
            fetched += 1
            for a in host_ifaces.get(sid_, ()):
                for b in host_ifaces.get(did_, ()):
                    if a == b:
                        continue
                    seen[(a, b, (transport or "tcp").lower(), port)] += 1
                    seen[(a, b, "*", None)] += 1
    seen_by_pair: dict = defaultdict(list)
    for (a, b, tr, port), n in seen.items():
        seen_by_pair[(a, b)].append((tr, port, n))

    def _seen(a, b, svc) -> int:
        if svc == "ALL":
            return seen.get((a, b, "*", None), 0)
        m = re.match(r"^(tcp|udp)/(.+)$", svc)
        if not m:
            return 0
        ranges = _ports_of(svc)
        return sum(n for tr, port, n in seen_by_pair.get((a, b), ()) if tr == m.group(1) and port is not None
                   and any(lo <= int(port) <= hi for lo, hi in ranges))

    out_links = []
    for (fid, s_id, d_id), L in links.items():
        si, di = by_id[s_id], by_id[d_id]
        services = []
        for svc, e in sorted(L["services"].items(), key=lambda kv: (kv[0] == "ALL", kv[0])):
            services.append({"svc": svc, "kind": _svc_kind(svc, cleartext, mgmt),
                             "policies": sorted(e["policies"], key=lambda x: (len(x), x)), "seen_sessions": _seen(s_id, d_id, svc)})
        sl, dl = _level(si.purdue_level), _level(di.purdue_level)
        out_links.append({"firewall_id": fid, "src_iface_id": s_id, "dst_iface_id": d_id,
                          "src_name": si.name, "dst_name": di.name,
                          "src_port": port_of_iface.get(s_id), "dst_port": port_of_iface.get(d_id),
                          "src_vlan": si.vlan_id, "dst_vlan": di.vlan_id, "any_side": L["any_side"],
                          "policies": sorted(L["policies"], key=lambda x: (len(x), x)), "services": services,
                          "into_ot": dl is not None and dl <= 2 and (sl is None or sl > 2),
                          "warnings": sum(1 for s in services if s["kind"] not in ("ok", "icmp"))})
    out_links.sort(key=lambda l: (l["firewall_id"], l["src_name"], l["dst_name"]))
    return {"site_id": site_id, "firewalls": firewalls_out, "links": out_links, "hosts_counted": len(host_ifaces),
            "sessions_truncated": fetched >= session_limit}
