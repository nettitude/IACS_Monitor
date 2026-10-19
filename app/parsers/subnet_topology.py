"""
Network Topology (owner 2026-10-16): the site's hosts in lanes by subnet / VLAN
instead of Purdue level, each host labelled by its function (device type), and
what separates each pair of lanes that talk to each other - a firewall interface
pair (with its policies), a routing switch, the same layer-2 segment ("flat"), or
nothing known.  Built for flat networks that do not have a mature Purdue
posture but route through a Layer-3 firewall.  View only: nothing here changes
a host, a level or a finding.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Optional

from sqlalchemy.orm import Session as DBSession

#: device type -> function group shown on the cards
FUNCTION_GROUPS = {
    "controller": ("plc", "rtu", "safety_plc", "safety_system", "sis", "controller", "drive", "io_module",
                   "ics_protocol_client_unclassified"),
    "hmi": ("hmi", "scada", "scada_client", "operator_workstation", "hmi_server", "scada_server"),
    "engineering": ("engineering_workstation", "jump_host", "admin_ws", "admin_workstation"),
    "server": ("historian", "site_dns_server", "site_ntp_server", "enterprise_dns_server", "enterprise_ntp_server",
               "domain_controller", "file_server", "server", "database", "patch_server", "av_server", "mes"),
    "infrastructure": ("switch", "router", "firewall", "ap", "access_point", "wireless_ap", "gateway",
                       "vlan_inferred", "network_device"),
    "it": ("workstation", "laptop", "printer", "phone", "mobile", "it_workstation", "consumer_device"),
    "remote": ("vpn_client", "remote_user", "remote_vpn_user"),
}
FUNCTION_ORDER = ("controller", "hmi", "engineering", "server", "infrastructure", "it", "remote", "unknown")
_TYPE_TO_GROUP = {t: g for g, ts in FUNCTION_GROUPS.items() for t in ts}


def function_of(device_type: Optional[str]) -> str:
    return _TYPE_TO_GROUP.get(str(device_type or "").lower(), "unknown" if not device_type else "server"
                              if "server" in str(device_type).lower() else "unknown")


def _net(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None


MAX_FLOWS_PER_HOST = 40


def build(db: DBSession, site_id: int, session_limit: int = 50000) -> dict:
    """Audit 2026-10-17: everything runs under the site's analysis scope - the
    capture segments and the routing-switch lookup are scoped by it."""
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, site_id):
        return _build(db, site_id, session_limit)


def _build(db: DBSession, site_id: int, session_limit: int) -> dict:
    from app.models import (Firewall, FirewallInterface, FirewallRule, Host, NetworkSession, SubnetZone,
                            real_host_clause)
    from app.parsers.device_classification import DEVICE_TYPE_REFERENCE
    from app.parsers.l3_switch import VENDOR as _SWITCH_VENDOR
    from app.parsers.segments import capture_networks

    fws = {f.id: f for f in db.query(Firewall).filter(Firewall.site_id == site_id)}
    switch_ids = {f.id for f in fws.values() if f.vendor == _SWITCH_VENDOR}
    # --- lanes from the firewall / routing-switch interface networks (most specific first)
    lanes: dict = {}
    fw_nets = []
    _all_ifaces = db.query(FirewallInterface).filter(FirewallInterface.firewall_id.in_(list(fws)) if fws else False).all()
    for i in _all_ifaces:
        if str(i.status or "").lower() == "down":
            continue                       # owner 2026-10-17: disabled interfaces are not lanes
        if str(i.role or "").lower() == "wan" or str(i.iface_type or "").lower() in ("tunnel", "loopback"):
            continue                       # audit 2026-10-17: the WAN leg / tunnels are the egress side, not a lane
        n = _net(i.network_cidr)
        if n is None or n.prefixlen == 0 or n.prefixlen == n.max_prefixlen:
            continue
        fw = fws.get(i.firewall_id)
        key = f"net:{n}"
        lane = lanes.get(key)
        if lane is None:
            lane = lanes[key] = {"key": key, "cidr": str(n), "kind": "svi" if i.firewall_id in switch_ids else "fw_interface",
                                 "vlan": i.vlan_id, "label": str(n), "interfaces": [], "purdue_level": i.purdue_level,
                                 "zone_label": i.zone_label, "domain": None, "declared": None, "hosts": []}
        parent = db.get(FirewallInterface, i.parent_interface_id) if i.parent_interface_id else None
        lane["interfaces"].append({"firewall_id": i.firewall_id, "firewall": (fw.device_name or fw.name) if fw else None,
                                   "interface_id": i.id, "name": i.name, "alias": i.alias, "vlan": i.vlan_id,
                                   "ip": i.ip_cidr, "switch": i.firewall_id in switch_ids,
                                   "purdue_level": i.purdue_level,
                                   "parent": parent.name if parent is not None else None})   # the physical port
        if lane["kind"] == "svi" and i.firewall_id not in switch_ids:
            lane["kind"] = "fw_interface"        # a firewall and a routing switch share it: the firewall decides
        if lane["purdue_level"] is None and i.purdue_level is not None:
            lane["purdue_level"] = i.purdue_level
        if lane["vlan"] is None and i.vlan_id:
            lane["vlan"] = i.vlan_id
        fw_nets.append((n, key))
    fw_nets.sort(key=lambda x: -x[0].prefixlen)
    # --- capture segments the firewalls do not cover (same layer-2 domain -> same "domain" label)
    cap_nets = []
    for n, cid, _gws, dom in capture_networks(db):
        key = f"net:{n}"
        if key not in lanes:
            lanes[key] = {"key": key, "cidr": str(n), "kind": "capture", "vlan": None, "label": str(n),
                          "interfaces": [], "purdue_level": None, "zone_label": None, "domain": dom,
                          "capture_id": cid, "declared": None, "hosts": []}
        cap_nets.append((n, key))
    cap_nets.sort(key=lambda x: -x[0].prefixlen)
    # --- operator declarations (Subnets & Zones)
    decl = []
    for z in db.query(SubnetZone).filter(SubnetZone.site_id == site_id):
        n = _net(z.cidr)
        if n is not None:
            decl.append((n, z))
    decl.sort(key=lambda x: -x[0].prefixlen)
    for lane in lanes.values():
        n = _net(lane["cidr"])
        for dn, z in decl:
            if dn.version == n.version and (n.subnet_of(dn) if hasattr(n, "subnet_of") else False):
                lane["declared"] = {"cidr": str(dn), "purdue_level": z.purdue_level, "zone_name": z.zone_name}
                break

    # --- hosts into lanes
    hosts = db.query(Host).filter(real_host_clause(), Host.site_id == site_id, Host.ip.isnot(None)).all()
    # a firewall address object persists as a MAC-less twin of a captured host: one card, the real one
    with_mac = {h.ip for h in hosts if h.mac}
    twin_of = {}                 # MAC-less twin id -> the real host id (sessions keyed on either land on one card)
    real_by_ip = {h.ip: h.id for h in hosts if h.mac}
    hosts = [h for h in hosts if h.mac or h.ip not in with_mac or twin_of.setdefault(h.id, real_by_ip[h.ip]) is None]
    host_lane: dict = {}
    beyond: dict = {}
    for h in hosts:
        a = ipaddress.ip_address(h.ip) if _ip_ok(h.ip) else None
        if a is None:
            continue
        key = next((k for n, k in fw_nets if n.version == a.version and a in n), None)
        if key is None:
            key = next((k for n, k in cap_nets if n.version == a.version and a in n), None)
        if key is None and h.vlan:
            key = f"vlan:{h.vlan}"
            lanes.setdefault(key, {"key": key, "cidr": None, "kind": "vlan", "vlan": str(h.vlan), "label": f"VLAN {h.vlan}",
                                   "interfaces": [], "purdue_level": None, "zone_label": None, "domain": None,
                                   "declared": None, "hosts": []})
        if key is None:
            if a.is_global:
                continue                      # outside the site: shown as an egress destination, not a lane host
            if not h.mac:
                # a private address outside every known network that the captures only saw behind a
                # router (no MAC of its own): the corporate side beyond the firewall - egress sub-group
                beyond[h.id] = h
                continue
            else:
                guess = ipaddress.ip_network(f"{h.ip}/{64 if a.version == 6 else 24}", strict=False)
                key = f"inferred:{guess}"
                lanes.setdefault(key, {"key": key, "cidr": str(guess), "kind": "inferred", "vlan": None, "label": f"{guess} (inferred)",
                                       "interfaces": [], "purdue_level": None, "zone_label": None, "domain": None,
                                       "declared": None, "hosts": []})
        host_lane[h.id] = key
        fn = function_of(h.device_type)
        lanes[key]["hosts"].append({
            "id": h.id, "ip": h.ip, "mac": h.mac, "hostname": h.hostname, "vendor": h.vendor,
            "device_type": h.device_type,
            "device_label": (DEVICE_TYPE_REFERENCE[h.device_type][1].split(" (")[0]
                             if h.device_type in DEVICE_TYPE_REFERENCE else (h.device_type or None)),
            "function": fn, "purdue_level": h.purdue_level, "classification_source": h.classification_source,
            "role": h.role, "vlan": h.vlan, "model": h.model, "firmware_version": h.firmware_version,
            "is_safety_function": bool(h.is_safety_function), "stale": bool(h.stale),
            "inventory_excluded": bool(h.inventory_excluded),
        })

    # --- traffic between lanes (and inside them), plus each host's observed flows
    pair_sessions: dict = defaultdict(lambda: {"sessions": 0, "protocols": set(), "ports": set()})
    intra: dict = defaultdict(lambda: {"sessions": 0, "protocols": set()})
    flows: dict = defaultdict(list)
    flows_dropped = 0
    ip_of = {h.id: h.ip for h in hosts}
    lane_ids = list(host_lane) + list(twin_of)
    q = (db.query(NetworkSession.id, NetworkSession.src_host_id, NetworkSession.dst_host_id, NetworkSession.protocol,
                  NetworkSession.dst_port, NetworkSession.transport, NetworkSession.packet_count, NetworkSession.cleartext_auth)
         .filter(NetworkSession.src_host_id.in_(lane_ids) if lane_ids else False,
                 NetworkSession.dst_host_id.in_(lane_ids) if lane_ids else False)
         .order_by(NetworkSession.packet_count.desc()).limit(session_limit))
    fetched = 0
    for sess_id, sid_, did_, proto, port, transport, packets, ct in q:
        fetched += 1
        sid_, did_ = twin_of.get(sid_, sid_), twin_of.get(did_, did_)
        a, b = host_lane.get(sid_), host_lane.get(did_)
        if a is None or b is None:
            continue
        if a == b:
            e = intra[a]
            e["sessions"] += 1
            if proto and proto != "unknown":
                e["protocols"].add(proto)
        else:
            e = pair_sessions[tuple(sorted((a, b)))]
            e["sessions"] += 1
            if proto and proto != "unknown":
                e["protocols"].add(proto)
            if port is not None:
                e["ports"].add(int(port))
        for me, peer, direction in ((sid_, did_, "to"), (did_, sid_, "from")):
            if len(flows[me]) >= MAX_FLOWS_PER_HOST:
                flows_dropped += 1
                continue
            flows[me].append({"session_id": sess_id, "peer_id": peer, "peer_ip": ip_of.get(peer), "peer_lane": host_lane.get(peer),
                              "direction": direction, "protocol": proto, "dst_port": port, "transport": transport,
                              "packets": packets or 0, "same_lane": a == b,
                              "cleartext_auth": ct})

    # --- what separates two lanes
    iface_names: dict = {}      # lane -> {(firewall_id, lower name / zone label)}
    for lane in lanes.values():
        names = set()
        for i in lane["interfaces"]:
            names.add((i["firewall_id"], str(i["name"]).lower()))
            if i.get("alias"):
                names.add((i["firewall_id"], str(i["alias"]).lower()))
        iface_names[lane["key"]] = names
    # zones -> member interfaces from the zone definitions (FortiOS, PAN-OS, ASA; keyed by firewall id,
    # so two firewalls sharing a name cannot swap zones)
    from app.parsers.port_topology import zone_memberships
    zones_of_iface: dict = defaultdict(set)
    for (fid, zl), members in zone_memberships(db, list(fws.values()), _all_ifaces).items():
        for m in members:
            zones_of_iface[(fid, m)].add(zl)
    rules = db.query(FirewallRule.firewall_id, FirewallRule.src_zone, FirewallRule.dst_zone, FirewallRule.action,
                     FirewallRule.policy_id).filter(FirewallRule.site_id == site_id, FirewallRule.enabled.is_not(False)).all()

    def _names_with_zones(key):
        out = set()
        for fw_id, n in iface_names.get(key, ()):
            out.add((fw_id, n))
            for z in zones_of_iface.get((fw_id, n), ()):
                out.add((fw_id, z))
        return out

    def _policies_between(a, b):
        na, nb = _names_with_zones(a), _names_with_zones(b)
        if not na or not nb:
            return None, []
        fa, fb = {f for f, _n in na}, {f for f, _n in nb}
        pols, permits = set(), set()            # per logical policy, not per expanded rule row
        per_fw: dict = defaultdict(lambda: (set(), set()))   # owner 2026-10-17: the policies of each firewall

        def _side(fw_id, value, names, fw_set):
            # a policy names several interfaces ("port2,port3"), a zone, or any / nothing (ASA inbound ACL)
            toks = {t.strip().lower() for t in str(value or "").split(",") if t.strip()}
            if not toks or "any" in toks:
                return fw_id in fw_set
            return any((fw_id, t) in names for t in toks)
        for fw_id, sz, dz, action, pid in rules:
            if (_side(fw_id, sz, na, fa) and _side(fw_id, dz, nb, fb)) or (_side(fw_id, sz, nb, fb) and _side(fw_id, dz, na, fa)):
                pols.add(str(pid))
                per_fw[fw_id][0].add(str(pid))
                if action == "permit":
                    permits.add(str(pid))
                    per_fw[fw_id][1].add(str(pid))
        fw_ids = {f for f, _n in na} & {f for f, _n in nb}
        return (sorted(fw_ids) or None), (sorted(pols, key=lambda x: (len(x), x)), len(permits), per_fw)

    separators = []
    for (a, b), e in sorted(pair_sessions.items()):
        la, lb = lanes[a], lanes[b]
        fw_ids, pol = _policies_between(a, b)
        if fw_ids:
            kind = "routed_switch" if all(f in switch_ids for f in fw_ids) else "firewall"
            policies, permits, per_fw = pol
            through = [{"firewall_id": f, "name": (fws[f].device_name or fws[f].name) if f in fws else str(f),
                        "switch": f in switch_ids,
                        "policies": sorted(per_fw[f][0], key=lambda x: (len(x), x))[:50],
                        "permit_policies": len(per_fw[f][1])} for f in fw_ids]
        elif la.get("domain") and la.get("domain") == lb.get("domain"):
            kind, through, policies, permits = "flat", [], [], 0
        else:
            kind, through, policies, permits = "unknown", [], [], 0
        separators.append({"a": a, "b": b, "kind": kind, "through": through, "policies": policies[:50],
                           "permit_policies": permits, "sessions": e["sessions"],
                           "protocols": sorted(e["protocols"])[:12], "ports": sorted(e["ports"])[:20]})

    # --- egress: every flow to an address outside the site's known networks (External comms),
    # grouped by destination; private destinations (corporate side beyond the firewall) are a sub-group
    egress = _egress(db, site_id, lanes, host_lane, fws, switch_ids, beyond)

    # --- the separator kind of every lane pair, for the per-host flows
    sep_kind = {(s["a"], s["b"]): s["kind"] for s in separators}
    for key, fl in flows.items():
        me_lane = host_lane.get(key)
        for f in fl:
            if f["same_lane"]:
                f["between"] = "same lane"
            else:
                f["between"] = sep_kind.get(tuple(sorted((me_lane, f["peer_lane"]))), "unknown")
    # --- lane summaries
    out_lanes = []
    for lane in lanes.values():
        lane["intra_sessions"] = intra[lane["key"]]["sessions"] if lane["key"] in intra else 0
        lane["intra_protocols"] = sorted(intra[lane["key"]]["protocols"])[:12] if lane["key"] in intra else []
        for h in lane["hosts"]:
            h["flows"] = flows.get(h["id"], [])
            h["flow_count"] = len(h["flows"])
        counts = {g: 0 for g in FUNCTION_ORDER}
        for h in lane["hosts"]:
            counts[h["function"]] += 1
        present = [g for g in FUNCTION_ORDER if counts[g] and g != "infrastructure"]
        lane["functions"] = counts
        lane["mixed"] = (counts["controller"] > 0 and (counts["it"] + counts["unknown"] + counts["server"] + counts["hmi"] + counts["engineering"]) > 0)
        lane["function_list"] = present
        lane["hosts"].sort(key=lambda h: (FUNCTION_ORDER.index(h["function"]), _sort_ip(h["ip"])))
        out_lanes.append(lane)
    kind_rank = {"fw_interface": 0, "svi": 1, "capture": 2, "vlan": 3, "inferred": 4}
    out_lanes.sort(key=lambda l: (kind_rank.get(l["kind"], 9), _sort_net(l.get("cidr")), l["label"]))
    lane_fws: dict = defaultdict(int)
    for l in out_lanes:
        for i in l["interfaces"]:
            lane_fws[i["firewall_id"]] += 1
    firewalls = [{"firewall_id": f.id, "name": f.device_name or f.name, "switch": f.id in switch_ids, "lanes": lane_fws.get(f.id, 0)}
                 for f in sorted(fws.values(), key=lambda f: f.id)]
    return {"site_id": site_id, "lanes": out_lanes, "separators": separators, "egress": egress, "firewalls": firewalls,
            "hosts_total": len(host_lane), "functions": list(FUNCTION_ORDER),
            "flows_truncated": flows_dropped, "max_flows_per_host": MAX_FLOWS_PER_HOST,
            "truncated": fetched >= session_limit}


def _ip_ok(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def _sort_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except (ValueError, TypeError):
        return (9, 0)


def _sort_net(cidr):
    n = _net(cidr)
    return (n.version, int(n.network_address)) if n else (9, 0)


def _lane_is_ot(lane: dict) -> bool:
    for lv in (lane.get("purdue_level"), (lane.get("declared") or {}).get("purdue_level")):
        try:
            if lv is not None and float(lv) <= 2:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _egress(db: DBSession, site_id: int, lanes: dict, host_lane: dict, fws: dict, switch_ids: set,
            beyond: Optional[dict] = None) -> dict:
    """The egress lane: destinations outside the site (from external_comms.flows),
    with the inside sources per lane.  ``private`` marks destinations with
    private addresses - the corporate side beyond the firewall - shown as a
    sub-group of the lane.  OT sources (host L0-L2, or an OT lane) are marked:
    no OT device may reach the Internet directly (owner's rule)."""
    from app.models import FirewallInterface
    from app.parsers import external_comms as ec
    from app.parsers.site_scope import analysis_site
    try:
        with analysis_site(db, site_id):
            data = ec.flows(db)
    except Exception:          # the egress lane never breaks the page
        data = {"flows": [], "summary": {}}
    wan = [{"firewall_id": i.firewall_id, "firewall": (fws[i.firewall_id].device_name or fws[i.firewall_id].name) if i.firewall_id in fws else None,
            "name": i.name, "alias": i.alias, "ip": i.ip_cidr}
           for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id.in_(list(fws)) if fws else False,
                                                        FirewallInterface.role == "wan")
           if i.firewall_id not in switch_ids and str(i.status or "").lower() != "down"]
    rows = list(data.get("flows", []))
    # the private sub-group: External comms treats RFC 1918 addresses as inside by design, so the
    # hosts beyond the firewall (private, no MAC, outside every known network) are added here
    if beyond:
        from app.models import Host, NetworkSession
        revs = {}
        try:
            with analysis_site(db, site_id):
                revs = ec.reviews(db)
        except Exception:
            revs = {}
        ids = list(beyond)
        grouped: dict = {}
        q = db.query(NetworkSession).filter(
            (NetworkSession.src_host_id.in_(ids) & NetworkSession.dst_host_id.in_(list(host_lane)))
            | (NetworkSession.dst_host_id.in_(ids) & NetworkSession.src_host_id.in_(list(host_lane))))
        for sess_row in q:
            out_id = sess_row.dst_host_id if sess_row.dst_host_id in beyond else sess_row.src_host_id
            in_id = sess_row.src_host_id if out_id == sess_row.dst_host_id else sess_row.dst_host_id
            g = grouped.setdefault((in_id, out_id), {"sessions": 0, "ports": set(), "outbound": False, "inbound": False})
            g["sessions"] += 1
            if sess_row.dst_port is not None:
                g["ports"].add(int(sess_row.dst_port))
            g["outbound" if out_id == sess_row.dst_host_id else "inbound"] = True
        inside_hosts = {h.id: h for h in db.query(Host).filter(Host.id.in_([i for i, _o in grouped]))} if grouped else {}
        for (in_id, out_id), g in grouped.items():
            h, o = inside_hosts.get(in_id), beyond[out_id]
            if h is None:
                continue
            rv = ec.review_for(revs, h.ip, o.ip, o.ip)
            rows.append({"inside": {"id": h.id, "ip": h.ip, "mac": h.mac, "vendor": h.vendor, "device_type": h.device_type,
                                    "purdue_level": h.purdue_level},
                         "dest_key": o.ip, "names": [o.hostname] if o.hostname else [], "addresses": [o.ip], "address_count": 1,
                         "organisations": [], "ports": sorted(g["ports"])[:20], "category": "corporate",
                         "direction": "both" if g["outbound"] and g["inbound"] else "outbound" if g["outbound"] else "inbound",
                         "sessions": g["sessions"], "attempts": 0, "left_via": [],
                         "status": rv.status if rv else "unreviewed",
                         "review": {"src": rv.src} if rv else None,
                         "ot_host": h.purdue_level is not None and float(h.purdue_level) <= 2})
    dests: dict = {}
    by_lane: dict = {}
    for r in rows:
        inside = r["inside"]
        addrs = r.get("addresses") or []
        private = bool(addrs) and all((lambda a: a is not None and not a.is_global)(_addr(x)) for x in addrs)
        key = r["dest_key"]
        d = dests.get(key)
        if d is None:
            d = dests[key] = {"dest_key": key, "name": (r.get("names") or [None])[0] or key, "names": r.get("names") or [],
                              "organisations": r.get("organisations") or [], "category": r.get("category") or "unknown",
                              "private": private, "addresses": addrs[:5], "address_count": r.get("address_count", len(addrs)),
                              "sources": [], "sessions": 0, "attempts": 0, "statuses": set(), "ot_sources": 0,
                              "left_via": set()}
        lane_key = host_lane.get(inside["id"])
        lane = lanes.get(lane_key) if lane_key else None
        ot = bool(r.get("ot_host")) or (lane is not None and _lane_is_ot(lane))
        d["sources"].append({"host_id": inside["id"], "ip": inside["ip"], "lane": lane_key, "purdue_level": inside.get("purdue_level"),
                             "device_type": inside.get("device_type"), "ot": ot, "ports": r.get("ports") or [],
                             "sessions": r.get("sessions", 0), "attempts": r.get("attempts", 0),
                             "direction": r.get("direction"), "status": r.get("status", "unreviewed"),
                             "review_src": (r.get("review") or {}).get("src")})
        d["sessions"] += r.get("sessions", 0)
        d["attempts"] += r.get("attempts", 0)
        d["statuses"].add(r.get("status", "unreviewed"))
        d["ot_sources"] += ot
        d["left_via"] |= set(r.get("left_via") or [])
        if lane_key:
            e = by_lane.setdefault(lane_key, {"sessions": 0, "attempts": 0, "ot": _lane_is_ot(lane) if lane else False,
                                              "ot_sources": 0, "destinations": {}, "categories": set(), "private": 0, "internet": 0})
            e["sessions"] += r.get("sessions", 0)
            e["attempts"] += r.get("attempts", 0)
            e["ot_sources"] += ot
            e["ot"] = e["ot"] or ot
            e["destinations"][d["name"]] = e["destinations"].get(d["name"], 0) + r.get("sessions", 0) + r.get("attempts", 0)
            e["categories"].add(d["category"])
            e["private" if private else "internet"] += 1
    out = []
    for d in dests.values():
        st = d.pop("statuses")
        d["status"] = ("approved" if st == {"approved"} else "remove" if "remove" in st else
                       "mixed" if len(st) > 1 else next(iter(st)) if st else "unreviewed")
        d["left_via"] = sorted(d["left_via"])
        d["sources"].sort(key=lambda x: (not x["ot"], str(x["ip"])))
        out.append(d)
    out.sort(key=lambda d: (d["private"], d["status"] == "approved" and not d["ot_sources"], -d["ot_sources"], -d["sessions"], d["name"]))
    for k, e in by_lane.items():
        e["destinations"] = [n for n, _c in sorted(e["destinations"].items(), key=lambda kv: -kv[1])[:5]]
        e["categories"] = sorted(e["categories"])
    return {"destinations": out, "by_lane": by_lane, "wan_interfaces": wan,
            "summary": {"destinations": len(out), "internet": sum(1 for d in out if not d["private"]),
                        "private": sum(1 for d in out if d["private"]),
                        "approved": sum(1 for d in out if d["status"] == "approved"),
                        "ot_sources": sum(d["ot_sources"] for d in out)}}


def _addr(x):
    try:
        return ipaddress.ip_address(x)
    except (ValueError, TypeError):
        return None
