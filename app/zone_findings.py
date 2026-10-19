"""The one check sourced from the IEC 62443-3-2 zone documentation.

``undocumented_conduit`` (owner decision 2026-10-11, "option 4"): a pair of
documented zones with a permitting firewall policy or observed traffic
between them and no documented conduit is a finding (SR 5.1 / ZCR 3.3 -
conduits documented; workbook row 1.4).  Everything else about zones stays
documentation: no other check reads them, and this one reports the zone
documentation gap, not the traffic (the level-based checks judge that).

Kept outside ``app/parsers`` so the guard test can name the single place the
engine reaches the zone model.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

CHECK = "undocumented_conduit"



def _slt(v) -> str:
    """SL-T for text: SL0 is a level (owner 2026-10-13), None is "-"."""
    return "-" if v is None else str(v)

def _levels_of(z: dict) -> list:
    return [float(x) for x in z.get("purdue_levels") or []]


def review_undocumented_conduits(db: DBSession) -> list:
    """One finding per undocumented zone pair of the analysis site (both ends
    documented zones).  Medium; high when traffic was observed and one of the
    zones holds basic-control / control assets (L0-L2); low when only a
    policy permits it and nothing was seen.  Pairs involving assets in no
    zone or the Internet are not findings (hosts in no zone are a zone
    documentation gap of their own; Internet pairs are the egress checks')."""
    from app import iec_zones as iz
    from app.models import IecZone
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import current_site
    site_id = current_site(db)
    if site_id is None or db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is None:
        return []
    model = iz.ZoneModel(db, site_id)
    zones = {z["id"]: z for z in iz.zone_summary(model)}
    view = iz.conduit_view(db, model)
    out = []
    for u in view["undocumented"]:
        if not u.get("declarable"):
            continue
        za, zb = u["zone_a"], u["zone_b"]
        a, b = sorted((za, zb), key=lambda z: z["id"])
        sessions = u["sessions"]
        policies = u["policy_count"]
        control = any(lv <= 2 for z in (a, b) for lv in _levels_of(zones.get(z["id"], {})))
        severity = "high" if sessions and control else ("medium" if sessions or control else "low")
        dirs = []
        for frm, to, d in ((za, zb, u["a_to_b"]), (zb, za, u["b_to_a"])):
            if not d["policy_count"] and not d["sessions"]:
                continue
            bits = []
            if d["policy_count"]:
                bits.append("polic" + ("y " if d["policy_count"] == 1 else "ies ")
                            + ", ".join(p["policy"].split(" policy ")[-1].replace(" (vdom root)", "")
                                        for p in d["policies"][:6]))
            if d["sessions"]:
                bits.append(f"{d['sessions']} session(s): "
                            + ", ".join(x.split(" ×")[0] for x in d["services"][:5]))
            dirs.append(f"{frm['name']} → {to['name']}: " + "; ".join(bits))
        title = (f"Communication between zones with no documented conduit: {a['name']} ↔ {b['name']}"
                 + (f" ({sessions} sessions seen)" if sessions else " (policy only, no traffic seen)"))
        text = (f"No conduit is documented between the zones '{a['name']}' and '{b['name']}', yet "
                f"{policies} polic{'y' if policies == 1 else 'ies'} permit{'s' if policies == 1 else ''} "
                f"traffic between them and {sessions} session(s) were observed. IEC 62443-3-2 requires every "
                "path between zones to be a documented conduit with its own security requirements (SR 5.1): "
                "document it (Zones & Conduits: name, SL-T, purpose) or remove the policies and stop the traffic.")
        ev = {"zone_a": a["name"], "zone_b": b["name"],
              "sl_t": f"{a['name']} SL-T {_slt(a.get('sl_t'))}, {b['name']} SL-T {_slt(b.get('sl_t'))}",
              "policies": policies, "sessions": sessions,
              "paths": dirs,
              "zone_a_id": a["id"], "zone_b_id": b["id"],
              "a_to_b": {"policies": [p["policy"] for p in u["a_to_b"]["policies"]],
                         "sessions": u["a_to_b"]["sessions"], "services": u["a_to_b"]["services"]},
              "b_to_a": {"policies": [p["policy"] for p in u["b_to_a"]["policies"]],
                         "sessions": u["b_to_a"]["sessions"], "services": u["b_to_a"]["services"]},
              "control_zone": control,
              "severity_reason": ("traffic observed and a zone holds control assets (L0-L2)" if severity == "high"
                                  else "policy permits it but no traffic was observed" if severity == "low"
                                  else "traffic observed, or a zone holds control assets")}
        f = ae._make_finding(db, CHECK, title, text, ev, severity=severity,
                             dedup_evidence={"rule_key": f"zones:{a['id']}:{b['id']}"})   # one per zone pair
        if f is not None:
            out.append(f)
    return out


def review_multi_zone_membership(db: DBSession) -> list:
    """Owner (2026-10-11): an asset documented in several zones is never
    refused, it is reported.  ``host_in_multiple_zones``: one finding per
    device (all addresses of a MAC) whose addresses resolve to two or more
    zones.  ``network_in_multiple_zones``: one per network that is a member
    of two or more zones.  Medium; high when the zones' SL-T differ (the
    asset's requirements are undetermined)."""
    from app import iec_zones as iz
    from app.models import IecZone
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import current_site
    site_id = current_site(db)
    if site_id is None or db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is None:
        return []
    model = iz.ZoneModel(db, site_id)
    out = []
    for d in model.multi_zone:
        names = [z["name"] for z in d["zones"]]
        sl = {z["sl_t"] for z in d["zones"]}
        severity = "high" if len(sl) > 1 else "medium"
        who = d.get("hostname") or d["addresses"][0]
        where = "; ".join(f"{z['name']}" + (f" (SL-T {z['sl_t']})" if z["sl_t"] is not None else "") + ": "
                          + ", ".join(f"{a['ip']} ({a['basis']})" for a in z["addresses"]) for z in d["zones"])
        f = ae._make_finding(
            db, "host_in_multiple_zones",
            f"Device in {len(names)} IEC 62443 zones: {who} ({', '.join(d['addresses'])}) - {' / '.join(names)}",
            (f"The device {who}" + (f" (MAC {d['mac']})" if d.get("mac") else "") + f" is documented in zones "
             f"{', '.join(names)}: {where}. IEC 62443-3-2 partitions the system into zones - an asset belongs to "
             "exactly one, so its security requirements and SL-T are defined. Decide which zone it belongs to and "
             "remove it from the others, or document the dual-homing as a conduit."
             + (" The zones have different SL-T: the device's target level is undetermined." if len(sl) > 1 else "")),
            {"ip": d["addresses"][0], "mac": d.get("mac"), "addresses": d["addresses"], "hostname": d.get("hostname"),
             "device_type": d.get("device_type"), "zones": names,
             "zone_detail": [{"zone": z["name"], "sl_t": z["sl_t"], "addresses": [a["ip"] for a in z["addresses"]],
                              "basis": sorted({a["basis"] for a in z["addresses"]})} for z in d["zones"]],
             "severity_reason": "zones with different SL-T" if len(sl) > 1 else "same SL-T in every zone"},
            severity=severity, dedup_evidence={"rule_key": "multizone:" + d["key"]})
        if f is not None:
            out.append(f)
    seen = set()
    for o in model.overlaps:
        if o["network"] in seen:
            continue
        seen.add(o["network"])
        zones = [z for z in model.zones.values() if z.name in o["zones"]]
        sl = {z.sl_t for z in zones}
        severity = "high" if len(sl) > 1 else "medium"
        f = ae._make_finding(
            db, "network_in_multiple_zones",
            f"Network in 2 IEC 62443 zones: {o['network']} - {' / '.join(o['zones'])}",
            (f"The network {o['network']} is a member of zones {' and '.join(o['zones'])} ({' / '.join(o['members'])}). "
             "Every host on it is claimed by both zones; the page resolves them to the first zone listed, but the "
             "zone documentation is contradictory. Keep the network in one zone, or split it / use host members."
             + (" The zones have different SL-T." if len(sl) > 1 else "")),
            {"network": o["network"], "zones": o["zones"], "members": o["members"],
             "severity_reason": "zones with different SL-T" if len(sl) > 1 else "same SL-T in every zone"},
            severity=severity, dedup_evidence={"rule_key": "multizone-net:" + o["network"]})
        if f is not None:
            out.append(f)
    return out


# ------------------------------------------------------------------ SF-6 --
def review_policies_spanning_conduits(db: DBSession) -> list:
    """SF-6 (owner, 2026-10-11): one firewall policy that serves two or more
    zone pairs is several conduits written as one rule - it cannot be scoped
    to one conduit's purpose (services, sources), and changing it for one
    zone changes the other.  One finding per policy whose permitted traffic
    maps to two or more pairs of documented zones (a pair may also be zone ↔
    Internet).  Low; medium when one of the zones holds L0-L2 assets."""
    from app import iec_zones as iz
    from app.models import IecZone
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import current_site
    site_id = current_site(db)
    if site_id is None or db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is None:
        return []
    model = iz.ZoneModel(db, site_id)
    zones = {z["id"]: z for z in iz.zone_summary(model)}
    flows = iz.derive_flows(db, model)
    conduits = {}
    from app.models import IecConduit
    for c in db.query(IecConduit).filter(IecConduit.site_id == site_id):
        conduits[(c.zone_a_id, c.zone_b_id)] = c.name

    def zname(z):
        return iz.EXTERNAL if z == "external" else model.zones[z].name

    out = []
    for label, p in sorted(flows.get("policy_pairs", {}).items()):
        pairs = sorted({(x, y) for x, y, _f in p["pairs"]
                        if (isinstance(x, int) or x == "external") and (isinstance(y, int) or y == "external")
                        and (isinstance(x, int) or isinstance(y, int))}, key=lambda t: (str(t[0]), str(t[1])))
        if len(pairs) < 2:
            continue
        ids = {z for pr in pairs for z in pr if isinstance(z, int)}
        control = any(lv <= 2 for z in ids for lv in (zones.get(z, {}).get("purdue_levels") or []))
        rows = []
        for x, y in pairs:
            name = conduits.get((x, y)) if isinstance(x, int) and isinstance(y, int) else None
            rows.append({"zones": [zname(x), zname(y)], "conduit": name})
        listing = "; ".join(f"{r['zones'][0]} ↔ {r['zones'][1]}" + (f" (conduit '{r['conduit']}')" if r["conduit"]
                                                                   else " (no documented conduit)") for r in rows)
        from app.models import FirewallRule
        r0 = (db.query(FirewallRule.src_zone, FirewallRule.dst_zone)
              .filter(FirewallRule.firewall_id == p["firewall_id"], FirewallRule.policy_id == str(p["policy_id"]))
              .first())
        f = ae._make_finding(
            db, "policy_spans_multiple_conduits",
            f"One policy serves {len(pairs)} conduits: {label} - "
            + ", ".join(f"{r['zones'][0]} ↔ {r['zones'][1]}" for r in rows[:4]) + (" …" if len(rows) > 4 else ""),
            (f"{label} permits traffic for {len(pairs)} zone pairs at once: {listing}. Each zone pair is its own "
             "conduit with its own purpose and security requirements (IEC 62443-3-2); one rule carrying several "
             "of them cannot be scoped to any one conduit's services or sources, and tightening it for one zone "
             "changes the others (SR 5.1, SR 5.2). Split the policy into one policy per conduit."),
            {"policy": label, "firewall_id": p["firewall_id"], "policy_id": p["policy_id"], "vdom": p["vdom"] or None,
             "firewall_name": model.infra.fw_label(p["firewall_id"]),
             "src_zone": r0[0] if r0 else None, "dst_zone": r0[1] if r0 else None,
             "conduits": rows, "services": p["services"], "control_zone": control,
             "severity_reason": ("a zone it serves holds control assets (L0-L2)" if control
                                 else "no control zone among the pairs")},
            severity="medium" if control else "low",
            device_name=model.infra.fw_label(p["firewall_id"]),
            dedup_evidence={"rule_key": f"spans:{p['firewall_id']}:{p['vdom'] or ''}:{p['policy_id']}"})
        if f is not None:
            out.append(f)
    return out


# ------------------------------------------------------------------ SF-5 --
_MGMT_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 161: "SNMP", 445: "SMB",
               3389: "RDP", 5800: "VNC (web)", 5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM"}
_SEV_UP = {"low": "medium", "medium": "high", "high": "high"}


def review_blocked_cross_zone_attempts(db: DBSession) -> list:
    """SF-5 (owner, 2026-10-11): a host whose connection attempts into another
    zone were all dropped (no answer / refused, and no session on that port).

    Segment = the IEC 62443 zone when the site has zones (a host in no zone is
    its own segment), else the firewall interface network.  For each target
    the conduit decides: no documented conduit between the zones, or a
    conduit whose services do not cover the port -> ``blocked_cross_zone_attempts``
    (one finding per source host); a documented conduit that covers the port
    (and source) -> ``conduit_service_blocked`` (info: designed traffic the
    firewall drops).  Severity: low; medium for management ports, an
    undocumented pair or a source not in any inventory and unclassified;
    high for such a source on management ports.  Internet targets are the
    egress checks', the firewall's own addresses local-in."""
    import ipaddress
    from app import iec_zones as iz
    from app.models import ConnectionAttempt, Host, IecZone, NetworkSession, real_host_clause
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import current_site
    site_id = current_site(db)
    if site_id is None:
        return []
    attempts = [a for a in db.query(ConnectionAttempt).filter(
        ConnectionAttempt.site_id == site_id, ConnectionAttempt.outcome.in_(("unanswered", "refused")),
        ConnectionAttempt.dst_port.isnot(None))]
    if not attempts:
        return []
    zoned = db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is not None
    judge = iz.FindingJudge(db, site_id) if zoned else None
    infra = judge.model.infra if zoned else iz._Infra(db, site_id)
    nets = []
    for i in infra.ifaces:
        n = iz._net(i.network_cidr)
        if n is not None and (i.iface_type or "") not in ("vdom-link", "npu-vlink", "vdom_link"):
            nets.append((n, f"{infra.fw_label(i.firewall_id)}/{i.name}", i.purdue_level))
    nets.sort(key=lambda t: -t[0].prefixlen)

    def net_of(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next(((n, lbl, lv) for n, lbl, lv in nets if n.version == a.version and a in n), None)

    def segment(ip):
        if zoned:
            zid = judge._zone_of_address(ip)
            if isinstance(zid, int):
                return ("zone", zid), judge.model.zones[zid].name, judge.model.zones[zid].sl_t
        n = net_of(ip)
        if n is None:
            return None, None, None
        return ("net", str(n[0])), f"{n[1]} ({n[0]}" + (f", L{float(n[2]):g})" if n[2] is not None else ")"), None

    src_ips = sorted({a.src_ip for a in attempts})
    hosts = {h.ip: h for h in db.query(Host).filter(Host.site_id == site_id, real_host_clause(), Host.ip.in_(src_ips))}
    by_ip = {}
    ids = [h.id for h in hosts.values()]
    if ids:
        dst_rows = db.query(Host.id, Host.ip).filter(Host.site_id == site_id)
        ip_of = {hid: ip for hid, ip in dst_rows}
        for s_id, d_id, port in db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id,
                                         NetworkSession.dst_port).filter(NetworkSession.src_host_id.in_(ids)):
            by_ip.setdefault(ip_of.get(s_id), set()).add((ip_of.get(d_id), port))
    try:
        from app.api.routes import _inventory_evidence
        inv = _inventory_evidence(db, site_id)
    except Exception:  # noqa: BLE001
        inv = {}
    out = []
    groups: dict = {}
    for a in attempts:
        if iz._public(a.dst_ip) or a.dst_ip in infra.iface_ips or a.src_ip in infra.iface_ips:
            continue
        if (a.dst_ip, a.dst_port) in by_ip.get(a.src_ip, set()):
            continue                                        # the same flow also got through: not "all dropped"
        sk, sname, _st = segment(a.src_ip)
        dk, dname, dsl = segment(a.dst_ip)
        if sk is None or dk is None or sk == dk:
            continue
        status, conduit = ("no_zones", None)
        if zoned and sk[0] == "zone" and dk[0] == "zone":
            c = judge.conduits.get(tuple(sorted((sk[1], dk[1]))))
            if c is None:
                status = "undocumented"
            else:
                conduit = c.name or "conduit"
                svcs = []
                try:
                    svcs = iz.parse_services(c.services) if c.services else []
                except iz.ZoneError:
                    svcs = []
                covered = bool(svcs) and iz.service_covered(svcs, a.transport, a.dst_port)
                if covered and c.sources:
                    try:
                        ad = ipaddress.ip_address(a.src_ip)
                        covered = any(ad.version == n.version and ad in n for n in iz.parse_sources(c.sources))
                    except (ValueError, iz.ZoneError):
                        covered = False
                status = "covered" if covered else ("outside_services" if c.services else "documented")
        elif zoned:
            status = "unzoned"
        groups.setdefault(a.src_ip, {"src_zone": sname, "targets": []})["targets"].append({
            "dst_ip": a.dst_ip, "port": a.dst_port, "transport": a.transport, "count": a.count or 1,
            "outcome": a.outcome, "zone": dname, "zone_sl_t": dsl, "status": status, "conduit": conduit,
            "service": _MGMT_PORTS.get(a.dst_port)})
    status_word = {"undocumented": "no documented conduit", "outside_services": "outside the conduit's services",
                   "documented": "documented conduit (no services listed)", "unzoned": "target in no zone",
                   "no_zones": "other firewall segment", "covered": "covered by the conduit"}
    for src_ip, g in sorted(groups.items()):
        h = hosts.get(src_ip)
        blocked = [t for t in g["targets"] if t["status"] != "covered"]
        covered = [t for t in g["targets"] if t["status"] == "covered"]

        def tlist(ts):
            return "; ".join(f"{t['dst_ip']}:{t['port']}" + (f" {t['service']}" if t["service"] else "")
                             + f" ×{t['count']} → {t['zone']} ({status_word[t['status']]})" for t in ts[:12]) \
                + (" …" if len(ts) > 12 else "")
        if blocked:
            mgmt = any(t["service"] for t in blocked)
            undoc = any(t["status"] in ("undocumented", "outside_services") for t in blocked)
            unclassified = h is None or ((h.device_type in (None, "ics_protocol_client_unclassified"))
                                         and h.classification_source != "manual")
            unknown = unclassified and not (inv.get(h.id) if h is not None else None)
            sev = "medium" if (mgmt or undoc or unknown) else "low"
            if unknown and mgmt:
                sev = "high"
            why = []
            if unknown:
                why.append("the source is not in any inventory and not classified")
            if mgmt:
                why.append("management / file-sharing ports were tried (" + ", ".join(sorted({t["service"] for t in blocked if t["service"]})) + ")")
            if undoc:
                why.append("the zone pair has no documented conduit, or the conduit does not cover the service")
            who = f"{src_ip}" + (f" ({h.hostname})" if h is not None and h.hostname else "")
            f = ae._make_finding(
                db, "blocked_cross_zone_attempts",
                f"Blocked attempts into other zones from {who} ({g['src_zone']}): "
                f"{len({t['dst_ip'] for t in blocked})} target(s), {len(blocked)} service(s)"
                + (" - unknown device" if unknown else ""),
                (f"{who} in {g['src_zone']} tried to reach {tlist(blocked)}, and every attempt was dropped (no "
                 "answer or refused, no session on that port). A host probing other zones - most of all one "
                 "nobody has identified, on management ports - is either misconfigured or exploring the network "
                 "(SR 5.1, SR 6.2). Identify the host (Inventory: classify or approve it), and check why it tries "
                 "these services." + ((" " + "; ".join(why).capitalize() + ".") if why else "")),
                {"ip": src_ip, "src_zone": g["src_zone"], "targets": blocked[:50],
                 "unknown_source": unknown, "management_ports": mgmt, "undocumented_path": undoc,
                 "device_type": h.device_type if h is not None else None,
                 "purdue_level": float(h.purdue_level) if h is not None and h.purdue_level is not None else None,
                 "severity_reason": ("High: " if sev == "high" else "Medium: " if sev == "medium" else "Low: ")
                 + ("; ".join(why) if why else "a few dropped attempts from an identified host")},
                severity=sev, dedup_evidence={"rule_key": f"blocked:{src_ip}"})
            if f is not None:
                out.append(f)
        if covered:
            f = ae._make_finding(
                db, "conduit_service_blocked",
                f"Designed traffic dropped: {src_ip} → " + ", ".join(sorted({t['conduit'] for t in covered}))
                + f" ({len(covered)} service(s))",
                (f"{src_ip} tried {tlist(covered)}: the documented conduit lists this service (and source), but the "
                 "firewall dropped the attempt. Either the conduit documentation is ahead of the firewall policy, "
                 "or the policy is missing - align the two."),
                {"ip": src_ip, "src_zone": g["src_zone"], "targets": covered[:50],
                 "severity_reason": "Info: documentation and firewall policy disagree"},
                severity="info", dedup_evidence={"rule_key": f"conduitblocked:{src_ip}"})
            if f is not None:
                out.append(f)
    return out
