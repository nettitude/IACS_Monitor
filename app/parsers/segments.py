"""
Flat control segments (VPN tabletop H-05).

``flat_control_segment`` (low; medium when broadly reachable from outside;
SR 5.1 network segmentation; workbook rows 1.2 / 1.3 zone definition)

One finding per segment - a firewall-connected subnet, else a switch VLAN -
that holds L1 controllers (PLC, RTU, IED, safety controller, field device)
AND L2 hosts (HMI, engineering workstation, historian, servers) with no
firewall between them.  A combined L1/L2 "cell/area zone" (CPwE) is a
legitimate 62443 design when it is a deliberate zone with one target security
level, so the finding is resolved by DECLARING the segment a cell/area zone
(Mgmt & Engineering page, purpose ``cell_zone`` on a network / VLAN) or by
acknowledging it.  It is medium while the segment is also reachable broadly
from outside it - a permit from an SSL-VPN tunnel, any service, or a broad
(/16 or wider / any) source into it - because then every exposure of an L2
host is an exposure of the controllers.
"""
from __future__ import annotations

import ipaddress
import logging

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

CHECK = "flat_control_segment"
PURPOSE_CELL = "cell_zone"
L1_TYPES = ("plc", "rtu", "rtu_or_ied", "ied", "safety", "sis", "modbus_device", "field_device",
            "actuator", "sensor", "drive", "vfd", "controller", "dcs_controller")


def _lvl(h):
    """The level this check judges a host by.  A host levelled by its firewall
    interface (owner 2026-10-14: the subnet's level applies to every host) is
    judged by what its device type says it is - an engineering workstation or
    historian on an L1-labelled subnet is still an L3 device sharing the
    controllers' segment, which is the flat-segment signal."""
    if h.classification_source == "interface_label" and h.device_type:
        from app.parsers.device_classification import DEVICE_TYPE_REFERENCE
        ref = DEVICE_TYPE_REFERENCE.get(h.device_type)
        if ref and ref[0] is not None:
            return ref[0]
    return h.purdue_level


def _is_l1(h) -> bool:
    if _lvl(h) is not None and _lvl(h) <= 1:
        return True
    # whole underscore-separated words: "unclassified" is not an "ied"
    dt = f"_{str(h.device_type or '').lower()}_"
    return h.purdue_level is None and any(f"_{t}_" in dt for t in L1_TYPES)


def _is_l2(h) -> bool:
    return _lvl(h) is not None and _lvl(h) == 2


_INFRA_TYPES = ("router", "firewall", "switch", "l3_switch", "gateway")

#: IO-04 / IO-05: OUI vendor words of consumer / SOHO network gear (Wi-Fi
#: access points, home routers) - never deliberate OT infrastructure
CONSUMER_NET_WORDS = ("tp-link", "tplink", "netgear", "ubiquiti", "asustek", "asus", "linksys",
                      "d-link", "dlink", "tenda", "mercusys", "belkin", "avm gmbh", "eero",
                      "xiaomi", "huawei device", "zte", "mikrotik", "routerboard", "edimax",
                      "buffalo", "totolink", "wavlink")
#: IO-04: OUI vendor words of consumer / mobile devices
CONSUMER_DEVICE_WORDS = ("apple", "samsung", "google", "oneplus", "oppo", "vivo mobile", "huawei device",
                         "xiaomi", "motorola mobility", "amazon technologies", "sony mobile", "nintendo",
                         "realme", "honor device", "lg electronics (mobile")


def vendor_matches(vendor, words) -> bool:
    v = str(vendor or "").lower()
    return bool(v) and any(w in v for w in words)


def capture_networks(db: DBSession) -> list:
    """FO-01: [(ip_network, capture id, gateway macs, domain label)] of the
    site's capture networks that no firewall subnet covers (a firewall subnet
    is the better segment).  IO-03: networks of one capture that share a
    layer-2 segment (``domains`` of the capture segment) carry the same
    domain label ("192.168.0.0/24 + 192.168.1.0/24")."""
    import json
    from app.models import Firewall, FirewallInterface, PcapCapture
    fw = []
    for (cidr,) in db.query(FirewallInterface.network_cidr).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            FirewallInterface.network_cidr.isnot(None)):
        try:
            fw.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    out, seen = [], set()
    for cid, raw in db.query(PcapCapture.id, PcapCapture.segment).filter(PcapCapture.segment.isnot(None)) \
            .order_by(PcapCapture.id.desc()):
        try:
            seg = json.loads(raw)
        except ValueError:
            continue
        kept = []
        for cidr in seg.get("networks") or []:
            try:
                n = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if n in seen or any(n.version == f.version and n.overlaps(f) for f in fw):
                continue
            seen.add(n)
            kept.append(n)
        dom_of = {}
        for grp in seg.get("domains") or []:
            members = [m for m in kept if str(m) in grp]
            for m in members:
                dom_of[m] = " + ".join(str(x) for x in members)
        gws = set(seg.get("gateway_macs") or [])
        for n in kept:
            out.append((n, cid, gws, dom_of.get(n, str(n))))
    return out


def _infra(h, gws) -> bool:
    """Network infrastructure, not a member of a segment.  IO-05: a manual
    classification as something else wins over the capture's gateway list,
    and consumer network gear is never infrastructure (it is reported)."""
    dt = str(h.device_type or "").lower()
    if h.classification_source == "manual" and dt not in _INFRA_TYPES:
        return False
    if vendor_matches(getattr(h, "vendor", None), CONSUMER_NET_WORDS):
        return False
    return dt in _INFRA_TYPES or bool(h.mac and h.mac.lower() in gws)


def segments(db: DBSession) -> list[dict]:
    """[{key, kind, network?, vlan?, l1: [hosts], l2: [hosts], upper: [hosts]}]
    - firewall subnets first, then capture segments (FO-01); hosts on
    neither are grouped by switch VLAN.  ``upper`` (capture segments only)
    holds the on-link L3+ hosts."""
    from app.models import Firewall, FirewallInterface, Host
    nets = []
    for cidr, lv in db.query(FirewallInterface.network_cidr, FirewallInterface.purdue_level).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            FirewallInterface.network_cidr.isnot(None)):
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if 0 < n.prefixlen < n.max_prefixlen and n not in [x for x, _ in nets]:
            nets.append((n, lv))
    nets.sort(key=lambda x: -x[0].prefixlen)          # most specific first
    caps = capture_networks(db)
    seg: dict = {}
    for h in db.query(Host).filter(Host.ip.isnot(None)):
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            continue
        net = next((n for n, _lv in nets if n.version == a.version and a in n), None)
        cap = None if net is not None else next(
            ((n, cid, g, d) for n, cid, g, d in caps if n.version == a.version and a in n), None)
        if cap is not None:
            n, cid, gws, dom = cap
            # on-link members only: a host with no MAC was seen through a router
            if not h.mac or _infra(h, gws):
                continue
            key = f"capture:{dom}"
            s = seg.setdefault(key, {"key": key, "kind": "capture", "network": dom, "capture_id": cid,
                                     "networks": dom.split(" + "),
                                     "vlans": set(), "l1": [], "l2": [], "upper": [], "unknown": []})
            # SF-8a: a level taken from the interface label does not make a
            # host a controller - it stays an unclassified member
            if h.classification_source == "interface_label" and not h.device_type:
                s["unknown"].append(h)
            elif _is_l1(h):
                s["l1"].append(h)
            elif _is_l2(h):
                s["l2"].append(h)
            elif _lvl(h) is not None and _lvl(h) >= 3:
                s["upper"].append(h)
            else:
                s["unknown"].append(h)
            continue
        if not (_is_l1(h) or _is_l2(h)) or (h.classification_source == "interface_label" and not h.device_type):
            continue
        if net is not None:
            key = f"subnet:{net}"
            s = seg.setdefault(key, {"key": key, "kind": "subnet", "network": str(net),
                                     "vlans": set(), "l1": [], "l2": [], "upper": []})
        elif h.vlan:
            key = f"vlan:{h.vlan}"
            s = seg.setdefault(key, {"key": key, "kind": "vlan", "network": None,
                                     "vlans": set(), "l1": [], "l2": [], "upper": []})
        else:
            continue
        if h.vlan:
            s["vlans"].add(str(h.vlan))
        (s["l1"] if _is_l1(h) else s["l2"]).append(h)
    # IO-03: on a capture segment unclassified members count as "other" too
    return [s for s in seg.values() if s["l1"] and (s["l2"] or s["upper"] or s.get("unknown"))]


def same_capture_segment(db: DBSession):
    """FO-02: predicate(src_host, dst_host) - both on-link members of one
    capture segment (traffic between them crosses no router)."""
    caps = capture_networks(db)
    if not caps:
        return lambda _a, _b: False

    def _net(h):
        if not h.ip or not h.mac:
            return None
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            return None
        for n, _cid, gws, dom in caps:
            if n.version == a.version and a in n:
                return None if _infra(h, gws) else dom
        return None

    def pred(a, b) -> bool:
        na = _net(a)
        return na is not None and na == _net(b)
    return pred


def ot_capture_segment_of(db: DBSession):
    """FO-05: function(host) -> the capture network (str) the host is an
    on-link member of when that segment also holds L0-L2 devices, else None.
    Hosts there are OT-adjacent whatever their own (missing) level."""
    from app.models import Firewall, FirewallInterface, Host
    caps = capture_networks(db)
    # RS-12: networks behind a firewall / routing-switch interface are
    # segments too (capture_networks leaves out what a firewall subnet covers)
    seen = {n for n, *_ in caps}
    for (cidr,) in db.query(FirewallInterface.network_cidr).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            FirewallInterface.network_cidr.isnot(None)):
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if n.prefixlen == 0 or n in seen or n.num_addresses > 65536:
            continue
        seen.add(n)
        caps.append((n, None, set(), str(n)))
    if not caps:
        return lambda _h: None
    ot_nets = set()
    for h in db.query(Host).filter(Host.ip.isnot(None), Host.mac.isnot(None)):
        if not (_is_l1(h) or _is_l2(h) or (h.purdue_level is not None and h.purdue_level <= 2)):
            continue
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            continue
        for n, _cid, gws, dom in caps:
            if n.version == a.version and a in n and not _infra(h, gws):
                ot_nets.add(dom)

    via = _routed_to_ot(db, caps, ot_nets)

    def of(h):
        if h is None or not h.ip or not h.mac:
            return None
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            return None
        for n, _cid, gws, dom in caps:
            if n.version == a.version and a in n and not _infra(h, gws):
                if dom in ot_nets:
                    return dom
                if dom in via:
                    return f"{dom} (routed to {via[dom][0]} by {via[dom][1]})"
        return None
    return of


def _routed_to_ot(db: DBSession, caps: list, ot_nets: set) -> dict:
    """RS-12: {capture segment: (OT segment, router name)} for segments
    without L0-L2 devices whose hosts the capture shows exchanging traffic
    with an OT segment through a router that is not a known firewall (a
    routing switch, or a router no config describes).  Nothing filters that
    path as far as the data shows, so those hosts are OT-adjacent too."""
    from app.models import Firewall, Host, NetworkSession
    from app.parsers.common import normalize_mac
    if not ot_nets:
        return {}
    try:
        from app.parsers.l3_switch import VENDOR, router_macs
        rmacs = router_macs(db)
        kinds = {fid: (name, vendor) for fid, name, vendor in db.query(Firewall.id, Firewall.name, Firewall.vendor)}
    except Exception:                                   # noqa: BLE001
        rmacs, kinds, VENDOR = {}, {}, None

    def dom_of(ip):
        try:
            a = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return None
        for n, _cid, _gws, dom in caps:
            if n.version == a.version and a in n:
                return dom
        return None

    ips = {hid: ip for hid, ip in db.query(Host.id, Host.ip).filter(Host.ip.isnot(None))}
    out: dict = {}
    for sid, did, cm in db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id,
                                 NetworkSession.carrier_mac).filter(
                                     NetworkSession.carrier_mac.isnot(None)).yield_per(2000):
        a, b = dom_of(ips.get(sid)), dom_of(ips.get(did))
        if not a or not b or a == b or ((a in ot_nets) == (b in ot_nets)):
            continue
        fid = rmacs.get(normalize_mac(cm))
        name, vendor = kinds.get(fid, (None, None)) if fid is not None else (None, None)
        if fid is not None and vendor != VENDOR:
            continue                    # a firewall carried it: filtered path
        other, ot = (a, b) if b in ot_nets else (b, a)
        out.setdefault(other, (ot, name or f"router {cm}"))
    return out


def _cross_level_flows(db: DBSession, seg: dict) -> list:
    """FO-02: sessions observed directly between members of a capture
    segment whose levels differ in the way session_it_ot_bypass judges
    (L3+ <-> L0-L1, L4+ <-> L2).  [{src, src_level, dst, dst_level, ports, kind}]"""
    from sqlalchemy import or_
    from app.models import NetworkSession
    from app.parsers.alert_engine import _bypass_kind
    members = {h.id: h for h in seg["l1"] + seg["l2"] + seg["upper"]}
    if not members:
        return []
    ids = sorted(members)
    flows: dict = {}
    for k in range(0, len(ids), 500):
        chunk = ids[k:k + 500]
        for ns in db.query(NetworkSession).filter(or_(NetworkSession.src_host_id.in_(chunk),
                                                      NetworkSession.dst_host_id.in_(chunk))):
            a, b = members.get(ns.src_host_id), members.get(ns.dst_host_id)
            if a is None or b is None or a.purdue_level is None or b.purdue_level is None:
                continue
            kind = _bypass_kind(a.purdue_level, b.purdue_level)
            if kind is None:
                continue
            hi, lo = (a, b) if a.purdue_level > b.purdue_level else (b, a)
            f = flows.setdefault((hi.ip, lo.ip), {"src": hi.ip, "src_level": float(hi.purdue_level),
                                                  "dst": lo.ip, "dst_level": float(lo.purdue_level),
                                                  "ports": set(), "kind": kind})
            if ns.dst_port is not None:
                f["ports"].add(int(ns.dst_port))
    out = []
    for f in sorted(flows.values(), key=lambda f: (-f["src_level"], f["dst_level"], f["src"], f["dst"])):
        f["ports"] = sorted(f["ports"])
        out.append(f)
    return out


def _cell_zones(db: DBSession) -> tuple:
    from app.models import ManagementNetwork
    nets, vlans = [], set()
    for r in db.query(ManagementNetwork).filter(ManagementNetwork.purpose == PURPOSE_CELL):
        if r.kind == "subnet" and r.cidr:
            try:
                nets.append(ipaddress.ip_network(r.cidr, strict=False))
            except ValueError:
                pass
        elif r.kind == "vlan" and r.vlan_id is not None:
            vlans.add(str(r.vlan_id))
    return nets, vlans


def _declared(seg: dict, cell_nets, cell_vlans) -> bool:
    if seg["network"]:
        ns = [ipaddress.ip_network(x) for x in (seg.get("networks") or [seg["network"]])]
        if all(any(n.version == c.version and n.subnet_of(c) for c in cell_nets) for n in ns):
            return True
    return bool(seg["vlans"]) and seg["vlans"] <= cell_vlans


def _exposure(db: DBSession, seg: dict) -> list[str]:
    """Permits that reach the segment broadly from outside it."""
    from app.models import FirewallRule
    from app.parsers import rule_match as rm
    from app.parsers.vpn import remote_tunnels, zone_is_remote
    if not seg["network"] or " + " in seg["network"]:
        return []
    try:
        target = rm.parse_address(seg["network"])
    except Exception:
        return []
    out = []
    _tun = remote_tunnels(db)
    for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(True)):
        if str(r.action or "").lower() not in ("permit", "accept", "allow", "pass"):
            continue
        try:
            dst = rm.parse_address(r.dst, v6_default_is_any=False)
            src = rm.parse_address(r.src, v6_default_is_any=False)
        except Exception:
            continue
        if isinstance(dst, rm.Unresolved) or rm.addr_overlaps(dst, target) is not True:
            continue
        if not isinstance(src, rm.Unresolved) and src != rm.ANY and rm.addr_contains(target, src) is True:
            continue                                  # traffic inside the segment
        why = None
        if zone_is_remote(r.src_zone, _tun.get(r.firewall_id, ())):
            why = ("SSL-VPN users" if zone_is_remote(r.src_zone, ()) else "dial-up IPsec VPN users")
        elif src == rm.ANY or (not isinstance(src, rm.Unresolved) and rm.is_family_wide(src)):
            why = "any source"
        elif str(r.dst_port or "any").lower() in ("any", "", "0-65535", "1-65535"):
            why = "any service"
        elif not isinstance(src, rm.Unresolved):
            try:
                v, lo, hi = rm.addr_bounds(src)
                if hi - lo + 1 >= (1 << 16 if v == 4 else 1 << 80):
                    why = "a /16-or-wider source"
            except Exception:
                pass
        if why:
            label = f"{r.device_name or '?'} #{r.policy_id} {r.policy_name or ''}".strip()
            item = f"{label} ({why})"
            if item not in out:
                out.append(item)
    return out


def _fmt_lv(v) -> str:
    return f"L{int(v)}" if float(v).is_integer() else f"L{v}"


def review_flat_control_segments(db: DBSession) -> list:
    from app.parsers import alert_engine as ae
    cell_nets, cell_vlans = _cell_zones(db)
    out = []
    for seg in segments(db):
        if _declared(seg, cell_nets, cell_vlans):
            continue
        exposure = _exposure(db, seg)
        where = seg["network"] or f"VLAN {sorted(seg['vlans'])[0]}"
        vl = f" (VLAN {', '.join(sorted(seg['vlans']))})" if seg["vlans"] and seg["network"] else ""
        l1 = [f"{h.ip} {h.device_type or 'L1'}" for h in seg["l1"]][:20]
        l2 = [f"{h.ip} {h.device_type or 'L2'}" for h in seg["l2"]][:20]
        upper = [f"{h.ip} {h.device_type or ''} ({_fmt_lv(h.purdue_level)})".replace("  ", " ")
                 for h in seg["upper"]][:20]
        unknown = [f"{h.ip} {h.vendor or h.mac or ''}".strip() for h in seg.get("unknown", [])][:20]
        capture = seg["kind"] == "capture"
        flows = _cross_level_flows(db, seg) if capture else []
        enterprise = [h for h in seg["upper"] if h.purdue_level >= 4]
        it_to_field = [f for f in flows if f["src_level"] >= 4 and f["dst_level"] <= 1]
        if it_to_field:
            severity = "critical"
            reason = ("Critical: an enterprise host (L4+) on the segment exchanged traffic directly with "
                      f"L0-L1 controllers ({', '.join(f['src'] + ' → ' + f['dst'] for f in it_to_field[:3])}).")
        elif enterprise:
            severity = "high"
            reason = ("High: enterprise hosts (L4+) share the controllers' layer-2 segment "
                      f"({', '.join(h.ip for h in enterprise[:5])}).")
        elif seg["upper"] or unknown or exposure:
            severity = "medium"
            reason = (f"Medium: L3 hosts share the controllers' segment ({', '.join(h.ip for h in seg['upper'][:5])})."
                      if seg["upper"] else
                      f"Medium: hosts of unknown role share the controllers' segment ({', '.join(unknown[:5])})."
                      if unknown else
                      f"Medium: the segment is also reachable broadly from outside it ({'; '.join(exposure[:3])}).")
        else:
            severity = "low"
            reason = ("Low: no broad access into the segment (medium when it is reachable "
                      "by VPN users, any service or a /16+ source).")
        multi = capture and len(seg.get("networks") or []) >= 2
        if multi and severity not in ("critical",):
            severity = "high"
            reason = (f"High: {len(seg['networks'])} subnets share one layer-2 segment with no router "
                      "between them - any host can add an address and reach every subnet, controllers "
                      "included (IO-03).")
        src_txt = (f"capture segment {where} (capture #{seg['capture_id']})" if capture else f"segment {where}{vl}")
        title = (f"Flat control segment {where}{vl}"
                 + (f" (one layer-2 segment, {len(seg['networks'])} subnets, no router)" if multi else "")
                 + f": {len(seg['l1'])} L1 controller(s) share it with "
                 f"{len(seg['l2'])} L2 host(s)"
                 + (f" and {len(seg['upper'])} L3+ host(s)" if seg["upper"] else "")
                 + (f" and {len(unknown)} unclassified host(s)" if unknown else "")
                 + (f" [{len(flows)} direct cross-level flow(s)]" if flows else "")
                 + (" [broadly reachable]" if exposure else ""))
        text = (f"The {src_txt} holds L1 controllers ({', '.join(l1)}) and "
                + (f"L2 hosts ({', '.join(l2)})" if l2 else "no L2 hosts")
                + (f" and L3+ hosts ({', '.join(upper)})" if upper else "")
                + (f", plus unclassified hosts ({', '.join(unknown)})" if unknown else "")
                + " with no firewall between them. ")
        if capture:
            text += ("The segment was taken from the capture (no firewall or switch data places it): its "
                     "members exchange frames directly, MAC to MAC, without a router. ")
        if multi:
            text += (f"The subnets {', '.join(seg['networks'])} are stacked on that one wire (a multi-homed "
                     "host or direct frames between them prove it): subnetting separates nothing here - a "
                     "device that adds an address in another subnet reaches it directly. ")
        text += ("A combined L1/L2 cell/area zone is a legitimate design when it is a deliberate zone with "
                 "one target security level - declare it as a cell/area zone (Mgmt & Engineering page) to "
                 "record that decision - otherwise separate the controllers behind their own boundary "
                 "(IEC 62443-3-3 SR 5.1; rows 1.2 / 1.3 zone definition). ")
        if unknown:
            text += "Classify the unclassified hosts: their level decides how serious the segment is. "
        if upper:
            text += ("Site-operations or enterprise hosts on the same segment are never a cell/area zone: "
                     "move them behind a boundary. ")
        if flows:
            text += ("Cross-level traffic observed directly on the segment (each skips the levels in between): "
                     + "; ".join(f"{f['src']} ({_fmt_lv(f['src_level'])}) → {f['dst']} ({_fmt_lv(f['dst_level'])})"
                                 f" {', '.join(map(str, f['ports'][:6])) or ''}".rstrip()
                                 for f in flows[:15])
                     + (f"; and {len(flows) - 15} more" if len(flows) > 15 else "") + ". ")
        if exposure:
            text += (f"The segment is also reachable broadly from outside it ({'; '.join(exposure[:5])}): "
                     "every exposure of an L2 host there is an exposure of the controllers.")
        f = ae._make_finding(
            db, CHECK, title[:512], text.strip(),
            {"segment": seg["key"], "network": seg["network"], "vlans": sorted(seg["vlans"]),
             "source": "capture" if capture else seg["kind"], "capture_id": seg.get("capture_id"),
             "networks": seg.get("networks") or ([seg["network"]] if seg["network"] else []),
             "l1_hosts": l1, "l2_hosts": l2, "upper_hosts": upper, "unclassified_hosts": unknown, "exposure": exposure,
             "cross_level_flows": flows[:50], "cross_level_flow_count": len(flows),
             "fix": ("Separate the controllers behind their own boundary and move L3+ hosts off the "
                     "segment; or declare an L1/L2 segment a cell/area zone." if capture else
                     "Declare the segment a cell/area zone, or separate L1 behind a firewall."),
             "severity_reason": reason},
            severity=severity, dedup_evidence={"rule_key": f"flat_segment:{seg['key']}"})
        if f is not None:
            out.append(f)
    return out


# --------------------------------------------------------------- IO-02 --
def review_multi_homed_hosts(db: DBSession) -> list:
    """IO-02: one MAC with addresses in two or more subnets (capture
    networks, else the /24 of each address) - a multi-homed host bridging
    them.  High when the subnets hold devices of different Purdue levels,
    medium otherwise.  Routers, firewalls and the captures' gateways are
    infrastructure, not multi-homed hosts."""
    from app.models import Host, NetworkSession
    from app.parsers import alert_engine as ae
    from app.models import real_host_clause
    from sqlalchemy import or_
    caps = capture_networks(db)
    gws = set()
    for _n, _c, g, _d in caps:
        gws |= g
    infra_ips, infra_macs, _vpn = ae._known_infrastructure(db)
    by_mac: dict = {}
    for h in db.query(Host).filter(real_host_clause(), Host.mac.isnot(None), Host.ip.isnot(None)):
        by_mac.setdefault(h.mac.lower(), []).append(h)

    def net_of(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for n, _c, _g, _d in caps:
            if a.version == n.version and a in n:
                return n
        if a.version == 4 and a.is_private:
            return ipaddress.ip_network(f"{a}/24", strict=False)
        return None

    # levels per subnet, by MAC, so a host's own addresses can be left out
    levels_by: dict = {}
    all_hosts = [h for hs in by_mac.values() for h in hs]
    for h in all_hosts:
        n = net_of(h.ip)
        if n is not None and h.purdue_level is not None:
            levels_by.setdefault(n, {}).setdefault((h.mac or "").lower(), set()).add(float(h.purdue_level))
    out = []
    for mac, rows in sorted(by_mac.items()):
        rows = [h for h in rows if not _infra(h, gws) and h.ip not in infra_ips]
        if mac in infra_macs or len(rows) < 2:
            continue
        nets: dict = {}
        for h in rows:
            n = net_of(h.ip)
            if n is not None:
                nets.setdefault(n, []).append(h)
        if len(nets) < 2:
            continue
        ids = [h.id for h in rows]
        peers: dict = {}
        for s_id, d_id in db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id).filter(
                or_(NetworkSession.src_host_id.in_(ids), NetworkSession.dst_host_id.in_(ids))).limit(5000):
            me, other = (s_id, d_id) if s_id in ids else (d_id, s_id)
            peers.setdefault(me, set()).add(other)
        peer_hosts = {h.id: h for h in db.query(Host).filter(Host.id.in_(
            sorted({o for v in peers.values() for o in v})))} if peers else {}
        # the other devices' levels on each subnet (not the host's own)
        lv_sets = {str(n): sorted({x for m, v in levels_by.get(n, {}).items() if m != mac for x in v})
                   for n in nets}
        distinct = {tuple(v) for v in lv_sets.values() if v}
        # high: the subnets hold different levels, or one holds controllers /
        # field devices (L0-L1) that the bridge exposes to the other subnets
        control = any(x <= 1 for v in lv_sets.values() for x in v)
        severity = "high" if len(distinct) >= 2 or control else "medium"
        vendor = next((h.vendor for h in rows if h.vendor), None)
        addrs = sorted(h.ip for h in rows)
        talk = []
        for n, hs in nets.items():
            ps = sorted({peer_hosts[o].ip for h in hs for o in peers.get(h.id, ()) if o in peer_hosts
                         and peer_hosts[o].ip})
            talk.append(f"{', '.join(h.ip for h in hs)} in {n}" + (f" talks to {', '.join(ps[:5])}" if ps else ""))
        lv_txt = "; ".join(f"{n}: " + (", ".join(f"L{int(x) if float(x).is_integer() else x}" for x in v)
                                         if v else "levels unknown") for n, v in lv_sets.items())
        f = ae._make_finding(
            db, "multi_homed_host",
            f"Multi-homed host bridges {len(nets)} subnets: {', '.join(addrs)} / {mac}"
            + (f" ({vendor})" if vendor else ""),
            (f"One network interface (MAC {mac}) holds addresses in {len(nets)} subnets: "
             + "; ".join(talk) + ". It joins those subnets directly, whatever routing or firewall "
             "design separates them, and anything that compromises it reaches all of them "
             f"(SR 5.1 zone separation; workbook row 2.6). Levels on each subnet: {lv_txt}. Remove the "
             "extra addresses, or put a firewall / dedicated interfaces between the subnets and "
             "document the host as a conduit."),
            {"mac": mac, "addresses": addrs, "vendor": vendor,
             "subnets": sorted(str(n) for n in nets), "levels_by_subnet": lv_sets,
             "severity_reason": ("High: the subnets hold devices of different Purdue levels."
                                 if len(distinct) >= 2 else
                                 "High: it exposes controllers / field devices (L0-L1) to another subnet."
                                 if severity == "high" else
                                 "Medium: the bridged subnets show no level difference (yet).")},
            severity=severity, dedup_evidence={"rule_key": f"multi_homed:{mac}"})
        if f is not None:
            out.append(f)
    return out


# --------------------------------------------------------------- IO-04 --
def review_rogue_dhcp_servers(db: DBSession) -> list:
    """IO-04: a host that answered DHCP (OFFER / ACK) in a capture.  OT
    networks are statically addressed as a rule; a DHCP server there is
    usually consumer gear or a laptop sharing its connection, and it hands
    out a default gateway (itself) - a ready man-in-the-middle."""
    import json
    from app.models import Host, PcapCapture
    from app.parsers import alert_engine as ae
    servers: dict = {}
    for cid, raw in db.query(PcapCapture.id, PcapCapture.segment).filter(PcapCapture.segment.isnot(None)):
        try:
            seg = json.loads(raw)
        except ValueError:
            continue
        for srv in seg.get("dhcp_servers") or []:
            cur = servers.setdefault(srv.get("mac") or srv.get("ip"), {**srv, "captures": []})
            cur["captures"].append(cid)
            for lease in srv.get("leases") or []:
                if lease not in cur["leases"]:
                    cur["leases"].append(lease)
    out = []
    for key, srv in sorted(servers.items()):
        h = db.query(Host).filter(Host.mac == srv.get("mac")).first() if srv.get("mac") else None
        vendor = h.vendor if h is not None else None
        consumer = vendor_matches(vendor, CONSUMER_NET_WORDS)
        f = ae._make_finding(
            db, "rogue_dhcp_server",
            f"DHCP server on the network: {srv.get('ip')} / {srv.get('mac')}" + (f" ({vendor})" if vendor else ""),
            (f"{srv.get('ip')} ({srv.get('mac')}{', ' + vendor if vendor else ''}) answered DHCP in the capture: "
             f"{srv.get('offers', 0)} offer(s), {srv.get('acks', 0)} acknowledgement(s), leases "
             f"{', '.join(srv.get('leases') or []) or 'none seen'}"
             + (f", default gateway handed out: {srv['router']}" if srv.get("router") else "") + ". "
             "An OT network is normally statically addressed; a DHCP server there is often consumer gear "
             "or a laptop sharing its connection. Any device that takes a lease uses the gateway the server "
             "names - a ready man-in-the-middle and exfiltration path (SR 7.6, SR 5.1). Find the device and "
             "switch its DHCP server off or remove it; if DHCP is deliberate, document the server and "
             "reserve the addresses."),
            {"ip": srv.get("ip"), "mac": srv.get("mac"), "vendor": vendor, "offers": srv.get("offers"),
             "acks": srv.get("acks"), "leases": srv.get("leases"), "router": srv.get("router"),
             "consumer_gear": consumer, "captures": srv["captures"],
             "severity_reason": "High: an undeclared DHCP server hands out addresses and a gateway."},
            dedup_evidence={"rule_key": f"dhcp_server:{key}"})
        if f is not None:
            out.append(f)
    return out
