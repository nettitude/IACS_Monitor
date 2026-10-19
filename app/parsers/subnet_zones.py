"""Routed-OT tabletop G3: operator zones per subnet.

The capture and the configs show the site's subnets; the operator says what
each one is - a Purdue level and a zone name (IEC 62443-3-2 zones).  That is
a handful of decisions instead of one per device, and it covers devices that
turn up later.

* ``discover(db)``  every subnet the data shows (capture segments, firewall /
  switch interface networks, declarations), with its VLAN, names, hosts,
  evidence, a suggested level / zone and the operator's declaration.
* ``apply(db)``     hosts in a declared subnet that no stronger evidence
  classifies take its level (source ``subnet_declared``); firewall / switch
  interfaces on that network without an operator level take it too
  (``purdue_suggestion_source = "zone_declared"``).  Runs at the end of
  ``classify_hosts`` and after every declaration change.
* ``mismatches(db)`` devices whose own evidence (manual classification or
  protocol role) disagrees with their subnet's declared level - reported by
  ``review_misplaced_devices`` (row 2.7), never silently overridden.

Owner decisions (2026-10-09): VoIP, CCTV and building systems are IT /
non-OT services, L4 (L5 is the Internet); a device that does not match its
zone is flagged.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from collections import Counter
from typing import Optional

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

SOURCE = "subnet_declared"
IFACE_SOURCE = "zone_declared"
#: SF-8a: a host on the network of a labelled firewall / switch interface
#: with no evidence of its own takes that interface's level
LABEL_SOURCE = "interface_label"
#: owner 2026-10-14: a labelled interface's level applies to every host on its network
#: except these - a manual classification (set on the Host Topology / Inventory), a
#: Subnets & Zones declaration (handled above the label), and the identities that are
#: not devices of the subnet (remote VPN users, the capture's gateway, routers)
_LABEL_KEEPS = ("manual", "subnet_declared", "vpn_pool", "capture_gateway", "router", "remote_vpn_user")
_LINK_TYPES = ("vdom-link", "npu-vlink", "vdom_link", "tunnel")
#: classifications a zone declaration overrides (weaker evidence)
_WEAK = (None, "oui_hint", "protocol_client_hint", "vlan_inferred", "lldp_role_inferred", SOURCE, "interface_label", "object_name")
_INFRA = {"router", "switch", "firewall", "wireless_ap"}

# zone keywords in VLAN / interface names -> (level, zone name)
_NAME_HINTS = [
    (("voip", "voice", "phone", "telephony", "sip"), 4, "VoIP"),
    (("cctv", "video", "camera", "cam", "nvr", "surveillance"), 4, "CCTV"),
    (("bms", "hvac", "building", "access-control", "badge"), 4, "Building systems"),
    (("guest", "wifi", "wlan", "corp", "office", "business", "enterprise"), 4, "IT"),
    (("dmz",), 3.5, "Industrial DMZ"),
    (("plc", "control", "controller", "rtu", "ics", "io", "field", "drive", "drives", "vfd"), 1, "Control"),
    (("hmi", "scada", "supervisory", "operator"), 2, "Supervisory"),
    (("historian", "mes", "server", "servers", "site", "workstation", "workstations", "ews",
      "engineering"), 3, "Site operations"),
    (("mgmt", "management", "oob", "net-mgmt", "netmgmt"), 3, "Network management"),
]
_PHONE_VENDORS = ("polycom", "yealink", "avaya", "mitel", "grandstream", "snom", "aastra", "gigaset",
                  "fanvil", "htek", "alcatel-lucent enterprise", "audiocodes")
_CAMERA_VENDORS = ("hikvision", "dahua", "axis communications", "hanwha", "samsung techwin", "bosch security",
                   "uniview", "zhejiang uniview", "vivotek", "mobotix", "avigilon", "milestone", "pelco",
                   "flir", "hangzhou ezviz", "tiandy", "honeywell security")
_NETGEAR_VENDORS = ("cisco", "aruba", "hewlett packard enterprise", "juniper", "hirschmann", "ruggedcom",
                    "westermo", "extreme networks", "arista", "brocade", "allied telesis", "netgear", "d-link",
                    "phoenix contact", "moxa")
_ICS_SERVER_PORTS = {502, 102, 44818, 20000, 2404, 34964, 1911, 18245, 20547, 9600, 5007, 4000}


def _net(cidr) -> Optional[ipaddress._BaseNetwork]:
    try:
        n = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None
    return n if 0 < n.prefixlen else None


def _site(db) -> Optional[int]:
    from app.parsers.site_scope import current_site
    from app.sites import scope_site_id
    sid = current_site(db)
    return int(sid) if sid is not None else scope_site_id(db)


def declarations(db) -> dict:
    """{network: SubnetZone} of the current site."""
    from app.models import SubnetZone
    out = {}
    for z in db.query(SubnetZone).filter(SubnetZone.site_id == _site(db)):
        n = _net(z.cidr)
        if n is not None:
            out[n] = z
    return out


def _declared_for(decl: dict):
    """function(ip) -> (network, SubnetZone) of the most specific declared subnet."""
    nets = sorted(decl, key=lambda n: n.prefixlen, reverse=True)
    cache: dict = {}

    def f(ip):
        if ip in cache:
            return cache[ip]
        r = None
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            a = None
        if a is not None:
            for n in nets:
                if n.version == a.version and a in n:
                    r = (n, decl[n])
                    break
        cache[ip] = r
        return r
    return f


# ------------------------------------------------------- interface labels --
def labelled_networks(db, sid=None) -> list:
    """SF-8a: [(network, level, firewall name, interface name)] of every
    interface the operator labelled (``purdue_level`` set, no automatic
    source) on the site's firewalls and routing switches.  Automatic levels
    do not count: an SVI's level may itself come from its hosts (circular),
    a zone's level already covers the hosts, a transit has none.  Inter-VDOM
    links and tunnels never count.  Most specific network first."""
    from app.models import Firewall, FirewallInterface
    sid = _site(db) if sid is None else sid
    out = []
    for i, fw_name in (db.query(FirewallInterface, Firewall.name)
                       .join(Firewall, Firewall.id == FirewallInterface.firewall_id)
                       .filter(Firewall.site_id == sid, FirewallInterface.network_cidr.isnot(None),
                               FirewallInterface.purdue_level.isnot(None),
                               FirewallInterface.purdue_suggestion_source.is_(None))):
        if (i.iface_type or "") in _LINK_TYPES:
            continue
        n = _net(i.network_cidr)
        if n is None:
            continue
        out.append((n, float(i.purdue_level), fw_name, i.name))
    out.sort(key=lambda t: (-t[0].prefixlen, str(t[0])))
    return out


def _labelled_for(nets: list):
    """function(ip) -> (network, level, firewall, interface) of the most
    specific labelled interface network, else None."""
    cache: dict = {}

    def f(ip):
        if ip in cache:
            return cache[ip]
        r = None
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            a = None
        if a is not None:
            for n, lvl, fw, name in nets:
                if n.version == a.version and a in n:
                    r = (n, lvl, fw, name)
                    break
        cache[ip] = r
        return r
    return f


# ---------------------------------------------------------------- apply --
def apply(db) -> dict:
    """Push the declarations onto hosts and interfaces, then the interface
    labels onto the hosts no declaration covers (SF-8a).  Returns counts."""
    from app.models import Firewall, FirewallInterface, Host
    sid = _site(db)
    decl = declarations(db)
    find = _declared_for(decl)
    stats = {"hosts_set": 0, "hosts_cleared": 0, "interfaces_set": 0, "interfaces_cleared": 0,
             "hosts_labelled": 0, "hosts_unlabelled": 0}
    # interfaces first: a host's label (below) is read from the interfaces
    by_net = {n: z for n, z in decl.items() if z.purdue_level is not None}
    for i in db.query(FirewallInterface).join(Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == sid, FirewallInterface.network_cidr.isnot(None)):
        n = _net(i.network_cidr)
        z = by_net.get(n) if n is not None else None
        from app.parsers.l3_switch import AUTO_SOURCE
        from app.parsers.edge_links import EDGE_SOURCE
        free = i.purdue_level is None or i.purdue_suggestion_source in (AUTO_SOURCE, IFACE_SOURCE, EDGE_SOURCE)
        if z is not None and free:
            if (i.purdue_level, i.purdue_suggestion_source) != (z.purdue_level, IFACE_SOURCE):
                i.purdue_level, i.purdue_suggestion_source = z.purdue_level, IFACE_SOURCE
                i.suggested_purdue_level = None
                if not i.zone_label and z.zone_name:
                    i.zone_label = z.zone_name
                stats["interfaces_set"] += 1
        elif z is None and i.purdue_suggestion_source == IFACE_SOURCE:
            i.purdue_level, i.purdue_suggestion_source = None, None
            stats["interfaces_cleared"] += 1
    db.flush()
    # SF-8a: the labels are read after the interface pass above
    label = _labelled_for(labelled_networks(db, sid))
    for h in db.query(Host).filter(Host.site_id == sid, Host.ip.isnot(None)):
        if str(h.device_type or "").lower() in _INFRA:
            continue
        hit = find(h.ip) if h.classification_source in _WEAK else None
        lvl = hit[1].purdue_level if hit else None
        if lvl is not None:
            if (h.purdue_level, h.classification_source) != (lvl, SOURCE):
                h.purdue_level, h.classification_source = lvl, SOURCE
                if h.device_type == "vlan_inferred":
                    h.device_type = None
                stats["hosts_set"] += 1
            continue
        if h.classification_source == SOURCE:
            h.purdue_level, h.classification_source = None, None
            stats["hosts_cleared"] += 1
        # owner 2026-10-14 (was SF-8a "weak evidence"): the interface's level is the
        # subnet's level - every host on the network takes it, keeping its device type
        # (a PLC found by its protocol stays a PLC, at the labelled level); only a
        # manual classification or a Subnets & Zones declaration stays above it
        if h.classification_source in _LABEL_KEEPS:
            continue
        lab = label(h.ip)
        if lab is not None:
            if (h.purdue_level, h.classification_source) != (lab[1], LABEL_SOURCE):
                h.purdue_level, h.classification_source = lab[1], LABEL_SOURCE
                stats["hosts_labelled"] += 1
        elif h.classification_source == LABEL_SOURCE:
            # back to what the host had on its own: the ICS-client marker keeps its hint
            h.purdue_level = None
            h.classification_source = ("protocol_client_hint"
                                       if h.device_type == "ics_protocol_client_unclassified" else None)
            stats["hosts_unlabelled"] += 1
    db.flush()
    # SVI levels and the automatic edge levels follow every classification
    # run (a firewall config uploaded after the switch has no zone change)
    try:
        from app.parsers.l3_switch import refresh_levels
        stats["levels_refreshed"] = refresh_levels(db)
    except Exception:                                   # noqa: BLE001
        log.warning("SVI / edge level refresh after zone change failed", exc_info=True)
    return stats


# ------------------------------------------------------------ mismatches --
def _boundary(level) -> str:
    return "dmz" if level == 3.5 else "it" if level >= 4 else "ot"


def mismatches(db) -> list:
    """[(host, network, SubnetZone, severity)] - a device whose own evidence
    (manual classification or protocol role) disagrees with its subnet's
    declared level: high across the OT / DMZ / IT boundary, medium two or
    more OT levels apart.  Neighbouring OT levels are a normal mix."""
    from app.models import Host
    decl = {n: z for n, z in declarations(db).items() if z.purdue_level is not None}
    if not decl:
        return []
    find = _declared_for(decl)
    out = []
    for h in db.query(Host).filter(Host.site_id == _site(db), Host.ip.isnot(None),
                                   Host.purdue_level.isnot(None),
                                   Host.classification_source.in_(["manual", "protocol_inferred"])):
        if str(h.device_type or "").lower() in _INFRA:
            continue
        hit = find(h.ip)
        if not hit:
            continue
        n, z = hit
        hl, zl = float(h.purdue_level), float(z.purdue_level)
        if hl == zl:
            continue
        if _boundary(hl) != _boundary(zl):
            out.append((h, n, z, "high"))
        elif abs(hl - zl) >= 2:
            out.append((h, n, z, "medium"))
    return out


# -------------------------------------------------------------- discover --
def _vendor_is(vendor, words) -> bool:
    v = str(vendor or "").lower()
    return bool(v) and any(w in v for w in words)


def _name_hint(names) -> Optional[tuple]:
    import re
    for nm in names:
        toks = set(re.split(r"[^a-z0-9]+", str(nm or "").lower())) | {str(nm or "").lower()}
        for words, lvl, zone in _NAME_HINTS:
            if toks & set(words):
                return lvl, zone, f"name '{nm}'"
    return None


def discover(db) -> list:
    """Every subnet of the site the data shows, with evidence and a suggestion."""
    from app.models import Firewall, FirewallInterface, Host, NetworkSession, PcapCapture
    from app.parsers.common import lookup_vendor  # noqa: F401  (vendor already on hosts)
    sid = _site(db)
    nets: dict = {}

    def add(n, **kw):
        if n is None:
            return
        e = nets.setdefault(n, {"cidr": str(n), "vlans": set(), "names": [], "sources": set(),
                                "interfaces": []})
        for k, v in kw.items():
            if k == "vlan" and v not in (None, ""):
                e["vlans"].add(str(v))
            elif k == "name" and v and v not in e["names"]:
                e["names"].append(v)
            elif k == "source":
                e["sources"].add(v)
            elif k == "interface":
                e["interfaces"].append(v)

    for (raw,) in db.query(PcapCapture.segment).filter(PcapCapture.site_id == sid, PcapCapture.segment.isnot(None)):
        try:
            seg = json.loads(raw)
        except ValueError:
            continue
        vl = seg.get("vlans") or {}
        for c in seg.get("networks") or []:
            n = _net(c)
            add(n, source="capture")
            for v in vl.get(c) or []:
                add(n, vlan=v)
    for i, fw in db.query(FirewallInterface, Firewall).join(Firewall, Firewall.id == FirewallInterface.firewall_id) \
            .filter(Firewall.site_id == sid, FirewallInterface.network_cidr.isnot(None)):
        n = _net(i.network_cidr)
        if n is None:
            continue
        add(n, source="switch" if fw.vendor == "cisco_l3_switch" else "firewall", vlan=i.vlan_id,
            interface={"firewall": fw.name, "interface": i.name, "purdue_level": i.purdue_level,
                       "level_source": i.purdue_suggestion_source, "zone_label": i.zone_label})
        for nm in (i.alias, i.zone_label, getattr(i, "description", None)):
            add(n, name=nm)
    try:
        from app.models import SwitchVlan
        vlan_names = {}
        for v in db.query(SwitchVlan).filter(SwitchVlan.site_id == sid):
            if v.name:
                vlan_names.setdefault(str(v.vlan_id), v.name)
    except Exception:                                       # noqa: BLE001
        vlan_names = {}
    decl = declarations(db)
    for n in decl:
        add(n, source="declared")
    if not nets:
        return []

    # hosts per subnet (most specific)
    order = sorted(nets, key=lambda n: n.prefixlen, reverse=True)

    def net_of(ip):
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return None
        for n in order:
            if n.version == a.version and a in n:
                return n
        return None

    members: dict = {}
    host_net: dict = {}
    for h in db.query(Host).filter(Host.site_id == sid, Host.ip.isnot(None)):
        n = net_of(h.ip)
        if n is None or str(h.device_type or "").lower() in _INFRA:
            continue
        members.setdefault(n, []).append(h)
        host_net[h.id] = n
    # server roles from sessions
    ics_srv, sip, rtsp, opc, ad, mgmt_srv = (Counter() for _ in range(6))
    for s_id, d_id, port in db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id,
                                      NetworkSession.dst_port).yield_per(5000):
        dn, sn = host_net.get(d_id), host_net.get(s_id)
        if port in _ICS_SERVER_PORTS and dn is not None:
            ics_srv[dn] += 1
        elif port in (5060, 5061):
            for x in (dn, sn):
                if x is not None:
                    sip[x] += 1
        elif port == 554 and dn is not None:
            rtsp[dn] += 1
        elif port == 4840 and dn is not None:
            opc[dn] += 1
        elif port in (88, 389, 636, 3268) and dn is not None:
            ad[dn] += 1
        elif port in (22, 23, 161, 830) and dn is not None:
            mgmt_srv[d_id] += 1

    mism = {}
    for h, n, z, sev in mismatches(db):
        mism.setdefault(n, []).append({"ip": h.ip, "device_type": h.device_type, "purdue_level": h.purdue_level,
                                       "severity": sev})
    try:
        from app.parsers.edge_links import describe as _edge_describe
        edge = _edge_describe(db)
    except Exception:                                   # noqa: BLE001
        log.warning("edge link description failed", exc_info=True)
        edge = {}
    out = []
    for n in sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen)):
        e = nets[n]
        hs = members.get(n, [])
        for v in e["vlans"]:
            if v in vlan_names:
                e["names"].append(vlan_names[v])
        types = Counter(h.device_type for h in hs if h.device_type)
        levels = Counter(h.purdue_level for h in hs if h.purdue_level is not None)
        phones = sum(1 for h in hs if _vendor_is(h.vendor, _PHONE_VENDORS))
        cams = sum(1 for h in hs if _vendor_is(h.vendor, _CAMERA_VENDORS))
        reasons, sugg = [], None
        labelled = [i for i in e["interfaces"] if i.get("purdue_level") is not None
                    and i.get("level_source") is None]           # operator labels (automatic ones explain themselves)
        if labelled:
            # SF-8a: the interface label places the hosts of this network
            # until a zone is declared or a device is classified
            i0 = labelled[0]
            reasons.append(f"behind {i0['firewall']} {i0['interface']} labelled L{i0['purdue_level']}: "
                           f"unclassified hosts take this level (interface label)")
            sugg = (i0["purdue_level"], i0.get("zone_label") or f"Behind {i0['interface']}")
        hint = _name_hint(e["names"])
        if hint:
            sugg = (hint[0], hint[1])
            reasons.append(f"{hint[2]} suggests {hint[1]}")
        if sip[n] or phones:
            reasons.append(f"VoIP: {sip[n]} SIP session(s), {phones} phone-vendor device(s)")
            sugg = sugg or (4, "VoIP")
        if rtsp[n] or cams:
            reasons.append(f"CCTV: {rtsp[n]} RTSP session(s), {cams} camera-vendor device(s)")
            sugg = sugg or (4, "CCTV")
        if ics_srv[n]:
            reasons.append(f"{ics_srv[n]} industrial-protocol session(s) to controllers in it")
            sugg = sugg or (1, "Control")
        if opc[n] or types.get("hmi") or types.get("local_scada"):
            reasons.append("HMI / SCADA devices or OPC UA servers")
            sugg = sugg or (2, "Supervisory")
        if ad[n] or types.get("historian") or types.get("engineering_workstation"):
            reasons.append("directory / historian / engineering servers")
            sugg = sugg or (3, "Site operations")
        netdev = [h for h in hs if mgmt_srv.get(h.id) and _vendor_is(h.vendor, _NETGEAR_VENDORS)]
        if netdev and len(netdev) * 2 >= len(hs):
            reasons.append(f"{len(netdev)} network device(s) managed over SSH / SNMP / telnet")
            sugg = sugg or (3, "Network management")
        ed = edge.get(str(n))
        if ed is not None:
            # the transit to the Internet firewall / its Internet leg - levelled
            # automatically (edge_links); declaring a zone here overrides it
            if ed[1] == "transit":
                reasons.append(f"transit link between the routing switch and {ed[2][len('Transit to '):]}: "
                               f"no devices of its own; levelled automatically at the top of the OT "
                               f"levels routed onto it ({'L' + str(ed[0])})")
            else:
                reasons.append("the firewall's Internet leg (default route / WAN role / public range): "
                               "levelled L5 automatically")
            sugg = sugg or (ed[0], ed[2])
        if not sugg and n.is_global:
            sugg = (5, "Internet / external")
            reasons.append("public address range")
        z = decl.get(n)
        out.append({
            "cidr": str(n),
            "vlans": sorted(e["vlans"], key=lambda x: (len(x), x)),
            "names": e["names"][:5],
            "sources": sorted(e["sources"]),
            "interfaces": e["interfaces"],
            "hosts": len(hs),
            "levels": {str(k): v for k, v in sorted(levels.items())},
            "device_types": dict(types.most_common(6)),
            "suggestion": ({"purdue_level": sugg[0], "zone_name": sugg[1], "reasons": reasons}
                           if sugg else {"purdue_level": None, "zone_name": None,
                                         "reasons": reasons or ["no evidence in the data"]}),
            "declaration": ({"id": z.id, "purdue_level": z.purdue_level, "zone_name": z.zone_name,
                             "note": z.note, "updated_at": z.updated_at} if z is not None else None),
            "mismatched_devices": mism.get(n, []),
            "interface_conflicts": [i for i in e["interfaces"]
                                    if z is not None and z.purdue_level is not None
                                    and i["purdue_level"] is not None
                                    and i["level_source"] not in (IFACE_SOURCE,)
                                    and float(i["purdue_level"]) != float(z.purdue_level)],
        })
    return out


def undeclared_count(db) -> int:
    """Subnets with hosts and no zone declaration (for the upload note)."""
    try:
        return sum(1 for s in discover(db) if s["hosts"] and s["declaration"] is None)
    except Exception:                                       # noqa: BLE001
        log.warning("subnet discovery failed", exc_info=True)
        return 0
