"""G5: external communications - every flow between an inside host and an
address outside the site's known networks.

"External" = outside every network the site knows (capture segments,
firewall / switch interface networks, declared subnet zones, VPN pools) -
public addresses AND, say, a corporate 10.x range reached through the
firewall.  Each flow is named from what the capture showed (DNS answers the
devices received, TLS server names, HTTP Host headers), given a category
(remote access, cloud IoT / video, time, DNS, updates, VoIP trunk, MQTT,
cloud, web ... or unknown), and the operator can approve it (a documented
conduit: it stops raising Internet-egress findings) or mark it for removal.

Optional: an IP-to-organisation table (the public-domain ``ip2asn-v4.tsv``
/ ``ip2asn-v6.tsv`` from iptoasn.com, gz or plain) named by
``IACS_IP2ASN_FILE`` (several, comma-separated) or placed in the data
directory - names the network owner ("AMAZON-02", "ALIBABA-CN-NET").  Not
shipped; the app runs offline.
"""
from __future__ import annotations

import bisect
import gzip
import ipaddress
import logging
import os
from collections import defaultdict
from typing import Optional

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

# (name suffixes, category)
_NAME_CATEGORIES = [
    (("teamviewer.com", "anydesk.com", "logmein.com", "logme.in", "gotoassist.com", "splashtop.com",
      "rustdesk.com", "screenconnect.com", "connectwise.com", "bomgar.com", "beyondtrustcloud.com",
      "remotepc.com", "ammyy.com", "realvnc.com", "vnc.com", "parsec.app", "zoho.com"), "remote access"),
    (("hik-connect.com", "hikvision.com", "ezvizlife.com", "ezviz.com", "dahuasecurity.com", "imoulife.com",
      "easy4ip.com", "p2p.hikvision.com", "reolink.com", "axis.com", "ubnt.com", "ui.com", "tuyaus.com",
      "tuyaeu.com", "tuya.com", "ring.com", "arlo.com"), "cloud IoT / video"),
    (("ntp.org", "time.windows.com", "time.google.com", "time.apple.com", "time.nist.gov",
      "time.cloudflare.com"), "time"),
    (("windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "download.microsoft.com",
      "ubuntu.com", "debian.org", "redhat.com", "centos.org", "fortinet.net", "fortiguard.com",
      "siemens.com", "rockwellautomation.com", "se.com", "symantec.com", "mcafee.com", "sophos.com",
      "trendmicro.com", "kaspersky.com", "avast.com", "eset.com"), "updates / vendor"),
    (("amazonaws.com", "cloudfront.net", "azure.com", "azurewebsites.net", "windows.net", "googleapis.com",
      "gstatic.com", "cloudflare.com", "akamaiedge.net", "akamai.net", "edgekey.net", "fastly.net",
      "aliyuncs.com", "alicdn.com"), "cloud services"),
    (("google.com", "microsoft.com", "office.com", "office365.com", "live.com", "apple.com", "icloud.com",
      "facebook.com", "youtube.com", "bing.com"), "web / office"),
]
_PORT_CATEGORIES = {
    5938: "remote access", 7070: "remote access", 3389: "remote access", 5900: "remote access",
    5901: "remote access", 21115: "remote access", 21116: "remote access", 6568: "remote access",
    123: "time", 53: "DNS", 853: "DNS", 5060: "VoIP trunk", 5061: "VoIP trunk", 1883: "MQTT", 8883: "MQTT",
    32100: "cloud IoT / video", 7681: "cloud IoT / video", 8000: "cloud IoT / video",
    25: "mail", 465: "mail", 587: "mail", 993: "mail", 995: "mail", 110: "mail", 143: "mail",
    502: "industrial protocol", 102: "industrial protocol", 44818: "industrial protocol",
    20000: "industrial protocol", 4840: "industrial protocol", 2404: "industrial protocol",
    1194: "VPN", 500: "VPN", 4500: "VPN", 51820: "VPN", 22: "SSH", 23: "telnet", 21: "FTP",
}
_GENERIC_PORTS = {80, 443, 8080, 8443}
_TWO_LEVEL = {"co.uk", "com.au", "co.jp", "com.cn", "com.br", "co.nz", "co.in", "com.sg", "co.za", "com.mx",
              "org.uk", "net.au", "gov.uk", "ac.uk", "com.tr", "co.kr"}
_NAME_RANK = {"tls_sni": 0, "http_host": 1, "dns": 2}


def domain_of(name: str) -> str:
    """Registrable domain of a name ('p2p.hik-connect.com' -> 'hik-connect.com')."""
    parts = [p for p in str(name).lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last2 = ".".join(parts[-2:])
    return ".".join(parts[-3:]) if last2 in _TWO_LEVEL else last2


def category_of(name: Optional[str], port: Optional[int]) -> Optional[str]:
    """Category from the destination name, else the port.  A distinctive
    port (MQTT, SIP ...) wins over a generic hosting name (cloud services,
    web / office): MQTT to an AWS host is MQTT."""
    name_cat = None
    if name:
        n = name.lower()
        for suffixes, cat in _NAME_CATEGORIES:
            if any(n == s or n.endswith("." + s) for s in suffixes):
                name_cat = cat
                break
    port_cat = _PORT_CATEGORIES.get(port)
    if name_cat and not (port_cat and name_cat in ("cloud services", "web / office")):
        return name_cat
    if port_cat:
        return port_cat
    if port in _GENERIC_PORTS:
        return "web" if name else None
    return name_cat


# ---------------------------------------------------------- organisation --
_ORG: dict = {}


def _load_org():
    """Lazy-load the optional ip2asn tables: {4|6: (starts, rows)}."""
    if _ORG.get("loaded"):
        return _ORG
    _ORG["loaded"] = True
    files = [f.strip() for f in os.environ.get("IACS_IP2ASN_FILE", "").split(",") if f.strip()]
    data_dir = os.environ.get("IACS_DATA_DIR") or "/data"
    for cand in ("ip2asn-v4.tsv.gz", "ip2asn-v4.tsv", "ip2asn-v6.tsv.gz", "ip2asn-v6.tsv"):
        p = os.path.join(data_dir, cand)
        if os.path.exists(p) and p not in files:
            files.append(p)
    for path in files:
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 5 or parts[2] == "0":
                        continue
                    try:
                        a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    t = _ORG.setdefault(a.version, ([], []))
                    t[0].append(int(a))
                    t[1].append((int(b), f"AS{parts[2]} {parts[4]}".strip(), parts[3]))
            _ORG.setdefault("files", []).append(path)
        except OSError:
            log.warning("ip2asn file %s not readable", path, exc_info=True)
    for v in (4, 6):
        if v in _ORG:
            pairs = sorted(zip(*_ORG[v]))
            _ORG[v] = ([p[0] for p in pairs], [p[1] for p in pairs])
    return _ORG


def organisation_of(ip: str) -> Optional[str]:
    org = _load_org()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    t = org.get(a.version)
    if not t:
        return None
    i = bisect.bisect_right(t[0], int(a)) - 1
    if i >= 0 and int(a) <= t[1][i][0]:
        end, name, cc = t[1][i]
        return f"{name} ({cc})" if cc and cc != "None" else name
    return None


# --------------------------------------------------------------- networks --
def _known_networks(db) -> list:
    import json
    from app.models import PcapCapture, SubnetZone
    from app.parsers.l3_switch import _site, known_networks
    sid = _site(db)
    nets = list(known_networks(db))
    for (raw,) in db.query(PcapCapture.segment).filter(PcapCapture.site_id == sid, PcapCapture.segment.isnot(None)):
        try:
            seg = json.loads(raw)
        except ValueError:
            continue
        for c in seg.get("networks") or []:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
    for (c,) in db.query(SubnetZone.cidr).filter(SubnetZone.site_id == sid):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


# Site-internal by definition: an RFC 1918 / CGNAT / ULA address the site's
# known networks do not cover is an undescribed inside subnet, not "outside".
_INTERNAL_RANGES = tuple(ipaddress.ip_network(n) for n in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))


def external_fn(db):
    """function(ip) -> True when the address lies outside every known site
    network and is not in an internal (RFC 1918 / CGNAT / ULA) range."""
    nets = _known_networks(db)
    cache: dict = {}

    def f(ip):
        if ip in cache:
            return cache[ip]
        r = False
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            a = None
        if a is not None and not (a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified
                                  or a.is_reserved):
            r = (not any(n.version == a.version and a in n for n in nets)
                 and not any(n.version == a.version and a in n for n in _INTERNAL_RANGES))
            if r and a.is_private and not nets:
                r = False           # nothing known yet: a private address is not "outside"
        cache[ip] = r
        return r
    return f


def names_by_ip(db) -> dict:
    """{ip: [(name, source, count)]} best first."""
    from app.models import ObservedName
    from app.parsers.l3_switch import _site
    out: dict = defaultdict(list)
    for r in db.query(ObservedName).filter(ObservedName.site_id == _site(db)):
        out[r.ip].append((r.name, r.source, r.count or 0))
    for ip, v in out.items():
        v.sort(key=lambda x: (_NAME_RANK.get(x[1], 9), -x[2], x[0]))
    return out


def reviews(db) -> dict:
    """{(src, dest_key): ExternalFlowReview}."""
    from app.models import ExternalFlowReview
    from app.parsers.l3_switch import _site
    return {(r.src, r.dest_key): r for r in db.query(ExternalFlowReview).filter(ExternalFlowReview.site_id == _site(db))}


def review_for(revs: dict, src_ip: str, dest_key: str, dst_ip: Optional[str] = None):
    for k in ((src_ip, dest_key), ("*", dest_key), (src_ip, dst_ip), ("*", dst_ip)):
        if k[1] and k in revs:
            return revs[k]
    return None


def dest_key_fn(db):
    """function(ip) -> (dest_key, best name or None): the registrable domain
    of the best name the capture showed for the address, else the address."""
    names = names_by_ip(db)

    def f(ip):
        v = names.get(ip)
        if v:
            return domain_of(v[0][0]), v[0][0]
        return ip, None
    return f


# ------------------------------------------------------------------ flows --
def flows(db) -> dict:
    """The external communications of the current site."""
    from app.models import ConnectionAttempt, Host, NetworkSession
    from app.parsers.l3_switch import _site, router_macs
    from app.parsers.subnet_zones import _declared_for, declarations
    from app.models import Firewall
    sid = _site(db)
    ext = external_fn(db)
    names = names_by_ip(db)
    revs = reviews(db)
    zone_of = _declared_for(declarations(db))
    try:
        rmacs = router_macs(db)
    except Exception:                                   # noqa: BLE001
        rmacs = {}
    fw_names = {f.id: f.name for f in db.query(Firewall).filter(Firewall.site_id == sid)}
    hosts = {h.id: h for h in db.query(Host).filter(Host.site_id == sid)}
    groups: dict = {}

    def key_for(dst_ip):
        v = names.get(dst_ip)
        if v:
            return domain_of(v[0][0]), v[0][0]
        return dst_ip, None

    def slot(inside, dst_ip):
        dk, nm = key_for(dst_ip)
        g = groups.get((inside.id, dk))
        if g is None:
            g = groups[(inside.id, dk)] = {
                "inside": inside, "dest_key": dk, "names": set(), "addresses": set(), "ports": set(),
                "sessions": 0, "packets": 0, "bytes": 0, "attempts": 0, "first": None, "last": None,
                "carriers": set(), "outbound": False, "inbound": False}
        if nm:
            g["names"].update(n for n, _s, _c in names.get(dst_ip, [])[:3])
        g["addresses"].add(dst_ip)
        return g

    def span(g, a, b):
        from app.parsers.common import as_utc
        a, b = as_utc(a), as_utc(b)
        if a is not None and (g["first"] is None or a < g["first"]):
            g["first"] = a
        if b is not None and (g["last"] is None or b > g["last"]):
            g["last"] = b

    for s in db.query(NetworkSession).yield_per(5000):
        src, dst = hosts.get(s.src_host_id), hosts.get(s.dst_host_id)
        if src is None or dst is None or not src.ip or not dst.ip:
            continue
        se, de = ext(src.ip), ext(dst.ip)
        if se == de:
            continue
        inside, outside = (src, dst) if de else (dst, src)
        g = slot(inside, outside.ip)
        g["sessions"] += 1
        g["packets"] += s.packet_count or 0
        g["bytes"] += s.byte_count or 0
        g["ports"].add(s.dst_port)
        g["outbound" if de else "inbound"] = True
        if s.carrier_mac:
            g["carriers"].add(s.carrier_mac)
        span(g, s.first_seen, s.last_seen)
    by_ip = {h.ip: h for h in hosts.values() if h.ip}
    for a in db.query(ConnectionAttempt).filter(ConnectionAttempt.outcome != "arp_unanswered"):
        inside = by_ip.get(a.src_ip)
        if inside is None or not ext(a.dst_ip) or ext(a.src_ip):
            continue
        g = slot(inside, a.dst_ip)
        g["attempts"] += a.count or 1
        g["ports"].add(a.dst_port)
        g["outbound"] = True
        span(g, a.first_seen, a.last_seen)

    from app.parsers.segments import ot_capture_segment_of
    _ot_seg = ot_capture_segment_of(db)

    def ot_of(h) -> bool:
        if h.purdue_level is not None:
            return float(h.purdue_level) <= 3
        return _ot_seg(h) is not None

    rows = []
    for g in groups.values():
        h = g["inside"]
        ports = sorted(p for p in g["ports"] if p is not None)
        name = sorted(g["names"])[0] if g["names"] else None
        cat = None
        for p in ports:
            cat = category_of(name, p) or cat
            if cat and cat not in ("web",):
                break
        cat = cat or category_of(name, None)
        orgs = sorted({o for o in (organisation_of(ip) for ip in g["addresses"]) if o})
        rv = review_for(revs, h.ip, g["dest_key"], next(iter(g["addresses"])))
        z = zone_of(h.ip)
        via = sorted({fw_names.get(rmacs.get(m), None) or f"router {m}" for m in g["carriers"]})
        unknown = not name and cat in (None, "web") and rv is None
        rows.append({
            "inside": {"id": h.id, "ip": h.ip, "mac": h.mac, "vendor": h.vendor, "device_type": h.device_type,
                       "purdue_level": h.purdue_level, "zone": z[1].zone_name if z else None},
            "dest_key": g["dest_key"], "names": sorted(g["names"])[:10],
            "addresses": sorted(g["addresses"])[:50], "address_count": len(g["addresses"]),
            "organisations": orgs[:5], "ports": ports[:20],
            "category": cat or "unknown", "answered": g["sessions"] > 0, "tried_only": g["sessions"] == 0,
            "direction": "both" if g["outbound"] and g["inbound"] else "outbound" if g["outbound"] else "inbound",
            "sessions": g["sessions"], "attempts": g["attempts"], "packets": g["packets"], "bytes": g["bytes"],
            "first_seen": g["first"], "last_seen": g["last"], "left_via": via,
            "status": rv.status if rv else "unreviewed",
            "review": ({"id": rv.id, "src": rv.src, "dest_key": rv.dest_key, "status": rv.status,
                        "note": rv.note} if rv else None),
            "unknown": unknown,
            # owner (G4): no OT device may reach the Internet directly - an
            # approval is recorded but its egress finding stays open
            "ot_host": ot_of(h),
        })
    def _lv(r):
        lv = r["inside"]["purdue_level"]
        return float(lv) if lv is not None else 4.5
    # unreviewed first, controllers first, unknown destinations first
    rows.sort(key=lambda r: (r["status"] == "approved" and not r["ot_host"], _lv(r), not r["unknown"],
                             r["inside"]["ip"] or "", r["dest_key"]))
    _attach_rules(db, rows)
    insides = {r["inside"]["id"] for r in rows}
    dests = {r["dest_key"] for r in rows}
    return {
        "flows": rows,
        "summary": {"inside_hosts": len(insides), "destinations": len(dests), "flows": len(rows),
                    "unknown": sum(1 for r in rows if r["unknown"]),
                    "tried_only": sum(1 for r in rows if r["tried_only"]),
                    "approved": sum(1 for r in rows if r["status"] == "approved"),
                    "remove": sum(1 for r in rows if r["status"] == "remove"),
                    "unreviewed": sum(1 for r in rows if r["status"] == "unreviewed"),
                    "ot_flows": sum(1 for r in rows if r["ot_host"])},
        "organisation_data": bool(_load_org().get("files")),
    }


def _attach_rules(db, rows: list) -> None:
    """The firewall / switch rules that match each flow (first match per device)."""
    try:
        from app.parsers.topology_diff import first_matches
    except Exception:                                   # noqa: BLE001
        return
    flows_ = []
    for r in rows:
        if not r["answered"] and not r["attempts"]:
            continue
        port = r["ports"][0] if r["ports"] else None
        flows_.append((r["inside"]["ip"], r["addresses"][0], port, "udp" if port in (53, 123, 5060, 500, 4500) else "tcp"))
    try:
        res = first_matches(db, flows_)
    except Exception:                                   # noqa: BLE001
        log.warning("rule lookup for external flows failed", exc_info=True)
        return
    for r in rows:
        port = r["ports"][0] if r["ports"] else None
        k = (r["inside"]["ip"], r["addresses"][0], port, "udp" if port in (53, 123, 5060, 500, 4500) else "tcp")
        # path order: the device the flow left through first
        hop = {n: i for i, n in enumerate(r.get("left_via") or [])}
        r["rules"] = sorted(res.get(k, []), key=lambda x: hop.get(x.get("device"), len(hop)))
