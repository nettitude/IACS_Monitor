"""Capture point of a PCAP upload (VD-02a).

Where a capture was taken decides which MAC on a frame is the router's.
Without it the app falls back to heuristics (a MAC is a router once it has
forwarded traffic for two or more source addresses), which leaves the
single-talker tap - one host behind a firewall, seen on one segment - with a
duplicate host row carrying the firewall's MAC.

The operator names the capture point at upload (or later):

``interface``  a firewall interface (and its VLAN sub-interfaces): the local
               networks are that interface's networks.
``firewall``   a firewall, interface not known (or a capture merged from
               several of its segments): the firewall's interface addresses
               and networks are known, the local segment is not.
``segment``    one or more CIDRs - a switch SPAN that is no firewall port.
``none``       capture only (soft fail): the heuristics alone decide.

Rules, each enough on ONE frame because the operator vouched for the place:

(a) firewall known - a MAC that claims one of the firewall's interface
    addresses (ARP / NDP) is the firewall's; its own addresses are all of
    the firewall's interface addresses.
(b) firewall known - a MAC that sends a frame whose source and destination
    lie in two DIFFERENT networks of that firewall is the firewall (the only
    device routing between its own networks on its segments).
(c) local networks known (interface / segment) - a MAC that sends a frame
    from, or receives a frame for, an address outside the local networks is
    the gateway; never for an address the MAC itself claimed in ARP / NDP.

A loaded switch ARP table still overrides everything (known_router_macs).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

ASSOCIATIONS = ("interface", "firewall", "segment", "none")


#: firewall vendor (config parser) -> words of its MAC OUI vendor name
_OUI_WORDS = (
    (("forti",), ("fortinet",)),
    (("asa", "ftd", "cisco", "ios"), ("cisco",)),
    (("pan", "palo"), ("palo alto",)),
    (("checkpoint", "check_point", "gaia"), ("check point",)),
    (("juniper", "srx", "junos"), ("juniper",)),
    (("sophos",), ("sophos",)),
    (("hp", "aruba"), ("hewlett", "aruba")),
)


def oui_words(fw_vendor) -> tuple:
    v = str(fw_vendor or "").lower()
    for keys, words in _OUI_WORDS:
        if v.startswith(keys):
            return words
    return ()


def _vendor_match(mac, words) -> bool:
    if not words:
        return False
    from app.parsers.common import lookup_vendor
    name = (lookup_vendor(mac) or "").lower()
    return bool(name) and any(w in name for w in words)


class CapturePointError(ValueError):
    """422 by default; ``status`` 404 for unknown ids."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _net(cidr) -> Optional[ipaddress._BaseNetwork]:
    try:
        n = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None
    if n.prefixlen == 0:
        return None
    return n


def parse_networks(text) -> list:
    """'10.3.0.0/24, 10.3.1.0/24' -> [ip_network]; raises on a bad entry."""
    out = []
    for tok in str(text or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        n = _net(tok)
        if n is None:
            raise CapturePointError(f"capture_networks: {tok!r} is not a network (expected e.g. 10.3.0.0/24)")
        out.append(n)
    return out


def resolve(db: DBSession, site_id: Optional[int], firewall_id=None, interface_id=None,
            capture_networks=None) -> Optional[dict]:
    """The capture point named by the operator, validated against the site.
    None = capture only.  Returns {association, firewall_id, firewall,
    interface_id, interface, local_networks, firewall_networks, firewall_ips,
    label}."""
    from app.models import Firewall, FirewallInterface
    nets = parse_networks(capture_networks) if capture_networks else []
    fw = iface = None
    if interface_id is not None:
        iface = db.get(FirewallInterface, int(interface_id))
        if iface is None:
            raise CapturePointError(f"interface id={interface_id} not found", 404)
        if firewall_id is not None and int(firewall_id) != iface.firewall_id:
            raise CapturePointError(f"interface id={interface_id} is not an interface of firewall id={firewall_id}")
        firewall_id = iface.firewall_id
    if firewall_id is not None:
        fw = db.get(Firewall, int(firewall_id))
        if fw is None:
            raise CapturePointError(f"firewall id={firewall_id} not found", 404)
        if site_id is not None and fw.site_id != site_id:
            raise CapturePointError(f"firewall id={firewall_id} belongs to another site (site_id={fw.site_id})")
    if fw is None and not nets:
        return None
    fw_nets, fw_ips = [], set()
    if fw is not None:
        for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id):
            n = _net(i.network_cidr) if i.network_cidr else None
            if n is not None and n.prefixlen < n.max_prefixlen:
                fw_nets.append(n)
            if i.ip_address:
                fw_ips.add(str(i.ip_address).strip())
    local = list(nets)
    if iface is not None:
        members = [iface] + db.query(FirewallInterface).filter(
            FirewallInterface.parent_interface_id == iface.id).all()
        for m in members:
            n = _net(m.network_cidr) if m.network_cidr else None
            if n is not None and n.prefixlen < n.max_prefixlen and n not in local:
                local.append(n)
        if not local:
            raise CapturePointError(f"interface {iface.name} has no network address, so it cannot "
                                    "place the capture - pick the firewall only, or give the segment")
    association = "interface" if iface is not None else ("firewall" if fw is not None and not nets else "segment")
    if fw is not None and nets and iface is None:
        association = "segment"           # a firewall plus explicit segment networks
    label = (f"{fw.name} {iface.name}" if iface is not None else
             f"{fw.name} (interface not given)" if association == "firewall" else
             ", ".join(str(n) for n in local) + (f" on {fw.name}" if fw is not None else ""))
    return {"association": association, "firewall_id": fw.id if fw else None,
            "firewall": fw.name if fw else None,
            "interface_id": iface.id if iface else None, "interface": iface.name if iface else None,
            "local_networks": local, "firewall_networks": fw_nets, "firewall_ips": fw_ips,
            "oui_words": oui_words(fw.vendor) if fw is not None else (),
            "label": label}


def describe(cp: Optional[dict]) -> dict:
    """JSON form of a capture point (for API responses)."""
    if not cp:
        return {"association": "none", "label": "capture only (no capture point)"}
    return {"association": cp["association"], "firewall_id": cp["firewall_id"],
            "firewall": cp["firewall"], "interface_id": cp["interface_id"],
            "interface": cp["interface"], "label": cp["label"],
            "local_networks": [str(n) for n in cp["local_networks"]]}


def _ip(s):
    try:
        return ipaddress.ip_address(s)
    except (TypeError, ValueError):
        return None


def _special(a) -> bool:
    return a is None or a.is_multicast or a.is_unspecified or a.is_loopback or \
        (a.version == 6 and a.is_link_local) or str(a) == "255.255.255.255"


def _in(a, nets) -> bool:
    return any(a.version == n.version and a in n for n in nets)


def _net_of(a, nets):
    best = None
    for n in nets:
        if a.version == n.version and a in n and (best is None or n.prefixlen > best.prefixlen):
            best = n
    return best


def gateways_from_scan(cp: Optional[dict], scan: dict, normalize_mac) -> tuple:
    """Rules (a)-(c) over the prescan.  Returns (gateway raw macs, own ips
    {raw mac: set}, evidence {normalized mac: [rule, ...]})."""
    gws: set = set()
    own: dict = {}
    ev: dict = {}
    if not cp:
        return gws, own, ev
    fw_ips = cp.get("firewall_ips") or set()
    fw_nets = cp.get("firewall_networks") or []
    local = cp.get("local_networks") or []
    claimed: dict = {}
    for src in (scan.get("arp_ips") or {}, scan.get("ndp_ips") or {}):
        for mac, ips in src.items():
            claimed.setdefault(mac, set()).update(ips)

    def mark(mac, rule):
        if mac is None or int(mac[0:2], 16) & 0x01:
            return
        gws.add(mac)
        ev.setdefault(normalize_mac(mac) or mac, [])
        if rule not in ev[normalize_mac(mac) or mac]:
            ev[normalize_mac(mac) or mac].append(rule)

    # (a) a MAC claiming a firewall interface address
    if fw_ips:
        for mac, ips in claimed.items():
            if ips & fw_ips:
                mark(mac, "claims a firewall interface address")
                own.setdefault(mac, set()).update(fw_ips)
    # (b) firewall known: (b1) a MAC of the firewall's vendor carrying an
    # address of one of its networks that another MAC carries as well (the
    # routed copy of a host's frame); (b2) a MAC sourcing addresses of two
    # or more of the firewall's networks, none of them its own.
    if fw_nets:
        words = cp.get("oui_words") or ()
        carriers: dict = {}
        for table, side in ((scan.get("mac_pairs") or {}, 0), (scan.get("mac_dst_pairs") or {}, 1)):
            for mac, pairs in table.items():
                for pair in pairs:
                    a = _ip(pair[side])
                    if not _special(a) and _net_of(a, fw_nets) is not None and pair[side] not in fw_ips:
                        carriers.setdefault(pair[side], set()).add(mac)
        if words:
            for ip, macs in carriers.items():
                if len(macs) < 2:
                    continue
                for mac in macs:
                    if ip not in claimed.get(mac, set()) and _vendor_match(mac, words):
                        mark(mac, f"{cp['firewall']}'s vendor MAC carrying {ip}, which another MAC carries too")
                        if fw_ips:
                            own.setdefault(mac, set()).update(fw_ips)
        for mac, pairs in (scan.get("mac_pairs") or {}).items():
            mine = claimed.get(mac, set())
            nets = {_net_of(_ip(sip), fw_nets) for sip, _d in pairs
                    if sip not in mine and not _special(_ip(sip))}
            nets.discard(None)
            if len(nets) >= 2:
                mark(mac, "sourced addresses of two or more of the firewall's networks")
                if fw_ips:
                    own.setdefault(mac, set()).update(fw_ips)
    # (c) an off-segment address on a frame, with the local segment known
    if local:
        for table, side in ((scan.get("mac_pairs") or {}, 0), (scan.get("mac_dst_pairs") or {}, 1)):
            for mac, pairs in table.items():
                mine = claimed.get(mac, set())
                for pair in pairs:
                    ip = pair[side]
                    if ip in mine or ip in fw_ips:
                        continue
                    a = _ip(ip)
                    if _special(a) or _in(a, local):
                        continue
                    mark(mac, "carried an off-segment address on the capture segment")
                    if fw_ips:
                        own.setdefault(mac, set()).update(fw_ips)
                    break
    return gws, own, ev


def fit(cp: Optional[dict], scan: dict) -> Optional[dict]:
    """How well the capture matches the named local networks: the share of
    MACs that claimed an address (ARP / NDP) inside them.  A low share
    means the operator probably picked the wrong interface."""
    if not cp or not cp.get("local_networks"):
        return None
    local = cp["local_networks"]
    claimed = {}
    for src in (scan.get("arp_ips") or {}, scan.get("ndp_ips") or {}):
        for mac, ips in src.items():
            claimed.setdefault(mac, set()).update(ips)
    macs = [m for m, ips in claimed.items() if any(not _special(_ip(i)) for i in ips)]
    if not macs:
        # no ARP in the capture: fall back to the addresses seen as frame sources
        # (frames the firewall's own vendor MACs sent are routed copies)
        srcs = set()
        words = cp.get("oui_words") or ()
        for m, pairs in (scan.get("mac_pairs") or {}).items():
            if not _vendor_match(m, words):
                srcs |= {p[0] for p in pairs}
        addrs = [a for a in (_ip(s) for s in srcs) if not _special(a)]
        if not addrs:
            return None
        inside = sum(1 for a in addrs if _in(a, local))
        return {"basis": "frame sources", "inside": inside, "total": len(addrs),
                "share": round(inside / len(addrs), 3)}
    inside = sum(1 for m in macs if any(_in(a, local) for a in (_ip(i) for i in claimed[m]) if a))
    return {"basis": "ARP / NDP claims", "inside": inside, "total": len(macs),
            "share": round(inside / len(macs), 3)}


def suggest_interface(db: DBSession, cp: Optional[dict], scan: dict) -> Optional[dict]:
    """Firewall named, interface not: the firewall interface whose networks
    best fit the capture (same measure as ``fit``).  A suggestion only - the
    operator associates it."""
    if not cp or cp.get("association") != "firewall" or not cp.get("firewall_id"):
        return None
    from app.models import FirewallInterface
    best = None
    for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == cp["firewall_id"],
                                                FirewallInterface.network_cidr.isnot(None)):
        if i.parent_interface_id is not None:
            continue
        try:
            sub = resolve(db, None, cp["firewall_id"], i.id)
        except CapturePointError:
            continue
        f = fit(sub, scan)
        if f and (best is None or f["share"] > best["score"]):
            best = {"interface_id": i.id, "interface": i.name,
                    "networks": [str(n) for n in sub["local_networks"]],
                    "score": f["share"], "basis": f["basis"]}
    if best is None or best["score"] <= 0:
        return None
    best["confidence"] = ("high" if best["score"] >= 0.9 else "medium" if best["score"] >= 0.6 else "low")
    return best


def notes_for(cp: Optional[dict], fit_info: Optional[dict], gw_evidence: dict) -> list:
    """Operator-facing notes on an upload (soft fail and fit warnings)."""
    out = []
    if not cp:
        out.append("No capture point: host identity from this capture rests on the router "
                   "heuristics alone (a MAC counts as a router only after it forwarded traffic "
                   "for two or more addresses). Associate the capture with the firewall and "
                   "interface it was taken on to firm it up - the hosts are re-attributed.")
        return out
    if cp["association"] == "firewall":
        out.append(f"Firewall known, interface not given: routed frames between {cp['firewall']}'s "
                   "networks identify its MAC; name the interface to also catch traffic from "
                   "networks the firewall does not own.")
    if fit_info and fit_info["total"] >= 3 and fit_info["share"] < 0.5:
        out.append(f"The capture does not look like it was taken on {cp['label']}: only "
                   f"{fit_info['inside']} of {fit_info['total']} addresses ({fit_info['basis']}) lie in "
                   f"{', '.join(str(n) for n in cp['local_networks'])}. Check the interface - a wrong "
                   "capture point makes remote hosts lose their MAC.")
    return out


# ------------------------------------------------------------ reprocess --
def _capture_point_of(db: DBSession, capture) -> Optional[dict]:
    nets = capture.capture_networks or None
    if capture.interface_id is None and capture.firewall_id is None and not nets:
        return None
    try:
        return resolve(db, capture.site_id, capture.firewall_id, capture.interface_id, nets)
    except CapturePointError:
        log.warning("capture %s: stored capture point no longer resolves", capture.id, exc_info=True)
        return None


def reattribute(db: DBSession, capture, cp: Optional[dict] = None) -> dict:
    """Associate-and-reprocess over the STORED rows of one capture (the raw
    file is not kept): find the gateway MACs the capture point implies
    among the hosts of the capture's sessions, then fold every host row that
    carries a gateway MAC for an address that is not the gateway's own into
    the real row of that address (or strip the MAC when there is none).
    Flushes; never commits.  Returns counts."""
    from sqlalchemy import or_
    from app.models import Host, NetworkSession
    from app.parsers.common import normalize_mac
    from app.parsers.host_identity import merge_hosts

    cp = cp if cp is not None else _capture_point_of(db, capture)
    out = {"capture_id": capture.id, "capture_point": describe(cp), "gateway_macs": [],
           "hosts_merged": 0, "macs_cleared": 0, "hosts_examined": 0}
    if not cp:
        return out
    fw_ips = cp.get("firewall_ips") or set()
    fw_nets = cp.get("firewall_networks") or []
    local = cp.get("local_networks") or []

    sess = db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id).filter(
        NetworkSession.pcap_capture_id == capture.id).all()
    ids = {i for pair in sess for i in pair if i is not None}
    if not ids:
        return out
    hosts = {h.id: h for h in db.query(Host).filter(Host.id.in_(sorted(ids)))}
    out["hosts_examined"] = len(hosts)
    by_ip: dict = {}
    for h in db.query(Host).filter(Host.site_id == capture.site_id, Host.ip.in_(
            sorted({h.ip for h in hosts.values() if h.ip}))):
        by_ip.setdefault(h.ip, []).append(h)

    gw: dict = {}               # normalized mac -> [rule]
    macs_on_local: dict = {}
    for h in hosts.values():
        m = normalize_mac(h.mac) if h.mac else None
        a = _ip(h.ip)
        if not m or _special(a):
            continue
        if h.ip in fw_ips:
            gw.setdefault(m, []).append("carries a firewall interface address")
        elif local and _in(a, local):
            macs_on_local.setdefault(m, set()).add(h.ip)
    if local:
        for h in hosts.values():
            m = normalize_mac(h.mac) if h.mac else None
            a = _ip(h.ip)
            if not m or _special(a) or h.ip in fw_ips or _in(a, local):
                continue
            # a MAC also bound to a local, non-firewall address is a host with
            # a second address, not the gateway
            if macs_on_local.get(m):
                continue
            gw.setdefault(m, []).append("bound to an off-segment address")
    if fw_nets:
        words = cp.get("oui_words") or ()
        nets_of_mac: dict = {}
        for h in hosts.values():
            m = normalize_mac(h.mac) if h.mac else None
            a = _ip(h.ip)
            if not m or _special(a) or h.ip in fw_ips:
                continue
            n = _net_of(a, fw_nets)
            if n is not None:
                nets_of_mac.setdefault(m, set()).add(n)
        for m, nets in nets_of_mac.items():
            if len(nets) >= 2:
                gw.setdefault(m, []).append("bound to addresses of two or more of the firewall's networks")
        if words:
            for h in hosts.values():
                m = normalize_mac(h.mac) if h.mac else None
                if not m or not h.ip or h.ip in fw_ips or _net_of(_ip(h.ip), fw_nets) is None:
                    continue
                twin = any(x.id != h.id and x.mac and normalize_mac(x.mac) != m for x in by_ip.get(h.ip, ()))
                if twin and _vendor_match(m, words):
                    gw.setdefault(m, []).append(f"{cp['firewall']}'s vendor MAC on a duplicate of {h.ip}")

    out["gateway_macs"] = sorted(gw)
    for h in list(hosts.values()):
        m = normalize_mac(h.mac) if h.mac else None
        if not m or m not in gw or h.ip in fw_ips or not h.ip:
            continue
        if db.get(Host, h.id) is None:
            continue
        siblings = [x for x in by_ip.get(h.ip, ()) if x.id != h.id and db.get(Host, x.id) is not None
                    and not (x.mac and normalize_mac(x.mac) in gw)]
        keep = next((x for x in siblings if x.mac), None) or next((x for x in siblings if not x.mac), None)
        if keep is not None:
            merge_hosts(db, keep, h)
            out["hosts_merged"] += 1
            by_ip[h.ip] = [x for x in by_ip[h.ip] if x.id != h.id]
        else:
            h.mac = None
            h.vendor = None
            out["macs_cleared"] += 1
    prev = []
    try:
        prev = json.loads(capture.gateway_macs or "[]")
    except ValueError:
        prev = []
    capture.gateway_macs = json.dumps(sorted(set(prev) | set(gw)))
    capture.reprocessed_at = datetime.now(timezone.utc)
    db.flush()
    out["evidence"] = gw
    return out


def known_capture_gateways(db: DBSession, site_id: Optional[int]) -> dict:
    """{normalized mac: firewall interface ips} learned from associated
    captures of the site - later captures (even unassociated ones) treat
    those MACs as routers."""
    from app.models import FirewallInterface, PcapCapture
    out: dict = {}
    q = db.query(PcapCapture.gateway_macs, PcapCapture.firewall_id).filter(
        PcapCapture.gateway_macs.isnot(None))
    if site_id is not None:
        q = q.filter(PcapCapture.site_id == site_id)
    fw_ips_cache: dict = {}
    for raw, fid in q:
        try:
            macs = json.loads(raw or "[]")
        except ValueError:
            continue
        if fid is not None and fid not in fw_ips_cache:
            fw_ips_cache[fid] = {str(ip).strip() for (ip,) in db.query(FirewallInterface.ip_address).filter(
                FirewallInterface.firewall_id == fid, FirewallInterface.ip_address.isnot(None))}
        for m in macs:
            out.setdefault(m, set()).update(fw_ips_cache.get(fid, set()))
    return out
