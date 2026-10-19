"""Classification hints for one host (UI "Classify" control).

From what the captures and configs show about a host - the industrial
protocols it speaks as client or server, its writes / program downloads,
its vendor (OUI), whether it hands out DHCP or forwards traffic - suggest
device types with their default Purdue level and the reasons.  Only
suggestions: nothing is written; the operator decides
(PATCH /hosts/{id}/classification).

Also reports the other addresses of the same MAC (one device, several
addresses: a multi-homed host) so a classification can cover them all.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession

from app.models import Host, NetworkSession, PcapCapture, ProtocolDetail
from app.parsers.device_classification import DEVICE_TYPE_REFERENCE
from app.parsers.segments import CONSUMER_DEVICE_WORDS, CONSUMER_NET_WORDS, vendor_matches

# industrial server ports -> protocol name
_ICS_SERVER_PORTS = {502: "Modbus/TCP", 102: "S7comm", 44818: "EtherNet/IP", 20000: "DNP3",
                     2404: "IEC 60870-5-104", 34964: "PROFINET CM", 1911: "Niagara Fox",
                     18245: "GE SRTP", 20547: "ProConOS"}
_OPC_UA = 4840
_HISTORIAN_PORTS = {1433: "MS SQL", 5450: "PI", 5457: "PI", 5459: "PI", 3306: "MySQL", 5432: "PostgreSQL"}
# PC / laptop makers (OUI) - a PC speaking industrial protocols is a workstation
_PC_WORDS = ("lcfc", "lenovo", "dell", "hewlett", "hp inc", "compal", "quanta", "wistron", "intel corporate",
             "liteon", "azurewave", "microsoft", "asustek", "acer", "pegatron", "fujitsu", "toshiba",
             "panasonic", "getac", "durabook", "vmware", "parallels", "realtek")
_ICS_VENDOR_WORDS = ("siemens", "rockwell", "allen-bradley", "schneider", "honeywell", "emerson", "abb",
                     "yokogawa", "mitsubishi electric", "omron", "phoenix contact", "wago", "beckhoff",
                     "ge fanuc", "general electric", "moxa", "hirschmann", "b&r", "bachmann", "pilz")


def _label(device_type: str) -> str:
    ref = DEVICE_TYPE_REFERENCE.get(device_type)
    return ref[1] if ref else device_type.replace("_", " ")


def _level(device_type: str):
    ref = DEVICE_TYPE_REFERENCE.get(device_type)
    return ref[0] if ref else None


def _is_public(ip: Optional[str]) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.is_global


def _capture_roles(db: DBSession, mac: Optional[str]) -> tuple:
    """(is a capture gateway, DHCP server record) for this MAC."""
    if not mac:
        return False, None
    m = mac.lower()
    gw, dhcp = False, None
    for (raw,) in db.query(PcapCapture.segment).filter(PcapCapture.segment.isnot(None)):
        try:
            seg = json.loads(raw)
        except ValueError:
            continue
        if m in {str(x).lower() for x in seg.get("gateway_macs") or []}:
            gw = True
        for srv in seg.get("dhcp_servers") or []:
            if str(srv.get("mac") or "").lower() == m:
                dhcp = srv
    return gw, dhcp


def suggest(db: DBSession, host: Host) -> dict:
    """Suggestions for ``host`` and the other addresses of its MAC."""
    same = []
    if host.mac:
        same = (db.query(Host).filter(Host.mac == host.mac, Host.id != host.id, Host.site_id == host.site_id)
                .order_by(Host.ip).all())
    rows = [host] + same
    ids = [h.id for h in rows]
    sessions = (db.query(NetworkSession)
                .filter(or_(NetworkSession.src_host_id.in_(ids), NetworkSession.dst_host_id.in_(ids)))
                .limit(20000).all())
    peer_ids = {s.dst_host_id if s.src_host_id in ids else s.src_host_id for s in sessions}
    peers = {h.id: h for h in db.query(Host).filter(Host.id.in_(peer_ids))} if peer_ids else {}

    ics_client: dict = {}      # protocol -> set of server ips
    ics_server: dict = {}      # protocol -> set of client ips
    opc_client, opc_server, hist_server, hist_clients = set(), set(), set(), set()
    public = set()
    for s in sessions:
        out = s.src_host_id in ids
        peer = peers.get(s.dst_host_id if out else s.src_host_id)
        pip = peer.ip if peer else None
        port = s.dst_port
        if out and _is_public(pip):
            public.add(f"{pip}:{port}")
        if port in _ICS_SERVER_PORTS:
            (ics_client if out else ics_server).setdefault(_ICS_SERVER_PORTS[port], set()).add(pip)
        elif port == _OPC_UA:
            (opc_client if out else opc_server).add(pip)
        elif port in _HISTORIAN_PORTS and not out:
            hist_server.add(_HISTORIAN_PORTS[port])
            hist_clients.add(pip)

    writes, programs = set(), set()
    sess_ids = [s.id for s in sessions if s.src_host_id in ids]
    for i in range(0, len(sess_ids), 900):
        for d in db.query(ProtocolDetail).filter(ProtocolDetail.session_id.in_(sess_ids[i:i + 900])):
            f = d.fields if isinstance(d.fields, dict) else {}
            op = f.get("operation")
            if op in ("program", "control"):
                programs.add(d.protocol)
            elif op == "write":
                writes.add(d.protocol)
    vendor = next((h.vendor for h in rows if h.vendor), "") or ""
    vl = vendor.lower()
    pc = any(w in vl for w in _PC_WORDS)
    ics_vendor = any(w in vl for w in _ICS_VENDOR_WORDS)
    consumer_net = vendor_matches(vendor, CONSUMER_NET_WORDS)
    consumer_dev = vendor_matches(vendor, CONSUMER_DEVICE_WORDS)
    gw, dhcp = _capture_roles(db, host.mac)

    sugg: list = []

    def add(device_type, confidence, reasons, level=None, note=None):
        if any(x["device_type"] == device_type for x in sugg):
            return
        sugg.append({"device_type": device_type, "label": _label(device_type),
                     "purdue_level": level if level is not None else _level(device_type),
                     "confidence": confidence, "reasons": reasons, **({"note": note} if note else {})})

    def ips(v):
        v = sorted(x for x in v if x)
        return ", ".join(v[:4]) + (f" +{len(v) - 4}" if len(v) > 4 else "")

    client_txt = [f"{p} client of {ips(v)}" for p, v in sorted(ics_client.items())]
    server_txt = [f"{p} server for {ips(v)}" for p, v in sorted(ics_server.items())]
    if consumer_net or dhcp or gw:
        r = []
        if consumer_net:
            r.append(f"vendor {vendor} makes consumer / SOHO routers and Wi-Fi access points")
        if dhcp:
            r.append(f"hands out DHCP addresses ({len(dhcp.get('leases') or [])} lease(s))")
        if gw:
            r.append("forwards traffic for other hosts (gateway)")
        add("router", "high" if (gw or dhcp) else "medium", r,
            note="Infrastructure has no Purdue level. Consumer equipment on an OT network is a finding "
                 "(wireless_in_ot_zone) whatever it is classified as - remove it." if consumer_net else None)
    if programs or (writes and (pc or client_txt)):
        r = []
        if programs:
            r.append(f"program download / control operations ({', '.join(sorted(programs))})")
        if writes:
            r.append(f"industrial writes ({', '.join(sorted(writes))})")
        r += client_txt[:3]
        if pc:
            r.append(f"vendor {vendor} makes PCs / laptops")
        add("engineering_workstation", "high" if programs else "medium", r,
            note="Program downloads come from an engineering workstation - or from someone else's laptop. "
                 "Confirm it is an approved, inventoried workstation before classifying it; an unknown "
                 "laptop should be removed, not classified.")
    if ics_server:
        r = list(server_txt)
        if ics_vendor:
            r.append(f"vendor {vendor} makes industrial controllers")
        if "S7comm" in ics_server or "EtherNet/IP" in ics_server:
            add("plc", "high", r)
        elif "DNP3" in ics_server or "IEC 60870-5-104" in ics_server:
            add("rtu_or_ied", "high", r)
        else:
            add("modbus_device", "medium", r + ["a Modbus server may be a PLC, drive, RTU or gateway"])
    if (client_txt or opc_server) and not programs and not writes and not ics_server:
        r = client_txt[:3] + ([f"OPC UA server for {ips(opc_server)}"] if opc_server else [])
        r.append("polls controllers without writing - an operator / supervisory station")
        add("hmi", "high" if len(ics_client) >= 1 and opc_server else "medium", r)
        if opc_server:
            add("local_scada", "medium", r)
        if pc and client_txt:
            add("engineering_workstation", "medium",
                client_txt[:3] + [f"vendor {vendor} makes PCs / laptops - an engineering workstation online "
                                  "with the controllers looks the same as an HMI until it writes"])
    if opc_client and not client_txt and not hist_server:
        add("hmi", "medium", [f"OPC UA client of {ips(opc_client)}",
                              "reads the process through a server - an HMI or a historian"])
    if hist_server or (opc_client and not client_txt):
        r = ([f"{', '.join(sorted(hist_server))} server for {ips(hist_clients)}"] if hist_server else []) \
            + ([f"OPC UA client of {ips(opc_client)}"] if opc_client else [])
        add("historian", "medium", r)
    if ics_vendor and not sugg:
        add("field_device", "low", [f"vendor {vendor} makes industrial equipment; no traffic shows its role"],
            note="Pick the specific type (PLC, IO device, drive ...) if you know it.")
    if consumer_dev:
        add("business_workstation", "low",
            [f"vendor {vendor} makes phones / tablets / consumer devices"]
            + ([f"tried to reach the Internet ({', '.join(sorted(public)[:3])})"] if public else []),
            note="A personal or mobile device does not belong on the OT network: remove it. Classifying it "
                 "only puts it in a lane.")
    if pc and not sugg:
        add("engineering_workstation", "low", [f"vendor {vendor} makes PCs / laptops"],
            note="Confirm what it is before classifying.")
    order = {"high": 0, "medium": 1, "low": 2}
    sugg.sort(key=lambda x: order[x["confidence"]])

    def brief(h):
        return {"id": h.id, "ip": h.ip, "device_type": h.device_type, "purdue_level": h.purdue_level,
                "classification_source": h.classification_source}
    return {
        "host": {**brief(host), "mac": host.mac, "vendor": host.vendor},
        "same_mac": [brief(h) for h in same],
        "suggestions": sugg,
        "evidence": {"ics_client": {k: sorted(x for x in v if x) for k, v in ics_client.items()},
                     "ics_server": {k: sorted(x for x in v if x) for k, v in ics_server.items()},
                     "writes": sorted(writes), "program_ops": sorted(programs),
                     "opc_ua_server_for": sorted(x for x in opc_server if x),
                     "opc_ua_client_of": sorted(x for x in opc_client if x),
                     "internet": sorted(public)[:10], "capture_gateway": gw, "dhcp_server": bool(dhcp),
                     "vendor_kind": ("consumer network gear" if consumer_net else "consumer device" if consumer_dev
                                     else "PC / laptop" if pc else "industrial" if ics_vendor else None)},
    }
