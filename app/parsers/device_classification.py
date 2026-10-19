"""
Purdue Enterprise Reference Architecture (PERA) / ISA-99 (IEC 62443)
device classification.

Maps hosts to a device_type (plc, rtu, hmi, engineering_workstation,
etc.) and a Purdue level (0-4, or 3.5 for the industrial DMZ), so the
topology view can be organized
into the level-based zones this model is built around, rather than a
flat host list.

    Level 0  Physical Process       sensors, actuators, field instruments
    Level 1  Basic Control          PLC, RTU, IED, DCS controllers
    Level 2  Area Supervisory       HMI, local SCADA/alarm systems
    Level 3  Site Operations        historians, MES, site engineering
                                     workstations, site-wide SCADA servers
    Level 3.5 Industrial DMZ        jump hosts, historian replicas, patch/AV relays
    Level 4  Business/Enterprise    ERP, business IT, corporate email
    (Level 5, internet / external, is never inferred here.  The level
    vocabulary itself lives in app/purdue.py - F-08.)

TWO SEPARATE CLASSIFICATION MECHANISMS, WITH DIFFERENT CONFIDENCE:

1. MAC-vendor hint (`oui_hint`): the OUI resolves to a manufacturer
   name (already available via `common.lookup_vendor`), matched against
   a curated list of known ICS-hardware vendor names. This tells you
   "this NIC was made by a company that makes industrial control
   hardware" - it does NOT tell you whether the specific device is a
   PLC, an HMI, or an engineering PC, because most of these vendors sell
   all of those product categories under the same OUI blocks (Siemens
   makes PLCs, HMI panels, AND engineering laptops; the same is true of
   Rockwell, Schneider, ABB, and others). This mechanism only sets a
   *generic* device_type of "ics_hardware_vendor_device" with
   purdue_level left unset - it's a signal that a host is plausibly OT
   equipment worth a closer look, not a specific classification. Treat
   it as a hint to prioritize manual review, not an answer.

2. Protocol-role inference (`protocol_inferred`): a host observed as the
   SERVER side of a NetworkSession using a well-known ICS protocol port
   is confidently a controller (Level 1) - a device that answers Modbus/
   DNP3/S7comm/EtherNet-IP requests is definitionally basic-control-layer
   equipment. The protocol itself narrows the device_type further where
   it's protocol-specific (S7comm server -> definitionally a Siemens
   PLC; EtherNet/IP+CIP server with Rockwell-style tag services ->
   definitionally a Rockwell PLC; DNP3 server is commonly, but not
   exclusively, an RTU/IED - protective relays and some PLCs speak DNP3
   too, so it's labeled "rtu_or_ied" rather than asserting one).

   The CLIENT side of these sessions is NOT auto-classified past a
   generic marker, on purpose: it could be an HMI (Level 2), a
   site-wide SCADA server or engineering workstation (Level 3), or an
   IT asset polling for inventory - these matter for different reasons
   in a security review, and guessing wrong between them is worse than
   leaving it for a human to set via the manual classification endpoint.
   Automatically labeling every ICS-protocol client as "HMI" would look
   authoritative while actually being a coin flip.

3. VLAN-name inference (`vlan_inferred`): once a host's VLAN is known
   (via the MAC address-table bridge in mac_table_parser.py, or its
   lower-confidence subnet-inference fallback), the VLAN's own name
   often encodes its Purdue level directly - a VLAN named "ICS_CONTROL"
   or "CORP_IT" is telling you what it's for. `VLAN_NAME_KEYWORDS`
   below only maps terms confident enough to act on; ambiguous ones are
   explicitly listed and excluded rather than guessed at (see the
   comment above that dict for the specific reasoning on each excluded
   term - "engineering" is the standout case, since it means different
   Purdue levels depending on site convention).

PRECEDENCE (most to least authoritative, below manual): protocol_inferred
> vlan_inferred > lldp_role_inferred > oui_hint > protocol_client_hint.
"protocol_client_hint" (T3-36) only records that a host was seen as the
CLIENT of an ICS session (device_type "ics_protocol_client_unclassified",
no level) - it ranks lowest so VLAN inference and LLDP promotion can still
classify the host. A more specific mechanism's result is never
downgraded by a less specific one re-running later; manual is never
touched by any of them.
"""
from typing import Optional
import re

from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession

from app.models import FirewallInterface, Host, NetworkSession, SwitchInterface, SwitchVlan
from app.parsers.common import normalize_mac
from app.purdue import DMZ_LEVEL
from app.parsers.site_scope import scope_module

# Reference table: device_type -> (purdue_level, human-readable label).
# Used both for validating manual classification input and for exposing
# a reference/legend via the API.
DEVICE_TYPE_REFERENCE = {
    # Level 0 - Physical Process
    "sensor": (0, "Sensor"),
    "actuator": (0, "Actuator"),
    "field_device": (0, "Field device (generic)"),

    # Level 1 - Basic Control
    "plc": (1, "Programmable Logic Controller"),
    "rtu": (1, "Remote Terminal Unit"),
    "ied": (1, "Intelligent Electronic Device (protective relay, etc.)"),
    "rtu_or_ied": (1, "RTU or IED (protocol-inferred, not distinguished)"),
    "modbus_device": (1, "Modbus/TCP server (PLC, RTU, VFD or protocol gateway - type needs review)"),
    "dcs_controller": (1, "DCS Controller"),

    # Level 2 - Area Supervisory Control
    "hmi": (2, "Human-Machine Interface"),
    "local_scada": (2, "Local/Area SCADA"),
    "alarm_system": (2, "Alarm System"),

    # Level 3 - Site Operations
    "engineering_workstation": (3, "Engineering Workstation"),
    "historian": (3, "Historian"),
    "site_scada_server": (3, "Site-wide SCADA Server"),
    "mes_server": (3, "Manufacturing Execution System Server"),
    "ot_domain_controller": (3, "OT Domain Controller"),
    # owner 2026-10-13: DNS / NTP servers at L3 and L4 (operator classification)
    "site_dns_server": (3, "Site DNS server"),
    "site_ntp_server": (3, "Site NTP / time server"),

    # Level 3.5 - Industrial DMZ (F-08)
    "jump_host": (3.5, "Remote-access jump host (industrial DMZ)"),
    "dmz_server": (3.5, "Industrial DMZ server (historian replica, patch / AV relay)"),

    # Level 4 - Business/Enterprise
    "business_workstation": (4, "Business Workstation"),
    "erp_server": (4, "ERP Server"),
    "corporate_it": (4, "Corporate IT (generic)"),
    "enterprise_dns_server": (4, "Enterprise DNS server"),
    "enterprise_ntp_server": (4, "Enterprise NTP / time server"),

    # Level 5 - outside the site (VD-05: SSL-VPN tunnel-pool addresses)
    "remote_vpn_user": (5, "Remote user on an SSL-VPN tunnel-pool address"),

    # Generic/uncertain markers used by automatic classification
    "ics_hardware_vendor_device": (None, "ICS hardware vendor device (unclassified level - needs review)"),
    "ics_protocol_client_unclassified": (None, "Client of an ICS protocol session (role not determined)"),
    # FO-10: the gateway a capture identified (forwarded traffic of several hosts)
    "router": (None, "Router / gateway (network infrastructure)"),
    "vlan_inferred": (None, "Level inferred from VLAN name only (specific role not determined)"),
}

# Vendor name keywords (matched case-insensitively as a substring against
# the OUI-resolved vendor string) known to primarily manufacture
# industrial control hardware. Not exhaustive - extend as needed. This
# is intentionally a coarse "is this plausibly OT hardware" signal, not
# a specific-device-type determination (see module docstring).
_ICS_VENDOR_KEYWORDS = [
    "siemens", "rockwell", "allen-bradley", "allen bradley",
    "schneider", "honeywell", "emerson", "abb", "yokogawa",
    "mitsubishi electric", "omron", "phoenix contact", "moxa",
    "hirschmann", "advantech", "ge fanuc", "general electric",
    "wago", "beckhoff", "festo", "endress",
]

# TCP ports that, when a host is the SERVER side of a session using
# them, confidently indicate Level 1 basic-control equipment - and, for
# the protocol-specific ones, narrow the device_type further.
_SERVER_PORT_DEVICE_TYPES = {
    502: "modbus_device",   # Modbus/TCP - PLC, RTU, VFD or gateway: level 1, type open (D-10)
    102: "plc",             # S7comm - Siemens-specific, definitionally a PLC
    20000: "rtu_or_ied",    # DNP3 - common on RTUs/IEDs, not exclusively
    44818: "plc",           # EtherNet/IP+CIP - Rockwell/Allen-Bradley tag services
}

# Canonical server port per pcap_parser protocol label (T3-36).
_PROTOCOL_CANONICAL_PORT = {
    "modbus": 502,
    "s7comm": 102,
    "dnp3": 20000,
    "ethernet_ip": 44818,
    "enip": 44818,
    "cip": 44818,
}

# Ports >= this that are not the protocol's canonical port are treated as
# ephemeral client ports (T3-36).
_EPHEMERAL_FLOOR = 1024


def _server_side(src_port, dst_port, protocol) -> Optional[str]:
    """
    Decide which side of a session is the ICS server: "dst", "src" or None.

    Sessions are stored bidirectionally (pcap_parser: src/dst = first packet
    seen, not the initiator), so neither direction is trusted blindly.  A
    port only identifies the server when it is in _SERVER_PORT_DEVICE_TYPES
    AND is either a well-known port (< 1024: 502, 102) or the canonical port
    of the session's protocol.  A high port facing a well-known (< 1024)
    port on the other side is always the client's ephemeral port - e.g. SMB
    from ephemeral 44818 to 445 never makes the client a "PLC".  If both
    sides qualify, the protocol's canonical port wins, else the lower port.
    """
    canon = _PROTOCOL_CANONICAL_PORT.get((protocol or "").lower())

    def ok(port, other):
        if port is None or port not in _SERVER_PORT_DEVICE_TYPES:
            return False
        if port < _EPHEMERAL_FLOOR:
            return True
        if port != canon:
            return False  # >= 1024 and not canonical -> ephemeral
        return not (other is not None and other < _EPHEMERAL_FLOOR)

    d, s_ = ok(dst_port, src_port), ok(src_port, dst_port)
    if d and s_:
        if canon is not None and dst_port != src_port:
            if dst_port == canon:
                return "dst"
            if src_port == canon:
                return "src"
        return "src" if src_port < dst_port else "dst"
    if d:
        return "dst"
    if s_:
        return "src"
    return None

# VLAN name -> Purdue level, matched as whole tokens (the VLAN name is
# split on any non-alphanumeric character - spaces, underscores,
# dashes - and each resulting token is checked for exact membership,
# NOT substring matching). Substring matching would false-positive
# badly here: naive "it" in name.lower() matches inside "digital", and
# even word-boundary regex (\b) doesn't help because underscore is a
# \w character - "\bit\b" does not match "IT_NETWORK" since there's no
# boundary at the underscore. Tokenizing first avoids both problems -
# verified directly against both failure cases before relying on it.
#
# "dmz" maps to Level 3.5, the industrial DMZ (F-08) - and it wins over
# every other token, see classify_vlan_name below.
#
# EXCLUDED ON PURPOSE (checked for, explicitly return no classification
# rather than guess): "engineering" - in real deployments this names
# either an automation/controls engineering network (Level 1) or an
# engineering-workstation network (Level 3) depending entirely on site
# convention, and this project's own earlier example configs used it
# both ways in different places - a coin flip, not a hint. "office" and
# other single-word IT-adjacent terms not listed below are similarly
# left unmapped rather than assumed to mean Level 4.
VLAN_NAME_KEYWORDS = {
    # Level 4 - Business/Enterprise
    "corp": 4, "corporate": 4, "business": 4, "enterprise": 4, "it": 4,

    # Level 3 - Site Operations
    "mes": 3, "historian": 3,

    # Level 2 - Area Supervisory Control
    "scada": 2, "supervisory": 2, "hmi": 2,

    # Level 1 - Basic Control
    "control": 1, "plc": 1, "rtu": 1, "automation": 1, "ics": 1,

    # Level 0 - Physical Process
    "process": 0, "field": 0, "sensor": 0, "instrument": 0,
}

# ── Mechanism 4: LLDP/CDP role inference ──────────────────────────────────
#
# Maps keywords found in SwitchInterface.neighbor_platform (CDP, e.g.
# "cisco WS-C3750", "Siemens S7-300 CPU315-2 DP") or neighbor_device
# hostname (LLDP, e.g. "plc-line-01", "hmi-press-02") to a role string.
# This gives a narrower, function-level label (what the device *does*) to
# complement device_type (what Purdue *level* it sits at).
#
# Matching strategy:
#   neighbor_platform (CDP): keyword list applied as case-insensitive
#     substring. CDP platform strings usually begin with the vendor or
#     product family (e.g. "cisco", "Siemens S7", "WS-C", "AIR-").
#   neighbor_device (LLDP): tokenized the same way as VLAN names, then
#     token list checked for membership. Hostnames like "plc-line-01"
#     split to {"plc", "line", "01"} — the "plc" token hits the table.
#
# Precedence inside this mechanism: platform keyword > device hostname
# (CDP hardware description is more authoritative than an admin-chosen
# hostname). Does NOT overwrite classification_source="manual" or an
# already-set role — call it after classify_hosts() so the precedence
# chain is respected.
#
# NOTE: "neighbor_platform" is None for LLDP parsers (switch_parser.py
# intentionally leaves it blank because LLDP's system-description varies
# too much to parse reliably). CDP is the reliable platform source; LLDP
# contributes through the device hostname only.
_PLATFORM_ROLE_KEYWORDS: list[tuple[str, str]] = [
    # ICS / OT devices (platform strings from common PLCs/controllers)
    ("s7",              "plc"),          # Siemens SIMATIC S7 family
    ("simatic",         "plc"),
    ("cpu3",            "plc"),          # S7-300/400 CPU series prefix
    ("compact logix",   "plc"),          # Rockwell CompactLogix (with space)
    ("compactlogix",    "plc"),          # Rockwell CompactLogix (CDP no-space form)
    ("control logix",   "plc"),          # Rockwell ControlLogix (with space)
    ("controllogix",    "plc"),          # Rockwell ControlLogix (CDP no-space form)
    ("micrologix",      "plc"),
    ("slc ",            "plc"),          # Allen-Bradley SLC 500
    ("omron",           "plc"),
    ("sysmac",          "plc"),          # Omron Sysmac
    ("melsec",          "plc"),          # Mitsubishi MELSEC
    ("schneider",       "plc"),
    ("modicon",         "plc"),
    ("twido",           "plc"),
    ("ge fanuc",        "plc"),
    ("rx3i",            "plc"),          # GE PACSystems RX3i
    ("beckhoff",        "plc"),
    ("wago",            "plc"),
    ("codesys",         "plc"),
    ("rtu",             "rtu"),
    ("sel-",            "ied"),          # Schweitzer Engineering (protection IEDs)
    ("ied",             "ied"),
    # SCADA / Historian / HMI
    ("wonderware",      "historian"),
    ("osisoft",         "historian"),
    ("pi server",       "historian"),
    ("wincc",           "hmi"),          # Siemens WinCC
    ("factorytalk",     "hmi"),          # Rockwell FactoryTalk
    ("rsview",          "hmi"),
    ("ifix",            "hmi"),          # GE iFIX
    ("indusoft",        "hmi"),
    ("citect",          "scada_server"),
    ("ignition",        "scada_server"), # Inductive Automation
    ("genesis",         "scada_server"), # Iconics
    # Network infrastructure
    ("ws-c",            "switch"),       # Cisco Catalyst (WS-C3750, WS-C4500...)
    ("catalyst",        "switch"),
    ("nexus",           "switch"),
    ("procurve",        "switch"),       # HP ProCurve
    ("aruba",           "switch"),       # HPE Aruba
    ("extremexos",      "switch"),
    ("juniper",         "switch"),
    ("asr ",            "router"),       # Cisco ASR (router)
    ("isr ",            "router"),       # Cisco ISR (router)
    ("air-",            "ap"),           # Cisco Aironet (wireless AP)
    ("aironet",         "ap"),
    ("ap ",             "ap"),
    # Security / Other
    ("fortigate",       "firewall"),
    ("fortios",         "firewall"),
    ("asa ",            "firewall"),     # Cisco ASA
    ("pix ",            "firewall"),
    ("juniper srx",     "firewall"),
    ("ups",             "ups"),
    ("apc ",            "ups"),          # APC Smart-UPS
    ("eaton",           "ups"),
    ("camera",          "ip_camera"),
    ("axis ",           "ip_camera"),    # Axis network cameras
    ("recorder",        "ip_camera"),
]

# Hostname token keywords (used against tokenised neighbor_device name for LLDP).
# Only roles where a single word in the hostname reliably identifies the device.
# More ambiguous terms ("server", "node", "dev") are intentionally excluded.
_HOSTNAME_ROLE_TOKENS: dict[str, str] = {
    "plc":        "plc",
    "hmi":        "hmi",
    "rtu":        "rtu",
    "ied":        "ied",
    "scada":      "scada_server",
    "historian":  "historian",
    "switch":     "switch",
    "sw":         "switch",
    "router":     "router",
    "fw":         "firewall",
    "firewall":   "firewall",
    "ap":         "ap",
    "wap":        "ap",
    "ups":        "ups",
    "camera":     "ip_camera",
    "cam":        "ip_camera",
    "printer":    "printer",
    "prt":        "printer",
    # Remote-access jump host -> Level 3.5 via DEVICE_TYPE_REFERENCE (F-08)
    "jumphost":   "jump_host",
    "jumpbox":    "jump_host",
    "bastion":    "jump_host",
}


def infer_role_from_platform(platform: str | None) -> str | None:
    """
    Match a CDP neighbor_platform string against `_PLATFORM_ROLE_KEYWORDS`.
    Returns the first matching role, or None if nothing matches.
    """
    if not platform:
        return None
    p = platform.lower()
    for keyword, role in _PLATFORM_ROLE_KEYWORDS:
        if keyword in p:
            return role
    return None


def infer_role_from_hostname(hostname: str | None) -> str | None:
    """
    Tokenize a neighbor_device hostname and check each token against
    `_HOSTNAME_ROLE_TOKENS`. Returns the first matching role, or None.
    """
    if not hostname:
        return None
    tokens = set(re.split(r"[^a-z]+", hostname.lower())) - {""}
    for token in tokens:
        if token in _HOSTNAME_ROLE_TOKENS:
            return _HOSTNAME_ROLE_TOKENS[token]
    return None


def classify_hosts_by_lldp_role(db: DBSession) -> dict:
    """
    Mechanism 4: populate Host.role from SwitchInterface CDP/LLDP data.

    For every SwitchInterface row with a non-null neighbor_ip or a
    neighbor_device that can be resolved to a Host, tries to infer a
    functional role string from:
      1. neighbor_platform (CDP - hardware platform string, higher confidence)
      2. neighbor_device hostname tokens (LLDP - admin-assigned name)

    The inferred role is written to Host.role and Host.role_source.
    "manual" role_source is never overwritten; an existing auto-inferred
    role is overwritten only if the new source is higher-confidence
    (cdp > lldp, since CDP carries actual hardware info vs. a hostname).

    Returns counts of what changed.
    """
    stats = {"role_applied": 0, "role_skipped_manual": 0, "hosts_matched": 0}

    ifaces = db.query(SwitchInterface).filter(
        or_(
            SwitchInterface.neighbor_ip.isnot(None),
            SwitchInterface.neighbor_device.isnot(None),
        )
    ).all()

    for iface in ifaces:
        # Attempt to find the Host this interface's neighbor corresponds to.
        # Prefer neighbor_ip match (most reliable); fall back to MAC via
        # neighbor_device when it looks like a normalized MAC address.
        host = None
        if iface.neighbor_ip:
            host = db.query(Host).filter(Host.ip == iface.neighbor_ip).first()
        if host is None and iface.neighbor_device:
            # neighbor_device may be a MAC (chassis-ID-as-MAC for LLDP) or a
            # hostname; try MAC match first.
            # F-16: normalise via the shared helper so Cisco dotted
            # (0011.2233.4455), hyphen, bare and colon forms all match the
            # canonical aa:bb:cc:dd:ee:ff stored on Host.mac.
            maybe_mac = normalize_mac(iface.neighbor_device)
            if maybe_mac:
                host = db.query(Host).filter(Host.mac == maybe_mac).first()

        if host is None:
            continue

        stats["hosts_matched"] += 1

        if host.role_source == "manual":
            stats["role_skipped_manual"] += 1
            continue

        # Determine role and source.  CDP platform > LLDP hostname.
        protocol = iface.neighbor_protocol or "lldp"
        role = None
        source = None

        if iface.neighbor_platform:
            # CDP: try platform string first.
            role = infer_role_from_platform(iface.neighbor_platform)
            if role:
                source = "cdp"

        if role is None:
            # LLDP (or CDP without platform data): try hostname.
            role = infer_role_from_hostname(iface.neighbor_device)
            if role:
                source = protocol  # "lldp" or "cdp"

        if role is None:
            continue  # no classification possible from this interface

        # Only overwrite a prior auto-inferred role if the new one is
        # from a higher-confidence source (cdp > lldp) or the slot is empty.
        current_source = host.role_source
        if host.role is not None and current_source == "cdp" and source == "lldp":
            continue  # don't downgrade CDP inference with LLDP hostname

        host.role = role
        host.role_source = source
        stats["role_applied"] += 1

    db.flush()  # caller (classify_hosts) commits the outer transaction
    return stats


# Precedence order for classification_source values (higher index = higher authority).
# lldp_role_inferred sits between oui_hint and vlan_inferred: it is more confident
# than a bare OUI vendor match, but less confident than an observed protocol session
# or an explicit VLAN-name keyword hit (which anchors the host to a designed segment).
_SOURCE_PRECEDENCE = [
    None,              # 0 — unset
    "interface_label",       # 0a — level of the labelled interface the host sits behind (SF-8a)
    "object_name",           # 0a' — owner 2026-10-19: the firewall address object's name says what it is
    "protocol_client_hint",  # 0b — seen as ICS client only, no level (T3-36)
    "oui_hint",        # 1 — OUI vendor name recognised as ICS hardware
    "lldp_role_inferred",  # 2 — LLDP/CDP neighbor reports a specific device role
    "vlan_inferred",   # 3 — VLAN name keyword maps to a Purdue level
    "protocol_inferred",   # 4 — device observed serving an ICS protocol
    "capture_gateway",     # 4a — FO-10: MAC seen forwarding traffic of several hosts
    "vpn_pool",        # 4b — address in an SSL-VPN tunnel pool: a remote user (VD-05)
    "manual",          # 5 — operator-set; never overwritten
]


def classify_vpn_pool_hosts(db: DBSession) -> dict:
    """VD-05: a host whose address lies in an SSL-VPN tunnel pool is a remote
    user (L5, ``remote_vpn_user``, source ``vpn_pool``).  Set before every
    other automatic mechanism and never moved by them - a VPN user polling
    PLCs is a remote user polling PLCs, not control-zone equipment.  A
    manual classification still wins."""
    from app.parsers import vpn as _vpn
    stats = {"vpn_pool_applied": 0}
    vctx = _vpn.VpnContext.build(db)
    if not vctx.pools:
        return stats
    for h in db.query(Host).filter(Host.ip.isnot(None),
                                   or_(Host.classification_source.is_(None),
                                       Host.classification_source != "manual")).all():
        if not vctx.is_pool_ip(h.ip):
            continue
        if (h.device_type, h.purdue_level, h.classification_source) != ("remote_vpn_user", 5, "vpn_pool"):
            h.device_type, h.purdue_level, h.classification_source = "remote_vpn_user", 5, "vpn_pool"
            stats["vpn_pool_applied"] += 1
    db.flush()
    return stats


def _source_rank(source: Optional[str]) -> int:
    """Return the authority rank of a classification_source string (0 = lowest)."""
    try:
        return _SOURCE_PRECEDENCE.index(source)
    except ValueError:
        return 0  # unknown source treated as lowest


def promote_purdue_from_lldp_role(db: DBSession) -> dict:
    """
    Mechanism 4b: after classify_hosts_by_lldp_role() writes Host.role,
    promote Host.purdue_level from that role using DEVICE_TYPE_REFERENCE.

    Only roles that map to a concrete Purdue level (0-4 or 3.5) are promoted;
    generic markers like "ics_hardware_vendor_device" (level=None) are skipped
    because they carry no zone information.

    Precedence:
      - Never overwrites classification_source="manual" or "protocol_inferred".
      - Overwrites "oui_hint" or None (sets classification_source="lldp_role_inferred").
      - Does NOT overwrite "vlan_inferred": a VLAN keyword placement is considered
        equally or more reliable than a CDP/LLDP hostname inference because the VLAN
        was deliberately designed by a network engineer, while a device hostname may
        be auto-generated or mis-named.

    Returns a count dict for stats reporting.
    """
    stats = {"purdue_promoted": 0, "skipped_no_level": 0, "skipped_precedence": 0}

    # Only hosts that have a role set but where promotion is still worthwhile.
    # Exclude sources with equal or higher precedence than "lldp_role_inferred"
    # at the SQL level so we don't load hosts we'd only skip in Python anyway.
    # _SOURCE_PRECEDENCE order: None < oui_hint < lldp_role_inferred < vlan_inferred
    #                           < protocol_inferred < manual
    # We may overwrite: None, oui_hint
    # We must NOT overwrite: lldp_role_inferred, vlan_inferred, protocol_inferred, manual
    candidates = db.query(Host).filter(
        Host.role.isnot(None),
        or_(
            Host.purdue_level.is_(None),
            Host.classification_source.is_(None),
            Host.classification_source.in_(
                ["oui_hint", "lldp_role_inferred", "protocol_client_hint", "interface_label"]),
        ),
    ).all()

    for host in candidates:
        if host.role not in DEVICE_TYPE_REFERENCE:
            stats["skipped_no_level"] += 1
            continue

        level, _label = DEVICE_TYPE_REFERENCE[host.role]
        if level is None:
            stats["skipped_no_level"] += 1
            continue  # generic marker — no Purdue level to promote

        # Respect precedence: never overwrite a higher-authority classification
        existing_rank = _source_rank(host.classification_source)
        new_rank = _source_rank("lldp_role_inferred")
        if existing_rank > new_rank:
            stats["skipped_precedence"] += 1
            continue

        host.purdue_level = level
        host.classification_source = "lldp_role_inferred"
        stats["purdue_promoted"] += 1

    db.flush()  # caller (classify_hosts) commits the outer transaction
    return stats


def _tokenize_vlan_name(vlan_name: str) -> set:
    return set(re.split(r"[^a-z0-9]+", vlan_name.lower())) - {""}


_DMZ_TOKENS = frozenset({"dmz", "idmz"})


def classify_vlan_name(vlan_name: Optional[str]):
    """
    Returns a Purdue level (0-4, or 3.5) if the VLAN name contains a
    token from VLAN_NAME_KEYWORDS, or None if it doesn't match anything
    confident enough to act on (including the explicitly-excluded
    ambiguous terms - see the comment above VLAN_NAME_KEYWORDS).

    A VLAN name with a "dmz" / "idmz" token is the industrial DMZ, Level
    3.5 (F-08), regardless of other tokens: "DMZ" names the zone, while
    the other words usually name what lives in it ("DMZ_HISTORIAN" is a
    historian replica in the DMZ, not an L3 historian; "IT_DMZ" is the
    DMZ facing IT, not L4).

    Otherwise, if multiple keyword tokens match different levels (a
    poorly-named or multi-purpose VLAN), the lowest matching level wins -
    being conservative about how far into the OT side a VLAN might reach
    is safer for a security review than assuming everything's business IT.
    """
    if not vlan_name:
        return None

    tokens = _tokenize_vlan_name(vlan_name)
    if tokens & _DMZ_TOKENS:
        return DMZ_LEVEL  # see docstring - the zone name wins

    matched_levels = [level for token, level in VLAN_NAME_KEYWORDS.items() if token in tokens]
    if not matched_levels:
        return None
    return min(matched_levels)


# owner 2026-10-19: what a firewall address object's NAME says about the host ("DRUMCROSS.Controllers",
# "...NTP_01", "plants_jumphost").  Tokens are matched whole after splitting on . _ - and spaces;
# the first matching rule wins; a manual or stronger classification is never overwritten.
OBJECT_NAME_KEYWORDS = (
    # (tokens, device_type, role, tokens that veto the match - audit 2026-10-19: "Domain_Controller",
    # "Wireless-Controller", "SMTP_Relay", "Fire_Panel" are IT / facility names, not OT devices)
    (("plc", "controller", "controllers", "ppc", "dcs"), "plc", None,
     ("domain", "ad", "dc", "wireless", "wlan", "wifi", "sd", "sdwan", "storage", "raid", "nic", "usb", "bmc")),
    (("rtu",), "rtu", None, ()),
    (("ied", "relay"), "ied", None, ("smtp", "mail", "dhcp", "dns", "frame", "proxy", "syslog", "log")),
    (("hmi", "panel"), "hmi", None, ("fire", "alarm", "patch", "solar", "pv")),
    (("scada",), "local_scada", None, ()),
    (("historian", "hist"), "historian", None, ()),
    (("mes",), "mes_server", None, ()),
    (("ntp",), "site_ntp_server", None, ()), (("dns",), "site_dns_server", None, ()),
    (("jumphost", "bastion"), "jump_host", None, ()),
    (("engineering", "ews"), "engineering_workstation", None, ()),
    (("switch", "switches", "swit"), None, "switch", ()),
    (("wap", "accesspoint", "fortiap"), None, "ap", ()),
)


def classify_object_name(name: Optional[str]):
    """(device_type, role) suggested by an address object / group name, or (None, None).  Whole
    tokens only; a veto token in the same name cancels the match (a domain controller is not a PLC)."""
    import re as _re
    if not name:
        return None, None
    toks = {t for t in _re.split(r"[.\s_\-/]+", str(name).lower()) if t}
    toks |= {_re.sub(r"\d+$", "", t) for t in toks}        # NTP_01 -> ntp, SWIT01 -> swit
    for words, dtype, role, veto in OBJECT_NAME_KEYWORDS:
        if toks & set(words) and not (toks & set(veto)):
            return dtype, role
    return None, None


def classify_host_by_vendor(vendor: Optional[str]) -> Optional[str]:
    """
    Returns "ics_hardware_vendor_device" if the OUI-resolved vendor name
    matches a known ICS hardware manufacturer, else None. See module
    docstring for why this doesn't attempt a more specific device_type.
    """
    if not vendor:
        return None
    lowered = vendor.lower()
    if any(keyword in lowered for keyword in _ICS_VENDOR_KEYWORDS):
        return "ics_hardware_vendor_device"
    return None


def _vlan_name_for_host(db: DBSession, host: Host) -> Optional[str]:
    """
    Look up the vlan_name for whatever VLAN this host is on.

    Priority order:
    1. SwitchVlan table (first-class VLAN objects, written by switch_parser
       from `show vlan brief` and running-config VLAN blocks). Covers trunk
       ports and MAC-table-sourced hosts that never had a named SwitchInterface
       row because the vlan_brief was ingested separately from a different file.
    2. SwitchInterface table (fallback for legacy data ingested before SwitchVlan
       rows existed, or configs without a vlan_brief section). Access ports only,
       since trunk ports intentionally have vlan_name=None on SwitchInterface.

    Since a given VLAN id is almost always named consistently across every
    device that carries it, taking the first match is correct in practice.
    """
    if not host.vlan:
        return None

    # host.vlan is stored as a String (set from MAC table or subnet inference).
    # SwitchVlan.vlan_id is Integer.  Cast before the filter to avoid a silent
    # type-mismatch on PostgreSQL (which raises DataError for str vs int column).
    # Trunk-port VLANs may be stored as "10,20-25"; extract the first id only.
    raw_vlan = str(host.vlan).split(",")[0].split("-")[0].strip()
    try:
        vlan_id_int = int(raw_vlan)
    except (ValueError, TypeError):
        return None

    # Path 1: SwitchVlan (authoritative - covers vlan_brief, trunk ports, any device)
    sv = (
        db.query(SwitchVlan)
        .filter(SwitchVlan.vlan_id == vlan_id_int, SwitchVlan.vlan_name.isnot(None))
        .first()
    )
    if sv:
        return sv.vlan_name

    # Path 2: SwitchInterface fallback (access ports from running-config, no vlan_brief)
    iface = (
        db.query(SwitchInterface)
        .filter(SwitchInterface.vlan == host.vlan, SwitchInterface.vlan_name.isnot(None))
        .first()
    )
    return iface.vlan_name if iface else None


def classify_hosts_by_vlan(db: DBSession) -> dict:
    """
    Mechanism 3: for hosts with a known VLAN (from mac_table_parser.py,
    either the authoritative mac_table link or the subnet_inference
    fallback) whose VLAN's name maps to a confident Purdue level via
    classify_vlan_name, apply that level - unless the host is already
    "manual" or "protocol_inferred" (both take precedence - see module
    docstring's precedence order).
    """
    stats = {"vlan_inferred_applied": 0}

    # NOTE: `classification_source.notin_([...])` alone would silently
    # exclude every host where classification_source IS NULL - standard
    # SQL's three-valued logic makes "NULL NOT IN (...)" evaluate to
    # NULL/unknown, not TRUE, so those rows would never satisfy the
    # WHERE clause at all. Since "unclassified" (NULL) is the single
    # most common case this mechanism needs to reach, that would have
    # been a real, silent bug - the explicit IS NULL branch below is
    # required, not optional.
    hosts = db.query(Host).filter(
        Host.vlan.isnot(None),
        or_(
            Host.classification_source.is_(None),
            Host.classification_source.notin_(["manual", "protocol_inferred", "vpn_pool", "capture_gateway"]),
        ),
    ).all()

    resolver = _VlanLevelResolver(db)
    # LS-06: a firewall / routing-switch interface address is known
    # infrastructure - never placed by a VLAN name.
    from app.models import FirewallInterface
    infra_ips = {str(ip).strip() for (ip,) in db.query(FirewallInterface.ip_address).filter(
        FirewallInterface.ip_address.isnot(None))}
    for host in hosts:
        if host.ip and host.ip in infra_ips:
            if host.classification_source == "vlan_inferred":
                host.purdue_level = None
                host.classification_source = None
                if host.device_type == "vlan_inferred":
                    host.device_type = None
            continue
        level = resolver.level_for(host.vlan)
        if level is None:
            continue
        if host.device_type == "ics_protocol_client_unclassified" and level < 2:
            # D-10: a host seen polling a controller is supervisory; a
            # "control" VLAN name must not push an HMI down to L0/L1.
            level = 2
        host.device_type = "vlan_inferred" if host.device_type != "ics_protocol_client_unclassified" else host.device_type
        host.purdue_level = level
        host.classification_source = "vlan_inferred"
        stats["vlan_inferred_applied"] += 1

    db.flush()  # caller (classify_hosts) commits the outer transaction
    return stats


_VLAN_LEVEL_SOURCE_RANK = {"manual": 3, "firewall_propagated": 2, "keyword_inferred": 1}


class _VlanLevelResolver:
    """
    VLAN id -> Purdue level, loaded once per run (T3-41: no per-host query).

    T3-37: SwitchVlan.purdue_level (manual > firewall_propagated >
    keyword_inferred > other) is used first; only if no SwitchVlan carrying
    that VLAN id has a level is the level re-derived from the VLAN name
    (SwitchVlan name first, then SwitchInterface.vlan_name fallback).
    """

    def __init__(self, db: DBSession):
        self.db = db
        self._levels: dict[int, tuple] = {}
        self._names: dict[int, str] = {}
        for sv in db.query(SwitchVlan.vlan_id, SwitchVlan.vlan_name,
                           SwitchVlan.purdue_level, SwitchVlan.purdue_level_source
                           ).order_by(SwitchVlan.id):
            if sv.purdue_level is not None:
                rank = _VLAN_LEVEL_SOURCE_RANK.get(sv.purdue_level_source, 0)
                cur = self._levels.get(sv.vlan_id)
                if cur is None or rank > cur[0]:
                    self._levels[sv.vlan_id] = (rank, sv.purdue_level)
            if sv.vlan_name and sv.vlan_id not in self._names:
                self._names[sv.vlan_id] = sv.vlan_name
        self._iface_names: Optional[dict[str, str]] = None
        self._cache: dict = {}

    def level_for(self, vlan) -> Optional[int]:
        if vlan in self._cache:
            return self._cache[vlan]
        lvl = self._compute(vlan)
        self._cache[vlan] = lvl
        return lvl

    def _compute(self, vlan) -> Optional[int]:
        if not vlan:
            return None
        raw = str(vlan).split(",")[0].split("-")[0].strip()
        try:
            vid = int(raw)
        except (ValueError, TypeError):
            return None
        if vid in self._levels:
            return self._levels[vid][1]
        name = self._names.get(vid)
        if name is None:
            if self._iface_names is None:
                self._iface_names = {}
                for si in self.db.query(SwitchInterface.vlan, SwitchInterface.vlan_name).filter(
                        SwitchInterface.vlan_name.isnot(None)).order_by(SwitchInterface.id):
                    self._iface_names.setdefault(si.vlan, si.vlan_name)
            name = self._iface_names.get(vlan)
        return classify_vlan_name(name)


def resolve_vlan_topology(db: DBSession) -> dict:
    """
    Propagate Purdue levels from firewall VLAN sub-interfaces to the
    matching SwitchVlan rows.

    When a FortiGate interface (e.g. "port3.10") has:
      - vlan_id set (e.g. "10")
      - purdue_level set by the operator or suggested (from topology review)

    ... and there is a SwitchVlan on any switch with the same vlan_id, the
    firewall's purdue_level is written to SwitchVlan.purdue_level with source
    "firewall_propagated".  This is stronger evidence than keyword inference,
    so it always overwrites "keyword_inferred"; it never overwrites "manual".

    After updating SwitchVlan, the new levels are immediately visible to the
    next call of classify_hosts_by_vlan (Mechanism 3), so hosts on those
    VLANs pick up the firewall-anchored level on the same classify_hosts() run.

    Returns counts of SwitchVlan rows updated.
    """
    stats = {"vlans_propagated": 0}

    # Only interfaces that have both a vlan_id and a usable purdue_level.
    # We prefer operator-confirmed purdue_level (not None) over suggested,
    # since suggested is only a heuristic; both are checked here so that a
    # site that hasn't done topology review yet still benefits if the operator
    # has confirmed any interface.
    fw_ifaces = db.query(FirewallInterface).filter(
        FirewallInterface.vlan_id.isnot(None),
        FirewallInterface.purdue_level.isnot(None),
    ).all()

    for iface in fw_ifaces:
        # vlan_id is stored as a string in the model ("10", not 10)
        try:
            vlan_id_int = int(iface.vlan_id)
        except (ValueError, TypeError):
            continue

        # Find all SwitchVlan rows with this VLAN id that are not manually set.
        # T3-37: `!= "manual"` alone excludes NULL sources (SQL NULL logic),
        # so VLANs with no keyword level were never updated.
        switch_vlans = db.query(SwitchVlan).filter(
            SwitchVlan.vlan_id == vlan_id_int,
            or_(SwitchVlan.purdue_level_source.is_(None),
                SwitchVlan.purdue_level_source != "manual"),
        ).all()

        for sv in switch_vlans:
            sv.purdue_level = iface.purdue_level
            sv.purdue_level_source = "firewall_propagated"
            stats["vlans_propagated"] += 1

    db.flush()  # caller (classify_hosts) commits the outer transaction
    return stats


def classify_capture_gateways(db: DBSession) -> int:
    """FO-10: a host row carrying a gateway MAC a capture identified (the
    MAC forwarded traffic for several hosts - PcapCapture.segment) and an
    address is the router itself: device type ``router``, no level, source
    ``capture_gateway``.  Infrastructure - the device checks skip it.  A
    manual classification still wins."""
    import json
    from app.models import PcapCapture
    macs: set = set()
    for (raw,) in db.query(PcapCapture.segment).filter(PcapCapture.segment.isnot(None)):
        try:
            macs |= {str(m).lower() for m in (json.loads(raw).get("gateway_macs") or [])}
        except (ValueError, AttributeError):
            continue
    if not macs:
        return 0
    n = 0
    ml = sorted(macs)
    for i in range(0, len(ml), 900):
        for h in db.query(Host).filter(Host.mac.in_(ml[i:i + 900]), Host.ip.isnot(None),
                                       or_(Host.classification_source.is_(None),
                                           Host.classification_source.notin_(["manual", "vpn_pool"]))):
            # IO-05: consumer / SOHO gear acting as gateway stays a device
            # (reported by wireless_in_ot_zone), never trusted infrastructure
            from app.parsers.segments import CONSUMER_NET_WORDS, vendor_matches
            if vendor_matches(h.vendor, CONSUMER_NET_WORDS):
                continue
            if (h.device_type, h.purdue_level, h.classification_source) != ("router", None, "capture_gateway"):
                h.device_type, h.purdue_level, h.classification_source = "router", None, "capture_gateway"
                n += 1
    db.flush()
    return n


#: Host.vlan_source values a firewall / L3-switch VLAN interface may replace
#: (owner 2026-10-12): empty, its own earlier value, and the /24 guess.  MAC
#: tables, 802.1Q captures and the operator's inventory always win.
_IFACE_VLAN_REPLACES = (None, "fw_interface", "subnet_inference")


def vlan_interfaces(db: DBSession, site_ids=None) -> dict:
    """{site_id: [(network, vlan_id, firewall, interface, alias)]} of firewall
    and routing-switch interfaces with a VLAN id and a network (FortiOS
    `set vlanid`, Cisco SVIs), most specific network first."""
    import ipaddress
    from app.models import Firewall
    q = (db.query(FirewallInterface.network_cidr, FirewallInterface.vlan_id, FirewallInterface.name,
                  FirewallInterface.alias, Firewall.name, Firewall.site_id)
         .join(Firewall, Firewall.id == FirewallInterface.firewall_id)
         .filter(FirewallInterface.vlan_id.isnot(None), FirewallInterface.vlan_id != "",
                 FirewallInterface.network_cidr.isnot(None)))
    if site_ids is not None:
        q = q.filter(Firewall.site_id.in_(list(site_ids)))
    out: dict = {}
    for net, vid, iname, alias, fname, sid in q:
        try:
            n = ipaddress.ip_network(str(net), strict=False)
        except ValueError:
            continue
        if n.prefixlen == 0:
            continue
        out.setdefault(sid, []).append((n, str(vid).strip(), fname, iname, alias))
    for lst in out.values():
        lst.sort(key=lambda t: -t[0].prefixlen)
    return out


def interface_vlan_for(ip, entries) -> Optional[tuple]:
    """The (network, vlan, firewall, interface, alias) of the most specific VLAN
    interface network holding ``ip``; None when none does, or when interfaces of
    that same network disagree on the VLAN id."""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    best = [e for e in entries if a.version == e[0].version and a in e[0]]
    if not best:
        return None
    top = best[0][0].prefixlen
    same = [e for e in best if e[0].prefixlen == top]
    if len({e[1] for e in same}) > 1:
        return None                              # two interfaces disagree: no guess
    return same[0]


def assign_vlans_from_interfaces(db: DBSession) -> dict:
    """Owner 2026-10-12: a host with no VLAN of its own takes the VLAN of the
    firewall / routing-switch VLAN interface whose subnet holds its address
    (vlan_source "fw_interface").  Replaces only an empty value, its own earlier
    value and the /24 subnet guess; a value of its own that no interface
    supports any more is cleared."""
    stats = {"vlan_from_interface": 0, "vlan_from_interface_cleared": 0}
    hosts = db.query(Host).filter(Host.ip.isnot(None),
                                  or_(Host.vlan_source.is_(None), Host.vlan_source.in_(
                                      [v for v in _IFACE_VLAN_REPLACES if v]))).all()
    if not hosts:
        return stats
    index = vlan_interfaces(db, {h.site_id for h in hosts})
    for h in hosts:
        hit = interface_vlan_for(h.ip, index.get(h.site_id, []))
        if hit is None:
            if h.vlan_source == "fw_interface":
                h.vlan, h.vlan_source = None, None
                stats["vlan_from_interface_cleared"] += 1
            continue
        if h.vlan_source == "subnet_inference" or h.vlan is None or h.vlan_source == "fw_interface":
            if h.vlan != hit[1] or h.vlan_source != "fw_interface":
                h.vlan, h.vlan_source = hit[1], "fw_interface"
                stats["vlan_from_interface"] += 1
    db.flush()
    return stats


def classify_hosts(db: DBSession) -> dict:
    """
    Run both classification mechanisms over every host that isn't
    manually classified, writing device_type/purdue_level/
    classification_source. Safe to call repeatedly (e.g. after every
    pcap ingest) - it only touches non-manually-classified rows, and a
    later, more specific protocol-inferred result overwrites an earlier,
    more generic vendor-hint result, but manual is never touched.

    Returns counts of what changed, for API responses.
    """
    stats = {"vendor_hint_applied": 0, "protocol_inferred_applied": 0, "vlan_inferred_applied": 0}

    # --- Mechanism 0 (VD-05): SSL-VPN tunnel-pool addresses are remote users
    stats["vpn_pool_applied"] = classify_vpn_pool_hosts(db)["vpn_pool_applied"]

    # --- Mechanism 0b (FO-10): the gateways the captures identified ---
    stats["capture_gateway_applied"] = classify_capture_gateways(db)

    # --- Mechanism 1: vendor hint ---
    # Same NULL/!= gotcha as classify_hosts_by_vlan's filter above:
    # `classification_source != "manual"` alone silently excludes every
    # host where classification_source IS NULL (SQL's three-valued
    # logic again), which is every freshly-discovered, not-yet-
    # classified host - the exact population this mechanism most needs
    # to reach. This was a real bug from when this mechanism was first
    # written, caught only once a second, structurally-identical filter
    # prompted checking this one too.
    hosts = db.query(Host).filter(
        or_(Host.classification_source.is_(None), Host.classification_source != "manual"),
        Host.device_type.is_(None),
        Host.vendor.isnot(None),
    ).all()
    for host in hosts:
        device_type = classify_host_by_vendor(host.vendor)
        if device_type and host.device_type is None:
            host.device_type = device_type
            host.purdue_level = DEVICE_TYPE_REFERENCE[device_type][0]
            host.classification_source = "oui_hint"
            stats["vendor_hint_applied"] += 1

    # --- Mechanism 2: protocol-role inference ---
    # T3-36 data repair: rows written by the old code as client markers with
    # source "protocol_inferred" and no level are demoted to the low-rank
    # client hint so VLAN / LLDP inference can reach them.
    db.query(Host).filter(
        Host.device_type == "ics_protocol_client_unclassified",
        Host.classification_source == "protocol_inferred",
        Host.purdue_level.is_(None),
    ).update({Host.classification_source: "protocol_client_hint"},
             synchronize_session="fetch")
    # T3-41: column-only query restricted to sessions that touch a server
    # port (no ORM objects, no per-session lazy host loads); hosts are then
    # loaded in id batches.  Sessions are processed in id order so the
    # result is deterministic.
    server_ports = list(_SERVER_PORT_DEVICE_TYPES)
    rows = (
        db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id,
                 NetworkSession.src_port, NetworkSession.dst_port, NetworkSession.protocol)
        .filter(NetworkSession.protocol != "unknown",
                or_(NetworkSession.dst_port.in_(server_ports),
                    NetworkSession.src_port.in_(server_ports)))
        .order_by(NetworkSession.id)
        .all()
    )
    server_type: dict[int, str] = {}   # host_id -> device_type (last session wins)
    client_ids: list[int] = []
    polls: dict[int, set] = {}         # client host_id -> distinct servers it polls
    for r in rows:
        side = _server_side(r.src_port, r.dst_port, r.protocol)
        if side is None:
            continue
        if side == "dst":
            server_id, client_id, port = r.dst_host_id, r.src_host_id, r.dst_port
        else:
            server_id, client_id, port = r.src_host_id, r.dst_host_id, r.src_port
        server_type[server_id] = _SERVER_PORT_DEVICE_TYPES[port]
        stats["protocol_inferred_applied"] += 1
        client_ids.append(client_id)
        polls.setdefault(client_id, set()).add(server_id)
    # D-10: a host that POLLS controllers is supervisory, whatever else it
    # does.  A SCADA master that also accepts DNP3 (unsolicited responses /
    # outstation role toward a higher master) is the server of one session
    # and the client of many - it is not an RTU.  Likewise an HMI polling
    # two or more controllers is a supervisory node (L2), not a basic-control
    # device.  Both get local_scada (L2, "type needs review" via the
    # protocol_inferred source) instead of the server-port type.  Two
    # distinct servers are required: an RTU that answers one master and
    # sends it unsolicited DNP3 polls exactly one host and stays an RTU.
    masters = {cid for cid, servers in polls.items() if len(servers - {cid}) >= 2}
    for cid in masters:
        server_type[cid] = "local_scada"
        stats["protocol_master_applied"] = stats.get("protocol_master_applied", 0) + 1

    needed = list(set(server_type) | set(client_ids))
    host_by_id: dict[int, Host] = {}
    for i in range(0, len(needed), 900):
        for h in db.query(Host).filter(Host.id.in_(needed[i:i + 900])):
            host_by_id[h.id] = h

    for hid, device_type in server_type.items():
        h = host_by_id.get(hid)
        if h is not None and h.classification_source not in ("manual", "vpn_pool", "capture_gateway"):
            h.device_type = device_type
            h.purdue_level = DEVICE_TYPE_REFERENCE[device_type][0]
            h.classification_source = "protocol_inferred"

    # Client side: only mark the generic "seen initiating ICS traffic"
    # device_type if nothing more specific is set.  T3-36: no level is
    # inferred, so the source is the LOWEST-ranked "protocol_client_hint"
    # (never "protocol_inferred", which would block VLAN/LLDP inference).
    for cid in dict.fromkeys(client_ids):
        h = host_by_id.get(cid)
        if h is None or cid in server_type:
            continue
        if h.classification_source not in ("manual", "vpn_pool") and h.device_type is None:
            h.device_type = "ics_protocol_client_unclassified"
            if h.classification_source != "interface_label":     # SF-8a: the label's level stays
                h.classification_source = "protocol_client_hint"

    db.flush()  # keep changes visible to downstream mechanisms within the same tx

    # --- Host VLAN from the firewall / routing-switch VLAN interfaces (owner
    # 2026-10-12) - before the VLAN-name mechanisms so they can use it
    stats.update(assign_vlans_from_interfaces(db))

    # --- Firewall VLAN propagation ---
    # Runs between mechanisms 2 and 3: promotes SwitchVlan.purdue_level from
    # "keyword_inferred" to "firewall_propagated" wherever a firewall VLAN
    # sub-interface confirms the same level.  This means Mechanism 3 (below)
    # immediately benefits from the firmer evidence without needing a second
    # classify_hosts() call.
    resolve_vlan_topology(db)

    # --- Mechanism 3: VLAN-name inference ---
    # Downstream queries run within the same ambient transaction; db.flush()
    # inside each sub-function makes staged writes visible without committing.
    vlan_stats = classify_hosts_by_vlan(db)
    stats["vlan_inferred_applied"] = vlan_stats["vlan_inferred_applied"]

    # --- Mechanism 4: LLDP/CDP role inference ---
    # Populates Host.role (functional role) from neighbor-discovery data.
    # Runs last so Purdue-level classification (mechanisms 1-3) is stable
    # before role inference writes; the two fields are orthogonal and do
    # not conflict, but consistency is cleaner this way.
    lldp_stats = classify_hosts_by_lldp_role(db)
    stats["lldp_role_applied"] = lldp_stats["role_applied"]

    # --- Mechanism 4b: LLDP role → Purdue level promotion ---
    # After lldp_role writes Host.role, promote Host.purdue_level for hosts
    # that still have no Purdue level (or only a weak oui_hint level).
    # MAC-only hosts with CDP/LLDP-reported roles (e.g. role="plc") remain
    # at purdue_level=None without this step, making them invisible to the
    # zone topology and every check that filters by purdue_level.
    promotion_stats = promote_purdue_from_lldp_role(db)
    stats["lldp_purdue_promoted"] = promotion_stats["purdue_promoted"]

    # --- Mechanism 5 (RS G3): the operator's subnet zones - last, so a
    # declared level wins over every weak automatic guess above; protocol
    # roles and manual classifications keep theirs (mismatches are reported)
    from app.parsers import subnet_zones
    stats["subnet_zone"] = subnet_zones.apply(db)

    # Single commit for the entire classify_hosts() unit of work — all
    # mechanisms succeed or all roll back together (A8 atomicity fix).
    db.commit()

    return stats


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("classify_", "promote_", "resolve_"))
