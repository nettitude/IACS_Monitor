"""
MAC address table ingestion - the bridge between switch-config VLAN
data and host identity.

Everything ingested so far knows either "this port is on VLAN 10"
(switch_parser.py) or "this MAC/IP is a host" (pcap_parser.py,
arp_parser.py) - but nothing connects the two. A MAC address table
(`show mac address-table` on Cisco, `show mac-address` on HP/ProCurve)
is exactly that connection: it's the switch's own record of which MAC
it learned on which port, which is also frequently annotated with the
VLAN directly.

Two formats are supported, auto-detected (or hinted via vendor_hint,
matching the pattern used by firewall_parser.py and switch_parser.py):

  1. Cisco IOS `show mac address-table`:
         Vlan    Mac Address       Type        Ports
         ----    -----------       --------    -----
           10    0011.2233.4455    DYNAMIC     Gi1/0/1
           20    aabb.ccdd.eeff    DYNAMIC     Gi1/0/2

  2. HP/ProCurve `show mac-address`:
         MAC Address   Located on Port  VLAN
         -------------  ---------------  ----
         001122-334455        1           10
         aabbcc-ddeeff        5           20

CONFIDENCE NOTE: Cisco's column layout above is very widely and
consistently documented and is implemented with confidence. HP's exact
column arrangement and header wording vary somewhat more across
ProCurve/Aruba firmware versions than Cisco's does across IOS versions -
the parser matches on the MAC/port/VLAN values themselves rather than
exact header text, which should be robust to minor header wording
differences, but if a real capture doesn't parse, check the header
regex against your actual device's output first.
"""
import re
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.sites import site_ingest
from app.models import Host, MacTableEntry, SwitchInterface, SwitchVlan
from app.parsers.common import is_group_mac, normalize_mac, get_or_create_host  # noqa: F401
from app.parsers.host_identity import HostIdentityResolver
from app.parsers.switch_parser import VendorMismatchError

_CISCO_ROW_RE = re.compile(
    r"^[ \t]*(?P<vlan>\d+|All)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<port>\S+)[ \t\r]*$",
    re.MULTILINE,  # ^/$ per line: detect_mac_table_type() uses .search on the whole dump
)

_HP_ROW_RE = re.compile(
    r"^[ \t]*(?P<mac>[0-9a-fA-F]{6}-[0-9a-fA-F]{6})\s+"
    r"(?P<port>\S+)\s+"
    r"(?P<vlan>\d+)[ \t\r]*$",
    re.MULTILINE,  # ^/$ per line: detect_mac_table_type() uses .search on the whole dump
)


# B-14c: switch-internal "ports" - rows learned on these are the switch's
# own / system entries (e.g. "All 0100.0ccc.cccc STATIC CPU"), not a host.
_SYSTEM_PORTS = frozenset({"cpu", "router", "switch", "drop", "self", "sup-eth1",
                           "sup-eth2", "vpc peer-link"})


def _is_system_row(mac: str, port: str, entry_type: Optional[str] = None) -> bool:
    """B-14c: group (I/G bit) MACs - broadcast, multicast, CDP/STP
    01:00:0c:cc:cc:cc ... - and CPU / system rows are never host entries."""
    if is_group_mac(mac):
        return True
    p = (port or "").strip().lower()
    if p in _SYSTEM_PORTS or p.startswith("cpu"):
        return True
    return (entry_type or "").strip().lower() in ("system", "self")


def parse_cisco_mac_table(text: str) -> list:
    """Parse Cisco `show mac address-table` output into entries (group MACs
    and CPU/system rows skipped - B-14c)."""
    entries = []
    for line in text.splitlines():
        match = _CISCO_ROW_RE.match(line)
        if not match:
            continue
        vlan = match.group("vlan")
        if vlan.lower() == "all":
            continue  # "All" VLAN rows are typically multicast/system entries, not a real host
        mac = normalize_mac(match.group("mac"))
        if not mac:
            continue
        if _is_system_row(mac, match.group("port"), match.group("type")):
            continue
        entries.append({"mac": mac, "port_name": match.group("port"), "vlan": vlan})
    return entries


def parse_hp_mac_table(text: str) -> list:
    """Parse HP/ProCurve `show mac-address` output into entries."""
    entries = []
    for line in text.splitlines():
        match = _HP_ROW_RE.match(line)
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if not mac:
            continue
        if _is_system_row(mac, match.group("port")):
            continue
        entries.append({"mac": mac, "port_name": match.group("port"), "vlan": match.group("vlan")})
    return entries


def detect_mac_table_type(text: str, vendor_hint: Optional[str] = None) -> str:
    """
    Returns "cisco_mac_table", "hp_mac_table", or "unknown". `vendor_hint`
    ("cisco" or "hp") skips detection and goes straight to that vendor's
    parser - same pattern as firewall_parser.py/switch_parser.py.
    """
    vendor_hint = (vendor_hint or "").strip().lower() or None
    if vendor_hint == "cisco":
        return "cisco_mac_table" if _CISCO_ROW_RE.search(text) else "unknown"
    if vendor_hint == "hp":
        return "hp_mac_table" if _HP_ROW_RE.search(text) else "unknown"

    if _CISCO_ROW_RE.search(text):
        return "cisco_mac_table"
    if _HP_ROW_RE.search(text):
        return "hp_mac_table"
    return "unknown"


def check_mac_vendor_hint(text: str, vendor_hint: Optional[str]) -> None:
    """Raise VendorMismatchError when the hint names one vendor but only the
    other vendor's MAC-table rows are present."""
    vendor_hint = (vendor_hint or "").strip().lower()
    if vendor_hint not in ("cisco", "hp"):
        return
    cisco, hp = bool(_CISCO_ROW_RE.search(text)), bool(_HP_ROW_RE.search(text))
    if vendor_hint == "cisco" and hp and not cisco:
        raise VendorMismatchError("cisco", "hp")
    if vendor_hint == "hp" and cisco and not hp:
        raise VendorMismatchError("hp", "cisco")


def _lookup_vlan_name(db: DBSession, device_name: Optional[str], port_name: str, vlan: str) -> Optional[str]:
    """
    Look up a VLAN name given the context of a MAC table entry (device,
    port, vlan_id).  Tried in priority order:

    1. SwitchVlan table: first-class VLAN objects from `show vlan brief`
       or running-config VLAN blocks.  Keyed on (device_name, vlan_id) -
       this is the correct join for MAC-table data because the MAC table
       carries the VLAN id directly, not a port that might be a trunk.
       Scoped to device_name when available; widens to any device when not
       (same-id VLANs are almost always named identically across devices in
       a site).

    2. SwitchInterface fallback: legacy rows from configs ingested before
       SwitchVlan rows existed.  Access ports only (trunk ports have
       vlan_name=None on purpose).
    """
    try:
        vlan_id_int = int(vlan)
    except (ValueError, TypeError):
        vlan_id_int = None

    from app.sites import scope_site_id
    sid = scope_site_id(db)  # phase 2: switch data of the upload's site only
    if vlan_id_int is not None:
        sv_query = db.query(SwitchVlan).filter(
            SwitchVlan.site_id == sid,
            SwitchVlan.vlan_id == vlan_id_int,
            SwitchVlan.vlan_name.isnot(None),
        )
        if device_name:
            sv_scoped = sv_query.filter(SwitchVlan.device_name == device_name).first()
            if sv_scoped:
                return sv_scoped.vlan_name
        sv_any = sv_query.first()
        if sv_any:
            return sv_any.vlan_name

    # Fallback: SwitchInterface (access ports, pre-SwitchVlan legacy data)
    iface_query = db.query(SwitchInterface).filter(
        SwitchInterface.site_id == sid,
        SwitchInterface.port_name == port_name,
        SwitchInterface.vlan_name.isnot(None),
    )
    if device_name:
        iface_query = iface_query.filter(SwitchInterface.device_name == device_name)
    iface = iface_query.first()
    return iface.vlan_name if iface else None


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_mac_table(
    text: str,
    db: DBSession,
    device_name: Optional[str] = None,
    source_file: Optional[str] = None,
    vendor_hint: Optional[str] = None,
) -> dict:
    """
    Parse a MAC address table and:
      1. Persist each row as a MacTableEntry (audit trail).
      2. Link to (or create) the Host with that MAC, setting Host.vlan
         with vlan_source="mac_table" - authoritative, overwrites a
         prior "subnet_inference" value but never "manual".
    """
    check_mac_vendor_hint(text, vendor_hint)  # N-24: reject, don't return "unknown"
    table_type = detect_mac_table_type(text, vendor_hint=vendor_hint)
    stats = {"table_type": table_type, "entries_found": 0, "hosts_linked": 0}

    if table_type == "cisco_mac_table":
        entries = parse_cisco_mac_table(text)
    elif table_type == "hp_mac_table":
        entries = parse_hp_mac_table(text)
    else:
        return stats

    stats["entries_found"] = len(entries)
    # F-09: MAC-only observations go through the shared identity resolver so
    # they un-stale hosts and land in HostAddressHistory (source "mac_table").
    resolver = HostIdentityResolver(db, "mac_table")
    # N-24: resolve VLAN ids to names from THIS site's switch_vlans (site is
    # bound by @site_ingest). MacTableEntry has no name column (no schema
    # change), so names are reported in the ingest stats.
    vlan_names: dict = {}
    for entry in entries:
        key = entry["vlan"]
        if key not in vlan_names:
            vlan_names[key] = _lookup_vlan_name(db, device_name, entry["port_name"], key)
    stats["vlan_names"] = {k: v for k, v in vlan_names.items() if v}
    stats["entries"] = [dict(e, vlan_name=vlan_names.get(e["vlan"])) for e in entries]

    # B-14c: one MacTableEntry per (site, device, mac, vlan, port) - a
    # re-ingest (or a repeated line) updates the existing row instead of
    # inserting a duplicate.
    existing: dict = {}
    q = db.query(MacTableEntry).filter(MacTableEntry.site_id == resolver.site_id)
    q = (q.filter(MacTableEntry.device_name == device_name) if device_name is not None
         else q.filter(MacTableEntry.device_name.is_(None)))
    for row in q.all():
        existing.setdefault((row.mac, row.vlan, row.port_name), row)
    stats["entries_inserted"] = stats["entries_updated"] = 0
    # LS-06: a MAC learned in several VLANs is a trunk peer (a firewall /
    # router with sub-interfaces), not a host of one VLAN.
    mac_vlans: dict = {}
    for entry in entries:
        mac_vlans.setdefault(entry["mac"], set()).add(entry["vlan"])
    multi_vlan = {m for m, v in mac_vlans.items() if len(v) > 1}
    stats["multi_vlan_macs"] = sorted(multi_vlan)
    for entry in entries:
        key = (entry["mac"], entry["vlan"], entry["port_name"])
        row = existing.get(key)
        if row is not None:
            if source_file:
                row.source_file = source_file
            stats["entries_updated"] += 1
        else:
            row = existing[key] = MacTableEntry(
                site_id=resolver.site_id,
                device_name=device_name,
                port_name=entry["port_name"],
                mac=entry["mac"],
                vlan=entry["vlan"],
                source_file=source_file,
            )
            db.add(row)
            stats["entries_inserted"] += 1

        host = resolver.resolve(None, entry["mac"])
        if host is None:
            continue
        if entry["mac"] in multi_vlan:
            if host.vlan_source == "mac_table":
                host.vlan, host.vlan_source = None, None
                if host.classification_source == "vlan_inferred":
                    host.purdue_level, host.classification_source = None, None
                    if host.device_type == "vlan_inferred":
                        host.device_type = None
            continue
        if host.vlan_source != "manual":
            host.vlan = entry["vlan"]
            host.vlan_source = "mac_table"
            stats["hosts_linked"] += 1

    resolver.finish()
    db.commit()
    return stats


def infer_vlan_by_subnet(db: DBSession, min_subnet_agreement: float = 0.8,
                         site_id: Optional[int] = None) -> dict:
    """
    Fallback for hosts with no MAC address-table data at all: derive a
    /24-subnet -> VLAN association from hosts that already have a
    confidently-known VLAN (vlan_source="mac_table"), then apply that
    VLAN to other hosts on the same subnet that have no VLAN of their
    own yet.

    This is explicitly lower-confidence than a real MAC-table lookup -
    it assumes VLANs are subnetted along clean /24 boundaries, which is
    common but not universal, and that IP address alone is a reliable
    proxy for VLAN membership (true on a typical flat-per-VLAN-subnet
    design, false if VLANs share a supernet or use inter-VLAN routing
    tricks). `min_subnet_agreement` requires that fraction of a
    subnet's *known* hosts to agree on one VLAN before it's used to
    infer anything - a subnet with mixed/disputed VLAN evidence is left
    alone rather than guessed at.

    Never touches a host whose vlan_source is already "mac_table" or
    "manual".
    """
    stats = {"subnets_used": 0, "hosts_inferred": 0}
    # Multi-site: votes are keyed by (site_id, subnet) so evidence from one
    # site never labels hosts of another (sites routinely reuse addressing).
    scope = [Host.site_id == site_id] if site_id is not None else []

    known_hosts = db.query(Host).filter(*scope, Host.vlan_source == "mac_table",
                                        Host.ip.isnot(None)).all()
    subnet_votes: dict = {}
    for host in known_hosts:
        subnet = (host.site_id, ".".join(host.ip.split(".")[:3]))  # naive /24 - see docstring
        subnet_votes.setdefault(subnet, {}).setdefault(host.vlan, 0)
        subnet_votes[subnet][host.vlan] += 1

    subnet_to_vlan = {}
    for subnet, votes in subnet_votes.items():
        total = sum(votes.values())
        best_vlan, best_count = max(votes.items(), key=lambda kv: kv[1])
        if best_count / total >= min_subnet_agreement:
            subnet_to_vlan[subnet] = best_vlan

    stats["subnets_used"] = len(subnet_to_vlan)

    candidates = db.query(Host).filter(
        *scope,
        Host.ip.isnot(None),
        Host.vlan_source.is_(None),
    ).all()
    for host in candidates:
        subnet = (host.site_id, ".".join(host.ip.split(".")[:3]))
        if subnet in subnet_to_vlan:
            host.vlan = subnet_to_vlan[subnet]
            host.vlan_source = "subnet_inference"
            stats["hosts_inferred"] += 1

    db.commit()
    return stats
