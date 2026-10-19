"""
ARP table ingestion.

Parses ARP table dumps into (ip, mac) pairs and feeds them into the
shared Host model. ARP tables are the cheapest possible input - no
packet capture needed - so this is usually the first thing you'd run
against a new segment to get a baseline of what's out there.

Three formats are supported, auto-detected from the text:

  1. Cisco IOS  `show ip arp`
         Protocol  Address          Age (min)  Hardware Addr   Type   Interface
         Internet  10.0.1.1                -   0011.2233.4455  ARPA   Vlan10
         Internet  10.0.1.10              23   0022.3344.5566  ARPA   Vlan10

  2. Linux/Unix  `arp -a`
         ? (10.0.1.10) at 00:22:33:44:55:66 [ether] on eth0
         gateway (10.0.1.1) at 00:11:22:33:44:55 [ether] on eth0

  3. Windows  `arp -a`
         Interface: 10.0.1.5 --- 0x3
           Internet Address      Physical Address      Type
           10.0.1.1              00-11-22-33-44-55     dynamic

Add a new format by writing a `_parse_<name>(text) -> list[ArpEntry]`
function and registering it in `_PARSERS` below - `parse_arp_table`
handles detection and dispatch.
"""
import re
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy.orm import Session as DBSession

from app.sites import site_ingest
from app.models import Host, real_host_clause
from app.sites import scope_site_id
from app.parsers.common import get_or_create_host, is_group_mac  # noqa: F401  (re-exported for callers)
from app.parsers.host_identity import HostIdentityResolver, is_unicast_host_ip, observed_bindings

SOURCE_LABEL = "arp"


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: Optional[str] = None  # VLAN/interface name, when the format has one


# ------------------------------------------------------------- detection --

_CISCO_HEADER_RE = re.compile(r"Protocol\s+Address\s+Age", re.IGNORECASE)
_CISCO_ROW_RE = re.compile(
    r"^[ \t]*Internet\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(?P<iface>\S+)",
    re.MULTILINE,
)

_WINDOWS_HEADER_RE = re.compile(r"Internet Address\s+Physical Address", re.IGNORECASE)
_WINDOWS_ROW_RE = re.compile(
    r"^[ \t]*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})\s+\S+",
    re.MULTILINE,
)

_UNIX_ROW_RE = re.compile(
    r"^\S+\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
    r"(?P<mac>[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5})"
    r"(?:\s+\[\S+\])?(?:\s+on\s+(?P<iface>\S+))?",
    re.MULTILINE,
)


def _parse_cisco(text: str) -> list[ArpEntry]:
    return [
        ArpEntry(ip=m.group("ip"), mac=m.group("mac"), interface=m.group("iface"))
        for m in _CISCO_ROW_RE.finditer(text)
    ]


def _parse_windows(text: str) -> list[ArpEntry]:
    entries = []
    current_iface = None
    for line in text.splitlines():
        iface_match = re.match(r"\s*Interface:\s*(\S+)", line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue
        row_match = _WINDOWS_ROW_RE.match(line)
        if row_match:
            entries.append(
                ArpEntry(ip=row_match.group("ip"), mac=row_match.group("mac"), interface=current_iface)
            )
    return entries


def _parse_unix(text: str) -> list[ArpEntry]:
    return [
        ArpEntry(ip=m.group("ip"), mac=m.group("mac"), interface=m.group("iface"))
        for m in _UNIX_ROW_RE.finditer(text)
    ]


# Order matters: more specific/header-anchored formats first. Unix is the
# loosest pattern, so it's tried last to avoid false-matching other formats.
_PARSERS: list[tuple[Callable[[str], bool], Callable[[str], list]]] = [
    (lambda t: bool(_CISCO_HEADER_RE.search(t)) or bool(_CISCO_ROW_RE.search(t)), _parse_cisco),
    (lambda t: bool(_WINDOWS_HEADER_RE.search(t)) or bool(_WINDOWS_ROW_RE.search(t)), _parse_windows),
    (lambda t: bool(_UNIX_ROW_RE.search(t)), _parse_unix),
]


_FORMAT_HINT_PARSERS = {
    "cisco": _parse_cisco,
    "unix": _parse_unix,
    "windows": _parse_windows,
}


def parse_arp_table(text: str, format_hint: Optional[str] = None) -> list:
    """
    Parse the ARP table text. When `format_hint` ("cisco", "unix", or
    "windows") is given, goes straight to that format's parser rather
    than auto-detecting - the intended path once the UI has already
    asked which platform this dump came from. An unrecognized hint
    falls back to auto-detection.

    Auto-detection (no hint, or an unrecognized one) tries each
    registered parser's detector in order and uses the first one that
    both matches AND yields at least one entry, so a false-positive
    header match with zero rows falls through to the next candidate
    instead of returning an empty result.
    """
    if format_hint in _FORMAT_HINT_PARSERS:
        return _filter_entries(_FORMAT_HINT_PARSERS[format_hint](text))

    for detector, parser in _PARSERS:
        if detector(text):
            entries = _filter_entries(parser(text))
            if entries:
                return entries
    return []


def _filter_entries(entries: list) -> list:
    """AU full review E-M2: an ARP table lists multicast (224.0.0.x ->
    01:00:5e:..), the subnet broadcast (-> ff:ff:ff:ff:ff:ff) and the
    occasional "999.1.1.1"-shaped junk row; none of those is a host."""
    out = []
    for e in entries:
        if is_group_mac(e.mac) or not is_unicast_host_ip(e.ip):
            continue
        out.append(e)
    return out


# --------------------------------------------------------------- ingest --

@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_arp_table(
    text: str,
    db: DBSession,
    source_file: Optional[str] = None,
    format_hint: Optional[str] = None,
) -> dict:
    """
    Parse ARP table text and populate/update Host rows.

    Returns a stats dict: how many entries were found in the text, and
    how many distinct hosts exist afterward (new + previously known).
    """
    entries = parse_arp_table(text, format_hint=format_hint)
    stats = {
        "entries_found": len(entries), "hosts_created_or_updated": 0,
        "hosts_total": 0, "format_hint_used": format_hint,
    }

    if not entries:
        stats["hosts_total"] = db.query(Host).filter(Host.site_id == scope_site_id(db), real_host_clause()).count()
        return stats

    # F-09: one identity resolver for the whole dump - a known MAC that now
    # answers for a new IP (and no longer for its old one) is renumbered
    # rather than duplicated; a known IP with a new MAC is recorded as a
    # conflict; every binding lands in HostAddressHistory (source "arp").
    resolver = HostIdentityResolver(
        db, SOURCE_LABEL, observed=observed_bindings((e.ip, e.mac) for e in entries),
    )
    for entry in entries:
        if resolver.resolve(entry.ip, entry.mac) is not None:
            stats["hosts_created_or_updated"] += 1
    resolver.finish()
    for key in ("hosts_renumbered", "hosts_merged", "ip_conflicts",
                "address_changes", "ip_conflict_events"):
        stats[key] = resolver.stats[key]

    db.commit()
    stats["hosts_total"] = db.query(Host).filter(Host.site_id == resolver.site_id, real_host_clause()).count()
    return stats
