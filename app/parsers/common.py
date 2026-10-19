"""
Shared helpers used across ingest parsers.

Every parser (pcap, ARP, and eventually firewall/switch configs) needs
the same "find or create this host, and note which source told us about
it" logic. Keeping it in one place means a host discovered by ARP today
and confirmed by pcap tomorrow is recognized as the *same* host, with
both sources recorded, rather than silently duplicated.
"""
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

from sqlalchemy.orm import Session as DBSession

from app.models import Host
from app.parsers.oui_database import (
    MAC_KIND_UNIVERSAL, load_manuf_file, lookup_manuf, mac_kind,
)

_HEX_BYTE_RE = re.compile(r"^[0-9a-f]{1,2}$")

# Lazily-loaded custom manuf database (Grassmarlin/Wireshark format),
# used in preference to scapy's bundled conf.manufdb when configured -
# see oui_database.py for why this matters (Grassmarlin has no OUI data
# of its own; it's this exact file format from whatever Wireshark
# install it's paired with, potentially newer/more complete than what
# ships with scapy). Set IACS_MANUF_FILE to a manuf file's path to use it.
_manuf_db: Optional[dict] = None
_manuf_db_load_attempted = False


def _get_manuf_db() -> Optional[dict]:
    global _manuf_db, _manuf_db_load_attempted
    if _manuf_db_load_attempted:
        return _manuf_db
    _manuf_db_load_attempted = True

    path = os.environ.get("IACS_MANUF_FILE")
    if not path:
        return None
    try:
        _manuf_db = load_manuf_file(path)
    except Exception as exc:
        log.warning("Failed to load IACS_MANUF_FILE=%r: %s", path, exc)
        _manuf_db = None
    return _manuf_db


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """
    Normalize any of the common MAC notations to lowercase colon-separated
    form (aa:bb:cc:dd:ee:ff), so the same physical NIC is recognized
    regardless of which tool/vendor format it was read from:
      - Cisco dotted-quad:  0011.2233.4455        (3 groups of 4 hex chars)
      - Windows dashes:     00-11-22-33-44-55     (6 groups, zero-padded)
      - Unix colons:        00:11:22:33:44:55     (6 groups, zero-padded)
      - Unix colons, short: 0:11:22:33:44:55      (6 groups, NOT zero-padded -
        classic `arp -a`/`ip neigh` output drops leading zeros per octet,
        so a naive strip-and-concatenate misparses this as an 11-digit MAC)
      - HP/ProCurve spaced: 00 00 00 12 34 ab     (6 groups, space-separated -
        this is how HP's `show lldp info remote-device` prints chassis IDs)
      - HP/ProCurve MAC table: 001122-334455      (2 groups of 6 hex chars,
        single dash - this is the traditional ProCurve `show mac-address`
        display convention, distinct from the 6-group dash format above)
      - Bare:               001122334455          (12 hex digits, no separator)
    Returns None for anything else. This is THE helper every MAC entry
    point should call (ARP, MAC tables, LLDP/CDP chassis IDs, pcap, CSV).
    """
    if not mac:
        return None
    mac = mac.strip().lower()

    if len(mac) == 12 and all(c in "0123456789abcdef" for c in mac):
        # Bare 12-hex-digit form (001122334455): SNMP dumps, some CSVs.
        return ":".join(mac[i:i + 2] for i in range(0, 12, 2))

    if "." in mac and ":" not in mac and "-" not in mac and " " not in mac:
        # Cisco dotted-quad: three 4-hex-char groups, always zero-padded.
        hex_only = "".join(ch for ch in mac if ch in "0123456789abcdef")
        if len(hex_only) != 12:
            return None
        return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))

    if mac.count("-") == 1 and ":" not in mac and " " not in mac:
        # HP/ProCurve MAC-table style: two 6-hex-digit groups, one dash.
        # Checked before the generic 6-group splitter below, since this
        # pattern has exactly 2 parts, not 6, and would otherwise fall
        # through to "not a MAC we recognize".
        left, right = mac.split("-")
        if len(left) == 6 and len(right) == 6 and all(c in "0123456789abcdef" for c in left + right):
            combined = left + right
            return ":".join(combined[i:i + 2] for i in range(0, 12, 2))

    # Colon-, dash-, or whitespace-separated: six groups, each 1-2 hex
    # digits, that may or may not be zero-padded - pad each individually
    # rather than concatenating first.
    parts = re.split(r"[:\-\s]+", mac)
    if len(parts) != 6 or not all(_HEX_BYTE_RE.match(p) for p in parts):
        return None
    return ":".join(p.zfill(2) for p in parts)


def _scapy_vendor(mac: str) -> Optional[str]:
    """Vendor from scapy's bundled manuf table. (The previous
    ``conf.manufdb._resolve`` call does not exist on ManufDA: it fell
    through DADict.__getattr__'s full-table scan - ~80 ms per call - and
    always returned None.)"""
    oui = mac[:8].upper()
    hit = _scapy_oui_cache.get(oui, False)
    if hit is not False:
        return hit
    try:
        from scapy.all import conf
        couple = conf.manufdb.d.get(oui)  # type: ignore[attr-defined]
    except Exception:
        couple = None
    hit = None
    if couple:
        short, long_name = (couple + (None,))[:2] if isinstance(couple, tuple) else (couple, None)
        name = (long_name or short or "").strip().rstrip(",").strip()
        hit = name or None
    _scapy_oui_cache[oui] = hit
    return hit


_scapy_oui_cache: dict = {}


def lookup_vendor_info(mac: Optional[str]) -> dict:
    """
    {"vendor": str | None, "mac_kind": "universal" | "locally_administered"
    | "multicast" | None}  (F-16).

    Locally administered (randomised / virtual) and multicast MACs are not
    assigned from an IEEE OUI, so the vendor is always None for them - an
    OUI-table match on their first three octets would name an unrelated
    manufacturer.
    """
    norm = normalize_mac(mac)
    kind = mac_kind(norm)
    if kind != MAC_KIND_UNIVERSAL:
        return {"vendor": None, "mac_kind": kind}

    vendor = None
    manuf_db = _get_manuf_db()
    if manuf_db is not None:
        vendor = lookup_manuf(norm, manuf_db)
    if not vendor:
        vendor = _scapy_vendor(norm)
    return {"vendor": vendor, "mac_kind": kind}


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """
    OUI vendor lookup. Prefers a custom manuf-format database (set via
    the IACS_MANUF_FILE env var - e.g. pointed at a real Grassmarlin or
    Wireshark installation's manuf file) if configured, since that may
    be more current/complete than scapy's bundled copy; falls back to
    scapy's conf.manufdb otherwise. Both are ultimately IEEE/Wireshark-
    derived data - see oui_database.py for why there's no separate
    "Grassmarlin OUI database" distinct from Wireshark's own file.

    Returns None for locally administered / randomised and multicast MACs
    (see lookup_vendor_info for the reason, F-16).
    """
    if not mac:
        return None
    return lookup_vendor_info(mac)["vendor"]


def as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Return ``dt`` as a timezone-aware UTC datetime. Naive values (which is
    what SQLite hands back for DateTime columns without timezone=True) are
    interpreted as UTC, the convention every writer in this code base uses.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def touch_host_times(host: Host, seen_at: datetime) -> None:
    """Widen host.first_seen/last_seen so they cover ``seen_at``."""
    seen_at = as_utc(seen_at)
    first = as_utc(host.first_seen)
    last = as_utc(host.last_seen)
    if first is None or seen_at < first:
        host.first_seen = seen_at
    if last is None or seen_at > last:
        host.last_seen = seen_at


def is_group_mac(mac: Optional[str]) -> bool:
    """True for broadcast/multicast MACs (I/G bit of the first octet set)."""
    if not mac:
        return False
    try:
        return bool(int(mac[0:2], 16) & 0x01)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Router / gateway MAC detection (T3-29)
# ---------------------------------------------------------------------------
# In a capture taken on a routed segment, every off-subnet IP arrives with
# the *gateway's* MAC in the Ethernet header. Naively pairing (ip, mac) from
# each frame gives every remote host the router's MAC and vendor. A MAC is
# classified as a gateway when, over the whole capture, it is seen carrying
#   - more than GATEWAY_MAX_IPS distinct unicast IPv4 addresses, or
#   - any IPv4 address outside the /GATEWAY_LOCAL_PREFIX subnet of its
#     reference IP (the lowest IP it claimed in ARP, else the first IP seen
#     with it in capture order) - A-22: at least GATEWAY_MIN_OFFSUBNET
#     distinct off-subnet IPs are required, so ONE spoofed off-subnet source
#     address can no longer turn an ordinary host's MAC into a "gateway"
#     (which would re-attribute every remote host to it). Trade-off: a
#     router that forwards traffic for a single remote host only is not
#     detected (that remote host is then paired with the router MAC, the
#     pre-T3-29 behaviour). IPv6 Router Advertisements remain direct router
#     evidence (detect_gateway_macs_v6).
# Membership tests use sets (A-22: the list-based dedup was quadratic).
# The decision is made from the full capture before any Host row is touched
# so it does not depend on which packet happened to come first.
GATEWAY_MAX_IPS = 8
GATEWAY_LOCAL_PREFIX = 24
#: A-22: distinct off-subnet unicast IPs needed before a MAC is a gateway.
GATEWAY_MIN_OFFSUBNET = 2


def _usable_unicast_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"))


def detect_gateway_macs(
    mac_ips: dict,
    mac_own_ips: Optional[dict] = None,
    max_ips: int = GATEWAY_MAX_IPS,
    local_prefix: int = GATEWAY_LOCAL_PREFIX,
    min_offsubnet: int = GATEWAY_MIN_OFFSUBNET,
) -> set:
    """
    Classify MACs that behave like routers.

    Args:
        mac_ips: {mac: iterable of IPs seen with that MAC, in capture order}
            (a list or an insertion-ordered dict; sets are sorted first so
            the result stays deterministic).
        mac_own_ips: {mac: IPs the MAC itself claimed via ARP}. Optional.

    Returns the set of normalized MACs considered gateways. Broadcast/
    multicast MACs are never gateways.
    """
    mac_own_ips = mac_own_ips or {}
    gateways: set = set()
    for raw_mac, ips in mac_ips.items():
        mac = normalize_mac(raw_mac)
        if not mac or is_group_mac(mac):
            continue
        ordered = sorted(ips) if isinstance(ips, (set, frozenset)) else list(ips)
        seen: list = []
        seen_set: set = set()
        for ip in ordered:
            if ip not in seen_set and _usable_unicast_ipv4(ip):
                seen_set.add(ip)
                seen.append(ip)
        if len(seen) < 2:
            continue
        if len(seen) > max_ips:
            gateways.add(mac)
            continue
        own = sorted(ip for ip in mac_own_ips.get(raw_mac, ()) if _usable_unicast_ipv4(ip))
        ref = own[0] if own else seen[0]
        local = ipaddress.IPv4Network(f"{ref}/{local_prefix}", strict=False)
        # IO-01: an address the MAC claimed itself (ARP) is its own, wherever
        # it lies - a multi-homed host on a flat network is not a router; a
        # router betrays itself by carrying addresses it does not own
        own_set = set(own)
        off = 0
        for ip in seen:
            if ip in own_set:
                continue
            if ipaddress.IPv4Address(ip) not in local:
                off += 1
                if off >= min_offsubnet:
                    break
        if off >= min_offsubnet:
            gateways.add(mac)
    return gateways


GATEWAY_LOCAL_PREFIX_V6 = 64


def _usable_unicast_ipv6(ip: str) -> bool:
    """Global / unique-local IPv6 unicast (link-local is never routed, so it
    can't betray a router and is ignored for gateway detection)."""
    try:
        addr = ipaddress.IPv6Address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr.is_link_local
                or addr.is_loopback)


def detect_gateway_macs_v6(
    mac_ips: dict,
    mac_own_ips: Optional[dict] = None,
    router_macs: Optional[set] = None,
    max_ips: int = GATEWAY_MAX_IPS,
    local_prefix: int = GATEWAY_LOCAL_PREFIX_V6,
    min_offsubnet: int = GATEWAY_MIN_OFFSUBNET,
) -> set:
    """
    IPv6 counterpart of detect_gateway_macs (F-07). A MAC is a gateway when
    it sent a Router Advertisement (``router_macs``), or carries more than
    ``max_ips`` distinct global/ULA addresses, or any such address outside
    the /``local_prefix`` of its reference address (lowest own address
    learned from NDP, else the first seen). IPv4 addresses in the inputs
    are ignored.
    """
    mac_own_ips = mac_own_ips or {}
    gateways: set = set()
    for raw in router_macs or ():
        mac = normalize_mac(raw)
        if mac and not is_group_mac(mac):
            gateways.add(mac)
    for raw_mac, ips in mac_ips.items():
        mac = normalize_mac(raw_mac)
        if not mac or is_group_mac(mac) or mac in gateways:
            continue
        ordered = sorted(ips) if isinstance(ips, (set, frozenset)) else list(ips)
        seen: list = []
        seen_set: set = set()
        for ip in ordered:
            if ip not in seen_set and _usable_unicast_ipv6(ip):
                seen_set.add(ip)
                seen.append(ip)
        if len(seen) < 2:
            continue
        if len(seen) > max_ips:
            gateways.add(mac)
            continue
        own = sorted(ip for ip in mac_own_ips.get(raw_mac, ()) if _usable_unicast_ipv6(ip))
        ref = own[0] if own else seen[0]
        local = ipaddress.IPv6Network(f"{ref}/{local_prefix}", strict=False)
        off = 0
        for ip in seen:
            if ipaddress.IPv6Address(ip) not in local:
                off += 1
                if off >= min_offsubnet:
                    break
        if off >= min_offsubnet:
            gateways.add(mac)
    return gateways


def get_or_create_host(
    db: DBSession,
    ip: Optional[str],
    mac: Optional[str],
    source: str,
    seen_at: Optional[datetime] = None,
    site_id: Optional[int] = None,
) -> Optional[Host]:
    """
    Find an existing Host by (mac, ip), or create one. Always normalizes
    the MAC first so the same NIC matches across ingest sources that use
    different notations. Appends `source` to Host.sources if not already
    present, and widens first_seen/last_seen to cover ``seen_at`` (the
    observation time - e.g. the packet timestamp; defaults to now).

    Matching / merge rules (T3-29) - never creates a row that would collide
    with uq_host_mac_ip, ix_host_ip_only or ix_host_mac_only:
      ip + mac:
        1. exact (mac, ip) row
        2. an IP-only row for this ip  -> the MAC is attached to it
        3. a MAC-only row for this mac -> the IP is attached to it
        4. otherwise a new (ip, mac) row
      ip only:
        1. the IP-only row for this ip
        2. exactly one row with this ip (any MAC) -> that row
        3. otherwise a new IP-only row
      mac only:
        1. the MAC-only row for this mac
        2. a row with this mac (any IP; the most recently seen when several)
        3. otherwise a new MAC-only row

    Only flushes (never commits) so callers control the transaction.

    Returns None (without inserting) when both ip and mac are None — a
    host with no identity cannot be matched to anything and an unbounded
    number of zero-identity rows would otherwise accumulate.
    """
    mac = normalize_mac(mac)
    ip = ip or None

    # Reject no-identity rows up front
    if not ip and not mac:
        log.warning("get_or_create_host called with both ip=None and mac=None (source=%r); skipped", source)
        return None

    # Phase 2 (multi-site): identity is per site - only rows of the upload's
    # site (explicit site_id, else the bound ingest site, else Default) match.
    from app.sites import scope_site_id
    sid = scope_site_id(db, site_id)
    host = match_host(db, ip, mac, sid)

    seen_at = as_utc(seen_at) if seen_at is not None else datetime.now(timezone.utc)
    if host:
        return refresh_host(host, ip, mac, source, seen_at)

    return create_host_row(db, ip, mac, source, seen_at, sid)


def match_host(db: DBSession, ip: Optional[str], mac: Optional[str],
               site_id: int) -> Optional[Host]:
    """The matching rules of get_or_create_host (``mac`` normalized,
    ``site_id`` resolved): the existing Host of the site the observation
    belongs to, or None."""
    query = db.query(Host).filter(Host.site_id == site_id)
    host = None
    if mac and ip:
        host = query.filter(Host.mac == mac, Host.ip == ip).first()
        if host is None:
            host = query.filter(Host.ip == ip, Host.mac.is_(None)).first()
        if host is None:
            host = query.filter(Host.mac == mac, Host.ip.is_(None)).first()
    elif ip:
        host = query.filter(Host.ip == ip, Host.mac.is_(None)).first()
        if host is None:
            candidates = query.filter(Host.ip == ip).order_by(Host.id).limit(2).all()
            if len(candidates) == 1:
                host = candidates[0]
    elif mac:
        host = query.filter(Host.mac == mac, Host.ip.is_(None)).first()
        if host is None:
            # F-01: when several rows carry this MAC (multi-homed NIC, router
            # MAC, or sources that disagree) use the most recently seen one.
            # Creating a MAC-only row here added a phantom Host (and an
            # unknown_device finding) the first time a MAC table was
            # RE-uploaded, so the ingest was not idempotent.
            host = (query.filter(Host.mac == mac)
                    .order_by(Host.last_seen.desc().nulls_last(), Host.id.desc()).first())
    return host


def refresh_host(host: Host, ip: Optional[str], mac: Optional[str], source: str,
                 seen_at: datetime) -> Host:
    """Update an existing Host matched by get_or_create_host (``mac``
    normalized, ``seen_at`` aware): widen its times, un-stale it, record
    ``source`` and fill in a missing ip / mac."""
    touch_host_times(host, seen_at)
    if host.stale:
        host.stale = False      # F-09: any ingest that sees a host un-stales it
    if source not in (host.sources or []):
        host.sources = list(host.sources or []) + [source]
    # An IP-only host (config/ARP) later confirmed with a MAC via pcap
    # (or a MAC-only host later seen with an IP) - fill in whichever
    # field was missing rather than creating a duplicate row.
    if mac and not host.mac:
        host.mac = mac
        if not host.vendor:
            host.vendor = lookup_vendor(mac)
    if ip and not host.ip:
        host.ip = ip
    return host


def create_host_row(db: DBSession, ip: Optional[str], mac: Optional[str], source: str,
                    seen_at: datetime, site_id: int) -> Host:
    """Insert a new Host (``mac`` already normalized, ``site_id`` resolved).

    The tail of get_or_create_host, shared with callers that already KNOW
    no row in the site has this ip or mac (B-08: the pcap ingest keeps the
    site's ip/mac sets in memory and skips the three lookup queries).
    Race-safe: see insert_host_row (returns the concurrently inserted row,
    refreshed, when another transaction got there first)."""
    return insert_host_row(db, ip, mac, source, seen_at, site_id)[0]


#: Attempts of insert_host_row's insert / re-select loop (the conflicting
#: row can vanish between the two when its transaction is rolled back or it
#: is merged away; each attempt is one INSERT plus at most one lookup).
_HOST_INSERT_ATTEMPTS = 5


_HOST_INSERT_STMTS: dict = {}


def _host_insert_stmt(db: DBSession):
    """Core ``INSERT INTO hosts ... ON CONFLICT DO NOTHING RETURNING <all
    columns>`` for PostgreSQL and SQLite (>= 3.35), built once per dialect
    (a Core statement: the ORM bulk-INSERT path costs ~4x more per row);
    None on other dialects."""
    name = db.get_bind().dialect.name
    stmt = _HOST_INSERT_STMTS.get(name)
    if stmt is None:
        if name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        elif name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as dialect_insert
        else:  # pragma: no cover - only SQLite and PostgreSQL are supported
            return None
        table = Host.__table__
        stmt = _HOST_INSERT_STMTS[name] = (
            dialect_insert(table).on_conflict_do_nothing().returning(*table.c))
    return stmt


def _host_from_row(db: DBSession, row) -> Host:
    """A persistent Host for a just-inserted row (every column loaded, so
    no further SELECT), as if it had been flushed by the ORM."""
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.orm import make_transient_to_detached
    m = row._mapping
    host = Host(**{prop.key: m[prop.columns[0]]
                   for prop in sa_inspect(Host).column_attrs})
    make_transient_to_detached(host)
    db.add(host)
    return host


def insert_host_row(db: DBSession, ip: Optional[str], mac: Optional[str], source: str,
                    seen_at: datetime, site_id: int) -> tuple[Host, bool]:
    """Insert a new Host -> (host, created).

    B-08 follow-up: callers decide to insert from a lookup (or an in-memory
    set) that can be stale by the time the INSERT runs - a concurrent ingest
    of the same site may have inserted the same identity meanwhile, which
    used to fail the whole ingest with an IntegrityError on PostgreSQL
    (ux_hosts_site_mac_ip / ux_hosts_site_ip_only / ux_hosts_site_mac_only).
    The insert is therefore ``ON CONFLICT DO NOTHING``: on PostgreSQL it
    waits for the competing transaction and inserts nothing if that one
    committed.  Then the existing row is re-selected with the full
    get_or_create_host matching rules (match_host - so an IP-only row
    gets the MAC attached etc., the identity rules are not bypassed),
    refreshed and returned with created=False.  Costs nothing extra when
    there is no conflict (one INSERT ... RETURNING, as the ORM flush did)
    and needs no SAVEPOINT (on pysqlite a SAVEPOINT opening the
    transaction would COMMIT on release)."""
    values = dict(site_id=site_id, ip=ip, mac=mac, vendor=lookup_vendor(mac),
                  first_seen=seen_at, last_seen=seen_at, sources=[source], stale=False)
    # Pending changes (e.g. a MAC just attached to an IP-only row by
    # refresh_host) must reach the database before ON CONFLICT checks it,
    # as the old ORM flush of the new row also flushed them.
    db.flush()
    stmt = _host_insert_stmt(db)
    if stmt is None:  # pragma: no cover
        return _insert_host_savepoint(db, ip, mac, source, seen_at, site_id, values)
    for _ in range(_HOST_INSERT_ATTEMPTS):
        row = db.execute(stmt, values).first()
        if row is not None:
            return _host_from_row(db, row), True
        existing = match_host(db, ip, mac, site_id)
        if existing is not None:
            log.info("insert_host_row: host ip=%s mac=%s (site %s) was inserted "
                     "concurrently - using the existing row %s", ip, mac, site_id, existing.id)
            return refresh_host(existing, ip, mac, source, seen_at), False
    raise RuntimeError(f"insert_host_row: could not insert or find host ip={ip} mac={mac}")


def _insert_host_savepoint(db, ip, mac, source, seen_at, site_id, values):  # pragma: no cover
    """Fallback for dialects without ON CONFLICT: SAVEPOINT + re-select."""
    from sqlalchemy.exc import IntegrityError
    host = Host(**values)
    try:
        with db.begin_nested():
            db.add(host)
    except IntegrityError:
        existing = match_host(db, ip, mac, site_id)
        if existing is None:
            raise
        return refresh_host(existing, ip, mac, source, seen_at), False
    return host, True


def name_has_keyword(name: Optional[str], keywords) -> bool:
    """Whole-token keyword test for zone / interface names (F-01).

    ``name`` is split into alphabetic and numeric runs ("OT_LAN-2" ->
    ot, lan, 2; "dmz1" -> dmz, 1). A token matches keyword ``k`` when it
    equals ``k`` or ``k + "s"``, or - for keywords of 4+ letters - starts
    with ``k`` ("controller", "jumphost", "users"). Plain substring tests
    misfire on short keywords: "ot" in "remote", "it" in "unit1",
    "rtu" in "portugal".
    """
    tokens = re.findall(r"[a-z]+|[0-9]+", (name or "").lower())
    return any(
        t == k or t == k + "s" or (len(k) >= 4 and t.startswith(k))
        for t in tokens for k in keywords
    )


# ---------------------------------------------------------------------------
# B-08: resource limits shared by the ingest parsers
# ---------------------------------------------------------------------------
# All limits are read from the environment at CALL time (not import time) so
# an operator change takes effect on restart and tests can monkeypatch them.
# Invalid / out-of-range values fall back to the default with a warning.

def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw.strip().replace("_", ""))
    except ValueError:
        log.warning("%s=%r is not an integer; using default %d", name, raw, default)
        return default
    if val < minimum:
        log.warning("%s=%r is below %d; using default %d", name, raw, minimum, default)
        return default
    return val


def env_float(name: str, default: float, minimum: float = 0.001) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = float(raw.strip())
    except ValueError:
        log.warning("%s=%r is not a number; using default %s", name, raw, default)
        return default
    if not val >= minimum:      # also rejects NaN
        log.warning("%s=%r is below %s; using default %s", name, raw, minimum, default)
        return default
    return val


class IngestLimitExceeded(Exception):
    """An ingest would exceed a hard resource limit (B-08).

    Raised BEFORE the offending data is materialised; the caller must roll
    back so nothing from the upload is stored.  The API maps it to HTTP 413
    with ``str(exc)`` as the detail (it names the limit and its env var)."""

    status_code = 413

    def __init__(self, what: str, observed: int, limit: int, env_var: str):
        self.what, self.observed, self.limit, self.env_var = what, observed, limit, env_var
        super().__init__(
            f"{what} exceeds the limit of {limit:,} ({env_var}; at least {observed:,} "
            f"needed) - the upload was rejected and nothing was stored. Split the "
            f"config, use smaller object groups, or raise {env_var}.")


# --- firewall rule rows: one budget per config ingest, all vendors --------
DEFAULT_MAX_RULE_ROWS_PER_INGEST = 100_000
RULE_ROWS_ENV = "IACS_MAX_RULE_ROWS_PER_INGEST"


def max_rule_rows_per_ingest() -> int:
    return env_int(RULE_ROWS_ENV, DEFAULT_MAX_RULE_ROWS_PER_INGEST)


class RuleRowBudget:
    """Running total of FirewallRule rows one config ingest will create.

    Parsers charge the (post per-rule cap) src x dst x service product of a
    rule BEFORE building its rows, so an over-budget config is rejected
    without ever materialising the cartesian product."""

    def __init__(self, limit: Optional[int] = None):
        self.limit = max_rule_rows_per_ingest() if limit is None else limit
        self.used = 0

    def charge(self, n: int, label: str = "") -> None:
        self.used += max(int(n), 0)
        if self.used > self.limit:
            log.warning("config ingest rejected: %d firewall rule rows > %s=%d (at %s)",
                        self.used, RULE_ROWS_ENV, self.limit, label or "?")
            raise IngestLimitExceeded("Firewall rule expansion (rows across all policies)",
                                      self.used, self.limit, RULE_ROWS_ENV)


from contextlib import contextmanager  # noqa: E402
from contextvars import ContextVar  # noqa: E402

_RULE_BUDGET: "ContextVar[Optional[RuleRowBudget]]" = ContextVar("iasc_rule_budget", default=None)


@contextmanager
def rule_row_budget(limit: Optional[int] = None):
    """Open a per-ingest rule-row budget (nested calls share the outer one)."""
    cur = _RULE_BUDGET.get()
    if cur is not None:
        yield cur
        return
    budget = RuleRowBudget(limit)
    token = _RULE_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _RULE_BUDGET.reset(token)


def charge_rule_rows(n: int, label: str = "") -> None:
    """Charge ``n`` rows to the active budget (no-op outside an ingest)."""
    budget = _RULE_BUDGET.get()
    if budget is not None:
        budget.charge(n, label)


# --- upload content sniffing ---------------------------------------------
_COMPRESSED_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x5d\x00\x00", "lzma"),
)


def compressed_format(head: bytes) -> Optional[str]:
    """Name of the compression/archive format ``head`` starts with, else None."""
    head = bytes(head[:8])
    for magic, name in _COMPRESSED_MAGIC:
        if head.startswith(magic):
            return name
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[3:4] != b"0":
        return "bzip2"
    return None


_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap", b"\xa1\xb2\xc3\xd4": "pcap",      # usec
    b"\x4d\x3c\xb2\xa1": "pcap", b"\xa1\xb2\x3c\x4d": "pcap",      # nsec
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def capture_format(head: bytes) -> Optional[str]:
    """"pcap" / "pcapng" when ``head`` carries an uncompressed capture magic."""
    return _PCAP_MAGIC.get(bytes(head[:4]))
