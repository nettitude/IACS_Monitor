"""
Host identity across ingests (F-09).

A Host row is keyed by (ip, mac) - see common.get_or_create_host for the
per-observation matching rules and the partial unique indexes they respect.
That alone cannot follow a device whose address changes between ingests,
so ingests that see IP<->MAC bindings (pcap, ARP, NDP, MAC tables) go
through a HostIdentityResolver, which adds:

  * DHCP renumbering - a known MAC seen with a NEW ip, while none of the
    MAC's old addresses of the same family/scope is still seen with it in
    this ingest, moves that Host's current ip to the new address instead of
    creating a second row. If an IP-only Host already holds the new address
    (e.g. learned from a firewall config) it is merged into the MAC host:
    sessions, protocol details, findings and every other FK are re-pointed,
    nothing is lost. Both addresses stay in HostAddressHistory.
  * IP conflicts - a known IP seen with a DIFFERENT MAC is never silently
    overwritten: a separate (ip, new-mac) Host is kept (which is what
    alert_engine.review_ip_conflicts keys on) and the event is counted and
    recorded in history.
  * History - every (host, ip, mac, source) observed is upserted into
    HostAddressHistory with first/last seen and an observation count.

Staleness: mark_stale_hosts() flags hosts not seen since a cutoff and
clears the flag on hosts seen again; get_or_create_host clears it whenever
any ingest touches a host.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy import and_, or_, update
from sqlalchemy.orm import Session as DBSession

from app.db import Base
from app.models import Host, HostAddressHistory, NetworkSession, real_host_clause
from app.parsers.common import as_utc, get_or_create_host, is_group_mac, normalize_mac

log = logging.getLogger(__name__)

HISTORY_SOURCES = frozenset({"pcap", "arp", "ndp", "mac_table", "config", "inventory"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_EVENTS = 200          # cap on per-ingest event lists returned in stats


def address_scope(ip: Optional[str]) -> Optional[tuple]:
    """(version, link_local) - renumbering only replaces an address of the
    same family and scope (an IPv6 global address never replaces the
    host's IPv4 address or its fe80:: address)."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return (addr.version, bool(addr.is_link_local))


def is_unicast_host_ip(ip: Optional[str], mac: Optional[str] = None,
                       broadcasts: Optional[Iterable[str]] = None) -> bool:
    """True for addresses that identify one host (not multicast, broadcast,
    unspecified).

    B-14b: an IPv4 address carried with a group/broadcast MAC (I/G bit set,
    e.g. ff:ff:ff:ff:ff:ff) is a directed broadcast / multicast delivery,
    not a host; so is any address in ``broadcasts`` (the known subnets'
    broadcast addresses - see site_broadcast_addresses)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    if addr.version == 4:
        if int(addr) == 0xFFFFFFFF:
            return False
        if mac and is_group_mac(normalize_mac(mac) or mac):
            return False
        if broadcasts and str(addr) in broadcasts:
            return False
    return True


def _broadcast_of(cidr: Optional[str]) -> Optional[str]:
    if not cidr:
        return None
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or net.prefixlen >= 31 or net.prefixlen == 0:
        return None
    return str(net.broadcast_address)


def site_broadcast_addresses(db: DBSession, site_id: Optional[int]) -> set:
    """B-14b: IPv4 broadcast addresses of every subnet known for ``site_id``
    (FirewallInterface ip_cidr / network_cidr of the site's firewalls,
    FirewallZone ip_cidr).  /31, /32 and /0 subnets have no broadcast.
    (SwitchVlan carries no subnet, so it contributes nothing.)"""
    from app.models import Firewall, FirewallInterface, FirewallZone
    out: set = set()
    if site_id is None:
        return out
    try:
        rows = (db.query(FirewallInterface.ip_cidr, FirewallInterface.network_cidr,
                         FirewallInterface.ip_address, FirewallInterface.prefix_len)
                .join(Firewall, FirewallInterface.firewall_id == Firewall.id)
                .filter(Firewall.site_id == site_id).all())
        for ip_cidr, net_cidr, ip_addr, plen in rows:
            for c in (ip_cidr, net_cidr,
                      f"{ip_addr}/{plen}" if ip_addr and plen is not None else None):
                b = _broadcast_of(c)
                if b:
                    out.add(b)
        for (ip_cidr,) in (db.query(FirewallZone.ip_cidr)
                           .filter(FirewallZone.site_id == site_id,
                                   FirewallZone.ip_cidr.isnot(None)).all()):
            b = _broadcast_of(ip_cidr)
            if b:
                out.add(b)
    except Exception:   # never let subnet lookup break an ingest
        log.exception("site_broadcast_addresses failed for site %s", site_id)
    return out


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _fks_to(table_name: str) -> list:
    """[(table, column)] for every FK in the metadata pointing at table.id."""
    out = []
    for table in Base.metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.name == table_name and fk.column.name == "id":
                out.append((table, fk.parent))
    return out


def _mapped_class(table):
    for mapper in Base.registry.mappers:
        if mapper.local_table is table:
            return mapper.class_
    return None


def _repoint(db: DBSession, table, column, old_id: int, new_id: int) -> None:
    cls = _mapped_class(table)
    if cls is not None:
        attr = getattr(cls, column.key, None)
        if attr is not None:
            db.execute(update(cls).where(attr == old_id).values({column.key: new_id})
                       .execution_options(synchronize_session="fetch"))
            return
    db.execute(table.update().where(column == old_id).values({column.name: new_id}))


def _fold_session(db: DBSession, src: NetworkSession, dst: NetworkSession) -> None:
    """Move everything from session ``src`` into ``dst`` and delete ``src``."""
    dst.packet_count = (dst.packet_count or 0) + (src.packet_count or 0)
    dst.byte_count = (dst.byte_count or 0) + (src.byte_count or 0)
    a, b = as_utc(dst.first_seen), as_utc(src.first_seen)
    if b is not None and (a is None or b < a):
        dst.first_seen = b
    a, b = as_utc(dst.last_seen), as_utc(src.last_seen)
    if b is not None and (a is None or b > a):
        dst.last_seen = b
    if (dst.protocol or "unknown") == "unknown" and src.protocol:
        dst.protocol = src.protocol
    if dst.pcap_capture_id is None and src.pcap_capture_id is not None:
        dst.pcap_capture_id = src.pcap_capture_id
    if getattr(dst, "carrier_mac", None) is None and getattr(src, "carrier_mac", None):
        dst.carrier_mac = src.carrier_mac
    for table, column in _fks_to(NetworkSession.__tablename__):
        _repoint(db, table, column, src.id, dst.id)
    db.expire(src, ["details"])
    db.delete(src)


def _find_session_for(db, sid, a, a_port, b, b_port, transport):
    def _eq(col, val):
        return col.is_(None) if val is None else col == val
    return (
        db.query(NetworkSession)
        .filter(
            NetworkSession.id != sid,
            NetworkSession.transport == transport,
            or_(
                and_(NetworkSession.src_host_id == a, NetworkSession.dst_host_id == b,
                     _eq(NetworkSession.src_port, a_port), _eq(NetworkSession.dst_port, b_port)),
                and_(NetworkSession.src_host_id == b, NetworkSession.dst_host_id == a,
                     _eq(NetworkSession.src_port, b_port), _eq(NetworkSession.dst_port, a_port)),
            ),
        )
        .order_by(NetworkSession.id)
        .first()
    )


_NO_COPY = frozenset({"id", "ip", "mac", "sources", "first_seen", "last_seen", "stale"})
_MANUAL_GROUPS = (
    ("classification_source", ("device_type", "purdue_level", "classification_source")),
    ("role_source", ("role", "role_source")),
    ("vlan_source", ("vlan", "vlan_source")),
)


def merge_hosts(db: DBSession, keep: Host, drop: Host) -> Host:
    """
    Merge Host ``drop`` into ``keep`` and delete ``drop``. Never loses rows:
    NetworkSessions are re-pointed (a session that would duplicate one keep
    already has is folded into it - counts/times summed, its ProtocolDetail
    and Finding rows re-pointed), every other FK to hosts.id is re-pointed,
    address history is moved (duplicate keys summed), and fields keep lacks
    are copied from drop (a "manual" classification/role/vlan on drop wins
    over an automatic one on keep). Flushes; never commits.
    """
    if keep.id == drop.id:
        return keep
    if keep.site_id is not None and drop.site_id is not None and keep.site_id != drop.site_id:
        # Sites are isolated (multi-site phase 2): identity never crosses them.
        raise ValueError(f"refusing to merge host {drop.id} (site {drop.site_id}) into "
                         f"host {keep.id} (site {keep.site_id}): different sites")
    db.flush()
    keep_id, drop_id = keep.id, drop.id

    # 1. Sessions (unique 5-tuple + bidirectional lookup semantics).
    sessions = (db.query(NetworkSession)
                .filter(or_(NetworkSession.src_host_id == drop_id,
                            NetworkSession.dst_host_id == drop_id))
                .order_by(NetworkSession.id).all())
    for s in sessions:
        new_src = keep_id if s.src_host_id == drop_id else s.src_host_id
        new_dst = keep_id if s.dst_host_id == drop_id else s.dst_host_id
        twin = _find_session_for(db, s.id, new_src, s.src_port, new_dst, s.dst_port, s.transport)
        if twin is not None:
            _fold_session(db, s, twin)
        else:
            s.src_host_id, s.dst_host_id = new_src, new_dst
        db.flush()
        if twin is None:
            db.expire(s, ["src_host", "dst_host"])

    # 2. Address history (unique per host/ip/mac/source).
    kept = {(r.ip, r.mac, r.source): r for r in
            db.query(HostAddressHistory).filter(HostAddressHistory.host_id == keep_id)}
    for r in db.query(HostAddressHistory).filter(HostAddressHistory.host_id == drop_id).all():
        twin = kept.get((r.ip, r.mac, r.source))
        if twin is None:
            r.host_id = keep_id
            kept[(r.ip, r.mac, r.source)] = r
            continue
        twin.observation_count = (twin.observation_count or 0) + (r.observation_count or 0)
        if r.first_seen and (twin.first_seen is None or as_utc(r.first_seen) < as_utc(twin.first_seen)):
            twin.first_seen = r.first_seen
        if r.last_seen and (twin.last_seen is None or as_utc(r.last_seen) > as_utc(twin.last_seen)):
            twin.last_seen = r.last_seen
        db.delete(r)
    db.flush()

    # 3. Any other table pointing at hosts.id (added by other modules).
    for table, column in _fks_to(Host.__tablename__):
        if table.name in (NetworkSession.__tablename__, HostAddressHistory.__tablename__):
            continue
        _repoint(db, table, column, drop_id, keep_id)

    # 4. Fields.
    for marker, cols in _MANUAL_GROUPS:
        if getattr(drop, marker) == "manual" and getattr(keep, marker) != "manual":
            for col in cols:
                setattr(keep, col, getattr(drop, col))
    for col in Host.__table__.columns:
        if col.key in _NO_COPY:
            continue
        if getattr(keep, col.key) is None and getattr(drop, col.key) is not None:
            setattr(keep, col.key, getattr(drop, col.key))
    keep.sources = list(dict.fromkeys(list(keep.sources or []) + list(drop.sources or [])))
    for attr, better in (("first_seen", lambda a, b: b < a), ("last_seen", lambda a, b: b > a)):
        a, b = as_utc(getattr(keep, attr)), as_utc(getattr(drop, attr))
        if b is not None and (a is None or better(a, b)):
            setattr(keep, attr, b)
    keep.stale = False

    db.delete(drop)
    db.flush()
    log.info("merged host %s into host %s", drop_id, keep_id)
    return keep


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class HostIdentityResolver:
    """
    Per-ingest identity logic. ``observed`` is {mac: iterable of ips} for
    every binding the ingest contains (pcap prescan, the whole ARP dump):
    renumbering is only considered when it is given, because "the old
    address is no longer seen with this MAC" can only be judged against the
    complete ingest. Call finish() before the caller's flush/commit to write
    HostAddressHistory.
    """

    def __init__(self, db: DBSession, source: str,
                 observed: Optional[dict] = None, history_source: Optional[str] = None,
                 site_id: Optional[int] = None):
        from app.sites import scope_site_id
        self.db = db
        # Phase 2: every lookup/merge stays inside this ingest's site.
        self.site_id = scope_site_id(db, site_id)
        self.source = source
        self.history_source = history_source or source
        self.observed: Optional[dict] = None
        if observed is not None:
            self.observed = {}
            for raw_mac, ips in observed.items():
                mac = normalize_mac(raw_mac)
                if mac:
                    self.observed.setdefault(mac, set()).update(i for i in ips if i)
        self._obs: dict[tuple, list] = {}
        self._reconciled: set = set()
        self._merged: dict[int, int] = {}
        self.stats = {
            "hosts_renumbered": 0,
            "hosts_merged": 0,
            "ip_conflicts": 0,
            "address_changes": [],
            "ip_conflict_events": [],
        }

    # -- observations ----------------------------------------------------
    def observe(self, host: Host, ip: Optional[str], mac: Optional[str],
                seen_at: Optional[datetime] = None, source: Optional[str] = None,
                count: int = 1) -> None:
        seen_at = as_utc(seen_at) or datetime.now(timezone.utc)
        key = (host.id, ip or None, normalize_mac(mac) if mac else None,
               source or self.history_source)
        cur = self._obs.get(key)
        if cur is None:
            self._obs[key] = [seen_at, seen_at, count]
        else:
            if seen_at < cur[0]:
                cur[0] = seen_at
            if seen_at > cur[1]:
                cur[1] = seen_at
            cur[2] += count

    def resolve(self, ip: Optional[str], mac: Optional[str],
                seen_at: Optional[datetime] = None, source: Optional[str] = None) -> Optional[Host]:
        """Reconcile (renumber/merge/conflict) then get-or-create and record."""
        mac = normalize_mac(mac)
        ip = ip or None
        if ip and mac:
            self.reconcile(ip, mac)
        host = get_or_create_host(self.db, ip, mac, source or self.source, seen_at=seen_at,
                                  site_id=self.site_id)
        if host is not None:
            self.observe(host, ip, mac, seen_at, source)
        return host

    def reconcile(self, ip: str, mac: str) -> None:
        mac = normalize_mac(mac)
        if not ip or not mac or (ip, mac) in self._reconciled:
            return
        self._reconciled.add((ip, mac))
        db = self.db
        db.flush()
        in_site = Host.site_id == self.site_id
        if db.query(Host.id).filter(in_site, Host.mac == mac, Host.ip == ip).first() is not None:
            return
        same_ip = db.query(Host).filter(in_site, Host.ip == ip).all()
        conflicting = [h for h in same_ip if h.mac and h.mac != mac]
        ip_only = next((h for h in same_ip if h.mac is None), None)

        mover = None
        if self.observed is not None:
            scope = address_scope(ip)
            still_seen = self.observed.get(mac, set())
            candidates = [
                h for h in db.query(Host).filter(in_site, Host.mac == mac, Host.ip.isnot(None)).all()
                if h.ip != ip and address_scope(h.ip) == scope and h.ip not in still_seen
            ]
            if candidates:
                mover = max(candidates, key=lambda h: (as_utc(h.last_seen) or _EPOCH, h.id))

        if mover is not None:
            old_ip = mover.ip
            self._ensure_history(mover, old_ip, mac)
            if ip_only is not None:
                self._merge(mover, ip_only)
            mac_only = db.query(Host).filter(in_site, Host.mac == mac, Host.ip.is_(None)).first()
            if mac_only is not None:
                self._merge(mover, mac_only)
            mover.ip = ip
            mover.stale = False
            db.flush()
            self.stats["hosts_renumbered"] += 1
            if len(self.stats["address_changes"]) < _MAX_EVENTS:
                self.stats["address_changes"].append(
                    {"host_id": mover.id, "mac": mac, "old_ip": old_ip, "new_ip": ip})
            log.info("host %s (%s) renumbered %s -> %s", mover.id, mac, old_ip, ip)

        elif ip_only is not None:
            # LS-05: the address is known without a MAC (firewall config,
            # routed capture) and the MAC without an address (switch MAC
            # table): one device - fold the MAC-only row into the IP row.
            # Not when the MAC looks like a router (seen with several
            # addresses in this capture) or the MAC-only row was classified
            # by hand: then the binding may be a routed frame, and the
            # switch-port row must not be folded into a remote host.
            # AU full review E-M4: a dual-stack host (one IPv4 + fe80:: +
            # a global IPv6) is not a router; only several addresses of the
            # SAME family and scope count.
            router_like = False
            if self.observed is not None:
                _scope = address_scope(ip)
                router_like = sum(1 for o in self.observed.get(mac, ()) if address_scope(o) == _scope) > 1
            mac_only = db.query(Host).filter(in_site, Host.mac == mac, Host.ip.is_(None)).first()
            if mac_only is not None and not router_like and mac_only.classification_source != "manual":
                self._merge(ip_only, mac_only)
            elif mac_only is not None:
                log.info("not merging MAC-only host %s into %s (%s)", mac_only.id, ip_only.id,
                         "router-like MAC" if router_like else "manual classification")

        if conflicting:
            self.stats["ip_conflicts"] += 1
            if len(self.stats["ip_conflict_events"]) < _MAX_EVENTS:
                self.stats["ip_conflict_events"].append(
                    {"ip": ip, "mac": mac, "existing_macs": sorted({h.mac for h in conflicting}),
                     "existing_host_ids": sorted(h.id for h in conflicting)})
            log.info("IP %s seen with new MAC %s (already known with %s)",
                     ip, mac, ", ".join(sorted({h.mac for h in conflicting})))

    def _merge(self, keep: Host, drop: Host) -> None:
        drop_id = drop.id
        merge_hosts(self.db, keep, drop)
        self._merged[drop_id] = keep.id
        for k, v in list(self._merged.items()):
            if v == drop_id:
                self._merged[k] = keep.id
        self.stats["hosts_merged"] += 1

    def _ensure_history(self, host: Host, ip: str, mac: str) -> None:
        """Make sure the address being replaced is in history even for
        hosts created before history existed."""
        exists = (self.db.query(HostAddressHistory.id)
                  .filter(HostAddressHistory.host_id == host.id,
                          HostAddressHistory.ip == ip, HostAddressHistory.mac == mac)
                  .first())
        if exists is None:
            sources = [s for s in (host.sources or []) if s]
            self.db.add(HostAddressHistory(
                host_id=host.id, ip=ip, mac=mac,
                first_seen=host.first_seen, last_seen=host.last_seen,
                source=(sources[0] if sources else self.history_source)[:32],
                observation_count=1,
            ))

    # -- history ----------------------------------------------------------
    def finish(self) -> dict:
        """Upsert recorded observations into HostAddressHistory; flushes."""
        if not self._obs:
            return self.stats
        merged: dict[tuple, list] = {}
        for (host_id, ip, mac, source), (first, last, n) in self._obs.items():
            while host_id in self._merged:
                host_id = self._merged[host_id]
            key = (host_id, ip, mac, (source or "unknown")[:32])
            cur = merged.get(key)
            if cur is None:
                merged[key] = [first, last, n]
            else:
                cur[0] = min(cur[0], first)
                cur[1] = max(cur[1], last)
                cur[2] += n
        self._obs.clear()
        self.db.flush()
        host_ids = sorted({k[0] for k in merged})
        existing: dict[tuple, HostAddressHistory] = {}
        for i in range(0, len(host_ids), 500):
            chunk = host_ids[i:i + 500]
            for r in self.db.query(HostAddressHistory).filter(HostAddressHistory.host_id.in_(chunk)):
                existing[(r.host_id, r.ip, r.mac, r.source)] = r
        new_rows = []
        for key, (first, last, n) in merged.items():
            row = existing.get(key)
            if row is None:
                new_rows.append(HostAddressHistory(
                    host_id=key[0], ip=key[1], mac=key[2], source=key[3],
                    first_seen=first, last_seen=last, observation_count=n))
                continue
            row.observation_count = (row.observation_count or 0) + n
            if row.first_seen is None or first < as_utc(row.first_seen):
                row.first_seen = first
            if row.last_seen is None or last > as_utc(row.last_seen):
                row.last_seen = last
        if new_rows:
            self.db.add_all(new_rows)
        self.db.flush()
        return self.stats

    def public_stats(self) -> dict:
        return dict(self.stats)


# ---------------------------------------------------------------------------
# Staleness / history queries
# ---------------------------------------------------------------------------

def mark_stale_hosts(db: DBSession, older_than_days: int = 30,
                     now: Optional[datetime] = None, site_id: Optional[int] = None) -> dict:
    """
    Flag hosts whose last_seen is older than ``older_than_days`` as stale and
    clear the flag on hosts seen since. Hosts with no last_seen are left
    alone. Flushes; the caller commits.
    """
    if older_than_days < 0:
        raise ValueError("older_than_days must be >= 0")
    now = as_utc(now) or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=older_than_days)
    scope = [Host.site_id == site_id] if site_id is not None else []
    marked = db.execute(
        update(Host).where(*scope, real_host_clause(), Host.last_seen < cutoff, Host.stale.is_not(True))
        .values(stale=True).execution_options(synchronize_session="fetch")
    ).rowcount or 0
    cleared = db.execute(
        update(Host).where(*scope, Host.last_seen >= cutoff, Host.stale.is_(True))
        .values(stale=False).execution_options(synchronize_session="fetch")
    ).rowcount or 0
    db.flush()
    total = db.query(Host).filter(*scope, Host.stale.is_(True)).count()
    return {"cutoff": cutoff.isoformat(), "older_than_days": older_than_days,
            "marked_stale": marked, "cleared": cleared, "stale_total": total}


def host_address_history(db: DBSession, host_id: int) -> list[dict]:
    rows = (db.query(HostAddressHistory)
            .filter(HostAddressHistory.host_id == host_id)
            .order_by(HostAddressHistory.last_seen.desc(), HostAddressHistory.id.desc())
            .all())
    return [
        {"id": r.id, "host_id": r.host_id, "ip": r.ip, "mac": r.mac, "source": r.source,
         "first_seen": r.first_seen, "last_seen": r.last_seen,
         "observation_count": r.observation_count}
        for r in rows
    ]


def observed_bindings(pairs: Iterable[tuple]) -> dict:
    """[(ip, mac), ...] -> {normalized mac: {ips}} for HostIdentityResolver."""
    out: dict = {}
    for ip, mac in pairs:
        mac = normalize_mac(mac)
        if mac and ip:
            out.setdefault(mac, set()).add(ip)
    return out
