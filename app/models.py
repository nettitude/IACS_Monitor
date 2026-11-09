"""
Core data model for IACS_Monitor.

Every ingest source (ARP tables, pcap, switch configs, firewall configs,
FortiAnalyzer reports/events) normalizes into these tables.

    Host              - a physical/logical endpoint, identified by MAC/IP
    NetworkSession    - an observed 5-tuple conversation between two hosts
    ProtocolDetail    - one or more protocol-specific frames decoded from a session
    FirewallDevice    - a named firewall device with its Purdue zone boundary
                        (e.g. "Corp-FW" protecting the Level 4→3 boundary).
                        Parent of FirewallRule: every rule is owned by exactly
                        one device, which anchors it to a specific boundary in
                        the Purdue swimlane topology.
    FirewallRule      - a rule pulled from a firewall config (the "allowed" topology)
    SwitchInterface   - a switch port's VLAN assignment and CDP/LLDP neighbor
    MacTableEntry     - a MAC address table row (bridges host identity to VLAN)
    FirewallZone      - a FortiGate interface's zone/IP/VLAN, from show full-configuration
    FortiAnalyzerEvent - a raw event/log record received from FortiAnalyzer
    Baseline          - a named baseline snapshot (approved comms matrix revision etc.)
    ApprovedCommsEntry - one row of the approved communications matrix
    ApprovedHost      - a host in an approved role (jump host, admin WS, eng WS/HMI)
    Finding           - a 62443-tagged finding (config-review, real-time, or periodic
                        review - the single unified record across all check-producing
                        modules; there is no separate "Alert" model)
"""
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    Column,
    Integer,
    Numeric,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    JSON,
    LargeBinary,
    UniqueConstraint,
    Index,
    text,
    true,
    false,
    or_,
)
from sqlalchemy.dialects.postgresql import JSONB as _PG_JSONB
from sqlalchemy.orm import declared_attr, deferred, relationship
from sqlalchemy.types import TypeDecorator

from app.db import Base
from app import purdue as _purdue


def _json_column(**kwargs):
    """
    Return a Column using JSONB on PostgreSQL and generic JSON elsewhere.

    JSONB gives:
      - Binary storage (smaller on disk, faster to deserialise)
      - GIN index support for @>, ?, ?| operators on evidence fields
      - Native operator pushdown in queries

    Generic JSON is used on SQLite (test/dev) because SQLite has no JSONB
    type.  The migration a1b2c3d4e5f6 converts existing JSON columns to
    JSONB on PostgreSQL at deploy time.

    Usage:
        detail = _json_column(default=dict)
    """
    return Column(
        _PG_JSONB().with_variant(JSON(), "sqlite"),
        **kwargs,
    )


def utcnow():
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Timestamp column that is always UTC (T3-07).

    Storage: naive UTC in a plain TIMESTAMP / DATETIME column on every
    backend, so PostgreSQL never converts values through the server's
    TimeZone setting (it did when timezone-aware datetimes were written
    into ``timestamp without time zone`` columns).

    Python side: values come back timezone-aware (tzinfo=UTC), so they
    compare cleanly with ``utcnow()`` and serialise with an explicit
    offset. Naive datetimes passed in are taken to be UTC already.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or not isinstance(value, datetime):
            return value
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class PurdueLevelType(TypeDecorator):
    """Purdue level column (F-08): 0, 1, 2, 3, 3.5 (industrial DMZ), 4, 5.

    Storage: NUMERIC(2,1) on every backend.  Exact fixed-point on
    PostgreSQL (3.5 is stored as 3.5, never 3.4999...), and on SQLite the
    NUMERIC affinity keeps whole levels as INTEGER (so pre-F-08 integer
    data is unchanged on disk) and stores 3.5 as REAL - which is exact
    for a .5 value.  ``IN (0, 1, 2, 3, 3.5, 4, 5)`` CHECK constraints
    behave identically on both.  (Float/REAL would also hold 3.5 exactly
    but would turn every whole level into 3.0 on SQLite and FLOAT8 on
    PostgreSQL, with no DDL-level statement of "one decimal place".)

    Python side: always ``int`` for whole levels and ``3.5`` for the DMZ
    (via app.purdue.normalize_level) - never Decimal or 3.0 - so JSON
    serialises 3 / 3.5.  Bind values are normalised when valid and passed
    through unchanged otherwise, so comparisons against arbitrary numbers
    still work and invalid writes are rejected by the CHECK constraints.
    """
    impl = Numeric(2, 1, asdecimal=False)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        try:
            return _purdue.normalize_level(value)
        except ValueError:
            return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return _purdue.normalize_level(value)
        except ValueError:
            return float(value)


def _purdue_check(column: str, name: str) -> CheckConstraint:
    return CheckConstraint(_purdue.check_sql(column), name=name)


# ==========================================================================
# SITES (multi-site phase 1, docs/multi-site-design.md)
# ==========================================================================

class Site(Base):
    """
    A plant / facility whose data is kept separate from every other site.
    The site is chosen at upload time (``site`` parameter on every non-log
    ingest route) and stamped on every ROOT row that upload creates.

    Migration c0d1e2f3a4b5 creates the "Default" site (code ``default``)
    and assigns all pre-existing data to it.  ``code`` is a short,
    URL-safe slug; ``name`` is the display name.  Both are unique (the API
    additionally rejects case-insensitive duplicates).
    """
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    code = Column(String(64), nullable=False)
    description = Column(String(1024), nullable=True)
    created_at = Column(UTCDateTime, default=utcnow)

    # Named unique INDEXES (not column-level unique=True): the reconcile
    # migration (d4e5f6a7b8c9) can only add uniqueness as named indexes.
    __table_args__ = (
        Index("ux_sites_name", "name", unique=True),
        Index("ux_sites_code", "code", unique=True),
    )

    def __repr__(self):
        return f"<Site id={self.id} code={self.code!r} name={self.name!r}>"


DEFAULT_SITE_CODE = "default"
DEFAULT_SITE_NAME = "Default"


class SiteScoped:
    """
    Mixin for ROOT tables: adds ``site_id`` (FK sites.id, NOT NULL, indexed
    as ``ix_<table>_site_id``).

    Child tables whose parent FK is NOT NULL (FirewallInterface -> firewalls,
    NetworkSession -> hosts, ProtocolDetail -> network_sessions,
    HostAddressHistory -> hosts, ApprovedComms/ApprovedHost -> baselines)
    inherit the site through that parent and carry no column.
    FirewallRule and NatRule DO carry a denormalised site_id: both of their
    parent FKs (firewall_id, firewall_device_id) are nullable (Cisco/pfSense
    rules ingested without a device label, reviewed-policy rows), so the
    parent alone cannot place every rule in a site, and /firewall-rules and
    /nat-rules filter on it directly.  FirewallZone has no parent FK at all
    (keyed by device_name), so it is a root table.

    New rows that do not set site_id explicitly are filled in at flush time
    by app.sites (parent's site -> ingest site bound by the route/parser ->
    the Default site); see app.sites.SITE_PARENTS.
    """

    @declared_attr
    def site_id(cls):
        return Column(Integer, ForeignKey("sites.id"), nullable=False, index=True)


class Host(SiteScoped, Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True)
    mac = Column(String(17), nullable=True, index=True)
    ip = Column(String(45), nullable=True, index=True)  # v4 or v6
    vendor = Column(String(128), nullable=True)  # resolved from OUI
    hostname = Column(String(255), nullable=True)

    first_seen = Column(UTCDateTime, default=utcnow)
    last_seen = Column(UTCDateTime, default=utcnow, index=True)  # T3-09: ORDER BY in /hosts

    # Comma-separated or JSON list of where we learned about this host:
    # "arp", "pcap", "switch_config", "firewall_config"
    sources = _json_column(default=list)

    # Purdue/ISA-99 (IEC 62443) model classification. device_type is a
    # free-form category (e.g. "plc", "rtu", "hmi", "engineering_workstation" -
    # see device_classification.py's DEVICE_TYPE_REFERENCE for the full
    # curated list and their default Purdue level). purdue_level is one of
    # app.purdue.VALID_LEVELS (0-5 plus 3.5 = industrial DMZ).
    # classification_source records how it was set: "manual" | "oui_hint" |
    # "protocol_inferred" | "vlan_inferred" (from the VLAN's own Purdue
    # classification - see device_classification.py's VLAN_NAME_KEYWORDS).
    # This is also the precedence order, most to least authoritative below
    # manual: protocol_inferred > vlan_inferred > oui_hint. Automatic
    # (re-)classification only ever touches rows where classification_source
    # is None or one of the three non-manual values - never "manual".
    device_type = Column(String(64), nullable=True)
    purdue_level = Column(PurdueLevelType, nullable=True)
    classification_source = Column(String(32), nullable=True)

    # Functional role derived from CDP/LLDP neighbor-discovery data - what
    # the device *does* in the architecture, as opposed to what level it
    # sits at.  This is narrower than device_type (which targets Purdue
    # classification) and is populated by mechanism 4 in
    # device_classification.py: `classify_hosts_by_lldp_role()`.
    #
    # Values: "plc" | "hmi" | "historian" | "switch" | "router" |
    #         "firewall" | "server" | "workstation" | "ip_camera" |
    #         "ups" | "printer" | "ot_gateway" | "scada_server"
    # None means role has not been determined from LLDP/CDP data.
    # role_source mirrors classification_source: "lldp" | "cdp" | "manual"
    # "manual" is never overwritten by automatic mechanisms.
    role = Column(String(64), nullable=True)
    role_source = Column(String(16), nullable=True)  # "lldp" | "cdp" | "manual"

    # VLAN membership - populated either from a MAC address-table
    # cross-reference (authoritative, vlan_source="mac_table") or, when
    # that's unavailable, inferred from which subnet the host's IP falls
    # in relative to subnets already known from mac_table-sourced hosts
    # (vlan_source="subnet_inference", lower confidence - see
    # mac_table_parser.py's infer_vlan_by_subnet). "manual" always wins
    # and is never overwritten by either automatic mechanism.
    vlan = Column(String(64), nullable=True)
    vlan_source = Column(String(32), nullable=True)  # "mac_table" | "subnet_inference" | "manual" | "pcap_8021q" (RS-07) | "fw_interface" (firewall / L3-switch VLAN interface subnet)

    # ------------------------------------------------------------------ IACS asset inventory fields
    # All nullable — populated manually (via PATCH /assets/{id} or CSV import)
    # or, where discoverable, from CDP/LLDP/FortiGate data.

    # Physical identity — not discoverable from network traffic alone
    model            = Column(String(128), nullable=True)   # e.g. "Allen-Bradley 1756-L73"
    serial_number    = Column(String(128), nullable=True)
    firmware_version = Column(String(128), nullable=True)   # also set from CDP platform string

    # Physical location in the plant/facility
    site             = Column(String(128), nullable=True)   # e.g. "Plant A"
    building         = Column(String(128), nullable=True)   # e.g. "Building 3"
    panel            = Column(String(128), nullable=True)   # e.g. "Panel PLC-07"

    # Operational classification
    # criticality: "high" | "medium" | "low"
    #   high   — loss causes production stop or safety hazard
    #   medium — loss degrades operations but has a manual workaround
    #   low    — loss has no immediate operational impact
    criticality      = Column(String(16), nullable=True)
    is_safety_function = Column(Boolean, nullable=True)     # True if SIL-rated or part of SIS
    # IEC 62443-4-2 capability security level of the component (1-4, NULL =
    # not assessed) and where it comes from (certificate, vendor statement,
    # assessment).  Documentation: compared with the zone SL-T on the Zones &
    # Conduits page only, never read by the findings engine.
    sl_c             = Column(Integer, nullable=True)
    sl_c_source      = Column(String(255), nullable=True)

    # Ownership / accountability
    owner            = Column(String(128), nullable=True)   # responsible team or person
    asset_tag        = Column(String(64),  nullable=True)   # physical asset tag / plant number
    notes            = Column(Text, nullable=True)          # free-text notes for the inventory

    # Approval status
    # approved: True  — device is in the approved asset baseline
    #           False — device has been explicitly flagged as unapproved/rogue
    #           None  — not yet reviewed (default for all auto-discovered hosts)
    approved         = Column(Boolean, nullable=True, default=None)
    approved_by      = Column(String(128), nullable=True)
    approved_at      = Column(UTCDateTime, nullable=True)
    last_reviewed_at = Column(UTCDateTime, nullable=True)
    last_reviewed_by = Column(String(128), nullable=True)

    # Staleness (F-09): set by host_identity.mark_stale_hosts() for hosts not
    # seen since a cutoff; cleared again by any ingest that touches the host.
    stale = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    # owner 2026-10-14: "not an inventory asset" - hidden from the Inventory list /
    # export only (topology, findings, traffic pages unchanged); counts as a reviewed,
    # known host for unknown_device (treated as a decision, like page approval).
    inventory_excluded = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    inventory_excluded_reason = Column(String(500), nullable=True)
    inventory_excluded_by = Column(String(128), nullable=True)
    inventory_excluded_at = Column(UTCDateTime, nullable=True)

    __table_args__ = (
        # Multi-site phase 2 (migration e1f2a3b4c5d6): host identity is per
        # site - the same (mac, ip) may exist once in EACH site.  Replaces the
        # global uq_host_mac_ip / ix_host_ip_only / ix_host_mac_only.
        Index("ux_hosts_site_mac_ip", "site_id", "mac", "ip", unique=True),
        # At least one of ip/mac must be set — a host with neither has no
        # identity and cannot be deduplicated, matched against a baseline, or
        # displayed meaningfully. Enforced at the DB level to catch any code
        # path that bypasses the Python guard in common.get_or_create_host().
        CheckConstraint(
            "ip IS NOT NULL OR mac IS NOT NULL",
            name="ck_host_identity",
        ),
        # Purdue level must be NULL (unknown) or a valid Purdue/ISA-99 level
        # (app.purdue.VALID_LEVELS: 0 = physical process, 1 = basic control,
        # 2 = supervisory, 3 = site operations, 3.5 = industrial DMZ,
        # 4 = enterprise, 5 = internet/external).  Anything else indicates a
        # data entry error and is rejected at the DB level so bad imports
        # don't propagate through reachability or compliance checks.
        # (Replaced ck_host_purdue_level_range, a 0-5 range, in F-08.)
        _purdue_check("purdue_level", "ck_host_purdue_level_valid"),
        # Partial unique indexes for identity-only rows (mac XOR ip is NULL).
        # The standard UniqueConstraint above covers rows where both are set,
        # but SQL NULL != NULL, so two rows with mac=NULL,ip=NULL would both
        # pass that constraint. These partial indexes close the gap.
        # SQLite: WHERE clause supported since 3.8.9.
        # PostgreSQL: WHERE clause is standard.
        Index(
            "ux_hosts_site_ip_only",
            "site_id", "ip",
            unique=True,
            postgresql_where=text("mac IS NULL"),
            sqlite_where=text("mac IS NULL"),
        ),
        Index(
            "ux_hosts_site_mac_only",
            "site_id", "mac",
            unique=True,
            postgresql_where=text("ip IS NULL"),
            sqlite_where=text("ip IS NULL"),
        ),
    )

    def __repr__(self):
        return f"<Host id={self.id} ip={self.ip} mac={self.mac}>"


# B-14 group marker: the per-site broadcast/multicast pseudo-host (no IP,
# MAC ff:ff:ff:ff:ff:ff) that group-destination sessions point at.  It is
# not a device: inventory / review / count queries exclude it with
# real_host_clause().  See app.parsers.pcap_parser.get_group_marker_host.
GROUP_MARKER_MAC = "ff:ff:ff:ff:ff:ff"


def real_host_clause():
    """SQL filter that excludes group marker hosts (NULL-safe)."""
    return or_(Host.ip.isnot(None), Host.mac.is_(None), Host.mac != GROUP_MARKER_MAC)


class HostAddressHistory(Base):
    """
    Every (ip, mac) a Host has been observed with, per source (F-09).

    Written by app/parsers/host_identity.py: when DHCP renumbers a known
    MAC the Host's current ip moves and both addresses stay here; when a
    known IP shows up with a different MAC the new pairing is recorded
    (the ip_conflict signal) instead of being silently overwritten.
    source: "pcap" | "arp" | "ndp" | "mac_table" | "config" | "inventory".
    """
    __tablename__ = "host_address_history"

    id = Column(Integer, primary_key=True)
    host_id = Column(
        Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    ip = Column(String(45), nullable=True, index=True)
    mac = Column(String(17), nullable=True, index=True)
    first_seen = Column(UTCDateTime, nullable=True)
    last_seen = Column(UTCDateTime, nullable=True)
    source = Column(String(32), nullable=False, server_default=text("'unknown'"), default="unknown")
    observation_count = Column(Integer, nullable=False, default=1, server_default=text("1"))

    __table_args__ = (
        # NULL ip/mac never collide in a unique index; host_identity.py
        # de-duplicates those rows itself before inserting.
        Index(
            "ux_host_address_history",
            "host_id", "ip", "mac", "source",
            unique=True,
        ),
    )

    def __repr__(self):
        return (f"<HostAddressHistory host={self.host_id} ip={self.ip} mac={self.mac} "
                f"source={self.source} n={self.observation_count}>")


class NetworkSession(Base):
    """
    An observed conversation between two hosts, identified by the classic
    5-tuple. Named NetworkSession (not Session) to avoid confusion with
    SQLAlchemy's own Session object.
    """
    __tablename__ = "network_sessions"

    id = Column(Integer, primary_key=True)

    src_host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    # src_host_id is covered by the leading column of ux_session_5tuple;
    # dst_host_id needs its own index (host drill-downs, T3-09).
    dst_host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)

    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)

    # Transport ("tcp"/"udp") and application protocol ("modbus", "dnp3",
    # "http", "unknown", ...) are tracked separately so we can still show
    # "tcp/502 - modbus" even before a protocol analyzer recognizes it.
    transport = Column(String(8), nullable=False, default="tcp")
    protocol = Column(String(32), nullable=False, default="unknown")

    first_seen = Column(UTCDateTime, default=utcnow)
    last_seen = Column(UTCDateTime, default=utcnow, index=True)  # T3-09: ORDER BY in /sessions
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    # FO-07: cleartext logins seen on the session (kinds, comma-separated,
    # e.g. "FTP login, HTTP Basic auth"); never the credential itself
    cleartext_auth = Column(String(128), nullable=True)

    source_file = Column(String(512), nullable=True)   # originating pcap path

    # Capture-point linkage: set when the PCAP is associated with a
    # specific firewall interface (multi-firewall mode).  NULL in
    # single-firewall mode or when the capture hasn't been confirmed yet.
    pcap_capture_id = Column(
        Integer, ForeignKey("pcap_captures.id"), nullable=True
    )

    # NAT tabletop P-04 / P-05 (app.parsers.nat_sessions): the session as
    # captured, when a firewall translated it.  nat_orig_dst_ip = the VIP
    # external address it was sent to (dst_host is now the real, mapped
    # host); nat_orig_src_ip = the translated source it arrived with (src_host
    # is now the real source, taken from the pre-NAT capture of the same
    # flow).  ``nat``: the translations and any source NAT that could not be
    # attributed ({"events": [...], "snat_rule_ids": [...], "unattributed": {...}}).
    nat_orig_src_ip = Column(String(64), nullable=True)
    nat_orig_dst_ip = Column(String(64), nullable=True)
    nat = _json_column(nullable=True)
    # LS-03 / MV-07: the gateway MAC that carried most of the session's
    # frames (a MAC the PCAP ingest took for a router); consumers map it to
    # a firewall / routing switch through app.parsers.l3_switch.router_macs
    # and ignore the rest.  NULL: same segment, no router seen, or captured
    # before this column existed.
    carrier_mac = Column(String(17), nullable=True)

    src_host = relationship("Host", foreign_keys=[src_host_id])
    dst_host = relationship("Host", foreign_keys=[dst_host_id])
    details = relationship(
        "ProtocolDetail", back_populates="session", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # UNIQUE 5-tuple (T3-10): concurrent ingests can no longer create two
        # rows for the same conversation - the loser gets an IntegrityError
        # and must re-read the winner's row.  Replaces the non-unique
        # ix_session_5tuple (migration f6a7b8c9d0e1 merges old duplicates).
        # NULL ports (transport="ethernet", PROFINET) are distinct in a
        # unique index on both SQLite and PostgreSQL, so port-less sessions
        # are not constrained by it.
        Index(
            "ux_session_5tuple",
            "src_host_id", "dst_host_id", "src_port", "dst_port", "transport",
            unique=True,
        ),
        Index(
            "ix_networksession_pcap_capture_id",
            "pcap_capture_id",
        ),
    )

    def __repr__(self):
        return (
            f"<NetworkSession id={self.id} {self.src_host_id}:{self.src_port} -> "
            f"{self.dst_host_id}:{self.dst_port} proto={self.protocol}>"
        )


class ProtocolDetail(Base):
    """
    A single decoded application-layer frame belonging to a session, e.g.
    one Modbus "write multiple registers" request. Kept as one row per
    frame (rather than one row per session) so a session's full
    read/write history is visible, not just its last message.
    """
    __tablename__ = "protocol_details"

    id = Column(Integer, primary_key=True)
    session_id = Column(
        Integer, ForeignKey("network_sessions.id"), nullable=False, index=True,  # T3-09
    )

    protocol = Column(String(32), nullable=False)  # "modbus", "dnp3", ...
    timestamp = Column(UTCDateTime, default=utcnow)

    # Polymorphic payload - shape depends on `protocol` and `summary` /
    # `direction`. See app/parsers/modbus_analyzer.py for the Modbus shape.
    direction = Column(String(16), nullable=True)  # "request" / "response"
    summary = Column(String(255), nullable=True)   # e.g. "write_multiple_registers"
    fields = _json_column(default=dict)

    session = relationship("NetworkSession", back_populates="details")

    def __repr__(self):
        return f"<ProtocolDetail id={self.id} proto={self.protocol} summary={self.summary}>"


class FirewallDevice(SiteScoped, Base):
    """
    A named firewall device, identified by the Purdue zone boundary it
    protects.  Every FirewallRule row is owned by one FirewallDevice so
    the diff engine and swimlane topology know *which boundary* each rule
    enforces.

    purdue_zone_from / purdue_zone_to describe the boundary as a
    (less-trusted, more-trusted) pair following the ISA/IEC 62443 /
    Purdue Enterprise Reference Architecture numbering:

        purdue_zone_from=5, purdue_zone_to=4  →  Internet → Enterprise/IT
        purdue_zone_from=4, purdue_zone_to=3.5 →  Enterprise/IT → Industrial DMZ
        purdue_zone_from=3.5, purdue_zone_to=3 →  Industrial DMZ → Site Operations
        purdue_zone_from=4, purdue_zone_to=3  →  Enterprise/IT → Site Operations (no DMZ)
        purdue_zone_from=3, purdue_zone_to=2  →  Site Operations → Control/HMI
        purdue_zone_from=2, purdue_zone_to=1  →  Control/HMI → Basic Control (PLC/RTU)
        purdue_zone_from=1, purdue_zone_to=0  →  Basic Control → Field Devices

    Either or both may be NULL when the operator has not yet assigned a
    boundary (single-firewall mode, or just imported with no hint).  The
    topology swimlane view only draws boundary annotations when both are
    set.

    firewall_id optionally links to the richer multi-firewall Firewall
    row (which carries interface-level data) when the site is using the
    multi-firewall topology feature.  It is NULL in single-firewall mode
    or when the config was ingested before multi-firewall wiring was set up.
    """
    __tablename__ = "firewall_devices"

    id = Column(Integer, primary_key=True)

    # Human-readable label, e.g. "Corp-FW", "Cell-FW-A", "Perimeter"
    name = Column(String(255), nullable=False)   # unique per site (ux_firewall_devices_site_name)

    # Technical metadata (populated from the config where possible)
    vendor = Column(String(32), nullable=True)       # "fortigate", "cisco_ios", "pfsense", "panos"
    device_hostname = Column(String(255), nullable=True)   # hostname extracted from config
    mgmt_ip = Column(String(45), nullable=True)      # management IP (operator-supplied)
    firmware_version = Column(String(128), nullable=True)  # e.g. "FortiOS 7.4.2"
    source_file = Column(String(512), nullable=True)  # original upload filename

    # Purdue boundary this device protects (operator-assigned at ingest or
    # via PATCH /firewall-devices/{id}).  NULL = unassigned.
    purdue_zone_from = Column(PurdueLevelType, nullable=True)   # less-trusted side (higher number)
    purdue_zone_to   = Column(PurdueLevelType, nullable=True)   # more-trusted side (lower number)

    # Optional link to the richer multi-FW topology record
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=True)

    created_at = Column(UTCDateTime, default=utcnow)
    updated_at = Column(UTCDateTime, default=utcnow, onupdate=utcnow)

    # Rules owned by this device
    rules = relationship(
        "FirewallRule",
        back_populates="firewall_device",
        cascade="all, delete-orphan",
    )
    firewall = relationship("Firewall", foreign_keys=[firewall_id])

    __table_args__ = (
        # Multi-site phase 2: device names are unique per site.
        Index("ux_firewall_devices_site_name", "site_id", "name", unique=True),
        _purdue_check("purdue_zone_from", "ck_fw_device_zone_from_purdue"),
        _purdue_check("purdue_zone_to", "ck_fw_device_zone_to_purdue"),
    )

    def __repr__(self):
        return (
            f"<FirewallDevice id={self.id} name={self.name!r} "
            f"boundary={self.purdue_zone_from}→{self.purdue_zone_to}>"
        )


class FirewallRule(SiteScoped, Base):
    """
    A normalized rule extracted from a Cisco ACL, pfSense XML, Palo
    Alto config, or FortiGate full-configuration. Represents "allowed"
    topology, diffed against NetworkSession ("observed" topology).
    """
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True)

    device_name = Column(String(255), nullable=True)
    device_type = Column(String(32), nullable=False)  # "cisco_ios", "pfsense", "panos", "fortigate"
    source_file = Column(String(512), nullable=True)

    # Purdue boundary ownership: which FirewallDevice this rule came from.
    # NULL for rules ingested before FirewallDevice tagging was introduced,
    # or when no purdue_from/to hint was provided.  device_name still
    # identifies the source in those cases.
    firewall_device_id = Column(Integer, ForeignKey("firewall_devices.id"), nullable=True)

    # Multi-firewall: which Firewall record this rule came from.
    # NULL for rules ingested before the multi-firewall topology was set up
    # or in single-firewall mode (device_name still identifies the source).
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=True)

    # FortiGate-specific: policy ID and name from config firewall policy
    policy_id = Column(String(32), nullable=True, index=True)
    policy_name = Column(String(255), nullable=True)

    # FortiGate multi-VDOM (N-24): the VDOM the policy lives in.  A FortiOS
    # policy id is only unique WITHIN a VDOM, so a rule's identity is
    # (firewall, vdom, policy_id).  NULL = no VDOM wrapper in the config
    # (single-VDOM / non-FortiGate rows, and rows ingested before N-24).
    vdom = Column(String(64), nullable=True)

    # Sequence position within the owning device's rule list, used for
    # shadow analysis (first-match-wins ordering). Populated from policy_id
    # (FortiGate / Cisco ACL line numbers) where the value is numeric;
    # NULL for platforms that don't expose a stable sequence number (pfSense
    # XML ordering is positional — see parsers for how that is handled).
    # Lower number = higher priority (evaluated first).
    rule_order = Column(Integer, nullable=True)

    # Zone-to-zone conduit info (FortiGate / PAN-OS).
    # C-16: Text, not String(128) - a multi-interface policy (e.g. 14 srcintf)
    # stores a comma-joined interface/zone list that overflows 128 chars on
    # PostgreSQL (upload 500).  SQLite ignores the length but PostgreSQL does
    # not, so the column must be unbounded.
    src_zone = Column(Text, nullable=True)
    dst_zone = Column(Text, nullable=True)

    src = Column(String(128), nullable=True)   # CIDR, "any", "fqdn:...", or object-group name
    dst = Column(String(128), nullable=True)
    protocol = Column(String(16), nullable=True)   # "tcp", "udp", "icmp", "any"
    # Canonical port list as text, e.g. "443", "1000-2000" or "80,443,1000-2000".
    # Widened from String(32) (T1 schema fix) - multi-port lists exceed 32 chars.
    dst_port = Column(String(255), nullable=True)
    action = Column(String(16), nullable=False, default="permit")  # permit/deny

    # False for rules present in the config but administratively disabled
    # (FortiOS `set status disable`, pfSense <disabled/>, PAN-OS
    # `disabled yes`, Cisco ASA `inactive`). Disabled rules enforce nothing,
    # so EVERY analysis (reachability, shadowing, rule twins, cross-FW,
    # topology diff, unused-policy) must filter `enabled.is_(True)`. They are
    # kept only so review_disabled_rules can flag them for removal
    # (checklist 3.8 / SR 7.7).
    enabled = Column(Boolean, nullable=False, default=True, server_default=true())

    # Who approved/owns this rule - populated from FortiGate policy
    # comments (by convention: comments = owner / justification text)
    owner = Column(String(255), nullable=True)

    # Conduit name from the reviewed-policy workbook (ingest_reviewed_policies).
    # Identifies which zone-to-zone conduit this rule is part of, separate
    # from device_name (which is the firewall hostname).
    conduit = Column(String(128), nullable=True)

    # Last time /diff found an observed session matching this rule.
    # NULL = never matched in any diff run (candidate for cleanup review).
    last_matched = Column(UTCDateTime, nullable=True)

    # H-10: identity-based match (FortiOS ``groups`` / ``users`` /
    # ``fsso-groups``, comma list): the rule applies to those users' sessions
    # only.  NULL = any user (IP-only rule).
    src_identity = Column(Text, nullable=True)
    raw_line = Column(Text, nullable=True)  # original rule text — Text avoids truncation on long ACLs

    # ORM relationships
    firewall_device = relationship("FirewallDevice", back_populates="rules")

    __table_args__ = (
        Index("ix_firewall_rule_device_id", "firewall_device_id"),
        Index("ix_firewall_rule_order", "firewall_device_id", "rule_order"),
        # N-24: policy identity is (firewall, vdom, policy_id)
        Index("ix_firewall_rule_fw_vdom_policy", "firewall_id", "vdom", "policy_id"),
    )

    def __repr__(self):
        return f"<FirewallRule {self.action} {self.src}->{self.dst}:{self.dst_port}/{self.protocol}>"


class SwitchInterface(SiteScoped, Base):
    """
    A single switch port: its VLAN assignment (from running-config or
    `show vlan brief`) and, where available, its CDP/LLDP neighbor -
    the device and port on the other end of the cable. This is the
    physical-topology counterpart to NetworkSession's logical topology.

    Keyed on (device_name, port_name) so VLAN info learned from a
    running-config and neighbor info learned from a separate
    `show cdp/lldp neighbors detail` capture merge onto the same row
    instead of creating duplicates - these commonly come from different
    files even though they describe the same switch.
    """
    __tablename__ = "switch_interfaces"

    id = Column(Integer, primary_key=True)

    device_name = Column(String(255), nullable=True)  # switch hostname
    port_name = Column(String(64), nullable=False)     # e.g. "GigabitEthernet1/0/1"

    vlan = Column(String(64), nullable=True)   # access VLAN id, or trunk list e.g. "10,20-25"
    vlan_name = Column(String(128), nullable=True)  # e.g. "ENGINEERING" - from vlan brief / vlan-block "name" lines
    mode = Column(String(16), nullable=True)   # "access" / "trunk"
    description = Column(String(255), nullable=True)

    neighbor_device = Column(String(255), nullable=True)
    neighbor_port = Column(String(64), nullable=True)
    neighbor_platform = Column(String(255), nullable=True)
    neighbor_ip = Column(String(45), nullable=True)
    neighbor_protocol = Column(String(8), nullable=True)  # "cdp" / "lldp"
    # owner 2026-10-19 (FortiLink-managed FortiSwitch): the port-security (802.1X) policy, admin state, uplink
    port_security_policy = Column(String(128), nullable=True)
    # owner 2026-11-09: what the bound policy does - "802.1x", "802.1x-mab" (MAC authentication
    # bypass for devices that cannot do 802.1X) or "open-auth" (unauthenticated devices admitted:
    # the port counts as unprotected in review_switch_port_nac); NULL when the policy is not known
    port_security_mode = Column(String(32), nullable=True)
    admin_status = Column(String(8), nullable=True)       # "up" / "down" when the config says
    uplink = Column(Boolean, nullable=False, default=False, server_default=false())

    source_file = Column(String(512), nullable=True)

    __table_args__ = (
        # Per site (phase 2): replaces the global uq_switch_iface_device_port.
        Index("ux_switch_iface_site_device_port", "site_id", "device_name", "port_name",
              unique=True),
    )

    def __repr__(self):
        return f"<SwitchInterface {self.device_name}:{self.port_name} vlan={self.vlan}>"


class SwitchVlan(SiteScoped, Base):
    """
    A VLAN as a first-class object, parsed from `show vlan brief` (or
    equivalent running-config VLAN blocks). One row per (device, vlan_id)
    pair; persists the name, active/inactive status, and port count that
    parse_vlan_brief() previously discarded.

    This is the authoritative source for vlan_name lookups - it covers
    trunk ports (where SwitchInterface.vlan_name is intentionally None)
    and MAC-table-sourced hosts (whose MAC table entry has a vlan_id but
    no port-specific name row). device_classification.py queries here
    first; SwitchInterface is the fallback.

    purdue_level is seeded at ingest time by keyword inference on the
    VLAN name. It can be upgraded later by resolve_vlan_topology() if a
    FirewallInterface with a matching vlan_id carries a firmer Purdue
    assignment; it can also be set manually (purdue_level_source="manual"),
    in which case it is never overwritten by any automatic mechanism.
    """
    __tablename__ = "switch_vlans"

    id = Column(Integer, primary_key=True)

    device_name = Column(String(255), nullable=True)   # switch hostname; None = "unknown switch"
    vlan_id = Column(Integer, nullable=False)            # integer VLAN id, e.g. 10
    vlan_name = Column(String(128), nullable=True)       # e.g. "ENGINEERING", "ICS_CONTROL"
    status = Column(String(16), nullable=True)           # "active" / "inactive" (from show vlan brief)
    port_count = Column(Integer, nullable=True)          # count of ports in entry["ports"] at parse time

    purdue_level = Column(PurdueLevelType, nullable=True)  # app.purdue.VALID_LEVELS; None = not inferred
    purdue_level_source = Column(String(32), nullable=True)
    # "manual" | "keyword_inferred" | "firewall_propagated"

    source_file = Column(String(512), nullable=True)

    __table_args__ = (
        # Per site (phase 2): replaces the global uq_switch_vlan_device_vid.
        Index("ux_switch_vlan_site_device_vid", "site_id", "device_name", "vlan_id",
              unique=True),
        _purdue_check("purdue_level", "ck_switch_vlan_purdue_level"),
    )

    def __repr__(self):
        return (
            f"<SwitchVlan {self.device_name} vlan={self.vlan_id}"
            f" name={self.vlan_name!r} status={self.status}>"
        )


class MacTableEntry(SiteScoped, Base):
    """
    A single row from a switch's MAC address table (`show mac address-
    table` on Cisco, `show mac-address` on HP/ProCurve): which MAC was
    seen on which port, on which VLAN. This is the bridge between
    SwitchInterface's port-level VLAN assignment and Host's MAC/IP
    identity - it's what lets a host discovered via pcap/ARP be
    associated with a real VLAN rather than a subnet guess.

    Kept as its own table (rather than writing straight onto Host) so
    the raw evidence persists for audit even as Host.vlan gets
    recomputed - "why do we think this host is on VLAN 10" should always
    be answerable by looking here.
    """
    __tablename__ = "mac_table_entries"

    id = Column(Integer, primary_key=True)

    device_name = Column(String(255), nullable=True)
    port_name = Column(String(64), nullable=False)
    mac = Column(String(17), nullable=False, index=True)  # normalized aa:bb:cc:dd:ee:ff
    vlan = Column(String(64), nullable=True)

    source_file = Column(String(512), nullable=True)

    def __repr__(self):
        return f"<MacTableEntry {self.mac} vlan={self.vlan} port={self.device_name}:{self.port_name}>"


# ==========================================================================
# 62443 CHECK REFERENCE TABLE
# ==========================================================================
#
# Entries verified directly against the OT Firewall Review 62443
# Checklist workbook (73 rows, openpyxl cell read, not markdown preview).
# Previous version inherited SR references from the pre-workbook project
# brief; on comparison, 12 of 16 had wrong SR values, wrong checklist IDs,
# or both. Detailed per-entry reasoning below.
#
# SR FORMAT NOTE: workbook cells use the full document-qualified form
# "3-3 SR X.Y" (where "3-3" = IEC 62443-3-3) and "2-1 NET X.Y" (where
# "2-1" = IEC 62443-2-1). Code uses the abbreviated form ("SR X.Y",
# "2-1 NET X.Y") which is the standard way these are cited in findings
# and reports. "SR X.Y" and "3-3 SR X.Y" are the same requirement.
# SRs numbered "3.X", "7.X", "8.X", "9.X" etc. DO NOT EXIST as 3-3 SR
# references - those were checklist row IDs being misused as SR numbers.
CHECK_TYPE_REFERENCE = {
    # ------------------------------------------------------------------ real-time --

    # 2.1: "No direct IT to Level 1/2 path" → SR 5.1 RE2 ✓
    # 2.2: "No flow bridges the DMZ end-to-end" → SR 5.2 (was wrongly SR 5.1 RE2)
    "it_ot_bypass":         ("SR 5.1 RE2, SR 5.2",    "2.1, 2.2",       "critical", "real_time"),

    # 3.7: "Internet egress from OT zones blocked" → SR 5.1 RE2 ✓
    # 9.11: "Firewall DNS points to internal resolvers" → SR 5.1 RE2, SR 7.6 ✓
    # 9.12: "Signature/firmware updates from internal source" → SR 5.1 RE2, SR 3.4 ✓
    "ot_internet_egress":   ("SR 5.1 RE2",            "3.7, 9.11, 9.12","high",     "real_time"),

    # 4.1: "All remote access terminates in the DMZ (jump host)" → SR 1.13 ✓
    "remote_access_bypass": ("SR 1.13",               "4.1",             "critical", "real_time"),

    # 4.5: "Remote access applications are approved" → 2-1 NET 3.1
    # WAS: "NET 3.1" (missing document prefix "2-1"); format fix only
    "remote_access_app":    ("2-1 NET 3.1",           "4.5",             "high",     "real_time"),

    # WAS: checklist_id "5.1, 9.5" and SR "SR 1.11, 2.8" — both wrong.
    # Workbook 5.1 = "Management access restricted to zone" (not auth failure)
    # Workbook 5.5 = "Account lockout, admin timeout, login banner" → SR 1.11, SR 1.12 ✓
    # Workbook 9.5 = "Admin access only from dedicated admin workstations" → SR 2.1 ✓
    # SR 2.8 was wrong (that's the logging SR, not the auth-failure SR)
    "auth_failure":         ("SR 1.11, SR 1.12, SR 2.1", "5.5, 9.5",    "high",     "real_time"),
    # 9.5 (admin-workstation path): same checklist/SR as auth_failure but split into a
    # distinct check_name (I-5) so their dedup keys never collide — a login from a
    # non-approved host has a different source-ref namespace than an outright failure.
    "auth_from_non_admin_host": ("SR 2.1",               "9.5",          "high",     "real_time"),

    # 6.2: "Admin logins and configuration changes logged" → SR 2.8, SR 2.12
    # WAS: "SR 2.8, 7.6" — SR 7.6 is wrong (it's a change-control SPE requirement,
    # not an audit-log SR). Real second SR is 2.12 (audit log protection).
    "fw_config_change":     ("SR 2.8, SR 2.12",       "6.2",             "high",     "real_time"),

    # 3.12: "Industrial protocol DPI used where available" → SR 5.2, SR 3.5
    # WAS: "SR 6.2" — that's the alerting SR (check 6.5), completely wrong
    "ips_ot_conduit":       ("SR 5.2, SR 3.5",        "3.12",            "high",     "real_time"),

    # 8.4: "Industrial write/program operations only from authorized hosts" → SR 2.1, SR 3.5 ✓
    # Two distinct checks for 8.4: this one (traffic-log port matching from FortiAnalyzer,
    # works without a pcap) and traffic_findings.py's "unauthorized_industrial_write"
    # (decoded from ProtocolDetail write operations, requires a pcap - more precise).
    # Kept separate so both sources corroborate rather than one silently replacing the other.
    "unauth_ot_write":      ("SR 2.1, SR 3.5",        "8.4",             "critical", "real_time"),

    # 8.8: "Scanning or anomalous traffic volumes" → SR 6.2, SR 7.1
    # WAS: "SR 6.2" only — missing SR 7.1 (availability/monitoring requirement)
    "scanning_denied":      ("SR 6.2, SR 7.1",        "8.8",             "medium",   "real_time"),

    # 6.3: "Logs forwarded to SIEM/log server with adequate retention" → SR 6.1, SR 2.9
    # WAS: "SR 2.9, 2.10" — SR 2.10 is wrong (it's audit non-repudiation), missing SR 6.1
    "log_silence":          ("SR 6.1, SR 2.9",        "6.3",             "high",     "real_time"),

    # 7.4: "HA/failover configured and tested where required" → SR 7.1, SR 7.2 ✓
    "ha_system_error":      ("SR 7.1, SR 7.2",        "7.4",             "medium",   "real_time"),
    # 7.4 (B-12): the active member of a registered active-passive FGCP
    # cluster changed (app.site_devices.track_member_activity).  Low - a
    # failover is the HA design working, recorded for audit; real_time, so
    # it is never auto-closed (stays until a human acknowledges / closes it).
    "ha_failover":          ("SR 7.1, SR 7.2",        "7.4",             "low",      "real_time"),

    # ----------------------------------------------------------- periodic review --

    # 8.1: "Flow matrix built from PCAP matches documented required comms" → ZCR 3; 2-1 NET 1.2
    # 8.2: "Cross-zone flows with no documented requirement identified" → SR 5.2
    # WAS: "SR 8.1, 8.2" — those SR numbers don't exist; checklist IDs were misused as SRs
    "conduit_matrix_drift": ("SR 5.2, ZCR 3",         "8.1, 8.2",        "medium",   "periodic_review"),
    # N-15: conduit_matrix_drift now compares observed sessions against the
    # ACTIVE baseline's ApprovedCommsEntry set (true matrix drift). The old
    # behaviour - observed session with no permitting firewall rule (via
    # topology_diff) - keeps its own check_name so nothing is lost.
    "session_no_permitting_rule": ("SR 5.2",          "8.1, 8.2",        "medium",   "periodic_review"),

    # 3.8: "Unused rules identified for removal" → SR 7.7; 2-1 SPE 2 (CM)
    # WAS: "SR 3.8" — doesn't exist; checklist ID misused as SR number
    "unused_policy":        ("SR 7.7",                "3.8",             "low",      "periodic_review"),
    # 3.8 also covers administratively DISABLED rules (FortiOS status disable,
    # pfSense <disabled/>, PAN-OS disabled yes, ASA inactive): unused by
    # declaration, straight from config. Separate check_name so evidence
    # source (config vs traffic/logs) and dedup stay independent.
    "disabled_rule":        ("SR 7.7",                "3.8",             "low",      "periodic_review"),

    # 3.1: "Default deny with explicit allow rules only" → SR 5.2 RE1
    # WAS: "SR 3.1" — doesn't exist; checklist ID misused as SR number
    "denied_trend":         ("SR 5.2 RE1",            "3.1",             "info",     "periodic_review"),

    # 3.5: "Insecure services blocked or justified" → SR 7.7, SR 4.1; 2-1 NET 1.7
    # WAS: "SR 3.5" — doesn't exist; checklist ID misused as SR number
    # Cleartext protocols (incl. cleartext management: Telnet, SNMP v1/v2c)
    "cleartext_protocol":   ("SR 7.7, SR 4.1",        "3.5",             "medium",   "periodic_review"),

    # 5.1 "Management access restricted to zone" + 5.2 "Encrypted management
    # protocols only" → SR 1.3, SR 5.1 RE1, SR 4.1. Management protocol (SSH,
    # Telnet, SNMP, RDP, VNC, WinRM, HTTPS-alt) seen crossing a zone boundary.
    # Base medium; high for a cleartext one (also reported as cleartext_protocol).
    "mgmt_protocol":        ("SR 1.3, SR 5.1 RE1, SR 4.1", "5.1, 5.2",   "medium",   "periodic_review"),

    # 7.3: "OT can operate autonomously if IT/external links are lost" → 2-1 NET 1.4
    # 9.2: "OT does not depend on the corporate (IT) Active Directory" → SR 5.1 RE2, SR 1.1; 2-1 NET 1.4
    # WAS: "SR 7.3, 9.2" — don't exist; checklist IDs misused as SR numbers
    # Use the union of the 3-3 SRs from both rows (SR 5.1 RE2, SR 1.1)
    "ot_it_dependency":     ("SR 5.1 RE2, SR 1.1",   "7.3, 9.2",        "low",      "periodic_review"),

    # 8.3: "Cleartext credentials not transmitted in the clear" → SR 4.1, SR 3.1
    # Previously borrowed "cleartext_protocol" (3.5) as a placeholder because no
    # dedicated entry existed. 8.3 is specifically about credential exposure in
    # cleartext protocols (telnet, ftp, http basic-auth), distinct from 3.5 which
    # covers the broader "insecure services blocked or justified" question.
    "cleartext_credentials": ("SR 4.1, SR 3.1",      "8.3",             "high",     "periodic_review"),

    # 8.6: "All devices accounted for in asset inventory" → SR 7.8
    # Previously borrowed "conduit_matrix_drift" (8.1/8.2) because no dedicated
    # entry existed. 8.6 is device inventory completeness — unknown host observed
    # on the network that doesn't appear in the approved asset list.
    "unknown_device":       ("SR 7.8",               "8.6",             "medium",   "periodic_review"),

    # 8.7: "IP conflicts / duplicate addresses" → SR 7.8
    # Previously borrowed "conduit_matrix_drift" (8.1/8.2). 8.7 is specifically
    # IP/MAC binding conflicts — same IP with multiple distinct MACs, which may
    # indicate ARP spoofing, device replacement, or misconfiguration.
    "ip_conflict":          ("SR 7.8",               "8.7",             "high",     "periodic_review"),

    # 2.7: "No devices in the wrong zone (OT equipment in IT zone)" → SR 5.1, SR 7.8
    # Previously borrowed "conduit_matrix_drift" (8.1/8.2) because no dedicated entry
    # existed. 2.7 is zone placement correctness for OT assets specifically.
    "misplaced_device":     ("SR 5.1, SR 7.8",       "2.7",             "high",     "periodic_review"),

    # 3.9: "Shadowed, redundant and conflicting rules identified" → SR 7.6
    # Previously borrowed "unused_policy" (3.8) because no dedicated entry existed.
    # 3.9 is specifically about rule shadowing/redundancy/conflict analysis, distinct
    # from 3.8 (unused rules) which is the simpler "last-matched never" check.
    "shadow_rule":          ("SR 7.6",               "3.9",             "medium",   "periodic_review"),

    # 3.5 (extension): SMBv1 specifically detected in cross-zone traffic.
    # check_name "cleartext_protocol" covers the generic port-based insecure
    # services check (3.5).  "smbv1_legacy" is the packet-level confirmation
    # that traffic on port 445/139 is actually SMBv1 (not just SMB-capable),
    # which is a stronger finding: SMBv1 is EoL, unpatched against
    # EternalBlue/MS17-010, and has no legitimate use in modern OT environments.
    # Still maps to checklist 3.5 and SR 7.7/4.1 — same workbook row, cleaner
    # evidence and higher severity than the port-only heuristic.
    "smbv1_legacy":         ("SR 7.7, SR 4.1",       "3.5",             "high",     "periodic_review"),

    # -------------------------------------------------------- Phase 2 additions (LLDP-role-enabled) --
    # These checks require Host.role to be populated by classify_hosts_by_lldp_role()
    # (mechanism 4 in device_classification.py, triggered after switch config ingest).
    # Without role data they produce no findings rather than false-positives.

    # 2.3: "Historian server placed in Site Operations zone (Level 3), not in
    # control zone (Level 1/2)" → SR 5.1, SR 7.8 — historian in wrong Purdue level
    "historian_in_control_zone": ("SR 5.1, SR 7.8",  "2.3",             "high",     "periodic_review"),

    # 2.5: "All management access to OT equipment restricted to a dedicated
    # management zone/VLAN, not directly from IT or internet" → SR 1.3, SR 5.1
    "mgmt_access_not_restricted": ("SR 1.3, SR 5.1", "2.5",             "medium",   "periodic_review"),

    # 2.6: "No wireless access points found in OT/control zones" → SR 7.7
    # Fires when a host with role "ap" or "wireless" is classified as Purdue L0-L2.
    "wireless_in_ot_zone":   ("SR 7.7",               "2.6",             "high",     "periodic_review"),

    # 5.1: "Management access restricted to zone - only from approved management
    # networks" → SR 1.3, SR 5.1 RE1 — sessions to firewall/switch management
    # ports from hosts not in an approved management zone.
    "mgmt_access_from_wrong_zone": ("SR 1.3, SR 5.1 RE1", "5.1",        "medium",   "periodic_review"),

    # 7.1: "Critical connections have redundant paths" → SR 7.7, SR 7.1
    # Fires when a host classified as plc/rtu/hmi has only a single switch
    # interface (no redundant uplink) - single point of failure for critical OT.
    "single_path_critical_device": ("SR 7.7, SR 7.1", "7.1",            "medium",   "periodic_review"),

    # 7.2: "Redundant paths verified by test or continuous monitoring" → SR 7.1, SR 7.2
    # Fires when HA config is absent (from forti_config_parser) AND no redundant
    # uplinks are visible from LLDP data for core/distribution switches.
    "no_path_redundancy_verified": ("SR 7.1, SR 7.2", "7.2",            "low",      "periodic_review"),

    # 7.7: "Asset inventory complete: all discovered devices match the documented
    # inventory" → SR 7.8 — fires on any host where LLDP/CDP identifies a role
    # but no matching ApprovedHost inventory entry exists for that IP/MAC.
    "undocumented_lldp_device": ("SR 7.8",            "7.7",             "medium",   "periodic_review"),

    # 7.8: "OT device firmware versions are documented and current" → SR 7.8, SR 2.2
    # Fires when a host has a known role (plc/rtu/hmi) and neighbor_platform
    # data is present (firmware/version visible in CDP platform string) but
    # that version is not in the ApprovedHost notes / baseline.
    "firmware_not_documented":  ("SR 7.8, SR 2.2",   "7.8",             "low",      "periodic_review"),

    # ---------------------------------------------------------- Phase 3: attestation-backed --
    # Section 1 (Zone Documentation) rows require human review of policy/design
    # artifacts.  Satisfied when a current Attestation row exists (< 365 days old).
    # review_zone_documentation() in alert_engine.py handles all six.

    # 1.1: "OT zones are formally defined and documented" → SR 5.1
    "zone_doc_1_1":             ("SR 5.1",            "1.1",             "high",     "periodic_review"),
    # 1.2: "Zones are defined by risk/consequence" → SR 5.1
    "zone_doc_1_2":             ("SR 5.1",            "1.2",             "high",     "periodic_review"),
    # 1.3: "Zone boundaries are enforced by controls (FW/VLAN)" → SR 5.1 RE1, SR 5.2
    "zone_doc_1_3":             ("SR 5.1 RE1, SR 5.2", "1.3",            "high",     "periodic_review"),
    # 1.4: "Communication conduits between zones are documented" → SR 5.2, ZCR 3
    "zone_doc_1_4":             ("SR 5.2, ZCR 3",     "1.4",             "medium",   "periodic_review"),
    # 1.5: "Security requirements are defined per zone" → SR 5.1, SR 1.1
    "zone_doc_1_5":             ("SR 5.1, SR 1.1",    "1.5",             "medium",   "periodic_review"),
    # 1.6: "Zone documentation has been reviewed and approved" → 2-1 SPE 2
    "zone_doc_1_6":             ("2-1 SPE 2",         "1.6",             "medium",   "periodic_review"),

    # 9.3: "OT devices sync NTP from a dedicated internal NTP server, not
    # directly from the internet or FortiGuard." → SR 7.6, 2-1 NET 1.4
    # Data sources: FortiGate config system ntp (config parse) +
    # NetworkSession rows with dst_port==123, transport=="udp" (pcap).
    "ntp_sync":                 ("SR 7.6, 2-1 NET 1.4", "9.3",           "medium",   "periodic_review"),

    # 3.10: "Policy references only concrete, resolvable address objects —
    # no FQDN or wildcard-FQDN objects in OT firewall policy" → SR 7.6
    # FQDN-based rules are unresolvable at parse time, excluded from shadow
    # and reachability analysis, and introduce DNS dependency into the OT
    # zone security boundary.  Wildcard-FQDN objects (*.vendor.com) are even
    # broader: they can match any sub-domain and cannot be audited statically.
    # In a well-run ISA-99 network, all OT firewall rules should reference
    # concrete CIDR objects; the presence of FQDN objects indicates either a
    # policy hygiene issue or an IT-style rule that was not reviewed for OT.
    # owner 2026-10-12: no workbook row covers FQDN objects (3.10 is rule documentation) -
    # no checklist row, judged by its SR
    "fqdn_in_policy":           ("SR 7.6",               "",              "medium",   "config_review"),

    # ---------------------------------------- Phase 5: NetworkSession-based fallback checks --
    # These run periodically when FortiAnalyzer is unavailable, using observed
    # NetworkSession rows (5-tuple pcap data) instead of FAZ deny/allow logs.
    # They share the same ISA/IEC 62443 SR references and checklist rows as their
    # real-time counterparts but use distinct check_names so their findings are
    # categorized as "periodic_review" and never collide in source_ref dedup with
    # FAZ-derived real-time findings.

    # 2.1/2.2: IT-to-OT bypass via observed sessions (no deny-side visibility)
    # Counterpart to real-time "it_ot_bypass" (SR 5.1 RE2, SR 5.2)
    "session_it_ot_bypass":      ("SR 5.1 RE2, SR 5.2",  "2.1, 2.2",       "critical", "periodic_review"),

    # 3.7: OT device observed sending traffic to public internet IP
    # Counterpart to real-time "ot_internet_egress" (SR 5.1 RE2)
    "session_ot_internet_egress": ("SR 5.1 RE2",          "3.7, 9.11, 9.12","high",     "periodic_review"),

    # 4.1: External or non-jump-host remote access bypassing DMZ
    # Counterpart to real-time "remote_access_bypass" (SR 1.13)
    "session_remote_access_bypass": ("SR 1.13",           "4.1",             "critical", "periodic_review"),

    # 8.8: High session-volume anomaly from a single source (no deny data)
    # Counterpart to real-time "scanning_denied" (SR 6.2, SR 7.1)
    "session_scanning_anomaly":  ("SR 6.2, SR 7.1",       "8.8",             "medium",   "periodic_review"),
    # FO-06: a remote-access tool seen in captured traffic (TeamViewer, AnyDesk ...)
    "session_remote_access_app": ("2-1 NET 3.1, SR 1.13",  "4.5",             "high",     "periodic_review"),
    "engineering_access_unapproved": ("SR 2.1, SR 1.3",   "8.4",             "medium",   "periodic_review"),

    # 5.5/9.5: Sessions to management ports from non-admin hosts (network-visible only)
    # Counterpart to real-time "auth_failure" / "auth_from_non_admin_host" (SR 1.11, SR 2.1)
    "session_mgmt_from_non_admin": ("SR 1.11, SR 1.12, SR 2.1", "5.5, 9.5", "high",    "periodic_review"),

    # ---- Phase 5: VLAN topology checks --
    # 2.7: "Host VLAN does not match the zone its traffic suggests"
    # Fires when a host's protocol-inferred purdue_level disagrees with the
    # purdue_level propagated from SwitchVlan (keyword_inferred or firewall_propagated).
    # SR 5.1 RE2 (zone isolation) / SR 5.2 (deny-by-default); checklist 2.7.
    "vlan_zone_mismatch":    ("SR 5.1 RE2, SR 5.2",     "2.7",             "high",     "periodic_review"),

    # 8.6: "MAC traffic observed on a VLAN the switch marks inactive"
    # A ghost VLAN is a strong indicator of a misconfiguration, rogue device,
    # or unmanaged segment - any of which is a 62443-3-3 zone-integrity issue.
    # SR 6.2 (audit log / anomaly detection); checklist 8.6.
    "ghost_vlan":            ("SR 6.2",                  "8.6",             "high",     "periodic_review"),

    # 2.1/2.2: "Firewall carries sibling VLAN sub-interfaces that cross IT/OT zone boundary
    #            but no explicit FirewallRule covers that conduit pair"
    # When port3.10 (OT, L1/L2) and port3.20 (IT, L3/L4) are 802.1Q siblings on the same
    # physical trunk the firewall is the SOLE zone-boundary enforcement point.
    # A missing or implicit-deny-without-log policy means no audit trail and no enforcement.
    # SR 5.1 RE2 (zone isolation) / SR 5.2 (deny-by-default); checklist 2.1, 2.2.
    "intervlan_routing_unchecked": ("SR 5.1 RE2, SR 5.2", "2.1, 2.2", "critical", "periodic_review"),

    # ---------------------------------------------------------- Phase 6: FirewallRule-based twins --
    # These checks scan FirewallRule rows (parsed policy) for dangerous permit entries
    # that exist regardless of whether traffic has been observed.  Severity escalates
    # from "medium"/"high" → "critical" when a matching NetworkSession row is also found,
    # meaning the policy gap has actually been exploited by live traffic.
    #
    # All six are "periodic_review" and use distinct check_names from their
    # traffic-only counterparts so findings from both sources are never deduplicated
    # against each other.

    # 3.5 (rule): Permit rule allows a cleartext protocol across zone boundary
    # Base: medium → critical when confirmed by matching NetworkSession traffic
    "rule_cleartext_protocol":  ("SR 7.7, SR 4.1",        "3.5",             "medium",   "periodic_review"),

    # 5.1/5.2 (rule): Permit rule allows a management protocol across zone boundary
    # Base: medium → high for a cleartext management protocol (Telnet, SNMP;
    # also reported as rule_cleartext_protocol) → critical when traffic is observed
    "rule_mgmt_protocol":       ("SR 1.3, SR 5.1 RE1, SR 4.1", "5.1, 5.2", "medium",  "periodic_review"),

    # 8.3 (rule): Permit rule allows cleartext credential protocol to OT-zone destination
    # Base: high → critical when confirmed by matching NetworkSession traffic
    "rule_cleartext_creds":     ("SR 4.1, SR 3.1",        "8.3",             "high",     "periodic_review"),

    # 7.3/9.2 (rule): Permit rule allows OT-zone src to reach IT service ports
    # Base: low → medium when confirmed by matching NetworkSession traffic
    "rule_ot_it_dependency":    ("SR 5.1 RE2, SR 1.1",    "7.3, 9.2",        "low",      "periodic_review"),
    "rule_dns_external":        ("SR 5.1 RE2, SR 7.6",    "9.11",            "medium",   "periodic_review"),

    # 5.1 (rule): Permit rule allows management protocol to OT-zone dst from non-approved src CIDR
    # Base: medium → high when confirmed by matching NetworkSession traffic
    "rule_mgmt_wrong_zone":     ("SR 1.3, SR 5.1 RE1",    "5.1",             "medium",   "periodic_review"),

    # 2.1/2.2 (rule): Permit rule allows direct IT-zone (L≥3) src to OT deep-zone (L≤1) dst
    # Base: high → critical when confirmed by matching NetworkSession traffic
    "rule_it_ot_bypass":        ("SR 5.1 RE2, SR 5.2",    "2.1, 2.2",        "high",     "periodic_review"),

    # 8.1/8.2 (rule): Permit rule with no matching ApprovedCommsEntry in the active baseline
    # Companion to "conduit_matrix_drift" (traffic-side) - policy-side gap
    # Base: medium → high when confirmed by matching NetworkSession traffic
    "rule_conduit_drift":       ("SR 5.2, ZCR 3",         "8.1, 8.2",        "medium",   "periodic_review"),

    # 3.2/3.5 (Access Review, docs/access-path-review.md phase 4): a permitted
    # communication path the reviewer classified "permissive". Raised by
    # app.parsers.access_path_findings (deduped on the path's tag_key) and
    # kept in sync by alert_engine._review_access_path_classifications.
    # SRs = config_permit_any_any_any (SR 5.2, SR 7.7) + rule_cleartext_protocol
    # (SR 7.7, SR 4.1). Base: medium -> high when seen in capture and flagged
    # permit_any / cleartext_protocol / mgmt_protocol.
    "access_path_permissive":   ("SR 5.2, SR 7.7, SR 4.1", "3.2, 3.5",       "medium",   "periodic_review"),

    # 2.1/2.2 (chain, D-05): a CHAIN of permit policies across >= 2 firewalls
    # together lets an IT-side source reach L0/L1 (or L4/L5 reach L2) in one
    # routed session; no single policy spans the crossing, so the rule twin
    # cannot see it.  Raised from the Access Review rows by
    # app.parsers.chain_findings.  Base: medium (L2) / high (deep OT) ->
    # one step up when the path is seen in the capture
    "chain_it_ot_bypass":       ("SR 5.1 RE2, SR 5.2",    "2.1, 2.2",        "high",     "periodic_review"),

    # 5.1 (chain, D-05): management protocol from the IT side to OT through
    # a chain of policies across >= 2 firewalls.  Base: medium -> high when
    # seen; DMZ-only source one step lower
    "chain_mgmt_wrong_zone":    ("SR 1.3, SR 5.1 RE1",    "5.1",             "medium",   "periodic_review"),

    # 2.1/2.2 (chain, G-02): OT reaching the IT side in one routed session -
    # L0/L1 to L3+ or L2 to L4/L5 - the upward mirror of chain_it_ot_bypass.
    # Base: medium -> high when seen in the capture
    "chain_ot_upward_skip":     ("SR 5.1 RE2, SR 5.2",    "2.1, 2.2",        "medium",   "periodic_review"),

    # 7.4 (HA): a non-primary member of a declared HA cluster runs a policy
    # that differs from the primary's - a failover changes what is enforced.
    # Base: medium; high when a permit is involved
    "ha_config_drift":          ("SR 7.6, SR 7.2",        "7.4",             "medium",   "periodic_review"),

    # 2.1 / 2.2 (chain reviews, MP-08): the permitted-path enumeration hit
    # its row budget (IACS_MAX_ACCESS_PATH_ROWS), so the chain reviews ran on
    # a partial list and may have missed crossings.  Informational; closes
    # when a run completes the list.
    "access_path_enumeration_truncated": ("SR 7.1", "2.1, 2.2",       "info",     "periodic_review"),

    # 1.3 (manual): a declared paired firewall (one boundary, firewalls in
    # series) without a current operator attestation that its members are of
    # different vendors (checklist id PF-<group id>).  Defence in depth
    # against a common-mode failure; acknowledging the finding accepts a
    # single-vendor pair as a documented risk.
    "paired_firewall_vendor_diversity": ("SR 5.1, SR 5.2", "1.3",          "low",      "periodic_review"),

    # 3.8 (chain): a permit whose traffic is dropped at the next boundary - the
    # destination lies beyond what the chain reaches.  Legacy leftover,
    # half-finished change or over-broad rule: investigate.  Base: low;
    # medium when the capture shows attempts
    "dead_end_permit":          ("SR 7.7, SR 5.2",        "3.8",             "low",      "periodic_review"),

    # ---------------------------------------------------------------- A-16 --
    # Check names written by modules that build Finding rows directly (with
    # inline SR metadata) rather than through alert_engine._make_finding.
    # Registered so every check_name in the findings table has a reference
    # entry (GET reference table, UI legends, tests/test_audit_engine2.py
    # scans app/ for check names and asserts they are all registered).
    # Values mirror the creation sites; severity is the default/base value
    # (some sites vary it per finding, e.g. cross_fw_missing_deny_all is
    # info when an implicit deny exists).
    # cross_fw_findings.py
    "cross_fw_no_rules": ("SR 5.1", "5.1", "high", "config_review"),
    "cross_fw_missing_deny_all": ("SR 5.1 RE1", "5.1", "high", "config_review"),
    "cross_fw_any_any_permit": ("SR 5.1 RE1", "5.1", "critical", "config_review"),
    "cross_fw_asymmetric_permit": ("SR 5.2", "5.2", "medium", "config_review"),
    # traffic_findings.py
    "unauthorized_industrial_write": ("SR 2.1, SR 3.5", "8.4", "critical", "periodic_review"),
    # forti_config_parser.py
    "config_logging_disabled": ("SR 2.8", "6.1", "high", "config_review"),
    "config_permit_any_any_any": ("SR 5.2, SR 7.7", "3.2", "critical", "config_review"),
    "config_industrial_dpi_missing": ("SR 5.2, SR 3.5", "3.12", "medium", "config_review"),
    "config_vpn_no_routing_policy": ("SR 1.13", "4.1", "medium", "config_review"),
    "config_vpn_direct_to_ot": ("SR 1.13", "4.1", "critical", "config_review"),
    "config_vpn_destination_unclear": ("SR 1.13", "4.1", "medium", "config_review"),
    "config_vpn_source_unrestricted": ("SR 1.13 RE1", "4.3", "high", "config_review"),
    "config_remote_session_not_logged": ("SR 2.8", "4.6", "medium", "config_review"),
    # Owner 2026-10-12: FortiGuard DNS / NTP is the vendor's own service - info on a
    # firewall with a WAN leg, low on an internal OT firewall; DNS low with FQDN permit
    # rules, medium when they lead into OT; a third-party public resolver stays medium.
    "config_dns_external": ("SR 5.1 RE2, SR 7.6", "9.11", "medium", "config_review"),
    "config_ntp_fortiguard": ("SR 2.11", "6.4", "info", "config_review"),
    "config_no_internal_segmentation": ("SR 5.1", "2.4", "medium", "config_review"),
    "config_wireless_not_isolated": ("SR 1.6", "2.5", "high", "config_review"),
    "config_possible_dual_homed": ("SR 5.1", "2.6", "high", "config_review"),
    "config_overly_broad_subnet": ("SR 5.2", "3.3", "low", "config_review"),
    "config_same_zone_rule": ("SR 5.2", "3.4", "low", "config_review"),
    "config_email_web_to_ot": ("SR 5.3", "3.6", "medium", "config_review"),
    "config_vpn_no_idle_timeout": ("SR 2.6", "4.4", "medium", "config_review"),
    "config_vpn_idle_timeout_long": ("SR 2.6", "4.4", "low", "config_review"),
    "config_mgmt_not_restricted_to_mgmt_zone": ("SR 5.1", "5.1", "medium", "config_review"),
    "config_insecure_mgmt_protocol": ("SR 4.1, SR 3.1", "5.2", "high", "config_review"),
    # G-03: switch running-config hardening (app.parsers.switch_hardening)
    "switch_snmp_default_community": ("SR 1.5, SR 4.1", "5.4", "high", "config_review"),
    "switch_snmp_cleartext_community": ("SR 4.1, SR 1.5", "5.2", "low", "config_review"),
    "switch_insecure_mgmt_protocol": ("SR 4.1, SR 3.1", "5.2", "high", "config_review"),
    "config_no_password_policy": ("SR 1.5, SR 1.7", "5.4", "high", "config_review"),
    "config_weak_password_policy": ("SR 1.5, SR 1.7", "5.4", "medium", "config_review"),
    "config_no_admin_lockout": ("SR 1.11, SR 1.12", "5.5", "high", "config_review"),
    "config_admin_lockout_threshold_high": ("SR 1.11, SR 1.12", "5.5", "medium", "config_review"),
    "config_no_admin_idle_timeout": ("SR 1.11, SR 1.12", "5.5", "medium", "config_review"),
    "config_admin_idle_timeout_long": ("SR 1.11, SR 1.12", "5.5", "low", "config_review"),
    "config_unused_interface_not_disabled": ("SR 7.7", "5.7", "low", "config_review"),
    "config_admin_no_trusted_hosts": ("SR 5.1, SR 2.1", "5.8", "high", "config_review"),
    # 6.3 (owner 2026-10-12; was 6.5): no off-box destination at all - syslog 1-4,
    # FortiAnalyzer 1-3 / Cloud, FortiGate Cloud each count
    "config_no_syslog_forwarding": ("SR 6.1, SR 6.2, SR 2.9", "6.3", "high", "config_review"),
    # 6.1 / 6.2: one finding per firewall listing what it does not log or send
    # (implicit deny, local-in deny, event categories, traffic filters, utm-only
    # policies, logs to an Internet service); low when only the cloud note
    "config_monitoring_readiness": ("SR 2.8, SR 6.1, SR 6.2", "6.1, 6.2", "medium", "config_review"),
    "config_fail_open_enabled": ("SR 5.2 RE3", "7.1", "critical", "config_review"),
    "config_broadcast_cross_zone": ("SR 5.1, SR 7.7", "8.5", "medium", "config_review"),
    "config_split_tunneling_enabled": ("SR 1.13, SR 5.1", "9.1", "medium", "config_review"),
    "config_vpn_shared_access": ("SR 2.8, SR 1.1", "4.3", "low", "config_review"),
    # DR-08 / DR-09 / DR-11 (real-config review 2026-10-07)
    "config_local_in_permits_all": ("SR 5.1, SR 2.1", "5.8", "medium", "config_review"),
    "config_ipsec_peer_unrestricted": ("SR 1.2, SR 1.9", "4.2", "medium", "config_review"),
    "config_ipsec_dialup_psk": ("SR 1.2, SR 1.1", "4.2", "low", "config_review"),
    "config_service_protocol_mismatch": ("SR 5.2", "3.3", "low", "config_review"),
    "config_no_central_auth": ("SR 1.1, SR 1.3", "9.4", "medium", "config_review"),
    "config_maintainer_account_enabled": ("SR 2.1", "9.7", "high", "config_review"),
    "config_maintainer_named_account": ("SR 2.1", "9.7", "medium", "config_review"),
    "config_weak_tls_version": ("SR 4.1", "9.8", "high", "config_review"),
    "config_ha_no_auth": ("SR 3.1", "9.9", "medium", "config_review"),
    # batch A (Evidence Automation Matrix, owner 2026-10-15)
    "config_strong_crypto_disabled": ("SR 4.3, SR 4.1", "9.8", "medium", "config_review"),
    "config_snmp_v1v2c_enabled": ("SR 4.1, SR 1.5", "5.2", "medium", "config_review"),
    "config_snmp_default_community": ("SR 1.5, SR 4.1", "5.4", "high", "config_review"),
    "config_admin_no_two_factor": ("SR 1.7, SR 1.1 RE1", "9.4", "medium", "config_review"),
    "config_fortimanager_admin_access": ("SR 1.1, SR 1.13", "9.4", "info", "config_review"),
    "config_admin_profile_overprivileged": ("SR 2.1, SR 1.3", "9.4", "medium", "config_review"),
    "config_no_login_banner": ("SR 1.12", "5.5", "low", "config_review"),
    "config_ha_no_monitor_interfaces": ("SR 7.1, SR 7.2", "7.4", "low", "config_review"),
    "config_policy_any_interface": ("SR 5.2, SR 5.1", "3.1", "medium", "config_review"),
    "config_device_detection_disabled": ("SR 7.8", "7.7", "info", "config_review"),
    "config_ntp_unauthenticated": ("SR 2.11, SR 3.1", "6.4", "low", "config_review"),
    "config_no_revision_backup": ("SR 7.3, SR 7.6", "7.5", "low", "config_review"),
    "config_vendor_rule_permanent": ("SR 1.13, 2-1 NET 3.2", "3.11", "low", "config_review"),
    "config_icmp_across_boundary": ("SR 5.2, SR 7.7", "3.5", "info", "config_review"),
    "config_implicit_deny_not_logged": ("SR 2.8, SR 6.2", "6.1", "medium", "config_review"),
    # batch B (Evidence Automation Matrix, owner 2026-10-15)
    "config_vpn_user_no_mfa": ("SR 1.7, SR 1.13 RE1", "4.3", "high", "config_review"),
    "config_weak_ipsec_crypto": ("SR 4.3, SR 4.1, SR 3.1", "4.2", "medium", "config_review"),
    "config_sslvpn_weak_tls": ("SR 4.1, SR 4.3", "4.2", "medium", "config_review"),
    "config_no_dos_policy_ot": ("SR 7.1, SR 7.2", "7.1", "low", "config_review"),
    "config_wireless_weak_security": ("SR 1.6, SR 4.1", "2.5", "medium", "config_review"),
    "sis_zone_not_isolated": ("SR 5.1, SR 5.2, 2-1 NET 1.3", "2.4", "high", "periodic_review"),
    # batch C (Evidence Automation Matrix, owner 2026-10-15)
    "transient_device_in_ot_zone": ("SR 7.8, SR 5.1, 2-1 NET 1.1", "8.6", "medium", "periodic_review"),
    "default_credentials_observed": ("SR 1.5, SR 4.1", "5.4", "high", "periodic_review"),
    "weak_tls_observed": ("SR 4.3, SR 4.1", "3.5", "medium", "periodic_review"),
    "config_syslog_unencrypted": ("SR 6.1, SR 2.9", "9.10", "medium", "config_review"),
    "config_default_hostname": ("SR 2.11", "9.13", "low", "config_review"),
    "config_no_timezone": ("SR 2.11", "9.13", "low", "config_review"),
    "config_rules_missing_owner": ("2-1 SPE 2 (CM)", "9.14", "low", "config_review"),
    "config_rsp_check_disabled": ("SR 5.2", "3.13", "medium", "config_review"),
    # owner 2026-10-12: workbook 3.10 / 3.11 are rule documentation / temporary rules -
    # IPS on a conduit -> 3.12 (inspection / DPI); antivirus has no workbook row (SR only)
    "config_ids_ips_missing": ("SR 3.3, SR 6.2", "3.12", "medium", "config_review"),
    # 3.11 (owner 2026-10-12): a policy named / commented temporary with no expiring
    # (one-time) schedule, or an enabled policy whose one-time schedule has ended
    "config_temporary_rule": ("2-1 SPE 2", "3.11", "medium", "config_review"),
    "config_av_missing_on_file_policy": ("SR 3.3, SR 3.2", "", "medium", "config_review"),
    "config_no_scheduled_backup": ("SR 7.3, SR 7.2", "7.5", "low", "config_review"),
    "config_no_av_profile": ("SR 3.2", "8.10", "medium", "config_review"),
    "config_av_profile_not_applied": ("SR 3.2", "8.10", "low", "config_review"),
    "config_admin_trusthost_too_broad": ("SR 5.1, SR 2.1", "9.5", "medium", "config_review"),
    # Admin trusted host outside every declared management network / trusted
    # management host (only judged once management networks are declared).
    "config_admin_trusthost_outside_mgmt": ("SR 5.1, SR 2.1", "9.5", "medium", "config_review"),
    # VPN tabletop (H-series): one finding per policy chain / segment
    "vpn_direct_to_ot":        ("SR 1.13, SR 5.2, SR 5.1", "4.1, 2.1", "critical", "periodic_review"),
    "dmz_bypass":              ("SR 5.1 RE2, SR 5.2",       "2.2",      "medium",   "periodic_review"),
    "path_ot_internet_egress": ("SR 5.1 RE2",               "3.7",      "high",     "periodic_review"),
    "flat_control_segment":    ("SR 5.1",                   "1.2, 1.3", "low",      "periodic_review"),
    # IO-02 / IO-04 / IO-08 (isolated OT tabletop): capture-only evidence
    "multi_homed_host":        ("SR 5.1",                   "2.6",      "high",     "periodic_review"),
    # IEC 62443-3-2 zone documentation (app/zone_findings.py): a zone pair that
    # communicates with no documented conduit (owner decision 2026-10-11)
    "undocumented_conduit":    ("SR 5.1",                   "1.4",      "medium",   "periodic_review"),
    # an asset (device by MAC) / a network documented in two or more zones (62443-3-2:
    # a zone partitions the system - every asset belongs to exactly one zone)
    "host_in_multiple_zones":  ("SR 5.1",                   "1.2",      "medium",   "periodic_review"),
    "network_in_multiple_zones": ("SR 5.1",                 "1.2",      "medium",   "periodic_review"),
    # SF-6: one firewall policy serving two or more zone pairs (several conduits in one rule)
    "policy_spans_multiple_conduits": ("SR 5.1, SR 5.2",     "3.1",      "low",      "periodic_review"),
    # SF-5: dropped connection attempts into other zones / segments; designed traffic dropped
    "blocked_cross_zone_attempts": ("SR 5.1, SR 6.2",        "8.8",      "low",      "periodic_review"),
    "conduit_service_blocked": ("SR 5.1",                    "1.4",      "info",     "periodic_review"),
    "rogue_dhcp_server":       ("SR 7.6, SR 5.1",           "8.6",      "high",     "periodic_review"),
    "dead_default_gateway":    ("SR 7.6, SR 5.1",           "3.7",      "medium",   "periodic_review"),
    "nat_hides_source_into_ot": ("SR 2.8, SR 6.2",          "6.1",      "medium",   "periodic_review"),
    "config_vip_unused":       ("SR 7.7, SR 5.2",           "3.8",      "medium",   "config_review"),
    "rule_implicit_permit":    ("SR 5.2, SR 5.1",           "3.1",      "medium",   "periodic_review"),
    "switch_routes_between_zones": ("SR 5.1 RE2, SR 5.2",   "2.1, 2.2", "high",     "periodic_review"),
    "switch_acl_wrong_direction": ("SR 5.2",                 "2.4",      "medium",   "periodic_review"),
    "switch_port_no_nac": ("SR 1.2, SR 2.1", "2.4", "low", "periodic_review"),
    "switch_unused_port_enabled": ("SR 7.7", "5.7", "low", "periodic_review"),
    "switch_mgmt_svi_unrestricted": ("SR 5.1 RE1, SR 1.3",   "5.1",      "medium",   "periodic_review"),
    "switch_dual_gateway":     ("SR 5.2",                   "2.1, 2.2", "high",     "periodic_review"),
    "config_usb_auto_install_config": ("SR 2.3, SR 3.4", "9.6", "high", "config_review"),
    "config_usb_auto_install_image": ("SR 2.3, SR 3.4", "9.6", "high", "config_review"),
    "config_updates_from_internet": ("SR 5.1 RE2, SR 3.4", "9.12", "medium", "config_review"),
    "config_auto_firmware_upgrade": ("SR 7.6, 2-1 SPE 2", "9.12", "low", "config_review"),
    "config_link_monitor_external": ("SR 7.1, SR 7.6", "7.4", "info", "config_review"),
    "config_wireless_in_ot": ("SR 1.6, SR 5.1", "2.5", "high", "config_review"),
}


class FortiAnalyzerEvent(SiteScoped, Base):
    """
    A raw event or log record received from FortiAnalyzer - either pushed
    via syslog/CEF, posted via the /ingest/forti-event REST endpoint, or
    imported from a scheduled CSV report.

    The raw fields are preserved as-is in `raw_fields` so nothing is
    irreversibly lost in normalization, but the most alert-relevant
    columns are also promoted to first-class indexed columns for fast
    queries without JSON path expressions.
    """
    __tablename__ = "fortiana_events"

    id = Column(Integer, primary_key=True)
    received_at = Column(UTCDateTime, default=utcnow, index=True)

    # Source metadata
    source_type = Column(String(16), nullable=False)  # "syslog_cef" | "api_push" | "csv_import"
    # | "syslog_asa" | "syslog_pfsense" | "syslog_panos" (F-11)
    # Log source vendor (F-11): "fortinet" | "cisco_asa" | "pfsense" | "panos"
    # (or a lower-cased CEF header vendor). NULL for rows ingested before F-11.
    vendor = Column(String(32), nullable=True)
    device_name = Column(String(255), nullable=True)  # FortiGate hostname
    log_type = Column(String(64), nullable=True)      # "traffic", "event", "utm", "ips", etc.
    subtype = Column(String(64), nullable=True)

    # Key fields promoted for indexed lookup
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    action = Column(String(32), nullable=True)        # "allow", "deny", "close", etc.
    policy_id = Column(String(64), nullable=True, index=True)
    policy_name = Column(String(255), nullable=True)
    service = Column(String(64), nullable=True)
    app = Column(String(128), nullable=True)          # for remote-access-app detection

    # For IPS events
    attack_name = Column(String(255), nullable=True)
    severity = Column(String(16), nullable=True)

    # For auth events
    user = Column(String(128), nullable=True)
    src_user = Column(String(128), nullable=True)

    # FortiAnalyzer timestamp (distinct from received_at)
    event_time = Column(UTCDateTime, nullable=True, index=True)

    # Original log message and all fields (nothing discarded)
    raw_message = Column(Text, nullable=True)  # Text avoids DataError on long CEF syslog lines
    # sha1 of (device_name, normalised raw line) - re-uploading the same log
    # file must not duplicate events (T3-06). Unique; NULL for legacy rows.
    dedup_hash = Column(String(40), nullable=True)

    # Named unique INDEX rather than column-level unique=True: migrations add
    # columns with ALTER TABLE, which SQLite can't combine with a constraint.
    __table_args__ = (
        # Per site (phase 2): the same line uploaded to two sites is two events.
        Index("ux_fortiana_events_site_dedup_hash", "site_id", "dedup_hash", unique=True),
    )
    raw_fields = _json_column(default=dict)

    # Findings sourced from this event are reachable via
    # Finding.forti_event_id (a plain FK column, no ORM relationship()
    # defined on either side - consistent with how Finding.session_id
    # and Finding.rule_id also don't have back-populated relationships).

    def __repr__(self):
        return f"<FortiAnalyzerEvent id={self.id} type={self.log_type} src={self.src_ip}->{self.dst_ip}>"


# ==========================================================================
# BASELINE / AUDIT INPUTS
# ==========================================================================

class Baseline(SiteScoped, Base):
    """
    A named, versioned snapshot of the approved/audited state of the
    network. Multiple baselines can coexist (e.g. "2024-Q4-audit",
    "2025-Q2-review") so drift between reviews is visible.

    ApprovedCommsEntry and ApprovedHost rows reference a Baseline;
    Attestation rows may (baseline_id, nullable).  FirewallRule has no
    baseline column - the approved-rules import writes owner / conduit onto
    the rule rows themselves (baseline_parser.ingest_reviewed_policies).
    """
    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)   # e.g. "2024-Q4-audit"; unique per site
    description = Column(String(1024), nullable=True)
    created_at = Column(UTCDateTime, default=utcnow)
    is_active = Column(Boolean, default=True)   # the active baseline is the one alerts compare against

    __table_args__ = (
        # Multi-site phase 2: names are unique per site and each site has at
        # most ONE active baseline (its reviews compare against it).
        Index("ux_baselines_site_name", "site_id", "name", unique=True),
        Index("ux_baselines_site_active", "site_id", unique=True,
              postgresql_where=text("is_active = true"),
              sqlite_where=text("is_active = 1")),
    )

    comms_entries = relationship("ApprovedCommsEntry", back_populates="baseline", cascade="all, delete-orphan")
    approved_hosts = relationship("ApprovedHost", back_populates="baseline", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Baseline id={self.id} name={self.name} active={self.is_active}>"


class ApprovedCommsEntry(Base):
    """
    One row of the approved communications matrix from the audit:
    a specific (src, dst, dst_port, protocol) combination that has
    been reviewed and approved. This is what the diff engine and
    conduit-matrix-drift periodic review compare observed traffic against.

    src and dst are stored as CIDRs or bare IPs (no Cisco wildcard
    masks or named objects here - by the time something goes into the
    approved comms matrix it should be resolved to actual addresses).
    """
    __tablename__ = "approved_comms"

    id = Column(Integer, primary_key=True)
    baseline_id = Column(Integer, ForeignKey("baselines.id"), nullable=False)

    src = Column(String(64), nullable=False)           # CIDR or bare IP
    dst = Column(String(64), nullable=False)
    dst_port = Column(Integer, nullable=True)           # None = any
    # Inclusive upper bound when the approved entry is a port RANGE
    # ("1024-65535" -> dst_port=1024, dst_port_end=65535). None = single port
    # (dst_port) or any port (dst_port None). Lists ("502,102") are stored as
    # one row per port/range (T3-32).
    dst_port_end = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False, default="any")   # tcp/udp/any
    service_name = Column(String(128), nullable=True)  # human label e.g. "Modbus/TCP"
    conduit = Column(String(128), nullable=True)        # conduit name from the policy review
    owner = Column(String(128), nullable=True)

    baseline = relationship("Baseline", back_populates="comms_entries")

    __table_args__ = (
        Index("ix_approved_comms_lookup", "baseline_id", "src", "dst", "dst_port"),
    )

    def __repr__(self):
        return f"<ApprovedCommsEntry {self.src}->{self.dst}:{self.dst_port}/{self.protocol}>"


class ApprovedHost(Base):
    """
    A host in an approved role from the audit inventory:
    jump hosts, admin workstations, engineering workstations/HMIs.
    Used by the remote-access-bypass and unauth-OT-write alert checks.
    """
    __tablename__ = "approved_hosts"

    id = Column(Integer, primary_key=True)
    baseline_id = Column(Integer, ForeignKey("baselines.id"), nullable=False)

    ip = Column(String(45), nullable=True)
    mac = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)

    role = Column(String(64), nullable=False)  # "jump_host" | "remote_access_gateway" | "admin_ws" | "engineering_ws" | "hmi"
    zone = Column(String(128), nullable=True)  # network zone / segment name
    owner = Column(String(128), nullable=True)
    notes = Column(String(512), nullable=True)

    baseline = relationship("Baseline", back_populates="approved_hosts")

    def __repr__(self):
        return f"<ApprovedHost role={self.role} ip={self.ip}>"


# ==========================================================================
# MULTI-FIREWALL TOPOLOGY
# ==========================================================================

class Firewall(SiteScoped, Base):
    """
    A single firewall device in the site topology, corresponding to one
    uploaded FortiGate (or other vendor) configuration file.

    The topology is inferred incrementally (Option 2):
      - The first config uploaded creates one Firewall row; is_multi_fw
        stays False and no topology wiring is required.
      - When a second config is uploaded, is_multi_fw is set True on ALL
        Firewall rows for the site, and the topology builder runs to
        detect subnet overlaps and propose upstream/downstream links.

    upstream_firewall_id encodes the chain:
      NULL  → outermost firewall (perimeter), or single-firewall site
      N     → this firewall sits behind Firewall N (N is closer to internet)

    Purdue levels describe the zones this firewall bridges:
      purdue_level_ingress  → the less-trusted side (e.g. 3.5, the industrial DMZ)
      purdue_level_egress   → the more-trusted side (e.g. Level 3 Control LAN)
    Both are nullable until the operator assigns them during topology review.
    """
    __tablename__ = "firewalls"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)            # operator-assigned friendly name
    device_name = Column(String(255), nullable=True)      # hostname extracted from config
    vendor = Column(String(32), nullable=False, default="fortigate")
    source_file = Column(String(512), nullable=True)      # original upload filename
    config_uploaded_at = Column(UTCDateTime, default=utcnow)

    # Purdue levels for the zones this FW bridges (operator-assigned)
    purdue_level_ingress = Column(PurdueLevelType, nullable=True)  # less-trusted side
    purdue_level_egress  = Column(PurdueLevelType, nullable=True)  # more-trusted side
    # IEC 62443-4-2 capability security level of the firewall / routing
    # switch (1-4, NULL = not assessed) and its source.  Documentation only
    # (Zones & Conduits page: compared with the SL-T of the conduits it carries).
    sl_c = Column(Integer, nullable=True)
    sl_c_source = Column(String(255), nullable=True)

    # Chain linkage: NULL = outermost / unlinked
    upstream_firewall_id = Column(
        Integer, ForeignKey("firewalls.id"), nullable=True
    )

    # True once the operator has reviewed and confirmed this FW's place
    # in the topology (or once auto-detection confirms it unambiguously).
    topology_confirmed = Column(Boolean, default=False, nullable=False)

    # HA / paired-firewall grouping (operator-confirmed, FirewallGroup).
    #   ha_group_id      - this config is one member of an HA cluster (one
    #                      logical firewall: the members share a config and
    #                      traffic passes ONE of them)
    #   paired_group_id  - this firewall (or HA cluster) is one of a
    #                      "paired firewall" set enforcing one boundary in
    #                      SERIES (traffic passes ALL of them)
    ha_group_id = Column(Integer, ForeignKey("firewall_groups.id", ondelete="SET NULL"),
                         nullable=True, index=True)
    paired_group_id = Column(Integer, ForeignKey("firewall_groups.id", ondelete="SET NULL"),
                             nullable=True, index=True)
    # `config system ha` of the last uploaded config: mode (a-p / a-a) and
    # "group-name/group-id" - used to SUGGEST HA clusters, never to decide.
    ha_mode = Column(String(8), nullable=True)
    ha_cfg_group = Column(String(80), nullable=True)
    # `config system admin` trusted hosts of the last uploaded config:
    # [{username, accprofile, trusted_hosts: [cidr, ...]}].  Kept so the
    # trusthost checks can be re-judged when management networks are
    # declared later, without a re-upload.
    admin_trusthosts = _json_column(default=list, nullable=True)

    # Set True on ALL Firewall rows for the site the moment a second
    # config is uploaded.  Drives the topology-builder prompt in the UI.
    is_multi_fw = Column(Boolean, default=False, nullable=False)

    interfaces = relationship(
        "FirewallInterface",
        back_populates="firewall",
        cascade="all, delete-orphan",
    )
    # B-07: FortiOS zone definitions (members per VDOM)
    zone_defs = relationship(
        "FirewallZoneDef",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    upstream = relationship(
        "Firewall",
        remote_side="Firewall.id",
        foreign_keys=[upstream_firewall_id],
    )

    __table_args__ = (
        # Multi-site phase 2: a firewall name identifies one firewall per site
        # (config re-ingest replaces the site's firewall of that name).
        Index("ux_firewalls_site_name", "site_id", "name", unique=True),
        _purdue_check("purdue_level_ingress", "ck_firewall_ingress_purdue"),
        _purdue_check("purdue_level_egress", "ck_firewall_egress_purdue"),
    )

    def __repr__(self):
        return f"<Firewall id={self.id} name={self.name} vendor={self.vendor}>"


class NatRule(SiteScoped, Base):
    """
    Address translation configured on a firewall (F-05).

    One row per translation, normalised across vendors:
      nat_type = "dnat"  destination NAT / port-forward (FortiOS VIP,
                         PAN-OS destination translation, pfSense port forward):
                         traffic to ext_ip[:ext_port] is sent to
                         mapped_ip[:mapped_port].
      nat_type = "snat"  source NAT (FortiOS policy `set nat enable` /
                         ippool, PAN-OS source translation, pfSense outbound
                         NAT): sources matching orig_src leave as mapped_ip.
    Addresses are canonical text ("10.0.1.10/32", "any", "range:a-b");
    ports use FirewallRule.dst_port's canonical form ("any", "502", "80,443").
    Re-ingesting a firewall config replaces that firewall's NAT rows.

    N-25 additions:
      nat_kind   what produced the row: "vip", "vip46", "vip64" (address-
                 family translating DNAT: ext_ip and mapped_ip are of
                 DIFFERENT families), "policy-nat" (policy `nat enable`),
                 "central-snat" (config firewall central-snat-map).  NULL =
                 older row / other vendor (nat_type alone applies).
      dst_intf   SNAT: egress interface(s) the translation applies to.
      orig_dst   SNAT: destination address(es) the translation is limited to
                 (central-snat `dst-addr`); NULL/"any" = all.
      vdom       FortiOS VDOM the rule lives in (see FirewallRule.vdom).
    """
    __tablename__ = "nat_rules"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id", ondelete="CASCADE"), nullable=True, index=True)
    firewall_device_id = Column(Integer, ForeignKey("firewall_devices.id", ondelete="CASCADE"), nullable=True, index=True)
    device_name = Column(String(255), nullable=True)
    device_type = Column(String(32), nullable=True)
    nat_type = Column(String(8), nullable=False)          # "dnat" | "snat"
    name = Column(String(255), nullable=True)             # VIP / pool / rule name
    # B-15(b): address / interface / policy lists are stored whole (Text) -
    # a cut list would silently change what the translation matches.
    policy_id = Column(Text, nullable=True)               # policy id(s) that apply it (SNAT on FortiOS)
    protocol = Column(String(16), nullable=True)          # tcp / udp / any
    src_intf = Column(Text, nullable=True)                # where translated traffic arrives
    orig_src = Column(Text, nullable=True)                # SNAT: original sources ("any" if all)
    ext_ip = Column(Text, nullable=True)                  # DNAT: public/outside address
    ext_port = Column(String(255), nullable=True)
    mapped_ip = Column(Text, nullable=True)               # DNAT: inside address; SNAT: translated source
    mapped_port = Column(String(255), nullable=True)
    # C-04: SNAT original-port limit (FortiOS central-snat-map `orig-port`,
    # canonical FirewallRule.dst_port form - "any", "80", "1000-2000").  A
    # `nat disable` exemption or translation is limited to flows whose port
    # matches; "any"/NULL = all ports.  Ignored without a port to test
    # (never narrows a portless query to a false deny).
    orig_port = Column(String(255), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True, server_default=true())
    source_file = Column(String(512), nullable=True)
    raw = Column(Text, nullable=True)
    # N-25 / N-24
    nat_kind = Column(String(24), nullable=True)
    dst_intf = Column(Text, nullable=True)
    orig_dst = Column(Text, nullable=True)
    vdom = Column(String(64), nullable=True)
    # B-13: evaluation order within the rule's table (FortiOS: position of
    # the central-snat-map entry / VIP / policy in the config).  Rows are
    # always loaded ORDER BY (sequence, id) and SNAT / DNAT are first-match.
    sequence = Column(Integer, nullable=True)
    # B-13: an exemption entry (FortiOS central-snat-map `set nat disable`):
    # a matching flow is NOT translated and no later entry is consulted.
    nat_exempt = Column(Boolean, nullable=False, default=False, server_default=false())


class FirewallInterface(Base):
    """
    One physical or logical interface on a Firewall, extracted from
    `config system interface` during config ingest.

    side and zone_label are operator-assigned during topology review:
      side        → "outside" (less trusted) or "inside" (more trusted)
                    relative to THIS firewall's position in the chain.
      zone_label  → human name for the network segment on this interface
                    (e.g. "DMZ", "Control LAN", "Corporate IT").

    connects_to_interface_id is set when the topology builder detects (or
    the operator confirms) that this interface's subnet overlaps with another
    firewall's interface — establishing the physical link between the two
    devices. Both directions are recorded (A.dmz ↔ B.wan) so traversal
    can walk in either direction.

    HA and loopback interfaces are flagged via is_ha / is_mgmt_only so the
    topology builder and PCAP picker can hide them from operator prompts.
    """
    __tablename__ = "firewall_interfaces"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=False)

    # From config system interface
    name         = Column(String(64),  nullable=False)   # "wan1", "dmz", "internal"
    ip_address   = Column(String(45),  nullable=True)    # "10.10.10.1"
    prefix_len   = Column(Integer,     nullable=True)    # 24
    ip_cidr      = Column(String(50),  nullable=True)    # "10.10.10.1/24"  (denormalised for fast lookup)
    network_cidr = Column(String(50),  nullable=True)    # "10.10.10.0/24"  (subnet, not host)
    vlan_id      = Column(String(16),  nullable=True)
    iface_type   = Column(String(32),  nullable=True)    # "physical","vlan","loopback","tunnel","aggregate"
    role         = Column(String(32),  nullable=True)    # "wan","lan","dmz","ha","undefined" — from FortiOS role field
    allowaccess  = _json_column(default=list)            # ["https","ssh","ping"]
    status       = Column(String(16),  nullable=True)    # "up" / "down"
    alias        = Column(String(128), nullable=True)    # operator-set description in config
    vdom         = Column(String(64),  nullable=True)    # FortiOS `set vdom` (NULL = no VDOM mode)

    # Operator-assigned during topology review
    side        = Column(String(16),  nullable=True)     # "outside" | "inside"
    zone_label  = Column(String(128), nullable=True)     # "Corporate IT", "DMZ", "Control LAN"
    purdue_level = Column(PurdueLevelType, nullable=True)  # Purdue level of the segment on this side (operator)

    # Auto-suggested Purdue level (never overwrites operator-set purdue_level)
    # Set by run_purdue_suggestions() in topology_manager.py.
    # "suggestion_source" records why: "peer_link", "fw_chain", "role_heuristic"
    suggested_purdue_level  = Column(PurdueLevelType, nullable=True)
    purdue_suggestion_source = Column(String(32), nullable=True)

    # Link to the interface on the adjacent firewall (if known)
    connects_to_interface_id = Column(
        Integer, ForeignKey("firewall_interfaces.id"), nullable=True
    )
    # D-07: operator-confirmed SHARED segment (three or more firewalls on one
    # network, e.g. the DMZ switch): every member interface carries the same
    # label.  A point-to-point link uses connects_to_interface_id instead;
    # cross-firewall checks treat every pair of members as linked.
    segment = Column(String(64), nullable=True, index=True)

    # For 802.1Q VLAN sub-interfaces (e.g. FortiGate "port3.10"):
    # parent_interface_id points to the physical parent row (port3).
    # Parsed from FortiOS `set interface <parent>` in _extract_zones().
    # None for physical/aggregate interfaces (they are their own root).
    parent_interface_id = Column(
        Integer, ForeignKey("firewall_interfaces.id"), nullable=True
    )

    # Classification flags for UI filtering
    is_ha       = Column(Boolean, default=False, nullable=False)
    is_mgmt_only = Column(Boolean, default=False, nullable=False)
    # DR-03: remote-access tunnel kind - "ssl" (ssl.<vdom>) or "ipsec_dialup"
    # (a dynamic IPsec phase1 handing users addresses by mode-cfg); NULL for
    # every other interface (site-to-site tunnels included).
    remote_access = Column(String(16), nullable=True)
    # owner 2026-10-19: site-to-site IPsec tunnels - {"peer", "wan_interface", "backup_of", "members",
    # "selectors": [{"local", "remote"}]} from phase1 / phase2 / ipsec-aggregate; NULL elsewhere
    tunnel_info = _json_column(nullable=True)

    firewall = relationship("Firewall", back_populates="interfaces")
    connects_to = relationship(
        "FirewallInterface",
        remote_side="FirewallInterface.id",
        foreign_keys=[connects_to_interface_id],
    )
    parent_interface = relationship(
        "FirewallInterface",
        remote_side="FirewallInterface.id",
        foreign_keys=[parent_interface_id],
        backref="vlan_subinterfaces",
    )

    __table_args__ = (
        UniqueConstraint(
            "firewall_id", "name",
            name="uq_fw_interface_fw_name",
        ),
        _purdue_check("purdue_level", "ck_fw_iface_purdue_level"),
        _purdue_check("suggested_purdue_level", "ck_fw_iface_suggested_purdue"),
    )

    def __repr__(self):
        return (
            f"<FirewallInterface fw={self.firewall_id} "
            f"name={self.name} cidr={self.ip_cidr} side={self.side}>"
        )


class ConnectionAttempt(SiteScoped, Base):
    """
    FO-04: a connection attempt seen in a capture that never became a
    conversation - a TCP SYN answered by RST (``refused``), a SYN / SYN-ACK
    probe with no data (``open``), a SYN nobody answered (``unanswered``), or
    an ARP request for an address nobody claimed (``arp_unanswered``, no
    port).  Kept out of network_sessions so a scan is not read as traffic;
    session_scanning_anomaly counts them.  One row per (source, target,
    port, transport, outcome), with a count.  Addresses are stored as text
    (no host FK): the probed address usually has no host.
    """
    __tablename__ = "connection_attempts"

    id = Column(Integer, primary_key=True)
    pcap_capture_id = Column(Integer, nullable=True, index=True)
    src_ip = Column(String(64), nullable=False)
    src_mac = Column(String(17), nullable=True)
    dst_ip = Column(String(64), nullable=False)
    dst_port = Column(Integer, nullable=True)
    transport = Column(String(8), nullable=False, default="tcp")
    outcome = Column(String(16), nullable=False)
    count = Column(Integer, nullable=False, default=1)
    first_seen = Column(UTCDateTime, nullable=True)
    last_seen = Column(UTCDateTime, nullable=True)

    __table_args__ = (
        Index("ix_connection_attempts_src", "site_id", "src_ip"),
    )


class PcapCapture(SiteScoped, Base):
    """
    Metadata for one PCAP file upload, linking it to the specific
    firewall interface it was captured on.

    A PCAP is always captured at one point in the network — a specific
    interface of a specific firewall, on either the inside or outside
    of that interface. This record ties the captured sessions
    (NetworkSession rows) back to that capture point so cross-firewall
    analysis knows:
      - Which sessions were seen at which point
      - Whether a session was seen on both sides of a firewall
        (confirmed traversal) or only one side (dropped or originated
        internally)

    suggestion_confidence reflects how confidently the system matched
    packet IPs to the declared interface subnet:
      "high"   → >90 % of sampled IPs fall in the interface's subnet
      "medium" → 60–90 %
      "low"    → <60 %
      "none"   → no interface subnets were declared yet (single-FW mode,
                 or upload before topology confirmation)
    """
    __tablename__ = "pcap_captures"

    id = Column(Integer, primary_key=True)
    uploaded_at = Column(UTCDateTime, default=utcnow)

    # Nullable: a PCAP uploaded in single-firewall mode, or before
    # topology wiring is done, has firewall_id/interface_id set later.
    firewall_id   = Column(Integer, ForeignKey("firewalls.id"),            nullable=True)
    interface_id  = Column(Integer, ForeignKey("firewall_interfaces.id"),  nullable=True)
    side          = Column(String(16), nullable=True)   # "outside" | "inside" | None

    filename              = Column(String(512), nullable=True)
    capture_interface_raw = Column(String(128), nullable=True)  # raw name if operator typed one
    packet_count          = Column(Integer, nullable=True)
    captured_at           = Column(UTCDateTime, nullable=True)     # timestamp from first packet

    suggestion_confidence = Column(String(8),  nullable=True)   # "high"|"medium"|"low"|"none"
    suggested_interface_id = Column(
        Integer, ForeignKey("firewall_interfaces.id"), nullable=True
    )
    operator_confirmed    = Column(Boolean, default=False, nullable=False)

    # VD-02a capture point: the segment(s) the capture was taken on when it
    # is no firewall port (comma-separated CIDRs), the router / firewall
    # MACs the capture point identified (JSON list) and the last
    # associate-and-reprocess run.  A capture with neither interface_id,
    # firewall_id nor capture_networks is "unassociated": host identity from
    # it rests on the router heuristics alone.
    capture_networks      = Column(Text, nullable=True)
    gateway_macs          = Column(Text, nullable=True)
    reprocessed_at        = Column(UTCDateTime, nullable=True)
    # interface | firewall | segment | none - what the OPERATOR named (NULL
    # on a /ingest/pcap-fw upload whose firewall is only a suggestion)
    association           = Column(String(16), nullable=True)
    # FO-01: the L2 segment the capture shows (JSON: networks, basis, the
    # gateway MACs, on-link address count) - the capture point's networks
    # when named, else inferred from the on-link addresses
    segment               = Column(Text, nullable=True)

    firewall   = relationship("Firewall",          foreign_keys=[firewall_id])
    interface  = relationship("FirewallInterface", foreign_keys=[interface_id])
    suggestion = relationship("FirewallInterface", foreign_keys=[suggested_interface_id])

    def __repr__(self):
        return (
            f"<PcapCapture id={self.id} fw={self.firewall_id} "
            f"iface={self.interface_id} side={self.side}>"
        )


class FirewallZone(SiteScoped, Base):
    """
    A FortiGate interface and its zone assignment, extracted from
    `config system interface` in show full-configuration. This is the
    authoritative source of which network segment each interface belongs
    to - used to determine conduit direction (src_zone → dst_zone) in
    FirewallRule rows and to classify hosts by their zone when VLAN
    data is unavailable.

    NOTE: FirewallZone predates the multi-firewall topology models above.
    For multi-firewall sites, FirewallInterface is the authoritative
    interface record. FirewallZone continues to serve single-firewall
    zone lookups and backward-compatible config-review queries.
    """
    __tablename__ = "firewall_zones"

    id = Column(Integer, primary_key=True)

    device_name = Column(String(255), nullable=True)
    interface_name = Column(String(64), nullable=False)  # e.g. "port3", "DMZ"
    zone_name = Column(String(128), nullable=True)        # e.g. "OT_ZONE", "DMZ_ZONE"
    ip_cidr = Column(String(45), nullable=True)           # e.g. "10.0.1.1/24"
    vlan_id = Column(String(16), nullable=True)
    interface_type = Column(String(32), nullable=True)    # "physical", "vlan", "loopback"
    source_file = Column(String(512), nullable=True)

    __table_args__ = (
        # Per site (phase 2): replaces the global uq_fw_zone_device_iface.
        Index("ux_fw_zone_site_device_iface", "site_id", "device_name", "interface_name",
              unique=True),
    )

    def __repr__(self):
        return f"<FirewallZone {self.device_name}:{self.interface_name} zone={self.zone_name}>"


class FirewallZoneDef(Base):
    """
    B-07: a FortiOS zone and its member interfaces, per (firewall, VDOM).

    Sources: ``config system zone`` (kind "zone": ``set interface`` members,
    ``set intrazone allow|deny`` - FortiOS default deny) and SD-WAN zones
    (kind "sdwan": ``config system sdwan`` / ``config zone`` with members
    from ``config members`` ``set interface`` / ``set zone``; the legacy
    ``config system virtual-wan-link`` is the single zone
    "virtual-wan-link").  A policy srcintf / dstintf naming a zone matches
    traffic on any member interface; analysis expands zone names through
    this table, so re-analysis works without re-parsing.

    members_resolved is False when the membership could not be parsed
    (an SD-WAN member without an interface, ...): the zone's direction is
    then unknown and analysis reports affected results as unknown.

    A child of Firewall (no site column of its own, like FirewallInterface):
    replaced per (firewall, VDOM scope) on config re-ingest and deleted with
    the firewall (FK ON DELETE CASCADE).
    """
    __tablename__ = "firewall_zone_defs"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id", ondelete="CASCADE"), nullable=False)
    vdom = Column(String(64), nullable=True)
    name = Column(String(128), nullable=False)
    kind = Column(String(16), nullable=False, default="zone", server_default="zone")
    intrazone = Column(String(8), nullable=True)          # "allow" | "deny" (system zones)
    members = _json_column(default=list)                  # member interface names
    members_resolved = Column(Boolean, nullable=False, default=True, server_default=true())
    source_file = Column(String(512), nullable=True)

    __table_args__ = (
        Index("ix_fw_zone_def_fw_vdom_name", "firewall_id", "vdom", "name"),
    )

    def __repr__(self):
        return f"<FirewallZoneDef fw={self.firewall_id} vdom={self.vdom} {self.name}={self.members}>"


class Finding(SiteScoped, Base):
    """
    A security finding generated from config-level 62443 checks (via
    ingest_fortigate_config), traffic-derived checks (traffic_findings.py),
    or the real-time/periodic alert engine (alert_engine.py, triggered by
    FortiAnalyzerEvent or NetworkSession data). This is the single,
    unified finding record across all check types - alert_engine.py
    previously wrote to a separate `Alert` model that this docstring
    described as superseded well before that was actually true; as of
    this migration, `Alert` no longer exists and alert_engine.py writes
    here like everything else does.

    Findings are never deleted - they accumulate as an auditable history.
    Status transitions:
      open → acknowledged → closed (human-driven), plus
      open → closed by the alert engine's auto-resolve (F-04: periodic
      review no longer detects the condition; noted in `notes`, never for
      acknowledged or real_time findings; IACS_AUTO_RESOLVE=false disables)

    Each finding carries the ISA/IEC 62443 SR reference and the checklist
    ID from the OT firewall review workbook so findings can be mapped
    back to specific controls.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    created_at = Column(UTCDateTime, default=utcnow, index=True)
    updated_at = Column(UTCDateTime, default=utcnow, onupdate=utcnow)

    category = Column(String(64), nullable=False, index=True)
    # "config_review"    - found by parsing show full-configuration
    # "real_time"        - triggered by a FortiAnalyzer/syslog event
    # "periodic_review"  - generated by a scheduled review run

    # The specific check that produced this finding (e.g. "it_ot_bypass",
    # "auth_failure", "unauthorized_industrial_write") - see
    # CHECK_TYPE_REFERENCE above for the real_time/periodic_review set.
    # category alone is too coarse for this: two real_time findings can
    # both have category="real_time" while being entirely different
    # checks. config_review checks (forti_config_parser.py) and the
    # traffic-derived checklist-8.4 check (traffic_findings.py) also
    # populate this for consistent identification across every check-
    # producing module, not just alert_engine.py's.
    check_name = Column(String(64), nullable=True, index=True)

    severity = Column(String(16), nullable=False, default="medium")
    # critical / high / medium / low / info

    status = Column(String(16), nullable=False, default="open", index=True)
    # open / acknowledged / closed / false_positive (FINDING_STATUSES)
    # SF: an operator marked the finding a false positive, with a reason.  It
    # stays active for dedup (the condition is never raised again as a new
    # finding) and is reported in its own section of the exports.
    false_positive_reason = Column(String(1024), nullable=True)
    false_positive_by = Column(String(128), nullable=True)
    false_positive_at = Column(UTCDateTime, nullable=True)

    isa62443_sr = Column(String(128), nullable=True)   # e.g. "SR 5.1 RE2"
    checklist_id = Column(String(64), nullable=True)   # e.g. "2.1"

    title = Column(String(512), nullable=False)
    detail = _json_column(default=dict)  # finding-specific evidence dict; JSONB on PG

    device_name = Column(String(255), nullable=True, index=True)

    # Source linkage (at most one will be set per finding)
    session_id = Column(Integer, ForeignKey("network_sessions.id"), nullable=True)
    # ON DELETE SET NULL (T3-19): a config re-ingest deletes and recreates
    # the firewall's FirewallRule rows; without it that DELETE fails on
    # PostgreSQL (and on SQLite with foreign_keys=ON) for any rule a finding
    # points at.  The finding keeps its evidence in `detail`.
    rule_id = Column(
        Integer, ForeignKey("firewall_rules.id", ondelete="SET NULL"), nullable=True,
    )
    forti_event_id = Column(Integer, ForeignKey("fortiana_events.id"), nullable=True)

    # Dedup hash (sha1 of the check's key evidence) - see alert_engine._dedup_key.
    # Unique only among OPEN findings (partial index ux_findings_source_ref_open
    # below): once a finding is closed or acknowledged, a recurrence of the
    # same condition must be able to open a fresh finding with the same
    # source_ref. A global UNIQUE here previously made recurrences fail with
    # IntegrityError (T1-10). NULLs are allowed and never collide.
    source_ref = Column(String(255), nullable=True, index=True)

    __table_args__ = (
        # Per site (phase 2): one OPEN finding per (site, source_ref).
        Index(
            "ux_findings_site_source_ref_open",
            "site_id", "source_ref",
            unique=True,
            sqlite_where=text("status = 'open'"),
            postgresql_where=text("status = 'open'"),
        ),
    )

    # Lifecycle fields
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(UTCDateTime, nullable=True)
    closed_at = Column(UTCDateTime, nullable=True)
    notes = Column(String(2048), nullable=True)

    # Re-detection tracking (F-04): every time the alert engine re-detects
    # the condition of an OPEN finding (dedup hit) it bumps last_seen and
    # occurrence_count and refreshes `detail`. Rows created before these
    # columns existed have last_seen NULL / occurrence_count 1.
    #
    # Auto-resolve (F-04, IACS_AUTO_RESOLVE, default on): after a periodic
    # review completes successfully with a complete evaluation, its OPEN
    # findings that were not re-produced are closed with an
    # "Auto-resolved: ..." note. Acknowledged findings (a human owns them)
    # and real_time findings are never auto-closed.
    last_seen = Column(UTCDateTime, nullable=True, default=utcnow)
    occurrence_count = Column(Integer, nullable=False, default=1, server_default=text("1"))

    def __repr__(self):
        return f"<Finding id={self.id} [{self.severity}] {self.title[:40]}>"


class Attestation(SiteScoped, Base):
    """
    A human-supplied attestation that a specific ISA/IEC 62443 checklist
    control is satisfied, with optional proof document upload.

    Used primarily for Section 1 (Zone Documentation) controls 1.1–1.6,
    which require human review of policy/design artifacts rather than
    automated detection.  The periodic review function
    `review_zone_documentation()` checks this table and opens a Finding
    only when no current, non-stale attestation exists for a given row.

    At most one `is_current=True` row exists per (checklist_id, baseline_id)
    pair at any time.  Submitting a new attestation for the same row flips
    the old one to `is_current=False` so history is preserved.
    """
    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True)
    created_at = Column(UTCDateTime, default=utcnow)

    checklist_id = Column(String(16), nullable=False, index=True)   # "1.1" – "1.6" etc.
    attested_by = Column(String(255), nullable=False)                # name / email
    attested_at = Column(UTCDateTime, nullable=False)                   # when the evidence was reviewed
    notes = Column(String(2048), nullable=True)                      # free-text: doc location, context

    # Optional proof file stored in-DB as bytes.  Large files (diagrams,
    # PDFs) may be many MB; the upload endpoint caps at 20 MB.
    proof_filename = Column(String(255), nullable=True)
    proof_mime = Column(String(128), nullable=True)                  # "application/pdf", "image/png" etc.
    # Deferred: not loaded by default ORM queries — only fetched when explicitly
    # accessed (e.g. the proof download endpoint). Avoids pulling 20 MB blobs
    # into memory whenever the attestation list is queried.
    proof_data = deferred(Column(LargeBinary, nullable=True))

    # Which audit baseline this attestation belongs to.
    baseline_id = Column(Integer, ForeignKey("baselines.id"), nullable=True)

    # Only the most recent attestation per (checklist_id, baseline_id) is
    # "current" — older ones are kept for audit history.
    is_current = Column(Boolean, default=True, nullable=False)

    baseline = relationship("Baseline")

    __table_args__ = (
        # Non-partial index for efficient "give me current attestation for row X"
        # queries regardless of is_current value.
        Index("ix_attestation_checklist_current", "checklist_id", "is_current"),
        # Partial unique index: at most one current attestation per
        # (checklist_id, baseline_id) pair. Prevents concurrent requests
        # from creating two "current" records for the same checklist row.
        # Both SQLite (≥3.8.9) and PostgreSQL support WHERE on indexes.
        # Per site (phase 2): one current row per (site, checklist, baseline).
        Index(
            "ux_attestation_site_one_current",
            "site_id",
            "checklist_id",
            "baseline_id",
            unique=True,
            # PostgreSQL treats boolean columns as boolean, not as integers.
            # "= 1" causes a type-mismatch error at migration time on Postgres.
            # SQLite coerces freely so "= 1" works there, but using "= true"
            # is valid SQL on both engines. (P4-H2)
            postgresql_where=text("is_current = true"),
            sqlite_where=text("is_current = 1"),
        ),
        # NULLs are distinct in unique indexes (SQLite and PostgreSQL), so the
        # index above never fires for baseline_id IS NULL rows. This second
        # partial index enforces "one current attestation per checklist row"
        # for the no-baseline case. (T1-35)
        Index(
            "ux_attestation_site_one_current_nobaseline",
            "site_id",
            "checklist_id",
            unique=True,
            postgresql_where=text("is_current = true AND baseline_id IS NULL"),
            sqlite_where=text("is_current = 1 AND baseline_id IS NULL"),
        ),
    )

    def __repr__(self):
        return f"<Attestation id={self.id} checklist={self.checklist_id} by={self.attested_by} current={self.is_current}>"



# ---------------------------------------------------------------------------
# Multi-site phase 3: device registry + unmapped log queue
# (docs/multi-site-design.md; logic in app/site_devices.py)
# ---------------------------------------------------------------------------

SITE_DEVICE_SOURCES = ("config_upload", "manual")
UNMAPPED_STATUSES = ("pending", "replayed", "discarded")
# B-11: why a line is held.  "unmapped" = device unknown / ambiguous;
# "serial_conflict" = the line's serial differs from the serial(s) registered
# for its device name; "site_mismatch" = a ?site= upload named another site
# than the one the device is registered to; "ha_candidate" (B-12) = like
# serial_conflict, but the registered device is an HA cluster, so the line
# may come from a not-yet-known cluster member.  Conflicts wait for an
# operator choice (POST /site-devices/conflicts/resolve); no site is ever
# guessed.
HELD_KINDS = ("unmapped", "serial_conflict", "site_mismatch", "ha_candidate")
CONFLICT_KINDS = ("serial_conflict", "site_mismatch", "ha_candidate")
# B-11 / B-12: how a serial got onto a device (site_device_serials.source).
SERIAL_SOURCES = ("config_upload", "manual", "first_seen", "conflict_resolution", "ha_evidence")
CONFLICT_ACTIONS = ("same_device", "different_device", "discard", "add_ha_member")
# B-12: FortiOS FGCP HA modes kept on a device (``set mode`` of
# ``config system ha``; "standalone" = not HA -> NULL).
HA_MODES = ("a-p", "a-a")
# FGCP clusters have at most 4 members; app.site_devices.HA_MAX_MEMBERS reads
# IACS_HA_MAX_MEMBERS (default this value).
HA_MAX_MEMBERS_DEFAULT = 4


class SiteDevice(Base):
    """
    A log-emitting device (firewall) and the site its log lines belong to.

    ``device_name`` is normalised (strip + lower) - it is matched against the
    hostname / devname of each log line.  A device owns zero or more serials
    (``serials`` -> ``site_device_serials``; FortiGate devid, PAN-OS serial),
    each globally unique: a standalone device has at most one, an HA cluster
    (B-12, ``is_ha``) one per member unit (at most HA_MAX_MEMBERS).  Lines
    carrying ANY member serial route to this device.  The same name may be
    registered at two sites only when both rows carry distinct serials
    (enforced in app.site_devices.register).

    ``source``: "config_upload" (registered by a firewall config upload) or
    "manual" (POST /site-devices, ?site= on a log upload).

    ``serial`` / ``serial_source`` / ``serial_bound_at`` are DERIVED (read
    only): the first member serial (lowest id = added first), its source and when it
    was added - the single-serial view the B-11 API keeps exposing.

    B-12 HA: ``is_ha`` / ``ha_mode`` (a-p | a-a) / ``ha_group_name`` /
    ``ha_group_id`` come from ``config system ha`` of a config upload
    (``set mode`` standalone -> not HA) or from an operator confirming an HA
    member (conflict resolution add_ha_member with mark_ha).
    """
    __tablename__ = "site_devices"

    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)
    device_name = Column(String(255), nullable=False)
    vendor = Column(String(32), nullable=True)
    source = Column(String(16), nullable=False, default="manual")
    is_ha = Column(Boolean, nullable=False, default=False, server_default=false())
    ha_mode = Column(String(8), nullable=True)
    ha_group_name = Column(String(64), nullable=True)
    ha_group_id = Column(Integer, nullable=True)
    created_at = Column(UTCDateTime, default=utcnow)
    updated_at = Column(UTCDateTime, default=utcnow, onupdate=utcnow)

    serials = relationship(
        "SiteDeviceSerial", back_populates="device", lazy="selectin",
        cascade="all, delete-orphan", passive_deletes=True,
        order_by="SiteDeviceSerial.id")

    __table_args__ = (
        Index("ix_site_devices_site_id", "site_id"),
        Index("ix_site_devices_device_name", "device_name"),
    )

    def _primary(self):
        return self.serials[0] if self.serials else None

    @property
    def serial(self):
        p = self._primary()
        return p.serial if p is not None else None

    @property
    def serial_source(self):
        p = self._primary()
        return p.source if p is not None else None

    @property
    def serial_bound_at(self):
        p = self._primary()
        return p.added_at if p is not None else None

    @property
    def member_serials(self) -> list:
        return [m.serial for m in self.serials]

    def __repr__(self):
        return (f"<SiteDevice id={self.id} site={self.site_id} name={self.device_name!r} "
                f"serials={self.member_serials!r} ha={self.is_ha}>")


class SiteDeviceSerial(Base):
    """
    B-12: one serial of a registered device (``site_devices``) - the only
    unit of a standalone device, or one member of an HA cluster.

    ``serial`` is globally unique (a physical unit belongs to one device, so
    to one site).  ``source``: config_upload | manual | first_seen |
    conflict_resolution | ha_evidence (models.SERIAL_SOURCES).
    ``last_seen_at`` - event time (else ingest time) of the newest stored
    line from this unit; ``last_role`` - "primary" / "secondary" as last
    observed (a-p failover tracking: traffic logged by the unit, or an FGCP
    HA "member state moved" log), NULL when never observed.
    """
    __tablename__ = "site_device_serials"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("site_devices.id", ondelete="CASCADE"), nullable=False)
    serial = Column(String(128), nullable=False)
    source = Column(String(24), nullable=False, default="manual")
    added_at = Column(UTCDateTime, nullable=False, default=utcnow)
    last_seen_at = Column(UTCDateTime, nullable=True)
    last_role = Column(String(16), nullable=True)

    device = relationship("SiteDevice", back_populates="serials")

    __table_args__ = (
        Index("ux_site_device_serials_serial", "serial", unique=True),
        Index("ix_site_device_serials_device_id", "device_id"),
    )

    def __repr__(self):
        return (f"<SiteDeviceSerial device={self.device_id} serial={self.serial!r} "
                f"source={self.source} role={self.last_role}>")


class UnmappedLogEvent(Base):
    """
    A log line whose device is not registered to any site (no checks run).
    Held until the device is mapped (POST /site-devices replays it into the
    site: status "replayed"), discarded (status "discarded") or purged by
    retention (IACS_UNMAPPED_RETENTION_DAYS).

    ``raw_line`` is what the route re-parses on replay (for /ingest/forti-
    report: the CSV header line + the row; for /ingest/forti-event: the
    canonical JSON payload).  ``device_key`` is the normalised device name
    ('' when the line carries no device identity).  ``dedup_hash`` (unique)
    keeps a re-uploaded file from queueing the same line twice; it covers
    the resolved device key (incl. the ?device_name fallback) and the serial
    (B-11), so the same identity-less line uploaded for two devices is held
    once per device.

    B-11: ``kind`` says why the line is held (models.HELD_KINDS).  For a
    conflict, ``registered_device_id`` / ``registered_site_id`` /
    ``registered_serial`` snapshot the registry row the line collided with
    and ``map_site_id`` the ?site= of the upload (site_mismatch).  Conflicts
    are never routed until resolved (POST /site-devices/conflicts/resolve);
    mapping a device (POST /site-devices) replays "unmapped" lines only.
    """
    __tablename__ = "unmapped_log_events"

    id = Column(Integer, primary_key=True)
    raw_line = Column(Text, nullable=False)
    device_key = Column(String(255), nullable=False, default="")
    serial = Column(String(128), nullable=True)
    vendor = Column(String(32), nullable=True)
    source_route = Column(String(64), nullable=False)
    received_at = Column(UTCDateTime, default=utcnow)
    dedup_hash = Column(String(40), nullable=False)
    upload_ref = Column(String(255), nullable=True)
    status = Column(String(16), nullable=False, default="pending")
    kind = Column(String(16), nullable=False, default="unmapped", server_default="unmapped")
    registered_device_id = Column(Integer, nullable=True)
    registered_site_id = Column(Integer, nullable=True)
    registered_serial = Column(String(128), nullable=True)
    map_site_id = Column(Integer, nullable=True)

    __table_args__ = (
        Index("ux_unmapped_log_events_dedup_hash", "dedup_hash", unique=True),
        Index("ix_unmapped_log_events_device_key", "device_key"),
        Index("ix_unmapped_log_events_status", "status"),
        Index("ix_unmapped_log_events_kind_status", "kind", "status"),
    )

    def __repr__(self):
        return (f"<UnmappedLogEvent id={self.id} device={self.device_key!r} kind={self.kind} "
                f"status={self.status}>")


class DeviceConflictResolution(Base):
    """
    B-11 audit trail: one row per POST /site-devices/conflicts/resolve, and
    (B-12) per automatic HA member addition.

    ``action`` same_device | different_device | discard | add_ha_member, or
    ``ha_evidence`` (automatic: an HA event log from a known member named the
    serial as a cluster peer; ``resolved_by`` "auto: HA event log"); ``kind`` /
    ``device_key`` / ``serial`` identify the conflict group;
    ``registered_*`` the registry row it collided with (as it was before the
    resolution); ``target_site_id`` / ``device_id`` where the held lines were
    replayed (NULL for discard); ``lines`` held lines handled,
    ``events_created`` / ``findings_created`` the replay result.
    ``resolved_by`` is optional free text (no auth in this deployment).
    """
    __tablename__ = "device_conflict_resolutions"

    id = Column(Integer, primary_key=True)
    resolved_at = Column(UTCDateTime, default=utcnow, nullable=False)
    action = Column(String(24), nullable=False)
    kind = Column(String(16), nullable=False)
    device_key = Column(String(255), nullable=False, default="")
    serial = Column(String(128), nullable=True)
    registered_device_id = Column(Integer, nullable=True)
    registered_site_id = Column(Integer, nullable=True)
    registered_serial = Column(String(128), nullable=True)
    target_site_id = Column(Integer, nullable=True)
    device_id = Column(Integer, nullable=True)
    lines = Column(Integer, nullable=False, default=0)
    events_created = Column(Integer, nullable=False, default=0)
    findings_created = Column(Integer, nullable=False, default=0)
    resolved_by = Column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_device_conflict_resolutions_resolved_at", "resolved_at"),
    )

    def __repr__(self):
        return (f"<DeviceConflictResolution id={self.id} {self.action} {self.kind} "
                f"device={self.device_key!r} serial={self.serial!r}>")


# Registers the flush-time site_id filling (app.sites) whenever the models
# are imported.  Kept at the bottom: app.sites imports the classes above.
from app import sites as _sites  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Access-path review classification (docs/access-path-review.md, phase 3)
# ---------------------------------------------------------------------------

#: Operator classifications of an access-path row.
ACCESS_PATH_CLASSIFICATIONS = ("unclassified", "permissive", "it_ot_bypass",
                               "reviewed_ok", "exception")
#: Row kinds a tag can attach to.
ACCESS_PATH_TAG_KINDS = ("path", "composed", "unexplained")


def _in_list(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class AccessPathTag(SiteScoped, Base):
    """
    Operator classification of one GET /access-paths row (path, composed
    conduit or unexplained observed flow).

    ``tag_key`` is the row's stable identity (app.parsers.access_paths
    .tag_key_for_*): built from the firewall NAME, VDOM, policy id and a
    hash of scope / service / direction - never a DB row id - so a tag
    survives a config re-ingest and a delete-and-re-add of the firewall.
    ``firewall_device_id`` / ``vdom`` / ``policy_id`` are descriptive copies
    taken when the tag was written (for composed rows: the first leg's
    policy); ``firewall_device_id`` is deliberately not a foreign key, it
    may go stale after a re-add and is never used for matching.

    ``report_include`` NULL = use the row's default (flagged and not
    reviewed_ok / exception).  ``classified_by`` is free text until auth
    exists (A-01).
    """
    __tablename__ = "access_path_tag"

    id = Column(Integer, primary_key=True)
    tag_key = Column(String(512), nullable=False)
    kind = Column(String(16), nullable=False)
    firewall_device_id = Column(Integer, nullable=True)
    vdom = Column(String(64), nullable=True)
    policy_id = Column(String(32), nullable=True)
    classification = Column(String(16), nullable=False, default="unclassified")
    report_include = Column(Boolean, nullable=True)
    note = Column(Text, nullable=True)
    classified_by = Column(String(128), nullable=True)
    classified_at = Column(UTCDateTime, nullable=True)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_access_path_tag_site_key", "site_id", "tag_key", unique=True),
        CheckConstraint(_in_list("kind", ACCESS_PATH_TAG_KINDS),
                        name="ck_access_path_tag_kind"),
        CheckConstraint(_in_list("classification", ACCESS_PATH_CLASSIFICATIONS),
                        name="ck_access_path_tag_classification"),
    )


class FirewallGroup(SiteScoped, Base):
    """
    An operator-confirmed group of firewalls (one site).

    kind ``ha``      HA cluster: several configs of ONE logical firewall.
                     The analysis uses ``primary_firewall_id``'s rules as the
                     cluster's enforcement point; the other members are
                     compared with it (ha_config_drift) and their duplicate
                     config findings are folded into the primary's.
    kind ``paired``  "Paired firewall": firewalls (or HA clusters) enforcing
                     ONE boundary in series, typically two vendors at the
                     IT/OT DMZ (NIST SP 800-82 paired-firewall DMZ).  Every
                     crossing passes all of them, so a permit on one without a
                     counterpart on another is a real asymmetry; vendor
                     diversity is confirmed by an operator attestation
                     (checklist id ``PF-<id>``).
    """
    __tablename__ = "firewall_groups"

    id = Column(Integer, primary_key=True)
    kind = Column(String(16), nullable=False)            # ha | paired
    name = Column(String(64), nullable=False)
    # plain id, no FK: firewalls -> firewall_groups already has one and a
    # second, reverse FK would make the two tables mutually dependent.  A
    # stale id falls back to the lowest member (firewall_groups.primary_of).
    primary_firewall_id = Column(Integer, nullable=True)
    note = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_firewall_groups_site_kind_name", "site_id", "kind", "name", unique=True),
        CheckConstraint("kind IN ('ha', 'paired')", name="ck_firewall_groups_kind"),
    )

    def __repr__(self):
        return f"<FirewallGroup id={self.id} site={self.site_id} {self.kind} {self.name!r}>"


class AccessPathHop(SiteScoped, Base):
    """
    Operator-declared hop between two hosts of ONE segment (typically the L3.5
    DMZ): "remote-access gateway -> jumpbox, ssh/rdp".  No firewall sits
    between them, so the rule engine cannot see the hop; declaring it lets
    Access Review join a path that ends on ``from_ip`` with the paths that
    leave from ``to_ip`` (a composed row, never an it_ot_bypass).

    Hosts are referenced by address, not by id (host rows are re-created by
    re-ingests).  ``service`` is a comma list of ``proto/port`` tokens or NULL
    for any; it documents the hop and is shown on the row.  ``created_by`` is
    free text until auth exists (A-01).
    """
    __tablename__ = "access_path_hop"

    id = Column(Integer, primary_key=True)
    from_ip = Column(String(64), nullable=False)
    to_ip = Column(String(64), nullable=False)
    service = Column(String(255), nullable=True)
    note = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_access_path_hop_site_pair", "site_id", "from_ip", "to_ip", unique=True),
    )

    def __repr__(self):
        return (f"<AccessPathHop id={self.id} site={self.site_id} "
                f"{self.from_ip}->{self.to_ip} {self.service!r}>")


MANAGEMENT_NETWORK_KINDS = ("subnet", "host", "vlan", "name")
# SF-4: a host may carry several roles (one declaration row per role).
# ntp_server (owner, SF tabletop): a site time server - time sync to it from
# any level is neither an upward skip nor an IT dependency.
MANAGEMENT_HOST_ROLES = ("admin_ws", "jump_host", "engineering_ws", "ntp_server")
# management: administering infrastructure (firewalls, switches, servers);
# engineering: programming / configuring controllers and field devices (L0-L2).
MANAGEMENT_PURPOSES = ("management", "engineering")

# Finding lifecycle.  ACTIVE statuses count for dedup: a persisting condition
# updates the active finding instead of opening a duplicate (N-21; SF: a
# false positive is never re-raised).
FINDING_STATUSES = ("open", "acknowledged", "closed", "false_positive")
ACTIVE_FINDING_STATUSES = ("open", "acknowledged", "false_positive")


VPN_GROUP_CATEGORIES = ("it", "vendor", "other")


class VpnUserGroup(SiteScoped, Base):
    """
    Operator classification of an SSL-VPN user group (or user) named by the
    ``groups`` / ``users`` of tunnel-sourced firewall policies.

    ``category`` it (the site's own IT / OT staff), vendor (vendor, integrator
    or other third party - IEC 62443-2-4 SP.07 applies) or other.  Without a
    row the checks guess from the name ("vendor", "3rd", "third",
    "contractor", "supplier") and say that they guessed.

    ``firewall_id`` NULL = the group name on every firewall of the site.
    ``key`` = ``<firewall id or *>:<lower-case name>`` (unique per site).
    ``created_by`` is free text until auth exists (A-01).
    """
    __tablename__ = "vpn_user_groups"

    id = Column(Integer, primary_key=True)
    key = Column(String(160), nullable=False)
    name = Column(String(128), nullable=False)
    firewall_id = Column(Integer, ForeignKey("firewalls.id", ondelete="CASCADE"),
                         nullable=True, index=True)
    category = Column(String(16), nullable=False)
    note = Column(Text, nullable=True)
    finding_id = Column(Integer, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_vpn_user_groups_site_key", "site_id", "key", unique=True),
        CheckConstraint("category IN ('it', 'vendor', 'other')",
                        name="ck_vpn_user_groups_category"),
    )

    def __repr__(self):
        return f"<VpnUserGroup id={self.id} site={self.site_id} {self.key}={self.category}>"


class InventoryImportMapping(SiteScoped, Base):
    """A saved Asset Inventory CSV column mapping (owner request 2026-10-11):
    ``column_map`` = ``{column key: field or ""}`` (column key = the header,
    stripped, lower case; ``""`` = ignore).  Applied to the next import of the
    site whose columns it names - the Import CSV preview, and uploads that
    carry no mapping.  ``name`` is unique per site."""
    __tablename__ = "inventory_import_mappings"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    column_map = Column(JSON, nullable=False)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_inventory_import_mappings_site_name", "site_id", "name", unique=True),
    )

    def __repr__(self):
        return f"<InventoryImportMapping id={self.id} site={self.site_id} {self.name}>"


class CheckEvaluation(SiteScoped, Base):
    """When a check was last evaluated, for the PDF's PASS / NOT EVALUATED
    (owner 2026-10-12: "print out tests that passed and the evidence").

    One row per (site, check_name, scope):
      * periodic reviews: scope "" - written by run_periodic_reviews for every
        check of a review that ran (``complete`` False when it failed or marked
        its input incomplete; ``note`` says why);
      * FortiGate config: check_name ``__fortigate_config__``, scope
        ``fw:<firewall id>`` - written at each config upload that generated
        findings; ``evidence`` holds the settings the config checks examined
        (sections of {setting, value, checks}) for the report appendix."""
    __tablename__ = "check_evaluations"

    id = Column(Integer, primary_key=True)
    check_name = Column(String(128), nullable=False)
    scope = Column(String(128), nullable=False, default="")
    source = Column(String(128), nullable=True)          # review function / "fortigate_config"
    evaluated_at = Column(UTCDateTime, nullable=False, default=utcnow)
    complete = Column(Boolean, nullable=False, default=True)
    note = Column(String(512), nullable=True)
    evidence = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ux_check_evaluations_site_check_scope", "site_id", "check_name", "scope", unique=True),
    )

    def __repr__(self):
        return f"<CheckEvaluation site={self.site_id} {self.check_name} {self.scope!r} {self.evaluated_at}>"


class AppSetting(Base):
    """Server-wide operator settings (not per site), e.g. RS-01: whether the
    scheduled periodic reviews run (``periodic_reviews``).  One row per key;
    ``value`` is JSON.  ``updated_by`` is free text until auth exists (A-01)."""
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(JSON, nullable=True)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_by = Column(String(128), nullable=True)

    def __repr__(self):
        return f"<AppSetting {self.key}={self.value!r}>"


class ObservedName(SiteScoped, Base):
    """G5: a name a capture showed for an address - from a DNS answer the
    devices received, a TLS server name (SNI) or an HTTP Host header.  One
    row per (address, name, source); nothing is looked up."""
    __tablename__ = "observed_names"

    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    source = Column(String(16), nullable=False)          # dns | tls_sni | http_host
    count = Column(Integer, nullable=False, default=1)
    first_seen = Column(UTCDateTime, nullable=True)
    last_seen = Column(UTCDateTime, nullable=True)

    __table_args__ = (
        Index("ux_observed_names_site_ip_name_source", "site_id", "ip", "name", "source", unique=True),
    )


class ExternalFlowReview(SiteScoped, Base):
    """G5: the operator's verdict on an external communication - an inside
    host (``src``, or "*" for every host) talking to a destination
    (``dest_key``: a domain such as ``hik-connect.com``, or an address).
    ``approved`` documents the flow (it stops raising Internet-egress
    findings); ``remove`` marks it for removal (findings say so)."""
    __tablename__ = "external_flow_reviews"

    id = Column(Integer, primary_key=True)
    src = Column(String(64), nullable=False)
    dest_key = Column(String(255), nullable=False)
    status = Column(String(16), nullable=False)         # approved | remove
    note = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_external_flow_reviews_site_src_dest", "site_id", "src", "dest_key", unique=True),
        CheckConstraint("status IN ('approved', 'remove')", name="ck_external_flow_reviews_status"),
    )


class SubnetZone(SiteScoped, Base):
    """RS G3: the operator's zone for one subnet - its Purdue level and zone
    name (IEC 62443-3-2 zones; workbook rows 1.1-1.5, 2.7).  Hosts in the
    subnet that no stronger evidence classifies take the level (source
    ``subnet_declared``); a device whose own traffic says otherwise keeps
    its level and is reported (``misplaced_device``).  Firewall / switch
    interfaces on the network without an operator level take it too
    (``purdue_suggestion_source = "zone_declared"``)."""
    __tablename__ = "subnet_zones"

    id = Column(Integer, primary_key=True)
    cidr = Column(String(64), nullable=False)
    purdue_level = Column(PurdueLevelType, nullable=True)
    zone_name = Column(String(128), nullable=True)
    note = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_subnet_zones_site_cidr", "site_id", "cidr", unique=True),
    )


class IecZone(SiteScoped, Base):
    """IEC 62443-3-2 zone: a named grouping of assets with common security
    requirements and an optional target security level (SL-T 1-4).

    Independent of the Purdue model and of addressing: a zone may hold
    assets at several Purdue levels and in several networks (members are
    hosts, subnets, firewall interfaces / VLAN sub-interfaces and FortiGate
    zones - ``IecZoneMember``).  Documentation only: the findings engine
    never reads these tables (app/iec_zones.py)."""
    __tablename__ = "iec_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    sl_t = Column(Integer, nullable=True)                 # target security level 0-4 (SL0 = no requirements)
    # SL-A: achieved security level (62443-3-2 / -3-3 assessment), 1-4, NULL = not assessed.
    # Documentation only, like SL-T and SL-C.
    sl_a = Column(Integer, nullable=True)
    sl_a_note = Column(String(255), nullable=True)      # assessment reference / date
    description = Column(Text, nullable=True)
    owner = Column(String(128), nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_iec_zones_site_name", "site_id", "name", unique=True),
        CheckConstraint("sl_t IS NULL OR sl_t IN (0, 1, 2, 3, 4)", name="ck_iec_zones_sl_t"),
    )


IEC_ZONE_MEMBER_KINDS = ("host", "subnet", "interface", "fw_zone")


class IecZoneMember(SiteScoped, Base):
    """One member of an IEC 62443-3-2 zone.  ``kind`` / ``ref``:

    * ``host``       ``mac:<aa:bb:..>`` or ``ip:<address>`` (survives re-ingest / merges)
    * ``subnet``     a CIDR
    * ``interface``  ``<firewall name>/<interface name>`` (a VLAN sub-interface too)
    * ``fw_zone``    ``<firewall name>/<vdom or empty>/<zone name>`` (FortiOS zone)

    Referenced by name, not row id, so a config re-upload keeps the
    membership.  A network member belongs to one zone; a host member may be
    in several (one row per zone)."""
    __tablename__ = "iec_zone_members"

    id = Column(Integer, primary_key=True)
    zone_id = Column(Integer, ForeignKey("iec_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(16), nullable=False)
    ref = Column(String(255), nullable=False)
    note = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        # an asset may be a member of several zones: never refused (owner, 2026-10-11),
        # reported by host_in_multiple_zones / network_in_multiple_zones
        Index("ux_iec_zone_members_zone_kind_ref", "site_id", "zone_id", "kind", "ref", unique=True),
        CheckConstraint("kind IN ('host', 'subnet', 'interface', 'fw_zone')", name="ck_iec_zone_members_kind"),
    )


class IecConduit(SiteScoped, Base):
    """IEC 62443-3-2 conduit between two zones (stored with zone_a_id <
    zone_b_id; conduits are documented per zone pair).  The policies and
    observed traffic between the zones are derived at read time.
    Documentation only - never read by the findings engine."""
    __tablename__ = "iec_conduits"

    id = Column(Integer, primary_key=True)
    zone_a_id = Column(Integer, ForeignKey("iec_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    zone_b_id = Column(Integer, ForeignKey("iec_zones.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=True)
    sl_t = Column(Integer, nullable=True)
    sl_a = Column(Integer, nullable=True)                 # achieved level, documentation only
    sl_a_note = Column(String(255), nullable=True)
    # Option 3 (owner, 2026-10-11): what the conduit is for.  ``services`` is
    # a comma list of service names / proto/port tokens (or "any");
    # ``sources`` a comma list of addresses / CIDRs allowed to use it.  A
    # finding on this conduit whose service (and source, when set) is listed
    # is shown one severity step lower, with the reason.  Both optional.
    services = Column(Text, nullable=True)
    sources = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_iec_conduits_site_pair", "site_id", "zone_a_id", "zone_b_id", unique=True),
        CheckConstraint("sl_t IS NULL OR sl_t IN (0, 1, 2, 3, 4)", name="ck_iec_conduits_sl_t"),
        CheckConstraint("zone_a_id < zone_b_id", name="ck_iec_conduits_pair_order"),
    )


class ReportCheckExclusion(SiteScoped, Base):
    """A check left out of the site's compliance report (owner 2026-10-14), with an
    optional reason, who and when.  The findings of the check stay on the Findings
    page and in the exports; the PDF lists the excluded checks / groups."""
    __tablename__ = "report_check_exclusions"

    id = Column(Integer, primary_key=True)
    check_name = Column(String(128), nullable=False)
    reason = Column(String(500), nullable=True)
    excluded_by = Column(String(128), nullable=True)
    excluded_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_report_check_exclusions_site_check", "site_id", "check_name", unique=True),
    )


class ReportDetails(SiteScoped, Base):
    """Owner 2026-10-18: the report details of a site printed on the compliance
    report's cover, distribution list and revision history (Reports page).
    One row per site; nothing in it changes findings."""
    __tablename__ = "report_details"

    id = Column(Integer, primary_key=True)
    client_name = Column(String(200), nullable=True)
    project_name = Column(String(200), nullable=True)
    author = Column(String(128), nullable=True)
    author_email = Column(String(200), nullable=True)
    version = Column(String(32), nullable=True)
    classification = Column(String(128), nullable=True)
    distribution = _json_column(default=list)      # [{name, role, email, side: "client" | "assessor"}]
    revisions = _json_column(default=list)         # [{version, date, status}]
    constraints = Column(Text, nullable=True)      # assessment window, observations and constraints
    updated_by = Column(String(128), nullable=True)
    updated_at = Column(UTCDateTime, nullable=True, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ux_report_details_site", "site_id", unique=True),
    )


class FirewallConfigText(SiteScoped, Base):
    """The latest uploaded configuration text of a firewall (owner 2026-10-14:
    "Firewall devices need a means to see the uploaded config to check findings").
    One row per Firewall, replaced on every upload (latest only); the text is
    stored with its secrets masked (``config_store.mask_secrets``: passwords,
    pre-shared keys, SNMP communities, private keys, ``ENC`` blobs -> ``***``)
    and zlib-compressed.  View only - the parsers never read it back."""
    __tablename__ = "firewall_config_texts"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id", ondelete="CASCADE"), nullable=False)
    device_name = Column(String(255), nullable=True)
    vendor = Column(String(32), nullable=True)
    filename = Column(String(512), nullable=True)
    uploaded_at = Column(UTCDateTime, nullable=False, default=utcnow)
    size_bytes = Column(Integer, nullable=False, default=0)       # of the masked text
    line_count = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=True)                    # of the masked text
    masked_count = Column(Integer, nullable=False, default=0)     # secrets replaced
    content = deferred(Column(LargeBinary, nullable=True))        # zlib(masked text, utf-8)

    __table_args__ = (
        Index("ux_firewall_config_texts_firewall", "firewall_id", unique=True),
    )


class IecConduitRule(SiteScoped, Base):
    """A firewall policy the operator attached to a documented conduit (owner
    2026-10-13: conduits named to their zones and firewall rule numbers).
    Keyed on the policy identity (firewall name, VDOM, policy id), not a
    FirewallRule row id, so it survives a config re-upload.  ``vdom`` is ""
    when the firewall has none.  Documentation only - never read by the
    findings engine."""
    __tablename__ = "iec_conduit_rules"

    id = Column(Integer, primary_key=True)
    conduit_id = Column(Integer, ForeignKey("iec_conduits.id", ondelete="CASCADE"), nullable=False, index=True)
    firewall_name = Column(String(128), nullable=False)
    vdom = Column(String(64), nullable=False, default="")
    policy_id = Column(String(64), nullable=False)
    note = Column(String(255), nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_iec_conduit_rules_policy", "conduit_id", "firewall_name", "vdom", "policy_id", unique=True),
    )


class ManagementNetwork(SiteScoped, Base):
    """
    Operator declaration of where management access legitimately comes
    from (ISA/IEC 62443-3-3 SR 1.3, SR 5.1 RE1; workbook rows 5.1, 9.5).

    kind ``subnet``  ``cidr`` is a management network (e.g. the OOB VLAN's
                     subnet).  Every address in it is a management source.
    kind ``host``    ``cidr`` (a /32 or /128, or a small range) is a trusted
                     host - ``role`` admin_ws / jump_host (management) or
                     engineering_ws (engineering).  Kept apart from the audit
                     baseline so no baseline is needed.
    kind ``vlan``    ``vlan_id`` is a management VLAN (site-wide id).  Its
                     subnets come from firewall VLAN interfaces with that id;
                     hosts the switches place on it are management sources.
    kind ``name``    reclassifies a firewall interface / FortiOS zone / alias
                     ``name`` (case-insensitive) on ``firewall_id`` (NULL =
                     every firewall of the site): ``is_management`` True = a
                     management zone, False = NOT one, whatever its name says.

    ``purpose`` management (administering infrastructure: firewalls,
    switches, servers - SSH / HTTPS / SNMP / RDP) or engineering (programming
    and configuring controllers and field devices at L0-L2: vendor
    programming tools, industrial writes, the device's web / SSH UI).  An
    engineering source is approved only toward OT equipment (L0-L2) and for
    industrial write / program operations; never for firewall / switch admin
    access.  A host's purpose follows its role.

    ``key`` is the normalised identity (unique per site).  ``finding_id`` is
    the finding the declaration was made from (plain id, informational).
    ``created_by`` is free text until auth exists (A-01).
    """
    __tablename__ = "management_networks"

    id = Column(Integer, primary_key=True)
    kind = Column(String(16), nullable=False)
    key = Column(String(320), nullable=False)
    cidr = Column(String(64), nullable=True)
    role = Column(String(32), nullable=True)
    vlan_id = Column(Integer, nullable=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id", ondelete="CASCADE"),
                         nullable=True, index=True)
    name = Column(String(128), nullable=True)
    is_management = Column(Boolean, nullable=False, default=True, server_default=true())
    purpose = Column(String(16), nullable=False, default="management", server_default="management")
    label = Column(String(128), nullable=True)
    note = Column(Text, nullable=True)
    finding_id = Column(Integer, nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(UTCDateTime, nullable=True, default=utcnow)

    __table_args__ = (
        Index("ux_management_networks_site_key", "site_id", "key", unique=True),
        CheckConstraint("kind IN ('subnet', 'host', 'vlan', 'name')",
                        name="ck_management_networks_kind"),
    )

    def __repr__(self):
        return f"<ManagementNetwork id={self.id} site={self.site_id} {self.key}>"


# ---------------------------------------------------------------------------
# AU full review D5 / D10 / F1 / F3: SQLite ignores VARCHAR(n) but PostgreSQL
# raises StringDataRightTruncation.  Parser-built values that can exceed a
# column's declared length ("too-large:<group name>" tokens, a 300-character
# policy name, syslog fields, ...) are clipped to the column length at flush
# time for every mapped class, so the ingest never fails on a long value.
# ---------------------------------------------------------------------------
from sqlalchemy import event as _sa_event, inspect as _sa_inspect  # noqa: E402

_STRING_COLS: dict = {}


def _string_columns(cls) -> list:
    cols = _STRING_COLS.get(cls)
    if cols is None:
        cols = []
        for attr in _sa_inspect(cls).column_attrs:
            for c in attr.columns:
                length = getattr(c.type, "length", None)
                if isinstance(c.type, String) and not isinstance(c.type, Text) and length:
                    cols.append((attr.key, length))
                    break
        _STRING_COLS[cls] = cols
    return cols


def _clip_strings(mapper, connection, target) -> None:
    for key, length in _string_columns(type(target)):
        v = getattr(target, key, None)
        if isinstance(v, str) and len(v) > length:
            setattr(target, key, v[:length])


_sa_event.listen(Base, "before_insert", _clip_strings, propagate=True)
_sa_event.listen(Base, "before_update", _clip_strings, propagate=True)
