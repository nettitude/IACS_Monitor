"""
Site device registry and per-line log routing (multi-site phase 3, see
docs/multi-site-design.md).

Log uploads (/ingest/syslog, /ingest/forti-syslog, /ingest/forti-event,
/ingest/forti-report) carry no site: each LINE is routed to the site of the
device that emitted it.

* ``site_devices`` maps a device (normalised name, optional serial) to a
  site.  Firewall config uploads register their hostname automatically
  (``register_from_config``, source ``config_upload``); operators map the
  rest (POST /site-devices, or ``?site=`` on a log upload; source
  ``manual``).
* ``resolve(db, name, serial)`` -> Site or None: serial first, then name; a
  name registered at several sites (with distinct serials) and a line
  without a known serial is ambiguous -> None.
* ``LogRouter`` routes parsed lines: known device -> stored in that site
  (the caller runs evaluate_event, which follows ev.site_id); unknown ->
  ``unmapped_log_events`` (no checks run, deduplicated).  With a map site
  (``?site=``) UNKNOWN devices are registered to it and routed there; a
  device already mapped elsewhere still goes to its own site and is counted
  in ``site_conflicts``.  Lines without any device identity go to the map
  site, else to the queue (device_key '').
* Mapping a device (``replay_pending``) replays its held lines through the
  normal ingest path into the device's site.  Remapping affects new lines
  only: stored events / findings are never moved.
* B-11 conflicts - a site is never guessed for a conflicting line, it is
  held (``unmapped_log_events.kind``) until an operator decides
  (``resolve_conflict``, POST /site-devices/conflicts/resolve):
    - serial binding: a name-matched device without a serial takes the first
      serial its lines carry (``serial_source='first_seen'``) and routes;
    - ``serial_conflict``: the line's serial differs from the serial
      registered for its name (and is registered nowhere) -> held;
    - ``site_mismatch``: a ?site= upload names another site than the
      device's -> held (lines of devices without any identity, and unknown
      devices, still go to the ?site);
    - a serial registered to another device routes to that device.
  Resolution: same_device (replaced unit: the registered serial is updated,
  held lines replayed into the registered site), different_device (a new
  device with that serial is registered at the chosen site, replayed there;
  future lines route there by serial) or discard.  Each resolution is
  recorded in ``device_conflict_resolutions``.  Stored data is never moved.
* B-12 HA clusters - a device owns one serial per member unit
  (``site_device_serials``); lines carrying ANY member serial route to it.
  ``config system ha`` of a config upload marks the device HA (``set mode
  a-p|a-a``, ``group-name``, ``group-id``; standalone -> not HA).  A new
  serial under an HA device's name is added as a member automatically when
  evidenced (an FGCP HA event log from a known member names it as a peer,
  same group; ``ha_evidence``) or pre-registered (POST
  /site-devices/{id}/serials); otherwise it is held as ``ha_candidate`` and
  the operator can "Add as HA member" (resolve ``add_ha_member``).  Held
  candidates are replayed as soon as evidence arrives (same or later
  upload).  Never across sites, never more than HA_MAX_MEMBERS.  An a-p
  cluster whose active (logging) member changes raises an ``ha_failover``
  finding (``track_member_activity``, called by the alert engine).
* ``purge_unmapped`` - retention (IACS_UNMAPPED_RETENTION_DAYS, default 30).

FortiOS HA event log fields used as evidence (sources, checked 2026-10-04):
  * FortiOS Log Message Reference - 37892 MESGID_VC_MOVE_MEMB_STATE
    ("Virtual cluster member state moved") and 37894
    MESGID_VC_DETECT_MEMB_JOIN ("Virtual cluster member joined"):
    https://docs.fortinet.com/document/fortigate/7.0.3/fortios-log-message-reference/37892
    https://docs.fortinet.com/document/fortigate/6.4.4/fortios-log-message-reference/37894
  * Sample lines (Fortinet "sample logs by log type"), e.g.
    logid="0108037894" type="event" subtype="ha" ... vcluster=1 ha_group=0
    sn="FG2K5E3916900286"  and  logid="0108037892" ... ha_role="master"
    vcluster_state="work" vcluster_member=0 hostname="FW_QA4" sn="FG2K..."
    https://github.com/alasta/splunkdemo/blob/main/logs/fortigate.log
  * Field meaning: ``sn`` = "The serial number of the FortiGate that joined
    the virtual cluster", ``ha_group`` = "The HA group ID":
    https://docs.logrhythm.com/devices/docs/syslog-fortinet-fortigate-v-2-0-event-ha
  The logging unit itself is ``devid``.  Only logids 0108037892 / 0108037894
  (type=event, subtype=ha) are taken as evidence; 0108037893 ("member
  dead") and heartbeat-device logs are not, because their peer-serial field
  could not be confirmed from the reference (Fortinet's log reference pages
  render client-side and could not be read in full).
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models import (
    HA_MAX_MEMBERS_DEFAULT, HA_MODES, DeviceConflictResolution, FortiAnalyzerEvent, Site,
    SiteDevice, SiteDeviceSerial, UnmappedLogEvent, utcnow,
)
from app.sites import ingest_site

log = logging.getLogger(__name__)

SOURCE_CONFIG = "config_upload"
SOURCE_MANUAL = "manual"

ROUTE_SYSLOG = "syslog"
ROUTE_FORTI_SYSLOG = "forti-syslog"
ROUTE_FORTI_EVENT = "forti-event"
ROUTE_FORTI_REPORT = "forti-report"

KIND_UNMAPPED = "unmapped"
KIND_SERIAL = "serial_conflict"
KIND_SITE = "site_mismatch"
KIND_HA = "ha_candidate"            # B-12: unknown serial under an HA device's name
CONFLICT_KINDS = (KIND_SERIAL, KIND_SITE, KIND_HA)
SERIAL_KINDS = (KIND_SERIAL, KIND_HA)   # "another unit under a registered name"

SERIAL_FIRST_SEEN = "first_seen"
SERIAL_RESOLUTION = "conflict_resolution"
SERIAL_HA_EVIDENCE = "ha_evidence"

ACTION_ADD_HA = "add_ha_member"
ACTION_HA_EVIDENCE = "ha_evidence"      # audit rows of automatic member additions
ACTION_MANUAL_MEMBER = "manual_member"  # audit rows of POST /site-devices/{id}/serials
AUTO_RESOLVED_BY = "auto: HA event log"


# C-16: identity values are matched against / stored in String columns
# (SiteDevice.device_name String(255), SiteDeviceSerial.serial / the
# UnmappedLogEvent.serial + device_key columns).  A log line carrying an
# over-long devid / devname would raise DataError on PostgreSQL and 500 the
# whole upload; such a line is NEVER routed (it could be misidentified) - it
# is held as a malformed unmapped line so nothing is silently misidentified.
MAX_DEVICE_NAME_LEN = 255
MAX_SERIAL_LEN = 128
MALFORMED_KEY = "__malformed__"


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


# FGCP: at most 4 cluster members (IACS_HA_MAX_MEMBERS overrides, 2..16).
HA_MAX_MEMBERS = _env_int("IACS_HA_MAX_MEMBERS", HA_MAX_MEMBERS_DEFAULT, 2, 16)

_SAMPLE_MAX = 500


# ------------------------------------------------------------ normalising --

def normalise_name(value) -> str:
    return str(value).strip().lower() if value is not None else ""


def normalise_serial(value) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _ci_get(d: dict, *keys):
    if not isinstance(d, dict):
        return None
    low = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        v = low.get(k)
        if v not in (None, "") and not isinstance(v, (dict, list)):
            return v
    return None


def identity_from_fields(fields: dict) -> tuple[str, Optional[str], Optional[str]]:
    """(normalised device name, serial, vendor) of a parsed log line.

    FortiGate: devname / devid (CEF dvchost / deviceExternalId); PAN-OS:
    device_name / serial; ASA / pfSense: the syslog header hostname (the
    parsers put it in ``device_name``).  A name that is just the serial
    (FortiOS falls back to devid) counts as no name."""
    raw = fields.get("raw_fields") or {}
    serial = normalise_serial(_ci_get(raw, "devid", "deviceexternalid", "serial"))
    name = normalise_name(fields.get("device_name"))
    if serial and name == serial.lower():
        name = ""
    return name, serial, fields.get("vendor")


# ---------------------------------------------------------------- lookup --

def member_of(db: Session, serial) -> Optional[SiteDeviceSerial]:
    """The ``site_device_serials`` row of ``serial`` (any device), or None."""
    serial = normalise_serial(serial)
    if not serial:
        return None
    return db.query(SiteDeviceSerial).filter(SiteDeviceSerial.serial == serial).first()


def serial_owner(db: Session, serial) -> Optional[SiteDevice]:
    """The device that owns ``serial`` as one of its (member) serials."""
    m = member_of(db, serial)
    return m.device if m is not None else None


def resolve_device(db: Session, device_name, serial=None) -> Optional[SiteDevice]:
    """The registry row a device identity maps to (any member serial first,
    then name); None when unknown or ambiguous."""
    name = normalise_name(device_name)
    row = serial_owner(db, serial)
    if row is not None:
        return row
    if not name:
        return None
    rows = db.query(SiteDevice).filter(SiteDevice.device_name == name).all()
    if not rows or len({r.site_id for r in rows}) != 1:
        return None   # unknown, or one name at several sites without a known serial
    return rows[0]


def resolve(db: Session, device_name, serial=None) -> Optional[Site]:
    row = resolve_device(db, device_name, serial)
    return db.get(Site, row.site_id) if row is not None else None


# ---------------------------------------------------------- registration --

class DeviceConflict(ValueError):
    """The device is registered to another site (or the name would become
    ambiguous); nothing was changed."""

    def __init__(self, message: str, row: Optional[SiteDevice] = None):
        super().__init__(message)
        self.row = row


@dataclass
class Registration:
    row: Optional[SiteDevice]
    status: str                     # created | updated | unchanged | conflict
    message: str = ""

    @property
    def conflict(self) -> bool:
        return self.status == "conflict"


def _site_name(db, site_id) -> str:
    s = db.get(Site, site_id)
    return s.name if s is not None else str(site_id)


def check_unambiguous(db: Session, site_id: int, name: str, serial: Optional[str],
                      exclude_id: Optional[int] = None) -> None:
    """Raise DeviceConflict unless (name, serial) at ``site_id`` keeps every
    name unambiguous: a name may exist at several sites only when every one
    of those rows carries (at least one) distinct serial."""
    q = db.query(SiteDevice).filter(SiteDevice.device_name == name,
                                    SiteDevice.site_id != site_id)
    if exclude_id is not None:
        q = q.filter(SiteDevice.id != exclude_id)
    others = q.all()
    if others:
        if serial is None:
            o = others[0]
            raise DeviceConflict(
                f"device {name!r} is already registered to site {_site_name(db, o.site_id)!r}; "
                "the same name at two sites needs distinct serials", o)
        for o in others:
            if not o.serials:
                raise DeviceConflict(
                    f"device {name!r} is registered to site {_site_name(db, o.site_id)!r} "
                    "without a serial; add its serial there first", o)
    if serial is not None:
        o = serial_owner(db, serial)
        if o is not None and o.id != exclude_id:
            raise DeviceConflict(
                f"serial {serial!r} is already registered (device {o.device_name!r}, "
                f"site {_site_name(db, o.site_id)!r})", o)


def _new_member(serial: str, source: str) -> SiteDeviceSerial:
    return SiteDeviceSerial(serial=serial, source=source, added_at=utcnow())


def set_serial(row: SiteDevice, serial: Optional[str], source: str) -> None:
    """Make ``serial`` the device's ONLY serial (standalone device: bind,
    replace a unit, clear with None) and note how / when.  Callers refuse
    this for an HA cluster with several members.  Does not flush."""
    keep = [m for m in row.serials if serial and m.serial == serial]
    if keep:
        row.serials[:] = keep[:1]
    else:
        row.serials[:] = [_new_member(serial, source)] if serial else []
    row.updated_at = utcnow()


class MemberError(ValueError):
    """A member serial that cannot be added / removed (HTTP ``status``)."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def add_member(db: Session, dev: SiteDevice, serial, source: str) -> tuple[SiteDeviceSerial, bool]:
    """Add ``serial`` to ``dev`` -> (member row, created).  A standalone
    device takes a serial only while it has none; an HA cluster up to
    HA_MAX_MEMBERS.  A serial owned by ANY other device (any site) is
    refused - a unit belongs to one device, so to one site.  Flushes;
    raises MemberError (nothing changed)."""
    serial = normalise_serial(serial)
    if not serial:
        raise MemberError("serial is required", 422)
    m = member_of(db, serial)
    if m is not None:
        if m.device_id == dev.id:
            return m, False
        o = m.device
        raise MemberError(f"serial {serial!r} is already registered to device "
                          f"{o.device_name!r} (site {_site_name(db, o.site_id)!r})")
    if not dev.is_ha and dev.serials:
        raise MemberError(f"device {dev.device_name!r} is not an HA cluster and already has "
                          f"serial {dev.serial!r}; mark it HA (config upload with "
                          "'config system ha', or an add_ha_member resolution with mark_ha) "
                          "or replace its serial (PATCH)")
    if len(dev.serials) >= HA_MAX_MEMBERS:
        raise MemberError(f"HA cluster {dev.device_name!r} already has {len(dev.serials)} "
                          f"member serials (maximum {HA_MAX_MEMBERS}); remove a member first")
    m = _new_member(serial, source)
    dev.serials.append(m)
    dev.updated_at = utcnow()
    db.flush()
    return m, True


def register(db: Session, site_id: int, device_name, serial=None, vendor=None,
             source: str = SOURCE_MANUAL) -> Registration:
    """Register (or update) a device at ``site_id``.  Never moves a device
    that is registered to another site: returns status "conflict" instead.
    A new serial for the name of an HA cluster at this site becomes a member
    of it (when there is room).  Flushes, does not commit."""
    name = normalise_name(device_name)
    serial = normalise_serial(serial)
    if not name and serial:
        name = serial.lower()
    if not name:
        raise ValueError("device_name (or serial) is required")
    vendor = (str(vendor).strip()[:32] or None) if vendor else None

    def _touch(row, changed):
        if vendor and row.vendor != vendor and (source == SOURCE_MANUAL or not row.vendor):
            row.vendor = vendor
            changed = True
        if changed:
            row.updated_at = utcnow()
            db.flush()
        return Registration(row, "updated" if changed else "unchanged")

    if serial:
        row = serial_owner(db, serial)
        if row is not None:
            if row.site_id != site_id:
                return Registration(row, "conflict",
                                    f"serial {serial!r} is registered to site "
                                    f"{_site_name(db, row.site_id)!r}")
            changed = False
            if row.device_name != name and not name == serial.lower():
                try:
                    check_unambiguous(db, site_id, name, serial, exclude_id=row.id)
                except DeviceConflict as exc:
                    return Registration(exc.row, "conflict", str(exc))
                row.device_name, changed = name, True
            return _touch(row, changed)

    same_name = (db.query(SiteDevice).filter(SiteDevice.device_name == name)
                 .order_by(SiteDevice.id).all())
    here = [r for r in same_name if r.site_id == site_id]
    if not serial and here:       # already registered here: nothing to check
        return _touch(here[0], False)
    try:
        check_unambiguous(db, site_id, name, serial)
    except DeviceConflict as exc:
        return Registration(exc.row, "conflict", str(exc))
    src = source if source in (SOURCE_CONFIG, SOURCE_MANUAL) else SOURCE_MANUAL
    if serial:
        cand = next((r for r in here if not r.serials), None)
        if cand is None:
            cand = next((r for r in here if r.is_ha and len(r.serials) < HA_MAX_MEMBERS), None)
        if cand is not None:
            cand.serials.append(_new_member(serial, src))
            return _touch(cand, True)
        # C-11(b): never spawn a SECOND same-name row at the site for an HA
        # cluster of that name - a new serial is a member, added via the
        # /serials path (or add_ha_member); creating a row here would bypass
        # the member cap and split the cluster.
        ha_here = next((r for r in here if r.is_ha), None)
        if ha_here is not None:
            return Registration(
                ha_here, "conflict",
                f"HA cluster {name!r} at site {_site_name(db, site_id)!r} already has "
                f"{len(ha_here.serials)} member serials (maximum {HA_MAX_MEMBERS}); add the "
                "serial with POST /site-devices/{id}/serials or remove a member first")
    row = SiteDevice(site_id=site_id, device_name=name, vendor=vendor, source=src)
    if serial:
        row.serials.append(_new_member(serial, src))
    db.add(row)
    db.flush()
    return Registration(row, "created")


# --------------------------------------------------- config registration --

_FORTI_START_RE = re.compile(r"^[ \t]*config system global\b", re.M | re.I)
_FORTI_HOST_RE = re.compile(
    r"^[ \t]*set hostname[ \t]+\"?([^\"\r\n]+?)\"?[ \t\r]*$", re.M | re.I)
_XML_HOST_RE = re.compile(r"<hostname>\s*([^<\s][^<]*?)\s*</hostname>", re.I)
_PAN_SET_HOST_RE = re.compile(r"^[ \t]*set deviceconfig system hostname\s+\"?([^\"\s]+)", re.M | re.I)
_CISCO_HOST_RE = re.compile(r"^[ \t]*hostname\s+\"?([^\"\s]+)", re.M | re.I)
_SERIAL_RE = re.compile(r"^#\s*(?:serial|serial[-_]?number|sn)\s*[=:]\s*([A-Za-z0-9-]{6,64})\s*$",
                        re.M | re.I)


def config_identity(text: str, device_type: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """(hostname, serial) found in a firewall config export, if any.
    FortiOS ``config system global / set hostname``, pfSense / PAN-OS XML
    ``<hostname>``, PAN-OS set ``deviceconfig system hostname``, Cisco
    ``hostname``.  Serials are only taken from an explicit ``#serial=``
    header comment (config exports normally carry none)."""
    text = text or ""
    host = None
    dt = (device_type or "").lower()
    order = [_FORTI_HOST_RE, _XML_HOST_RE, _PAN_SET_HOST_RE, _CISCO_HOST_RE]
    if "cisco" in dt or "asa" in dt:
        order = [_CISCO_HOST_RE] + order
    for rx in order:
        if rx is _FORTI_HOST_RE:
            # linear: first "config system global", then the first
            # "set hostname" after it (same result as the old .*? regex)
            start = _FORTI_START_RE.search(text)
            m = rx.search(text, start.end()) if start else None
        else:
            m = rx.search(text)
        if m:
            host = m.group(1).strip()
            break
    m = _SERIAL_RE.search(text)
    return (host or None), (m.group(1) if m else None)


def vendor_for_device_type(device_type: Optional[str]) -> Optional[str]:
    dt = (device_type or "").lower()
    if not dt or dt == "unknown":
        return None
    if "forti" in dt:
        return "fortinet"
    if "pfsense" in dt or "opnsense" in dt:
        return "pfsense"
    if "pan" in dt or "palo" in dt:
        return "panos"
    if "cisco" in dt or "asa" in dt:
        return "cisco_asa"
    return dt[:32]


_FORTI_HA_RE = re.compile(r"^[ \t]*config system ha[ \t]*\r?$", re.M | re.I)


@dataclass
class HAConfig:
    """``config system ha`` of a FortiOS config (B-12)."""
    mode: Optional[str]             # a-p | a-a | None (standalone / not HA)
    group_name: Optional[str] = None
    group_id: Optional[int] = None

    @property
    def is_ha(self) -> bool:
        return self.mode in HA_MODES


def ha_config(text: str) -> Optional[HAConfig]:
    """HA settings of a FortiOS config export, or None when it has no
    ``config system ha`` block (HA state is then left unchanged).  ``set
    mode a-p | a-a`` -> HA; standalone (the default when ``mode`` is
    absent) -> not HA.  Uses the config parser's tokenizer (also handles the
    multi-VDOM ``config global`` wrapping)."""
    text = text or ""
    if not _FORTI_HA_RE.search(text):
        return None
    from app.parsers.forti_config_parser import (
        flatten_global_vdom, parse_forti_block, sanitize_forti_tree,
    )
    try:
        tree = sanitize_forti_tree(flatten_global_vdom(parse_forti_block(text), quiet=True))
    except Exception:          # a config the parser cannot read: leave HA alone
        log.warning("ha_config: could not parse the config; HA state unchanged", exc_info=True)
        return None
    ha = tree.get("system ha")
    if not isinstance(ha, dict):
        return None

    def _scalar(v):
        if isinstance(v, list):
            v = " ".join(str(x) for x in v if isinstance(x, str))
        return str(v).strip() if v not in (None, "") else None

    mode = (_scalar(ha.get("mode")) or "standalone").lower()
    if mode not in HA_MODES:
        return HAConfig(None)
    gid = _scalar(ha.get("group-id"))
    try:
        gid = int(gid) if gid is not None else None
    except ValueError:
        gid = None
    gname = _scalar(ha.get("group-name"))
    return HAConfig(mode, (gname[:64] if gname else None), gid)


def _retag_held(db: Session, dev: SiteDevice) -> int:
    """Pending serial conflicts of ``dev`` follow its HA state: an HA
    device's unknown serials are ``ha_candidate``s, a standalone device's
    ``serial_conflict``s.  Returns the number of lines re-tagged."""
    want, other = (KIND_HA, KIND_SERIAL) if dev.is_ha else (KIND_SERIAL, KIND_HA)
    return db.query(UnmappedLogEvent).filter(
        UnmappedLogEvent.status == "pending", UnmappedLogEvent.kind == other,
        UnmappedLogEvent.registered_device_id == dev.id,
    ).update({UnmappedLogEvent.kind: want}, synchronize_session=False)


def apply_ha_config(db: Session, dev: SiteDevice, ha: HAConfig) -> dict:
    """Record a config's HA settings on its registered device (per site, per
    hostname - ``dev`` is the row the config registered).  Flushes."""
    before = (dev.is_ha, dev.ha_mode, dev.ha_group_name, dev.ha_group_id)
    dev.is_ha = ha.is_ha
    dev.ha_mode = ha.mode if ha.is_ha else None
    dev.ha_group_name = ha.group_name if ha.is_ha else None
    dev.ha_group_id = ha.group_id if ha.is_ha else None
    changed = before != (dev.is_ha, dev.ha_mode, dev.ha_group_name, dev.ha_group_id)
    if changed:
        dev.updated_at = utcnow()
        db.flush()
        log.info("site device %r (id=%s): HA %s (mode=%s group=%r/%s)", dev.device_name, dev.id,
                 "on" if dev.is_ha else "off", dev.ha_mode, dev.ha_group_name, dev.ha_group_id)
    retagged = _retag_held(db, dev)
    return {"is_ha": dev.is_ha, "ha_mode": dev.ha_mode, "ha_group_name": dev.ha_group_name,
            "ha_group_id": dev.ha_group_id, "changed": changed, "held_lines_retagged": retagged}


def register_from_config(db: Session, site_id: int, text: str, device_type: Optional[str],
                         label: Optional[str] = None,
                         evaluate: Optional[Callable] = None) -> dict:
    """Auto-registration on a firewall config upload: the config's hostname
    (else the explicit operator ``label``) and serial -> ``site_id``
    (source config_upload).  A device registered to a DIFFERENT site is not
    moved - it is reported in ``site_device_conflicts``.  A FortiOS
    ``config system ha`` block sets the device's HA state (B-12).  Newly
    registered devices replay their held log lines.  Commits."""
    host, serial = config_identity(text, device_type)
    name = host or label
    out = {"site_devices": [], "site_device_conflicts": []}
    if not name and not serial:
        return out
    reg = register(db, site_id, name, serial, vendor_for_device_type(device_type),
                   source=SOURCE_CONFIG)
    if reg.conflict:
        r = reg.row
        out["site_device_conflicts"].append({
            "device_name": normalise_name(name), "serial": serial,
            "registered_site_id": r.site_id if r else None,
            "registered_site": _site_name(db, r.site_id) if r else None,
            "upload_site_id": site_id, "message": reg.message,
        })
        db.commit()
        return out
    ha = ha_config(text) if vendor_for_device_type(device_type) in (None, "fortinet") else None
    ha_out = apply_ha_config(db, reg.row, ha) if ha is not None else None
    entry = {**device_dict(reg.row, {site_id: _site_name(db, site_id)}), "status": reg.status}
    if ha_out is not None:
        entry["ha"] = ha_out
    if reg.status in ("created", "updated"):
        entry["replay"] = replay_pending(db, reg.row, evaluate=evaluate)
    out["site_devices"].append(entry)
    db.commit()
    return out


# --------------------------------------------------------------- parsing --

def parse_item(source_route: str, raw_line: str, vendor_hint: Optional[str] = None,
               upload_ref: Optional[str] = None) -> Optional[dict]:
    """Parse one held line the way ``source_route`` parses it -> field dict
    with ``dedup_hash`` (None when it no longer parses)."""
    from app.parsers import forti_parser as fp
    from app.parsers.syslog_vendors import parse_syslog_any
    line = (raw_line or "").strip()
    if not line:
        return None
    if source_route == ROUTE_SYSLOG:
        try:
            fields = parse_syslog_any(line, vendor_hint)
        except ValueError:
            fields = parse_syslog_any(line, None)
    elif source_route == ROUTE_FORTI_SYSLOG:
        fields = fp.parse_cef_line(line) if fp._locate_cef(line) is not None \
            else fp.parse_forti_kv_line(line)
    elif source_route == ROUTE_FORTI_EVENT:
        try:
            payload = json.loads(line)
        except ValueError:
            return None
        return fp._json_fields(payload if isinstance(payload, dict) else {})
    elif source_route == ROUTE_FORTI_REPORT:
        rows = fp._parse_csv_rows(raw_line, upload_ref)
        if not rows or rows[0][0] is None:
            return None
        fields, dedup = rows[0]
        fields["dedup_hash"] = dedup
        return fields
    else:
        return None
    if not fields:
        return None
    fields["dedup_hash"] = fp._sha1(f"{fields.get('device_name') or ''}|{line}")
    return fields


# --------------------------------------------------------------- routing --

def _persist_in_site(db: Session, site_id: int, fields: dict):
    from app.parsers import forti_parser as fp
    with ingest_site(db, site_id):
        return fp._persist(fields, db)


def held_dedup_hash(device_key: str, serial: Optional[str], line_hash: str) -> str:
    """Queue dedup key of a held line (B-11): the resolved device key (incl.
    the ?device_name fallback) and the serial are part of it, so the same
    identity-less line uploaded for fwA and then for fwB is held twice -
    once per device - instead of the second being dropped as a duplicate."""
    from app.parsers import forti_parser as fp
    return fp._sha1(f"held|{device_key or ''}|{serial or ''}|{line_hash}")


@dataclass
class Decision:
    """Where one device identity's lines go: ``site_id`` (routed, ``device``
    the registry row when known) or held with ``kind`` (unmapped |
    serial_conflict | site_mismatch | ha_candidate)."""
    site_id: Optional[int] = None
    kind: Optional[str] = None
    registered: Optional[SiteDevice] = None     # the row a conflict collided with
    device: Optional[SiteDevice] = None
    bound_serial: Optional[str] = None          # serial first-sight bound by this decision (C-07c)


# ------------------------------------------------------- B-12 HA evidence --

# FortiOS FGCP HA event logs (type=event subtype=ha) whose ``sn`` names a
# cluster member: 37892 "Virtual cluster member state moved" (ha_role,
# vcluster_state, hostname, sn), 37894 "Virtual cluster member joined"
# (ha_group, sn).  Sources: module docstring.
HA_LOGID_STATE = "0108037892"
HA_LOGID_JOIN = "0108037894"
HA_EVIDENCE_LOGIDS = (HA_LOGID_STATE, HA_LOGID_JOIN)
_PRIMARY_ROLES = ("master", "primary")
_SECONDARY_ROLES = ("slave", "secondary", "backup", "standby")


@dataclass
class HAEvidence:
    logid: str
    logging_serial: str             # devid of the unit that wrote the log
    peer_serial: str                # sn - the member the log is about
    group_id: Optional[int] = None  # ha_group
    role: Optional[str] = None      # primary | secondary (37892 ha_role)
    hostname: Optional[str] = None  # hostname field (37892) - the logging cluster's name


def ha_evidence_of(fields: dict) -> Optional[HAEvidence]:
    """The HA facts of one parsed FortiGate log line, or None."""
    raw = fields.get("raw_fields") or {}
    if not isinstance(raw, dict):
        return None
    logid = str(_ci_get(raw, "logid") or "").strip()
    if logid not in HA_EVIDENCE_LOGIDS:
        return None
    if str(_ci_get(raw, "subtype") or fields.get("subtype") or "").strip().lower() != "ha":
        return None
    lsn = normalise_serial(_ci_get(raw, "devid", "deviceexternalid"))
    sn = normalise_serial(_ci_get(raw, "sn"))
    if not lsn or not sn:
        return None
    gid = _ci_get(raw, "ha_group")
    try:
        gid = int(str(gid).strip()) if gid is not None else None
    except ValueError:
        gid = None
    role = str(_ci_get(raw, "ha_role") or "").strip().lower()
    role = "primary" if role in _PRIMARY_ROLES else ("secondary" if role in _SECONDARY_ROLES else None)
    hostname = _ci_get(raw, "hostname")
    hostname = str(hostname).strip() if hostname not in (None, "") else None
    return HAEvidence(logid, lsn, sn, gid, role, hostname)


def _member_held_rows(db: Session, dev: SiteDevice, serial: str) -> list:
    """Pending held lines of ``serial`` that belong to ``dev`` now that the
    serial is one of its members: its serial conflicts / HA candidates, and
    unmapped lines carrying the serial under its name (or no name).  Lines
    whose upload named ANOTHER site (?site=) are left for the operator -
    never replayed across sites."""
    U = UnmappedLogEvent
    rows = db.query(U).filter(
        U.status == "pending", U.serial == serial,
        or_(U.kind.in_(SERIAL_KINDS) & (U.registered_device_id == dev.id),
            (U.kind == KIND_UNMAPPED) & U.device_key.in_(("", dev.device_name)))
    ).order_by(U.id).all()
    return [r for r in rows if r.map_site_id is None or r.map_site_id == dev.site_id]


def _record_member(db: Session, dev: SiteDevice, serial: str, action: str, rows: list,
                   replay: Optional[dict], resolved_by: Optional[str]) -> DeviceConflictResolution:
    rec = DeviceConflictResolution(
        resolved_at=utcnow(), action=action, kind=KIND_HA, device_key=dev.device_name,
        serial=serial, registered_device_id=dev.id, registered_site_id=dev.site_id,
        registered_serial=next((m.serial for m in dev.serials if m.serial != serial), None),
        target_site_id=dev.site_id, device_id=dev.id, lines=len(rows),
        events_created=(replay or {}).get("events_created", 0),
        findings_created=(replay or {}).get("findings_created", 0), resolved_by=resolved_by)
    db.add(rec)
    db.flush()
    return rec


def add_member_and_replay(db: Session, dev: SiteDevice, serial, source: str, action: str,
                          resolved_by: Optional[str] = None,
                          evaluate: Optional[Callable] = None) -> dict:
    """Add a member serial to ``dev`` (add_member rules) and replay the
    lines held for it into the device's site; audited in
    device_conflict_resolutions.  Raises MemberError (nothing changed)."""
    member, created = add_member(db, dev, serial, source)
    rows = _member_held_rows(db, dev, member.serial)
    replay = _replay_rows(db, rows, dev.site_id, evaluate) if rows else None
    rec = _record_member(db, dev, member.serial, action, rows, replay, resolved_by) \
        if (created or rows) else None
    return {"member": member_dict(member), "created": created, "replay": replay,
            "resolution_id": rec.id if rec is not None else None}


def process_ha_evidence(db: Session, fields: dict, evaluate: Optional[Callable] = None,
                        skip_logging_serial: Optional[str] = None) -> Optional[dict]:
    """B-12: act on an FGCP HA event log.  When the logging unit (devid) is a
    member of an HA device and the log names another unit (sn) of the same
    group (ha_group vs the configured group-id, when the device's group is
    known) that is registered nowhere, the unit is added as a member
    (``ha_evidence``) and its held lines are replayed.  Never across sites
    (the peer joins the logging unit's device), never beyond HA_MAX_MEMBERS.

    C-07 (anti-spoofing): a peer is only added as a member when the evidence
    is trustworthy -
      * the logging serial must be an ALREADY-known member - a serial that
        this very line first-sight bound (``skip_logging_serial``) is not yet
        trusted, so it cannot in the same breath vouch for a peer;
      * when the log carries a ``hostname`` it must name the logging device;
      * when the device's HA group is known the log must carry that group
        (a log with no / another group is NOT evidence).
    Returns what was done, or None.  Flushes."""
    evd = ha_evidence_of(fields)
    if evd is None or evd.peer_serial == evd.logging_serial:
        return None
    # C-07(c): evidence must come from an already-known member, never from a
    # serial that this same line just bound on first sight.
    if skip_logging_serial and evd.logging_serial == skip_logging_serial:
        return None
    dev = serial_owner(db, evd.logging_serial)
    if dev is None or not dev.is_ha:
        return None
    owner = serial_owner(db, evd.peer_serial)
    if owner is not None:
        return None if owner.id == dev.id else {
            "device_id": dev.id, "serial": evd.peer_serial, "status": "registered_elsewhere"}
    # about to ADD evd.peer_serial as a new member - require strong evidence
    # C-07(a): when the log names a hostname it must be the logging device's.
    if evd.hostname is not None and normalise_name(evd.hostname) != dev.device_name:
        log.info("HA evidence ignored: hostname %r != device %r (logger %s names %s)",
                 evd.hostname, dev.device_name, evd.logging_serial, evd.peer_serial)
        return {"device_id": dev.id, "serial": evd.peer_serial, "status": "hostname_mismatch"}
    # C-07(b): when the device's HA group is known, the log must match it
    # (a log that omits ha_group, or carries another, is not evidence).
    if dev.ha_group_id is not None and evd.group_id != dev.ha_group_id:
        log.info("HA evidence ignored: %s names %s in group %s, device %r is group %s",
                 evd.logging_serial, evd.peer_serial, evd.group_id, dev.device_name, dev.ha_group_id)
        return {"device_id": dev.id, "serial": evd.peer_serial, "status": "group_mismatch"}
    try:
        out = add_member_and_replay(db, dev, evd.peer_serial, SERIAL_HA_EVIDENCE,
                                    ACTION_HA_EVIDENCE, AUTO_RESOLVED_BY, evaluate)
    except MemberError as exc:
        log.warning("HA evidence for %r on device %r not applied: %s",
                    evd.peer_serial, dev.device_name, exc)
        return {"device_id": dev.id, "serial": evd.peer_serial, "status": "refused",
                "message": str(exc)}
    log.warning("B-12: serial %r added to HA device %r (id=%s, site %s) on HA log %s from %r; "
                "%d held line(s) replayed", evd.peer_serial, dev.device_name, dev.id, dev.site_id,
                evd.logid, evd.logging_serial, (out["replay"] or {}).get("lines", 0))
    return {"device_id": dev.id, "device_name": dev.device_name, "site_id": dev.site_id,
            "serial": evd.peer_serial, "status": "added", "logid": evd.logid,
            "evidenced_by": evd.logging_serial, "replay": out["replay"]}


# ----------------------------------------------------- B-12 HA failover --

_ACTIVE_LOG_TYPES = ("traffic", "utm", "ips")


def _event_ts(ev):
    return getattr(ev, "event_time", None) or getattr(ev, "received_at", None) or utcnow()


def track_member_activity(db: Session, ev) -> Optional[dict]:
    """Note which unit logged ``ev`` (``last_seen_at`` of its serial) and,
    for an active-passive HA cluster, whether the ACTIVE member changed.

    Active signal: a forwarded-traffic / UTM line (only the primary of an a-p
    cluster processes traffic; ``subtype=local`` is excluded - every unit
    logs its own local traffic) logged by a member, or an FGCP "member state
    moved" log (0108037892) naming a member with ha_role master/primary.
    When the active member differs from the member last seen active (and the
    line is not older than that member's last line), returns
    {device, from_serial, to_serial, at, via}; the caller raises the
    ``ha_failover`` finding.  a-a clusters (both units log traffic,
    interleaved) and clusters of unknown mode never fail over here.  Only
    the event's own site is touched.  Flushes nothing (ORM changes only)."""
    raw = ev.raw_fields if isinstance(getattr(ev, "raw_fields", None), dict) else {}
    lsn = normalise_serial(_ci_get(raw, "devid", "deviceexternalid", "serial"))
    if not lsn:
        return None
    me = member_of(db, lsn)
    if me is None:
        return None
    dev = me.device
    if dev is None or (getattr(ev, "site_id", None) is not None and dev.site_id != ev.site_id):
        return None
    ts = _event_ts(ev)
    if me.last_seen_at is None or ts > me.last_seen_at:
        me.last_seen_at = ts
    if not dev.is_ha:
        return None
    target, role, via = None, None, None
    evd = ha_evidence_of({"raw_fields": raw, "subtype": getattr(ev, "subtype", None)})
    if evd is not None and evd.logid == HA_LOGID_STATE and evd.role:
        target = next((m for m in dev.serials if m.serial == evd.peer_serial), None)
        role, via = evd.role, "ha_state_log"
    elif (getattr(ev, "log_type", None) or "").lower() in _ACTIVE_LOG_TYPES \
            and (getattr(ev, "subtype", None) or "").lower() != "local":
        target, role, via = me, "primary", "traffic"
    if target is None:
        return None
    if role == "secondary":
        target.last_role = "secondary"
        return None
    if dev.ha_mode != "a-p":
        return None        # active-active: both members log traffic
    prev = next((m for m in dev.serials if m.last_role == "primary" and m is not target), None)
    if target.last_role == "primary" and prev is None:
        return None
    # C-11(a): last-write-wins by the log's own timestamp - an older state /
    # traffic line arriving after a newer one (out-of-order upload) must not
    # flip the active member backward.  Applies to every evidence source, not
    # only forwarded traffic (an older 37892 "member master" state log would
    # otherwise raise a false failover).
    if prev is not None and prev.last_seen_at is not None and ts < prev.last_seen_at:
        return None        # an older line (out-of-order upload): not a failover
    for m in dev.serials:
        m.last_role = "primary" if m is target else ("secondary" if m.last_role == "primary"
                                                    else m.last_role)
    if prev is None:
        return None        # first active member seen: baseline, no failover
    return {"device": dev, "from_serial": prev.serial, "to_serial": target.serial,
            "at": ts, "via": via}


# --------------------------------------------------------------- router --

@dataclass
class LogRouter:
    """Per-upload router.  ``handle(fields, raw_line)`` returns
    (status, event) with status created | duplicate | unmapped |
    unmapped_duplicate | conflict | conflict_duplicate."""
    db: Session
    source_route: str
    map_site: Optional[Site] = None
    upload_ref: Optional[str] = None
    fallback_device: Optional[str] = None
    evaluate: Optional[Callable] = None
    created: list = field(default_factory=list)
    new_devices: list = field(default_factory=list)
    bound_devices: list = field(default_factory=list)
    ha_members: list = field(default_factory=list)
    _routed: dict = field(default_factory=dict)
    _cache: dict = field(default_factory=dict)
    unmapped: int = 0
    unmapped_duplicates: int = 0
    conflicts: int = 0
    conflict_duplicates: int = 0
    serial_conflicts: int = 0
    site_conflicts: int = 0
    ha_candidates: int = 0

    def _decide(self, name, serial, vendor) -> Decision:
        db, ms = self.db, self.map_site
        if not name and not serial:
            return Decision(site_id=ms.id) if ms else Decision(kind=KIND_UNMAPPED)
        dev = serial_owner(db, serial)            # a registered serial always wins
        bind = None
        if dev is None and name:
            rows = (db.query(SiteDevice).filter(SiteDevice.device_name == name)
                    .order_by(SiteDevice.id).all())
            sites = {r.site_id for r in rows}
            if rows and serial:
                unbound = [r for r in rows if not r.serials]
                if len(sites) == 1 and unbound:
                    dev, bind = unbound[0], serial   # first serial seen for this device
                else:
                    # the name is registered with other serial(s): never guess.
                    # B-12: an HA cluster of that name -> a member candidate
                    ha = [r for r in rows if r.is_ha]
                    if len(ha) == 1:
                        return Decision(kind=KIND_HA, registered=ha[0])
                    return Decision(kind=KIND_SERIAL, registered=rows[0] if len(rows) == 1 else None)
            elif rows:
                if len(sites) != 1:
                    return Decision(kind=KIND_UNMAPPED)   # ambiguous name, no serial
                dev = rows[0]
        if dev is not None:
            if ms is not None and dev.site_id != ms.id:
                return Decision(kind=KIND_SITE, registered=dev)
            if bind:
                set_serial(dev, bind, SERIAL_FIRST_SEEN)
                db.flush()
                if dev not in self.bound_devices:
                    self.bound_devices.append(dev)
                log.info("site device %r (id=%s): serial %r bound on first sight",
                         dev.device_name, dev.id, bind)
            return Decision(site_id=dev.site_id, device=dev, bound_serial=bind)
        if ms is None:
            return Decision(kind=KIND_UNMAPPED)
        reg = register(db, ms.id, name, serial, vendor, source=SOURCE_MANUAL)
        if reg.conflict:          # e.g. an ambiguous name: hold the line
            return Decision(kind=KIND_UNMAPPED)
        if reg.status in ("created", "updated") and reg.row not in self.new_devices:
            self.new_devices.append(reg.row)
        return Decision(site_id=ms.id, device=reg.row)

    def _site_for(self, name, serial, vendor) -> Decision:
        key = (name, serial)
        if key not in self._cache:
            self._cache[key] = self._decide(name, serial, vendor)
        return self._cache[key]

    def handle(self, fields: dict, raw_line: str):
        name, serial, vendor = identity_from_fields(fields)
        # C-16: an over-long devid / devname would overflow the String columns
        # (DataError -> 500 on PostgreSQL).  Never route it (it could be
        # misidentified) - hold it as a malformed unmapped line.
        if len(name) > MAX_DEVICE_NAME_LEN or (serial is not None and len(serial) > MAX_SERIAL_LEN):
            return self._queue_malformed(fields, raw_line), None
        if not name and not serial and self.fallback_device:
            name = normalise_name(self.fallback_device)
        # C-07(c): only the line that ITSELF performs a first-sight bind is
        # barred from vouching for a peer; a serial bound by an earlier line
        # in this upload is an already-known member and may be evidence.
        fresh = (name, serial) not in self._cache
        d = self._site_for(name, serial, vendor)
        if d.site_id is None:
            return self._queue(fields, raw_line, name, serial, vendor, d), None
        ev, status = _persist_in_site(self.db, d.site_id, fields)
        per = self._routed.setdefault(d.site_id, {"events_created": 0, "duplicates_skipped": 0})
        if status == "created" and ev is not None:
            if self.fallback_device and not ev.device_name:
                ev.device_name = self.fallback_device
            self.created.append(ev)
            per["events_created"] += 1
        else:
            per["duplicates_skipped"] += 1
        if d.device is not None and d.device.is_ha:
            self._ha_evidence(fields, just_bound=d.bound_serial if fresh else None)
        return status, ev

    def _ha_evidence(self, fields: dict, just_bound: Optional[str] = None) -> None:
        """B-12: an HA log from a member may evidence a peer -> member added,
        its held lines replayed, later lines of this upload routed.  C-07(c):
        a serial first-sight bound by this same line cannot vouch for a peer
        (``just_bound``)."""
        out = process_ha_evidence(self.db, fields, self.evaluate, skip_logging_serial=just_bound)
        if not out:
            return
        if out.get("status") == "added":
            self._cache = {k: v for k, v in self._cache.items() if k[1] != out["serial"]}
        self.ha_members.append(out)

    def _queue_malformed(self, fields: dict, raw_line: str) -> str:
        """C-16: hold a line whose devid / devname is too long for the String
        columns.  Its identity is NOT stored (it could be misidentified and
        would overflow); the line is grouped under ``__malformed__`` so an
        operator can inspect it.  Counts as an unmapped (held) line."""
        db = self.db
        line_hash = fields.get("dedup_hash") or ""
        dedup = held_dedup_hash(MALFORMED_KEY, None, line_hash)
        if db.query(UnmappedLogEvent.id).filter(UnmappedLogEvent.dedup_hash == dedup).first():
            self.unmapped_duplicates += 1
            return "unmapped_duplicate"
        vendor = fields.get("vendor")
        db.add(UnmappedLogEvent(
            raw_line=raw_line, device_key=MALFORMED_KEY, serial=None,
            vendor=(vendor or None) and str(vendor)[:32], source_route=self.source_route,
            received_at=utcnow(), dedup_hash=dedup,
            upload_ref=(self.upload_ref or None) and str(self.upload_ref)[:255],
            status="pending", kind=KIND_UNMAPPED))
        db.flush()
        self.unmapped += 1
        return "unmapped"

    def _queue(self, fields, raw_line, name, serial, vendor, d: Decision) -> str:
        db = self.db
        kind = d.kind or KIND_UNMAPPED
        conflict = kind in CONFLICT_KINDS
        if kind == KIND_SERIAL:
            self.serial_conflicts += 1
        elif kind == KIND_SITE:
            self.site_conflicts += 1
        elif kind == KIND_HA:
            self.ha_candidates += 1
        dedup = held_dedup_hash(name, serial, fields["dedup_hash"])
        if db.query(UnmappedLogEvent.id).filter(UnmappedLogEvent.dedup_hash == dedup).first():
            if conflict:
                self.conflict_duplicates += 1
                return "conflict_duplicate"
            self.unmapped_duplicates += 1
            return "unmapped_duplicate"
        reg = d.registered
        db.add(UnmappedLogEvent(
            raw_line=raw_line, device_key=name or "", serial=serial,
            vendor=(vendor or None) and str(vendor)[:32], source_route=self.source_route,
            received_at=utcnow(), dedup_hash=dedup,
            upload_ref=(self.upload_ref or None) and str(self.upload_ref)[:255],
            status="pending", kind=kind,
            registered_device_id=reg.id if reg is not None else None,
            registered_site_id=reg.site_id if reg is not None else None,
            registered_serial=reg.serial if reg is not None else None,
            map_site_id=self.map_site.id if (conflict and self.map_site) else None))
        db.flush()
        if conflict:
            self.conflicts += 1
            return "conflict"
        self.unmapped += 1
        return "unmapped"

    def summary(self) -> dict:
        names = {}
        if self._routed:
            names = dict(self.db.query(Site.id, Site.name)
                         .filter(Site.id.in_(list(self._routed))).all())
        return {
            "map_site": self.map_site.name if self.map_site else None,
            "routed": {names.get(sid, str(sid)): {"site_id": sid, **c}
                       for sid, c in sorted(self._routed.items())},
            "unmapped": self.unmapped,
            "unmapped_duplicates": self.unmapped_duplicates,
            # B-11: held conflicts (new / already held) and per kind (lines)
            "conflicts": self.conflicts,
            "conflict_duplicates": self.conflict_duplicates,
            "serial_conflicts": self.serial_conflicts,
            "site_conflicts": self.site_conflicts,
            # B-12: lines held as HA member candidates; members added on evidence
            "ha_candidates": self.ha_candidates,
            "ha_members": [{k: v for k, v in m.items()} for m in self.ha_members],
            "serial_bindings": [{"device_id": d.id, "device_name": d.device_name,
                                 "serial": d.serial, "site_id": d.site_id}
                                for d in self.bound_devices],
            "new_mappings": len(self.new_devices),
            "mapped_devices": [device_dict(d) for d in self.new_devices],
        }


def created_by_site(events) -> dict[int, list]:
    out: dict[int, list] = {}
    for ev in events:
        if ev is not None:
            out.setdefault(ev.site_id, []).append(ev)
    return out


def record_rule_hits_per_site(db: Session, events) -> int:
    """F-10 rule hits for routed events, each site's events matched only
    against that site's rules."""
    from app.parsers.rule_hits import record_rule_hits_safe
    from app.parsers.site_scope import analysis_site
    total = 0
    for sid, evs in created_by_site(events).items():
        with analysis_site(db, sid):
            total += record_rule_hits_safe(db, evs)
    return total


# ----------------------------------------------------------------- replay --

def _replay_rows(db: Session, rows, site_id: int, evaluate: Optional[Callable] = None) -> dict:
    """Replay held lines into ``site_id`` through the normal ingest path
    (stored, deduplicated, real-time checks run there) and mark them
    replayed.  An HA log among them may evidence a peer (B-12), whose own
    held lines are then replayed too (rows already handled that way are
    skipped here).  Does not commit."""
    if evaluate is None:
        from app.parsers.alert_engine import evaluate_event as evaluate
    stats = {"lines": 0, "events_created": 0, "duplicates_skipped": 0, "parse_failures": 0,
             "findings_created": 0, "finding_ids": [], "rule_hits_updated": 0, "claimed": 0}
    created = []
    findings = []
    # C-19: claim the rows with a conditional UPDATE (status pending ->
    # replayed) so two operators resolving the same group concurrently cannot
    # both replay them; rows another transaction already claimed are skipped.
    claimed: set = set()
    for r in rows:
        if r.status != "pending":
            continue
        n = (db.query(UnmappedLogEvent)
             .filter(UnmappedLogEvent.id == r.id, UnmappedLogEvent.status == "pending")
             .update({UnmappedLogEvent.status: "replayed"}, synchronize_session=False))
        if n:
            claimed.add(r.id)
    stats["claimed"] = len(claimed)
    for row in rows:
        if row.id not in claimed:
            continue
        row.status = "replayed"          # mirror the claim on the loaded object
        stats["lines"] += 1
        fields = parse_item(row.source_route, row.raw_line, vendor_hint=row.vendor,
                            upload_ref=row.upload_ref)
        if fields is None:
            stats["parse_failures"] += 1
            row.status = "discarded"
            continue
        ev, status = _persist_in_site(db, site_id, fields)
        row.status = "replayed"
        if status == "created" and ev is not None:
            if not ev.device_name and row.device_key:
                ev.device_name = row.device_key
            created.append(ev)
            stats["events_created"] += 1
            findings.extend(f for f in (evaluate(ev, db) or []) if f)
        else:
            stats["duplicates_skipped"] += 1
        process_ha_evidence(db, fields, evaluate)
    db.flush()
    stats["rule_hits_updated"] = record_rule_hits_per_site(db, created)
    stats["findings_created"] = len(findings)
    stats["finding_ids"] = [f.id for f in findings]
    return stats


def _name_is_ambiguous(db: Session, device: SiteDevice) -> bool:
    """True when another registered device shares ``device``'s name (the same
    name lives at more than one site).  A serial-less held line matched only
    by such a name could belong to either device, so it must never be routed
    by name alone (C-06 "never guess a site")."""
    return db.query(SiteDevice.id).filter(
        SiteDevice.device_name == device.device_name,
        SiteDevice.id != device.id).first() is not None


def _pending_for(db: Session, device: SiteDevice) -> list:
    """Pending UNMAPPED held lines of ``device`` to replay, in arrival order.

    C-06: a held line is (re)routed to ``device`` only when the match is
    UNAMBIGUOUS - by one of the device's member serials, or by name when that
    name is unique across sites.  When the same ``device_name`` is registered
    at more than one site, serial-less held lines of that name STAY held
    (resolved explicitly via the conflicts flow) and are never auto-replayed
    into one of the sites by an unrelated create/update.

    Lines held as conflicts wait for a resolution.  A name-matched line whose
    serial is not one of the device's is another physical unit: with a serial
    registered nowhere it becomes a serial_conflict (an ha_candidate for an HA
    device, B-12); the first serial seen binds a device that has none
    (``first_seen``) - but only for an unambiguous (unique) name."""
    members = device.member_serials
    ambiguous = _name_is_ambiguous(db, device)
    if ambiguous:
        # unambiguous match only: lines carrying one of this device's serials.
        # A bare name match could be the other site's device - leave it held.
        if not members:
            return []
        return db.query(UnmappedLogEvent).filter(
            UnmappedLogEvent.status == "pending", UnmappedLogEvent.kind == KIND_UNMAPPED,
            UnmappedLogEvent.serial.in_(members)).order_by(UnmappedLogEvent.id).all()

    conds = [UnmappedLogEvent.device_key == device.device_name]
    if members:
        conds.append(UnmappedLogEvent.serial.in_(members))
    q = db.query(UnmappedLogEvent).filter(UnmappedLogEvent.status == "pending",
                                          UnmappedLogEvent.kind == KIND_UNMAPPED, or_(*conds))
    rows = []
    for r in q.order_by(UnmappedLogEvent.id).all():
        if r.serial and r.serial not in device.member_serials:
            owner = serial_owner(db, r.serial)
            if owner is not None and owner.id != device.id:
                continue                      # belongs to another registered device
            if not device.serials:
                set_serial(device, r.serial, SERIAL_FIRST_SEEN)
                db.flush()
            else:
                r.kind = KIND_HA if device.is_ha else KIND_SERIAL
                r.registered_device_id, r.registered_site_id = device.id, device.site_id
                r.registered_serial = device.serial
                continue
        rows.append(r)
    return rows


def replay_pending(db: Session, device: SiteDevice, evaluate: Optional[Callable] = None) -> dict:
    """Replay the held (unmapped) lines of ``device`` into its site (normal
    ingest path: stored, deduplicated, real-time checks run) and mark them
    replayed.  Does not commit."""
    return _replay_rows(db, _pending_for(db, device), device.site_id, evaluate)


# -------------------------------------------------------------- conflicts --

class ResolveError(ValueError):
    """A conflict resolution that cannot be applied (HTTP ``status``)."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def _conflict_query(db: Session, device_key, kind: str, serial):
    U = UnmappedLogEvent
    q = db.query(U).filter(U.status == "pending", U.kind == kind,
                           U.device_key == normalise_name(device_key))
    serial = normalise_serial(serial)
    q = q.filter(U.serial == serial) if serial else q.filter(U.serial.is_(None))
    return q.order_by(U.id)


def _registered_of(db: Session, rows, device_id: Optional[int]) -> SiteDevice:
    if device_id is not None:
        dev = db.get(SiteDevice, int(device_id))
        if dev is None:
            raise ResolveError(f"site device id={device_id} not found", 404)
        return dev
    ids = {r.registered_device_id for r in rows if r.registered_device_id is not None}
    if len(ids) == 1:
        dev = db.get(SiteDevice, ids.pop())
        if dev is not None:
            return dev
    # snapshot missing (ambiguous name) or the device was deleted since
    cands = db.query(SiteDevice).filter(SiteDevice.device_name == rows[0].device_key).all()
    if len(cands) == 1:
        return cands[0]
    raise ResolveError("the registered device is ambiguous or gone: pass device_id "
                       f"(candidates: {[c.id for c in cands]})", 422)


def mark_ha(db: Session, dev: SiteDevice) -> None:
    """An operator confirmed ``dev`` is an HA cluster (mode stays unknown
    until a config upload states it).  Flushes."""
    if not dev.is_ha:
        dev.is_ha = True
        dev.updated_at = utcnow()
        db.flush()
        _retag_held(db, dev)


RESOLVE_ACTIONS = ("same_device", "different_device", "discard", ACTION_ADD_HA)


def resolve_conflict(db: Session, device_key, kind: str, serial, action: str,
                     site: Optional[Site] = None, device_name=None, device_id=None,
                     resolved_by: Optional[str] = None, mark_ha_device: bool = False,
                     evaluate: Optional[Callable] = None) -> dict:
    """Apply an operator decision to one conflict group (device_key, kind,
    serial).  same_device: the registered device is the emitter (replaced
    unit: its serial becomes the line's) -> replay into its site;
    different_device: register a new device (``device_name`` or the key,
    the line's serial) at ``site`` -> replay there; add_ha_member (B-12):
    the line's serial becomes a member of the registered HA device (a
    standalone device only with ``mark_ha_device``) -> replay into its site;
    discard: drop the held lines.  Records a DeviceConflictResolution.
    Flushes, does not commit; raises ResolveError (nothing changed)."""
    if kind not in CONFLICT_KINDS:
        raise ResolveError(f"kind must be one of {', '.join(CONFLICT_KINDS)}", 422)
    if action not in RESOLVE_ACTIONS:
        raise ResolveError(f"action must be one of {', '.join(RESOLVE_ACTIONS)}", 422)
    key, serial = normalise_name(device_key), normalise_serial(serial)
    rows = _conflict_query(db, key, kind, serial).all()
    if not rows:
        raise ResolveError(f"no pending {kind} lines for device {key!r} serial {serial!r}", 404)
    db.refresh(rows[0])             # C-19: see a concurrent resolver's claim
    if rows[0].status != "pending":
        raise ResolveError(f"the {kind} lines for device {key!r} are being resolved by another "
                           "request; reload the conflict list", 409)
    snap = rows[-1]
    rec = DeviceConflictResolution(
        resolved_at=utcnow(), action=action, kind=kind, device_key=key, serial=serial,
        registered_device_id=snap.registered_device_id,
        registered_site_id=snap.registered_site_id, registered_serial=snap.registered_serial,
        lines=len(rows), events_created=0, findings_created=0,
        resolved_by=(str(resolved_by).strip()[:128] or None) if resolved_by else None)
    replay = None
    target: Optional[SiteDevice] = None
    if action == "discard":
        for r in rows:
            r.status = "discarded"
    elif action == ACTION_ADD_HA:
        if kind == KIND_SITE:
            raise ResolveError("a site mismatch carries the registered device's own identity; "
                               "add_ha_member applies to serial conflicts / HA candidates")
        if not serial:
            raise ResolveError("the held lines carry no serial to add as an HA member", 422)
        target = _registered_of(db, rows, device_id)
        rec.registered_device_id, rec.registered_site_id = target.id, target.site_id
        rec.registered_serial = target.serial
        if not target.is_ha:
            if not mark_ha_device:
                raise ResolveError(f"device {target.device_name!r} is not marked as an HA cluster; "
                                   "confirm with mark_ha: true (or upload its config with "
                                   "'config system ha')")
            mark_ha(db, target)
        try:
            add_member(db, target, serial, SERIAL_RESOLUTION)
        except MemberError as exc:
            raise ResolveError(str(exc), exc.status)
    elif action == "same_device":
        target = _registered_of(db, rows, device_id)
        rec.registered_device_id, rec.registered_site_id = target.id, target.site_id
        rec.registered_serial = target.serial
        if serial and serial not in target.member_serials:
            if kind == KIND_SITE and target.serials:
                raise ResolveError(f"serial {serial!r} differs from the registered serial "
                                   f"{target.serial!r}; resolve it as a serial conflict")
            if len(target.serials) > 1:
                raise ResolveError(f"device {target.device_name!r} is an HA cluster with "
                                   f"{len(target.serials)} member serials; remove the replaced "
                                   "unit's serial (DELETE /site-devices/{id}/serials/{serial}) and "
                                   "choose Add as HA member")
            owner = serial_owner(db, serial)
            if owner is not None and owner.id != target.id:
                raise ResolveError(f"serial {serial!r} is registered to device "
                                   f"{owner.device_name!r} (site {_site_name(db, owner.site_id)!r})")
            set_serial(target, serial, SERIAL_RESOLUTION)
            db.flush()
    else:   # different_device
        if site is None:
            raise ResolveError("site is required for different_device", 422)
        name = normalise_name(device_name) or key
        if not name and not serial:
            raise ResolveError("device_name is required (the lines carry no identity)", 422)
        reg = register(db, site.id, name, serial, snap.vendor, source=SOURCE_MANUAL)
        if reg.conflict:
            raise ResolveError(reg.message + "; a different device needs its own serial or "
                               "name (remap the registered device with PATCH /site-devices/{id} "
                               "if it moved, then choose same_device)")
        if reg.status != "created" and reg.row is not None and (
                reg.row.id == snap.registered_device_id or not serial):
            raise ResolveError(f"device {name!r} at site {site.name!r} is the registered device "
                               "itself; choose same_device, or give the other device a distinct "
                               "name or serial")
        target = reg.row
        for m in target.serials:
            if serial and m.serial == serial and m.source != SERIAL_RESOLUTION:
                m.source = SERIAL_RESOLUTION
        db.flush()
    if target is not None:
        replay = _replay_rows(db, rows, target.site_id, evaluate)
        rec.target_site_id, rec.device_id = target.site_id, target.id
        rec.events_created = replay["events_created"]
        rec.findings_created = replay["findings_created"]
    db.add(rec)
    db.flush()
    log.warning("B-11 conflict resolved: %s %s device=%r serial=%r lines=%d -> site %s",
                action, kind, key, serial, len(rows), rec.target_site_id)
    return {"resolution": resolution_dict(rec, site_names_map(db)), "replay": replay,
            "device": device_dict(target, site_names_map(db)) if target is not None else None}


def site_names_map(db: Session) -> dict:
    return dict(db.query(Site.id, Site.name).all())


def resolution_dict(r: DeviceConflictResolution, names: Optional[dict] = None) -> dict:
    names = names or {}
    return {
        "id": r.id, "resolved_at": r.resolved_at, "action": r.action, "kind": r.kind,
        "device_key": r.device_key, "serial": r.serial,
        "registered_device_id": r.registered_device_id,
        "registered_site_id": r.registered_site_id,
        "registered_site": names.get(r.registered_site_id),
        "registered_serial": r.registered_serial,
        "target_site_id": r.target_site_id, "target_site": names.get(r.target_site_id),
        "device_id": r.device_id, "lines": r.lines, "events_created": r.events_created,
        "findings_created": r.findings_created, "resolved_by": r.resolved_by,
    }


def conflict_count(db: Session) -> int:
    return db.query(func.count(UnmappedLogEvent.id)).filter(
        UnmappedLogEvent.status == "pending",
        UnmappedLogEvent.kind.in_(CONFLICT_KINDS)).scalar() or 0


def _add_ha_option(k: str, dev: Optional[SiteDevice], serial) -> tuple[bool, bool, str]:
    """(allowed, needs mark_ha confirmation, hint) of add_ha_member."""
    if k == KIND_SITE:
        return False, False, "not applicable - the lines carry the registered device's identity"
    if dev is None:
        return False, False, "the registered device is ambiguous or gone"
    if not serial:
        return False, False, "the lines carry no serial"
    if dev.is_ha and len(dev.serials) >= HA_MAX_MEMBERS:
        return False, False, (f"the cluster already has {len(dev.serials)} member serials "
                              f"(maximum {HA_MAX_MEMBERS}); remove one first")
    if not dev.is_ha:
        return True, True, (f"{dev.device_name} is not marked as an HA cluster - adding the "
                            "member marks it HA")
    return True, False, f"add serial {serial} as member {len(dev.serials) + 1} of the cluster"


def conflicts_summary(db: Session, detail: bool = False, site_id: Optional[int] = None,
                      kind: Optional[str] = None, limit: int = 100) -> dict:
    """Pending conflicts grouped by (device_key, kind, serial): counts,
    first/last seen, the registered device (live row, else the snapshot),
    the line serial, vendor, the requested ?site(s), a sample line.
    ``site_id`` keeps groups whose registered or requested site it is."""
    U = UnmappedLogEvent
    base = [U.status == "pending", U.kind.in_(CONFLICT_KINDS)]
    if kind:
        base.append(U.kind == kind)
    if site_id is not None:
        base.append(or_(U.registered_site_id == site_id, U.map_site_id == site_id))
    groups = (db.query(U.device_key, U.kind, U.serial, func.count(U.id), func.min(U.received_at),
                       func.max(U.received_at), func.max(U.id))
              .filter(*base).group_by(U.device_key, U.kind, U.serial)
              .order_by(func.max(U.id).desc()).all())
    names = site_names_map(db)
    out = []
    for key, k, serial, n, first, last, last_id in groups:
        latest = db.get(U, last_id)
        grp = [U.device_key == key, U.kind == k,
               (U.serial == serial) if serial is not None else U.serial.is_(None), *base]
        req_sites = sorted({sid for (sid,) in db.query(U.map_site_id).filter(*grp)
                            .distinct() if sid is not None})
        dev = db.get(SiteDevice, latest.registered_device_id) \
            if latest.registered_device_id is not None else None
        if dev is not None:
            registered = {"id": dev.id, "device_name": dev.device_name, "site_id": dev.site_id,
                          "site": names.get(dev.site_id), "serial": dev.serial,
                          "serial_source": dev.serial_source, "live": True,
                          "is_ha": bool(dev.is_ha), "ha_mode": dev.ha_mode,
                          "ha_group_name": dev.ha_group_name,
                          "members": dev.member_serials, "max_members": HA_MAX_MEMBERS}
        elif latest.registered_site_id is not None or latest.registered_device_id is not None:
            registered = {"id": latest.registered_device_id, "device_name": key,
                          "site_id": latest.registered_site_id,
                          "site": names.get(latest.registered_site_id),
                          "serial": latest.registered_serial, "serial_source": None,
                          "live": False, "is_ha": False, "ha_mode": None, "ha_group_name": None,
                          "members": [], "max_members": HA_MAX_MEMBERS}
        else:
            registered = None
        candidates = [{"id": c.id, "site_id": c.site_id, "site": names.get(c.site_id),
                       "serial": c.serial}
                      for c in db.query(SiteDevice).filter(SiteDevice.device_name == key)
                      .order_by(SiteDevice.id)] if registered is None else []
        if k in SERIAL_KINDS:
            dd_ok, dd_hint = True, ("register a separate device with serial "
                                    f"{serial} at the site you pick")
        else:
            dd_ok = False
            dd_hint = ("not possible - the lines carry the registered device's identity. "
                       "If the device moved, remap it, then choose Same device")
        ha_ok, ha_mark, ha_hint = _add_ha_option(k, dev, serial)
        entry = {
            "device_key": key, "kind": k, "serial": serial, "count": n,
            "first_seen": first, "last_seen": last,
            "vendor": latest.vendor, "source_route": latest.source_route,
            "registered": registered, "candidates": candidates,
            "requested_site_ids": req_sites,
            "requested_sites": [names.get(s, str(s)) for s in req_sites],
            "sample_line": (latest.raw_line or "")[:_SAMPLE_MAX],
            "different_device_allowed": dd_ok, "different_device_hint": dd_hint,
            # B-12: add the line's serial as a member of the registered HA device
            "add_ha_member_allowed": ha_ok, "add_ha_member_needs_mark_ha": ha_mark,
            "add_ha_member_hint": ha_hint,
        }
        if detail:
            rows = db.query(U).filter(*grp).order_by(U.id.desc()).limit(limit).all()
            entry["lines"] = [{"id": r.id, "received_at": r.received_at, "raw_line": r.raw_line,
                               "source_route": r.source_route, "upload_ref": r.upload_ref,
                               "serial": r.serial, "map_site_id": r.map_site_id} for r in rows]
        out.append(entry)
    return {"pending_conflicts": conflict_count(db), "pending_lines": pending_count(db),
            "group_count": len(out), "conflicts": out}


# ------------------------------------------------------ queue maintenance --

def unmapped_summary(db: Session, status: str = "pending", detail: bool = False,
                     device_key: Optional[str] = None, limit: int = 100) -> dict:
    """Held lines of UNMAPPED devices grouped by device_key (conflicts are
    listed by conflicts_summary)."""
    U = UnmappedLogEvent
    q = db.query(U.device_key, func.count(U.id), func.min(U.received_at),
                 func.max(U.received_at), func.max(U.id)).filter(U.status == status,
                                                                 U.kind == KIND_UNMAPPED)
    if device_key is not None:
        q = q.filter(U.device_key == normalise_name(device_key))
    groups = q.group_by(U.device_key).order_by(func.count(U.id).desc(), U.device_key).all()
    devices = []
    for key, n, first, last, last_id in groups:
        latest = db.get(U, last_id)
        entry = {
            "device_key": key, "count": n, "first_seen": first, "last_seen": last,
            "vendor": latest.vendor if latest else None,
            "serial": latest.serial if latest else None,
            "source_route": latest.source_route if latest else None,
            "sample_line": (latest.raw_line or "")[:_SAMPLE_MAX] if latest else "",
        }
        if detail:
            rows = (db.query(U).filter(U.status == status, U.kind == KIND_UNMAPPED,
                                       U.device_key == key)
                    .order_by(U.id.desc()).limit(limit).all())
            entry["lines"] = [{"id": r.id, "received_at": r.received_at, "raw_line": r.raw_line,
                               "source_route": r.source_route, "upload_ref": r.upload_ref,
                               "serial": r.serial} for r in rows]
        devices.append(entry)
    return {"status": status, "pending_lines": pending_count(db),
            "pending_conflicts": conflict_count(db),
            "device_count": len(devices), "devices": devices}


def pending_count(db: Session) -> int:
    """Pending held lines of unmapped devices (conflicts: conflict_count)."""
    return db.query(func.count(UnmappedLogEvent.id)).filter(
        UnmappedLogEvent.status == "pending", UnmappedLogEvent.kind == KIND_UNMAPPED).scalar() or 0


def discard_unmapped(db: Session, device_key) -> int:
    """Mark every pending unmapped line of ``device_key`` discarded.  Does
    not commit."""
    n = db.query(UnmappedLogEvent).filter(
        UnmappedLogEvent.status == "pending",
        UnmappedLogEvent.kind == KIND_UNMAPPED,
        UnmappedLogEvent.device_key == normalise_name(device_key),
    ).update({UnmappedLogEvent.status: "discarded"}, synchronize_session=False)
    return n


def retention_days() -> int:
    try:
        return max(0, int(os.environ.get("IACS_UNMAPPED_RETENTION_DAYS", "30")))
    except ValueError:
        return 30


def purge_unmapped(db: Session, days: Optional[int] = None) -> dict:
    """Delete replayed / discarded lines and pending lines older than
    ``days`` (IACS_UNMAPPED_RETENTION_DAYS, default 30).  Commits."""
    days = retention_days() if days is None else max(0, int(days))
    cutoff = utcnow() - timedelta(days=days)
    U = UnmappedLogEvent
    done = db.query(U).filter(U.status.in_(("replayed", "discarded"))) \
        .delete(synchronize_session=False)
    # Only expire pending UNMAPPED lines by retention.  Pending CONFLICT lines
    # (serial_conflict / site_mismatch / ha_candidate) await an explicit
    # operator decision; deleting them here would drop held routing conflicts
    # silently, with no DeviceConflictResolution audit row.
    old = db.query(U).filter(U.status == "pending", U.kind == KIND_UNMAPPED,
                             U.received_at < cutoff).delete(synchronize_session=False)
    db.commit()
    return {"retention_days": days, "replayed_or_discarded": done, "expired_pending": old}


# ---------------------------------------------------------------- output --

def member_dict(m: SiteDeviceSerial) -> dict:
    return {"serial": m.serial, "source": m.source, "added_at": m.added_at,
            "last_seen_at": m.last_seen_at, "last_role": m.last_role}


def device_dict(row: SiteDevice, site_names: Optional[dict] = None) -> dict:
    """API view of a device.  ``serial`` / ``serial_source`` /
    ``serial_bound_at`` are the first member (B-11 single-serial view);
    ``members`` lists every serial (B-12)."""
    return {
        "id": row.id, "site_id": row.site_id,
        "site": (site_names or {}).get(row.site_id) if site_names is not None else None,
        "device_name": row.device_name, "serial": row.serial, "vendor": row.vendor,
        "source": row.source, "serial_source": row.serial_source,
        "serial_bound_at": row.serial_bound_at,
        "is_ha": bool(row.is_ha), "ha_mode": row.ha_mode, "ha_group_name": row.ha_group_name,
        "ha_group_id": row.ha_group_id, "max_members": HA_MAX_MEMBERS,
        "members": [member_dict(m) for m in row.serials],
        "created_at": row.created_at, "updated_at": row.updated_at,
    }
