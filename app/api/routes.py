"""
API routes for IACS_Monitor.

Kept as plain dict responses rather than heavy Pydantic ORM models for
this first pass - swap in response_model schemas once the shape of the
data stabilizes and the Node.js frontend team has opinions about field
naming.
"""
import csv
import json
import ipaddress
import logging
import re
import tempfile
import urllib.parse
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

# FastAPI imports must precede _read_limited, which raises HTTPException.
# (Previously imported after the function definition, causing a NameError
# at runtime whenever an oversized file was uploaded.)
from fastapi.routing import APIRoute
from contextlib import contextmanager
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Query, Request, Response, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

log = logging.getLogger(__name__)

# Upload size limits — enforced before writing to disk/DB.
# PCAP files can be large; text-based ingest files (configs, CSVs, syslogs)
# are almost always small — a 10 MB config is enormous in practice.
_MAX_PCAP_BYTES   = 50  * 1024 * 1024   # 50 MB
_MAX_TEXT_BYTES   = 10  * 1024 * 1024   # 10 MB  (configs, CSVs, syslog)
_MAX_PROOF_BYTES  = 20  * 1024 * 1024   # 20 MB  (attestation proof files)

_UPLOAD_CHUNK     = 1024 * 1024         # read uploads 1 MB at a time
_SPOOL_MEM_BYTES  = 2 * 1024 * 1024     # spooled uploads roll to disk above this

# Pagination for list endpoints (T3-03).  The UI expects complete lists, so
# the default is generous; `limit` is still bounded and X-Total-Count tells
# callers when there is more.
_LIST_LIMIT_DEFAULT = 1000
_LIST_LIMIT_MAX     = 10000


def _limit_param():
    return Query(_LIST_LIMIT_DEFAULT, ge=1, le=_LIST_LIMIT_MAX,
                 description=f"Page size (1-{_LIST_LIMIT_MAX}); total in X-Total-Count")


def _offset_param():
    return Query(0, ge=0, description="Rows to skip")


def _page(query, response: Response, limit: int, offset: int):
    """Set X-Total-Count from ``query`` (ORDER BY stripped) and return the
    requested page of it (still a Query)."""
    response.headers["X-Total-Count"] = str(query.order_by(None).count())
    return query.offset(offset).limit(limit)


def _too_large(max_bytes: int, label: str) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"{label} exceeds {max_bytes // (1024 * 1024)} MB limit",
    )


def _unsupported_media(detail: str) -> HTTPException:
    return HTTPException(status_code=415, detail=detail)


def _limit_exceeded(exc) -> HTTPException:
    """B-08: an IngestLimitExceeded (nothing stored) -> 413 naming the limit."""
    log.warning("ingest rejected: %s", exc)
    return HTTPException(status_code=413, detail=str(exc))


def _bad_csv(exc: BaseException) -> HTTPException:
    """C-13: a CSV upload that is not parseable (binary, UTF-16, corrupted;
    csv.Error / UnicodeDecodeError) -> 422.  Raised before any row is stored,
    so nothing is persisted."""
    log.warning("CSV ingest rejected: %s", exc)
    return HTTPException(status_code=422, detail=str(exc))


# C-13 / C-20: a UTF-16 / UTF-32 file leads with a byte-order mark that is
# invalid UTF-8.  The CSV parsers expect UTF-8 text, and decoding such a file
# with errors="replace" produces garbage that either mis-parses or (with
# embedded NULs) silently yields zero usable rows - never a clear error.  A
# UTF-8 / UTF-8-SIG file (BOM EF BB BF, which the parsers strip) is fine and
# is NOT listed here.  Longer BOMs first so UTF-32 LE is not shadowed by the
# UTF-16 LE prefix it starts with.
_NON_UTF8_BOMS = (
    (b"\xff\xfe\x00\x00", "UTF-32 (little-endian)"),
    (b"\x00\x00\xfe\xff", "UTF-32 (big-endian)"),
    (b"\xff\xfe", "UTF-16 (little-endian)"),
    (b"\xfe\xff", "UTF-16 (big-endian)"),
)


def _decode_text_upload(raw: bytes) -> str:
    """Decode an uploaded text file (config, syslog, switch output) as UTF-8,
    transcoding UTF-16 / UTF-32 files by their byte-order mark instead of
    turning them into NUL-studded garbage (C-20).  The BOM is dropped."""
    for bom, enc in _NON_UTF8_BOMS:
        if raw.startswith(bom):
            codec = {"UTF-32 (little-endian)": "utf-32-le", "UTF-32 (big-endian)": "utf-32-be",
                     "UTF-16 (little-endian)": "utf-16-le", "UTF-16 (big-endian)": "utf-16-be"}[enc]
            return raw[len(bom):].decode(codec, errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace")


def _decode_csv_upload(raw: bytes) -> str:
    """Decode an uploaded CSV as (lenient) UTF-8, rejecting UTF-16/UTF-32
    files up front with a clear 422 (C-13/C-20).  Raised before any DB write,
    so nothing is stored."""
    for bom, enc in _NON_UTF8_BOMS:
        if raw.startswith(bom):
            raise HTTPException(
                status_code=422,
                detail=(f"The uploaded file is {enc}-encoded, but a UTF-8 CSV "
                        "is required - re-export or save it as UTF-8. Nothing "
                        "was stored."),
            )
    return raw.decode("utf-8", errors="replace")


def _check_upload_head(head: bytes, label: str, content: str | None) -> None:
    """B-08: refuse compressed uploads (and, for captures, anything that is
    not a plain pcap/pcapng) with 415.  The size limit is enforced on the
    bytes actually received, so accepting a compressed file would let a
    10 MB / 50 MB upload inflate to many GB inside a parser."""
    if content is None:
        return
    if content == "pcap":
        try:
            check_capture_head(head)
        except UnsupportedCaptureError as exc:
            raise _unsupported_media(f"{label}: {exc}")
        return
    comp = compressed_format(head)
    if comp:
        raise _unsupported_media(
            f"{label} is compressed ({comp}); compressed uploads are not accepted - "
            f"upload the plain text file.")


async def _spool_upload(file, max_bytes: int, label: str = "file", *, to_path: bool = False,
                        suffix: str = "", content: str | None = None):
    """Copy an UploadFile in chunks, aborting with 413 as soon as the running
    total exceeds ``max_bytes`` (T3-02) - the upload is never held in memory
    as one bytes object.

    Returns a rewound SpooledTemporaryFile, or with ``to_path=True`` the path
    of a NamedTemporaryFile (caller unlinks it).  When the multipart parser
    already knows the part size (UploadFile.size) an oversize file is
    rejected without reading any of it.

    The limit is applied to the bytes actually read (a Content-Length or
    multipart size is never trusted on its own).  ``content`` (B-08):
    "pcap" -> the file must start with a pcap/pcapng magic, "text" -> it
    must not be compressed; otherwise 415.
    """
    size = getattr(file, "size", None)
    if size is not None and size > max_bytes:
        raise _too_large(max_bytes, label)

    if to_path:
        out = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    else:
        out = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEM_BYTES)
    total = 0
    head = b""
    try:
        while True:
            chunk = await file.read(_UPLOAD_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _too_large(max_bytes, label)
            if len(head) < 8:
                head += chunk[:8 - len(head)]
                if len(head) >= 8:
                    _check_upload_head(head, label, content)
            out.write(chunk)
        if len(head) < 8:
            _check_upload_head(head, label, content)
    except BaseException:
        out.close()
        if to_path:
            Path(out.name).unlink(missing_ok=True)
        raise
    if to_path:
        out.close()
        return out.name
    out.seek(0)
    return out


async def _read_limited(file, max_bytes: int, label: str = "file",
                        content: str | None = None) -> bytes:
    """Read an UploadFile (chunked) and raise 413 once it exceeds max_bytes.

    Used for the small text uploads (configs, CSVs, syslog - the parsers need
    the whole text anyway) and the attestation proof.  The read stops at the
    first chunk past the limit instead of buffering the whole upload first.
    Ingest routes pass ``content="text"`` (B-08: compressed -> 415).
    """
    spool = await _spool_upload(file, max_bytes, label, content=content)
    try:
        return spool.read()
    finally:
        spool.close()


_DB_BUSY_RETRY_AFTER = "5"


def _is_db_locked(exc: BaseException) -> bool:
    """B-09: SQLite lock contention ("database is locked" / "busy") - a
    transient condition, not a client error."""
    from sqlalchemy.exc import OperationalError
    seen = 0
    while exc is not None and seen < 5:
        if isinstance(exc, OperationalError) or type(exc).__name__ == "OperationalError":
            msg = str(getattr(exc, "orig", None) or exc).lower()
            if "database is locked" in msg or "database is busy" in msg or "sqlite_busy" in msg \
                    or "database table is locked" in msg:
                return True
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return False


def _db_busy_http() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="The database is busy with another write (e.g. a large ingest); "
               "nothing was stored - retry shortly.",
        headers={"Retry-After": _DB_BUSY_RETRY_AFTER},
    )


def _internal_error(exc: BaseException, message: str, status_code: int = 500,
                    context: str = "") -> HTTPException:
    """Log an unexpected exception with a short correlation id and return an
    HTTPException that does NOT leak the exception text (T3-12).
    SQLite lock contention becomes 503 + Retry-After instead (B-09)."""
    if _is_db_locked(exc):
        log.warning("database busy: %s%s", message, f" ({context})" if context else "")
        return _db_busy_http()
    err_id = uuid.uuid4().hex[:10]
    log.error("error_id=%s %s%s", err_id, message, f" ({context})" if context else "",
              exc_info=(type(exc), exc, exc.__traceback__))
    return HTTPException(
        status_code=status_code,
        detail=f"{message} (error id {err_id}; see server logs)",
    )


def _error_stub(exc: BaseException, message: str) -> dict:
    """Same as _internal_error for non-fatal sub-steps whose failure is
    reported inside a 200 response (e.g. {"classification": {"error": ...}})."""
    err_id = uuid.uuid4().hex[:10]
    log.error("error_id=%s %s", err_id, message,
              exc_info=(type(exc), exc, exc.__traceback__))
    return {"error": f"{message} (error id {err_id}; see server logs)", "error_id": err_id}


class _DeferredCommits:
    """Make ``db.commit()`` a flush for the duration of the block so a
    multi-step ingest (pcap parse -> classify -> industrial-write check, each
    of which commits internally) becomes ONE transaction that the route
    commits or rolls back as a whole (T3-13).  Only this Session object is
    affected, and only inside the ``with``."""

    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.commit = self.db.flush  # instance attribute shadows the method
        return self.db

    def __exit__(self, *exc):
        try:
            del self.db.commit
        except AttributeError:
            pass
        return False


_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _clean_upload_name(name, default: str = "upload", max_len: int = 200) -> str:
    """B-24c: basename of a client-supplied filename with NUL/control chars
    removed and the length capped (never raises)."""
    raw = _CTRL_RE.sub("", str(name or "")).replace("\\", "/").rsplit("/", 1)[-1].strip()
    if len(raw) > max_len:
        stem, dot, ext = raw.rpartition(".")
        ext = ("." + ext) if dot and len(ext) <= 16 else ""
        raw = raw[:max_len - len(ext)] + ext
    return raw or default


def _upload_suffix(name, default: str = ".pcap") -> str:
    """Safe temp-file suffix from an upload filename (alnum extension <= 16 chars)."""
    ext = Path(_clean_upload_name(name, "x")).suffix
    return ext if re.fullmatch(r"\.[A-Za-z0-9]{1,16}", ext or "") else default


_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(v):
    """B-18: neutralise spreadsheet formula injection - a string cell starting
    with = + - @ TAB or CR gets a leading single quote.  Non-strings pass through."""
    if isinstance(v, str) and v.startswith(_FORMULA_LEAD):
        return "'" + v
    return v


def _csv_safe_row(row: dict) -> dict:
    return {k: _csv_safe(v) for k, v in row.items()}
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import DataError as SADataError
from sqlalchemy.exc import OperationalError as SAOperationalError
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.orm import Session as DBSession

from app.db import get_db, get_write_db


@contextmanager
def _write_session(request: Request):
    """C-17: a write-capable session for the rare GET that has to write
    (default-site creation, findings from ?generate_findings).  Resolved
    through the app's dependency overrides, so tests and alternative
    deployments that override get_write_db are honoured; closed on exit."""
    provider = get_write_db
    app = getattr(request, "app", None)
    if app is not None:
        ov = app.dependency_overrides
        # an override of get_db alone (the common test harness) means "every
        # session comes from here": never fall through to the real database
        provider = ov.get(get_write_db) or ov.get(get_db) or get_write_db
    gen = provider()
    db = next(gen)
    try:
        yield db
    finally:
        try:
            next(gen)
        except StopIteration:
            pass
from app.models import (
    ApprovedCommsEntry, ApprovedHost, Attestation, Baseline,
    Finding, Firewall, FirewallDevice, FirewallGroup, FirewallInterface, FirewallZone,
    PcapCapture, Host, NetworkSession, ProtocolDetail, FirewallRule,
    FortiAnalyzerEvent, SwitchInterface, CHECK_TYPE_REFERENCE, Site, real_host_clause,
)
from app.sites import (  # multi-site phase 1 (docs/multi-site-design.md)
    SiteNotFound, bind_ingest_site, find_site, get_default_site, get_default_site_id,
    ingest_site, resolve_site,
    site_names,
)
from app.parsers.pcap_parser import (
    UnsupportedCaptureError, check_capture_file, check_capture_head, ingest_pcap,
)
from app.parsers.common import IngestLimitExceeded, compressed_format
from app.parsers.topology_manager import (
    get_topology_state, confirm_link, confirm_segment, detect_subnet_overlaps,
    set_upstream_firewall, run_purdue_suggestions,
)
from app.parsers.topology_manager import (  # N-11 / N-13
    set_interface_labels,
)
from app.purdue import (  # F-08: the one Purdue level vocabulary
    canonical_levels, normalize_level, purdue_level_error,
)
from app.parsers.cross_fw_findings import run_cross_fw_checks
from app.parsers.arp_parser import ingest_arp_table
from app.parsers.firewall_parser import ingest_firewall_config
from app.parsers.switch_parser import ingest_switch_config, VendorMismatchError
from app.parsers.device_classification import classify_hosts, DEVICE_TYPE_REFERENCE
from app.parsers.topology_diff import compute_diff
from app.parsers.mac_table_parser import ingest_mac_table, infer_vlan_by_subnet
from app.parsers.forti_config_parser import ingest_fortigate_config, parse_forti_block
from app.parsers.forti_parser import (
    ingest_syslog_line, ingest_forti_event_json, ingest_forti_csv,
)
try:  # T3-06: duplicate-aware variant -> (event | None, "created"|"duplicate"|"unparsed")
    from app.parsers.forti_parser import ingest_syslog_line_ex as _ingest_syslog_line_ex
except ImportError:  # pragma: no cover - older forti_parser
    _ingest_syslog_line_ex = None
try:  # T3-06: (event, "created"|"duplicate"); event is the EXISTING row on duplicate
    from app.parsers.forti_parser import ingest_forti_event_json_ex as _ingest_forti_event_json_ex
except ImportError:  # pragma: no cover - older forti_parser
    _ingest_forti_event_json_ex = None
from app.parsers.alert_engine import evaluate_event, run_periodic_reviews
from app.site_devices import (  # multi-site phase 3 (docs/multi-site-design.md)
    LogRouter, ROUTE_FORTI_EVENT, ROUTE_FORTI_REPORT, ROUTE_FORTI_SYSLOG, ROUTE_SYSLOG,
    parse_item, record_rule_hits_per_site, register_from_config, replay_pending,
)
# F-11 multi-vendor syslog + F-10 rule-hit tracking
from app.parsers.syslog_vendors import (
    ingest_syslog_any_ex, normalise_vendor_hint, event_vendor as _event_vendor,
)
from app.parsers.rule_hits import record_rule_hits_safe as _record_rule_hits
from app.parsers.alert_engine import (  # N-02 / F-04 response fields
    auto_resolved_counts as _ae_auto_resolved_counts,
    escalation_count as _ae_escalation_count,
)
from app.parsers.traffic_findings import check_unauthorized_industrial_writes
from app.parsers.baseline_parser import (
    ingest_approved_comms, ingest_approved_hosts,
    ingest_asset_inventory, ingest_reviewed_policies,
    get_or_create_baseline,
)

def _data_error_detail(exc: BaseException) -> str:
    """C-16: a DataError can be a numeric overflow (PG 22003 /
    NumericValueOutOfRange) OR a string that is too long for its column (PG
    22001 / StringDataRightTruncation - e.g. an over-long /assets ``location``
    against String(128)).  Return an accurate 422 message for each instead of
    always claiming "a numeric value is out of range"."""
    orig = getattr(exc, "orig", None)
    pgcode = str(getattr(orig, "pgcode", "") or "")
    msg = str(orig or exc).lower()
    if (pgcode == "22001" or "right truncation" in msg or "value too long" in msg
            or "too long for" in msg or "string or binary data would be truncated" in msg):
        return "a text value is too long for its column"
    return "a numeric value is out of range"


class _RangeSafeRoute(APIRoute):
    """B-24b: an id above the DB integer range (e.g. /hosts/99999999999999999999/history)
    raises OverflowError (SQLite) / DataError (PostgreSQL) deep inside a query.
    Turn that into a 422 for every route instead of a 500.  C-16: a DataError
    may instead be a string that overflowed its column, which gets its own
    accurate message (see _data_error_detail).

    B-09: SQLite lock contention that outlasted busy_timeout ("database is
    locked" / "busy" OperationalError) becomes 503 + Retry-After on every
    route (a transient server condition, never a 400/500).  C-12: a pool
    checkout that timed out (sqlalchemy.exc.TimeoutError - every pooled
    connection is held by queued writers) is the same transient condition and
    is likewise mapped to 503 + Retry-After rather than a plain 500."""

    def get_route_handler(self):
        inner = super().get_route_handler()

        async def handler(request):
            try:
                return await inner(request)
            except OverflowError:
                raise HTTPException(status_code=422, detail="a numeric value is out of range")
            except SADataError as exc:
                raise HTTPException(status_code=422, detail=_data_error_detail(exc))
            except SATimeoutError:
                # C-12: QueuePool.checkout() timed out - all connections are in
                # use (typically a burst of writers queued on BEGIN IMMEDIATE).
                # Transient; tell the client to retry rather than returning 500.
                log.warning("db pool checkout timed out on %s %s",
                            request.method, request.url.path)
                raise _db_busy_http()
            except SAOperationalError as exc:
                if _is_db_locked(exc):
                    log.warning("database busy on %s %s", request.method, request.url.path)
                    raise _db_busy_http()
                raise
        return handler


router = APIRouter(route_class=_RangeSafeRoute)


# F-08: every endpoint that accepts a Purdue level parses it here, so they
# all accept the same spellings (3, 3.5, "L3.5", "dmz") and reject with the
# same 422 message.  Query parameters are declared ``str`` (not int/float)
# so FastAPI's own type error never pre-empts this message.
_LEVEL_DOC = "Purdue level: 0, 1, 2, 3, 3.5 (industrial DMZ), 4 or 5 ('L3.5' / 'dmz' accepted)"


def _level_param(field: str, value):
    """Normalised Purdue level (int, or 3.5), None for None/'' - or HTTP 422."""
    try:
        return normalize_level(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=purdue_level_error(field, value))


def _level_query():
    return Query(None, description=_LEVEL_DOC)


# ------------------------------------------------------------------ sites --
# Multi-site phase 1.  Every NON-log upload takes a REQUIRED ``site`` (id,
# name or code); it is declared optional here only so a missing value gets
# the same clear 422 message as an unknown one instead of FastAPI's generic
# "field required".  Every list endpoint takes an optional ``site_id``
# filter (omitted = all sites).

_SITE_DOC = ("REQUIRED. Site this upload belongs to: site id, name or code "
             "(case-insensitive). GET /sites lists them, POST /sites creates one.")
_SITE_FILTER_DOC = "Only rows of this site (id from GET /sites); omit for all sites"


def _site_query():
    return Query(None, description=_SITE_DOC)


def _site_filter_query():
    return Query(None, ge=1, description=_SITE_FILTER_DOC)


def _require_site(db, value) -> Site:
    """Resolve the ``site`` upload parameter or raise HTTP 422."""
    try:
        return resolve_site(db, value)
    except SiteNotFound as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _check_site_filter(db, site_id: int | None) -> int | None:
    """Validate an optional ``site_id`` list filter (422 when unknown)."""
    if site_id is None:
        return None
    if db.get(Site, site_id) is None:
        raise HTTPException(status_code=422, detail=f"Unknown site_id {site_id} (GET /sites lists them)")
    return site_id


def _site_info(site: Site) -> dict:
    return {"site_id": site.id, "site": site.name}


_OP_SITE_DOC = ("Site this operation runs in (id, name or code). Sites are isolated; "
                "required when more than one site exists.")


def _op_site_params():
    """(site, site_id) query parameters of a per-site operation."""
    return (Query(None, description=_OP_SITE_DOC),
            Query(None, ge=1, description=_OP_SITE_DOC))


def _operation_site(db, site=None, site_id: int | None = None) -> Site:
    """The site a per-site operation (analysis, topology, baseline/attestation
    action, report section) runs in - multi-site phase 2.

    ``site`` (id / name / code) or ``site_id``; both given must agree.  When
    neither is given the site is DERIVED only if it is unambiguous (exactly
    one site exists); otherwise HTTP 422 - sites are isolated, so an analysis
    never silently spans them."""
    if site_id is not None and site not in (None, ""):
        a, b = _require_site(db, site), _require_site(db, site_id)
        if a.id != b.id:
            raise HTTPException(status_code=422,
                                detail=f"'site' ({a.name}) and 'site_id' ({b.id}) disagree")
        return a
    if site_id is not None:
        _check_site_filter(db, site_id)          # "Unknown site_id N" (422)
        return db.get(Site, site_id)
    if site not in (None, ""):
        return _require_site(db, site)
    rows = db.query(Site).order_by(Site.id).limit(2).all()
    if not rows:
        # FI-01: never create a site implicitly
        raise HTTPException(
            status_code=409,
            detail="No site exists yet: create one first (POST /sites, or '+ New site' on the "
                   "Upload Data page), or load the sample data")
    if len(rows) == 1:
        return rows[0]
    raise HTTPException(
        status_code=422,
        detail="'site' is required: this operation runs within one site and more than "
               "one site exists (pass site=<id|name|code> or site_id=<id>; GET /sites lists them)")


def _iface_fw_id(db, interface_id: int):
    """firewall_id of FirewallInterface ``interface_id`` (None when it does
    not exist - the topology function then reports its own error)."""
    iface = db.get(FirewallInterface, interface_id)
    if iface is None:
        return None
    return iface.firewall_id


def _builder_site(db, site, site_id, firewall_ids) -> Site:
    """Site of a topology-builder operation on existing firewalls.

    All referenced firewalls must belong to ONE site (else 422 - sites are
    isolated, so links / upstream chains never cross them).  With an
    explicit ``site``/``site_id`` every referenced firewall must belong to it
    (else 404); without one the site is derived from the firewalls."""
    fws = []
    for fid in firewall_ids:
        if fid is None:
            continue
        fw = db.get(Firewall, fid)
        if fw is not None:
            fws.append(fw)
    sites = {fw.site_id for fw in fws}
    if len(sites) > 1:
        raise HTTPException(status_code=422, detail=(
            "cross-site reference: the firewalls "
            + ", ".join(f"id={fw.id} (site_id={fw.site_id})" for fw in fws)
            + " belong to different sites; sites are isolated"))
    if site is not None or site_id is not None:
        site_row = _operation_site(db, site, site_id)
        for fw in fws:
            if fw.site_id != site_row.id:
                raise HTTPException(status_code=404, detail=(
                    f"firewall id={fw.id} not found in site {site_row.name!r}"))
        return site_row
    if sites:
        return db.get(Site, sites.pop())
    return _operation_site(db)


def _value_error_status(exc: ValueError) -> int:
    """422 for a cross-site refusal raised by the topology functions (part
    B's CrossSiteError), 400 for any other validation error."""
    try:
        from app.parsers.site_scope import CrossSiteError
        if isinstance(exc, CrossSiteError):
            return 422
    except ImportError:  # pragma: no cover
        pass
    return 400


def _in_site(db, site_id: int, fn, /, *args, **kwargs):
    """Run ``fn`` with ``site_id`` bound as the ingest site of ``db`` (so
    every root row it creates - including rows the parser does not create
    itself, e.g. findings from classification - lands in that site)."""
    with ingest_site(db, site_id):
        return fn(*args, **kwargs)


# ---------------------------------------------------------------- ingest --

def _tunnel_kind(iface_type, remote_access, name) -> Optional[str]:
    """VPN kind of a firewall interface (owner 2026-10-12, Firewall Devices VPN
    badges): "SSL" (ssl.root / SSL-VPN), "dial-up IPsec", "L2TP", "site-to-site
    IPsec" for any other tunnel; None for a non-tunnel / internal one."""
    n = str(name or "").strip().lower()
    ra = str(remote_access or "").lower()
    if ra == "ssl" or n == "ssl.root":
        return "SSL"
    if ra == "ipsec_dialup":
        return "dial-up IPsec"
    if str(iface_type or "").lower() != "tunnel" or n in ("naf.root",):
        return None
    if n == "l2t.root":
        return "L2TP"
    return "site-to-site IPsec"


def _attach_review(out, what: str):
    """Owner 2026-10-12: run the periodic reviews at upload time - queue one for
    the upload's site (app.review_trigger; background, coalesced) and say so in
    the response (``reviews``: queued / queued after the running review / off)."""
    if isinstance(out, dict) and "reviews" not in out:
        try:
            from app import review_trigger
            out["reviews"] = review_trigger.request(out.get("site_id"), what)
        except Exception:                                   # noqa: BLE001 - the upload itself succeeded
            logging.getLogger(__name__).exception("could not queue the reviews after %s", what)
    return out


def _reviews_after_upload(what: str):
    """Decorator for upload routes: a successful (dict) response queues the reviews."""
    import functools
    import inspect

    def deco(fn):
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def aw(*a, **k):
                return _attach_review(await fn(*a, **k), what)
            return aw

        @functools.wraps(fn)
        def w(*a, **k):
            return _attach_review(fn(*a, **k), what)
        return w
    return deco


@router.post("/ingest/pcap")
@_reviews_after_upload('pcap')
async def ingest_pcap_file(
    file: UploadFile = File(...),
    site: str | None = _site_query(),
    firewall_id: int | None = Query(None, ge=1, description=(
        "Capture point (VD-02a): the uploaded firewall the capture was taken on. "
        "Omit for a capture-only upload (soft fail: ingested, flagged unassociated).")),
    interface_id: str | None = Query(None, description=(
        "Firewall interface / port of the capture (id from GET /topology/firewalls/{id}/interfaces); "
        "'any' or omitted = the firewall only (merged taps, or port not known).")),
    capture_networks: str | None = Query(None, description=(
        "Comma-separated CIDRs of the capture segment when it is no firewall port "
        "(a switch SPAN), e.g. 10.3.0.0/24.")),
    db: DBSession = Depends(get_db),
):
    """
    Upload a pcap/pcapng file for parsing. Builds hosts and sessions,
    decodes any Modbus/DNP3/S7comm/EtherNet-IP/PROFINET traffic found,
    runs Purdue-model device classification (see /classify and
    /purdue-levels) over the resulting hosts, and checks every decoded
    industrial write/program operation against the approved engineering-
    workstation/HMI baseline (checklist 8.4 - see /findings/scan-
    industrial-writes for what this checks and its fail-open behavior
    when no baseline has been loaded yet).

    VD-02a capture point: name the firewall (and interface, or the segment
    CIDRs) the capture was taken on and a single routed frame identifies
    the firewall's MAC, so a remote host is never recorded with it.  Every
    upload creates a ``PcapCapture`` row (``capture_id`` in the response);
    without a firewall the capture is still ingested, ``association`` is
    ``"none"`` and it can be associated later with
    ``POST /ingest/pcap/{capture_id}/associate`` (the hosts are re-attributed).
    """
    from app.parsers import capture_point as _cp
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    iface_id = _capture_iface_param(interface_id)
    try:
        cp = _cp.resolve(db, site_id, firewall_id, iface_id, capture_networks)
    except _cp.CapturePointError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    # Stream the upload to a temp file (413 as soon as it is too big), then
    # do all parsing/DB work in a worker thread so the event loop - and
    # /health - stay responsive during a large ingest (T3-01).
    suffix = _upload_suffix(file.filename)
    tmp_path = await _spool_upload(file, _MAX_PCAP_BYTES, "PCAP file",
                                   to_path=True, suffix=suffix, content="pcap")
    filename = _clean_upload_name(file.filename, "upload.pcap")

    def _work():
        _phase = "parse"
        try:
            # One transaction for parse + classify + write-check (T3-13).
            with _DeferredCommits(db), ingest_site(db, site_id):
                capture = _new_capture(db, site_id, filename, cp, capture_networks)
                stats = ingest_pcap(tmp_path, db, source_file=filename, commit=False,
                                    pcap_capture_id=capture.id, capture_point=cp, site_id=site_id)
                _store_capture_result(capture, stats)
                db.flush()   # FO-10: classify_hosts reads the capture segment
                _phase = "classify"
                stats["classification"] = classify_hosts(db, site_id=site_id)
                _phase = "nat-reconcile"
                from app.parsers.nat_sessions import reconcile as _nat_reconcile
                stats["nat_sessions"] = _nat_reconcile(db, site_id=site_id)
                _phase = "industrial-write-check"
                stats["industrial_write_check"] = check_unauthorized_industrial_writes(db, commit=False, site_id=site_id)
                capture_id = capture.id
                try:                                        # RS G3: ask for the zones
                    from app.parsers import subnet_zones as _sz
                    from app.parsers.site_scope import analysis_site as _as
                    db.flush()
                    with _as(db, site_id):
                        stats["subnets_without_zone"] = _sz.undeclared_count(db)
                except Exception:                           # noqa: BLE001 - a note, never a failure
                    log.warning("subnet zone count failed", exc_info=True)
            db.commit()
            return capture_id, stats
        except UnsupportedCaptureError as exc:
            db.rollback()
            raise _unsupported_media(f"PCAP file: {exc}")
        except Exception as exc:
            db.rollback()
            raise _internal_error(exc, f"Failed during {_phase} phase; nothing was stored",
                                  status_code=400, context=f"pcap {filename!r}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    capture_id, stats = await run_in_threadpool(_work)
    return {"filename": filename, **site_out, **_pcap_truncation(stats),
            "capture_id": capture_id, **_capture_summary(stats), "stats": stats}


def _capture_iface_param(value) -> int | None:
    """interface_id query value: an id, or 'any' / 'auto' / '' = none."""
    if value is None or str(value).strip().lower() in ("", "any", "auto", "none"):
        return None
    try:
        v = int(str(value).strip())
    except ValueError:
        raise HTTPException(status_code=422, detail=(
            f"interface_id must be an interface id or 'any', got {value!r}"))
    if v < 1:
        raise HTTPException(status_code=422, detail="interface_id must be >= 1")
    return v


def _new_capture(db, site_id, filename, cp, capture_networks) -> "PcapCapture":
    """The PcapCapture row of an upload, with the operator's capture point."""
    capture = PcapCapture(
        site_id=site_id, uploaded_at=datetime.now(timezone.utc), filename=filename,
        firewall_id=cp["firewall_id"] if cp else None,
        interface_id=cp["interface_id"] if cp else None,
        capture_networks=(", ".join(str(n) for n in cp["local_networks"])
                          if cp and cp["association"] == "segment" else None),
        association=cp["association"] if cp else "none",
        operator_confirmed=bool(cp and cp["interface_id"]),
    )
    db.add(capture)
    db.flush()
    return capture


def _store_capture_result(capture, stats: dict) -> None:
    import json as _json
    capture.packet_count = stats.get("packets")
    if stats.get("capture_segment"):
        capture.segment = _json.dumps(stats["capture_segment"])
    gws = sorted((stats.get("gateway_macs_by_capture_point") or {}).keys())
    if gws:
        capture.gateway_macs = _json.dumps(gws)


def _upload_notes(stats: dict) -> list:
    """FO-12: what the operator should load next, from a pcap upload's stats."""
    out = []
    nz = stats.get("subnets_without_zone")
    if nz:
        out.append(f"{nz} subnet(s) have no zone yet. Assign each one a Purdue level and zone name "
                   "(Subnets & Zones page, or POST /subnets): its devices take that level, and devices "
                   "that do not match it are reported.")
    iw = stats.get("industrial_write_check") or {}
    if iw.get("fail_open") and (iw.get("findings_created") or iw.get("already_flagged")):
        cands = iw.get("engineering_candidates") or []
        text = ("No approved engineering-workstation / HMI list is loaded, so every industrial write "
                "is reported (fail-open). Load the approved host list (Upload Data → Approved Host "
                "List) to keep only the writes from other hosts.")
        if cands:
            c = cands[0]
            what = (f"{c['program_ops']} program / control operation(s)" if c["program_ops"]
                    else f"{c['writes']} write(s)")
            # IO-11: evidence, not a recommendation - an intruder's laptop
            # does program downloads too
            text += (f" Program downloads / writes came from {c['ip']}"
                     + ("" if c.get("identified") else " (unidentified, not in any inventory)")
                     + f" ({what} to {', '.join(c['targets'][:4])}): confirm it is an approved "
                     f"engineering workstation before approving it.")
        out.append(text)
    return out


def _capture_summary(stats: dict) -> dict:
    """Top-level capture-point keys of a pcap upload response."""
    cp = stats.get("capture_point") or {"association": "none"}
    return {"association": cp.get("association", "none"), "capture_point": cp,
            "upload_notes": _upload_notes(stats),
            "capture_point_notes": stats.get("capture_point_notes") or [],
            "capture_point_suggestion": stats.get("capture_point_suggestion"),
            "gateway_macs_by_capture_point": stats.get("gateway_macs_by_capture_point") or {}}


def _pcap_truncation(stats: dict) -> dict:
    """B-08: top-level truncation summary of a pcap ingest.  ``truncated``
    is true when a per-ingest limit (IACS_PCAP_MAX_*) stopped processing;
    everything processed up to that point was committed."""
    if not stats.get("truncated"):
        return {"truncated": False}
    from app.parsers.pcap_parser import PCAP_LIMITS
    limit = stats.get("truncated_by")
    env_var = PCAP_LIMITS.get(limit, (None,))[0]
    value = (stats.get("limits") or {}).get(limit)
    return {
        "truncated": True,
        "truncation": {
            "limit": limit,
            "env_var": env_var,
            "limit_value": value,
            "records_processed": stats.get("records_processed"),
            "packets": stats.get("packets"),
            "hosts_created": stats.get("hosts"),
            "sessions": stats.get("sessions"),
            "message": (f"Processing stopped at the {limit} limit ({env_var}={value}); "
                        f"the data processed so far was stored. Raise {env_var} or split "
                        f"the capture to ingest the rest."),
        },
    }


@router.post("/ingest/arp")
@_reviews_after_upload('arp')
async def ingest_arp_file(
    file: UploadFile = File(...),
    format_hint: str | None = None,
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload an ARP table dump. Pass `?format_hint=cisco|unix|windows`
    when the UI already asked which platform this came from; omit it
    to fall back to content-based auto-detection (Cisco `show ip arp`,
    or `arp -a` output from Linux/Unix or Windows). Populates Host rows
    with the ip/mac pairs found.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "ARP table", content="text")
    text = _decode_text_upload(raw)
    filename = file.filename

    def _work():
        stats = ingest_arp_table(text, db, source_file=filename, format_hint=format_hint,
                                 site_id=site_id)
        if stats["entries_found"] == 0:
            raise HTTPException(
                status_code=422,
                detail="No ARP entries recognized - expected Cisco 'show ip arp' or "
                       "Linux/Windows 'arp -a' output. If you passed format_hint, "
                       "double check it matches the actual file.",
            )
        stats["classification"] = classify_hosts(db, site_id=site_id)
        return stats

    stats = await run_in_threadpool(_in_site, db, site_id, _work)
    return {"filename": filename, **site_out, "stats": stats}


@router.post("/ingest/firewall")
@_reviews_after_upload('firewall config')
async def ingest_firewall_file(
    file: UploadFile = File(...),
    vendor_hint: str | None = None,
    firewall_device_name: str | None = Query(None, max_length=255),
    purdue_zone_from: str | None = _level_query(),
    purdue_zone_to: str | None = _level_query(),
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload a firewall config export - Cisco IOS ACL, pfSense config.xml,
    or Palo Alto XML/set-format. Pass `?vendor_hint=cisco|pfsense|palo_alto`
    when the UI already asked the person which vendor this is (the
    intended path - a vendor picklist is more reliable than guessing from
    content alone, and fails predictably with a clear error rather than
    silently mis-parsing when the wrong vendor is picked). Omit it to
    fall back to content-based auto-detection. Populates FirewallRule
    rows representing the "allowed" topology.

    Purdue boundary tagging (optional but recommended for swimlane topology):
      Pass `?firewall_device_name=<label>` to identify this device
      (e.g. "Corp-FW", "Cell-FW-A").
      Pass `?purdue_zone_from=4&purdue_zone_to=3` to record that this
      firewall sits between Purdue Level 4 (Enterprise/IT) and Level 3
      (Site Operations) - or `3.5` for the industrial DMZ side. This wires the firewall into the topology swimlane
      view so boundary annotations appear between the correct level lanes.
      Both are optional - rules without a boundary tag are still ingested
      and matched in /diff, just without swimlane placement.
    """
    # N-13 / F-08: server-side check (the UI checks too, API callers may not).
    purdue_zone_from = _level_param("purdue_zone_from", purdue_zone_from)
    purdue_zone_to = _level_param("purdue_zone_to", purdue_zone_to)
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Firewall config", content="text")
    text = _decode_text_upload(raw)

    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_firewall_config,
            text, db,
            site_id=site_id,
            source_file=file.filename,
            vendor_hint=vendor_hint,
            firewall_device_name=firewall_device_name,
            purdue_zone_from=purdue_zone_from,
            purdue_zone_to=purdue_zone_to,
        )
    except IngestLimitExceeded as exc:
        # B-08: raised before any row is written; roll back regardless.
        await run_in_threadpool(db.rollback)
        raise _limit_exceeded(exc)
    if stats["device_type"] == "unknown":
        raise HTTPException(
            status_code=422,
            detail="Could not detect config format - expected Cisco IOS ACL, "
                   "pfSense config.xml, or Palo Alto XML/set-format. If you "
                   "passed vendor_hint, double check it matches the actual "
                   "file - a mismatched hint produces this same error rather "
                   "than a wrong parse.",
        )

    stats["config_stored"] = await run_in_threadpool(
        _in_site, db, site_id, _store_config_text, db, site_id, stats.get("firewall_id"), text,
        stats.get("device_type"), file.filename, firewall_device_name)
    # Phase 3: register the config's hostname in the site device registry.
    reg = await run_in_threadpool(_register_config_device, db, site_id, text,
                                  stats.get("device_type"), firewall_device_name)
    return {"filename": file.filename, **site_out, "stats": stats, **reg}


def _record_ha(db, site_id: int, text: str, name: str, ha_peer: Optional[str]) -> dict:
    """After a config upload: record its ``config system ha`` (suggestions),
    declare the HA cluster when ``ha_peer`` names an uploaded firewall, and
    fold duplicate member findings into the primary's.  Never fails the
    upload: problems are reported in the result."""
    from app.parsers import firewall_groups as fg
    from app.parsers.site_scope import analysis_site
    from app.site_devices import ha_config
    out: dict = {}
    try:
      with analysis_site(db, site_id):     # group names / finding folding stay in this site
        fw = db.query(Firewall).filter(Firewall.site_id == site_id, Firewall.name == name).first()
        if fw is None:
            return out
        ha = ha_config(text)
        if ha is not None:
            fw.ha_mode = ha.mode
            key = "/".join(str(x) for x in (ha.group_name, ha.group_id) if x not in (None, ""))
            fw.ha_cfg_group = key[:80] or None
            out["config_ha"] = {"mode": ha.mode, "group": fw.ha_cfg_group}
        if ha_peer:
            peer = db.query(Firewall).filter(Firewall.site_id == site_id,
                                             Firewall.name == ha_peer.strip()).first()
            if peer is None:
                out["error"] = f"ha_peer {ha_peer!r} is not an uploaded firewall of this site"
            elif peer.id == fw.id:
                out["error"] = "ha_peer names this firewall itself"
            elif fw.ha_group_id is not None and fw.ha_group_id == peer.ha_group_id:
                out["group_id"] = fw.ha_group_id
            elif peer.ha_group_id is not None and fw.ha_group_id is None:
                g = db.get(FirewallGroup, peer.ha_group_id)
                fw.ha_group_id = g.id
                if peer.paired_group_id is not None:
                    fw.paired_group_id = peer.paired_group_id
                out["group_id"] = g.id
            else:
                g = fg.declare_ha(db, site_id, [peer.id, fw.id], primary_id=peer.id)
                out["group_id"] = g.id
        fg.consolidate_ha_findings(db)
        db.commit()
    except fg.GroupError as exc:
        db.rollback()
        out["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        out["error"] = "HA cluster recording failed; see the server log"
        log.exception("HA cluster recording failed for %s", name)
    return out


def _register_config_device(db, site_id: int, text: str, device_type, label) -> dict:
    """Auto-register a firewall config's device (multi-site phase 3).  A
    failure never fails the upload (which is already committed)."""
    try:
        return register_from_config(db, site_id, text, device_type, label=label,
                                    evaluate=evaluate_event)
    except Exception as exc:
        db.rollback()
        return {"site_devices": [], "site_device_conflicts": [],
                "site_device_error": _error_stub(exc, "site device registration failed")["error"]}


def _store_config_text(db, site_id: int, firewall_id, text: str, vendor, filename, device_name) -> bool:
    """Keep the upload's text for the config viewer (owner 2026-10-14; secrets
    masked, latest only).  Never fails the upload, which is already committed."""
    if not firewall_id:
        return False
    try:
        from app import config_store as _cs
        _cs.store_config(db, site_id, int(firewall_id), text, vendor=vendor, filename=filename,
                         device_name=device_name)
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        log.warning("config text not stored for firewall %s: %r", firewall_id, exc)
        return False


@router.post("/ingest/fortigate-config")
@_reviews_after_upload('FortiGate config')
async def ingest_fortigate_config_file(
    file: UploadFile = File(...),
    firewall_name: str | None = Query(None, max_length=255),
    device_name: str | None = Query(None, max_length=255),
    generate_findings: bool = True,
    populate_approved_hosts: bool = False,
    baseline_id: int | None = None,
    baseline_name: str | None = None,
    purdue_zone_from: str | None = _level_query(),
    purdue_zone_to: str | None = _level_query(),
    ha_peer: str | None = Query(None, max_length=128, description=(
        "name of an already uploaded firewall of the site that this config is the HA "
        "peer of: both become one HA cluster (the peer stays primary)")),
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload a FortiGate `show full-configuration` CLI output.

    HA clusters: pass ``?ha_peer=<firewall name>`` when this config is the
    other member of an HA cluster already uploaded (upload the two member
    configs one after the other).  The ``config system ha`` group of every
    upload is recorded and offered as a suggestion on the topology page.

    Multi-firewall support (Option 2 — infer from count):
      Pass `?firewall_name=<label>` to identify this device
      (e.g. "Perimeter-FW", "Cell-FW-A"). The label is the stable
      identifier used to link FirewallInterface, FirewallRule and
      PcapCapture rows to this device. If omitted, the hostname from
      `config system global / set hostname` is used; if that is also
      absent, the filename is used as a fallback.

      When this upload brings the total number of uploaded configs to
      ≥ 2, the response includes `topology_state: "multi"` and
      `is_multi_fw: true` — the UI should open the topology builder
      so the operator can confirm which interfaces connect across
      firewalls (GET /topology returns the current state and pending
      link proposals).

    Purdue boundary tagging (optional):
      Pass `?purdue_zone_from=4&purdue_zone_to=3` to record that this
      FortiGate sits between Level 4 (Enterprise/IT) and Level 3 (Site
      Operations). This wires the device into the swimlane topology so
      boundary annotations appear between the correct level lanes.
      Values 0–5 and 3.5 are accepted (5 = Internet, 4 = Enterprise/IT,
      3.5 = Industrial DMZ, 3 = Site Operations, 2 = Control/HMI,
      1 = Basic Control, 0 = Field Devices; anything else -> 422). purdue_zone_from / purdue_zone_to in either order (the analysis normalises the pair)
      (less-trusted side → more-trusted side).

    Two-pass parse:
      Pass 1 — tokenize the FortiOS block structure and flatten
      global/vdom wrapping if present.

      Pass 2 — resolve and emit:
        - Firewall row (created or updated for this device)
        - FirewallInterface rows (one per `config system interface` entry,
          with network_cidr and HA/mgmt classification)
        - FirewallZone rows (legacy — kept for backward compat)
        - FirewallRule rows linked to this Firewall
        - Host rows for concrete /32 address objects

    Optional, default OFF:
      `?generate_findings=true` runs config-level 62443 checks and
      writes Finding rows.
      `?populate_approved_hosts=true&baseline_id=<id>` or
      `?populate_approved_hosts=true&baseline_name=<name>` extracts admin
      trusted-hosts into ApprovedHost rows. When `baseline_name` is given
      instead of `baseline_id`, the named Baseline is looked up (or
      created) automatically so the caller does not need a prior lookup.
    """
    purdue_zone_from = _level_param("purdue_zone_from", purdue_zone_from)
    purdue_zone_to = _level_param("purdue_zone_to", purdue_zone_to)
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "FortiGate config", content="text")
    text = _decode_text_upload(raw)

    if not text.strip():
        raise HTTPException(status_code=422, detail="File is empty.")

    # firewall_name takes precedence; fall back to device_name (legacy param).
    # AU full review D9: no filename-stem fallback here - the parser falls
    # back to the config's own "set hostname", which the stem used to mask
    # (two uploads of one firewall under different file names made two
    # Firewall rows).  The stem is only used when the config has no hostname.
    effective_name = firewall_name or device_name or None
    stem_fallback = Path(file.filename or "unknown").stem

    filename = file.filename

    def _work():
        nonlocal baseline_id
        # C-13: reject input that is not a FortiGate config BEFORE storing
        # anything.  A FortiGate `show full-configuration` is a nest of
        # `config ... end` blocks; tokenising arbitrary text like
        # "hello world" yields zero blocks.  Without this guard the parser
        # would still register a FirewallDevice and emit bogus "missing
        # control" compliance findings from an empty config (every other
        # config route already 422s on unparseable input).  parse_forti_block
        # is pure/read-only, and this runs before any DB write so nothing is
        # stored; run in the threadpool (here) so a large upload never blocks
        # the event loop.
        if not parse_forti_block(text):
            raise HTTPException(
                status_code=422,
                detail="Not a FortiGate configuration: no 'config ... end' "
                       "blocks were found. Upload the output of 'show "
                       "full-configuration' (or a config backup). Nothing "
                       "was stored.",
            )
        # Resolve baseline_name → baseline_id when the caller passes a name
        # instead of an ID, so they don't need a prior /baselines lookup.
        # baseline_id takes precedence if both are supplied.
        if populate_approved_hosts and baseline_id is None and baseline_name:
            bl = get_or_create_baseline(db, baseline_name, site_id=site_id)
            baseline_id = bl.id

        try:
            stats = ingest_fortigate_config(
                text, db,
                firewall_name=effective_name,
                fallback_name=stem_fallback,
                source_file=filename,
                generate_findings=generate_findings,
                populate_approved_hosts=populate_approved_hosts,
                baseline_id=baseline_id,
                purdue_zone_from=purdue_zone_from,
                purdue_zone_to=purdue_zone_to,
                site_id=site_id,
            )
        except IngestLimitExceeded as exc:
            # B-08: rule-row budget exceeded before any DB write.
            db.rollback()
            raise _limit_exceeded(exc)
        except ValueError as exc:
            # Deliberate, user-facing validation messages from the parser
            # (e.g. "no firewall policies found") - shown as-is.
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            db.rollback()
            raise _internal_error(exc, "Failed to parse FortiGate config",
                                  status_code=400, context=repr(filename))

        try:
            stats["classification"] = classify_hosts(db, site_id=site_id)
            db.commit()
        except Exception as exc:
            # ingest_fortigate_config() already committed its own transaction;
            # this rolls back the classify_hosts() changes only.
            db.rollback()
            stats["classification"] = _error_stub(
                exc, "classify_hosts failed after FortiGate ingest (non-fatal)")
        return stats

    stats = await run_in_threadpool(_in_site, db, site_id, _work)
    effective_name = stats.get("device_name") or effective_name or stem_fallback   # D9: hostname-resolved
    stats["config_stored"] = await run_in_threadpool(
        _in_site, db, site_id, _store_config_text, db, site_id, stats.get("firewall_id"), text,
        "fortigate", file.filename, effective_name)
    stats["ha_cluster"] = await run_in_threadpool(_in_site, db, site_id, _record_ha, db, site_id,
                                                  text, effective_name, ha_peer)
    reg = await run_in_threadpool(_register_config_device, db, site_id, text, "fortigate",
                                  firewall_name or device_name)
    return {
        "filename": file.filename,
        **site_out,
        **reg,
        "firewall_name": effective_name,
        "topology_state": stats.get("topology_state", "single"),
        "is_multi_fw": stats.get("is_multi_fw", False),
        "stats": stats,
    }


@router.post("/ingest/switch")
@_reviews_after_upload('switch output')
async def ingest_switch_file(
    file: UploadFile = File(...),
    device_name: str | None = Query(None, max_length=255),
    vendor_hint: str | None = None,
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload switch config/command output. Pass `?vendor_hint=cisco|hp|fortinet`
    when the UI already asked which vendor this switch is - this only
    needs the vendor, not the specific `show` command used; the exact
    sub-format (running-config vs. vlan-brief vs. cdp/lldp neighbors) is
    still auto-detected within that vendor's family. Omit it to fall
    back to detecting across both vendors from content alone.

    Cisco: running-config, `show vlan brief`, `show cdp neighbors
    detail`, `show lldp neighbors detail`.
    HP/ProCurve: running-config, `show lldp info remote-device` (brief
    or detail). HP switches don't speak CDP (that's Cisco-proprietary),
    so LLDP is their only neighbor-discovery source.

    Populates SwitchInterface rows (physical topology: VLAN assignment
    and CDP/LLDP neighbor per port).

    Pass `?device_name=<switch-hostname>` for command outputs that don't
    carry their own hostname (vlan brief, cdp/lldp neighbor dumps) so
    ports are correctly associated with the switch they came from.
    Running-config text can supply its own hostname via the `hostname`
    line and doesn't need this.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Switch config", content="text")
    text = _decode_text_upload(raw)

    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_switch_config,
            text, db, device_name=device_name, source_file=file.filename, vendor_hint=vendor_hint,
            site_id=site_id,
        )
    except VendorMismatchError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if stats["config_type"] == "unknown":
        raise HTTPException(
            status_code=422,
            detail="Could not detect config format for the given vendor_hint "
                   "(or, if none was given, across Cisco/HP auto-detection). "
                   "If you passed vendor_hint, double check it matches the "
                   "actual switch vendor.",
        )

    return {"filename": file.filename, **site_out, "stats": stats}


@router.post("/ingest/mac-table")
@_reviews_after_upload('MAC table')
async def ingest_mac_table_file(
    file: UploadFile = File(...),
    device_name: str | None = Query(None, max_length=255),
    vendor_hint: str | None = None,
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload a MAC address table dump (`show mac address-table` on Cisco,
    `show mac-address` on HP/ProCurve). Pass `?vendor_hint=cisco|hp`
    to skip auto-detection. Pass `?device_name=<switch>` to tag which
    switch the entries came from.

    This is the bridge that links hosts discovered via pcap/ARP to
    their real VLAN membership, rather than relying on subnet inference.
    Populates MacTableEntry rows (audit trail) and sets Host.vlan with
    vlan_source="mac_table". Auto-runs classification afterward since
    VLAN data feeds the vlan_inferred classification mechanism.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "MAC table", content="text")
    text = _decode_text_upload(raw)
    filename = file.filename

    def _work():
        stats = ingest_mac_table(
            text, db, device_name=device_name,
            source_file=filename, vendor_hint=vendor_hint,
            site_id=site_id,
        )
        if stats["table_type"] == "unknown":
            raise HTTPException(
                status_code=422,
                detail="Could not detect MAC table format. Expected Cisco "
                       "'show mac address-table' or HP 'show mac-address' output. "
                       "Pass ?vendor_hint=cisco or ?vendor_hint=hp if auto-detection fails.",
            )
        stats["classification"] = classify_hosts(db, site_id=site_id)
        return stats

    try:
        stats = await run_in_threadpool(_in_site, db, site_id, _work)
    except VendorMismatchError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"filename": filename, **site_out, "stats": stats}


# ------------------------------------------------------- switch interfaces --

@router.get("/switch-interfaces")
def list_switch_interfaces(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    device_name: str | None = Query(None, max_length=255),
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List switch ports with their VLAN assignment (including name), and
    CDP/LLDP neighbor. Optionally filter by device_name and site_id.
    """
    query = db.query(SwitchInterface)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(SwitchInterface.site_id == site_id)
    if device_name:
        query = query.filter(SwitchInterface.device_name == device_name)

    interfaces = _page(
        query.order_by(SwitchInterface.device_name.asc(), SwitchInterface.port_name.asc(),
                       SwitchInterface.id.asc()),
        response, limit, offset,
    ).all()
    names = site_names(db)
    return [
        {
            "id": i.id,
            "site_id": i.site_id,
            "site_name": names.get(i.site_id),
            "device_name": i.device_name,
            "port_name": i.port_name,
            "vlan": i.vlan,
            "vlan_name": i.vlan_name,
            "mode": i.mode,
            "description": i.description,
            "neighbor_device": i.neighbor_device,
            "neighbor_port": i.neighbor_port,
            "neighbor_platform": i.neighbor_platform,
            "neighbor_ip": i.neighbor_ip,
            "neighbor_protocol": i.neighbor_protocol,
        }
        for i in interfaces
    ]


# -------------------------------------------------- device classification --

@router.post("/classify")
def run_classification(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """
    (Re-)run automatic Purdue-model classification over all hosts that
    aren't manually classified — vendor-hint, protocol-inferred, and
    VLAN-name-inferred mechanisms, in that precedence order. Also runs
    subnet inference to fill VLAN membership for hosts not yet reached
    by a MAC address-table ingest.

    Safe to call repeatedly — never overwrites a manual classification.
    """
    site_row = _operation_site(db, site, site_id)
    subnet_stats = infer_vlan_by_subnet(db, site_id=site_row.id)
    classification_stats = classify_hosts(db, site_id=site_row.id)
    return {**classification_stats, "subnet_inference": subnet_stats, **_site_info(site_row)}



@router.get("/purdue-levels")
def get_purdue_levels():
    """
    The canonical Purdue level list (F-08, app.purdue.VALID_LEVELS) and
    the device_type reference table.

    ``levels``: ``[{"level": 0|1|2|3|3.5|4|5, "label": "L3.5",
    "name": "Industrial DMZ", "is_dmz": bool}]``, lowest first - the one
    list every level picker should offer.

    ``device_types``: the Purdue/ISA-99 device_type categories this tool
    knows about and their default level (0-4, 3.5 for DMZ roles; null =
    no default), for the manual-classification picklist.
    """
    return {
        "levels": canonical_levels(),
        "device_types": [
            {"device_type": device_type, "purdue_level": level, "label": label}
            for device_type, (level, label) in DEVICE_TYPE_REFERENCE.items()
        ],
    }


@router.get("/hosts/{host_id}/classification-suggestion")
def get_host_classification_suggestion(host_id: int, db: DBSession = Depends(get_db)):
    """Suggested device types (with default Purdue level and reasons) for a
    host, from its captured traffic, writes, vendor and capture roles, plus
    the other addresses of its MAC.  Read only - classify with
    PATCH /hosts/{id}/classification."""
    from app.parsers.classification_hints import suggest
    from app.parsers.site_scope import analysis_site
    host = db.query(Host).filter(Host.id == host_id, real_host_clause()).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    with analysis_site(db, host.site_id):
        return suggest(db, host)


@router.delete("/hosts/{host_id}/classification")
def clear_host_classification(
    host_id: int,
    apply_to_same_mac: bool = Query(False, description="Also clear the other addresses of the host's MAC"),
    db: DBSession = Depends(get_db),
):
    """Remove a manual classification: the host (and, with
    apply_to_same_mac, the other addresses of its MAC) goes back to
    automatic classification, which runs at once for the host's site."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    rows = _same_mac_rows(db, host, apply_to_same_mac)
    cleared = []
    for h in rows:
        if h.classification_source == "manual":
            h.device_type = h.purdue_level = h.classification_source = None
            cleared.append(h.id)
    db.flush()
    classify_hosts(db, site_id=host.site_id)
    db.commit()
    return {"cleared": cleared, "hosts": [
        {"id": h.id, "ip": h.ip, "device_type": h.device_type, "purdue_level": h.purdue_level,
         "classification_source": h.classification_source} for h in rows]}


def _same_mac_rows(db: DBSession, host: Host, apply: bool) -> list:
    """The host, plus (apply) every other row of its site carrying its MAC."""
    if not apply or not host.mac:
        return [host]
    others = db.query(Host).filter(Host.mac == host.mac, Host.id != host.id,
                                   Host.site_id == host.site_id, real_host_clause()).all()
    return [host] + others


@router.patch("/hosts/{host_id}/classification")
def set_host_classification(
    host_id: int,
    device_type: str | None = Query(None, max_length=64, description=(
        "Device type; omitted = keep each host's device type and set only purdue_level "
        "(Host Topology drag and drop between levels)")),
    purdue_level: str | None = _level_query(),
    apply_to_same_mac: bool = Query(False, description=(
        "Also classify the other addresses of the host's MAC (one device, several addresses)")),
    unclassified: bool = Query(False, description=(
        "Pin the host as unclassified: no Purdue level, set by the operator, so automatic "
        "classification does not place it again (device type kept unless given)")),
    db: DBSession = Depends(get_db),
):
    """
    Manually classify a host. This is authoritative: once set, automatic
    (re-)classification (via /classify, or automatically after future
    pcap/ARP ingests) will never overwrite this host's device_type or
    purdue_level.

    If `device_type` matches an entry in /purdue-levels and `purdue_level`
    isn't given explicitly, the reference table's default level is used.
    An unrecognized device_type is still accepted (for cases not covered
    by the reference table) but then requires purdue_level to be given
    explicitly, since there's no default to infer it from.

    Without device_type (owner 2026-10-13: Host Topology drag and drop
    between levels) only the level is set - each host keeps its device type -
    and purdue_level is required.

    unclassified=true (owner 2026-10-13: Host Topology drop on Unclassified)
    pins the host without a level: classification_source "manual", so
    subnet / VLAN / interface-label classification leaves it alone.
    DELETE returns it to automatic classification.
    """
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    purdue_level = _level_param("purdue_level", purdue_level)
    if unclassified and purdue_level is not None:
        raise HTTPException(status_code=400, detail="unclassified=true takes no purdue_level.")
    if device_type is None and purdue_level is None and not unclassified:
        raise HTTPException(status_code=400, detail=f"Give device_type, purdue_level or both ({_LEVEL_DOC}).")
    if purdue_level is None and not unclassified:
        reference = DEVICE_TYPE_REFERENCE.get(device_type)
        if device_type == "router":
            reference = (None, "")          # infrastructure: no Purdue level
        elif reference is None or reference[0] is None:
            raise HTTPException(
                status_code=400,
                detail=(f"'{device_type}' has no default purdue_level - please provide one "
                        f"explicitly ({_LEVEL_DOC})."),
            )
        purdue_level = reference[0] if reference else None

    rows = _same_mac_rows(db, host, apply_to_same_mac)
    for h in rows:
        if device_type is not None:
            h.device_type = device_type
        h.purdue_level = purdue_level
        h.classification_source = "manual"
    db.commit()

    return {
        "id": host.id, "device_type": host.device_type,
        "purdue_level": host.purdue_level, "classification_source": host.classification_source,
        "updated_ids": [h.id for h in rows],
    }


@router.patch("/hosts/{host_id}/role")
def set_host_role(
    host_id: int,
    role: str = Query(..., max_length=64),
    db: DBSession = Depends(get_db),
):
    """
    Manually set a host's functional role. This is authoritative: once
    set (role_source="manual"), automatic LLDP/CDP role inference will
    never overwrite it.

    Valid roles: plc, hmi, rtu, ied, historian, scada_server, switch,
    router, firewall, ap, server, workstation, ip_camera, ups, printer,
    ot_gateway — or any other string for custom/unlisted roles.

    To clear a manual role, PATCH with role="" (empty string).
    """
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    if role == "":
        host.role = None
        host.role_source = None
    else:
        host.role = role
        host.role_source = "manual"
    db.commit()

    return {
        "id": host.id, "ip": host.ip, "mac": host.mac,
        "role": host.role, "role_source": host.role_source,
    }


# ----------------------------------------------------------------- hosts --

@router.get("/hosts")
def list_hosts(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    purdue_level: str | None = _level_query(),
    device_type: str | None = None,
    role: str | None = None,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List hosts. Optionally filter by purdue_level (0-5 or 3.5), device_type, or
    role (functional role from LLDP/CDP: plc, hmi, historian, switch, etc.)
    to power a Purdue-level-grouped or role-filtered view of the network.
    """
    purdue_level = _level_param("purdue_level", purdue_level)
    query = db.query(Host).filter(real_host_clause())   # not the group marker
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(Host.site_id == site_id)
    if purdue_level is not None:
        query = query.filter(Host.purdue_level == purdue_level)
    if device_type:
        query = query.filter(Host.device_type == device_type)
    if role:
        query = query.filter(Host.role == role)

    hosts = _page(query.order_by(Host.last_seen.desc(), Host.id.desc()),
                  response, limit, offset).all()
    names = site_names(db)
    return [
        {
            "id": h.id,
            "site_id": h.site_id,
            "site_name": names.get(h.site_id),
            "ip": h.ip,
            "mac": h.mac,
            "vendor": h.vendor,
            "hostname": h.hostname,
            "device_type": h.device_type,
            "purdue_level": h.purdue_level,
            "classification_source": h.classification_source,
            "role": h.role,
            "role_source": h.role_source,
            "vlan": h.vlan,
            "vlan_source": h.vlan_source,
            "first_seen": h.first_seen,
            "last_seen": h.last_seen,
            "sources": h.sources,
            "stale": bool(h.stale),
            "inventory_excluded": bool(h.inventory_excluded),
        }
        for h in hosts
    ]


@router.post("/hosts/mark-stale")
def mark_stale_hosts_route(
    older_than_days: int = Query(30, ge=0, le=3650),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Flag hosts not seen for ``older_than_days`` as stale (and un-flag
    hosts seen since). F-09.  Runs in ONE site: ``site_id``, or derived when
    only one site exists (else 422) - it never writes across all sites."""
    from app.parsers.host_identity import mark_stale_hosts
    site_row = _operation_site(db, None, site_id)
    result = mark_stale_hosts(db, older_than_days, site_id=site_row.id)
    db.commit()
    return result


@router.get("/hosts/{host_id}/history")
def get_host_address_history(host_id: int, db: DBSession = Depends(get_db)):
    """Every (ip, mac, source) this host has been observed with, newest
    first (F-09: DHCP renumbering, IP conflicts)."""
    from app.parsers.host_identity import host_address_history
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return {
        "host_id": host.id, "ip": host.ip, "mac": host.mac, "stale": bool(host.stale),
        "history": host_address_history(db, host_id),
    }


# ---------------------------------------------------------- asset inventory --

def _host_to_asset(h: Host, protocols: list[str] | None = None,
                   site_name: str | None = None, inventory: list[str] | None = None) -> dict:
    """Serialize a Host to the full IACS asset inventory dict.

    ``site_id`` / ``site_name`` are the multi-site Site the host belongs to;
    ``site`` (below) is the older free-text physical-location field."""
    return {
        # Identity
        "id":                  h.id,
        "site_id":             h.site_id,
        "site_name":           site_name,
        "ip":                  h.ip,
        "mac":                 h.mac,
        "vendor":              h.vendor,
        "hostname":            h.hostname,
        # Network placement
        "device_type":         h.device_type,
        "purdue_level":        h.purdue_level,
        "classification_source": h.classification_source,
        "role":                h.role,
        "role_source":         h.role_source,
        "vlan":                h.vlan,
        "vlan_source":         h.vlan_source,
        "sources":             h.sources,
        "stale":               bool(h.stale),
        # Inventory membership (SF-5 follow-up): see _inventory_evidence
        "in_inventory":        bool(inventory),
        "inventory_evidence":  list(inventory or []),
        # owner 2026-10-14: not an inventory asset (hidden from the list / export only)
        "inventory_excluded":  bool(h.inventory_excluded),
        "inventory_excluded_reason": h.inventory_excluded_reason,
        "inventory_excluded_by": h.inventory_excluded_by,
        "inventory_excluded_at": h.inventory_excluded_at,
        # Timestamps
        "first_seen":          h.first_seen,
        "last_seen":           h.last_seen,
        # IACS inventory — physical identity
        "model":               h.model,
        "serial_number":       h.serial_number,
        "firmware_version":    h.firmware_version,
        # IACS inventory — physical location
        "site":                h.site,
        "building":            h.building,
        "panel":               h.panel,
        # IACS inventory — operational
        "criticality":         h.criticality,
        "is_safety_function":  h.is_safety_function,
        # IEC 62443-4-2 capability security level (documentation only)
        "sl_c":                h.sl_c,
        "sl_c_source":         h.sl_c_source,
        # IACS inventory — ownership
        "owner":               h.owner,
        "asset_tag":           h.asset_tag,
        "notes":               h.notes,
        # IACS inventory — approval
        "approved":            h.approved,
        "approved_by":         h.approved_by,
        "approved_at":         h.approved_at,
        "last_reviewed_at":    h.last_reviewed_at,
        "last_reviewed_by":    h.last_reviewed_by,
        # Derived — protocols spoken (optional, only when joined)
        "protocols":           protocols or [],
    }


_VALID_CRITICALITY = {"high", "medium", "low"}


def _sl_c_param(value) -> int | None:
    """SL-C query / body value -> 0-4 or None ('none', '', null clear); 422 otherwise."""
    from app.iec_zones import ZoneError, parse_sl
    if value is None or str(value).strip().lower() in ("", "none", "null", "not assessed"):
        return None
    try:
        return parse_sl(value)
    except ZoneError as exc:
        raise HTTPException(status_code=422, detail=f"sl_c: {exc}")

_INVENTORY_DOC = ("Inventory membership: 'listed' = the host came from an Asset Inventory CSV, "
                  "matches an Approved Host List entry (ip or mac) or was approved on the inventory "
                  "page; 'unlisted' = known only from traffic, ARP / MAC tables or firewall configs; "
                  "'unknown' = unlisted and not classified by the operator (no device type / level); "
                  "'excluded' = only the hosts excluded from the inventory; 'all' = every host incl. excluded.")
_INVENTORY_VALUES = ("listed", "unlisted", "unknown", "excluded", "all")
_INCLUDE_EXCLUDED_HOSTS_DOC = ("owner 2026-10-14: hosts excluded from the inventory ('not an inventory asset') are left "
                               "out unless true (or inventory=excluded / all)")
_UNCLASSIFIED_TYPES = (None, "", "ics_protocol_client_unclassified")


def _inventory_evidence(db, sid: int | None = None) -> dict[int, list[str]]:
    """SF-5 follow-up: per host id, why the host counts as *in an inventory*
    (empty list = not in any).  ``asset_inventory`` - loaded from an Asset
    Inventory CSV (source ``baseline``); ``approved_host_list`` - an
    ApprovedHost row carries its ip or mac; ``approved`` - approved on the
    inventory page.  Computed in Python: ``sources`` is a JSON list."""
    from app.models import ApprovedHost
    q = db.query(Host.id, Host.ip, Host.mac, Host.sources, Host.approved).filter(real_host_clause())
    if sid is not None:
        q = q.filter(Host.site_id == sid)
    ah_ips, ah_macs = set(), set()
    for ip, mac in db.query(ApprovedHost.ip, ApprovedHost.mac).all():
        if ip:
            ah_ips.add(ip)
        if mac:
            ah_macs.add(mac.lower())
    out: dict[int, list[str]] = {}
    for hid, ip, mac, sources, approved in q.all():
        ev = []
        if "baseline" in (sources or []):
            ev.append("asset_inventory")
        if (ip and ip in ah_ips) or (mac and mac.lower() in ah_macs):
            ev.append("approved_host_list")
        if approved is True:
            ev.append("approved")
        out[hid] = ev
    return out


def _apply_inventory_filter(query, inventory: str | None, evidence: dict[int, list[str]],
                            include_excluded: bool = False):
    """``inventory=listed|unlisted|unknown|excluded|all`` on /assets and /assets/export;
    hosts excluded from the inventory are left out unless ``include_excluded``,
    ``excluded`` (only them) or ``all``."""
    if inventory not in (None, "") and inventory not in _INVENTORY_VALUES:
        raise HTTPException(status_code=422,
                            detail=f"inventory must be one of {', '.join(_INVENTORY_VALUES)}")
    if inventory == "excluded":
        return query.filter(Host.inventory_excluded.is_(True))
    if inventory == "all":
        return query
    if not include_excluded:
        query = query.filter(Host.inventory_excluded.is_not(True))
    if inventory in (None, ""):
        return query
    from sqlalchemy import false
    listed = [hid for hid, ev in evidence.items() if ev]
    if inventory == "listed":
        return query.filter(Host.id.in_(listed)) if listed else query.filter(false())
    if listed:
        query = query.filter(Host.id.notin_(listed))
    if inventory == "unknown":
        query = query.filter(Host.device_type.in_(_UNCLASSIFIED_TYPES[1:]) | Host.device_type.is_(None),
                             Host.classification_source.is_distinct_from("manual"))
    return query

_ASSET_SITE_DOC = ("Multi-site filter: only hosts of this site (id, name or code). "
                   "Omit for all sites.")
_ASSET_LOCATION_DOC = ("Free-text physical location of the asset (the inventory "
                       "'site' field), case-insensitive contains")


def _asset_site_filter(db, site: str | None, site_id: int | None) -> int | None:
    """B-24: the optional multi-site filter of /assets and /assets/export.

    ``site`` (id / name / code) or ``site_id``; both given must agree.  None
    (no filter, every site) when neither is given; HTTP 422 when unknown."""
    if site in (None, ""):
        return _check_site_filter(db, site_id)
    row = _require_site(db, site)
    if site_id is not None and site_id != row.id:
        _check_site_filter(db, site_id)
        raise HTTPException(status_code=422,
                            detail=f"'site' ({row.name}) and 'site_id' ({site_id}) disagree")
    return row.id


@router.get("/assets")
def list_assets(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    purdue_level: str | None = _level_query(),
    device_type: str | None = None,
    role: str | None = None,
    criticality: str | None = None,
    approved: str | None = None,
    location: str | None = Query(None, max_length=128, description=_ASSET_LOCATION_DOC),
    search: str | None = None,
    inventory: str | None = Query(None, description=_INVENTORY_DOC),
    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_HOSTS_DOC),
    site: str | None = Query(None, description=_ASSET_SITE_DOC),
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    Full IACS asset inventory — every Host with all inventory fields joined.

    **Query parameters** (all optional)

    - ``purdue_level``  — 0–5, or 3.5 (industrial DMZ)
    - ``device_type``   — plc, hmi, historian, etc.
    - ``role``          — functional role from CDP/LLDP
    - ``criticality``   — high / medium / low
    - ``approved``      — true / false / null (not yet reviewed)
    - ``location``      — free-text physical location (the inventory ``site``
      field of each asset), case-insensitive contains
    - ``search``        — free-text substring across ip, mac, hostname, model
    - ``inventory``     — ``listed`` (from an Asset Inventory CSV, an Approved
      Host List entry or approved on the page), ``unlisted`` (known only from
      traffic, ARP / MAC tables or firewall configs) or ``unknown`` (unlisted
      and not classified by the operator)
    - ``site`` / ``site_id`` — multi-site: only hosts of this site (id, name
      or code / numeric id; both given must agree)

    Returns each host with its protocols spoken (distinct values from
    ProtocolDetail) included as a list, ``in_inventory`` and the
    ``inventory_evidence`` behind it.
    """
    from sqlalchemy import func as _func

    purdue_level = _level_param("purdue_level", purdue_level)
    query = db.query(Host).filter(real_host_clause())   # not the group marker
    sid = _asset_site_filter(db, site, site_id)
    if sid is not None:
        query = query.filter(Host.site_id == sid)
    inv_ev = _inventory_evidence(db, sid)
    query = _apply_inventory_filter(query, inventory, inv_ev, include_excluded)
    if purdue_level is not None:
        query = query.filter(Host.purdue_level == purdue_level)
    if device_type:
        query = query.filter(Host.device_type == device_type)
    if role:
        query = query.filter(Host.role == role)
    if criticality:
        query = query.filter(Host.criticality == criticality)
    if approved is not None:
        if approved.lower() == "true":
            query = query.filter(Host.approved == True)
        elif approved.lower() == "false":
            query = query.filter(Host.approved == False)
        else:
            query = query.filter(Host.approved.is_(None))
    if location:
        query = query.filter(Host.site.ilike(_like_pattern(location), escape="\\"))
    if search:
        term = _like_pattern(search)
        from sqlalchemy import or_
        query = query.filter(or_(
            Host.ip.ilike(term, escape="\\"),
            Host.mac.ilike(term, escape="\\"),
            Host.hostname.ilike(term, escape="\\"),
            Host.model.ilike(term, escape="\\"),
            Host.asset_tag.ilike(term, escape="\\"),
        ))

    hosts = _page(
        query.order_by(Host.purdue_level.asc().nulls_last(), Host.ip.asc(), Host.id.asc()),
        response, limit, offset,
    ).all()

    # Gather protocols spoken per host in a single query
    from app.models import NetworkSession, ProtocolDetail
    host_ids = [h.id for h in hosts]
    proto_rows = (
        db.query(NetworkSession.src_host_id, ProtocolDetail.protocol)
        .join(ProtocolDetail, ProtocolDetail.session_id == NetworkSession.id)
        .filter(NetworkSession.src_host_id.in_(host_ids))
        .distinct()
        .all()
    ) if host_ids else []

    proto_map: dict[int, list[str]] = {}
    for host_id, proto in proto_rows:
        proto_map.setdefault(host_id, []).append(proto)

    names = site_names(db)
    out = [_host_to_asset(h, proto_map.get(h.id), names.get(h.site_id), inv_ev.get(h.id)) for h in hosts]
    _add_iec_zones(db, hosts, out)
    # owner 2026-10-12: where a VLAN taken from a firewall interface came from
    fw_vlan = [h for h in hosts if h.vlan_source == "fw_interface"]
    if fw_vlan:
        from app.parsers.device_classification import interface_vlan_for, vlan_interfaces
        index = vlan_interfaces(db, {h.site_id for h in fw_vlan})
        origin = {}
        for h in fw_vlan:
            hit = interface_vlan_for(h.ip, index.get(h.site_id, []))
            if hit is not None:
                origin[h.id] = (f"{hit[2]} {hit[3]}" + (f" ({hit[4]})" if hit[4] else "")
                                + f", {hit[0]}")
        for d in out:
            if d.get("id") in origin:
                d["vlan_origin"] = origin[d["id"]]
    return out


def _add_iec_zones(db: DBSession, hosts, rows) -> None:
    """Asset rows gain ``iec_zones`` ([{id, name, sl_t, basis}]) and ``iec_zone``
    (the first name, or None) - owner 2026-10-13: "asset inventory needs a zone
    parameter" (IEC 62443 zone on Zones & Conduits)."""
    from app import iec_zones as iz
    idx = iz.host_zone_index(db, hosts)
    for d in rows:
        zs = idx.get(d.get("id"), [])
        d["iec_zones"] = zs
        d["iec_zone"] = zs[0]["name"] if zs else None


@router.patch("/assets/{host_id}")
def update_asset(
    host_id: int,
    # C-16: every string parameter declares the max_length of the column it
    # writes, so an over-long value is rejected with a clean FastAPI 422
    # before it ever reaches the DB - on SQLite (which silently truncates /
    # stores) as well as PostgreSQL (which would otherwise raise a DataError
    # turned into a 500/mislabelled 422).  notes is a Text column (unbounded)
    # so it carries no cap.
    # Physical identity
    model:            str | None = Query(None, max_length=128),
    serial_number:    str | None = Query(None, max_length=128),
    firmware_version: str | None = Query(None, max_length=128),
    # Physical location (free text; NOT the multi-site Site - B-24).
    # Column Host.site is String(128), so cap at 128 (was mistakenly 256).
    location:         str | None = Query(None, max_length=128, description="Free-text physical location (stored in the asset's 'site' field)"),
    building:         str | None = Query(None, max_length=128),
    panel:            str | None = Query(None, max_length=128),
    # Operational
    criticality:      str | None = None,
    is_safety_function: bool | None = None,
    # IEC 62443-4-2 capability security level: 1-4, "none" clears
    sl_c:             str | None = Query(None, max_length=64, description="SL-C 0-4 (also SL1 / SL-C 2 / 'SL0 - No Requirements'); 'none' clears"),
    sl_c_source:      str | None = Query(None, max_length=255, description="where the SL-C comes from (certificate, vendor statement, assessment); empty clears"),
    # Ownership
    owner:            str | None = Query(None, max_length=128),
    asset_tag:        str | None = Query(None, max_length=64),
    notes:            str | None = None,
    # Approval
    approved:         bool | None = None,
    approved_by:      str | None = Query(None, max_length=128),
    inventory_excluded: bool | None = Query(None, description=(
        "owner 2026-10-14: true = not an inventory asset - hidden from the Inventory list / export only "
        "(topology, findings and traffic pages unchanged) and counted as a reviewed, known host by "
        "unknown_device; false = include it again")),
    inventory_excluded_reason: str | None = Query(None, max_length=500),
    inventory_excluded_by: str | None = Query(None, max_length=128),
    # Review
    last_reviewed_by: str | None = Query(None, max_length=128),
    # IEC 62443 zone (Zones & Conduits)
    iec_zone:         str | None = Query(None, max_length=128, description=(
        "IEC 62443 zone name: the host becomes a host member of that zone (created when missing), "
        "leaving any other zone it was a host member of; empty removes its own membership (a zone "
        "inherited from its subnet stays)")),
    db: DBSession = Depends(get_db),
):
    """
    Update IACS inventory fields on a host.  Only provided (non-null)
    parameters are written; omit a field to leave it unchanged.

    **Approval workflow**

    Pass ``approved=true`` + ``approved_by=<name>`` to approve the device;
    ``approved=false`` to flag it as unapproved/rogue.  ``approved_at`` and
    ``last_reviewed_at`` are set automatically to the current UTC time
    whenever ``approved`` or ``last_reviewed_by`` is provided.

    ``location`` sets the free-text physical location (returned as the
    asset's ``site`` field).  The multi-site Site of a host is not changed
    here.

    **Criticality values**   high / medium / low

    **SL-C** (IEC 62443-4-2 capability security level of the component)
    0-4 (SL0 - No Requirements ... SL4), ``none`` to clear, with ``sl_c_source``.  Documentation only: shown
    against the zone SL-T on the Zones & Conduits page, never used by the
    findings engine.

    This endpoint never overwrites network-discovered fields (ip, mac,
    vendor, hostname, device_type, purdue_level, role, vlan) — use
    PATCH /hosts/{id}/classification for those.
    """
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    now = datetime.now(timezone.utc)

    if model            is not None: host.model            = model
    if serial_number    is not None: host.serial_number    = serial_number
    if firmware_version is not None: host.firmware_version = firmware_version
    if location         is not None: host.site             = location
    if building         is not None: host.building         = building
    if panel            is not None: host.panel            = panel
    if owner            is not None: host.owner            = owner
    if asset_tag        is not None: host.asset_tag        = asset_tag
    if notes            is not None: host.notes            = notes
    if is_safety_function is not None: host.is_safety_function = is_safety_function

    if sl_c is not None:
        host.sl_c = _sl_c_param(sl_c)
    if sl_c_source is not None:
        host.sl_c_source = sl_c_source.strip() or None

    if criticality is not None:
        if criticality not in _VALID_CRITICALITY:
            raise HTTPException(
                status_code=400,
                detail=f"criticality must be one of: {', '.join(sorted(_VALID_CRITICALITY))}",
            )
        host.criticality = criticality

    if approved is not None:
        host.approved    = approved
        host.approved_at = now
        if approved_by:
            host.approved_by = approved_by

    if inventory_excluded is not None:
        if inventory_excluded:
            # audit 2026-10-15: a repeated exclude keeps the recorded reason / author / time
            if not host.inventory_excluded:
                host.inventory_excluded_at = now
            if inventory_excluded_reason is not None:
                host.inventory_excluded_reason = inventory_excluded_reason.strip()[:500] or None
            if inventory_excluded_by is not None:
                host.inventory_excluded_by = inventory_excluded_by.strip()[:128] or None
            host.inventory_excluded = True
        else:
            host.inventory_excluded = False
            host.inventory_excluded_at = None
            host.inventory_excluded_reason = None
            host.inventory_excluded_by = None
    if last_reviewed_by is not None:
        host.last_reviewed_by = last_reviewed_by
        host.last_reviewed_at = now

    zone_status = None
    if iec_zone is not None:
        if host.site_id is None:
            raise HTTPException(status_code=422, detail="The host has no site: IEC 62443 zones are per site.")
        from app import iec_zones as iz
        zone_status = iz.set_host_zone(db, host.site_id, host, iec_zone)
        if zone_status == "skipped":
            raise HTTPException(status_code=422, detail="The host has neither a MAC nor a valid IP address to place in a zone.")

    db.commit()
    out = _host_to_asset(host, site_name=site_names(db).get(host.site_id))
    _add_iec_zones(db, [host], [out])
    if zone_status is not None:
        out["iec_zone_change"] = zone_status
    return out


@router.get("/assets/export")
def export_assets_csv(
    purdue_level: str | None = _level_query(),
    approved: str | None = None,
    criticality: str | None = None,
    location: str | None = Query(None, max_length=128, description=_ASSET_LOCATION_DOC),
    inventory: str | None = Query(None, description=_INVENTORY_DOC),
    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_HOSTS_DOC),
    site: str | None = Query(None, description=_ASSET_SITE_DOC),
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    Export the full IACS asset inventory as CSV.

    One row per host, all inventory fields included, with protocols spoken
    as a pipe-separated list in a single column.  Scoped exports take
    ``purdue_level``, ``approved``, ``criticality``, ``location`` (free-text
    physical location), ``inventory`` (listed / unlisted / unknown) and the
    multi-site ``site`` / ``site_id`` filter.

    The file includes a UTF-8 BOM so Excel opens it without a text import
    wizard.

    **Columns**

    asset_tag, ip, mac, hostname, vendor, model, serial_number,
    firmware_version, device_type, role, purdue_level, vlan, zone (IEC 62443),
    site, building, panel, criticality, is_safety_function, sl_c,
    sl_c_source, owner, protocols, approved, approved_by, approved_at, in_inventory,
    inventory_evidence, last_reviewed_at, last_reviewed_by, notes,
    first_seen, last_seen
    """
    import csv, io
    from sqlalchemy import or_
    from app.models import NetworkSession, ProtocolDetail

    purdue_level = _level_param("purdue_level", purdue_level)
    query = db.query(Host).filter(real_host_clause())   # not the group marker
    sid = _asset_site_filter(db, site, site_id)
    if sid is not None:
        query = query.filter(Host.site_id == sid)
    if purdue_level is not None:
        query = query.filter(Host.purdue_level == purdue_level)
    if criticality:
        query = query.filter(Host.criticality == criticality)
    if approved is not None:
        if approved.lower() == "true":
            query = query.filter(Host.approved == True)
        elif approved.lower() == "false":
            query = query.filter(Host.approved == False)
        else:
            query = query.filter(Host.approved.is_(None))
    if location:
        query = query.filter(Host.site.ilike(_like_pattern(location), escape="\\"))
    inv_ev = _inventory_evidence(db, sid)
    query = _apply_inventory_filter(query, inventory, inv_ev, include_excluded)

    hosts = query.order_by(Host.purdue_level.asc().nulls_last(), Host.ip.asc()).all()

    host_ids = [h.id for h in hosts]
    proto_rows = (
        db.query(NetworkSession.src_host_id, ProtocolDetail.protocol)
        .join(ProtocolDetail, ProtocolDetail.session_id == NetworkSession.id)
        .filter(NetworkSession.src_host_id.in_(host_ids))
        .distinct().all()
    ) if host_ids else []
    proto_map: dict[int, list[str]] = {}
    for host_id, proto in proto_rows:
        proto_map.setdefault(host_id, []).append(proto)

    def _dt(v) -> str:
        return v.isoformat() if v else ""

    def _bool(v) -> str:
        if v is True:  return "yes"
        if v is False: return "no"
        return ""

    names = site_names(db)
    from app import iec_zones as iz
    zone_idx = iz.host_zone_index(db, hosts)       # IEC 62443 zone (owner 2026-10-13); re-imports as "zone"
    _FIELDS = [
        "site_name",
        "asset_tag", "ip", "mac", "hostname", "vendor",
        "model", "serial_number", "firmware_version",
        "device_type", "role", "purdue_level", "vlan", "zone",
        "site", "building", "panel",
        "criticality", "is_safety_function", "sl_c", "sl_c_source", "owner",
        "protocols",
        "approved", "approved_by", "approved_at",
        "in_inventory", "inventory_evidence", "inventory_excluded", "inventory_excluded_reason",
        "last_reviewed_at", "last_reviewed_by",
        "notes", "first_seen", "last_seen",
    ]

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=_FIELDS, lineterminator="\r\n")
    writer.writeheader()

    for h in hosts:
        writer.writerow(_csv_safe_row({
            "site_name":          names.get(h.site_id, ""),
            "asset_tag":          h.asset_tag or "",
            "ip":                 h.ip or "",
            "mac":                h.mac or "",
            "hostname":           h.hostname or "",
            "vendor":             h.vendor or "",
            "model":              h.model or "",
            "serial_number":      h.serial_number or "",
            "firmware_version":   h.firmware_version or "",
            "device_type":        h.device_type or "",
            "role":               h.role or "",
            "purdue_level":       "" if h.purdue_level is None else h.purdue_level,
            "vlan":               h.vlan or "",
            "zone":               " | ".join(z["name"] for z in zone_idx.get(h.id, [])),
            "site":               h.site or "",
            "building":           h.building or "",
            "panel":              h.panel or "",
            "criticality":        h.criticality or "",
            "is_safety_function": _bool(h.is_safety_function),
            "sl_c":               "" if h.sl_c is None else h.sl_c,
            "sl_c_source":        h.sl_c_source or "",
            "owner":              h.owner or "",
            "protocols":          "|".join(sorted(proto_map.get(h.id, []))),
            "approved":           _bool(h.approved),
            "approved_by":        h.approved_by or "",
            "in_inventory":       _bool(bool(inv_ev.get(h.id))),
            "inventory_evidence": "|".join(inv_ev.get(h.id, [])),
            "inventory_excluded": _bool(bool(h.inventory_excluded)),
            "inventory_excluded_reason": h.inventory_excluded_reason or "",
            "approved_at":        _dt(h.approved_at),
            "last_reviewed_at":   _dt(h.last_reviewed_at),
            "last_reviewed_by":   h.last_reviewed_by or "",
            "notes":              h.notes or "",
            "first_seen":         _dt(h.first_seen),
            "last_seen":          _dt(h.last_seen),
        }))

    csv_bytes = out.getvalue().encode("utf-8-sig")
    fname = f"iacs_asset_inventory_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# -------------------------------------------------------------- sessions --

@router.get("/sessions")
def list_sessions(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    protocol: str | None = None,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List observed sessions (the host/port/protocol map). Optionally
    filter by protocol, e.g. GET /sessions?protocol=modbus, and by site_id
    (a session belongs to the site of its source host).
    """
    from sqlalchemy.orm import joinedload as _jl
    query = db.query(NetworkSession).options(
        _jl(NetworkSession.src_host),
        _jl(NetworkSession.dst_host),
    )
    if protocol:
        query = query.filter(NetworkSession.protocol == protocol)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(NetworkSession.src_host_id.in_(
            db.query(Host.id).filter(Host.site_id == site_id)))

    sessions = _page(query.order_by(NetworkSession.last_seen.desc(), NetworkSession.id.desc()),
                     response, limit, offset).all()
    return [
        {
            "id": s.id,
            "site_id": s.src_host.site_id if s.src_host else None,
            "src_host": {"id": s.src_host.id, "ip": s.src_host.ip, "mac": s.src_host.mac} if s.src_host else None,
            "dst_host": {"id": s.dst_host.id, "ip": s.dst_host.ip, "mac": s.dst_host.mac} if s.dst_host else None,
            "src_port": s.src_port,
            "dst_port": s.dst_port,
            "transport": s.transport,
            "protocol": s.protocol,
            "packet_count": s.packet_count,
            "byte_count": s.byte_count,
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
        }
        for s in sessions
    ]


@router.get("/sessions/{session_id}/details")
def get_session_details(
    session_id: int,
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    db: DBSession = Depends(get_db),
):
    """
    Protocol-level detail for a single session - e.g. every Modbus
    read/write frame observed on that conversation.
    """
    session_row = db.query(NetworkSession).filter(NetworkSession.id == session_id).first()
    if not session_row:
        raise HTTPException(status_code=404, detail="Session not found")

    details = _page(
        db.query(ProtocolDetail)
        .filter(ProtocolDetail.session_id == session_id)
        .order_by(ProtocolDetail.timestamp.asc(), ProtocolDetail.id.asc()),
        response, limit, offset,
    ).all()
    return [
        {
            "id": d.id,
            "protocol": d.protocol,
            "direction": d.direction,
            "summary": d.summary,
            "fields": d.fields,
            "timestamp": d.timestamp,
        }
        for d in details
    ]


# --------------------------------------------------------- firewall rules --

@router.get("/firewall-rules")
def list_firewall_rules(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    device_type: str | None = None,
    device_name: str | None = None,
    action: str | None = None,
    enabled: bool | None = None,
    firewall_device_id: int | None = None,
    firewall_id: int | None = None,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List parsed firewall rules ("allowed" topology). Filter by
    device_type, device_name, action (permit/deny), or enabled
    (``?enabled=false`` lists administratively disabled rules, which are
    stored for review but excluded from every analysis).
    """
    query = db.query(FirewallRule)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(FirewallRule.site_id == site_id)
    if enabled is not None:
        query = query.filter(FirewallRule.enabled.is_(enabled))
    # Reliable per-device drill-down: Cisco/pfSense rows store the ACL or rule
    # label in device_name, so device_name can't select "rules of firewall X".
    if firewall_device_id is not None:
        query = query.filter(FirewallRule.firewall_device_id == firewall_device_id)
    if firewall_id is not None:
        query = query.filter(FirewallRule.firewall_id == firewall_id)
    if device_type:
        query = query.filter(FirewallRule.device_type == device_type)
    if device_name:
        query = query.filter(FirewallRule.device_name == device_name)
    if action:
        query = query.filter(FirewallRule.action == action)

    rules = _page(query.order_by(FirewallRule.device_name.asc(), FirewallRule.id.asc()),
                  response, limit, offset).all()
    names = site_names(db)
    return [
        {
            "id": r.id,
            "site_id": r.site_id,
            "site_name": names.get(r.site_id),
            "device_name": r.device_name,
            "device_type": r.device_type,
            "policy_id": r.policy_id,
            "vdom": r.vdom,
            "policy_name": r.policy_name,
            "src_zone": r.src_zone,
            "dst_zone": r.dst_zone,
            "src": r.src,
            "dst": r.dst,
            "protocol": r.protocol,
            "dst_port": r.dst_port,
            "action": r.action,
            "enabled": r.enabled,
            "rule_order": r.rule_order,
            "firewall_device_id": r.firewall_device_id,
            "firewall_id": r.firewall_id,
            "owner": r.owner,
            "last_matched": r.last_matched,
            "source_file": r.source_file,
        }
        for r in rules
    ]


# ------------------------------------------------- firewall rule shadowing --

@router.get("/firewall-rules/shadowed")
def get_shadowed_firewall_rules(
    device_name: str | None = None,
    firewall_device_id: int | None = None,
    include_partial: bool = True,
    generate_findings: bool = False,
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
    request: Request = None,
):
    """
    Identify firewall rules that are shadowed (fully or partially) by
    an earlier rule on the same device — i.e. rules that can never fire
    (full shadow / duplicate) or whose intent is silently overridden for
    a subset of traffic (partial shadow, action-conflicting overlap).

    Rules are sorted by rule_order ASC (lower = higher priority, first
    evaluated).  The comparison uses the same address/port parsing logic
    as the diff engine.

    **shadow_type values**

    | Value           | Meaning |
    |-----------------|---------|
    | `full_shadow`   | Rule B can never fire — earlier rule A matches a strict superset |
    | `duplicate`     | A and B match identical traffic AND have the same action |
    | `partial_shadow`| A overlaps B and has a conflicting action (some traffic silently re-governed) |

    **Query parameters**

    - `device_name` — scope to one device (by name)
    - `firewall_device_id` — scope to one FirewallDevice row (precise)
    - `include_partial` — include action-conflicting partial shadows (default true)
    - `generate_findings` — write Finding rows for each shadow found (SR 7.6)

    **Limitations**

    Rules whose `src`, `dst`, or `dst_port` contain unresolvable named
    objects (PAN-OS address groups not expanded, etc.) are returned in
    `unanalysed_rules` and excluded from the shadow check rather than
    flagged as false positives.
    """
    from app.parsers.rule_shadow import find_shadowed_rules

    site_row = _operation_site(db, site, site_id)
    if firewall_device_id is not None:
        dev = db.get(FirewallDevice, firewall_device_id)
        if dev is None or dev.site_id != site_row.id:
            raise HTTPException(status_code=404, detail=(
                f"firewall_device_id={firewall_device_id} not found in site {site_row.name!r}"))
    if generate_findings:
        # C-17: writing findings from a GET - do it on a write-capable
        # session (BEGIN IMMEDIATE) so it cannot hit SQLITE_BUSY_SNAPSHOT.
        with _write_session(request) as wdb:
            try:
                result = find_shadowed_rules(
                    db=wdb, device_name=device_name, firewall_device_id=firewall_device_id,
                    include_partial=include_partial, generate_findings=True, site_id=site_row.id)
                wdb.commit()
            except Exception:
                wdb.rollback()
                raise
    else:
        result = find_shadowed_rules(
            db=db,
            device_name=device_name,
            firewall_device_id=firewall_device_id,
            include_partial=include_partial,
            generate_findings=False,
            site_id=site_row.id,
        )
    if isinstance(result, dict):
        result = {**result, **_site_info(site_row)}
    return result


# --------------------------------------------------------- firewall zones --

@router.get("/firewall-zones")
def list_firewall_zones(
    device_name: str | None = None,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List FortiGate interface-to-zone mappings ingested from
    show full-configuration. Optionally filter by device_name.
    """
    query = db.query(FirewallZone)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(FirewallZone.site_id == site_id)
    if device_name:
        query = query.filter(FirewallZone.device_name == device_name)
    zones = query.order_by(FirewallZone.device_name, FirewallZone.interface_name).all()
    # the interface's config alias (FortiOS `set alias`), by (site, firewall name or
    # hostname, interface name) - display only, e.g. "vlan_20" -> "Process Control"
    aliases: dict = {}
    if zones:
        q = (db.query(FirewallInterface.name, FirewallInterface.alias, FirewallInterface.iface_type,
                      FirewallInterface.remote_access, Firewall.name, Firewall.device_name, Firewall.site_id)
             .join(Firewall, Firewall.id == FirewallInterface.firewall_id))
        if _check_site_filter(db, site_id) is not None:
            q = q.filter(Firewall.site_id == site_id)
        for iname, alias, itype, ra, fname, fdev, fsite in q:
            tk = _tunnel_kind(itype, ra, iname)
            if not alias and not tk:
                continue
            for dev in (fname, fdev):
                if dev:
                    aliases.setdefault((fsite, dev.lower(), (iname or "").lower()), (alias or None, tk))
    return [
        {
            "id": z.id,
            "site_id": z.site_id,
            "device_name": z.device_name,
            "interface_name": z.interface_name,
            "alias": (aliases.get((z.site_id, (z.device_name or "").lower(), (z.interface_name or "").lower())) or (None, None))[0],
            # VPN tunnel kind of the interface (SSL / dial-up IPsec / site-to-site IPsec / L2TP)
            "tunnel": (aliases.get((z.site_id, (z.device_name or "").lower(), (z.interface_name or "").lower())) or (None, None))[1],
            "zone_name": z.zone_name,
            "ip_cidr": z.ip_cidr,
            "vlan_id": z.vlan_id,
            "interface_type": z.interface_type,
        }
        for z in zones
    ]


# -------------------------------------------------------------- NAT rules --

_NAT_TYPES = ("dnat", "snat")


@router.get("/nat-rules")
def list_nat_rules(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    firewall_id: int | None = None,
    firewall_device_id: int | None = None,
    nat_type: str | None = Query(None, description="dnat | snat"),
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List address translations parsed from firewall configs (F-05, see
    app.models.NatRule): ``dnat`` = VIP / port-forward (traffic to
    ext_ip[:ext_port] goes to mapped_ip[:mapped_port]); ``snat`` = source NAT
    (sources matching orig_src leave as mapped_ip). Filter by firewall_id,
    firewall_device_id or nat_type; paged with limit/offset, total in
    X-Total-Count.  B-13: rows come in evaluation order per table (sequence,
    id) with ``sequence`` and ``nat_exempt`` (a `nat disable` entry: matching
    flows are not translated, no later entry is consulted).
    """
    from app.models import NatRule

    query = db.query(NatRule)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(NatRule.site_id == site_id)
    if nat_type is not None and nat_type != "":
        nt = nat_type.strip().lower()
        if nt not in _NAT_TYPES:
            raise HTTPException(status_code=422,
                                detail=f"nat_type must be one of {', '.join(_NAT_TYPES)}; got {nat_type!r}")
        query = query.filter(NatRule.nat_type == nt)
    if firewall_id is not None:
        query = query.filter(NatRule.firewall_id == firewall_id)
    if firewall_device_id is not None:
        query = query.filter(NatRule.firewall_device_id == firewall_device_id)

    # B-13: SNAT / DNAT are first-match in configured order - list each
    # table (firewall, type, VDOM) in evaluation order: (sequence, id), rows
    # without a sequence last (explicit, PostgreSQL / SQLite NULL order differ).
    rows = _page(query.order_by(NatRule.firewall_id.asc(), NatRule.nat_type.asc(),
                                NatRule.vdom.asc(),
                                NatRule.sequence.is_(None).asc(),
                                NatRule.sequence.asc(), NatRule.id.asc()),
                 response, limit, offset).all()
    return [
        {
            "id": n.id,
            "site_id": n.site_id,
            "firewall_id": n.firewall_id,
            "firewall_device_id": n.firewall_device_id,
            "device_name": n.device_name,
            "device_type": n.device_type,
            "nat_type": n.nat_type,
            "nat_kind": n.nat_kind,
            "vdom": n.vdom,
            "name": n.name,
            "policy_id": n.policy_id,
            "protocol": n.protocol,
            "src_intf": n.src_intf,
            "dst_intf": n.dst_intf,
            "orig_src": n.orig_src,
            "orig_dst": n.orig_dst,
            "ext_ip": n.ext_ip,
            "ext_port": n.ext_port,
            "mapped_ip": n.mapped_ip,
            "mapped_port": n.mapped_port,
            "enabled": n.enabled,
            "sequence": n.sequence,
            "nat_exempt": bool(n.nat_exempt),
            "source_file": n.source_file,
            "raw": n.raw,
        }
        for n in rows
    ]


# --------------------------------------------------------- firewall devices --

@router.get("/firewall-devices")
def list_firewall_devices(
    purdue_zone_from: str | None = _level_query(),
    purdue_zone_to: str | None = _level_query(),
    vendor: str | None = None,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List FirewallDevice records — the operator-friendly abstraction above
    individual FirewallRule rows that captures which Purdue zone boundary
    each physical firewall protects.

    Optionally filter by:
      ``?purdue_zone_from=4`` — only devices whose less-trusted side is level 4
      ``?purdue_zone_to=3``   — only devices whose more-trusted side is level 3
      ``?vendor=fortigate``   — vendor string (fortigate, cisco, pfsense, …)

    Each device includes its boundary (purdue_zone_from / purdue_zone_to),
    the linked Firewall row id (firewall_id), and the count of FirewallRules
    owned by this device.

    This is the companion endpoint to GET /topology's ``firewall_boundaries``
    field — the topology endpoint returns only boundary-tagged devices for
    swimlane rendering; this endpoint returns every FirewallDevice regardless
    of boundary tagging, for device management / audit UI.
    """
    from sqlalchemy import func as _func

    # Count rules per device in one aggregated query
    rule_counts = dict(
        db.query(FirewallRule.firewall_device_id, _func.count(FirewallRule.id))
        .filter(FirewallRule.firewall_device_id.isnot(None), FirewallRule.enabled.is_(True))
        .group_by(FirewallRule.firewall_device_id)
        .all()
    )
    disabled_counts = dict(
        db.query(FirewallRule.firewall_device_id, _func.count(FirewallRule.id))
        .filter(FirewallRule.firewall_device_id.isnot(None), FirewallRule.enabled.is_(False))
        .group_by(FirewallRule.firewall_device_id)
        .all()
    )

    # owner 2026-10-12: the card counts policy LINES (one per device / VDOM /
    # policy id / action / state, as the rules drill-down groups them), and the
    # VPN ones (a side is a tunnel interface of the firewall)
    tunnels: dict = {}
    for fid, iname, itype, ra in db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                                          FirewallInterface.iface_type, FirewallInterface.remote_access):
        if _tunnel_kind(itype, ra, iname):
            tunnels.setdefault(fid, set()).add(str(iname).strip().lower())
    pol_keys: dict = {}
    for rid, did, fid, vd, pid, act, en, sz, dz in db.query(
            FirewallRule.id, FirewallRule.firewall_device_id, FirewallRule.firewall_id, FirewallRule.vdom,
            FirewallRule.policy_id, FirewallRule.action, FirewallRule.enabled,
            FirewallRule.src_zone, FirewallRule.dst_zone).filter(FirewallRule.firewall_device_id.isnot(None)):
        key = (vd, pid, str(act or "").lower(), bool(en)) if pid not in (None, "") else ("row", rid)
        ent = pol_keys.setdefault(did, {}).setdefault(key, {"enabled": en is not False, "vpn": False})
        toks = {t.strip().lower() for t in f"{sz or ''},{dz or ''}".split(",") if t.strip()}
        if toks & tunnels.get(fid, set()):
            ent["vpn"] = True
    pol_counts = {did: (sum(1 for e in v.values() if e["enabled"]),
                        sum(1 for e in v.values() if not e["enabled"]),
                        sum(1 for e in v.values() if e["vpn"]))
                  for did, v in pol_keys.items()}

    purdue_zone_from = _level_param("purdue_zone_from", purdue_zone_from)
    purdue_zone_to = _level_param("purdue_zone_to", purdue_zone_to)
    query = db.query(FirewallDevice)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(FirewallDevice.site_id == site_id)
    if purdue_zone_from is not None:
        query = query.filter(FirewallDevice.purdue_zone_from == purdue_zone_from)
    if purdue_zone_to is not None:
        query = query.filter(FirewallDevice.purdue_zone_to == purdue_zone_to)
    if vendor:
        query = query.filter(FirewallDevice.vendor == vendor)

    devices = query.order_by(
        FirewallDevice.purdue_zone_from.asc().nulls_last(),
        FirewallDevice.name.asc(),
    ).all()

    names = site_names(db)
    return [
        {
            "id": dev.id,
            "site_id": dev.site_id,
            "site_name": names.get(dev.site_id),
            "name": dev.name,
            "vendor": dev.vendor,
            "device_hostname": dev.device_hostname,
            "mgmt_ip": dev.mgmt_ip,
            "firmware_version": dev.firmware_version,
            "source_file": dev.source_file,
            "purdue_zone_from": dev.purdue_zone_from,
            "purdue_zone_to": dev.purdue_zone_to,
            "boundary_tagged": (
                dev.purdue_zone_from is not None and dev.purdue_zone_to is not None
            ),
            "firewall_id": dev.firewall_id,
            "rule_count": rule_counts.get(dev.id, 0),
            "disabled_rule_count": disabled_counts.get(dev.id, 0),
            # grouped like the rules drill-down's "one line per policy"
            "policy_count": pol_counts.get(dev.id, (0, 0, 0))[0],
            "disabled_policy_count": pol_counts.get(dev.id, (0, 0, 0))[1],
            "vpn_policy_count": pol_counts.get(dev.id, (0, 0, 0))[2],
            "created_at": dev.created_at,
            "updated_at": dev.updated_at,
        }
        for dev in devices
    ]


@router.patch("/firewall-devices/{device_id}/boundary")
def set_firewall_device_boundary(
    device_id: int,
    purdue_zone_from: str | None = _level_query(),
    purdue_zone_to: str | None = _level_query(),
    db: DBSession = Depends(get_db),
):
    """
    Update the Purdue boundary tags on an existing FirewallDevice.

    Use this to tag a device after initial ingest, or to correct boundary
    values set during upload. Pass ``?purdue_zone_from=4&purdue_zone_to=3``
    to set the boundary (0–5, or 3.5 for the industrial DMZ:
    ``?purdue_zone_from=4&purdue_zone_to=3.5``).

    Pass only one value to update one side without changing the other.
    This is the preferred path when the operator wants to adjust boundary
    tags without re-uploading the config file.
    """
    levels = {f: _level_param(f, v) for f, v in
              (("purdue_zone_from", purdue_zone_from), ("purdue_zone_to", purdue_zone_to))}
    dev = db.get(FirewallDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail=f"FirewallDevice id={device_id} not found")

    for field, val in levels.items():
        if val is not None:
            setattr(dev, field, val)

    from datetime import datetime, timezone
    dev.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "updated": True,
        "id": dev.id,
        "name": dev.name,
        "purdue_zone_from": dev.purdue_zone_from,
        "purdue_zone_to": dev.purdue_zone_to,
    }


# ---------------------------------------------------------------- findings --

def _like_pattern(text: str) -> str:
    """A-28: '%text%' with LIKE wildcards escaped (use with escape='\\')."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _findings_text_filter(text: str):
    """N-12: portable case-insensitive substring match (LIKE with escaped
    wildcards; ilike -> lower() LIKE lower() on SQLite, ILIKE on PostgreSQL)
    over the human-visible finding fields."""
    from sqlalchemy import or_
    pat = _like_pattern(text)
    return or_(*[col.ilike(pat, escape="\\") for col in (
        Finding.title, Finding.check_name, Finding.device_name,
        Finding.isa62443_sr, Finding.checklist_id,
    )])


_INCLUDE_EXCLUDED_DOC = ("also the findings of checks the site left out of the compliance report "
                         "(Reports page, /reports/check-selection) - hidden everywhere by default; "
                         "rows carry excluded_from_report")


def _rc_hide(db, query, site_id, include_excluded=False):
    from app import report_checks as rc
    return rc.hide_excluded(db, query, site_id, include_excluded)


_TARGET_SL_DESC = (
    "Target security level (1-4, or SL2 / SL-T2): keep findings whose ISA/IEC 62443-3-3 "
    "requirement applies at that level or below (SR/RE SL-C from 62443-3-3 Annex B; the "
    "finding's level is the lowest of its SRs).  Findings with no 62443-3-3 SR are kept.")
_FR_DESC = "Foundational requirement: FR1-FR7 (or 1-7, IAC/UC/SI/DC/RDF/TRE/RA)"


def _sl_fr_params(target_sl, fr):
    """Validate ?target_sl= / ?fr= -> (int|None, "FRn"|None); 422 on bad input."""
    from app.security_levels import normalize_fr, normalize_sl
    try:
        return normalize_sl(target_sl), normalize_fr(fr)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _apply_sl_fr(query, target_sl, fr):
    """Filter a Finding query to target level / FR.  The level comes from the
    finding's own isa62443_sr text, so the distinct SR strings in scope are
    classified in Python and matched with IN (paging stays in SQL)."""
    if target_sl is None and fr is None:
        return query
    from sqlalchemy import false, or_
    from app.security_levels import matching_values
    values = [v for (v,) in query.with_entities(Finding.isa62443_sr).distinct().all()]
    # A string with no 62443-3-3 SR ("2-1 SPE 2") has no level: matches()
    # keeps it for a target level (it applies at every level), not for an FR.
    keep, nulls = matching_values(values, target_sl, fr)
    conds = [Finding.isa62443_sr.in_(keep)] if keep else []
    if nulls:
        conds += [Finding.isa62443_sr.is_(None), Finding.isa62443_sr == ""]
    return query.filter(or_(*conds)) if conds else query.filter(false())


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_order():
    """SQL sort key: critical, high, medium, low, info, then anything else."""
    from sqlalchemy import case, func
    return case(_SEVERITY_RANK, value=func.lower(Finding.severity), else_=5)


def _false_positive_last():
    """SF: false positives form their own section at the end of a list."""
    from sqlalchemy import case
    return case((Finding.status == "false_positive", 1), else_=0)


def _findings_order(sort: str | None):
    """ORDER BY for finding lists: ``severity`` (default) = severity rank,
    then newest first; ``newest`` = newest first.  False positives come
    last either way; id is the tie-break so pages are stable."""
    newest = (Finding.created_at.desc(), Finding.id.desc())
    return (_false_positive_last(), *newest) if sort == "newest" else (_false_positive_last(), _severity_order(), *newest)


_ZONE_SCOPE_DESC = (
    "Judge device findings against the SL-T of the IEC 62443 zone (or documented conduit) the "
    "device sits in: applies (the check's SL is at or below that SL-T, or it has no 62443-3-3 SR), "
    "beyond (its requirement first applies above that SL-T), no_sl_t (zone has no SL-T), "
    "no_zone (the device is in no zone, or the finding has no single device).  View-time only: "
    "findings and severities are unchanged.")


class _ZoneJudges:
    """FindingJudge per site, built on first use."""

    def __init__(self, db):
        self.db, self.by_site = db, {}

    def _get(self, site_id):
        from app.iec_zones import FindingJudge
        j = self.by_site.get(site_id)
        if j is None:
            j = self.by_site[site_id] = FindingJudge(self.db, site_id)
        return j

    def warm(self, query):
        """Build every site's judge (and its conduit / device view) before a
        streamed export, so no query runs while rows are being yielded."""
        for (sid,) in query.with_entities(Finding.site_id).distinct():
            if sid is not None:
                j = self._get(sid)
                if j.active:
                    j._device_targets()
        return self

    def __call__(self, f):
        if f.site_id is None:
            return None
        return self._get(f.site_id).judge(f.detail, f.device_name, f.isa62443_sr, f.check_name)


_CONDUIT_DOC_DESC = (
    "Zone documentation of a finding with two ends: intra_zone (both ends in one zone), documented "
    "(a conduit is documented between the two zones), undocumented (two zones, no conduit), partial "
    "(the other end is in no zone), external (the other end is outside the site).  View-time only.")
_CONDUIT_DOC_VALUES = ("intra_zone", "documented", "undocumented", "partial", "external")


def _conduit_doc_param(v):
    if v in (None, ""):
        return None
    if v not in _CONDUIT_DOC_VALUES:
        raise HTTPException(status_code=422, detail="conduit_doc must be one of " + ", ".join(_CONDUIT_DOC_VALUES))
    return v


def _judged(j, severity) -> dict:
    """zone_judgement plus the severity to show (option 3: one step lower on
    a documented conduit that covers the finding's service and source)."""
    from app.iec_zones import adjusted_severity
    adj = adjusted_severity(severity, j)
    return {"zone_judgement": j, "shown_severity": adj,
            "severity_adjustment": (j or {}).get("adjustment") if adj != (severity or "info").lower() else None}


def _zone_scope_param(zone_scope):
    if zone_scope in (None, ""):
        return None
    if zone_scope not in ("applies", "beyond", "no_sl_t", "no_zone"):
        raise HTTPException(status_code=422, detail="zone_scope must be applies, beyond, no_sl_t or no_zone")
    return zone_scope


def _apply_zone_scope(db, query, zone_scope, conduit_doc=None):
    """Filter a Finding query by zone judgement and / or documentation
    status.  The judgement is computed in Python (it needs the zone model)
    over the matching rows' evidence; paging stays in SQL via id IN (...)."""
    if zone_scope is None and conduit_doc is None:
        return query
    from sqlalchemy import false
    judge = _ZoneJudges(db)
    ids = []
    for f in query.with_entities(Finding.id, Finding.site_id, Finding.detail, Finding.device_name,
                                 Finding.isa62443_sr, Finding.check_name):
        j = judge(f)
        v = j["verdict"] if j else "no_zone"
        if zone_scope is not None and v != zone_scope:
            continue
        if conduit_doc is not None and (j or {}).get("documentation") != conduit_doc:
            continue
        ids.append(f.id)
    return query.filter(Finding.id.in_(ids)) if ids else query.filter(false())


def _sl_fields(sr_text) -> dict:
    from app.security_levels import frs, security_level
    return {"fr": frs(sr_text), "security_level": security_level(sr_text)}


@router.get("/findings")
def list_findings(
    response: Response,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    check_name: str | None = None,
    device_name: str | None = None,
    isa62443_sr: str | None = None,
    q: str | None = Query(None, max_length=200, description=(
        "Case-insensitive substring search over title, check_name, device_name, "
        "isa62443_sr and checklist_id; combines (AND) with the other filters (N-12)")),
    target_sl: str | None = Query(None, max_length=8, description=_TARGET_SL_DESC),
    fr: str | None = Query(None, max_length=8, description=_FR_DESC),
    zone_scope: str | None = Query(None, max_length=16, description=_ZONE_SCOPE_DESC),
    conduit_doc: str | None = Query(None, max_length=16, description=_CONDUIT_DOC_DESC),
    sort: str = Query("severity", pattern="^(severity|newest)$", description=(
        "severity (default): critical, high, medium, low, info, newest first within a "
        "severity; newest: newest first")),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    site_id: int | None = _site_filter_query(),
    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
    db: DBSession = Depends(get_db),
):
    """
    List findings from every check-producing source: config-level 62443
    checks (forti_config_parser.py), traffic-derived checks
    (traffic_findings.py), and the real-time/periodic alert engine
    (alert_engine.py) - one unified list, since all three write to the
    same Finding table. Filter by status (open/acknowledged/closed),
    severity (critical/high/medium/low/info), category (config_review/
    real_time/periodic_review - the coarse phase), check_name (the
    specific check, e.g. "it_ot_bypass" or "unauthorized_industrial_write"
    - see /findings/category-reference for the full list), device_name,
    isa62443_sr, target_sl (1-4: findings in scope at that ISA/IEC 62443
    target security level) or fr (FR1-FR7). Each row carries ``fr`` (the
    foundational requirements of its SRs) and ``security_level`` (the lowest
    SL at which one of its 62443-3-3 requirements applies; null = no 3-3 SR)
    and ``zone_judgement`` (null when the device is in no IEC 62443 zone):
    the zone(s) / conduit / firewall the finding's device resolves to, that
    SL-T and whether the check applies at it (``zone_scope`` filters on it),
    plus ``documentation`` for a finding with two ends: inside one zone, over
    a documented conduit, between two zones with no conduit, or with the
    other end in no zone / outside the site (``conduit_doc`` filters on it).
    Sorted by severity (critical, high, medium, low, info), newest first
    within a severity (``sort=newest``: newest first only; id as tie-break, so pages are
    stable), `limit` 1-5000 (default 200) starting at `offset`. The total
    number of matching findings is returned in the X-Total-Count header so
    UIs can page without re-fetching everything.
    """
    query = db.query(Finding)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(Finding.site_id == site_id)
    query = _rc_hide(db, query, site_id, include_excluded)
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if check_name:
        query = query.filter(Finding.check_name == check_name)
    if device_name:
        query = query.filter(Finding.device_name == device_name)
    if isa62443_sr:
        query = query.filter(Finding.isa62443_sr == isa62443_sr)
    if q and q.strip():
        query = query.filter(_findings_text_filter(q.strip()))
    query = _apply_sl_fr(query, *_sl_fr_params(target_sl, fr))
    query = _apply_zone_scope(db, query, _zone_scope_param(zone_scope), _conduit_doc_param(conduit_doc))

    response.headers["X-Total-Count"] = str(query.count())
    findings = (
        query.order_by(*_findings_order(sort))
        .offset(offset).limit(limit).all()
    )
    return _finding_rows(db, findings)


def _finding_rows(db: DBSession, findings) -> list:
    """The /findings row of each finding (also used by /findings/linked)."""
    from app import report_checks as rc
    names = site_names(db)
    judge = _ZoneJudges(db)
    excluded = rc.excluded_by_site(db)
    return [
        {
            "id": f.id,
            "excluded_from_report": f.check_name in excluded.get(f.site_id, ()),
            "site_id": f.site_id,
            "site_name": names.get(f.site_id),
            "created_at": f.created_at,
            "category": f.category,
            "check_name": f.check_name,
            "severity": f.severity,
            "status": f.status,
            "isa62443_sr": f.isa62443_sr,
            **_sl_fields(f.isa62443_sr),
            "checklist_id": f.checklist_id,
            "title": f.title,
            "detail": f.detail,
            "device_name": f.device_name,
            "acknowledged_by": f.acknowledged_by,
            "acknowledged_at": f.acknowledged_at,
            "closed_at": f.closed_at,
            "false_positive_reason": f.false_positive_reason,
            "false_positive_by": f.false_positive_by,
            "false_positive_at": f.false_positive_at,
            "notes": f.notes,
            "last_seen": f.last_seen,                 # F-04: last re-detection
            "occurrence_count": f.occurrence_count,   # F-04: times detected
            "updated_at": getattr(f, "updated_at", None),
            **_judged(judge(f), f.severity),
        }
        for f in findings
    ]


_REPORT_DETAIL_FIELDS = ("client_name", "project_name", "author", "author_email", "version", "classification", "constraints")


def _report_details_dict(row, site_row) -> dict:
    """The report details with their defaults (owner 2026-10-18)."""
    d = {"site_id": site_row.id, "site": site_row.name, "client_name": None, "project_name": None, "author": None,
         "author_email": None, "version": "1.0", "classification": "Confidential Security Data (CSD)",
         "distribution": [], "revisions": [], "constraints": None, "updated_by": None, "updated_at": None, "stored": row is not None}
    if row is not None:
        for k in _REPORT_DETAIL_FIELDS:
            v = getattr(row, k)
            if v not in (None, ""):
                d[k] = v
        d["distribution"] = list(row.distribution or [])
        d["revisions"] = list(row.revisions or [])
        d["updated_by"], d["updated_at"] = row.updated_by, row.updated_at
    return d


@router.get("/reports/details")
def get_report_details(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """Owner 2026-10-18: the site's report details (cover, distribution list,
    revision history, constraints) with their defaults when nothing is stored."""
    from app.models import ReportDetails
    site_row = _operation_site(db, site, site_id)
    row = db.query(ReportDetails).filter(ReportDetails.site_id == site_row.id).one_or_none()
    return _report_details_dict(row, site_row)


@router.put("/reports/details")
def put_report_details(
    client_name: str | None = Body(None, max_length=200), project_name: str | None = Body(None, max_length=200),
    author: str | None = Body(None, max_length=128), author_email: str | None = Body(None, max_length=200),
    version: str | None = Body(None, max_length=32), classification: str | None = Body(None, max_length=128),
    distribution: list | None = Body(None, description="[{name, role, email, side: client | assessor}]"),
    revisions: list | None = Body(None, description="[{version, date, status}]"),
    constraints: str | None = Body(None, max_length=4000), by: str | None = Body(None, max_length=128),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Store the site's report details (every field replaces the stored one)."""
    from app.models import ReportDetails
    site_row = _operation_site(db, site, site_id)

    import re as _re

    def _clean(v, limit=200):
        """Scalars only, control characters removed, trimmed (audit 2026-10-18)."""
        if v is None or isinstance(v, (dict, list, tuple, bool)):
            return ""
        return _re.sub(r"[\x00-\x1f\x7f]", " ", str(v)).strip()[:limit]

    def _rows(items, keys, limit=50):
        out = []
        for it in (items or []):
            if not isinstance(it, dict):
                continue
            row = {k: _clean(it.get(k)) for k in keys}
            if "side" in keys:
                row["side"] = "assessor" if row.get("side") == "assessor" else "client"
            if any(v for k, v in row.items() if k != "side"):
                out.append(row)
            if len(out) >= limit:
                break
        return out
    row = db.query(ReportDetails).filter(ReportDetails.site_id == site_row.id).one_or_none()
    if row is None:
        row = ReportDetails(site_id=site_row.id)
        db.add(row)
    for k, v in (("client_name", client_name), ("project_name", project_name), ("author", author), ("author_email", author_email),
                 ("version", version), ("classification", classification), ("constraints", constraints)):
        setattr(row, k, _clean(v, 4000 if k == "constraints" else 200) or None)
    dist = _rows(distribution, ("name", "role", "email", "side"), limit=200)
    row.distribution = ([x for x in dist if x["side"] == "client"][:50] + [x for x in dist if x["side"] == "assessor"][:50])
    row.revisions = _rows(revisions, ("version", "date", "status"))
    row.updated_by = _clean(by, 128) or None
    db.commit()
    db.refresh(row)
    return _report_details_dict(row, site_row)


@router.get("/reports/check-selection")
def get_report_check_selection(site_id: int = Query(..., ge=1), db: DBSession = Depends(get_db)):
    """Every check, grouped (FortiGate configuration (CIS), rule reviews, ...), with
    whether it is in the site's compliance report, the reason it is not, and the
    site's open + acknowledged findings of it (owner 2026-10-14)."""
    from app import report_checks as rc
    _check_site_filter(db, site_id)
    return rc.selection(db, site_id)


@router.put("/reports/check-selection")
def set_report_check_selection(site_id: int = Query(..., ge=1),
                               exclude: list = Body([], description="[{check_name, reason?}] or names to leave out"),
                               include: list = Body([], description="check names to put back in the report"),
                               by: str | None = Body(None, max_length=128),
                               db: DBSession = Depends(get_db)):
    """Leave checks out of the site's compliance report (optional reason) or put
    them back.  The findings stay on the Findings page and in the exports; the PDF
    lists the excluded checks / groups."""
    from app import report_checks as rc
    _check_site_filter(db, site_id)
    try:
        stats = rc.apply(db, site_id, exclude, include, by=by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    db.commit()
    return {**stats, **rc.selection(db, site_id)}


@router.get("/findings/linked")
def linked_findings(site_id: int = Query(..., ge=1, description="site of the object"),
                    host_id: int | None = Query(None, ge=1, description="an asset: findings naming its address or MAC"),
                    ip: str | None = Query(None, max_length=64), mac: str | None = Query(None, max_length=32),
                    firewall_id: int | None = Query(None, ge=1), policy_id: str | None = Query(None, max_length=64),
                    zone_id: int | None = Query(None, ge=1), conduit_id: int | None = Query(None, ge=1),
                    include_closed: bool = Query(False, description="also closed findings and false positives"),
                    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
                    db: DBSession = Depends(get_db)):
    """Findings about one object, to edit them next to it (owner 2026-10-14):
    a host (``host_id``, or ``ip`` / ``mac``: every finding naming the address or
    MAC - a multi-homed device's other addresses share its MAC), a firewall
    policy (``firewall_id`` + ``policy_id``), an IEC 62443 zone (``zone_id``:
    findings naming the zone plus the findings of its hosts) or a conduit
    (``conduit_id``: findings naming both zones plus those of its attached
    rules).  Open and acknowledged findings unless ``include_closed``.  Rows as
    /findings.  View only."""
    from app import finding_links as fl
    from app.models import IecConduit, IecConduitRule, IecZone
    _check_site_filter(db, site_id)
    idx = fl.LinkIndex(db, site_id, include_closed=include_closed, include_excluded=include_excluded)
    if host_id is not None:
        h = db.query(Host).filter(Host.id == host_id, Host.site_id == site_id).first()
        if h is None:
            raise HTTPException(status_code=404, detail="Host not found in this site")
        ids, what = idx.for_host(h.ip, h.mac), {"host_id": h.id, "ip": h.ip, "mac": h.mac}
    elif ip or mac:
        ids, what = idx.for_host(ip, mac), {"ip": ip, "mac": mac}
    elif firewall_id is not None and policy_id:
        ids, what = idx.for_policy(firewall_id, policy_id), {"firewall_id": firewall_id, "policy_id": policy_id}
    elif zone_id is not None:
        z = db.query(IecZone).filter(IecZone.id == zone_id, IecZone.site_id == site_id).first()
        if z is None:
            raise HTTPException(status_code=404, detail="Zone not found in this site")
        from app import iec_zones as iz
        hosts = db.query(Host).filter(Host.site_id == site_id, real_host_clause()).all()
        zidx = iz.host_zone_index(db, hosts)
        members = [h for h in hosts if any(x["id"] == z.id for x in zidx.get(h.id, []))]
        ids, what = idx.for_zone(z.name, members), {"zone_id": z.id, "zone": z.name}
    elif conduit_id is not None:
        c = db.query(IecConduit).filter(IecConduit.id == conduit_id, IecConduit.site_id == site_id).first()
        if c is None:
            raise HTTPException(status_code=404, detail="Conduit not found in this site")
        za, zb = db.get(IecZone, c.zone_a_id), db.get(IecZone, c.zone_b_id)
        pols = []
        for r in db.query(IecConduitRule).filter(IecConduitRule.conduit_id == c.id):
            fid = idx.fw_by_name.get((r.firewall_name or "").lower())
            if fid is not None:
                pols.append((fid, r.policy_id))
        ids = idx.for_conduit(za.name if za else "", zb.name if zb else "", pols)
        what = {"conduit_id": c.id, "zones": [za.name if za else None, zb.name if zb else None]}
    else:
        raise HTTPException(status_code=422, detail="give host_id, ip / mac, firewall_id + policy_id, zone_id or conduit_id")
    found = idx.rows(ids)
    return {"object": what, "summary": idx.summary(ids), "findings": _finding_rows(db, found)}


@router.get("/findings/link-counts")
def finding_link_counts(site_id: int = Query(..., ge=1), db: DBSession = Depends(get_db)):
    """Open + acknowledged findings per object of a site, for list badges:
    ``hosts`` (host id), ``policies`` ("firewall_id|policy_id"), ``zones`` and
    ``conduits`` (id) -> {count, open, max_severity}.  View only."""
    from app import finding_links as fl
    _check_site_filter(db, site_id)
    return {"site_id": site_id, **fl.link_counts(db, site_id)}


@router.get("/findings/summary")
def findings_summary(site_id: int | None = _site_filter_query(),
                     target_sl: str | None = Query(None, max_length=8, description=_TARGET_SL_DESC),
                     fr: str | None = Query(None, max_length=8, description=_FR_DESC),
                     include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
                     db: DBSession = Depends(get_db)):
    """
    Count of open findings by category, check_name, and severity.
    Intended for a dashboard widget / header badge - the Finding-based
    equivalent of what the now-removed /alerts/summary provided for the
    old Alert model.
    """
    # Use SQL GROUP BY aggregates rather than loading all Finding rows
    # into Python memory. On a busy deployment open findings can number
    # in the thousands; loading every row just to count them is wasteful.
    from sqlalchemy import func as _func

    _check_site_filter(db, site_id)
    sl_t, fr_v = _sl_fr_params(target_sl, fr)
    scoped = db.query(Finding)
    if site_id is not None:
        scoped = scoped.filter(Finding.site_id == site_id)
    scoped = _rc_hide(db, scoped, site_id, include_excluded)
    scoped = _apply_sl_fr(scoped, sl_t, fr_v)
    base = scoped.filter(Finding.status == "open")

    total_open = base.with_entities(_func.count()).scalar() or 0

    by_severity = {
        sev: cnt
        for sev, cnt in base.with_entities(Finding.severity, _func.count())
                             .group_by(Finding.severity).all()
        if sev
    }
    by_category = {
        cat: cnt
        for cat, cnt in base.with_entities(Finding.category, _func.count())
                             .group_by(Finding.category).all()
        if cat
    }
    by_check_name = {
        cn: cnt
        for cn, cnt in base.with_entities(Finding.check_name, _func.count())
                            .group_by(Finding.check_name).all()
        if cn
    }

    # All-status counts (open / acknowledged / closed) for lifecycle badges.
    by_status = {
        st: cnt
        for st, cnt in scoped.with_entities(Finding.status, _func.count())
                             .group_by(Finding.status).all()
        if st
    }

    # Multi-site: open findings per site.  Unfiltered: every site (a
    # dashboard can show every site's badge from one call); with site_id:
    # only that site (B-24 - a filtered summary never leaks other sites).
    names = site_names(db)
    if site_id is not None:
        names = {k: v for k, v in names.items() if k == site_id}
    open_q = db.query(Finding.site_id, _func.count()).filter(Finding.status == "open")
    if site_id is not None:
        open_q = open_q.filter(Finding.site_id == site_id)
    open_q = _rc_hide(db, open_q, site_id, include_excluded)
    open_q = _apply_sl_fr(open_q, sl_t, fr_v)
    open_by_site = dict(open_q.group_by(Finding.site_id).all())
    by_site = [{"site_id": sid, "site_name": nm, "open": open_by_site.get(sid, 0)}
               for sid, nm in sorted(names.items())]

    # Open findings per lowest security level / per FR (a finding with SRs
    # in two FRs counts in both), from the distinct SR strings.
    from app.security_levels import frs as _frs, security_level as _sl
    by_security_level: dict[str, int] = {}
    by_fr: dict[str, int] = {}
    for sr_txt, cnt in base.with_entities(Finding.isa62443_sr, _func.count()) \
                           .group_by(Finding.isa62443_sr).all():
        lvl = _sl(sr_txt)
        key = f"SL{lvl}" if lvl else "none"
        by_security_level[key] = by_security_level.get(key, 0) + cnt
        for f_ in _frs(sr_txt):
            by_fr[f_] = by_fr.get(f_, 0) + cnt

    return {
        "site_id": site_id,
        "target_sl": sl_t,
        "fr": fr_v,
        "by_security_level": by_security_level,
        "by_fr": by_fr,
        "by_site": by_site,
        "total_open": total_open,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_check_name": by_check_name,
        "by_status": by_status,
    }


def _parse_since(value: str, name: str = "since") -> datetime:
    try:
        return datetime.fromisoformat(value.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{name}' must be an ISO date or datetime")


def _until_filter(column, value: str, name: str = "until"):
    """Upper-bound filter for ``?until=``.  A date-only value (YYYY-MM-DD)
    means "through the end of that day" -> ``column < day + 1`` (T3-05);
    a datetime is an inclusive bound as before."""
    raw = value.strip()
    try:
        if len(raw) == 10:
            return column < datetime.combine(date.fromisoformat(raw) + timedelta(days=1),
                                             datetime.min.time())
        return column <= datetime.fromisoformat(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{name}' must be an ISO date or datetime")


def _detail_key_equals(db, key: str, value: str):
    """SQL predicate: Finding.detail[key], as text, == value (T3-04).

    Matches both int (5) and string ("5") stored values because the JSON
    value is compared as text on every dialect."""
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import JSONB
        from sqlalchemy import cast
        return cast(Finding.detail, JSONB)[key].astext == value
    if dialect == "sqlite":
        from sqlalchemy import String, cast, func
        return cast(func.json_extract(Finding.detail, f'$."{key}"'), String) == value
    return Finding.detail[key].as_string() == value


@router.get("/findings/export")
def export_findings_csv(
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    check_name: str | None = None,
    firewall_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    target_sl: str | None = Query(None, max_length=8, description=_TARGET_SL_DESC),
    fr: str | None = Query(None, max_length=8, description=_FR_DESC),
    zone_scope: str | None = Query(None, max_length=16, description=_ZONE_SCOPE_DESC),
    conduit_doc: str | None = Query(None, max_length=16, description=_CONDUIT_DOC_DESC),
    sort: str = Query("severity", pattern="^(severity|newest)$",
                      description="severity (default) or newest"),
    site_id: int | None = _site_filter_query(),
    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Export findings as a flat CSV — one row per finding, detail JSONB
    destructured into individual columns so the file is usable directly
    in Excel/Sheets without post-processing.

    **Query parameters** (all optional)

    - ``severity``   — comma-separated list: ``critical,high``
    - ``status``     — comma-separated list: ``open,acknowledged``
    - ``category``   — comma-separated list: ``config_review,periodic_review,real_time``
    - ``check_name`` — exact check_name string
    - ``firewall_id``— filter by ``firewall_id`` / ``fw_id`` in finding detail
      (matched in SQL as text, so ``5`` matches both stored 5 and "5")
    - ``since``      — ISO date/datetime, e.g. ``2026-09-01`` (inclusive)
    - ``until``      — ISO date/datetime, e.g. ``2026-09-30``; a date-only
      value includes that whole day
    - ``target_sl``  — 1-4: findings in scope at that target security level
    - ``fr``         — FR1-FR7
    - ``zone_scope`` — applies / beyond / no_sl_t / no_zone (judged against the
      device's IEC 62443 zone SL-T)
    - ``conduit_doc`` — intra_zone / documented / undocumented / partial / external
    - ``sort``       — ``severity`` (default: critical → info, newest first
      within a severity) or ``newest``.  False positives come last, as their
      own section, with ``false_positive_reason`` / ``_by`` / ``_at`` filled.

    The CSV is streamed in batches (rows are never all loaded at once).

    **Columns**

    finding_id, detected_at, status, severity, category, check_name,
    title, isa_sr, fr, security_level, checklist_id, false_positive_reason,
    false_positive_by, false_positive_at, firewall_name, firewall_id, policy_id,
    source_zone, dest_zone, src_ip, dst_ip, dst_port, protocol,
    purdue_src, purdue_dst, source_ref, resolved_at, acknowledged_by,
    acknowledged_at, notes, iec_zone, zone_sl_t, zone_verdict, zone_documentation
    (the device's IEC 62443 zone(s) / conduit, its SL-T, whether the check
    applies at it, and whether the path is inside one zone / over a documented
    conduit / between zones with no conduit)
    """
    import csv
    import io
    from sqlalchemy import or_

    query = db.query(Finding)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(Finding.site_id == site_id)
    query = _rc_hide(db, query, site_id, include_excluded)

    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        query = query.filter(Finding.status.in_(statuses))
    if severity:
        severities = [s.strip() for s in severity.split(",") if s.strip()]
        query = query.filter(Finding.severity.in_(severities))
    if category:
        categories = [c.strip() for c in category.split(",") if c.strip()]
        query = query.filter(Finding.category.in_(categories))
    if check_name:
        query = query.filter(Finding.check_name == check_name)
    if since:
        query = query.filter(Finding.created_at >= _parse_since(since))
    if until:
        query = query.filter(_until_filter(Finding.created_at, until))

    # firewall_id lives in the JSON detail column: filtered in SQL (T3-04),
    # not in Python after loading every row.
    if firewall_id is not None and firewall_id.strip() != "":
        fid = firewall_id.strip()
        query = query.filter(
            Finding.detail.isnot(None),
            or_(_detail_key_equals(db, "firewall_id", fid),
                _detail_key_equals(db, "fw_id", fid)),
        )
    query = _apply_sl_fr(query, *_sl_fr_params(target_sl, fr))
    query = _apply_zone_scope(db, query, _zone_scope_param(zone_scope), _conduit_doc_param(conduit_doc))

    judge = _ZoneJudges(db).warm(query)
    query = query.order_by(*_findings_order(sort))

    def _dt(val) -> str:
        if val is None:
            return ""
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    def _extract(detail: dict | None, *keys, default="") -> str:
        """Try each key in order, return the first non-empty value as a string
        (lists joined with ", "; nested objects are never dumped raw)."""
        if not detail:
            return default
        for k in keys:
            v = detail.get(k)
            if v is None or isinstance(v, dict):
                continue
            if isinstance(v, (list, tuple)):
                if not v or any(isinstance(x, (dict, list, tuple)) for x in v):
                    continue
                return ", ".join(str(x) for x in v)
            return str(v)
        return default

    def _path_side(d: dict, side: str, key: str) -> str:
        """Access-path style evidence (chain / dead-end / upward-skip
        findings): detail["path"][side][key]."""
        p = d.get("path")
        v = ((p or {}).get(side) or {}).get(key) if isinstance(p, dict) else None
        return "" if v is None else str(v)

    def _chain(d: dict) -> tuple[str, str]:
        """(firewalls, policies) of an access-path chain in hop order."""
        ch = d.get("chain")
        if not isinstance(ch, list) or not ch or not all(isinstance(x, dict) for x in ch):
            return "", ""
        fws = " + ".join(dict.fromkeys(str(x.get("firewall_name") or "?") for x in ch))
        pols = " + ".join(f"{x.get('firewall_name') or '?'}#{x.get('policy_id') if x.get('policy_id') is not None else '-'}"
                          for x in ch)
        return fws, pols

    names = site_names(db)
    _FIELDNAMES = [
        "finding_id", "site_name", "detected_at", "status", "severity", "category",
        "check_name", "title", "isa_sr", "fr", "security_level", "checklist_id",
        "false_positive_reason", "false_positive_by", "false_positive_at",
        "firewall_name", "firewall_id", "policy_id",
        "source_zone", "dest_zone",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "purdue_src", "purdue_dst",
        "source_ref",
        "resolved_at", "acknowledged_by", "acknowledged_at", "notes",
        "iec_zone", "zone_sl_t", "zone_verdict", "zone_documentation", "shown_severity", "severity_adjustment",
    ]

    def _row(f) -> dict:
        d = f.detail if isinstance(f.detail, dict) else {}
        chain_fws, chain_pols = _chain(d)
        return {
            "finding_id":      f.id,
            "site_name":       names.get(f.site_id, ""),
            "detected_at":     _dt(f.created_at),
            "status":          f.status or "",
            "severity":        f.severity or "",
            "category":        f.category or "",
            "check_name":      f.check_name or "",
            "title":           f.title or "",
            "isa_sr":          f.isa62443_sr or "",
            "fr":              " ".join(_sl_fields(f.isa62443_sr)["fr"]),
            "security_level":  (lambda v: f"SL{v}" if v else "")(_sl_fields(f.isa62443_sr)["security_level"]),
            "checklist_id":    f.checklist_id or "",
            "false_positive_reason": f.false_positive_reason or "",
            "false_positive_by": f.false_positive_by or "",
            "false_positive_at": _dt(f.false_positive_at),
            # Firewall context — detail keys vary by check type
            "firewall_name":   (_extract(d, "firewall_name", "device_name", "fw_name", "switch")
                                or chain_fws or (f.device_name or "")),
            "firewall_id":     _extract(d, "firewall_id", "fw_id"),
            "policy_id":       _extract(d, "policy_id", "vpn_policy_id", "rule_id") or chain_pols,
            "source_zone":     _extract(d, "src_zone", "source_zone", "zone") or _path_side(d, "src", "zone"),
            "dest_zone":       _extract(d, "dst_zone", "dest_zone") or _path_side(d, "dst", "zone"),
            "src_ip":          (_extract(d, "src_ip", "ip", "host_ip", "ot_host_ip")
                                or _path_side(d, "src", "scope")),
            "dst_ip":          _extract(d, "dst_ip", "dst", "dest_ip") or _path_side(d, "dst", "scope"),
            "dst_port":        _extract(d, "dst_port", "port"),
            "protocol":        _extract(d, "protocol", "service"),
            "purdue_src":      (_extract(d, "purdue_src", "src_level", "src_purdue_level")
                                or _path_side(d, "src", "level")),
            "purdue_dst":      (_extract(d, "purdue_dst", "dst_level", "dst_purdue_level")
                                or _path_side(d, "dst", "level")),
            "source_ref":      f.source_ref or "",
            "resolved_at":     _dt(f.closed_at),
            "acknowledged_by": f.acknowledged_by or "",
            "acknowledged_at": _dt(f.acknowledged_at),
            "notes":           f.notes or "",
            **_zone_cols(judge(f), f.severity),
        }

    def _zone_cols(j, severity) -> dict:
        jd = _judged(j, severity)
        extra = {"shown_severity": jd["shown_severity"], "severity_adjustment": jd["severity_adjustment"] or ""}
        if not j:
            return {"iec_zone": "", "zone_sl_t": "", "zone_verdict": "", "zone_documentation": "", **extra}
        where = j.get("conduit") or (f"{j['firewall']} (conduits: {', '.join(j['zones'])})" if j.get("firewall")
                                     else " ↔ ".join(j["zones"]))
        return {"iec_zone": where, "zone_sl_t": "" if j.get("zone_sl_t") is None else j.get("zone_sl_t"),
                "zone_verdict": j["verdict"].replace("_", " "),
                "zone_documentation": (j.get("documentation") or "").replace("_", " "), **extra}

    _BATCH = 500

    def _generate():
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_FIELDNAMES, extrasaction="ignore",
                                lineterminator="\r\n")
        writer.writeheader()
        # BOM for Excel auto-detection, then the header.
        yield "\ufeff".encode("utf-8") + buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate()
        n = 0
        for f in query.yield_per(_BATCH):
            writer.writerow(_csv_safe_row(_row(f)))
            n += 1
            if n % _BATCH == 0:
                yield buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate()
                # (the identity map holds rows weakly, so yielded batches
                # are released as soon as they are written)
        if buf.tell():
            yield buf.getvalue().encode("utf-8")

    filename = f"iasc_findings_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/firewalls/{firewall_id}/config")
def get_firewall_config(firewall_id: int, site_id: int = Query(..., ge=1),
                        download: bool = Query(False, description="return the text as a file"),
                        db: DBSession = Depends(get_db)):
    """The latest uploaded configuration text of a firewall (owner 2026-10-14),
    secrets masked (`***`) before it was stored: the metadata (filename, upload
    time, line count, how many values were masked) and the text; `download=true`
    returns it as a text file.  404 when the firewall is not in the site or no
    text is stored (configs uploaded before this release)."""
    from app import config_store as _cs
    _check_site_filter(db, site_id)
    fw = db.get(Firewall, firewall_id)
    if fw is None or fw.site_id != site_id:
        raise HTTPException(status_code=404, detail="Firewall not found in this site")
    row = _cs.get_config(db, firewall_id)
    if row is None:
        raise HTTPException(status_code=404, detail=(
            "No configuration text is stored for this firewall - upload its config again to keep it"))
    text = _cs.config_text(row)
    if download:
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", (row.filename or fw.device_name or fw.name or "firewall")) or "firewall"
        if not base.lower().endswith((".conf", ".txt", ".xml", ".cfg")):
            base += ".txt"
        data = text.encode("utf-8")
        return Response(content=data, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{base}"',
                                 "Content-Length": str(len(data))})
    return {**_cs.meta(row), "firewall_name": fw.name, "text": text}


@router.get("/firewalls/{firewall_id}/config/block")
def get_firewall_config_block(firewall_id: int, site_id: int = Query(..., ge=1),
                              key: str = Query(..., max_length=128, description="edit key: interface name, policy id, ..."),
                              section: str = Query("system interface", max_length=64, description="FortiOS config section"),
                              vdom: str | None = Query(None, max_length=64),
                              db: DBSession = Depends(get_db)):
    """One block of the stored configuration with its settings as a key / value
    table (owner 2026-10-14, FW Topology Builder *Settings from the config*).
    `section=system interface` is vendor-aware: FortiOS `edit "<name>"`, Cisco
    `interface <name>` (or the stanza whose `nameif` is the name, plus its
    `access-group` bindings), pfSense `<name>` under `<interfaces>`, PAN-OS
    `<entry name="<name>">`; other sections are FortiOS only. `available: false`
    with a `reason` when nothing is stored or the block is not in the config."""
    from app import config_store as _cs
    _check_site_filter(db, site_id)
    fw = db.get(Firewall, firewall_id)
    if fw is None or fw.site_id != site_id:
        raise HTTPException(status_code=404, detail="Firewall not found in this site")
    return _cs.config_block(db, fw, section, key, vdom)


@router.get("/findings/{finding_id}/config-snippet")
def finding_config_snippet(finding_id: int, db: DBSession = Depends(get_db)):
    """The stored configuration lines behind a finding (owner 2026-10-14): the
    policy / interface / admin / VIP / IPsec phase1 / service block named by
    the finding, else the section its check reads, else (Cisco, PAN-OS,
    pfSense) the rule's own line - with the firewall, file, upload time and
    1-based line numbers for *Open in config*.  `available: false` with a
    `reason` when the finding names no firewall, no text is stored, or the
    object is no longer in the stored config."""
    from app import config_store as _cs
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _cs.snippet_for_finding(db, f)


@router.get("/findings/export.xlsx")
def export_findings_xlsx(site_id: int = Query(..., ge=1),
                         include_closed: bool = Query(False, description="also closed findings"),
                         include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
                         db: DBSession = Depends(get_db)):
    """The findings workbook (owner 2026-10-14): one row per finding of the site -
    open, acknowledged and false positives (closed with include_closed; findings of
    checks left out of the report with include_excluded) - with the editable columns
    Status, Name, New note and False-positive reason, to review in Excel and import
    back with POST /findings/import.xlsx."""
    import io as _io
    from app import findings_workbook as fw
    _check_site_filter(db, site_id)
    data = fw.export_xlsx(db, site_id, include_closed=include_closed, include_excluded=include_excluded)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(_io.BytesIO(data),
                             media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f'attachment; filename="iasc_findings_{stamp}.xlsx"',
                                      "Content-Length": str(len(data))})


@router.post("/findings/import.xlsx")
async def import_findings_xlsx(site_id: int = Query(..., ge=1),
                               dry_run: bool = Query(True, description="preview: report the changes, write nothing"),
                               name: str | None = Query(None, max_length=128, description=(
                                   "name used for rows whose Name cell is empty")),
                               file: UploadFile = File(...),
                               db: DBSession = Depends(get_db)):
    """Apply an edited findings workbook: for every row whose Status, New note or
    False-positive reason differs from the finding, the Findings page's status rules
    are applied (a refusal is reported per row, the other rows go through).  Rows
    are matched on the Finding ID and must belong to the site.  ``dry_run`` (default)
    only reports."""
    from app import findings_workbook as fw
    _check_site_filter(db, site_id)
    data = await _read_limited(file, _MAX_TEXT_BYTES, "workbook")
    try:
        rows = fw.parse_xlsx(data)
    except Exception as exc:                              # noqa: BLE001 - not a workbook / wrong sheet
        raise HTTPException(status_code=422, detail=f"not a findings workbook: {exc}")
    stats = fw.apply_rows(db, site_id, rows, dry_run=dry_run, default_name=(name or "").strip() or None)
    return {"filename": file.filename, "site_id": site_id, **stats}


@router.get("/findings/export/summary")
def export_findings_summary_csv(
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    site_id: int | None = _site_filter_query(),
    include_excluded: bool = Query(False, description=_INCLUDE_EXCLUDED_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Export a pivot-style SR-section summary CSV — one row per ISA/IEC 62443
    checklist section, with finding counts broken out by severity.  Useful
    for management reports and gap-analysis presentations.

    **Query parameters** (all optional)

    - ``status``  — comma-separated status filter (default: ``open``)
    - ``since``   — ISO date lower bound on detected_at
    - ``until``   — ISO date upper bound on detected_at

    **Columns**

    checklist_id, isa_sr, critical, high, medium, low, info, total,
    worst_severity
    """
    import csv
    import io
    from sqlalchemy import func as _func

    query = db.query(Finding)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(Finding.site_id == site_id)
    query = _rc_hide(db, query, site_id, include_excluded)

    # Default to open findings only when no status filter is given
    statuses = (
        [s.strip() for s in status.split(",") if s.strip()]
        if status
        else ["open"]
    )
    query = query.filter(Finding.status.in_(statuses))

    if since:
        query = query.filter(Finding.created_at >= _parse_since(since))
    if until:
        query = query.filter(_until_filter(Finding.created_at, until))

    # Aggregate in SQL: one count per (checklist_id, isa62443_sr, severity)
    agg_rows = (
        query
        .with_entities(
            Finding.checklist_id,
            Finding.isa62443_sr,
            Finding.severity,
            _func.count().label("cnt"),
        )
        .group_by(Finding.checklist_id, Finding.isa62443_sr, Finding.severity)
        .order_by(Finding.checklist_id.asc())
        .all()
    )

    # Pivot into {checklist_id -> {severity -> count}} in Python
    _SEVERITIES = ["critical", "high", "medium", "low", "info"]
    _SEV_ORDER = {s: i for i, s in enumerate(_SEVERITIES)}

    pivot: dict[str, dict] = {}
    for checklist_id, isa_sr, severity, cnt in agg_rows:
        key = checklist_id or "unknown"
        if key not in pivot:
            pivot[key] = {
                "checklist_id": key,
                "isa_sr": isa_sr or "",
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            }
        if severity in _SEVERITIES:
            pivot[key][severity] += cnt
        # Prefer the most-specific SR label we've seen for this checklist row
        if isa_sr and len(isa_sr) > len(pivot[key]["isa_sr"]):
            pivot[key]["isa_sr"] = isa_sr

    # Sort rows by checklist_id (numeric where possible, string fallback)
    def _cl_sort_key(k: str):
        try:
            parts = [int(p) for p in k.split(".")]
            return (0, parts)
        except ValueError:
            return (1, [k])

    sorted_keys = sorted(pivot.keys(), key=_cl_sort_key)

    _FIELDNAMES = [
        "checklist_id", "isa_sr",
        "critical", "high", "medium", "low", "info",
        "total", "worst_severity",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_FIELDNAMES, extrasaction="ignore",
                            lineterminator="\r\n")
    writer.writeheader()

    for key in sorted_keys:
        row = pivot[key]
        total = sum(row[s] for s in _SEVERITIES)
        worst = next(
            (s for s in _SEVERITIES if row[s] > 0),
            "none",
        )
        writer.writerow(_csv_safe_row({**row, "total": total, "worst_severity": worst}))

    csv_bytes = output.getvalue().encode("utf-8-sig")

    filename = f"iasc_summary_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/findings/category-reference")
def findings_category_reference():
    """
    Reference table for the structured check_names produced by IACS_Monitor:
    every entry of CHECK_TYPE_REFERENCE (real-time, periodic-review, chain,
    access-path, switch and management checks) plus the cross-firewall and
    traffic-derived checks that build their Finding rows with inline
    metadata.  The exact counts change as checks are added; the list is
    the source of truth.

    The inline config_* check names from forti_config_parser.py are not
    included here because their SR/checklist metadata is embedded per-finding
    at generation time rather than in a static reference table.  Query
    GET /findings?category=config_review for the full config finding set.

    Use this endpoint to build a UI legend or filter picklist.
    """
    # Cross-FW and traffic checks are not in CHECK_TYPE_REFERENCE (they
    # construct Finding objects directly with inline SR metadata), so we
    # append them here to give callers a single complete reference.
    _SUPPLEMENTAL: dict[str, tuple] = {
        # (isa62443_sr, checklist_id, default_severity, category)
        "cross_fw_no_rules":          ("SR 5.1",      "5.1",  "high",     "config_review"),
        "cross_fw_missing_deny_all":  ("SR 5.1 RE1",  "5.1",  "high",     "config_review"),
        "cross_fw_any_any_permit":    ("SR 5.1 RE1",  "5.1",  "critical", "config_review"),
        "cross_fw_asymmetric_permit": ("SR 5.2",      "5.2",  "medium",   "config_review"),
        "cross_fw_same_permit_both_sides": ("SR 5.2", "5.2",  "info",     "config_review"),
        "unauthorized_industrial_write": ("SR 2.1, SR 3.5", "8.4", "critical", "periodic_review"),
    }
    from app.security_levels import frs, security_level
    rows = [
        {
            "check_name": k,
            "isa62443_sr": v[0],
            "checklist_id": v[1],
            "default_severity": v[2],
            "category": v[3],
            "fr": frs(v[0]),
            "security_level": security_level(v[0]),
        }
        for k, v in {**CHECK_TYPE_REFERENCE, **_SUPPLEMENTAL}.items()
    ]
    return rows


from app.models import FINDING_STATUSES as _FINDING_STATUSES   # open / acknowledged / closed / false_positive
_FP_REASON_MAX = 1024
_FINDING_NOTES_MAX = 2048        # Finding.notes String(2048)
_FINDING_ACK_BY_MAX = 128        # Finding.acknowledged_by String(128)


def _open_twin(db, finding: Finding):
    """Another OPEN finding holding ``finding``'s (site_id, source_ref) slot
    of the partial unique index ux_findings_site_source_ref_open, or None."""
    if not finding.source_ref:
        return None
    return (db.query(Finding)
            .filter(Finding.id != finding.id, Finding.status == "open",
                    Finding.source_ref == finding.source_ref,
                    Finding.site_id == finding.site_id)
            .order_by(Finding.id).first())


def _reopen_conflict(twin_id) -> HTTPException:
    return HTTPException(status_code=409, detail={
        "message": "cannot re-open: a recurrence of this finding is already open "
                   f"(finding id {twin_id}); update that finding instead",
        "open_finding_id": twin_id,
    })


@router.get("/findings/{finding_id}/explanation")
def finding_explanation(finding_id: int, db: DBSession = Depends(get_db)):
    """Why the finding was raised (app.explain): what was found (the
    finding's own analysis, key facts, the policy path with its NAT), why it
    is a risk, the IEC 62443 requirement and workbook row(s), why it has its
    severity, how to resolve it, how it closes, how to verify it by hand, and
    the remaining raw evidence.  404 for an unknown finding."""
    from app.explain import explain
    f = db.get(Finding, int(finding_id))
    if f is None:
        raise HTTPException(status_code=404, detail=f"finding {finding_id} not found")
    return {"finding_id": f.id, **explain(f)}


def apply_finding_status(db: DBSession, finding: Finding, status: str, notes: str | None = None,
                         acknowledged_by: str | None = None, reason: str | None = None) -> None:
    """The Findings page's status rules, applied to ``finding`` in place (the caller
    commits): a false positive needs a reason, acknowledging needs a name, re-opening
    a finding whose recurrence is open is refused (409), notes are appended with a
    stamp, never overwritten.  Raises HTTPException on a refusal.  Shared by
    PATCH /findings/{id}/status and the findings workbook import (owner 2026-10-14)."""
    if status not in _FINDING_STATUSES:
        raise HTTPException(status_code=422, detail="status must be one of: " + ", ".join(_FINDING_STATUSES))
    ack_by = (acknowledged_by or "").strip() or None
    fp_reason = (reason or "").strip() or None
    if status == "false_positive" and fp_reason is None and not finding.false_positive_reason:
        raise HTTPException(status_code=422,
                            detail="reason is required when marking a finding a false positive")
    if status == "acknowledged" and ack_by is None and not (
            finding.status == "acknowledged" and finding.acknowledged_by):
        raise HTTPException(status_code=422,
                            detail="acknowledged_by is required when acknowledging a finding")

    if status == "open" and finding.status != "open":
        twin = _open_twin(db, finding)
        if twin is not None:
            raise _reopen_conflict(twin.id)

    now = datetime.now(timezone.utc)
    prev_status = finding.status
    finding.status = status
    finding.updated_at = now
    if notes:
        # C-20: append, never overwrite - the notes column is the audit
        # trail (auto-resolve / escalation / Access Review entries live there)
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        who = ack_by or "operator"
        entry = f"[{stamp} {who} -> {status}] {notes.strip()}"
        prior = (finding.notes or "").strip()
        if prior and prior != entry:
            joined = f"{prior} | {entry}"
            if len(joined) > _FINDING_NOTES_MAX:          # keep the newest text whole
                joined = "… " + joined[-(_FINDING_NOTES_MAX - 2):]
            finding.notes = joined
        else:
            finding.notes = entry[:_FINDING_NOTES_MAX]
    if status == "false_positive":
        finding.closed_at = None
        if fp_reason is not None:
            finding.false_positive_reason = fp_reason
        finding.false_positive_by = ack_by or finding.false_positive_by or "operator"
        finding.false_positive_at = now
    elif prev_status == "false_positive":
        # leaving the false-positive state drops its record; the notes keep
        # the audit trail
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = f"[{stamp} {ack_by or 'operator'} -> {status}] was a false positive: {finding.false_positive_reason}"
        prior = (finding.notes or "").strip()
        finding.notes = (f"{prior} | {entry}" if prior else entry)[-_FINDING_NOTES_MAX:]
        finding.false_positive_reason = None
        finding.false_positive_by = None
        finding.false_positive_at = None
    if status == "false_positive":
        pass
    elif status == "open":
        finding.acknowledged_by = None
        finding.acknowledged_at = None
        finding.closed_at = None
    elif status == "acknowledged":
        finding.closed_at = None
        if ack_by is not None and (ack_by != finding.acknowledged_by
                                   or finding.acknowledged_at is None):
            finding.acknowledged_by = ack_by
            finding.acknowledged_at = now
    else:  # closed
        finding.closed_at = now



@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    status: str,
    notes: str | None = Query(None, max_length=_FINDING_NOTES_MAX),
    acknowledged_by: str | None = Query(None, max_length=_FINDING_ACK_BY_MAX),
    reason: str | None = Query(None, max_length=_FP_REASON_MAX, description=(
        "false_positive: why the finding is wrong (required); recorded with the operator "
        "(acknowledged_by) and the time, and listed in the false-positive section of the "
        "CSV export and the PDF report")),
    db: DBSession = Depends(get_db),
):
    """
    Transition a finding status: open → acknowledged → closed, or
    false_positive (SF: the operator judged the condition wrong; ``reason``
    required).  A false positive is never raised again as a new finding -
    a persisting condition updates it silently - and is reported in its own
    section of the exports.  Findings are never deleted - status changes are
    the audit trail.

    B-16: ``status`` must be open / acknowledged / closed (422 otherwise);
    acknowledging needs a non-empty ``acknowledged_by`` (unless the finding
    is already acknowledged by someone); ``notes`` ≤ 2048 chars.  Moving a
    finding to ``open`` clears acknowledged_by / acknowledged_at /
    closed_at; ``closed_at`` is set only on close.  Re-opening a finding
    whose recurrence is already open returns 409 naming that finding's id
    (``open_finding_id``).
    """
    if status not in _FINDING_STATUSES:
        raise HTTPException(
            status_code=422,
            detail="status must be one of: " + ", ".join(_FINDING_STATUSES),
        )
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    apply_finding_status(db, finding, status, notes=notes, acknowledged_by=acknowledged_by, reason=reason)
    try:
        db.commit()
    except IntegrityError:
        # A concurrent writer opened a recurrence between the check and the
        # commit (partial unique index on (site_id, source_ref) WHERE open).
        db.rollback()
        finding = db.get(Finding, finding_id)
        twin = _open_twin(db, finding) if finding is not None else None
        if twin is not None:
            raise _reopen_conflict(twin.id)
        raise
    return {
        "id": finding.id,
        "status": finding.status,
        "updated_at": finding.updated_at,
        "false_positive_reason": finding.false_positive_reason,
        "false_positive_by": finding.false_positive_by,
        "false_positive_at": finding.false_positive_at,
    }


@router.post("/findings/scan-industrial-writes")
def scan_industrial_writes(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                           site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                           db: DBSession = Depends(get_db)):
    """
    Re-run checklist 8.4 ("Industrial write/program operations only
    from authorized hosts") over all already-ingested pcap data, without
    re-uploading a capture. Useful after loading or updating
    ApprovedHost baseline data (/ingest/baseline/approved-hosts) - a
    write flagged before the baseline existed won't automatically
    un-flag itself (findings are never deleted, by design - see
    Finding's docstring), but re-running after the baseline is loaded
    means any *new* pcap ingests will correctly recognize those hosts.

    Safe to call repeatedly - deduplicates via Finding.source_ref, so
    re-scanning the same data twice doesn't create duplicate findings.

    If no ApprovedHost baseline exists yet for engineering_ws/hmi roles,
    every industrial write in the dataset will be flagged (fail-open by
    design - see check_unauthorized_industrial_writes' docstring).
    """
    site_row = _operation_site(db, site, site_id)
    out = check_unauthorized_industrial_writes(db, site_id=site_row.id)
    return {**out, **_site_info(site_row)} if isinstance(out, dict) else out


# ---------------------------------------------------------- reachability ---

@router.get("/reachability")
def get_reachability_matrix(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    src_level: Optional[str] = _level_query(),
    dst_level: Optional[str] = _level_query(),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Compute the cross-level reachability matrix of ONE site (its firewall
    devices and hosts only; ``site``/``site_id`` required when several
    sites exist).

    Walks every FirewallDevice boundary and evaluates whether traffic can
    traverse from one Purdue level to another.  Returns a matrix of all
    level pairs with an enforcement point between them.

    **overall values per cell**

    | Value       | Meaning |
    |-------------|---------|
    | `permitted` | At least one path exists where all boundary devices permit the traffic |
    | `denied`    | All paths are blocked by at least one deny rule |
    | `unknown`   | Some enforcement points have unresolvable rules — result indeterminate |
    | `no_policy` | No FirewallDevice exists on any path between these two levels |

    **Several firewalls on one boundary.** Boxes declared in series — a
    paired firewall group, a confirmed upstream chain, or a confirmed
    inside↔outside link — must all permit the traffic.  Boxes with no such
    relation are alternatives (parallel cell firewalls, for instance): one
    permitting is enough.  Each enforcement point in the response carries
    ``arrangement`` (single / series / parallel / mixed) and its
    ``alternatives`` with the basis of every series relation; each hop of a
    host query carries ``placement`` when a box whose labelled interface
    networks hold neither address was left out of the decision.

    **Firewalls not in the model.** ``unplaced_firewalls`` lists every
    firewall that carries rules but built no enforcement point (no interface
    Purdue levels and no boundary, or only one level labelled).  Nothing is
    evaluated through them: a cell or path crossing where they sit is
    ``no_policy`` (no path at all) or ``unknown`` (a path that relies on an
    inferred unfirewalled hop - its ``inferred_hop_note`` says why and the
    ``path`` string prints the hop as ``~ L2 (inferred, no firewall)``).
    Inferred hops are only ever drawn between levels that have hosts, a
    boundary or a labelled interface.

    **Traffic filter parameters** (all optional)

    When `src_ip` / `dst_ip` are provided the rule evaluation narrows to
    that specific IP pair rather than generic any-to-any.  The `dst_port`
    and `protocol` parameters (e.g. `protocol=tcp`) further narrow matching.

    **Level filter parameters** (all optional)

    `src_level` and `dst_level` restrict the matrix to paths originating
    from and/or terminating at the specified Purdue levels (0–5, or 3.5 =
    industrial DMZ).  When both are provided only the single
    `"<src>→<dst>"` cell is returned.  When only one is provided, all paths
    from/to that level are returned.  Any other value returns HTTP 422.

    **Examples**

    - `GET /reachability?src_level=4&dst_level=2` — all paths L4 → L2
    - `GET /reachability?src_level=3` — every destination reachable from L3
    - `GET /reachability?src_level=4&dst_level=2&dst_port=502&protocol=tcp`

    **Enforcement points** are listed separately so the caller can see which
    firewall devices guard which boundaries, and how many rules each has.
    """
    from app.parsers.reachability import compute_reachability

    src_level = _level_param("src_level", src_level)
    dst_level = _level_param("dst_level", dst_level)
    site_row = _operation_site(db, site, site_id)

    out = compute_reachability(
        db=db,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        src_level=src_level,
        dst_level=dst_level,
        site_id=site_row.id,
    )
    return {**out, **_site_info(site_row)} if isinstance(out, dict) else out


@router.get("/reachability/path")
def get_reachability_path(
    src: str,
    dst: Optional[str] = None,
    dst_level: Optional[str] = _level_query(),
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Trace (within ONE site) the hop-by-hop policy path for traffic from a specific source
    IP (`src`) to a destination IP (`dst`) or Purdue level (`dst_level`).

    At least one of `dst` or `dst_level` must be provided.

    Returns the per-firewall permit/deny decision at each boundary on the
    shortest path, including which rule was the first match and why.

    **overall values**

    | Value          | Meaning |
    |----------------|---------|
    | `permitted`    | All enforcement points on the path permit the traffic |
    | `denied`       | At least one enforcement point denies the traffic (shows which rule) |
    | `unknown`      | An enforcement point has unresolvable rules |
    | `no_policy`    | No FirewallDevice exists on the path between these levels |
    | `intra_level`  | Same Purdue level and no firewall leg between the two hosts: not evaluated |

    Same level, two legs of ONE firewall (two L3 subnets on port2 / port3):
    the crossing IS evaluated - the result is permitted / partial / denied
    with one hop ``[3↔3 FW port2→port3]`` and ``same_level_crossing``
    naming the firewall, ingress and egress interface (MP-16).

    Several level paths: the result is the most permissive one (an upper
    bound); ``paths_evaluated``, ``alternatives`` (every path with its
    verdict and firewalls) and ``path_note`` say so, and among equally
    permissive paths the one whose firewalls hold the queried addresses is
    shown (MP-17).

    **Examples**

    - `GET /reachability/path?src=192.168.1.10&dst=10.0.3.5`
    - `GET /reachability/path?src=192.168.1.10&dst_level=2&dst_port=502&protocol=tcp`
    """
    from app.parsers.reachability import compute_path

    dst_level = _level_param("dst_level", dst_level)
    if not dst and dst_level is None:
        raise HTTPException(
            status_code=400,
            detail="At least one of 'dst' (destination IP) or 'dst_level' must be provided",
        )

    site_row = _operation_site(db, site, site_id)
    out = compute_path(
        db=db,
        src_ip=src,
        dst_ip=dst,
        dst_level=dst_level,
        dst_port=dst_port,
        protocol=protocol,
        site_id=site_row.id,
    )
    return {**out, **_site_info(site_row)} if isinstance(out, dict) else out


_TRAFFIC_STATUSES = ("seen", "not_seen", "no_capture", "partial")


@router.get("/access-paths")
def get_access_paths(
    direction: str = Query("all", description="all | down | up (vertical direction filter)"),
    boundary_only: bool = Query(True, description="Only cross-Purdue-level paths (default); "
                                                  "False also lists intra-zone / same-level permits"),
    flagged_only: bool = Query(False, description="Only rows carrying at least one flag"),
    traffic: Optional[str] = Query(None, description="seen | not_seen | no_capture | partial "
                                                     "(traffic overlay status filter)"),
    classification: Optional[str] = Query(None, description="unclassified | permissive | "
                                          "it_ot_bypass | reviewed_ok | exception"),
    report_include: Optional[bool] = Query(None, description="Only rows whose effective "
                                           "report_include is this value"),
    include_unmatched: bool = Query(True, description="Also list observed crossing flows "
                                                      "that no permitted path explains"),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Every permitted communication path of ONE site (docs/access-path-review.md,
    "API"), with the traffic overlay and the operator's classification tags.

    Row (path / composed / intra-zone)::

        {tag_key, src: {level, zone, scope}, dst: {...}, service: [str],
         protocol: [str], direction: down|up|composed|same,
         chain: [{rule_id, firewall_id, firewall_device_id, firewall_name, vdom,
                  policy_id, policy_name, action}],
         flags: [str], initiation: {level, zone, initiates},
         traffic: {status: seen|not_seen|no_capture|partial, sessions, last_seen,
                   rule_hits, rule_hits_since, last_matched,
                   capture_window?: {first, last}, by_leg? (composed)},
         classification, note, classified_by, classified_at,
         report_include, report_include_default,
         pivot?: {ip, level}, legs?: [...] (composed)}

    `unmatched_observed` entries carry the same tag fields.  Envelope:
    `paths`, `truncated`, `capture_window`, `counts` {total, by_direction,
    by_flag, by_traffic, by_classification, report_include,
    report_include_by_kind {path, composed, unexplained}, orphaned,
    unmatched_total}, `orphaned_tags`, `orphaned_incomplete`, and (with
    `include_unmatched`) `unmatched_observed`, `unmatched_total`,
    `unmatched_sessions`, `unmatched_capped`, `unmatched_incomplete`.

    Filters (`flagged_only`, `traffic`, `classification`, `report_include`)
    narrow `paths`; counts describe the returned rows, except
    `report_include` / `report_include_by_kind`: the number of lines the
    compliance report prints for the site (report-included paths, composed
    conduits and unexplained flows), whatever the filters.  `site`/`site_id` are
    required when more than one site exists (422 otherwise, and when they
    disagree).
    """
    from app.models import ACCESS_PATH_CLASSIFICATIONS
    from app.parsers.access_paths import count_rows, enumerate_access_paths

    if direction not in ("all", "down", "up"):
        raise HTTPException(
            status_code=422,
            detail=f"direction must be 'all', 'down' or 'up'; got {direction!r}")
    if traffic not in (None, "") and traffic not in _TRAFFIC_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"traffic must be one of {', '.join(_TRAFFIC_STATUSES)}; got {traffic!r}")
    if classification not in (None, "") and classification not in ACCESS_PATH_CLASSIFICATIONS:
        raise HTTPException(
            status_code=422,
            detail=(f"classification must be one of {', '.join(ACCESS_PATH_CLASSIFICATIONS)}; "
                    f"got {classification!r}"))

    site_row = _operation_site(db, site, site_id)
    out = enumerate_access_paths(
        db, site_row.id, direction=direction, boundary_only=boundary_only,
        include_unmatched=include_unmatched)
    paths = out["paths"]
    if flagged_only:
        paths = [p for p in paths if p["flags"]]
    if traffic:
        paths = [p for p in paths if (p.get("traffic") or {}).get("status") == traffic]
    if classification:
        paths = [p for p in paths if p.get("classification") == classification]
    if report_include is not None:
        paths = [p for p in paths if bool(p.get("report_include")) is report_include]
    counts = count_rows(paths)
    # report_include = every line the report prints for the site (paths +
    # composed + unexplained), independent of the filters above
    counts.update(out["report_counts"])
    counts["orphaned"] = len(out["orphaned_tags"])
    resp = {"paths": paths, "truncated": out["truncated"], "counts": counts,
            "capture_window": out["capture_window"],
            "orphaned_tags": out["orphaned_tags"],
            "orphaned_incomplete": out["orphaned_incomplete"],
            "unlabelled_firewalls": out.get("unlabelled_firewalls") or [],   # D-11
            "unplaced_firewalls": out.get("unplaced_firewalls") or [],       # MP-03
            "paired_group_warnings": out.get("paired_group_warnings") or [],  # MP-04
            "label_conflicts": out.get("label_conflicts") or [],              # MP-12
            "composition_notes": out.get("composition_notes") or []}          # MP-21
    if include_unmatched:
        counts["unmatched_total"] = out.get("unmatched_total", 0)
        for k in ("unmatched_observed", "unmatched_total", "unmatched_sessions",
                  "unmatched_capped", "unmatched_incomplete"):
            resp[k] = out.get(k)
    return {**resp, **_site_info(site_row)}


@router.post("/access-paths/classify")
def classify_access_paths_route(
    items: list = Body(..., description="[{tag_key, classification?, report_include? "
                                        "(true|false|null = reset to default), note? "
                                        "(<=2000 chars), classified_by? (<=128)}], max 500"),
    site: str | int | None = Body(None, description=_OP_SITE_DOC),
    site_id: int | None = Body(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_write_db),
):
    """
    Bulk classify access-path rows of ONE site (docs/access-path-review.md,
    "API").  Every `tag_key` must belong to the site's current enumeration
    (paths, composed rows, intra-zone rows, unexplained flows); one unknown
    key - including a key of another site - returns 422 and nothing is
    stored.  Upserts the `access_path_tag` rows, commits, then calls
    `access_path_findings.sync_findings_for_tags(db, site_id, tag_keys)`.

    An omitted field is left unchanged; `report_include: null` resets it to
    the row's default.  Returns `{items: [rows in the GET shape, request
    order], counts: {report_include, report_include_by_kind} (after the
    update), site_id, site, findings_sync}`.
    """
    from app.parsers import access_path_findings
    from app.parsers.access_paths import ClassifyError, classify_access_paths

    site_row = _operation_site(db, None if site is None else str(site), site_id)
    try:
        res = classify_access_paths(db, site_row.id, items)
    except ClassifyError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc))
    db.commit()
    try:
        sync = access_path_findings.sync_findings_for_tags(db, site_row.id, res["tag_keys"])
    except Exception:  # tags are committed; findings sync must not undo the request
        logging.getLogger(__name__).exception("access-path findings sync failed")
        db.rollback()
        sync = {"error": "findings sync failed; see the server log"}
    return {"items": res["items"], "counts": res["report_counts"], **_site_info(site_row),
            "findings_sync": sync}


# ------------------------------------------- declared hops (gateway -> jumpbox) --

def _hop_http_error(exc):
    return HTTPException(status_code=getattr(exc, "status", 422), detail=str(exc))


@router.get("/access-paths/hops")
def list_access_path_hops(
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Declared segment hops of ONE site plus suggestions.

    A hop says "host A reaches host B inside one segment" (typically a
    remote-access gateway -> the DMZ jumpbox).  No firewall sees that step, so
    Access Review joins the paths ending on A with the paths leaving B only
    when the operator declares it.  ``suggestions`` lists labelled gateway ->
    jump host pairs (same level / VLAN) that are not declared yet.
    """
    from app.parsers import remote_access as ra
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        return {"hops": ra.list_hops(db), "suggestions": ra.suggest_hops(db),
                **_site_info(site_row)}


@router.post("/access-paths/hops", status_code=201)
def create_access_path_hop(
    from_ip: str = Body(..., description="gateway / entry host (leg 1 ends here)"),
    to_ip: str = Body(..., description="jump host (leg 2 starts here)"),
    service: str | None = Body(None, description="e.g. 'tcp/22,tcp/3389'; omitted = any"),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    site: str | int | None = Body(None, description=_OP_SITE_DOC),
    site_id: int | None = Body(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_write_db),
):
    """Declare a hop.  422: bad address / service, unknown host, hosts on
    different Purdue levels.  409: already declared."""
    from app.parsers import remote_access as ra
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, None if site is None else str(site), site_id)
    try:
        with analysis_site(db, site_row.id):
            hop = ra.create_hop(db, site_row.id, from_ip=from_ip, to_ip=to_ip,
                                service=service, note=note, created_by=created_by)
            out = ra.hop_dict(hop)
        db.commit()
    except ra.HopError as exc:
        db.rollback()
        raise _hop_http_error(exc)
    return {**out, **_site_info(site_row)}


@router.delete("/access-paths/hops/{hop_id}")
def delete_access_path_hop(
    hop_id: int,
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_write_db),
):
    """Remove a declared hop (404 when it is not this site's).  Tags of rows
    that only existed through the hop show up as orphaned_tags."""
    from app.parsers import remote_access as ra
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    try:
        with analysis_site(db, site_row.id):
            ra.delete_hop(db, hop_id)
        db.commit()
    except ra.HopError as exc:
        db.rollback()
        raise _hop_http_error(exc)
    return {"deleted": hop_id, **_site_info(site_row)}


# ------------------------------------------------------------------ diff --

@router.get("/diff")
def get_topology_diff(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                      site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                      db: DBSession = Depends(get_db), request: Request = None):
    """
    Compare observed traffic (NetworkSession, from pcap/ARP) against
    configured firewall permit rules (FirewallRule). Surfaces:

      - unexpected_traffic: observed sessions with no matching permit
        rule - a misconfiguration, a stale/removed rule, or traffic
        covered by a rule this parser couldn't resolve (see
        unresolvable_rules).
      - unused_rules: permit rules never matched by any observed
        session in this dataset - candidates for firewall cleanup,
        though "not seen in this capture" isn't the same as "never
        used ever".
      - unresolvable_rules: rules referencing a named object (pfSense
        alias, unresolved PAN-OS service/address object) this parser
        can't expand - excluded from the two lists above rather than
        guessed at either way.

    Requires both FirewallRule data (from /ingest/firewall) and
    NetworkSession data (from /ingest/pcap or, for host-only sessions,
    /ingest/arp) to already be ingested - this only reads existing data,
    it doesn't ingest anything itself.
    """
    site_row = _operation_site(db, site, site_id)
    # C-17: the diff stamps FirewallRule.last_matched, so it runs on a
    # write-capable session (BEGIN IMMEDIATE on SQLite) and never fails with
    # SQLITE_BUSY_SNAPSHOT under a concurrent writer.
    with _write_session(request) as wdb:
        out = compute_diff(wdb, site_id=site_row.id)
    return {**out, **_site_info(site_row)} if isinstance(out, dict) else out


# -------------------------------------------------------------- topology --

_TOPO_HOST_MAX = 20_000
_TOPO_SESSION_MAX = 50_000


_PORT_NAMES = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
               69: "TFTP", 80: "HTTP", 102: "S7comm", 110: "POP3", 123: "NTP", 135: "MS-RPC",
               137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 389: "LDAP",
               443: "HTTPS", 445: "SMB", 502: "Modbus", 514: "Syslog", 1433: "MS SQL", 1883: "MQTT",
               2404: "IEC 104", 3389: "RDP", 4840: "OPC UA", 5900: "VNC", 8883: "MQTT/TLS",
               20000: "DNP3", 34962: "PROFINET", 34963: "PROFINET", 34964: "PROFINET", 44818: "EtherNet/IP",
               47808: "BACnet"}


_DECODED_NAMES = {"s7comm": "S7comm", "modbus": "Modbus", "profinet": "PROFINET", "smb1": "SMBv1",
                  "smb2_3": "SMB", "dnp3": "DNP3", "ethernet_ip": "EtherNet/IP", "opcua": "OPC UA",
                  "bacnet": "BACnet", "iec104": "IEC 104"}


def _protocol_label(protocol, port) -> str:
    """Readable protocol of a session: the decoded protocol, else the
    well-known service of its port, else tcp/udp:port."""
    p = str(protocol or "").strip()
    if p and p.lower() not in ("unknown", "other", "tcp", "udp"):
        return _DECODED_NAMES.get(p.lower(), p)
    return _PORT_NAMES.get(port) or (f"port {port}" if port is not None else (p or "unknown"))


@router.get("/topology/ports")
def get_port_topology(site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                      site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                      db: DBSession = Depends(get_db)):
    """Firewall Ports (owner 2026-10-17): every firewall / routing switch of the
    site as its front - physical ports in config order (aggregates as one port
    naming their members, from the stored config), per port the untagged subnet
    and the VLAN sub-interfaces with network, FortiOS zone, Purdue label /
    declaration, alias, host count and status - and `links`: the services the
    enabled permit rules allow between two interfaces (protocol/port, with a
    kind: cleartext, mgmt, cleartext-mgmt, any, icmp, ok; the policy numbers;
    how many captured sessions used them).  View only."""
    from app.parsers import port_topology as pt
    sid = _operation_site(db, site, site_id).id
    return pt.build(db, sid)


@router.get("/topology/subnets")
def get_subnet_topology(site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """Network Topology (owner 2026-10-16): the site's hosts in lanes by subnet /
    VLAN - firewall / routing-switch interface networks first, then capture
    segments, switch VLANs and inferred /24s (public addresses are egress
    destinations, not lane hosts) - each host with
    its function (device type group), per-lane function counts and a *mixed*
    flag, and `separators`: for every pair of lanes with observed sessions what
    sits between them - a firewall (policies between the two interfaces / zones),
    a routing switch, the same layer-2 segment (flat), or nothing known - and
    `egress`: the destinations outside the site.  View only."""
    from app.parsers import subnet_topology as st
    sid = _operation_site(db, site, site_id).id
    return st.build(db, sid)


@router.get("/topology")
def get_topology(
    response: Response,
    host_limit: int = Query(5_000, ge=1, le=_TOPO_HOST_MAX),
    session_limit: int = Query(10_000, ge=1, le=_TOPO_SESSION_MAX),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Graph-shaped view of the network for the UI: nodes = hosts (with
    Purdue-model device_type/purdue_level for grouping into level-based
    swimlanes), edges = sessions carrying protocol/port as edge attributes.

    Also returns ``firewall_boundaries``: a list of FirewallDevice records
    that have Purdue zone boundary tags (purdue_zone_from / purdue_zone_to).
    The UI swimlane renderer uses this list to draw labelled boundary
    annotations between the correct level lanes — for example, a device
    with purdue_zone_from=4 / purdue_zone_to=3 gets a label drawn across
    the boundary between the Level-4 and Level-3 swimlanes.

    Devices without boundary tags are omitted from ``firewall_boundaries``
    (they appear in ``GET /firewall-devices`` if needed).

    ``host_limit`` (1-20 000, default 5 000) and ``session_limit``
    (1-50 000, default 10 000) cap the rows returned.  Only edges whose
    BOTH endpoints are in the returned node set are emitted (T3-03), so the
    graph never references a missing node.  ``truncated`` / ``hosts_total``
    / ``sessions_total`` (also X-Hosts-Total / X-Sessions-Total headers) tell
    the UI when the caps cut something off.
    """
    from sqlalchemy import select

    # Phase 2: the graph is per site (required when several sites exist):
    # only that site's hosts, the sessions between them, and the site's
    # firewall boundaries.
    site_id = _operation_site(db, site, site_id).id
    host_q = db.query(Host).filter(real_host_clause())        # B-14: never the group marker
    host_sel = select(Host.id).where(real_host_clause())
    if site_id is not None:
        host_q = host_q.filter(Host.site_id == site_id)
        host_sel = host_sel.where(Host.site_id == site_id)
    hosts_total = host_q.count()
    hosts = host_q.order_by(Host.id.asc()).limit(host_limit).all()

    session_q = db.query(NetworkSession)
    if hosts_total > len(hosts) or site_id is not None:
        kept = host_sel.order_by(Host.id.asc()).limit(host_limit).scalar_subquery()
        session_q = session_q.filter(
            NetworkSession.src_host_id.in_(kept),
            NetworkSession.dst_host_id.in_(kept),
        )
    sessions_total = session_q.count()
    sessions = session_q.order_by(NetworkSession.id.asc()).limit(session_limit).all()
    node_ids = {h.id for h in hosts}
    sessions = [s for s in sessions if s.src_host_id in node_ids and s.dst_host_id in node_ids]

    # Lane display: the capture segment of each address (subnets on one
    # layer-2 segment share a label), public addresses flagged external,
    # readable type labels.
    from app.parsers.segments import capture_networks
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, site_id):
        cap_nets = [(n, dom) for n, _cid, _gws, dom in capture_networks(db)]
        from app.parsers.subnet_zones import _declared_for, declarations
        _zone_of = _declared_for(declarations(db))
        from app.parsers.external_comms import external_fn as _ext_fn, names_by_ip as _names_by_ip
        _names = _names_by_ip(db)
        _outside = _ext_fn(db)

    def _segment_of(ip):
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return None
        for n, dom in cap_nets:
            if a.version == n.version and a in n:
                return dom
        return None

    def _external(ip):
        # G5: the same test as the External comms view - outside every known
        # site network (a VoIP trunk peer in 198.51.100.0/24 is outside even
        # though it is not "global"); public addresses always are.
        try:
            return ipaddress.ip_address(str(ip)).is_global or _outside(ip)
        except ValueError:
            return False

    nodes = [
        {
            "id": h.id,
            "site_id": h.site_id,
            "label": h.ip or h.mac,
            "ip": h.ip,
            "mac": h.mac,
            "vendor": h.vendor,
            "device_type": h.device_type,
            "inventory_excluded": bool(h.inventory_excluded),   # owner 2026-10-14: topology mark only
            "device_label": (DEVICE_TYPE_REFERENCE[h.device_type][1].split(" (")[0]
                             if h.device_type in DEVICE_TYPE_REFERENCE else None),
            "purdue_level": h.purdue_level,
            "classification_source": h.classification_source,
            "vlan": h.vlan,
            "vlan_source": h.vlan_source,
            "segment": _segment_of(h.ip) if h.ip else None,
            "external": bool(h.ip) and _external(h.ip),
            "name": (_names[h.ip][0][0] if h.ip in _names else None),      # G5: name the capture showed
            # RS G3: the operator's zone for the host's subnet
            "zone": ({"cidr": str(z[0]), "name": z[1].zone_name, "purdue_level": z[1].purdue_level}
                     if h.ip and (z := _zone_of(h.ip)) else None),
        }
        for h in hosts
    ]
    edges = [
        {
            "id": s.id,
            "source": s.src_host_id,
            "target": s.dst_host_id,
            "protocol": s.protocol,
            "protocol_label": _protocol_label(s.protocol, s.dst_port),
            "dst_port": s.dst_port,
            "packet_count": s.packet_count,
        }
        for s in sessions
    ]

    # Firewall boundaries for swimlane rendering — only devices with both
    # zone columns set are meaningful for the boundary annotation layer.
    fw_dev_q = db.query(FirewallDevice)
    if site_id is not None:
        fw_dev_q = fw_dev_q.filter(FirewallDevice.site_id == site_id)
    fw_devices_with_boundary = (
        fw_dev_q
        .filter(
            FirewallDevice.purdue_zone_from.isnot(None),
            FirewallDevice.purdue_zone_to.isnot(None),
        )
        .order_by(FirewallDevice.purdue_zone_from.asc(), FirewallDevice.name.asc())
        .all()
    )
    firewall_boundaries = [
        {
            "id": dev.id,
            "name": dev.name,
            "vendor": dev.vendor,
            "purdue_zone_from": dev.purdue_zone_from,
            "purdue_zone_to": dev.purdue_zone_to,
            # Canonical (lo, hi) pair - easier for the UI to render lane lines
            "zone_lo": min(dev.purdue_zone_from, dev.purdue_zone_to),
            "zone_hi": max(dev.purdue_zone_from, dev.purdue_zone_to),
            "firewall_id": dev.firewall_id,
            "device_hostname": dev.device_hostname,
            "mgmt_ip": dev.mgmt_ip,
        }
        for dev in fw_devices_with_boundary
    ]

    # N-10: additive keys - node hostname, and per-edge server-side
    # classification (same / adjacent / skips_level / unclassified) plus
    # crosses_firewall (a firewall boundary sits between the two levels).
    from app.parsers.topology_manager import classify_level_edge, firewall_level_boundaries
    _host_by_id = {h.id: h for h in hosts}
    for _n in nodes:
        _n["hostname"] = _host_by_id[_n["id"]].hostname
    _fw_bounds = firewall_level_boundaries(db, site_id=site_id)
    for _e in edges:
        _e.update(classify_level_edge(_host_by_id[_e["source"]].purdue_level,
                                      _host_by_id[_e["target"]].purdue_level, _fw_bounds))

    if hosts_total > len(hosts):
        all_q = db.query(NetworkSession)
        if site_id is not None:
            in_site = select(Host.id).where(Host.site_id == site_id).scalar_subquery()
            all_q = all_q.filter(NetworkSession.src_host_id.in_(in_site),
                                 NetworkSession.dst_host_id.in_(in_site))
        all_sessions = all_q.count()
    else:
        all_sessions = sessions_total
    response.headers["X-Hosts-Total"] = str(hosts_total)
    response.headers["X-Sessions-Total"] = str(all_sessions)
    return {
        "site_id": site_id,
        "site": site_names(db).get(site_id),
        "nodes": nodes,
        "edges": edges,
        "firewall_boundaries": firewall_boundaries,
        "hosts_total": hosts_total,
        "sessions_total": all_sessions,
        "truncated": hosts_total > len(hosts) or all_sessions > len(edges),
    }


# ========================================================= FORTIANA INGEST ==
#
# Multi-site phase 3: log uploads carry no site - every line is routed to the
# site of the device that emitted it (app/site_devices.py).  Unknown devices
# are held in unmapped_log_events (no checks run) until mapped
# (POST /site-devices replays them).  ``?site=`` maps UNKNOWN devices of the
# upload to that site; it never overrides an existing mapping.

_LOG_SITE_DOC = ("Optional. Map log lines from UNKNOWN devices in this upload to this site "
                 "(id, name or code): the devices are registered there (source=manual) and "
                 "their lines routed to it. Never overrides an existing mapping and never "
                 "guesses: lines of a device registered to ANOTHER site are held as "
                 "'site_mismatch' conflicts (counted in site_conflicts) until resolved on "
                 "GET/POST /site-devices/conflicts. Lines without any device identity go to "
                 "this site too. Without it, lines of unknown devices are held in the unmapped "
                 "queue (GET /site-devices/unmapped).")


def _log_site_query():
    return Query(None, description=_LOG_SITE_DOC)


def _log_map_site(db, site) -> Site | None:
    if site is None or (isinstance(site, str) and not site.strip()):
        return None
    return _require_site(db, site)


def _replay_new_mappings(db, router) -> dict:
    """Replay held lines of devices the upload's ``?site=`` just mapped."""
    total = {"lines": 0, "events_created": 0, "findings_created": 0}
    for dev in router.new_devices:
        r = replay_pending(db, dev, evaluate=evaluate_event)
        for k in total:
            total[k] += r.get(k, 0)
    return total


def _routing_out(router, replay: dict) -> dict:
    out = router.summary()
    out["replayed"] = replay
    return out


@router.post("/ingest/forti-event")
async def ingest_fortiana_event(
    payload: dict = Body(...),
    db: DBSession = Depends(get_db),
    device_name: str | None = None,
    site: str | None = _log_site_query(),
):
    """
    Receive a single event from FortiAnalyzer as a JSON POST.
    FortiAnalyzer can call this via a custom event handler connector
    script or webhook. Field names should match FortiGate log reference
    (devname, devid, type, subtype, srcip, dstip, srcport, dstport, action,
    policyid, app, user, etc.). Returns the Finding IDs created, if any.

    The event is stored in the site its device (devid / devname) is
    registered to; an unknown device's event is held (``status:
    "unmapped"``) unless ``?site=`` maps it; a serial / site conflict is
    held for an operator decision (``status: "conflict"``, B-11).

    Pass ``?device_name=<label>`` to override or supply the device name
    when the payload does not include a ``devname`` field (useful in
    multi-firewall environments where each FortiGate posts to its own
    webhook URL and the device identity is known from the URL routing
    rather than the payload itself).
    """
    import json as _json

    def _work():
        map_site = _log_map_site(db, site)
        rt = LogRouter(db, ROUTE_FORTI_EVENT, map_site=map_site, fallback_device=device_name, evaluate=evaluate_event)
        fields = parse_item(ROUTE_FORTI_EVENT, _json.dumps(payload or {}, sort_keys=True,
                                                            default=str, ensure_ascii=False))
        raw_line = fields["raw_message"]
        status, ev = rt.handle(fields, raw_line)
        if status != "created":
            replay = _replay_new_mappings(db, rt)
            db.commit()
            return {
                "event_id": ev.id if ev is not None else None,
                "device_name": ev.device_name if ev is not None else device_name,
                "site_id": ev.site_id if ev is not None else None,
                "findings_created": 0,
                "finding_ids": [],
                "duplicate": status == "duplicate",
                "unmapped": status.startswith("unmapped"),
                "conflict": status.startswith("conflict"),   # B-11: held for a decision
                "status": status,
                "escalations": 0,
                "rule_hits_updated": 0,
                "routing": _routing_out(rt, replay),
            }
        findings = [f for f in evaluate_event(ev, db) if f]
        rule_hits_updated = record_rule_hits_per_site(db, [ev])  # F-10
        replay = _replay_new_mappings(db, rt)
        db.commit()
        return {
            "event_id": ev.id,
            "device_name": ev.device_name,
            "site_id": ev.site_id,
            "findings_created": len(findings),
            "finding_ids": [f.id for f in findings],
            "duplicate": False,
            "unmapped": False,
            "conflict": False,
            "status": "created",
            "rule_hits_updated": rule_hits_updated,
            # N-02: open findings escalated (higher severity) by this event
            "escalations": _ae_escalation_count(db),
            "routing": _routing_out(rt, replay),
        }

    return await run_in_threadpool(_work)


def _route_log_lines(db, rt, lines, source_route, vendor_hint=None, on_event=None) -> dict:
    """Shared per-line loop of /ingest/forti-syslog and /ingest/syslog."""
    stats = {"lines": 0, "events_created": 0, "findings_created": 0,
             "parse_failures": 0, "duplicates_skipped": 0, "unmapped": 0, "conflicts": 0}
    all_findings = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        stats["lines"] += 1
        fields = parse_item(source_route, line, vendor_hint=vendor_hint)
        if not fields:
            stats["parse_failures"] += 1
            continue
        status, ev = rt.handle(fields, line)
        if status == "created" and ev is not None:
            stats["events_created"] += 1
            if on_event:
                on_event(ev, "events_created")
            all_findings.extend(f for f in evaluate_event(ev, db) if f)
        elif status == "duplicate":
            # Re-uploaded line already stored (T3-06): not re-evaluated,
            # not counted as a parse failure.
            stats["duplicates_skipped"] += 1
            if on_event and ev is not None:
                on_event(ev, "duplicates_skipped")
        elif status.startswith("conflict"):
            stats["conflicts"] += 1       # B-11: held for an operator decision
        else:
            stats["unmapped"] += 1
    replay = _replay_new_mappings(db, rt)
    stats["rule_hits_updated"] = record_rule_hits_per_site(db, rt.created)  # F-10
    db.commit()
    stats["findings_created"] = len(all_findings)
    stats["finding_ids"] = [f.id for f in all_findings]
    stats["escalations"] = _ae_escalation_count(db)  # N-02
    stats["routing"] = _routing_out(rt, replay)
    return stats


@router.post("/ingest/forti-syslog")
async def ingest_fortiana_syslog(
    file: UploadFile = File(...),
    db: DBSession = Depends(get_db),
    device_name: str | None = None,
    site: str | None = _log_site_query(),
):
    """
    Upload a syslog/CEF log file exported from FortiAnalyzer or directly
    from a FortiGate (one log line per line). Accepts both CEF format and
    FortiGate native key=value format. Each line is stored in the site of
    its device (devid / devname, see /site-devices) and the real-time
    checks run there; lines of unknown devices are held (``unmapped``)
    unless ``?site=`` maps them.  ``stats.routing`` summarises the routing.

    Pass ``?device_name=<label>`` to supply a fallback device name for
    events whose log lines do not contain ``devname=`` /
    ``deviceExternalId``. Useful when:
    - Uploading a log file from one specific FortiGate in a multi-firewall
      environment where log lines may be missing the device field.
    - Some FortiGate firmware versions omit ``devname`` from forward
      traffic logs.

    When ``device_name`` is supplied it is used only as a fallback: if a
    log line already contains a ``devname`` / ``deviceExternalId`` value
    that value is kept and ``device_name`` is ignored for that line.
    """
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Syslog file", content="text")
    text = _decode_text_upload(raw)
    filename = file.filename

    def _work():
        rt = LogRouter(db, ROUTE_FORTI_SYSLOG, map_site=_log_map_site(db, site),
                       upload_ref=filename, fallback_device=device_name, evaluate=evaluate_event)
        return _route_log_lines(db, rt, text.splitlines(), ROUTE_FORTI_SYSLOG)

    stats = await run_in_threadpool(_work)
    return {"filename": filename, "device_name": device_name, "stats": stats}


@router.post("/ingest/syslog")
async def ingest_syslog_multi_vendor(
    file: UploadFile = File(...),
    db: DBSession = Depends(get_db),
    vendor_hint: str = Query("auto", description="fortinet | cisco_asa | pfsense | panos | auto"),
    device_name: str | None = None,
    site: str | None = _log_site_query(),
):
    """
    F-11: upload a syslog file from FortiGate (CEF / key=value), Cisco
    ASA/FTD, pfSense/OPNsense (filterlog) or PAN-OS (CSV). The vendor is
    auto-detected per line unless ``vendor_hint`` restricts parsing to one
    vendor. Behaves like /ingest/forti-syslog: each line is routed to the
    site of its device (syslog hostname / devname / serial), unknown
    devices are held unless ``?site=`` maps them, duplicate lines (same
    dedup_hash) are skipped, created events run the real-time checks, and
    FirewallRule.last_matched is updated from traffic events (F-10).

    ``device_name`` is a fallback for lines without a hostname / devname.
    """
    try:
        hint = normalise_vendor_hint(vendor_hint)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="vendor_hint must be one of fortinet, cisco_asa, pfsense, panos, auto",
        )
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Syslog file", content="text")
    text = _decode_text_upload(raw)
    filename = file.filename

    def _work():
        rt = LogRouter(db, ROUTE_SYSLOG, map_site=_log_map_site(db, site),
                       upload_ref=filename, fallback_device=device_name, evaluate=evaluate_event)
        by_vendor: dict = {}

        def _bump(ev, key):
            per = by_vendor.setdefault(
                _event_vendor(ev), {"events_created": 0, "duplicates_skipped": 0})
            per[key] += 1

        stats = _route_log_lines(db, rt, text.splitlines(), ROUTE_SYSLOG,
                                 vendor_hint=hint, on_event=_bump)
        stats["by_vendor"] = by_vendor
        return stats

    stats = await run_in_threadpool(_work)
    return {"filename": filename, "device_name": device_name,
            "vendor_hint": hint or "auto", "stats": stats}


@router.post("/ingest/forti-report")
@_reviews_after_upload('FortiAnalyzer report')
async def ingest_fortiana_report(
    file: UploadFile = File(...),
    db: DBSession = Depends(get_db),
    site: str | None = _log_site_query(),
):
    """
    Upload a FortiAnalyzer scheduled CSV report. Parses the traffic/
    event/IPS dataset rows, stores each row in the site of its device
    (devid / device column; unknown devices are held unless ``?site=``
    maps them) and runs the real-time checks. Use for bulk import of the
    19 FortiAnalyzer datasets from the workbook review.
    """
    from app.parsers.forti_parser import _parse_csv_rows
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "FortiAnalyzer report", content="text")
    text = _decode_csv_upload(raw)   # C-13/C-20: reject UTF-16/UTF-32 up front
    filename = file.filename

    def _work():
        rt = LogRouter(db, ROUTE_FORTI_REPORT, map_site=_log_map_site(db, site),
                       upload_ref=filename, evaluate=evaluate_event)
        findings = []
        imported = duplicates = skipped = unmapped = conflicts = 0
        for fields, dedup, raw_rows in _parse_csv_rows(text, filename, with_raw=True):
            if fields is None:
                skipped += 1
                continue
            fields["dedup_hash"] = dedup
            status, ev = rt.handle(fields, raw_rows)
            if status == "created" and ev is not None:
                imported += 1
                findings.extend(f for f in evaluate_event(ev, db) if f)
            elif status == "duplicate":
                duplicates += 1
            elif status.startswith("conflict"):
                conflicts += 1
            else:
                unmapped += 1
        replay = _replay_new_mappings(db, rt)
        rule_hits_updated = record_rule_hits_per_site(db, rt.created)  # F-10
        db.commit()
        return {
            "filename": filename,
            "events_imported": imported,
            "findings_created": len(findings),
            "finding_ids": [f.id for f in findings],
            "rule_hits_updated": rule_hits_updated,
            "escalations": _ae_escalation_count(db),  # N-02
            "duplicates_skipped": duplicates,
            "rows_skipped": skipped,
            "unmapped": unmapped,
            "conflicts": conflicts,
            "routing": _routing_out(rt, replay),
        }

    try:
        return await run_in_threadpool(_work)
    except (csv.Error, UnicodeDecodeError) as exc:   # C-13: not a parseable CSV
        await run_in_threadpool(db.rollback)
        raise _bad_csv(exc)


# ======================================================== BASELINE INGEST ==

@router.post("/ingest/baseline/comms-matrix")
@_reviews_after_upload('comms matrix')
async def ingest_baseline_comms(
    file: UploadFile = File(...),
    baseline_name: str = "default",
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload the approved communications matrix CSV from the audit workbook.
    Required columns: src, dst, dst_port. Optional: protocol, service_name,
    conduit, owner. Creates or updates the named baseline.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Comms matrix CSV", content="text")
    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_approved_comms,
            _decode_csv_upload(raw), db, baseline_name, file.filename,
            site_id=site_id,
        )
    except (csv.Error, UnicodeDecodeError) as exc:   # C-13: not a parseable CSV
        await run_in_threadpool(db.rollback)
        raise _bad_csv(exc)
    return {"filename": file.filename, **site_out, "stats": stats}


@router.post("/ingest/baseline/approved-hosts")
@_reviews_after_upload('approved hosts')
async def ingest_baseline_hosts(
    file: UploadFile = File(...),
    baseline_name: str = "default",
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload the approved host list CSV (jump hosts, remote-access gateways,
    admin WSs, engineering WSs/HMIs). Required columns: ip, role. role must be
    one of: jump_host, remote_access_gateway, admin_ws, engineering_ws, hmi.
    A remote_access_gateway (VPN concentrator, Teleport-style proxy, RDP/SSH
    gateway) is the sanctioned external entry point; once one is declared,
    external sessions that reach a jump_host directly are flagged.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Approved hosts CSV", content="text")
    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_approved_hosts,
            _decode_csv_upload(raw), db, baseline_name, file.filename,
            site_id=site_id,
        )
    except (csv.Error, UnicodeDecodeError) as exc:   # C-13: not a parseable CSV
        await run_in_threadpool(db.rollback)
        raise _bad_csv(exc)
    return {"filename": file.filename, **site_out, "stats": stats}


def _parse_column_map(text: Optional[str]) -> Optional[dict]:
    """``column_map`` form field: a JSON object {CSV column: field or ""}."""
    if text is None or not str(text).strip():
        return None
    try:
        m = json.loads(text)
    except ValueError:
        raise HTTPException(status_code=422, detail='column_map must be a JSON object {"column": "field"}')
    if (not isinstance(m, dict) or len(m) > 500
            or not all(isinstance(k, str) and len(k) <= 255 and (v is None or isinstance(v, str))
                       for k, v in m.items())):
        raise HTTPException(status_code=422,
                            detail='column_map must be a JSON object {"column": "field or empty"} '
                                   '(at most 500 columns)')
    return {k: (v or "") for k, v in m.items()}


def _mapping_out(row) -> dict:
    return {"id": row.id, "name": row.name, "column_map": row.column_map or {},
            "created_by": row.created_by,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None}


def _saved_mapping_for(db, site_id: int, headers: list, mapping_id: Optional[int] = None):
    """The saved mapping to apply: the one named by ``mapping_id`` (404 when
    it is not this site's), else the site's mapping that names the most of
    this file's columns - at least half of them (a mapping saved for another
    export system is not applied to this one)."""
    from app.models import InventoryImportMapping as M
    from app.parsers.inventory_mapping import column_key
    if mapping_id is not None:
        row = db.query(M).filter(M.id == mapping_id, M.site_id == site_id).first()
        if row is None:
            raise HTTPException(status_code=404, detail="Saved mapping not found for this site")
        return row
    keys = {column_key(h) for h in headers if column_key(h)}
    if not keys:
        return None
    best, best_n = None, 0
    for row in db.query(M).filter(M.site_id == site_id).order_by(M.updated_at.desc(), M.id.desc()):
        n = len(keys & {column_key(k) for k in (row.column_map or {})})
        if n > best_n:
            best, best_n = row, n
    return best if best is not None and best_n * 2 >= len(keys) else None


def _save_mapping(db, site_id: int, name: str, column_map: dict, by: Optional[str]) -> dict:
    from app.models import InventoryImportMapping as M
    name = name.strip()[:64]
    row = db.query(M).filter(M.site_id == site_id, M.name == name).first()
    if row is None:
        row = M(site_id=site_id, name=name, column_map=dict(column_map), created_by=by)
        db.add(row)
    else:
        row.column_map = dict(column_map)
        row.updated_at = datetime.now(timezone.utc)
    db.commit()
    return _mapping_out(row)


@router.post("/ingest/baseline/asset-inventory/preview")
async def preview_baseline_assets(
    file: UploadFile = File(...),
    column_map: Optional[str] = Form(None),
    mapping_id: Optional[int] = Form(None),
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """Preview an Asset Inventory CSV import - nothing is written.

    Returns every column with sample values and a suggested field (``basis``:
    ``saved`` from the site's saved mapping, ``exact`` field name, ``alias``,
    ``values`` - the column holds addresses -, or ``guess`` from the header
    words), the mapping in effect (``column_map``: the one sent, else the
    suggestions), blocking ``errors`` (no IP / MAC column, a field mapped
    twice, an unknown field, duplicate headers), ``warnings`` and ``checks``
    over every row (rows that would be imported, rows without a usable IP /
    MAC, Purdue levels and SL-C values that are not valid, device type
    values the checks do not know).  ``column_map`` (form, JSON
    ``{"column": "field" or ""}``) previews an operator mapping;
    ``mapping_id`` picks a saved mapping instead of the best-matching one."""
    from app.parsers import inventory_mapping as im
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    cmap = _parse_column_map(column_map)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Asset inventory CSV", content="text")
    try:
        text = _decode_csv_upload(raw)
        headers, _data = im.read_table(text)
    except (csv.Error, UnicodeDecodeError) as exc:
        raise _bad_csv(exc)
    if not headers:
        raise HTTPException(status_code=422, detail="The file is empty: no header row.")
    saved = await run_in_threadpool(_saved_mapping_for, db, site_id, headers, mapping_id)
    out = await run_in_threadpool(im.preview, text, cmap, saved.column_map if saved else None,
                                  saved.name if saved else None)
    return {"filename": file.filename, **site_out,
            "saved_mapping_id": saved.id if saved else None, **out}


@router.post("/ingest/baseline/asset-inventory")
@_reviews_after_upload('asset inventory')
async def ingest_baseline_assets(
    file: UploadFile = File(...),
    baseline_name: str = "default",
    column_map: Optional[str] = Form(None),
    mapping_id: Optional[int] = Form(None),
    save_mapping_as: Optional[str] = Form(None, max_length=64),
    saved_by: Optional[str] = Form(None, max_length=128),
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload the asset inventory CSV. Required: ip or mac. Optional:
    hostname, device_type, purdue_level, vlan, zone, sl_c, sl_c_source.
    Entries with purdue_level set are classified as manual (highest
    priority).  ``zone`` puts the host in that IEC 62443-3-2 zone (Zones &
    Conduits page; created when missing; a host already in another zone is
    added to this one too - dual-homed / multi-VLAN - and listed in
    ``zone_multi``, which the host_in_multiple_zones check reports); ``sl_c`` (1-4) and
    ``sl_c_source`` record the IEC 62443-4-2 capability security level.
    Zones and SL-C are documentation only.

    Column mapping: ``column_map`` (form, JSON ``{"column": "field" or ""}``,
    "" = ignore) says which column feeds which field - checked first, 422
    with the problems when it maps no IP / MAC column, a field twice or an
    unknown field.  Without it, ``mapping_id`` or the site's saved mapping
    that names at least half of the file's columns is applied, the other
    columns matched by name and alias (never a guess).  ``save_mapping_as``
    stores the mapping used under that name for the site.  The stats name
    the mapping (``mapping_source``, ``columns_mapped``) and list the
    columns left out (``columns_ignored``).
    """
    from app.parsers import inventory_mapping as im
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    cmap = _parse_column_map(column_map)
    if save_mapping_as is not None and not save_mapping_as.strip():
        raise HTTPException(status_code=422, detail="save_mapping_as must not be blank")
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Asset inventory CSV", content="text")
    try:
        text = _decode_csv_upload(raw)
        headers, _data = im.read_table(text)
    except (csv.Error, UnicodeDecodeError) as exc:
        raise _bad_csv(exc)
    source = None
    if cmap is not None:
        _clean, problems, _w = im.validate_column_map(headers, cmap)
        if problems:
            raise HTTPException(status_code=422, detail={"message": "The column mapping cannot be used.",
                                                         "errors": problems})
    else:
        saved = await run_in_threadpool(_saved_mapping_for, db, site_id, headers, mapping_id)
        if saved is not None:
            cmap, source = im.auto_map(headers, saved.column_map), f"saved:{saved.name}"
    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_asset_inventory,
            text, db, baseline_name, file.filename, cmap, source,
            site_id=site_id,
        )
    except (csv.Error, UnicodeDecodeError) as exc:   # C-13: not a parseable CSV
        await run_in_threadpool(db.rollback)
        raise _bad_csv(exc)
    except ValueError as exc:                         # a saved mapping that no longer fits
        await run_in_threadpool(db.rollback)
        raise HTTPException(status_code=422, detail={"message": "The column mapping cannot be used.",
                                                     "errors": str(exc).split("; ")})
    stats.update(await run_in_threadpool(_apply_inventory_zones, db, site_id, stats.pop("_zone_requests", [])))
    out = {"filename": file.filename, **site_out, "stats": stats}
    if save_mapping_as:
        full = {k: "" for k in stats.get("columns_ignored", [])}
        full.update(stats.get("columns_mapped", {}))
        out["mapping_saved"] = await run_in_threadpool(_save_mapping, db, site_id, save_mapping_as,
                                                       full, saved_by)
    return out


@router.get("/ingest/baseline/asset-inventory/mappings")
def list_inventory_mappings(site: str | None = _site_query(), db: DBSession = Depends(get_db)):
    """Saved Asset Inventory column mappings of the site, newest first, with
    the field list the mapping picker offers."""
    from app.models import InventoryImportMapping as M
    from app.parsers.inventory_mapping import ASSET_FIELDS
    site_row = _require_site(db, site)
    rows = (db.query(M).filter(M.site_id == site_row.id)
            .order_by(M.updated_at.desc(), M.id.desc()).all())
    return {**_site_info(site_row), "mappings": [_mapping_out(r) for r in rows],
            "fields": [{"field": f, "label": l, "hint": h} for f, l, h in ASSET_FIELDS]}


@router.delete("/ingest/baseline/asset-inventory/mappings/{mapping_id}")
def delete_inventory_mapping(mapping_id: int, site: str | None = _site_query(),
                             db: DBSession = Depends(get_db)):
    """Remove a saved column mapping of the site (hosts already imported are
    unchanged)."""
    from app.models import InventoryImportMapping as M
    site_row = _require_site(db, site)
    row = db.query(M).filter(M.id == mapping_id, M.site_id == site_row.id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Saved mapping not found for this site")
    db.delete(row)
    db.commit()
    return {"deleted": mapping_id}


def _apply_inventory_zones(db, site_id: int, requests: list) -> dict:
    """Asset Inventory CSV ``zone`` column -> IEC 62443-3-2 zone membership."""
    from app import iec_zones as iz
    out = {"zone_members_added": 0, "zone_already": 0, "zone_multi": [], "zones_created": []}
    for n, host_id, zone in requests:
        host = db.get(Host, host_id)
        if host is None:
            continue
        res = iz.assign_from_inventory(db, site_id, host, zone)
        if res in ("added", "created"):
            out["zone_members_added"] += 1
            if res == "created":
                out["zones_created"].append(zone[:128])
        elif res == "already":
            out["zone_already"] += 1
        elif res.startswith("also_in:"):
            out["zone_members_added"] += 1
            if len(out["zone_multi"]) < 20:
                out["zone_multi"].append(f"row {n}: {host.ip or host.mac} is now in zone '{zone}' and in "
                                         f"'{res.split(':', 1)[1]}' (a host in several zones is reported by "
                                         f"host_in_multiple_zones)")
    db.commit()
    return out


@router.post("/ingest/baseline/reviewed-policies")
@_reviews_after_upload('reviewed policies')
async def ingest_baseline_policies(
    file: UploadFile = File(...),
    baseline_name: str = "default",
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload the reviewed firewall policy list CSV. Required: policy_id.
    Optional: conduit, owner, notes, last_reviewed. Matches existing
    FirewallRule rows by policy_id.
    """
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)
    raw = await _read_limited(file, _MAX_TEXT_BYTES, "Reviewed policies CSV", content="text")
    try:
        stats = await run_in_threadpool(
            _in_site, db, site_id, ingest_reviewed_policies,
            _decode_csv_upload(raw), db, baseline_name, file.filename,
            site_id=site_id,
        )
    except (csv.Error, UnicodeDecodeError) as exc:   # C-13: not a parseable CSV
        await run_in_threadpool(db.rollback)
        raise _bad_csv(exc)
    return {"filename": file.filename, **site_out, "stats": stats}



# ========================================================== PERIODIC REVIEW ==

def _review_schedule_state(db) -> dict:
    """RS-01: the operator switch, the environment switch, the cron and the
    last scheduled run.  ``effective``: "on" (runs on the schedule),
    "paused" (operator switch off) or "disabled" (IACS_REVIEW_ENABLED off:
    the scheduler is not started; the switch cannot override that)."""
    from app import main as _main
    from app import settings_store as ss
    env_on = _main._scheduler_enabled()
    row = ss.get_row(db, ss.PERIODIC_REVIEWS)
    enabled = ss.periodic_reviews_enabled(db)
    cron = _main._review_cron()
    effective = "disabled" if not env_on else ("on" if enabled else "paused")
    next_run = None
    if effective == "on":
        try:
            from apscheduler.triggers.cron import CronTrigger
            nxt = CronTrigger.from_crontab(cron, timezone="UTC").get_next_fire_time(
                None, datetime.now(timezone.utc))
            next_run = nxt.isoformat() if nxt else None
        except Exception:                                   # noqa: BLE001 - bad cron: shown as None
            next_run = None
    st = _main.SCHEDULER_STATE
    return {
        "enabled": enabled,
        "effective": effective,
        "env_enabled": env_on,
        "cron": cron,
        "timezone": "UTC",
        "next_run": next_run,
        "last_run": ss.get_setting(db, ss.PERIODIC_REVIEWS_LAST),
        "updated_at": row.updated_at.isoformat() if row is not None and row.updated_at else None,
        "updated_by": row.updated_by if row is not None else None,
        "scheduler_in_this_process": bool(st.get("running")),
        "note": ("Scheduled reviews are switched off by the IACS_REVIEW_ENABLED environment "
                 "variable; change it and restart the server to use this switch."
                 if not env_on else None),
    }


@router.get("/reviews/rules-not-judged")
def get_rules_not_judged(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                         site_id: int | None = Query(None, description="site id (alternative to `site`)"),
                         db: DBSession = Depends(get_db)):
    """MP-24: per firewall, the enabled permit policies the rule-level
    reviews could NOT judge (a side that resolves to no Purdue level), with
    the reason per policy.  Their absence from the findings is not a pass:
    label the interfaces / zones they name and re-run the reviews."""
    from app.parsers.alert_engine import rules_not_judged
    site_row = _operation_site(db, site, site_id)
    out = rules_not_judged(db, site_id=site_row.id)
    return {**out, **_site_info(site_row)}


@router.get("/reviews/schedule")
def get_review_schedule(db: DBSession = Depends(get_db)):
    """RS-01: is the scheduled periodic review run on?  Manual runs
    (POST /reviews/run) are never affected by this switch."""
    return _review_schedule_state(db)


@router.put("/reviews/schedule")
def set_review_schedule(
    enabled: bool = Body(..., embed=True, description="true = run on the schedule, false = paused"),
    changed_by: str | None = Body(None, embed=True, max_length=128, description="who changed it (free text)"),
    db: DBSession = Depends(get_db),
):
    """RS-01: pause / resume the scheduled periodic reviews (server-wide, all
    sites).  Takes effect at the next scheduled firing, survives restarts.
    Manual runs (POST /reviews/run) keep working while paused."""
    from app import settings_store as ss
    ss.set_setting(db, ss.PERIODIC_REVIEWS, {"enabled": bool(enabled)},
                   by=(changed_by or "").strip() or None)
    db.commit()
    log.info("Scheduled periodic reviews %s by %s", "enabled" if enabled else "paused",
             changed_by or "(unnamed)")
    return _review_schedule_state(db)


@router.post("/reviews/run")
def run_periodic_review(site: Optional[str] = Query(None, description=(
                            "Site to review (id, name or code). Omitted: every site is "
                            "reviewed in turn (sites are isolated) and per-site results are "
                            "returned under 'sites'.")),
                        site_id: int | None = Query(None, ge=1),
                        db: DBSession = Depends(get_db)):
    """
    Run every ISA/IEC 62443 periodic review function (alert_engine.run_periodic_reviews) and return counts of
    findings produced. Reviews cover: conduit matrix drift, unused policies,
    denied trends, insecure protocols, OT-IT dependencies, cleartext
    credentials, unknown devices, IP conflicts, misplaced devices, shadow
    rules, historian in control zone, wireless in OT zone, single-path
    critical devices, undocumented LLDP devices, management access from wrong
    zone, management access not restricted, no path redundancy, firmware not
    documented, zone documentation (1.1–1.6), and NTP sync.

    The scheduler runs this automatically on the cron schedule set by the
    IACS_REVIEW_SCHEDULE environment variable (default: Sundays 02:00 UTC).
    Call this endpoint to trigger an immediate run outside the schedule.
    """
    if site is not None or site_id is not None:
        targets = [_operation_site(db, site, site_id)]
    else:
        targets = db.query(Site).order_by(Site.id).all()     # FI-01: may be empty
    per_site = {}
    plan = [(r.id, r.name, _site_info(r)) for r in targets]   # read before any expunge
    for sid, sname, sinfo in plan:
        per_site[sname] = {**_review_one_site(db, sid), **sinfo}
        db.expunge_all()          # C-18: no warm identity-map objects across sites
    # Top level: the single site's result, or the sum over all sites (keeps
    # the pre-multi-site response shape for existing callers).
    by_review: dict = {}
    auto_resolved: dict = {}
    failed: list = []
    for res in per_site.values():
        for k, v in res["by_review"].items():
            by_review[k] = by_review.get(k, 0) + (v or 0)
        for k, v in res["auto_resolved"].items():
            auto_resolved[k] = auto_resolved.get(k, 0) + (v or 0)
        failed += [f for f in res["failed_reviews"] if f not in failed]
    out = {"total_findings": sum(r["total_findings"] for r in per_site.values()),
           "by_review": by_review, "failed_reviews": failed,
           "escalations": sum(r["escalations"] for r in per_site.values()),
           "auto_resolved": auto_resolved, "sites": per_site}
    if len(plan) == 1:
        out.update(plan[0][2])
    return out


def _review_one_site(db, site_id: int) -> dict:
    """One run_periodic_reviews pass scoped to ``site_id``."""
    from app.parsers.alert_engine import failed_reviews
    esc_before = _ae_escalation_count(db)
    stats = run_periodic_reviews(db, site_id=site_id) or {}
    stats = {k: v for k, v in stats.items() if isinstance(v, (int, float))}
    try:
        failed = failed_reviews(db, site_id)
        auto = _ae_auto_resolved_counts(db, site_id)
    except TypeError:   # alert_engine without per-site bookkeeping
        failed, auto = failed_reviews(db), _ae_auto_resolved_counts(db)
    # Reviews that raised were rolled back individually (T3-17); name them so
    # the caller knows the run was partial.  N-02 / F-04: open findings
    # escalated, findings auto-resolved per review.
    return {"total_findings": sum(stats.values()), "by_review": stats,
            "failed_reviews": failed,
            "escalations": _ae_escalation_count(db) - esc_before,
            "auto_resolved": auto}


@router.get("/diagnostics")
def findings_engine_diagnostics():
    """
    F-17: findings-engine diagnostics. ``unknown_check_names`` counts
    check_names passed to the alert engine that are not registered in
    CHECK_TYPE_REFERENCE (process lifetime; such findings are skipped).
    ``last_review`` summarises the most recent periodic review run in this
    process (failed_reviews, escalations, auto_resolved); empty values when
    no run has happened yet.
    """
    from app.parsers.alert_engine import last_review_info, unknown_check_name_counts
    last = last_review_info()
    return {
        "unknown_check_names": unknown_check_name_counts(),
        "last_review": {
            "failed_reviews": last.get("failed_reviews", []),
            "escalations": last.get("escalations", 0),
            "auto_resolved": last.get("auto_resolved", {}),
            "finished_at": last.get("finished_at"),
        },
    }


# ========================================================== BASELINES ==

@router.get("/baselines")
def list_baselines(site_id: int | None = _site_filter_query(),
                   db: DBSession = Depends(get_db)):
    """List all baselines, active one first."""
    from sqlalchemy import func as _func
    from app.models import ApprovedCommsEntry, ApprovedHost

    # Use SQL COUNT sub-queries instead of loading all related rows into
    # memory via lazy-load (b.comms_entries triggers one query per baseline).
    comms_counts = dict(
        db.query(ApprovedCommsEntry.baseline_id, _func.count())
          .group_by(ApprovedCommsEntry.baseline_id).all()
    )
    host_counts = dict(
        db.query(ApprovedHost.baseline_id, _func.count())
          .group_by(ApprovedHost.baseline_id).all()
    )

    bq = db.query(Baseline)
    if _check_site_filter(db, site_id) is not None:
        bq = bq.filter(Baseline.site_id == site_id)
    baselines = bq.order_by(
        Baseline.is_active.desc(), Baseline.created_at.desc()
    ).all()
    names = site_names(db)
    return [
        {
            "id": b.id, "site_id": b.site_id, "site_name": names.get(b.site_id),
            "name": b.name, "description": b.description,
            "created_at": b.created_at, "is_active": b.is_active,
            "comms_entries": comms_counts.get(b.id, 0),
            "approved_hosts": host_counts.get(b.id, 0),
        }
        for b in baselines
    ]


@router.post("/baselines/{baseline_name}/activate")
@_reviews_after_upload('baseline activation')
def activate_baseline(baseline_name: str,
                      site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                      site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                      db: DBSession = Depends(get_db)):
    """Set a baseline as the active one OF ITS SITE (deactivates the site's
    other baselines; other sites keep theirs).  ``site`` / ``site_id`` is
    required when more than one site exists."""
    site_row = _operation_site(db, site, site_id)
    baseline = (db.query(Baseline)
                .filter(Baseline.site_id == site_row.id, Baseline.name == baseline_name).first())
    if not baseline:
        raise HTTPException(status_code=404,
                            detail=f"Baseline '{baseline_name}' not found in site {site_row.name!r}")
    # Deactivate first and flush: ux_baselines_site_active allows one active
    # row per site.
    db.query(Baseline).filter(Baseline.site_id == site_row.id, Baseline.id != baseline.id) \
        .update({"is_active": False}, synchronize_session="fetch")
    db.flush()
    baseline.is_active = True
    db.commit()
    db.refresh(baseline)   # ensure in-memory object reflects the committed state
    return {"activated": baseline_name, **_site_info(site_row)}


# ======================================================== ATTESTATION ==

_ATTESTABLE_ROWS = {"1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}
# _MAX_PROOF_BYTES defined at module top


@router.get("/attestation")
def list_attestations(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    checklist_id: Optional[str] = None,
    current_only: bool = False,
    site_id: int | None = _site_filter_query(),
    db: DBSession = Depends(get_db),
):
    """
    List attestation records.  By default returns all rows (history
    included) sorted newest-first.  Pass current_only=true for just the
    active record per checklist row, or checklist_id to filter to one row.

    Proof bytes are NOT included in list responses - use
    GET /attestation/{id}/proof to download the file.
    """
    query = db.query(Attestation)
    if _check_site_filter(db, site_id) is not None:
        query = query.filter(Attestation.site_id == site_id)
    if checklist_id:
        query = query.filter(Attestation.checklist_id == checklist_id)
    if current_only:
        query = query.filter(Attestation.is_current == True)
    records = _page(query.order_by(Attestation.attested_at.desc(), Attestation.id.desc()),
                    response, limit, offset).all()
    return [_att_dict(a) for a in records]


@router.get("/attestation/current")
def current_attestations(
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    baseline_name: Optional[str] = None,
    db: DBSession = Depends(get_db),
):
    """The current attestation per checklist row (1.1 - 1.6) of ONE site
    (multi-site phase 2: attestations are per site x checklist x baseline).
    ``baseline_name``: that baseline of the site (default: the site's active
    baseline, falling back to no-baseline attestations).  Rows without a
    current attestation are ``null``."""
    site_row = _operation_site(db, site, site_id)
    if baseline_name:
        bl = (db.query(Baseline)
              .filter(Baseline.site_id == site_row.id, Baseline.name == baseline_name).first())
        if bl is None:
            raise HTTPException(status_code=404,
                                detail=f"Baseline '{baseline_name}' not found in site {site_row.name!r}")
    else:
        bl = (db.query(Baseline)
              .filter(Baseline.site_id == site_row.id, Baseline.is_active == True)  # noqa: E712
              .first())
    q = db.query(Attestation).filter(Attestation.site_id == site_row.id,
                                     Attestation.is_current == True)  # noqa: E712
    rows = {}
    for a in q.order_by(Attestation.id.asc()).all():
        if bl is not None and a.baseline_id == bl.id:
            rows[a.checklist_id] = a          # the baseline's own wins
        elif a.baseline_id is None and a.checklist_id not in rows:
            rows[a.checklist_id] = a
    return {**_site_info(site_row), "baseline": bl.name if bl else None,
            "rows": {cid: (_att_dict(rows[cid]) if cid in rows else None)
                     for cid in sorted(_ATTESTABLE_ROWS)}}


@router.post("/attestation", status_code=201)
async def create_attestation(
    checklist_id: str = Form(...),
    attested_by: str = Form(..., max_length=255),
    attested_at: str = Form(...),       # ISO date string, e.g. "2026-09-27"
    notes: Optional[str] = Form(None),
    baseline_name: Optional[str] = Form(None),
    site: Optional[str] = Form(None, description=_SITE_DOC),
    proof: Optional[UploadFile] = File(None),
    db: DBSession = Depends(get_db),
):
    """
    Submit a new attestation for a checklist row.

    - checklist_id: one of 1.1 – 1.6
    - attested_by:  name / email of the reviewer
    - attested_at:  ISO date the evidence was reviewed (YYYY-MM-DD)
    - notes:        free-text (document location, context, version …)
    - baseline_name: optional; links to a Baseline row by name
    - site:         REQUIRED; site id, name or code the attestation belongs to
    - proof:        optional file upload (PDF / PNG / DOCX etc., max 20 MB)

    Automatically flips any previous is_current=True record for the same
    (checklist_id, baseline_id) pair to is_current=False so only the newest
    attestation is "current" while the history is preserved.
    """
    site_row = _require_site(db, site)
    if checklist_id not in _ATTESTABLE_ROWS:
        # Paired firewall vendor diversity: "PF-<group id>" of a paired group
        # of THIS site (manual control, review_paired_firewall_vendor_diversity)
        from app.parsers.firewall_groups import ATTEST_PREFIX, group_of_attestation
        from app.parsers.site_scope import analysis_site
        ok = False
        if str(checklist_id).startswith(ATTEST_PREFIX):
            with analysis_site(db, site_row.id):
                ok = group_of_attestation(db, checklist_id) is not None
        if not ok:
            raise HTTPException(
                status_code=400,
                detail=(f"checklist_id must be one of {sorted(_ATTESTABLE_ROWS)} or "
                        f"{ATTEST_PREFIX}<id> of a paired firewall of this site"))
    if not (attested_by or "").strip():
        raise HTTPException(status_code=422, detail="attested_by must not be blank")

    # Parse date — attach UTC timezone so comparisons with tz-aware
    # datetime.now(timezone.utc) values stored in the DB don't raise
    # TypeError (mixing naive and aware datetimes fails on PostgreSQL
    # and produces incorrect orderings on SQLite).
    try:
        att_date = datetime.strptime(attested_at.strip(), "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="attested_at must be YYYY-MM-DD")
    if att_date.date() > datetime.now(timezone.utc).date():
        raise HTTPException(status_code=422, detail="attested_at must not be in the future")

    # Read proof file - chunked, 413 as soon as it passes the limit (T3-02).
    proof_data = None
    proof_filename = None
    proof_mime = None
    if proof and proof.filename:
        proof_data = await _read_limited(proof, _MAX_PROOF_BYTES, "Proof file")
        # Strip directory traversal components and ASCII control characters
        # before storing. Path().name handles ../../../etc cases; _CTRL_RE
        # removes embedded CR/LF/NUL that could corrupt HTTP headers later.
        raw_name = Path(proof.filename).name if proof.filename else "proof"
        proof_filename = _CTRL_RE.sub("", raw_name) or "proof"
        proof_mime = _safe_proof_mime(proof.content_type)

    return await run_in_threadpool(
        _create_attestation_sync, db, checklist_id, attested_by, att_date, notes,
        baseline_name, proof_filename, proof_mime, proof_data, site_row.id,
    )


def _create_attestation_sync(db, checklist_id, attested_by, att_date, notes,
                             baseline_name, proof_filename, proof_mime, proof_data,
                             site_id=None):
    """DB part of POST /attestation, run in a worker thread (T3-01)."""
    # Resolve baseline
    baseline_id = None
    if baseline_name:
        # Phase 2: baseline names are per site - only the attestation's site.
        baseline = (db.query(Baseline)
                    .filter(Baseline.site_id == site_id, Baseline.name == baseline_name).first())
        if not baseline:
            raise HTTPException(status_code=404,
                                detail=f"Baseline '{baseline_name}' not found")
        baseline_id = baseline.id

    # Demote the previous current record(s) for exactly this
    # (checklist_id, baseline_id) pair FIRST, flush, and only then insert the
    # new is_current=True row. Inserting first (the old order) always tripped
    # the partial unique index ix_attestation_one_current, so every second
    # attestation for the same row returned 409 (T1-34). The baseline filter
    # must also match NULL explicitly: without it a no-baseline attestation
    # demoted the current attestation of every baseline (T1-35).
    # Both statements run in one transaction, so no other session ever sees a
    # state with zero current attestations.
    prev_query = db.query(Attestation).filter(
        Attestation.site_id == site_id,
        Attestation.checklist_id == checklist_id,
        Attestation.is_current == True,  # noqa: E712
    )
    if baseline_id is not None:
        prev_query = prev_query.filter(Attestation.baseline_id == baseline_id)
    else:
        prev_query = prev_query.filter(Attestation.baseline_id.is_(None))

    # Phase 2: "current" is per (site, checklist_id, baseline) -
    # ux_attestation_site_one_current[_nobaseline].
    att = Attestation(
        site_id=site_id,
        checklist_id=checklist_id,
        attested_by=attested_by.strip(),
        attested_at=att_date,
        notes=notes.strip() if notes else None,
        baseline_id=baseline_id,
        proof_filename=proof_filename,
        proof_mime=proof_mime,
        proof_data=proof_data,
        is_current=True,
    )
    try:
        prev_query.update({"is_current": False}, synchronize_session="fetch")
        db.flush()
        db.add(att)
        # The partial unique indexes (ix_attestation_one_current and
        # ix_attestation_one_current_nobaseline) now only fire on a genuine
        # race: a concurrent request committed a new current row between our
        # demote and insert.
        db.flush()
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A concurrent attestation for this checklist / baseline pair was "
                   "submitted at the same time. Refresh and try again.",
        )

    db.refresh(att)
    return _att_dict(att)


# A-26: only these MIME types are stored / served for proof files; anything
# else (text/html, image/svg+xml, ...) becomes application/octet-stream.
_PROOF_MIME_ALLOW = frozenset({
    "application/pdf", "image/png", "image/jpeg", "image/gif",
    "text/plain", "text/csv", "application/zip",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
})


def _safe_proof_mime(mime: Optional[str]) -> str:
    m = (mime or "").split(";", 1)[0].strip().lower()
    return m if m in _PROOF_MIME_ALLOW else "application/octet-stream"


@router.get("/attestation/{attestation_id}/proof")
def get_attestation_proof(attestation_id: int, db: DBSession = Depends(get_db)):
    """
    Download the proof file attached to an attestation record.
    Returns 404 if no file was uploaded with that record.
    """
    att = db.query(Attestation).filter(Attestation.id == attestation_id).first()
    if not att:
        raise HTTPException(status_code=404, detail="Attestation not found")
    if not att.proof_data:
        raise HTTPException(status_code=404, detail="No proof file attached to this attestation")
    return Response(
        content=att.proof_data,
        media_type=_safe_proof_mime(att.proof_mime),
        headers={
            # Use RFC 5987 percent-encoded form (filename*) to prevent
            # header injection via embedded quotes, CR/LF or non-ASCII chars.
            "Content-Disposition": (
                "attachment; filename*=UTF-8''"
                + urllib.parse.quote(att.proof_filename or "proof", safe="")
            ),
        },
    )


def _att_dict(a: Attestation) -> dict:
    """Serialise an Attestation to a JSON-safe dict (proof bytes excluded)."""
    return {
        "id": a.id,
        "site_id": a.site_id,
        "checklist_id": a.checklist_id,
        "attested_by": a.attested_by,
        "attested_at": a.attested_at,
        "notes": a.notes,
        "proof_filename": a.proof_filename,
        "proof_mime": a.proof_mime,
        # Check proof_filename, not proof_data — the blob column is declared
        # deferred (lazy-loaded) in models.py to avoid loading binary data in
        # list queries. Accessing proof_data here would issue a per-row SELECT
        # that defeats the deferred declaration. (P4-H1)
        "has_proof": a.proof_filename is not None,
        "baseline_id": a.baseline_id,
        "is_current": a.is_current,
        "created_at": a.created_at,
    }


# ============================================================ TOPOLOGY ==

@router.get("/topology/state")
def topology_state(site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                   site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                   db: DBSession = Depends(get_db)):
    """
    Return the current multi-firewall topology state.

    Response shape:
      {
        "is_multi_fw": bool,
        "firewall_count": int,
        "firewalls": [
          {
            "id": int, "name": str, "vendor": str,
            "upstream_firewall_id": int|null,
            "topology_confirmed": bool,
            "interfaces": [
              {
                "id": int, "name": str,
                "ip_cidr": str|null, "network_cidr": str|null,
                "side": "inside"|"outside"|null,
                "zone_label": str|null, "purdue_level": int|null,
                "connects_to_interface_id": int|null,
                "is_ha": bool, "is_mgmt_only": bool
              }
            ]
          }
        ],
        "pending_proposals": [
          {
            "fw_a_id": int, "fw_a_name": str,
            "iface_a_id": int, "iface_a_name": str, "iface_a_cidr": str,
            "fw_b_id": int, "fw_b_name": str,
            "iface_b_id": int, "iface_b_name": str, "iface_b_cidr": str,
            "confidence": "high"|"medium"
          }
        ],
        "segment_proposals": [          # D-07: >= 3 firewalls on one network
          {"network": str, "confidence": "high",
           "members": [{"fw_id", "fw_name", "iface_id", "iface_name", "ip_cidr"}]}
        ]
      }

    When `is_multi_fw` is false (only one config uploaded) the firewalls
    list has one entry and both proposal lists are empty.
    """
    site_row = _operation_site(db, site, site_id)
    return {**get_topology_state(db, site_id=site_row.id), **_site_info(site_row)}


@router.post("/topology/confirm-segment")
def topology_confirm_segment(
    iface_ids: list[int] = Body(..., description="interfaces of >= 2 firewalls on one network"),
    name: Optional[str] = Body(None, max_length=64),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """D-07: confirm a SHARED segment (three or more firewalls on one network,
    e.g. the DMZ switch), which the one-peer link model cannot record.

    Every member interface gets the same ``segment`` label (default
    ``seg-<network>``); point-to-point links between members are cleared.
    Cross-firewall checks then treat every pair of members as linked, and the
    group disappears from ``segment_proposals``.  400 for fewer than two
    firewalls or an unknown interface, 422 across sites."""
    if not iface_ids or len(iface_ids) > 64:
        raise HTTPException(status_code=422, detail="iface_ids: 2-64 interface ids")
    site_row = _builder_site(db, site, site_id,
                             firewall_ids=[_iface_fw_id(db, i) for i in iface_ids])
    try:
        out = confirm_segment(db, iface_ids, name, site_id=site_row.id)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=_value_error_status(exc), detail=str(exc))
    try:
        check_stats = run_cross_fw_checks(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        check_stats = _error_stub(exc, "Cross-firewall check run failed")
    return {**out, "cross_fw_checks": check_stats, **_site_info(site_row)}


# -------------------------------------------- HA clusters / paired firewalls --

def _group_http_error(exc):
    return HTTPException(status_code=getattr(exc, "status", 422), detail=str(exc))


@router.get("/topology/firewall-groups")
def list_firewall_groups(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                         site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                         db: DBSession = Depends(get_db)):
    """HA clusters and paired firewalls of ONE site, plus suggestions.

    ``groups``: [{id, kind: ha|paired, name, members: [{id, name, vendor,
    ha_mode, ha_cfg_group}], primary_firewall_id (ha), recorded_vendors /
    attestation_checklist_id / vendor_diversity_attested (paired)}];
    ``suggestions``: HA (configs sharing a ``config system ha`` group) and
    paired (linked firewalls enforcing the same levels) - nothing changes in
    the analysis until a group is confirmed."""
    from app.parsers import firewall_groups as fg
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        return {"groups": fg.list_groups(db),
                "suggestions": fg.suggest_ha(db) + fg.suggest_paired(db),
                **_site_info(site_row)}


def _declare_group(db, kind, site, site_id, firewall_ids, name, note, created_by, primary_id=None):
    from app.parsers import firewall_groups as fg
    from app.parsers.site_scope import analysis_site
    site_row = _builder_site(db, site, site_id, firewall_ids=list(firewall_ids or []))
    try:
        with analysis_site(db, site_row.id):
            if kind == fg.KIND_HA:
                g = fg.declare_ha(db, site_row.id, firewall_ids, primary_id=primary_id,
                                  name=name, created_by=created_by, note=note)
            else:
                g = fg.declare_paired(db, site_row.id, firewall_ids, name=name,
                                      created_by=created_by, note=note)
            out = fg.group_dict(db, g)
        db.commit()
    except fg.GroupError as exc:
        db.rollback()
        raise _group_http_error(exc)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="a group of that name already exists")
    try:
        check_stats = run_cross_fw_checks(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        check_stats = _error_stub(exc, "Cross-firewall check run failed")
    return {**out, "cross_fw_checks": check_stats, **_site_info(site_row)}


@router.post("/topology/ha-pairs", status_code=201)
def declare_ha_pair(
    firewall_ids: list[int] = Body(..., description="the member configs (2-8)"),
    primary_id: int | None = Body(None, description="member whose rules the analysis uses (default: first)"),
    name: str | None = Body(None, max_length=64),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Declare an HA cluster: several uploaded configs of ONE logical firewall
    (traffic passes one member).  The primary's rules are its single
    enforcement point; the others are compared with it (``ha_config_drift``)
    and their duplicate findings are folded into the primary's.  422 bad
    input, 404 unknown firewall, 409 already clustered / name taken."""
    from app.parsers.firewall_groups import KIND_HA
    return _declare_group(db, KIND_HA, site, site_id, firewall_ids, name, note, created_by,
                          primary_id=primary_id)


@router.post("/topology/paired-firewalls", status_code=201)
def declare_paired_firewall(
    firewall_ids: list[int] = Body(..., description="firewalls in series on one boundary (2-8)"),
    name: str | None = Body(None, max_length=64),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Declare a paired firewall: firewalls (an HA cluster counts as one)
    enforcing ONE boundary in series, typically two vendors at the IT/OT DMZ.
    The asymmetric-permit check compares exactly these; vendor diversity is
    confirmed by an attestation for checklist id ``PF-<group id>``
    (``paired_firewall_vendor_diversity`` until then)."""
    from app.parsers.firewall_groups import KIND_PAIRED
    return _declare_group(db, KIND_PAIRED, site, site_id, firewall_ids, name, note, created_by)


@router.delete("/topology/firewall-groups/{group_id}")
def delete_firewall_group(
    group_id: int,
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Dissolve an HA cluster or paired firewall (members stay; 404 when it
    is not this site's)."""
    from app.parsers import firewall_groups as fg
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    try:
        with analysis_site(db, site_row.id):
            g = fg.delete_group(db, group_id)
            out = {"deleted": group_id, "kind": g.kind, "name": g.name}
        db.commit()
    except fg.GroupError as exc:
        db.rollback()
        raise _group_http_error(exc)
    return {**out, **_site_info(site_row)}


# --------------------------------------------------------------------------
# Declared management networks (app/parsers/mgmt_networks.py,
# docs/management-networks.md)
# --------------------------------------------------------------------------
def _mgmt_http_error(exc):
    return HTTPException(status_code=getattr(exc, "status", 422), detail=str(exc))


def _mgmt_site(db, site, site_id, finding_id=None) -> Site:
    """The site of a management-network operation: explicit site / site_id,
    else the site of ``finding_id``, else the only site (see _operation_site)."""
    if finding_id is not None:
        f = db.get(Finding, int(finding_id))
        if f is None:
            raise HTTPException(status_code=404, detail=f"finding {finding_id} not found")
        if site in (None, "") and site_id is None:
            return _require_site(db, f.site_id)
        row = _operation_site(db, site, site_id)
        if f.site_id != row.id:                      # a finding of another site
            raise HTTPException(status_code=404, detail=f"finding {finding_id} not found in site {row.name!r}")
        return row
    return _operation_site(db, site, site_id)


@router.get("/external-comms")
def list_external_comms(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """G5: every communication of ONE site between an inside host and an
    address outside the site's known networks (capture segments, firewall /
    switch interface networks, subnet zones, VPN pools): one row per inside
    host and destination (the registrable domain of the name the capture
    showed - DNS answer, TLS server name, HTTP Host - else the address),
    with category, answered / tried only, volume, first / last seen, the
    router(s) it left by, the rules that match it, and the review status.
    ``summary.unknown``: no name, no recognised service, not reviewed."""
    from app.parsers import external_comms as ec
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        out = ec.flows(db)
    return {**out, **_site_info(site_row)}


@router.post("/external-comms/review")
def review_external_comm(
    src: str = Body(..., max_length=64, description='inside host address, or "*" for every host'),
    dest_key: str = Body(..., max_length=255, description="destination domain (e.g. hik-connect.com) or address"),
    status: str = Body(..., description="approved | remove"),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Approve an external communication (a documented conduit - it stops
    raising Internet-egress findings at the next review run) or mark it for
    removal.  Re-posting changes the status.  422 bad status / address."""
    import ipaddress as _ipa
    from app.models import ExternalFlowReview
    if status not in ("approved", "remove"):
        raise HTTPException(status_code=422, detail="status must be 'approved' or 'remove'")
    src = src.strip()
    if src != "*":
        try:
            src = str(_ipa.ip_address(src))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"src: '{src}' is not an address or '*'")
    dest_key = dest_key.strip().lower()
    if not dest_key:
        raise HTTPException(status_code=422, detail="dest_key is empty")
    site_row = _operation_site(db, site, site_id)
    row = db.query(ExternalFlowReview).filter(ExternalFlowReview.site_id == site_row.id,
                                              ExternalFlowReview.src == src,
                                              ExternalFlowReview.dest_key == dest_key).first()
    created = row is None
    if created:
        row = ExternalFlowReview(site_id=site_row.id, src=src, dest_key=dest_key, created_by=created_by)
        db.add(row)
    row.status, row.note = status, note
    db.commit()
    return {"review": {"id": row.id, "src": row.src, "dest_key": row.dest_key, "status": row.status,
                       "note": row.note}, "created": created, **_site_info(site_row)}


@router.delete("/external-comms/review/{review_id}")
def delete_external_comm_review(review_id: int,
                                site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                                site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                                db: DBSession = Depends(get_db)):
    """Remove a review: the flow is unreviewed again (findings come back at
    the next review run).  404 when it is not this site's."""
    from app.models import ExternalFlowReview
    site_row = _operation_site(db, site, site_id)
    row = db.query(ExternalFlowReview).filter(ExternalFlowReview.id == review_id,
                                              ExternalFlowReview.site_id == site_row.id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Review not found")
    db.delete(row)
    db.commit()
    return {"deleted": review_id, **_site_info(site_row)}


# ------------------------------------------- IEC 62443-3-2 zones and conduits --
# Documentation only (owner 2026-10-10): zones may span Purdue levels and
# address ranges, and nothing here feeds the findings engine (app/iec_zones.py).

def _zone_call(fn, *a, **kw):
    from app.iec_zones import ZoneError
    try:
        return fn(*a, **kw)
    except ZoneError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))


@router.get("/iec-zones")
def list_iec_zones(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                   site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                   db: DBSession = Depends(get_db)):
    """IEC 62443-3-2 zones of ONE site: each zone with its SL-T, members
    (hosts, subnets, firewall interfaces / VLAN sub-interfaces, FortiGate
    zones - with whether they still resolve), the hosts it holds and the
    Purdue levels it spans; hosts in no zone; networks claimed by two zones.
    Documentation only: zones never change findings."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    model = iz.ZoneModel(db, site_row.id)
    zones = iz.zone_summary(model)
    return {"zones": zones, "unassigned_hosts": iz.unassigned_hosts(model), "overlaps": model.overlaps,
            "multi_zone_hosts": model.multi_zone,
            "counts": {"zones": len(zones), "hosts_in_zones": sum(z["host_count"] for z in zones)},
            **_site_info(site_row)}


@router.get("/iec-zones/candidates")
def iec_zone_candidates(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """What can be added to a zone: firewall interfaces (incl. VLAN
    sub-interfaces), FortiGate zones, known subnets and hosts, each with the
    zone it is already in."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    return {**iz.candidates(db, iz.ZoneModel(db, site_row.id)), **_site_info(site_row)}


@router.post("/iec-zones")
def create_iec_zone(name: str = Body(..., max_length=128), sl_t: Any = Body(None, description="SL-T 1-4"),
                    description: str | None = Body(None, max_length=4000),
                    owner: str | None = Body(None, max_length=128),
                    created_by: str | None = Body(None, max_length=128),
                    sl_a: Any = Body(None, description="SL-A (achieved) 1-4"),
                    sl_a_note: str | None = Body(None, max_length=255),
                    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                    db: DBSession = Depends(get_db)):
    """Create a zone (409 when the name exists in this site, 422 bad SL-T / SL-A)."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    z = _zone_call(iz.create_zone, db, site_row.id, name, sl_t, description, owner, created_by,
                   sl_a=sl_a, sl_a_note=sl_a_note)
    db.commit()
    return {"zone": {"id": z.id, "name": z.name, "sl_t": z.sl_t, "sl_a": z.sl_a, "sl_a_note": z.sl_a_note,
                     "description": z.description, "owner": z.owner},
            **_site_info(site_row)}


@router.patch("/iec-zones/{zone_id}")
def update_iec_zone(zone_id: int, body: dict = Body(..., description="name, sl_t, sl_a, sl_a_note, description, owner"),
                    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                    db: DBSession = Depends(get_db)):
    """Change a zone's name, SL-T / SL-A (null clears), SL-A note, description or owner.
    SL-A is the achieved level from an assessment; like SL-T it is documentation only."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    fields = {k: body[k] for k in ("name", "sl_t", "sl_a", "sl_a_note", "description", "owner") if k in body}
    for k, lim in (("name", 128), ("owner", 128), ("description", 4000)):
        if isinstance(fields.get(k), str) and len(fields[k]) > lim:
            raise HTTPException(status_code=422, detail=f"{k}: at most {lim} characters")
    z = _zone_call(iz.update_zone, db, site_row.id, zone_id, fields)
    db.commit()
    return {"zone": {"id": z.id, "name": z.name, "sl_t": z.sl_t, "sl_a": z.sl_a, "sl_a_note": z.sl_a_note,
                     "description": z.description, "owner": z.owner},
            **_site_info(site_row)}


@router.delete("/iec-zones/{zone_id}")
def delete_iec_zone(zone_id: int, site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                    db: DBSession = Depends(get_db)):
    """Remove a zone with its members and the conduits that touch it."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    z = _zone_call(iz.delete_zone, db, site_row.id, zone_id)
    db.commit()
    return {"deleted": zone_id, "name": z.name, **_site_info(site_row)}


@router.post("/iec-zones/{zone_id}/members")
def add_iec_zone_member(zone_id: int,
                        kind: str = Body(..., max_length=16, description="host | subnet | interface | fw_zone"),
                        ref: str = Body(..., max_length=255,
                                        description="host: IP or MAC; subnet: CIDR; interface: "
                                                    "'<firewall>/<interface>'; fw_zone: '<firewall>/<zone>' "
                                                    "or '<firewall>/<vdom>/<zone>'"),
                        note: str | None = Body(None, max_length=2000),
                        created_by: str | None = Body(None, max_length=128),
                        move: bool = Body(False, description="move it here when it is in another zone"),
                        site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """Add a member to a zone.  An asset belongs to one zone: 409 when it is
    in another zone unless ``move`` is true.  422 bad kind / reference."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    m, changed = _zone_call(iz.add_member, db, site_row.id, zone_id, kind, ref, note, created_by, move)
    db.commit()
    return {"member": {"id": m.id, "zone_id": m.zone_id, "kind": m.kind, "ref": m.ref, "note": m.note},
            "changed": changed, **_site_info(site_row)}


@router.delete("/iec-zones/members/{member_id}")
def remove_iec_zone_member(member_id: int, site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                           site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                           db: DBSession = Depends(get_db)):
    """Remove one member from its zone."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    m = _zone_call(iz.remove_member, db, site_row.id, member_id)
    db.commit()
    return {"deleted": member_id, "kind": m.kind, "ref": m.ref, **_site_info(site_row)}


@router.post("/iec-zones/import")
def import_iec_zones(source: str = Body(..., embed=True, description="subnet_zones | fortigate"),
                     created_by: str | None = Body(None, embed=True, max_length=128),
                     site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                     site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                     db: DBSession = Depends(get_db)):
    """Seed zones from the Subnets & Zones declarations (one zone per zone
    name) or from the FortiGate zones (one zone per FortiOS zone).  Existing
    zones and members are kept; assets already in a zone are skipped."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    stats = _zone_call(iz.import_zones, db, site_row.id, source, created_by)
    db.commit()
    return {"imported": stats, "source": source, **_site_info(site_row)}


@router.patch("/firewalls/{firewall_id}/sl-c")
def set_firewall_sl_c(firewall_id: int,
                      sl_c: Any = Body(None, description="SL-C 1-4; null / 'none' clears"),
                      sl_c_source: str | None = Body(None, max_length=255),
                      site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                      site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                      db: DBSession = Depends(get_db)):
    """Record the IEC 62443-4-2 capability security level (SL-C) of a
    firewall or routing switch of this site, with its source.  Shown against
    the SL-T of the conduits it carries on the Zones & Conduits page;
    documentation only (404 when the firewall is not this site's)."""
    site_row = _operation_site(db, site, site_id)
    fw = db.query(Firewall).filter(Firewall.id == firewall_id, Firewall.site_id == site_row.id).first()
    if fw is None:
        raise HTTPException(status_code=404, detail="Firewall not found in this site")
    fw.sl_c = _sl_c_param(sl_c)
    fw.sl_c_source = (sl_c_source or "").strip() or None
    db.commit()
    return {"firewall": {"id": fw.id, "name": fw.name, "sl_c": fw.sl_c, "sl_c_source": fw.sl_c_source},
            **_site_info(site_row)}


@router.get("/iec-conduits")
def list_iec_conduits(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                      site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                      db: DBSession = Depends(get_db)):
    """Declared conduits with the permitting policies and observed traffic
    between their zones (per direction), zone pairs that communicate with no
    documented conduit (incl. assets in no zone and the Internet), and
    intra-zone traffic counts.  Documentation only: never a finding."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    return {**iz.conduit_view(db, iz.ZoneModel(db, site_row.id)), **_site_info(site_row)}


@router.post("/iec-conduits")
def declare_iec_conduit(zone_a_id: int = Body(...), zone_b_id: int = Body(...),
                        name: str | None = Body(None, max_length=128), sl_t: Any = Body(None),
                        description: str | None = Body(None, max_length=4000),
                        created_by: str | None = Body(None, max_length=128),
                        sl_a: Any = Body(None), sl_a_note: str | None = Body(None, max_length=255),
                        services: str | None = Body(None, max_length=1000, description=(
                            "what the conduit is for: comma list of service names (s7comm, modbus, enip, rdp ...), "
                            "tcp/PORT, udp/PORT, PORT, or any")),
                        sources: str | None = Body(None, max_length=1000, description=(
                            "addresses / CIDRs allowed to use the conduit (comma list)")),
                        firewall: str | None = Body(None, max_length=128, description=(
                            "firewall (name or id) of the rule numbers in policy_ids")),
                        policy_ids: Any = Body(None, description=(
                            "firewall policy numbers implementing the conduit: list or '20, 21, 33'")),
                        site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """Document (or update) the conduit between two zones of this site, optionally
    with the firewall policy numbers that implement it (documentation only)."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    c, created = _zone_call(iz.upsert_conduit, db, site_row.id, zone_a_id, zone_b_id, name, sl_t, description,
                            created_by, sl_a=sl_a, sl_a_note=sl_a_note, services=services, sources=sources)
    if policy_ids not in (None, "", []):
        if not firewall:
            raise HTTPException(status_code=422, detail="firewall: required with policy_ids")
        _zone_call(iz.add_conduit_rules, db, site_row.id, c.id, firewall, policy_ids, created_by=created_by)
    db.commit()
    return {"conduit": {"id": c.id, "zone_a_id": c.zone_a_id, "zone_b_id": c.zone_b_id, "name": c.name,
                        "sl_t": c.sl_t, "sl_a": c.sl_a, "sl_a_note": c.sl_a_note, "services": c.services,
                        "sources": c.sources, "description": c.description}, "created": created, **_site_info(site_row)}


@router.patch("/iec-conduits/{conduit_id}")
def update_iec_conduit(conduit_id: int, body: dict = Body(..., description="name, sl_t, sl_a, sl_a_note, services, sources, description"),
                       site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """Change a conduit's name, SL-T, SL-A (achieved), SL-A note, services / sources (what
    the conduit is for: a finding on it whose service and source are covered is shown one
    severity step lower - view only) or description."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    fields = {k: body[k] for k in ("name", "sl_t", "sl_a", "sl_a_note", "services", "sources", "description")
              if k in body}
    for k, lim in (("name", 128), ("description", 4000), ("services", 1000), ("sources", 1000)):
        if isinstance(fields.get(k), str) and len(fields[k]) > lim:
            raise HTTPException(status_code=422, detail=f"{k}: at most {lim} characters")
    c = _zone_call(iz.update_conduit, db, site_row.id, conduit_id, fields)
    db.commit()
    return {"conduit": {"id": c.id, "zone_a_id": c.zone_a_id, "zone_b_id": c.zone_b_id, "name": c.name,
                        "sl_t": c.sl_t, "sl_a": c.sl_a, "sl_a_note": c.sl_a_note, "services": c.services,
                        "sources": c.sources, "description": c.description}, **_site_info(site_row)}


@router.post("/iec-conduits/{conduit_id}/rules", status_code=201)
def add_iec_conduit_rules(conduit_id: int,
                          firewall: str = Body(..., max_length=128, description="firewall name (or id)"),
                          policy_ids: Any = Body(..., description="policy numbers: list or '20, 21, 33'"),
                          vdom: str | None = Body(None, max_length=64),
                          note: str | None = Body(None, max_length=255),
                          created_by: str | None = Body(None, max_length=128),
                          site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                          site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                          db: DBSession = Depends(get_db)):
    """Attach firewall policies (rule numbers) to a documented conduit (owner
    2026-10-13).  Every policy must exist on that firewall (422 otherwise);
    attaching one twice is a no-op.  Documentation only - no finding changes."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    rows = _zone_call(iz.add_conduit_rules, db, site_row.id, conduit_id, firewall, policy_ids,
                      vdom=vdom or "", note=note, created_by=created_by)
    db.commit()
    return {"rules": [{"id": r.id, "firewall": r.firewall_name, "vdom": r.vdom, "policy_id": r.policy_id,
                       "note": r.note} for r in rows], **_site_info(site_row)}


@router.delete("/iec-conduits/{conduit_id}/rules/{rule_id}")
def remove_iec_conduit_rule(conduit_id: int, rule_id: int,
                            site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                            site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                            db: DBSession = Depends(get_db)):
    """Detach a firewall policy from a conduit."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    _zone_call(iz.remove_conduit_rule, db, site_row.id, conduit_id, rule_id)
    db.commit()
    return {"deleted": rule_id, **_site_info(site_row)}


@router.delete("/iec-conduits/{conduit_id}")
def delete_iec_conduit(conduit_id: int, site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """Remove a documented conduit (the zones stay)."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    c = _zone_call(iz.get_conduit, db, site_row.id, conduit_id)
    from app.models import IecConduitRule
    db.query(IecConduitRule).filter(IecConduitRule.conduit_id == c.id).delete(synchronize_session=False)
    db.delete(c)
    db.commit()
    return {"deleted": conduit_id, **_site_info(site_row)}


@router.get("/iec-zones/export")
def export_iec_zones(table: str = Query("zones", description="zones | assets | conduits"),
                     site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                     site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                     db: DBSession = Depends(get_db)):
    """CSV (UTF-8 BOM) of the zone documentation: ``zones`` (one row per
    member), ``assets`` (every host with its zone and SL-T) or
    ``conduits`` (one row per conduit / undocumented zone pair and direction)."""
    from app import iec_zones as iz
    site_row = _operation_site(db, site, site_id)
    body = _zone_call(iz.export_csv, db, iz.ZoneModel(db, site_row.id), table)
    fname = f"iec_{table}_{(site_row.code or site_row.id)}.csv"
    return Response(content=body, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"',
                             "X-Content-Type-Options": "nosniff"})


@router.get("/subnets")
def list_subnets(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                 site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                 db: DBSession = Depends(get_db)):
    """RS G3: every subnet of ONE site the data shows (capture segments,
    firewall / switch interface networks, declarations) with its VLAN,
    names, hosts, evidence, a suggested Purdue level / zone, the operator's
    declaration, devices that do not match it and interface labels that
    disagree.  ``undeclared``: subnets with hosts and no declaration."""
    from app.parsers import subnet_zones as sz
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        rows = sz.discover(db)
    return {"subnets": rows, "undeclared": sum(1 for r in rows if r["hosts"] and r["declaration"] is None),
            **_site_info(site_row)}


@router.post("/subnets")
def declare_subnet(
    cidr: str = Body(..., max_length=64, description="the subnet, e.g. 10.30.40.0/24"),
    purdue_level: Any = Body(None, description=_LEVEL_DOC + " (null = zone name only)"),
    zone_name: str | None = Body(None, max_length=128),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Declare (or update) the zone of a subnet: Purdue level and zone name.
    Hosts in it that no stronger evidence classifies take the level, and
    firewall / switch interfaces on it without an operator level take it
    too; devices whose own evidence disagrees are reported at the next
    review run (misplaced_device).  422 bad CIDR / level."""
    import ipaddress as _ipa
    from app.models import SubnetZone
    from app.parsers import subnet_zones as sz
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    try:
        net = _ipa.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"cidr: '{cidr}' is not an IPv4 / IPv6 network")
    if net.prefixlen == 0:
        raise HTTPException(status_code=422, detail="cidr: a default route (/0) is not a subnet")
    level = _level_param("purdue_level", purdue_level)
    with analysis_site(db, site_row.id):
        row = db.query(SubnetZone).filter(SubnetZone.site_id == site_row.id,
                                          SubnetZone.cidr == str(net)).first()
        created = row is None
        if created:
            row = SubnetZone(site_id=site_row.id, cidr=str(net), created_by=created_by)
            db.add(row)
        row.purdue_level = level
        row.zone_name = (zone_name or "").strip() or None
        row.note = note
        db.flush()
        applied = sz.apply(db)
        out = {"id": row.id, "cidr": row.cidr, "purdue_level": row.purdue_level, "zone_name": row.zone_name,
               "note": row.note}
    db.commit()
    return {"declaration": out, "created": created, "applied": applied, **_site_info(site_row)}


@router.delete("/subnets/{zone_id}")
def delete_subnet_zone(zone_id: int,
                       site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """Remove a subnet's zone declaration (404 when it is not this site's).
    Hosts and interfaces that took its level go back to automatic."""
    from app.models import SubnetZone
    from app.parsers import subnet_zones as sz
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    row = db.query(SubnetZone).filter(SubnetZone.id == zone_id, SubnetZone.site_id == site_row.id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Subnet zone not found")
    cidr = row.cidr
    db.delete(row)
    db.flush()
    with analysis_site(db, site_row.id):
        applied = sz.apply(db)
    db.commit()
    classify_hosts(db, site_id=site_row.id)         # hosts back to their automatic level
    return {"deleted": zone_id, "cidr": cidr, "applied": applied, **_site_info(site_row)}


@router.get("/management/networks")
def list_management_networks(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                             site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                             db: DBSession = Depends(get_db)):
    """Where management and engineering access legitimately come from, for
    ONE site.

    ``declarations``: management subnets, trusted management hosts
    (admin_ws / jump_host), management VLANs and reclassified interface /
    zone names; ``interfaces``: every firewall interface with its management
    classification and why; ``vlans``: every VLAN id the site knows and
    whether it is a management VLAN; ``suggestions``: names that say
    management but are not decided yet (they change nothing until declared);
    ``sources``: the effective management networks the checks use."""
    from app.parsers import mgmt_networks as mg
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        ctx = mg.build_context(db)
        return {"declarations": mg.list_declarations(db),
                "interfaces": mg.interface_inventory(db, ctx),
                "vlans": mg.vlan_inventory(db, ctx),
                "suggestions": mg.suggestions(db, ctx),
                "sources": [{"network": str(n), "why": d, "purpose": p} for n, d, p in ctx.nets],
                "vlan_hosts": len(ctx.host_ips),
                "checks": list(mg.MGMT_CHECKS),
                **_site_info(site_row)}


@router.post("/management/networks", status_code=201)
def declare_management_network(
    kind: str = Body(..., description="subnet | host | vlan | name"),
    cidr: str | None = Body(None, max_length=64, description="subnet / host: CIDR or IP"),
    role: str | None = Body(None, description="host: admin_ws (default) | jump_host | engineering_ws"),
    purpose: str | None = Body(None, description="management (default) | engineering; a host's follows its role"),
    vlan_id: int | None = Body(None, ge=1, le=4094, description="vlan: VLAN id"),
    firewall_id: int | None = Body(None, ge=1, description="name: firewall (omit = every firewall)"),
    name: str | None = Body(None, max_length=128, description="name: interface / zone / alias"),
    is_management: bool = Body(True, description="name: false = neither a management nor an engineering zone"),
    label: str | None = Body(None, max_length=128),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    finding_id: int | None = Body(None, ge=1, description="the finding this fixes (site is taken from it)"),
    recheck: bool = Body(True, description="re-run the management checks now"),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Declare a management or engineering subnet, a trusted host (admin
    workstation, jump host or engineering workstation), a management or
    engineering VLAN, or reclassify an interface / zone name (``purpose``;
    ``is_management`` false = neither).  Management = administering
    infrastructure; engineering = programming / configuring L0-L2 devices
    (approved toward OT equipment and for industrial writes only).
    Re-declaring with another purpose / role updates the row.  The affected
    checks are re-run and the response reports what closed (``recheck``).
    422 bad input, 404 unknown firewall / finding, 409 already declared."""
    from app.parsers import mgmt_networks as mg
    from app.parsers.site_scope import analysis_site
    site_row = _mgmt_site(db, site, site_id, finding_id)
    try:
        with analysis_site(db, site_row.id):
            row, created = mg.declare(db, site_row.id, kind=kind, cidr=cidr, role=role,
                                      vlan_id=vlan_id, firewall_id=firewall_id, name=name,
                                      is_management=is_management, purpose=purpose,
                                      label=label, note=note,
                                      created_by=created_by, finding_id=finding_id)
            out = mg.declaration_dict(db, row)
        db.commit()
    except mg.MgmtError as exc:
        db.rollback()
        raise _mgmt_http_error(exc)
    result = {"declaration": out, "created": created, **_site_info(site_row)}
    if recheck:
        try:
            result["recheck"] = mg.recheck(db, site_row.id)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            result["recheck"] = _error_stub(exc, "Management re-check failed")
    return result


@router.delete("/management/networks/{decl_id}")
def delete_management_network(
    decl_id: int,
    recheck: bool = Query(True, description="re-run the management checks now"),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Remove a declaration (404 when it is not this site's); the management
    checks are re-run, so findings it had resolved come back."""
    from app.parsers import mgmt_networks as mg
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    try:
        with analysis_site(db, site_row.id):
            row = mg.delete(db, decl_id)
            out = {"deleted": decl_id, "key": row.key}
        db.commit()
    except mg.MgmtError as exc:
        db.rollback()
        raise _mgmt_http_error(exc)
    result = {**out, **_site_info(site_row)}
    if recheck:
        try:
            result["recheck"] = mg.recheck(db, site_row.id)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            result["recheck"] = _error_stub(exc, "Management re-check failed")
    return result


@router.get("/management/fix-options")
def management_fix_options(finding_id: int = Query(..., ge=1),
                           db: DBSession = Depends(get_db)):
    """Declarations that would resolve a management finding: trusted host,
    management subnet, management VLAN or interface / zone reclassification,
    each ready to POST to /management/networks (with ``finding_id``)."""
    from app.parsers import mgmt_networks as mg
    from app.parsers.site_scope import analysis_site
    f = db.get(Finding, int(finding_id))
    if f is None:
        raise HTTPException(status_code=404, detail=f"finding {finding_id} not found")
    with analysis_site(db, f.site_id):
        return mg.fix_options(db, f)


@router.post("/management/recheck")
def management_recheck(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                       site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                       db: DBSession = Depends(get_db)):
    """Re-run every management check of the site against the current
    declarations (open findings per check before / after)."""
    from app.parsers import mgmt_networks as mg
    site_row = _operation_site(db, site, site_id)
    return {**mg.recheck(db, site_row.id), **_site_info(site_row)}


@router.get("/vpn/groups")
def list_vpn_groups(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                    db: DBSession = Depends(get_db)):
    """SSL-VPN user groups (and users) named by the site's tunnel-sourced
    policies, per firewall, with their category - it / vendor / other -
    and how it was decided (declared, guessed from the name, unclassified);
    ``declarations``: the operator's classifications."""
    from app.parsers import vpn as vp
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    with analysis_site(db, site_row.id):
        return {"groups": vp.discovered_groups(db),
                "declarations": [vp.declaration_dict(r) for r in vp.declarations(db).values()],
                "categories": list(vp.CATEGORIES), **_site_info(site_row)}


@router.post("/vpn/groups", status_code=201)
def classify_vpn_group(
    name: str = Body(..., max_length=128, description="user group (or user) name as in the policy"),
    category: str = Body(..., description="it | vendor | other"),
    firewall_id: int | None = Body(None, ge=1, description="omit = the name on every firewall of the site"),
    note: str | None = Body(None, max_length=2000),
    created_by: str | None = Body(None, max_length=128),
    finding_id: int | None = Body(None, ge=1, description="the finding this was made from (site is taken from it)"),
    recheck: bool = Body(True, description="re-run vpn_direct_to_ot now"),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Classify an SSL-VPN user group as IT staff, vendor / third party or
    other.  Vendor groups get IEC 62443-2-4 SP.07 on their
    ``vpn_direct_to_ot`` findings; the classification replaces the name
    guess.  Re-classifying updates the row.  422 bad input, 404 unknown
    firewall / finding, 409 unchanged."""
    from app.parsers import vpn as vp
    from app.parsers.site_scope import analysis_site
    site_row = _mgmt_site(db, site, site_id, finding_id)
    try:
        with analysis_site(db, site_row.id):
            row, created = vp.classify(db, site_row.id, name=name, category=category,
                                       firewall_id=firewall_id, note=note,
                                       created_by=created_by, finding_id=finding_id)
            out = vp.declaration_dict(row)
        db.commit()
    except vp.VpnGroupError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status, detail=str(exc))
    result = {"declaration": out, "created": created, **_site_info(site_row)}
    if recheck:
        try:
            result["recheck"] = vp.recheck(db, site_row.id)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            result["recheck"] = _error_stub(exc, "VPN re-check failed")
    return result


@router.delete("/vpn/groups/{decl_id}")
def unclassify_vpn_group(
    decl_id: int,
    recheck: bool = Query(True, description="re-run vpn_direct_to_ot now"),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """Remove a VPN group classification (404 when it is not this site's);
    the group falls back to the name guess."""
    from app.parsers import vpn as vp
    from app.parsers.site_scope import analysis_site
    site_row = _operation_site(db, site, site_id)
    try:
        with analysis_site(db, site_row.id):
            row = vp.unclassify(db, decl_id)
            out = {"deleted": decl_id, "key": row.key}
        db.commit()
    except vp.VpnGroupError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status, detail=str(exc))
    result = {**out, **_site_info(site_row)}
    if recheck:
        try:
            result["recheck"] = vp.recheck(db, site_row.id)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            result["recheck"] = _error_stub(exc, "VPN re-check failed")
    return result


@router.post("/topology/confirm-link")
def topology_confirm_link(
    iface_a_id: int = Body(...),
    iface_b_id: int = Body(...),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Confirm a physical link between two firewall interfaces.

    Writes `connects_to_interface_id` on both rows bidirectionally.
    The pair will no longer appear in `pending_proposals` after this call.

    Body (JSON):
      { "iface_a_id": <int>, "iface_b_id": <int> }

    Returns the confirmed link with both interface names and their firewalls.
    """
    site_row = _builder_site(db, site, site_id,
                             firewall_ids=[_iface_fw_id(db, iface_a_id), _iface_fw_id(db, iface_b_id)])
    try:
        iface_a, iface_b = confirm_link(db, iface_a_id, iface_b_id, site_id=site_row.id)
        db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=_value_error_status(exc), detail=str(exc))

    # Auto-run Purdue level suggestions after each confirmed link
    try:
        suggestion_stats = run_purdue_suggestions(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        suggestion_stats = _error_stub(exc, "Purdue suggestion run failed")

    # Auto-run cross-FW policy checks on every confirmed link
    try:
        check_stats = run_cross_fw_checks(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:  # noqa: BLE001 — don't fail the confirm on check errors
        db.rollback()
        check_stats = _error_stub(exc, "Cross-FW check run failed")

    return {
        "confirmed": True,
        "link": {
            "iface_a": {
                "id": iface_a.id, "name": iface_a.name,
                "firewall_id": iface_a.firewall_id,
            },
            "iface_b": {
                "id": iface_b.id, "name": iface_b.name,
                "firewall_id": iface_b.firewall_id,
            },
        },
        "purdue_suggestions": suggestion_stats,
        "cross_fw_checks": check_stats,
        **_site_info(site_row),
    }


@router.post("/topology/set-interface-side")
def topology_set_interface_side(
    interface_id: int = Body(...),
    side: str | None = Body(None),
    zone_label: str | None = Body(None),
    purdue_level: Any = Body(None, description=_LEVEL_DOC),
    clear: list[str] | None = Body(None),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Set operator-assigned labels on a FirewallInterface.

    These fields are never overwritten by a re-ingest of the config:
      - `side`         — "inside" or "outside" (which side of the firewall
                         this interface faces)
      - `zone_label`   — free-text zone name for display (e.g. "OT Floor",
                         "DMZ", "Corporate")
      - `purdue_level` — ISA/IEC 62443 Purdue level (0–5 or 3.5 = industrial
                         DMZ, see app/purdue.py) for this interface

    Body (JSON):
      {
        "interface_id": <int>,
        "side": "inside"|"outside"|null,
        "zone_label": "<str>"|null,
        "purdue_level": 0-5|3.5|null,
        "clear": ["side", "zone_label", "purdue_level"]   (optional)
      }

    Only provided fields are updated; omit a key (or pass null) to leave
    the existing value unchanged.  To CLEAR a value back to null (N-11),
    list the field name in `clear`; listing a field in `clear` and also
    passing a value for it is a 422.
    """
    purdue_level = _level_param("purdue_level", purdue_level)
    fw_id = _iface_fw_id(db, interface_id)
    if fw_id is None:
        raise HTTPException(status_code=404, detail=f"FirewallInterface id={interface_id} not found")
    site_row = _builder_site(db, site, site_id, firewall_ids=[fw_id])
    try:
        iface = set_interface_labels(db, interface_id, side=side, zone_label=zone_label,
                                     purdue_level=purdue_level, clear=clear,
                                     site_id=site_row.id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    db.commit()
    return {
        "updated": True,
        "interface": {
            "id": iface.id,
            "name": iface.name,
            "firewall_id": iface.firewall_id,
            "side": iface.side,
            "zone_label": iface.zone_label,
            "purdue_level": iface.purdue_level,
        },
    }


# ============================================================== PCAP (multi-FW aware) ==

@router.post("/ingest/pcap-fw")
@_reviews_after_upload('pcap (firewall-aware)')
async def ingest_pcap_fw(
    file: UploadFile = File(...),
    firewall_id: int | None = None,
    side: str | None = None,
    site: str | None = _site_query(),
    db: DBSession = Depends(get_db),
):
    """
    Upload a PCAP file with firewall-aware interface suggestion (Phase 1).

    Unlike `/ingest/pcap` (which just builds hosts and sessions),
    this endpoint:
      1. Creates a `PcapCapture` row tracking this upload.
      2. Samples up to 500 packets and collects unique IP addresses.
      3. Scores every `FirewallInterface` by what fraction of sampled
         IPs fall in its `network_cidr` subnet.
      4. Picks the best-matching interface and sets
         `PcapCapture.suggested_interface_id` and
         `PcapCapture.suggestion_confidence` ("high"≥90%, "medium"
         60–90%, "low"<60%, "none" if no topology loaded).
      5. Runs the standard PCAP session/host ingest and links every
         new `NetworkSession` to this `PcapCapture` row.

    Returns the `PcapCapture` id and suggestion so the UI can display
    "we think this is Cell-FW port2 inside (high confidence) — confirm?"

    Confirm the assignment with `POST /ingest/pcap/{capture_id}/confirm`.

    Parameters:
      `?firewall_id=<id>` — narrow the interface search to one firewall
      `?side=inside|outside` — pre-hint; stored on the capture row and
        used as a tiebreaker when two interfaces have equal scores
    """
    if side and side not in ("inside", "outside"):
        raise HTTPException(status_code=422, detail="side must be 'inside' or 'outside'")
    site_row = _require_site(db, site)
    site_id, site_out = site_row.id, _site_info(site_row)

    suffix = _upload_suffix(file.filename)
    tmp_path = await _spool_upload(file, _MAX_PCAP_BYTES, "PCAP", to_path=True, suffix=suffix,
                                   content="pcap")
    filename = _clean_upload_name(file.filename, "upload.pcap")
    try:
        out = await run_in_threadpool(
            _in_site, db, site_id,
            _ingest_pcap_fw_sync, db, tmp_path, filename, firewall_id, side, site_id,
        )
        return {**out, **site_out}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _ingest_pcap_fw_sync(db, tmp_path: str, filename, firewall_id, side,
                         site_id: int | None = None) -> dict:
    """Worker-thread body of POST /ingest/pcap-fw (T3-01).

    Capture row, hosts/sessions, classification and the industrial-write
    check are ONE transaction: any failure rolls everything back, so a failed
    upload no longer leaves a committed partial capture behind (T3-13).
    """
    import ipaddress as _iplib
    from scapy.all import PcapReader
    from scapy.layers.inet import IP

    try:
        # ---- Phase 1a: sample IPs from the first 500 packets ----
        sampled_ips: set[str] = set()
        packet_count = 0
        # B-08: validate the header and hand scapy an open file object so it
        # can never transparently gunzip the upload.
        check_capture_file(tmp_path)
        with open(tmp_path, "rb") as _fh, PcapReader(_fh) as reader:
            for pkt in reader:
                packet_count += 1
                if IP in pkt:
                    sampled_ips.add(pkt[IP].src)
                    sampled_ips.add(pkt[IP].dst)
                if packet_count >= 500:
                    break

        # ---- Phase 1b: score interfaces by IP match ----
        query = db.query(FirewallInterface).filter(
            FirewallInterface.network_cidr.isnot(None),
            FirewallInterface.is_ha.is_(False),
            FirewallInterface.is_mgmt_only.is_(False),
        )
        if site_id is not None:
            # Only this site's firewalls are candidate capture points.
            query = query.join(Firewall, Firewall.id == FirewallInterface.firewall_id) \
                         .filter(Firewall.site_id == site_id)
        if firewall_id is not None:
            fw = db.get(Firewall, firewall_id)
            if fw is None:
                raise HTTPException(status_code=404, detail=f"Firewall id={firewall_id} not found")
            if site_id is not None and fw.site_id != site_id:
                raise HTTPException(status_code=422, detail=(
                    f"Firewall id={firewall_id} belongs to another site (site_id={fw.site_id})"))
            query = query.filter(FirewallInterface.firewall_id == firewall_id)

        interfaces = query.all()

        best_iface = None
        best_score = 0.0
        best_confidence = "none"

        if sampled_ips and interfaces:
            parsed_ips = []
            for ip_str in sampled_ips:
                try:
                    parsed_ips.append(_iplib.ip_address(ip_str))
                except ValueError:
                    pass

            for iface in interfaces:
                try:
                    net = _iplib.ip_network(iface.network_cidr, strict=False)
                except ValueError:
                    continue
                hits = sum(1 for ip in parsed_ips if ip in net)
                score = hits / len(parsed_ips) if parsed_ips else 0.0
                if score > best_score:
                    best_score = score
                    best_iface = iface

            if best_score >= 0.90:
                best_confidence = "high"
            elif best_score >= 0.60:
                best_confidence = "medium"
            elif best_score > 0.0:
                best_confidence = "low"

        with _DeferredCommits(db):
            # ---- Phase 1c: create PcapCapture row ----
            capture = PcapCapture(
                site_id=site_id,
                uploaded_at=datetime.now(timezone.utc),
                firewall_id=firewall_id or (best_iface.firewall_id if best_iface else None),
                side=side,
                filename=filename,
                packet_count=packet_count,
                suggestion_confidence=best_confidence,
                suggested_interface_id=best_iface.id if best_iface else None,
                operator_confirmed=False,
                # VD-02a: a firewall the operator NAMED is a capture point;
                # one only suggested by the IP scoring is not
                association="firewall" if firewall_id is not None else None,
            )
            db.add(capture)
            db.flush()  # get capture.id before ingest_pcap runs

            # ---- Phase 1d: full session/host ingest, link sessions to capture ----
            from app.parsers import capture_point as _cp
            cp = _cp.resolve(db, site_id, firewall_id) if firewall_id is not None else None
            stats = ingest_pcap(tmp_path, db, source_file=filename,
                                pcap_capture_id=capture.id, commit=False, capture_point=cp,
                                site_id=site_id)
            _store_capture_result(capture, stats)
            db.flush()   # FO-10: classify_hosts reads the capture segment
            stats["classification"] = classify_hosts(db, site_id=site_id)
            from app.parsers.nat_sessions import reconcile as _nat_reconcile
            stats["nat_sessions"] = _nat_reconcile(db, site_id=site_id)
            stats["industrial_write_check"] = check_unauthorized_industrial_writes(db, commit=False, site_id=site_id)
        db.commit()
        capture_id = capture.id

    except HTTPException:
        db.rollback()
        raise
    except UnsupportedCaptureError as exc:
        db.rollback()
        raise _unsupported_media(f"PCAP: {exc}")
    except Exception as exc:
        db.rollback()
        raise _internal_error(exc, "Failed to process PCAP; nothing was stored",
                              status_code=400, context=f"pcap-fw {filename!r}")

    suggestion = None
    if best_iface:
        suggestion = {
            "interface_id": best_iface.id,
            "interface_name": best_iface.name,
            "firewall_id": best_iface.firewall_id,
            "network_cidr": best_iface.network_cidr,
            "confidence": best_confidence,
            "score": round(best_score, 3),
        }

    return {
        "filename": filename,
        "capture_id": capture_id,
        "packet_count": packet_count,
        "sampled_ips": len(sampled_ips),
        "suggestion": suggestion,
        **_pcap_truncation(stats),
        "stats": stats,
    }


@router.post("/ingest/pcap/{capture_id}/confirm")
@_reviews_after_upload('capture assignment')
def pcap_confirm_interface(
    capture_id: int,
    interface_id: int = Body(...),
    side: str | None = Body(None),
    db: DBSession = Depends(get_db),
):
    """
    Confirm the firewall interface assignment for a PCAP capture (Phase 2).

    After the operator reviews the suggestion from `POST /ingest/pcap-fw`,
    this endpoint:
      1. Sets `PcapCapture.interface_id` to the confirmed interface.
      2. Sets `PcapCapture.firewall_id` to that interface's firewall.
      3. Sets `PcapCapture.side` (if provided; otherwise keeps the
         value from the upload).
      4. Sets `PcapCapture.operator_confirmed = True`.

    Body (JSON):
      { "interface_id": <int>, "side": "inside"|"outside" }

    `side` is optional if it was already set at upload time.
    """
    capture = db.get(PcapCapture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail=f"PcapCapture id={capture_id} not found")

    iface = db.get(FirewallInterface, interface_id)
    if iface is None:
        raise HTTPException(status_code=404, detail=f"FirewallInterface id={interface_id} not found")
    iface_fw = db.get(Firewall, iface.firewall_id) if iface.firewall_id is not None else None
    if iface_fw is not None and iface_fw.site_id != capture.site_id:
        # Sites are isolated: a capture cannot be pinned to another site's firewall.
        raise HTTPException(status_code=422, detail=(
            f"FirewallInterface id={interface_id} belongs to a firewall of another site "
            f"(capture site_id={capture.site_id}, firewall site_id={iface_fw.site_id})"))

    if side and side not in ("inside", "outside"):
        raise HTTPException(status_code=422, detail="side must be 'inside' or 'outside'")

    capture.interface_id = interface_id
    capture.firewall_id = iface.firewall_id
    capture.capture_networks = None
    if side:
        capture.side = side
    capture.operator_confirmed = True
    try:
        reprocess = _reattribute_capture(db, capture)
    except HTTPException:
        db.rollback()
        raise

    db.commit()

    return {
        "confirmed": True,
        "capture_id": capture_id,
        "interface": {
            "id": iface.id,
            "name": iface.name,
            "firewall_id": iface.firewall_id,
            "network_cidr": iface.network_cidr,
        },
        "side": capture.side,
        "reprocess": reprocess,
    }


def _reattribute_capture(db, capture) -> dict:
    """VD-02a associate-and-reprocess body: resolve the capture point now
    stored on ``capture``, fold the routed duplicates of its hosts and
    re-run classification.  Flushes; the caller commits."""
    from app.parsers import capture_point as _cp
    try:
        cp = _cp.resolve(db, capture.site_id, capture.firewall_id, capture.interface_id,
                         capture.capture_networks)
    except _cp.CapturePointError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    capture.association = cp["association"] if cp else "none"
    with ingest_site(db, capture.site_id):
        out = _cp.reattribute(db, capture, cp)
        out["classification"] = classify_hosts(db, site_id=capture.site_id)
    return out


@router.post("/ingest/pcap/{capture_id}/associate")
@_reviews_after_upload('capture association')
def pcap_associate(
    capture_id: int,
    firewall_id: int | None = Body(None, embed=True),
    interface_id: int | None = Body(None, embed=True),
    capture_networks: str | None = Body(None, embed=True),
    side: str | None = Body(None, embed=True),
    db: DBSession = Depends(get_db),
):
    """
    Associate a capture with its capture point AFTER the upload and
    re-attribute its hosts (VD-02a associate-and-reprocess).

    For a capture uploaded before its firewall config (soft fail), or with
    the wrong interface.  Body (JSON): ``firewall_id`` and / or
    ``interface_id`` (a firewall interface - its firewall is implied), or
    ``capture_networks`` (CIDRs of a segment that is no firewall port);
    ``side`` optional.  All empty = back to capture only.

    The raw capture is not kept, so the reprocess works on the stored rows
    of the capture's sessions: a host row carrying the firewall's MAC for an
    address that is not the firewall's is folded into the real row of that
    address (sessions, observations and findings move with it), or loses
    the MAC when there is no other row.  The identified MACs are stored on
    the capture and treated as routers by later uploads of the site.
    """
    capture = db.get(PcapCapture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail=f"PcapCapture id={capture_id} not found")
    if side and side not in ("inside", "outside"):
        raise HTTPException(status_code=422, detail="side must be 'inside' or 'outside'")
    from app.parsers import capture_point as _cp
    try:
        cp = _cp.resolve(db, capture.site_id, firewall_id, interface_id, capture_networks)
    except _cp.CapturePointError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    capture.firewall_id = cp["firewall_id"] if cp else None
    capture.interface_id = cp["interface_id"] if cp else None
    capture.capture_networks = (", ".join(str(n) for n in cp["local_networks"])
                                if cp and cp["association"] == "segment" else None)
    capture.operator_confirmed = bool(cp and cp["interface_id"])
    if side:
        capture.side = side
    try:
        out = _reattribute_capture(db, capture)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise _internal_error(exc, "Failed to re-attribute the capture; nothing was changed",
                              status_code=400, context=f"capture {capture_id}")
    return {"capture_id": capture_id, "association": capture.association,
            "capture": _capture_row(db, capture), **out}


def _capture_row(db, c) -> dict:
    import json as _json
    from sqlalchemy import func
    fw = db.get(Firewall, c.firewall_id) if c.firewall_id else None
    iface = db.get(FirewallInterface, c.interface_id) if c.interface_id else None
    sugg = db.get(FirewallInterface, c.suggested_interface_id) if c.suggested_interface_id else None
    try:
        gws = _json.loads(c.gateway_macs or "[]")
    except ValueError:
        gws = []
    assoc = c.association or ("interface" if c.interface_id else "suggested" if c.firewall_id else "none")
    return {"id": c.id, "filename": c.filename, "uploaded_at": c.uploaded_at,
            "packet_count": c.packet_count, "association": assoc,
            "unassociated": assoc in ("none", "suggested"),
            "firewall_id": c.firewall_id, "firewall": fw.name if fw else None,
            "interface_id": c.interface_id, "interface": iface.name if iface else None,
            "capture_networks": c.capture_networks, "side": c.side,
            "operator_confirmed": bool(c.operator_confirmed),
            "suggested_interface_id": c.suggested_interface_id,
            "suggested_interface": sugg.name if sugg else None,
            "suggestion_confidence": c.suggestion_confidence,
            "gateway_macs": gws, "reprocessed_at": c.reprocessed_at,
            "segment": _json.loads(c.segment) if c.segment else None,
            "sessions": db.query(func.count(NetworkSession.id)).filter(
                NetworkSession.pcap_capture_id == c.id).scalar() or 0}


@router.get("/ingest/pcap/captures")
def pcap_captures(site: str | None = Query(None, description="Site id, name or code (omit: every site)"),
                  site_id: int | None = _site_filter_query(),
                  db: DBSession = Depends(get_db)):
    """
    PCAP uploads with their capture point (VD-02a), newest first.
    ``unassociated`` rows rest on the router heuristics alone - associate
    them with ``POST /ingest/pcap/{capture_id}/associate``.
    """
    sid = _require_site(db, site).id if site else _check_site_filter(db, site_id)
    q = db.query(PcapCapture)
    if sid is not None:
        q = q.filter(PcapCapture.site_id == sid)
    rows = [_capture_row(db, c) for c in q.order_by(PcapCapture.id.desc())]
    return {"site_id": sid, "captures": rows, "unassociated": sum(1 for r in rows if r["unassociated"])}


@router.post("/topology/run-checks")
def topology_run_checks(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                        site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                        db: DBSession = Depends(get_db)):
    """
    Run (or re-run) all cross-firewall ISA/IEC 62443 policy-gap checks
    across every confirmed topology link.

    This is called automatically after ``POST /topology/confirm-link``, but
    can be triggered manually at any time — for example after re-uploading
    an updated firewall config.

    Checks performed:
      - ``cross_fw_no_rules``         — firewall in the topology has no rules
      - ``cross_fw_missing_deny_all`` — no explicit deny on a cross-FW interface
      - ``cross_fw_any_any_permit``   — permit any→any on a cross-FW interface
      - ``cross_fw_asymmetric_permit``— one side allows what the other doesn't

    Existing open/acknowledged findings are not duplicated (idempotent via
    ``source_ref``).  Already-closed findings are re-opened if the condition
    still exists and no open finding exists.

    Returns a summary of findings created and skipped by check name.
    """
    site_row = _operation_site(db, site, site_id)
    try:
        suggestion_stats = run_purdue_suggestions(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise _internal_error(exc, "Purdue suggestion run failed")

    try:
        check_stats = run_cross_fw_checks(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise _internal_error(exc, "Cross-FW check run failed")

    return {
        "purdue_suggestions": suggestion_stats,
        **check_stats,
        **_site_info(site_row),
    }


@router.post("/topology/set-upstream")
def topology_set_upstream(
    firewall_id: int = Body(...),
    upstream_firewall_id: int | None = Body(None),
    purdue_level_ingress: Any = Body(None, description=_LEVEL_DOC),
    purdue_level_egress: Any = Body(None, description=_LEVEL_DOC),
    topology_confirmed: bool | None = Body(None),
    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
    db: DBSession = Depends(get_db),
):
    """
    Set the upstream_firewall_id and Purdue level bridge descriptors for a
    Firewall row.

    Body (JSON, all fields except ``firewall_id`` optional):
      {
        "firewall_id":         <int>,         -- required
        "upstream_firewall_id": <int | null>, -- null = perimeter/outermost
        "purdue_level_ingress": <0-5 | 3.5 | null>, -- less-trusted side (e.g. 3.5, industrial DMZ)
        "purdue_level_egress":  <0-5 | 3.5 | null>, -- more-trusted side (e.g. Level 3 OT LAN)
        "topology_confirmed":   <bool | null>
      }

    After writing, Purdue level suggestions are re-run so interface-level
    ``suggested_purdue_level`` values reflect the new fw_chain data.
    """
    # F-08: one validation path (0-5 and 3.5, 422) - this endpoint used to
    # cap at 0-4 with a 400 while every other one allowed 0-5.
    purdue_level_ingress = _level_param("purdue_level_ingress", purdue_level_ingress)
    purdue_level_egress = _level_param("purdue_level_egress", purdue_level_egress)
    ids = [firewall_id] + ([upstream_firewall_id] if upstream_firewall_id is not None else [])
    site_row = _builder_site(db, site, site_id, firewall_ids=ids)

    try:
        fw = set_upstream_firewall(
            db,
            site_id=site_row.id,
            firewall_id=firewall_id,
            upstream_firewall_id=upstream_firewall_id,
            purdue_level_ingress=purdue_level_ingress,
            purdue_level_egress=purdue_level_egress,
            topology_confirmed=topology_confirmed,
        )
        db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=_value_error_status(exc), detail=str(exc))

    # Re-run Purdue suggestions to pick up fw_chain source updates
    try:
        suggestion_stats = run_purdue_suggestions(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        suggestion_stats = _error_stub(exc, "Purdue suggestion run after set-upstream failed")

    return {
        "updated": True,
        "firewall": {
            "id":                    fw.id,
            "name":                  fw.name,
            "upstream_firewall_id":  fw.upstream_firewall_id,
            "purdue_level_ingress":  fw.purdue_level_ingress,
            "purdue_level_egress":   fw.purdue_level_egress,
            "topology_confirmed":    fw.topology_confirmed,
        },
        "purdue_suggestions": suggestion_stats,
        **_site_info(site_row),
    }


@router.post("/topology/suggest-purdue")
def topology_suggest_purdue(site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                            site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                            db: DBSession = Depends(get_db)):
    """
    Manually trigger a re-run of Purdue level auto-suggestion across all
    FirewallInterface rows.

    Called automatically by ``POST /topology/confirm-link``,
    ``POST /topology/run-checks``, and ``POST /topology/set-upstream``, but
    can also be triggered manually — for example after the operator updates
    zone labels, side assignments, or upstream firewall metadata without
    confirming a new link.

    Returns a summary of interfaces updated and which heuristic sourced each
    suggestion::

        {
            "interfaces_updated": int,
            "by_source": {
                "peer_link":     int,
                "fw_chain":      int,
                "role_heuristic": int,
            }
        }
    """
    site_row = _operation_site(db, site, site_id)
    try:
        stats = run_purdue_suggestions(db, site_id=site_row.id)
        db.commit()
    except Exception as exc:
        raise _internal_error(exc, "Purdue suggestion run failed")
    return {**stats, **_site_info(site_row)} if isinstance(stats, dict) else stats


@router.get("/topology/firewalls")
def list_firewalls(site_id: int | None = _site_filter_query(),
                   db: DBSession = Depends(get_db)):
    """
    List all uploaded firewall configs with their interface counts and
    PCAP capture counts. Lightweight alternative to GET /topology when
    the UI just needs a picker for upload forms.
    """
    from sqlalchemy import func as _func
    # Single grouped query for PCAP counts — avoids N+1 per-firewall COUNT queries
    pcap_counts = dict(
        db.query(PcapCapture.firewall_id, _func.count(PcapCapture.id))
        .group_by(PcapCapture.firewall_id)
        .all()
    )
    from sqlalchemy.orm import selectinload
    # selectinload: one extra query for every firewall's interfaces instead
    # of one lazy load per firewall (T3-11).
    # Site name joined in (no extra query: T3-11 caps this endpoint's queries).
    fw_q = (db.query(Firewall, Site.name)
              .outerjoin(Site, Site.id == Firewall.site_id)
              .options(selectinload(Firewall.interfaces)))
    if _check_site_filter(db, site_id) is not None:
        fw_q = fw_q.filter(Firewall.site_id == site_id)
    rows = fw_q.order_by(Firewall.id.asc()).all()
    result = []
    for fw, site_name in rows:
        result.append({
            "id": fw.id,
            "site_id": fw.site_id,
            "site_name": site_name,
            "name": fw.name,
            "vendor": fw.vendor,
            "device_name": fw.device_name,
            "source_file": fw.source_file,
            "config_uploaded_at": fw.config_uploaded_at,
            "is_multi_fw": fw.is_multi_fw,
            "topology_confirmed": fw.topology_confirmed,
            "interface_count": len(fw.interfaces or []),
            "capture_count": pcap_counts.get(fw.id, 0),
        })
    return {"firewalls": result, "count": len(result)}


# ============================================================ DELETE (F-14) ==
#
# The API has no authentication yet (owner decision), so destructive
# endpoints are DISABLED unless the operator opts in with
# IACS_ENABLE_DELETE=true.  Every delete is logged with what it removed.
# Cascades are done explicitly (not left to DB FKs) so the result is the
# same on PostgreSQL and on SQLite with IACS_SQLITE_FOREIGN_KEYS=false.

def _delete_enabled() -> bool:
    import os as _os
    return _os.environ.get("IACS_ENABLE_DELETE", "").strip().lower() in ("1", "true", "yes", "on")


def _require_delete_enabled() -> None:
    if not _delete_enabled():
        raise HTTPException(status_code=403, detail=(
            "Delete endpoints are disabled. The API has no authentication, so "
            "deleting data must be enabled explicitly by the operator: set "
            "IACS_ENABLE_DELETE=true in the server environment and restart."))


@router.delete("/findings/{finding_id}")
def delete_finding(finding_id: int, db: DBSession = Depends(get_db)):
    """Delete one finding (disabled unless IACS_ENABLE_DELETE=true).  Prefer
    closing findings (PATCH /findings/{id}/status) to keep the audit trail."""
    _require_delete_enabled()
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    summary = {"id": f.id, "check_name": f.check_name, "status": f.status,
               "severity": f.severity, "title": (f.title or "")[:200]}
    db.delete(f)
    db.commit()
    log.warning("DELETE /findings/%d: removed finding %r", finding_id, summary)
    return {"deleted": "finding", "finding": summary}


@router.delete("/attestation/{attestation_id}")
def delete_attestation(attestation_id: int, db: DBSession = Depends(get_db)):
    """Delete one attestation (disabled unless IACS_ENABLE_DELETE=true).  When
    the current attestation for its (checklist_id, baseline) row is deleted,
    the most recent remaining one for that row becomes current again."""
    _require_delete_enabled()
    a = db.get(Attestation, attestation_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    summary = {"id": a.id, "checklist_id": a.checklist_id, "baseline_id": a.baseline_id,
               "attested_by": a.attested_by, "is_current": bool(a.is_current),
               "proof_filename": a.proof_filename}
    was_current, cl, bid, sid = bool(a.is_current), a.checklist_id, a.baseline_id, a.site_id
    db.delete(a)
    db.flush()
    promoted = None
    if was_current:
        prev = (db.query(Attestation)
                  .filter(Attestation.site_id == sid,
                          Attestation.checklist_id == cl,
                          Attestation.baseline_id.is_(None) if bid is None
                          else Attestation.baseline_id == bid)
                  .order_by(Attestation.attested_at.desc(), Attestation.id.desc()).first())
        still_current = db.query(Attestation.id).filter(
            Attestation.site_id == sid, Attestation.checklist_id == cl,
            Attestation.is_current == True,  # noqa: E712
            Attestation.baseline_id.is_(None) if bid is None
            else Attestation.baseline_id == bid).first()
        if prev is not None and still_current is None:
            prev.is_current = True
            promoted = prev.id
    db.commit()
    log.warning("DELETE /attestation/%d: removed attestation %r (promoted to current: %s)",
                attestation_id, summary, promoted)
    return {"deleted": "attestation", "attestation": summary, "promoted_current_id": promoted}


@router.delete("/firewall-devices/{device_id}")
def delete_firewall_device(device_id: int, db: DBSession = Depends(get_db)):
    """Delete a firewall device with its FirewallRule and NatRule rows
    (disabled unless IACS_ENABLE_DELETE=true).  Findings that pointed at
    those rules keep their evidence; their rule_id becomes NULL."""
    _require_delete_enabled()
    from app.models import NatRule
    dev = db.get(FirewallDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Firewall device not found")
    name = dev.name
    rule_ids = [r for (r,) in db.query(FirewallRule.id)
                                .filter(FirewallRule.firewall_device_id == device_id).all()]
    unlinked = 0
    for i in range(0, len(rule_ids), 500):
        chunk = rule_ids[i:i + 500]
        unlinked += db.query(Finding).filter(Finding.rule_id.in_(chunk)) \
                      .update({Finding.rule_id: None}, synchronize_session=False)
    nat = db.query(NatRule).filter(NatRule.firewall_device_id == device_id) \
            .delete(synchronize_session=False)
    rules = db.query(FirewallRule).filter(FirewallRule.firewall_device_id == device_id) \
              .delete(synchronize_session=False)
    db.expire(dev)
    db.delete(dev)
    db.commit()
    result = {"deleted": "firewall_device", "id": device_id, "name": name,
              "firewall_rules": rules, "nat_rules": nat, "findings_unlinked": unlinked}
    log.warning("DELETE /firewall-devices/%d: %r", device_id, result)
    return result


@router.delete("/baselines/{baseline_name}")
def delete_baseline(baseline_name: str,
                    force: bool = Query(False, description="also delete an ACTIVE baseline / its attestations"),
                    site: Optional[str] = Query(None, description=_OP_SITE_DOC),
                    site_id: int | None = Query(None, ge=1, description=_OP_SITE_DOC),
                    db: DBSession = Depends(get_db)):
    """Delete a baseline with its approved-comms and approved-host rows
    (disabled unless IACS_ENABLE_DELETE=true).  Refused with 409 when the
    baseline is active or has attestations, unless ?force=true (attestations
    scoped to the baseline are then deleted too)."""
    _require_delete_enabled()
    site_row = _operation_site(db, site, site_id)   # names are unique per site
    b = (db.query(Baseline)
         .filter(Baseline.site_id == site_row.id, Baseline.name == baseline_name).first())
    if b is None:
        raise HTTPException(status_code=404, detail="Baseline not found")
    n_att = db.query(Attestation).filter(Attestation.baseline_id == b.id).count()
    if (b.is_active or n_att) and not force:
        why = []
        if b.is_active:
            why.append("it is the active baseline")
        if n_att:
            why.append(f"{n_att} attestation(s) reference it")
        raise HTTPException(status_code=409, detail=(
            f"Baseline {baseline_name!r} not deleted: {' and '.join(why)}. "
            "Repeat with ?force=true to delete it anyway."))
    comms = db.query(ApprovedCommsEntry).filter(ApprovedCommsEntry.baseline_id == b.id) \
              .delete(synchronize_session=False)
    hosts = db.query(ApprovedHost).filter(ApprovedHost.baseline_id == b.id) \
              .delete(synchronize_session=False)
    atts = db.query(Attestation).filter(Attestation.baseline_id == b.id) \
             .delete(synchronize_session=False)
    was_active = bool(b.is_active)
    db.expire(b)
    db.delete(b)
    db.commit()
    result = {"deleted": "baseline", "name": baseline_name, "was_active": was_active,
              "approved_comms": comms, "approved_hosts": hosts, "attestations": atts}
    log.warning("DELETE /baselines/%s: %r", baseline_name, result)
    return result


@router.delete("/hosts/{host_id}")
def delete_host(host_id: int,
                force: bool = Query(False, description="also delete the host's sessions"),
                db: DBSession = Depends(get_db)):
    """Delete a host (disabled unless IACS_ENABLE_DELETE=true).  Refused with
    409 while network sessions reference it, unless ?force=true: those
    sessions and their protocol details are then deleted and findings that
    pointed at them keep their evidence with session_id set to NULL."""
    _require_delete_enabled()
    from sqlalchemy import or_
    h = db.get(Host, host_id)
    if h is None:
        raise HTTPException(status_code=404, detail="Host not found")
    sess_q = db.query(NetworkSession.id).filter(or_(
        NetworkSession.src_host_id == host_id, NetworkSession.dst_host_id == host_id))
    sess_ids = [s for (s,) in sess_q.all()]
    if sess_ids and not force:
        raise HTTPException(status_code=409, detail=(
            f"Host {host_id} is referenced by {len(sess_ids)} network session(s). "
            "Repeat with ?force=true to delete the host and those sessions."))
    details = unlinked = 0
    for i in range(0, len(sess_ids), 500):
        chunk = sess_ids[i:i + 500]
        unlinked += db.query(Finding).filter(Finding.session_id.in_(chunk)) \
                      .update({Finding.session_id: None}, synchronize_session=False)
        details += db.query(ProtocolDetail).filter(ProtocolDetail.session_id.in_(chunk)) \
                     .delete(synchronize_session=False)
        db.query(NetworkSession).filter(NetworkSession.id.in_(chunk)) \
          .delete(synchronize_session=False)
    ident = {"ip": h.ip, "mac": h.mac, "hostname": h.hostname}
    from app.models import HostAddressHistory as _HAH
    db.query(_HAH).filter(_HAH.host_id == host_id).delete(synchronize_session=False)   # same on FK=off
    db.expire(h)
    db.delete(h)
    db.commit()
    result = {"deleted": "host", "id": host_id, **ident, "sessions": len(sess_ids),
              "protocol_details": details, "findings_unlinked": unlinked}
    log.warning("DELETE /hosts/%d: %r", host_id, result)
    return result


# ================================================================ SITES ==
# Multi-site phase 1 (docs/multi-site-design.md).  Sites isolate plants from
# each other; every non-log upload names its site.

_SITE_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _site_counts(db, site_ids: list[int] | None = None) -> dict[int, dict]:
    """{site_id: {firewalls, firewall_devices, hosts, open_findings}} in four
    grouped queries."""
    from sqlalchemy import func as _func

    def grouped(model, *filters):
        q = db.query(model.site_id, _func.count(model.id)).filter(*filters)
        if site_ids is not None:
            q = q.filter(model.site_id.in_(site_ids))
        return dict(q.group_by(model.site_id).all())

    fws = grouped(Firewall)
    devs = grouped(FirewallDevice)
    hosts = grouped(Host, real_host_clause())   # group marker is not a host
    from app import report_checks as _rc
    _hide = _rc.hidden_clause(db, None)          # owner 2026-10-14: excluded checks hidden app-wide
    open_f = grouped(Finding, Finding.status == "open", *([_hide] if _hide is not None else []))
    from app.models import SiteDevice
    from app.site_devices import conflict_count, pending_count
    log_devs = grouped(SiteDevice)
    pending = pending_count(db)   # held lines belong to no site yet: global
    conflicts = conflict_count(db)   # B-11: held conflict lines, global too
    ids = site_ids if site_ids is not None else [i for (i,) in db.query(Site.id)]
    return {i: {"firewalls": fws.get(i, 0), "firewall_devices": devs.get(i, 0),
                "hosts": hosts.get(i, 0), "open_findings": open_f.get(i, 0),
                "devices": log_devs.get(i, 0), "unmapped_pending": pending,
                "conflicts_pending": conflicts} for i in ids}


def _site_dict(site: Site, counts: dict | None = None) -> dict:
    out = {"id": site.id, "name": site.name, "code": site.code,
           "description": site.description, "created_at": site.created_at,
           "is_default": site.code == "default"}
    if counts is not None:
        out["counts"] = counts
    return out


def _validate_site_fields(db, name, code, exclude_id: int | None = None):
    """Normalised (name, code) or HTTP 422/409."""
    from sqlalchemy import func as _func
    if name is not None:
        name = _CTRL_RE.sub("", str(name)).strip()
        if not name or len(name) > 128:
            raise HTTPException(status_code=422, detail="name must be 1-128 characters")
        if name.isdigit():
            raise HTTPException(status_code=422, detail=(
                "name must not be all digits (a numeric 'site' value is read as a site id)"))
    if code is not None:
        code = str(code).strip().lower()
        if not _SITE_CODE_RE.match(code) or code.isdigit():
            raise HTTPException(status_code=422, detail=(
                "code must be 1-64 characters of a-z, 0-9, '-' or '_', start with a "
                "letter or digit, and not be all digits"))
    for field, value in (("name", name), ("code", code)):
        if value is None:
            continue
        col = getattr(Site, field)
        q = db.query(Site).filter(_func.lower(col) == value.lower())
        if exclude_id is not None:
            q = q.filter(Site.id != exclude_id)
        if q.first() is not None:
            raise HTTPException(status_code=409, detail=f"A site with {field} {value!r} already exists")
    # A name must not collide with another site's code (or vice versa):
    # 'site' upload values are matched against both.
    for value, other in ((name, Site.code), (code, Site.name)):
        if value is None:
            continue
        q = db.query(Site).filter(_func.lower(other) == value.lower())
        if exclude_id is not None:
            q = q.filter(Site.id != exclude_id)
        if q.first() is not None:
            raise HTTPException(status_code=409, detail=(
                f"{value!r} is already used as the name or code of another site"))
    return name, code


def _sites_rollup(db, now: datetime | None = None) -> dict:
    """Read-only cross-site aggregation (multi-site phase 4).  Grouped
    queries only (one per metric, never per site); no analysis runs and
    nothing is written."""
    from sqlalchemy import func as _func
    from app.models import Attestation, Baseline, PcapCapture
    from app.parsers.alert_engine import last_review_info

    now = now or datetime.now(timezone.utc)
    mod = _report_module()
    stale_days = mod.ATTESTATION_STALE_DAYS
    rows_needed = list(mod.ATTESTABLE_ROWS)
    sites = db.query(Site).order_by(Site.id.asc()).all()
    ids = [x.id for x in sites]
    counts = _site_counts(db, ids)

    sev: dict[int, dict[str, int]] = {i: {} for i in ids}
    for sid, sv, n in _rc_hide(db, db.query(Finding.site_id, Finding.severity, _func.count(Finding.id))
                               .filter(Finding.status == "open"), None).group_by(Finding.site_id, Finding.severity).all():
        key = (sv.value if hasattr(sv, "value") else str(sv or "info")).lower()
        sev.setdefault(sid, {})[key] = sev.get(sid, {}).get(key, 0) + n

    def _max_by_site(col, site_col):
        return dict(db.query(site_col, _func.max(col)).group_by(site_col).all())
    cfg_up = _max_by_site(Firewall.config_uploaded_at, Firewall.site_id)
    pcap_up = _max_by_site(PcapCapture.uploaded_at, PcapCapture.site_id)

    active = {sid: (bid, name) for sid, bid, name in
              db.query(Baseline.site_id, Baseline.id, Baseline.name)
                .filter(Baseline.is_active.is_(True)).order_by(Baseline.id.asc()).all()}
    cutoff = now - timedelta(days=stale_days)
    cur: dict[int, dict[str, list]] = {}   # site -> checklist -> [(baseline_id, attested_at)]
    for sid, cl, bid, at in db.query(Attestation.site_id, Attestation.checklist_id,
                                     Attestation.baseline_id, Attestation.attested_at) \
                              .filter(Attestation.is_current.is_(True),
                                      Attestation.checklist_id.in_(rows_needed)).all():
        cur.setdefault(sid, {}).setdefault(cl, []).append((bid, at))

    def _aware(d):
        return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d

    out_sites = []
    for x in sites:
        c = counts[x.id]
        bid, bname = active.get(x.id, (None, None))
        n_cur = n_stale = 0
        for row in rows_needed:
            cands = cur.get(x.id, {}).get(row, [])
            if bid is not None:   # same scoping as the report: this baseline, else baseline-less
                cands = [t for t in cands if t[0] == bid] or [t for t in cands if t[0] is None]
            if not cands:
                continue
            at = _aware(max((t[1] for t in cands if t[1] is not None), default=None))
            if at is not None and at >= cutoff:
                n_cur += 1
            else:
                n_stale += 1
        missing = len(rows_needed) - n_cur - n_stale
        uploads = [t for t in (_aware(cfg_up.get(x.id)), _aware(pcap_up.get(x.id))) if t is not None]
        by_sev = sev.get(x.id, {})
        out_sites.append({
            "id": x.id, "name": x.name, "code": x.code,
            "firewalls": c["firewalls"], "firewall_devices": c["firewall_devices"],
            "hosts": c["hosts"], "devices": c["devices"],
            "open_findings": c["open_findings"], "open_by_severity": by_sev,
            "open_critical": by_sev.get("critical", 0), "open_high": by_sev.get("high", 0),
            "last_review_at": last_review_info(x.id).get("finished_at"),
            "last_upload_at": max(uploads) if uploads else None,
            "baseline_active": bname,
            "attestation": {"state": "current" if n_cur == len(rows_needed) else "overdue",
                            "current": n_cur, "stale": n_stale, "missing": missing,
                            "total": len(rows_needed), "stale_after_days": stale_days},
        })
    totals_sev: dict[str, int] = {}
    for s_ in out_sites:
        for k, v in s_["open_by_severity"].items():
            totals_sev[k] = totals_sev.get(k, 0) + v
    return {
        "sites": out_sites,
        "unmapped_pending": counts[ids[0]]["unmapped_pending"] if ids else 0,  # global
        "conflicts_pending": counts[ids[0]]["conflicts_pending"] if ids else 0,  # global (B-11)
        "totals": {"sites": len(out_sites),
                   "firewalls": sum(s_["firewalls"] for s_ in out_sites),
                   "firewall_devices": sum(s_["firewall_devices"] for s_ in out_sites),
                   "hosts": sum(s_["hosts"] for s_ in out_sites),
                   "open_findings": sum(s_["open_findings"] for s_ in out_sites),
                   "open_by_severity": totals_sev,
                   "open_critical": totals_sev.get("critical", 0),
                   "open_high": totals_sev.get("high", 0),
                   "attestation_overdue_sites": sum(1 for s_ in out_sites if s_["attestation"]["state"] != "current")},
    }


@router.get("/sites/rollup")
def sites_rollup(db: DBSession = Depends(get_db)):
    """Read-only cross-site roll-up: per site firewalls / hosts, open
    findings by severity (critical / high called out), last review run
    (this server process only) and last config / PCAP upload time, active
    baseline, attestation state (current / overdue vs. the 1.1-1.6 rows) -
    plus totals and the global unmapped held-line count.  Aggregation only:
    sites stay isolated, no analysis runs and nothing is written."""
    return _sites_rollup(db)


@router.get("/sites")
def list_sites(request: Request, db: DBSession = Depends(get_db)):
    """Every site, oldest first, with per-site counts (firewalls,
    firewall_devices, hosts, open_findings, devices = registered log
    devices) plus ``unmapped_pending`` (held log lines of unmapped devices -
    global, they belong to no site yet) and ``conflicts_pending`` (B-11:
    held lines waiting for a conflict resolution - global too)."""
    # FI-01: a fresh install has no site until the operator creates one
    # (listing them never creates one).
    sites = db.query(Site).order_by(Site.id.asc()).all()
    counts = _site_counts(db, [x.id for x in sites])
    return [_site_dict(x, counts.get(x.id)) for x in sites]


@router.post("/sites", status_code=201)
def create_site(
    name: str = Body(..., max_length=128),
    code: str | None = Body(None, max_length=64,
                            description="short slug; derived from name when omitted"),
    description: str | None = Body(None, max_length=1024),
    db: DBSession = Depends(get_db),
):
    """Create a site.  Body (JSON): ``{"name": "Plant A", "code": "plant-a",
    "description": "..."}`` - ``code`` is optional (slug of the name).
    409 when the name or code is taken (case-insensitive)."""
    from app.sites import slugify
    if code is None or not str(code).strip():
        code = slugify(name or "")
    name, code = _validate_site_fields(db, name, code)
    site = Site(name=name, code=code,
                description=(description.strip() or None) if description else None)
    db.add(site)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A site with that name or code already exists")
    db.refresh(site)
    return _site_dict(site, _site_counts(db, [site.id])[site.id])


def _get_site_or_404(db, site_id: int) -> Site:
    site = db.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail=f"Site id={site_id} not found")
    return site


@router.get("/sites/{site_id}")
def get_site(site_id: int, db: DBSession = Depends(get_db)):
    site = _get_site_or_404(db, site_id)
    return _site_dict(site, _site_counts(db, [site.id])[site.id])


@router.patch("/sites/{site_id}")
def update_site(
    site_id: int,
    name: str | None = Body(None, max_length=128),
    code: str | None = Body(None, max_length=64),
    description: str | None = Body(None, max_length=1024),
    db: DBSession = Depends(get_db),
):
    """Rename a site / change its code or description (only the fields
    given).  Data stays attached by id, so renaming is always safe."""
    site = _get_site_or_404(db, site_id)
    name, code = _validate_site_fields(db, name, code, exclude_id=site.id)
    if name is not None:
        site.name = name
    if code is not None:
        site.code = code
    if description is not None:
        site.description = description.strip() or None
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A site with that name or code already exists")
    return _site_dict(site, _site_counts(db, [site.id])[site.id])


def _site_data_counts(db, site_id: int) -> dict[str, int]:
    """Rows per site-scoped table for one site (only non-zero entries)."""
    from sqlalchemy import func as _func
    from app.models import SiteScoped
    from app.db import Base as _Base
    out = {}
    for mapper in _Base.registry.mappers:
        cls = mapper.class_
        if isinstance(cls, type) and issubclass(cls, SiteScoped):
            n = db.query(_func.count(cls.id)).filter(cls.site_id == site_id).scalar() or 0
            if n:
                out[cls.__tablename__] = n
    return out


def _purge_site_data(db, site_id: int) -> dict[str, int]:
    """Delete every row of the site, children first.  References from other
    sites' rows (only possible in phase 1 through shared natural keys) are
    set to NULL rather than deleted."""
    from sqlalchemy import or_, select
    from app.models import (HostAddressHistory, MacTableEntry, NatRule, SwitchVlan)
    nosync = {"synchronize_session": False}
    removed: dict[str, int] = {}

    def ids(model):
        return select(model.id).where(model.site_id == site_id)

    host_ids = ids(Host)
    fw_ids = ids(Firewall)
    iface_ids = select(FirewallInterface.id).where(FirewallInterface.firewall_id.in_(fw_ids))
    sess_ids = select(NetworkSession.id).where(or_(NetworkSession.src_host_id.in_(host_ids),
                                                   NetworkSession.dst_host_id.in_(host_ids)))
    q = db.query
    # findings of the site go first; other sites' findings lose their links
    removed["findings"] = q(Finding).filter(Finding.site_id == site_id).delete(**nosync)
    q(Finding).filter(Finding.session_id.in_(sess_ids)).update({Finding.session_id: None}, **nosync)
    q(Finding).filter(Finding.rule_id.in_(ids(FirewallRule))).update({Finding.rule_id: None}, **nosync)
    q(Finding).filter(Finding.forti_event_id.in_(ids(FortiAnalyzerEvent))) \
        .update({Finding.forti_event_id: None}, **nosync)
    # traffic
    removed["protocol_details"] = q(ProtocolDetail).filter(
        ProtocolDetail.session_id.in_(sess_ids)).delete(**nosync)
    removed["network_sessions"] = q(NetworkSession).filter(NetworkSession.id.in_(
        select(NetworkSession.id).where(or_(NetworkSession.src_host_id.in_(host_ids),
                                            NetworkSession.dst_host_id.in_(host_ids))))
    ).delete(**nosync)
    q(NetworkSession).filter(NetworkSession.pcap_capture_id.in_(ids(PcapCapture))) \
        .update({NetworkSession.pcap_capture_id: None}, **nosync)
    removed["host_address_history"] = q(HostAddressHistory).filter(
        HostAddressHistory.host_id.in_(host_ids)).delete(**nosync)
    removed["hosts"] = q(Host).filter(Host.site_id == site_id).delete(**nosync)
    from app.models import ConnectionAttempt
    removed["connection_attempts"] = q(ConnectionAttempt).filter(
        ConnectionAttempt.site_id == site_id).delete(**nosync)
    removed["pcap_captures"] = q(PcapCapture).filter(PcapCapture.site_id == site_id).delete(**nosync)
    for col in (PcapCapture.interface_id, PcapCapture.suggested_interface_id):
        q(PcapCapture).filter(col.in_(iface_ids)).update({col: None}, **nosync)
    q(PcapCapture).filter(PcapCapture.firewall_id.in_(fw_ids)).update({PcapCapture.firewall_id: None}, **nosync)
    # phase-2/3 declarations (AU: every SiteScoped root table _site_data_counts
    # counts must be purged here, or the site delete hits the sites.id FK)
    from app.models import (AccessPathHop, AccessPathTag, CheckEvaluation, FirewallConfigText, IecConduit,
                            IecConduitRule, IecZone, IecZoneMember, InventoryImportMapping, ManagementNetwork,
                            ReportCheckExclusion, VpnUserGroup)
    for model in (AccessPathTag, AccessPathHop, VpnUserGroup, ManagementNetwork,
                  IecConduitRule, IecConduit, IecZoneMember, IecZone, InventoryImportMapping, CheckEvaluation,
                  ReportCheckExclusion, FirewallConfigText):
        removed[model.__tablename__] = q(model).filter(model.site_id == site_id).delete(**nosync)
    q(Firewall).filter(Firewall.site_id == site_id).update(
        {Firewall.ha_group_id: None, Firewall.paired_group_id: None}, **nosync)
    removed["firewall_groups"] = q(FirewallGroup).filter(FirewallGroup.site_id == site_id).delete(**nosync)
    # firewalls
    removed["nat_rules"] = q(NatRule).filter(NatRule.site_id == site_id).delete(**nosync)
    removed["firewall_rules"] = q(FirewallRule).filter(FirewallRule.site_id == site_id).delete(**nosync)
    removed["firewall_devices"] = q(FirewallDevice).filter(FirewallDevice.site_id == site_id).delete(**nosync)
    for model in (NatRule, FirewallRule, FirewallDevice):
        q(model).filter(model.firewall_id.in_(fw_ids)).update({model.firewall_id: None}, **nosync)
    for col in (FirewallInterface.connects_to_interface_id, FirewallInterface.parent_interface_id):
        q(FirewallInterface).filter(col.in_(iface_ids)).update({col: None}, **nosync)
    removed["firewall_interfaces"] = q(FirewallInterface).filter(
        FirewallInterface.firewall_id.in_(fw_ids)).delete(**nosync)
    q(Firewall).filter(Firewall.upstream_firewall_id.in_(fw_ids)) \
        .update({Firewall.upstream_firewall_id: None}, **nosync)
    removed["firewalls"] = q(Firewall).filter(Firewall.site_id == site_id).delete(**nosync)
    removed["firewall_zones"] = q(FirewallZone).filter(FirewallZone.site_id == site_id).delete(**nosync)
    # switches / logs
    for model in (SwitchInterface, SwitchVlan, MacTableEntry, FortiAnalyzerEvent):
        removed[model.__tablename__] = q(model).filter(model.site_id == site_id).delete(**nosync)
    # baselines / attestations
    bl_ids = ids(Baseline)
    removed["attestations"] = q(Attestation).filter(Attestation.site_id == site_id).delete(**nosync)
    q(Attestation).filter(Attestation.baseline_id.in_(bl_ids)).update({Attestation.baseline_id: None}, **nosync)
    removed["approved_comms"] = q(ApprovedCommsEntry).filter(
        ApprovedCommsEntry.baseline_id.in_(bl_ids)).delete(**nosync)
    removed["approved_hosts"] = q(ApprovedHost).filter(ApprovedHost.baseline_id.in_(bl_ids)).delete(**nosync)
    removed["baselines"] = q(Baseline).filter(Baseline.site_id == site_id).delete(**nosync)
    # safety net: a SiteScoped root table this function does not know yet
    from app.models import SiteScoped as _SS
    from app.db import Base as _Base
    for mapper in _Base.registry.mappers:
        cls = mapper.class_
        if isinstance(cls, type) and issubclass(cls, _SS) and cls.__tablename__ not in removed:
            n = q(cls).filter(cls.site_id == site_id).delete(**nosync)
            if n:
                removed[cls.__tablename__] = n
    return {k: v for k, v in removed.items() if v}


@router.delete("/sites/{site_id}")
def delete_site(site_id: int,
                force: bool = Query(False, description="also delete ALL of the site's data"),
                db: DBSession = Depends(get_db)):
    """Delete a site (disabled unless IACS_ENABLE_DELETE=true).  Refused with
    409 for the last remaining site, and while the site has any data unless
    ?force=true - then every row of the site (hosts, sessions, firewalls,
    rules, findings, baselines, attestations, ...) is deleted with it."""
    _require_delete_enabled()
    site = _get_site_or_404(db, site_id)
    if db.query(Site).count() <= 1:
        raise HTTPException(status_code=409, detail="The last remaining site cannot be deleted")
    data = _site_data_counts(db, site_id)
    if data and not force:
        raise HTTPException(status_code=409, detail=(
            f"Site {site.name!r} still has data ({', '.join(f'{k}: {v}' for k, v in data.items())}). "
            "Repeat with ?force=true to delete the site AND all of its data."))
    removed = _purge_site_data(db, site_id) if data else {}
    from sqlalchemy import select as _select
    from app.models import SiteDevice, SiteDeviceSerial
    dev_ids = _select(SiteDevice.id).where(SiteDevice.site_id == site_id)
    db.query(SiteDeviceSerial).filter(SiteDeviceSerial.device_id.in_(dev_ids)).delete(
        synchronize_session=False)   # B-12: member serials go with their devices
    n_dev = db.query(SiteDevice).filter(SiteDevice.site_id == site_id).delete(
        synchronize_session=False)   # registry rows only route log lines
    if n_dev:
        removed["site_devices"] = n_dev
    summary = {"id": site.id, "name": site.name, "code": site.code}
    db.expire(site)
    db.delete(site)
    db.commit()
    log.warning("DELETE /sites/%d: removed site %r with data %r", site_id, summary, removed)
    return {"deleted": "site", "site": summary, "data_removed": removed}


# ========================================================= SITE DEVICES ==
# Multi-site phase 3 (docs/multi-site-design.md, app/site_devices.py): the
# registry that routes log lines to sites, and the unmapped-device queue.

def _sd_out(db, rows) -> list:
    from app.site_devices import device_dict
    names = site_names(db)
    return [device_dict(r, names) for r in rows]


@router.get("/site-devices")
def list_site_devices(
    response: Response,
    site_id: int | None = _site_filter_query(),
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    db: DBSession = Depends(get_db),
):
    """Registered log devices (name, serial, vendor, site, source
    config_upload | manual), optionally of one site."""
    from app.models import SiteDevice
    _check_site_filter(db, site_id)
    q = db.query(SiteDevice)
    if site_id is not None:
        q = q.filter(SiteDevice.site_id == site_id)
    q = q.order_by(SiteDevice.site_id, SiteDevice.device_name, SiteDevice.id)
    return _sd_out(db, _page(q, response, limit, offset).all())


@router.get("/site-devices/unmapped")
def list_unmapped_devices(
    detail: bool = Query(False, description="include the held lines of each device"),
    status: str = Query("pending", pattern="^(pending|replayed|discarded)$"),
    device_key: str | None = Query(None, description="only this device (normalised name)"),
    limit: int = Query(100, ge=1, le=1000, description="lines per device with detail=true"),
    db: DBSession = Depends(get_db),
):
    """Log lines held because their device is not mapped to a site, grouped
    by device (``device_key`` = normalised device name, '' for lines with no
    device identity): count, first/last seen, vendor, serial, a sample line.
    ``pending_lines`` is the total for the console badge."""
    from app.site_devices import unmapped_summary
    return unmapped_summary(db, status=status, detail=detail, device_key=device_key, limit=limit)


@router.post("/site-devices/unmapped/discard")
def discard_unmapped_device(
    device_key: str = Body(..., embed=True, max_length=255),
    db: DBSession = Depends(get_db),
):
    """Discard every pending held line of ``device_key`` (they are purged by
    retention).  Body: ``{"device_key": "fw-x"}``."""
    _require_delete_enabled()
    from app.site_devices import discard_unmapped, pending_count
    n = discard_unmapped(db, device_key)
    db.commit()
    return {"device_key": device_key.strip().lower(), "discarded": n,
            "pending_lines": pending_count(db)}


@router.post("/site-devices/unmapped/purge")
def purge_unmapped_lines(
    days: int | None = Query(None, ge=0, le=3650,
                             description="retention in days (default IACS_UNMAPPED_RETENTION_DAYS, 30)"),
    db: DBSession = Depends(get_db),
):
    """Retention: delete replayed / discarded held lines and pending ones
    older than the retention period.  Also runs daily from the scheduler."""
    _require_delete_enabled()
    from app.site_devices import purge_unmapped, pending_count
    out = purge_unmapped(db, days)
    out["pending_lines"] = pending_count(db)
    return out


# ----------------------------------------------------------- B-11 conflicts --
# A line whose serial differs from the serial registered for its device name,
# or whose ?site= names another site than its device's, is never routed by
# guess: it is held (unmapped_log_events.kind) until an operator decides.

@router.get("/site-devices/conflicts")
def list_device_conflicts(
    detail: bool = Query(False, description="include the held lines of each conflict"),
    site_id: int | None = Query(None, description="only conflicts whose registered or "
                                                  "requested (?site) site is this one"),
    kind: str | None = Query(None, pattern="^(serial_conflict|site_mismatch|ha_candidate)$"),
    limit: int = Query(100, ge=1, le=1000, description="lines per conflict with detail=true"),
    db: DBSession = Depends(get_db),
):
    """Pending routing conflicts grouped by (device_key, kind, serial):
    ``serial_conflict`` (the line's serial differs from the serial registered
    for its device name), ``ha_candidate`` (B-12: the same, for a device
    registered as an HA cluster - possibly an unknown member) and
    ``site_mismatch`` (a ?site= upload named another site than the
    device's).  Each group: count, first/last seen, the
    registered device (id, site, serial), the line serial, vendor, requested
    site(s), a sample line, and whether ``different_device`` can apply.
    ``pending_conflicts`` + ``pending_lines`` feed the console badge."""
    from app.site_devices import conflicts_summary
    _check_site_filter(db, site_id)
    return conflicts_summary(db, detail=detail, site_id=site_id, kind=kind, limit=limit)


@router.post("/site-devices/conflicts/resolve")
def resolve_device_conflict(
    device_key: str = Body(..., max_length=255, description="the conflict's device_key"),
    kind: str = Body(..., pattern="^(serial_conflict|site_mismatch|ha_candidate)$"),
    action: str = Body(..., pattern="^(same_device|different_device|discard|add_ha_member)$"),
    serial: str | None = Body(None, max_length=128, description="the conflict's line serial"),
    site: str | None = Body(None, description="different_device: site (id, name or code)"),
    device_name: str | None = Body(None, max_length=255,
                                   description="different_device: name (default device_key)"),
    device_id: int | None = Body(None, description="same_device: the registered device, "
                                                   "when the conflict names none"),
    resolved_by: str | None = Body(None, max_length=128, description="optional, for the audit"),
    mark_ha: bool = Body(False, description="add_ha_member: confirm that a device not yet "
                                            "registered as an HA cluster is one (marks it HA)"),
    db: DBSession = Depends(get_db),
):
    """Resolve one conflict group and replay its held lines through the
    normal ingest path (stored, deduplicated, real-time checks run in the
    chosen site).  ``same_device``: the registered device sent them (a
    replaced unit: its serial becomes the line's serial,
    ``serial_source=conflict_resolution``) -> replayed into its site.
    ``different_device`` + ``site`` (+ ``device_name``): a new device with
    the line's serial is registered there -> replayed there; future lines
    route there by serial.  ``add_ha_member`` (B-12): the line's serial
    becomes a member serial of the registered HA device (409 when the device
    is not HA unless ``mark_ha: true``, when the cluster is full, or when the
    serial is registered elsewhere) -> replayed into the device's site;
    future lines route there.  ``discard`` (needs IACS_ENABLE_DELETE=true):
    the held lines are dropped.  Stored data is never moved.  Every
    resolution is recorded (GET /site-devices/conflicts/resolutions)."""
    from app.site_devices import ResolveError, conflict_count, pending_count, resolve_conflict
    if action == "discard":
        _require_delete_enabled()
    site_row = _require_site(db, site) if (action == "different_device" and site not in (None, "")) else None
    try:
        out = resolve_conflict(db, device_key, kind, serial, action, site=site_row,
                               device_name=device_name, device_id=device_id,
                               resolved_by=resolved_by, mark_ha_device=mark_ha,
                               evaluate=evaluate_event)
    except ResolveError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise _sd_conflict("the device / serial is already registered")
    db.commit()
    out["pending_conflicts"] = conflict_count(db)
    out["pending_lines"] = pending_count(db)
    return out


@router.get("/site-devices/conflicts/resolutions")
def list_conflict_resolutions(
    response: Response,
    limit: int = _limit_param(),
    offset: int = _offset_param(),
    db: DBSession = Depends(get_db),
):
    """Audit trail of conflict resolutions, newest first (action, conflict,
    registered device before the change, target site / device, replay
    counts, timestamp, optional resolved_by)."""
    from app.models import DeviceConflictResolution as R
    from app.site_devices import resolution_dict
    q = db.query(R).order_by(R.id.desc())
    names = site_names(db)
    return [resolution_dict(r, names) for r in _page(q, response, limit, offset).all()]


def _sd_conflict(exc_or_msg) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc_or_msg))


@router.post("/site-devices", status_code=201)
def create_site_device(
    response: Response,
    site: str | int = Body(..., description="site id, name or code"),
    device_name: str | None = Body(None, max_length=255),
    serial: str | None = Body(None, max_length=128),
    vendor: str | None = Body(None, max_length=32),
    db: DBSession = Depends(get_db),
):
    """Map a device to a site (source=manual) and REPLAY its pending held
    lines into that site (stored, checks run; marked replayed).  Body:
    ``{"site": "plant-a", "device_name": "fw-x", "serial": "FGT...",
    "vendor": "fortinet"}`` (device_name or serial required).  409 when the
    device is registered to another site (PATCH it to remap); 200 when it
    already was mapped to this site."""
    from app.site_devices import device_dict, register
    site_row = _require_site(db, site)
    if not (device_name or "").strip() and not (serial or "").strip():
        raise HTTPException(status_code=422, detail="device_name or serial is required")
    reg = register(db, site_row.id, device_name, serial, vendor, source="manual")
    if reg.conflict:
        db.rollback()
        raise _sd_conflict(reg.message + " (PATCH /site-devices/{id} remaps a device)")
    # C-06: replay the device's pending held lines - but _pending_for only
    # (re)routes an UNAMBIGUOUS match (by member serial, or by a name that is
    # unique across sites), so a no-op POST can no longer guess a serial-less
    # held line of an ambiguous name into this site.
    replay = replay_pending(db, reg.row, evaluate=evaluate_event)
    db.commit()
    if reg.status != "created":
        response.status_code = 200
    return {**device_dict(reg.row, site_names(db)), "status": reg.status, "replay": replay}


def _get_site_device_or_404(db, device_id: int):
    from app.models import SiteDevice
    row = db.get(SiteDevice, device_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Site device id={device_id} not found")
    return row


@router.patch("/site-devices/{device_id}")
def update_site_device(
    device_id: int,
    site: str | int | None = Body(None, description="remap to this site (id, name or code)"),
    device_name: str | None = Body(None, max_length=255),
    serial: str | None = Body(None, max_length=128, description="'' clears it"),
    vendor: str | None = Body(None, max_length=32),
    db: DBSession = Depends(get_db),
):
    """Edit / remap a device.  Remapping affects NEW log lines only: events
    and findings already stored stay in the old site.  Still-pending held
    lines of the device are replayed into its (new) site."""
    from app.site_devices import (DeviceConflict, check_unambiguous, device_dict,
                                  normalise_name, normalise_serial)
    from app.models import utcnow as _utcnow
    row = _get_site_device_or_404(db, device_id)
    new_site = _require_site(db, site).id if site not in (None, "") else row.site_id
    new_name = normalise_name(device_name) if device_name is not None else row.device_name
    new_serial = normalise_serial(serial) if serial is not None else row.serial
    if not new_name:
        raise HTTPException(status_code=422, detail="device_name must not be empty")
    try:
        check_unambiguous(db, new_site, new_name, new_serial, exclude_id=row.id)
    except DeviceConflict as exc:
        raise _sd_conflict(exc)
    old_site = row.site_id
    if new_serial != row.serial:
        if len(row.serials) > 1:
            raise _sd_conflict(f"device {row.device_name!r} is an HA cluster with "
                               f"{len(row.serials)} member serials; manage them with "
                               "POST/DELETE /site-devices/{id}/serials")
        from app.site_devices import set_serial
        set_serial(row, new_serial, "manual")
    row.site_id, row.device_name = new_site, new_name
    if vendor is not None:
        row.vendor = vendor.strip()[:32] or None
    row.source = "manual"
    row.updated_at = _utcnow()
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise _sd_conflict(f"device {new_name!r} / serial {new_serial!r} is already registered")
    replay = replay_pending(db, row, evaluate=evaluate_event)
    db.commit()
    return {**device_dict(row, site_names(db)), "remapped": old_site != new_site,
            "previous_site_id": old_site, "replay": replay}


@router.post("/site-devices/{device_id}/serials", status_code=201)
def add_site_device_serial(
    device_id: int,
    response: Response,
    serial: str = Body(..., embed=True, min_length=1, max_length=128),
    db: DBSession = Depends(get_db),
):
    """B-12: pre-register a member serial of an HA cluster (or the first
    serial of a device without one).  Lines carrying it route to this
    device's site from now on, and lines already held for it (HA candidates
    / serial conflicts of this device, unmapped lines under its name) are
    replayed there.  409 when the serial is registered to any other device
    (any site), when the device is standalone and already has a serial, or
    when the cluster already has the maximum number of members
    (IACS_HA_MAX_MEMBERS, FGCP: 4); 200 when it already is a member."""
    from app.site_devices import (ACTION_MANUAL_MEMBER, MemberError, add_member_and_replay,
                                  conflict_count, device_dict, pending_count)
    row = _get_site_device_or_404(db, device_id)
    try:
        out = add_member_and_replay(db, row, serial, "manual", ACTION_MANUAL_MEMBER,
                                    evaluate=evaluate_event)
    except MemberError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise _sd_conflict(f"serial {serial.strip()!r} is already registered")
    db.commit()
    if not out["created"]:
        response.status_code = 200
    return {**device_dict(row, site_names(db)), "added": out["member"], "created": out["created"],
            "replay": out["replay"], "pending_conflicts": conflict_count(db),
            "pending_lines": pending_count(db)}


@router.delete("/site-devices/{device_id}/serials/{serial}")
def delete_site_device_serial(device_id: int, serial: str, db: DBSession = Depends(get_db)):
    """B-12: remove one member serial from a device (disabled unless
    IACS_ENABLE_DELETE=true).  Stored events stay; new lines carrying the
    serial are held again (HA candidate / serial conflict)."""
    from app.site_devices import device_dict, normalise_serial
    _require_delete_enabled()
    row = _get_site_device_or_404(db, device_id)
    want = normalise_serial(serial)
    m = next((x for x in row.serials if x.serial == want), None)
    if m is None:
        raise HTTPException(status_code=404,
                            detail=f"serial {want!r} is not a member of site device id={device_id}")
    row.serials.remove(m)
    from app.models import utcnow as _utcnow
    row.updated_at = _utcnow()
    db.commit()
    log.warning("DELETE /site-devices/%d/serials/%s", device_id, want)
    return {"deleted": "site_device_serial", "serial": want, "device": device_dict(row, site_names(db))}


@router.delete("/site-devices/{device_id}")
def delete_site_device(device_id: int, db: DBSession = Depends(get_db)):
    """Unregister a device (disabled unless IACS_ENABLE_DELETE=true).  Its
    stored events stay; new lines from it are held as unmapped."""
    from app.site_devices import device_dict
    _require_delete_enabled()
    row = _get_site_device_or_404(db, device_id)
    out = device_dict(row, site_names(db))
    db.delete(row)
    db.commit()
    log.warning("DELETE /site-devices/%d: %r", device_id, out)
    return {"deleted": "site_device", **out}


# ============================================================ REPORTS (F-02) ==

def _report_module():
    """generate_report.py lives at the project root (next to app/)."""
    try:
        import generate_report as mod
    except ImportError:
        import importlib.util
        path = Path(__file__).resolve().parent.parent.parent / "generate_report.py"
        spec = importlib.util.spec_from_file_location("generate_report", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


@router.get("/reports/compliance.pdf", response_class=StreamingResponse)
async def compliance_report_pdf(
    baseline: str | None = Query(None, max_length=255,
                                 description="baseline for attestation scope (default: active)"),
    include_closed: bool = Query(False, description="include closed findings"),
    site: str | None = Query(None, max_length=128,
                             description="site of the report (id, name or code)"),
    site_id: int | None = Query(None, ge=1, description="site of the report (id)"),
    all_sites: bool = Query(False, description=(
        "explicit all-sites roll-up: one section per site (sites are isolated)")),
    target_sl: str | None = Query(None, max_length=8, description=(
        "ISA/IEC 62443 target security level 0-4: leave out checks and findings whose "
        "62443-3-3 requirements apply only above it (default: every level)")),
    include_zones: bool = Query(True, description=(
        "IEC 62443-3-2 Zones and Conduits section next to the attestation, and device findings "
        "judged against their zone SL-T (only when the site has zones; findings are unchanged)")),
    all_checks: bool = Query(False, description=(
        "ignore the site's check selection (Reports page, /reports/check-selection): report every check")),
    layout: str = Query("public", pattern="^(public)$", description="public = the compliance report (cover table, executive summary, findings by area)"),
    db: DBSession = Depends(get_db),
):
    """ISA/IEC 62443 compliance PDF built from the live database (same
    output as `python generate_report.py`).  Multi-site: the report covers
    ONE site (``site``/``site_id``; required when several sites exist) or,
    with ``all_sites=true``, every site in its own section.  Rendering runs
    in the threadpool so it never blocks the event loop."""
    import io as _io
    mod = _report_module()
    sl_t, _ = _sl_fr_params(target_sl, None)
    if all_sites:
        if site_id is not None:
            raise HTTPException(status_code=422, detail="all_sites=true excludes site_id")
        label = site  # free-text cover label for a roll-up
        opts = dict(all_sites=True, site=label)
    else:
        # ``site`` is a site reference; a value that names no site is kept as
        # the free-text cover label (pre-multi-site behaviour) and the site
        # then comes from site_id / is derived.
        ref = find_site(db, site) if site else None
        label = None if ref is not None else site
        site_row = _operation_site(db, ref.id if ref is not None else None, site_id)
        opts = dict(site=label or site_row.name, site_id=site_row.id)
    try:
        pdf = await run_in_threadpool(mod.generate_report_bytes, db, baseline=baseline,
                                      include_closed=include_closed, target_sl=sl_t,
                                      include_zones=include_zones, apply_check_selection=not all_checks,
                                      layout=layout, **opts)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return StreamingResponse(
        _io.BytesIO(pdf), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="iasc_compliance_{stamp}.pdf"',
                 "Content-Length": str(len(pdf))})


def _audit_report_module():
    """generate_audit_report.py lives at the project root (next to generate_report.py)."""
    try:
        import generate_audit_report as mod
    except ImportError:
        import importlib.util
        path = Path(__file__).resolve().parent.parent.parent / "generate_audit_report.py"
        spec = importlib.util.spec_from_file_location("generate_audit_report", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


@router.post("/reports/audit-checklist")
async def audit_checklist_report(
    format: str = Query("pdf", pattern="^(pdf|csv|json)$", description=(
        "pdf (default): the audit report in the technical-report layout; csv: one line per finding; json: the preview "
        "(counts per status / severity / domain, the finding list, workbook notes)")),
    scope: str = Query("findings", pattern="^(findings|assessed|all)$", description=(
        "findings (default): checks rated Non-compliant / Partially compliant plus checks with a recorded finding, "
        "severity or recommendation not rated Compliant / Not applicable; assessed: every status but Not assessed; "
        "all: every check")),
    order: str = Query("severity", pattern="^(severity|checklist)$", description=(
        "analysis order: severity (High, Medium, Low, unrated; then checklist order) or checklist (row order)")),
    site: str | None = Query(None, max_length=128, description=(
        "site whose Report details fill the cover, distribution list, revision history and constraints (optional)")),
    site_id: int | None = Query(None, ge=1, description="site of the Report details (id, optional)"),
    file: UploadFile = File(...),
    details: str | None = Form(None, max_length=60000, description=(
        "JSON with the report details given for this report, overriding the site's stored ones: client_name (Prepared for), "
        "author, author_email, report_date (YYYY-MM-DD), project_name, version, classification, constraints, "
        "pocs ([{name, role, email}] - the client's points of contact, any number), consultants ([{name, role, email}] - the "
        "assessor team, any number), or distribution ([{name, role, email, side: client | assessor}]), revisions")),
    db: DBSession = Depends(get_db),
):
    """Owner 2026-10-24: the ISA/IEC 62443 audit report from a filled-in Master Audit
    Checklist workbook (``ISA62443_Master_Audit_Checklist.xlsx``, sheet *Master Checklist*).
    One report finding per checklist row: the Check title is the title, the Audit check the
    details, with the Domain and the auditor's Finding / Observation, Evidence Reviewed,
    Severity, Recommendation, Owner and Target Date.  Nothing is stored; the upload is read
    once.  Same output as ``python generate_audit_report.py``."""
    import io as _io
    from app import audit_checklist as ac
    site_details = None
    if site not in (None, "") or site_id is not None:
        from app.models import ReportDetails
        site_row = _operation_site(db, site, site_id)
        row = db.query(ReportDetails).filter(ReportDetails.site_id == site_row.id).one_or_none()
        site_details = _report_details_dict(row, site_row)
    given = None
    if details is not None and details.strip():
        try:
            raw = json.loads(details)
        except ValueError:
            raw = None
        if not isinstance(raw, dict):
            raise HTTPException(status_code=422, detail="details must be a JSON object")
        given = ac.clean_details(raw)
    details = ac.merge_details(site_details, given)
    data = await _read_limited(file, _MAX_TEXT_BYTES, "checklist")
    try:
        parsed = ac.parse_workbook(data)
    except ac.ChecklistError as exc:
        raise HTTPException(status_code=422, detail=f"not a master audit checklist: {exc}")
    name = Path(file.filename or "").name[:120] or None
    if format == "json":
        return {"filename": file.filename, **ac.summary_json(ac.report_data(parsed, scope, order, details=details, source_name=name))}
    mod = _audit_report_module()
    body = await run_in_threadpool(mod.report_bytes, parsed, format, scope=scope, order=order, details=details, source_name=name)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    media = "application/pdf" if format == "pdf" else "text/csv; charset=utf-8"
    return StreamingResponse(
        _io.BytesIO(body), media_type=media,
        headers={"Content-Disposition": f'attachment; filename="iasc_audit_{stamp}.{format}"',
                 "Content-Length": str(len(body))})


# ====================================================== STATIC UI PAGES ==

_UI_DIR = Path(__file__).resolve().parent.parent.parent / "ui"


@router.get("/ui/attestation", response_class=HTMLResponse, include_in_schema=False)
def ui_attestation():
    """Serve the Zone Documentation Attestation form."""
    html_path = _UI_DIR / "attestation.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/ui/topology", response_class=HTMLResponse, include_in_schema=False)
def ui_topology():
    """Serve the host-level Purdue topology viewer: the console itself in
    standalone mode (Host Topology only, full screen) - one renderer."""
    html_path = _UI_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/ui/fw-topology", response_class=HTMLResponse, include_in_schema=False)
def ui_fw_topology():
    """Serve the multi-firewall topology builder UI."""
    html_path = _UI_DIR / "fw_topology.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/ui/upload", response_class=HTMLResponse, include_in_schema=False)
def ui_upload():
    """Serve the config + PCAP upload form."""
    html_path = _UI_DIR / "upload.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/ui/findings", response_class=HTMLResponse, include_in_schema=False)
def ui_findings():
    """Serve the findings review page."""
    html_path = _UI_DIR / "findings.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/", include_in_schema=False)
def ui_root():
    """Send browsers hitting the bare host to the unified console."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/ui", status_code=307)


@router.get("/ui", response_class=HTMLResponse, include_in_schema=False)
@router.get("/ui/", response_class=HTMLResponse, include_in_schema=False)
def ui_index():
    """Serve the unified console (sidebar SPA). Served from the API's own
    origin so its fetches are same-origin and need no CORS configuration
    (T2-01); opening ui/index.html from disk gives origin 'null'."""
    html_path = _UI_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI file not found")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
