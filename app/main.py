"""
IACS_Monitor API entrypoint.

Run with:
    uvicorn app.main:app --reload --port 8000

Then, e.g.:
    curl -F "file=@sample_data/modbus_sample.pcap  # python sample_data/generate_sample_pcap.py" http://localhost:8000/ingest/pcap
    curl http://localhost:8000/hosts
    curl http://localhost:8000/sessions?protocol=modbus
    curl http://localhost:8000/sessions/1/details
    curl http://localhost:8000/topology

Scheduled reviews
-----------------
Periodic ISA/IEC 62443 reviews run automatically on a background schedule
controlled by two environment variables:

    IACS_REVIEW_SCHEDULE   cron expression (5 fields, UTC)
                           Default: "0 2 * * 0"  (Sundays at 02:00 UTC)
    IACS_REVIEW_ENABLED    set to "0" or "false" to disable the scheduler
                           entirely (useful in test environments).

Examples:
    IACS_REVIEW_SCHEDULE="0 3 * * 1-5"   weekdays at 03:00 UTC
    IACS_REVIEW_SCHEDULE="0 */6 * * *"   every 6 hours
    IACS_REVIEW_ENABLED=false             scheduler off (manual-only)

The reviews can still be triggered manually at any time via POST /reviews/run.

Single scheduler per host (T3-14): with ``uvicorn --workers N`` (or several
gunicorn workers) every worker runs this lifespan.  Only the process that
wins a non-blocking OS file lock (``fcntl.flock``) starts the scheduler, so
reviews run once per schedule, not N times.  Lock file:

    IACS_SCHEDULER_LOCK    path of the lock file.  Default: next to the
                           SQLite database file, or <tmpdir>/iasc_scheduler.lock
                           for non-SQLite databases.
"""
import json
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_db
from app.api.routes import router as api_router, _MAX_PCAP_BYTES

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scheduler helpers
# ---------------------------------------------------------------------------

#: RS-01: whether THIS process runs the scheduler (only the holder of the
#: scheduler lock does) - read by GET /reviews/schedule.
SCHEDULER_STATE: dict = {"running": False, "pid": None, "scheduler": None}


def _scheduler_enabled() -> bool:
    val = os.environ.get("IACS_REVIEW_ENABLED", "true").strip().lower()
    return val not in ("0", "false", "no", "off")


def _review_cron() -> str:
    """Return the cron expression for periodic reviews (5-field, UTC)."""
    return os.environ.get("IACS_REVIEW_SCHEDULE", "0 2 * * 0").strip()


def _run_scheduled_reviews() -> None:
    """Job target: open a DB session and run all periodic reviews once PER
    SITE (multi-site phase 2: sites are isolated, so every review run - and
    its auto-resolve and run lock - is scoped to one site).  A failing site
    does not stop the others."""
    from app.db import WriteSessionLocal  # B-09: writer (SQLite BEGIN IMMEDIATE)
    from app.models import Site
    from app.parsers.alert_engine import run_periodic_reviews

    from app import settings_store as ss

    def _record(status: str, n_sites: int = 0, detail: str = "") -> None:
        try:
            ss.set_setting(db, ss.PERIODIC_REVIEWS_LAST,
                           {"at": datetime.now(timezone.utc).isoformat(), "status": status,
                            "sites": n_sites, "detail": detail[:500]}, by="scheduler")
            db.commit()
        except Exception:                                   # noqa: BLE001 - bookkeeping only
            log.exception("Scheduled periodic reviews: could not record the run")
            db.rollback()

    db = WriteSessionLocal()
    try:
        try:
            # RS-01: the operator switch (console / PUT /reviews/schedule),
            # read at every firing - changing it needs no restart.
            if not ss.periodic_reviews_enabled(db):
                log.info("Scheduled periodic reviews: paused by the operator - skipped")
                _record("skipped", 0, "paused by the operator")
                return
            sites = db.query(Site.id, Site.name).order_by(Site.id).all()
            if not sites:   # FI-01: fresh install - nothing to review yet
                log.info("Scheduled periodic reviews: no site exists yet - skipped")
                _record("skipped", 0, "no site exists yet")
                return
        except Exception:
            log.exception("Scheduled periodic reviews: could not list sites")
            db.rollback()
            return
        failed = []
        for site_id, name in sites:
            try:
                stats = run_periodic_reviews(db, site_id=site_id) or {}
                total = sum(v for v in stats.values() if isinstance(v, (int, float)))
                log.info("Scheduled periodic reviews complete for site %r: %d findings produced %s",
                         name, total, stats)
            except Exception:
                log.exception("Scheduled periodic reviews failed for site %r", name)
                db.rollback()
                failed.append(str(name))
            finally:
                # C-18: one session serves every site's run; a warm identity
                # map must not carry site A's rows into site B's run
                # (Session.get() bypasses the site loader criteria).
                db.expunge_all()
        _record("failed" if failed else "completed", len(sites),
                ("failed for: " + ", ".join(failed)) if failed else "")
    finally:
        db.close()


def _run_unmapped_retention() -> None:
    """Daily job: purge held log lines of unmapped devices (multi-site phase
    3) - replayed / discarded ones and pending ones older than
    IACS_UNMAPPED_RETENTION_DAYS (default 30)."""
    from app.db import WriteSessionLocal  # B-09: writer (SQLite BEGIN IMMEDIATE)
    from app.site_devices import purge_unmapped

    db = WriteSessionLocal()
    try:
        out = purge_unmapped(db)
        log.info("Unmapped log retention: %s", out)
    except Exception:
        log.exception("Unmapped log retention failed")
        db.rollback()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Single-instance scheduler guard (T3-14)
# ---------------------------------------------------------------------------

def _scheduler_lock_path() -> Path:
    env = os.environ.get("IACS_SCHEDULER_LOCK", "").strip()
    if env:
        return Path(env)
    try:
        from sqlalchemy.engine import make_url
        from app.db import DATABASE_URL

        url = make_url(DATABASE_URL)
        db = url.database
        if url.get_backend_name() == "sqlite" and db and db != ":memory:" \
                and not db.startswith("file:"):
            return Path(db).resolve().parent / "iasc_scheduler.lock"
    except Exception:  # pragma: no cover - defensive
        pass
    return Path(tempfile.gettempdir()) / "iasc_scheduler.lock"


def _acquire_scheduler_lock(path: Optional[Path] = None):
    """Try to become the one process on this host that runs the scheduler.

    Returns an open file handle holding an exclusive, non-blocking
    ``fcntl.flock`` on the lock file (keep it open for the life of the
    process - closing it, or process exit, releases the lock), or None when
    another process (or another open handle) already holds it.

    flock locks belong to the open file description, so two acquisitions in
    the same process also exclude each other.  On platforms without fcntl
    (Windows) the guard is skipped and a dummy handle is returned.
    """
    path = Path(path) if path is not None else _scheduler_lock_path()
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX
        log.warning("fcntl unavailable; scheduler single-instance guard disabled")
        return open(os.devnull, "w")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(path, "a+")
    except OSError:
        log.exception("Cannot open scheduler lock file %s; not starting the scheduler", path)
        return None
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, PermissionError):
        fh.close()
        return None
    except OSError:
        fh.close()
        log.exception("flock(%s) failed; not starting the scheduler", path)
        return None
    try:
        fh.seek(0)
        fh.truncate()
        fh.write(f"{os.getpid()}\n")
        fh.flush()
    except OSError:
        pass
    return fh


def _release_scheduler_lock(fh) -> None:
    if fh is None:
        return
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Request size guard (T3-02)
# ---------------------------------------------------------------------------

# Hard ceiling on any request body, checked before FastAPI parses the
# multipart form (which spools the whole upload to disk first).  Per-file
# limits (_MAX_PCAP_BYTES / _MAX_TEXT_BYTES / _MAX_PROOF_BYTES) are enforced
# again in routes._spool_upload; this only stops absurd bodies early.
_MAX_REQUEST_BYTES = int(
    os.environ.get("IACS_MAX_REQUEST_BYTES", str(_MAX_PCAP_BYTES + 2 * 1024 * 1024))
)


class _BodySizeLimitMiddleware:
    """Pure-ASGI guard: 413 when Content-Length (or the streamed body)
    exceeds ``max_bytes``.  Declared Content-Length is rejected without
    reading the body; chunked bodies are counted as they are received."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)

        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > self.max_bytes:
                    return await self._reject(send)
                break

        received = 0
        limit = self.max_bytes

        async def _limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Raised inside FastAPI's body parsing, which re-raises
                    # HTTPException unchanged -> 413 via ExceptionMiddleware.
                    raise HTTPException(status_code=413, detail=_too_large_detail(limit))
            return message

        return await self.app(scope, _limited_receive, send)

    async def _reject(self, send):
        body = json.dumps({"detail": _too_large_detail(self.max_bytes)}).encode()
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def _too_large_detail(limit: int) -> str:
    return f"Request body exceeds {limit // (1024 * 1024)} MB limit"


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialise DB and scheduler on startup, tear down after."""
    init_db()

    scheduler = None
    lock_fh = None
    if _scheduler_enabled():
        lock_fh = _acquire_scheduler_lock()
        if lock_fh is None:
            log.info(
                "Periodic review scheduler NOT started in pid %d: another process "
                "holds the scheduler lock %s", os.getpid(), _scheduler_lock_path(),
            )
    if lock_fh is not None:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger

            cron = _review_cron()
            scheduler = BackgroundScheduler(timezone="UTC")
            scheduler.add_job(
                _run_scheduled_reviews,
                trigger=CronTrigger.from_crontab(cron, timezone="UTC"),
                id="periodic_reviews",
                name="ISA/IEC 62443 Periodic Reviews",
                replace_existing=True,
                misfire_grace_time=3600,   # tolerate up to 1 h of downtime
            )
            scheduler.add_job(
                _run_unmapped_retention,
                trigger=CronTrigger.from_crontab("17 3 * * *", timezone="UTC"),
                id="unmapped_retention",
                name="Unmapped log line retention",
                replace_existing=True,
                misfire_grace_time=3600,
            )
            scheduler.start()
            SCHEDULER_STATE.update(running=True, pid=os.getpid(), scheduler=scheduler)
            log.info("Periodic review scheduler started in pid %d (cron=%r, UTC, lock %s)",
                     os.getpid(), cron, _scheduler_lock_path())
        except Exception:
            log.exception(
                "Failed to start periodic review scheduler — reviews will not run automatically. "
                "Use POST /reviews/run to trigger them manually."
            )
    elif not _scheduler_enabled():
        log.info("Periodic review scheduler disabled (IACS_REVIEW_ENABLED=false)")

    try:
        yield  # application runs here
    finally:
        if scheduler is not None and scheduler.running:
            scheduler.shutdown(wait=False)
            SCHEDULER_STATE.update(running=False, scheduler=None)
            log.info("Periodic review scheduler stopped")
        _release_scheduler_lock(lock_fh)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="IACS_Monitor",
    description=(
        "ICS/OT network monitoring: host/port/protocol mapping and protocol-level "
        "detail (Modbus, DNP3, etc.) with ISA/IEC 62443 compliance findings."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS: set IACS_ALLOWED_ORIGINS to a comma-separated list of UI origins
# (e.g. "http://localhost:3000,https://iasc.example.com") before deployment.
# Falls back to localhost-only dev origins so the default is not wildcard.
_raw_origins = os.environ.get("IACS_ALLOWED_ORIGINS", "")
_allowed_origins = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if _raw_origins
    else ["http://localhost:8000", "http://127.0.0.1:8000",
          "http://localhost:3000", "http://127.0.0.1:3000"]
)
# Starlette wraps middleware in reverse order of add_middleware: the body
# limit is added FIRST so CORS (added last, outermost) also decorates its
# 413 - a UI on another origin then sees the "exceeds N MB" message instead
# of an opaque network error.
app.add_middleware(_BodySizeLimitMiddleware, max_bytes=_MAX_REQUEST_BYTES)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
    expose_headers=["X-Total-Count", "X-Hosts-Total", "X-Sessions-Total"],  # list paging when the UI is on another origin
)


# A-26: security headers.  nosniff everywhere; a CSP + framing/referrer
# policy on the /ui HTML pages.  The pages use inline <script>/<style> and
# inline event handlers, hence 'unsafe-inline'.  connect-src allows http(s)
# because each page has a user-configurable API base URL (may be another
# origin); everything else is same-origin only.
_UI_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self' http: https:; frame-ancestors 'none'; "
    "base-uri 'self'; form-action 'self'; object-src 'none'"
)


class _SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        is_ui = path == "/ui" or path.startswith("/ui/")

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"x-content-type-options",)]
                headers.append((b"x-content-type-options", b"nosniff"))
                if is_ui:
                    headers += [
                        (b"content-security-policy", _UI_CSP.encode()),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                    ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, _send)


app.add_middleware(_SecurityHeadersMiddleware)


@app.exception_handler(UnicodeDecodeError)
async def _unicode_body_error(request, exc):   # noqa: ANN001  (C-20)
    """A request body that is not valid UTF-8 where JSON / form text is
    expected (e.g. a UTF-16 webhook payload) is the caller's error, not a
    server fault: 422 with the position, never a 500."""
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=422, content={"detail": [{
        "type": "body_not_utf8", "loc": ["body"],
        "msg": f"request body is not valid UTF-8 text (byte {exc.start}); send UTF-8 "
               f"JSON / form data"}]})

app.include_router(api_router)


@app.get("/health")
def health():
    return {"status": "ok"}
