"""
Periodic reviews at upload time (owner 2026-10-12: "period findings should be ran at
upload time").

``request(site_id, what)`` queues one run_periodic_reviews pass for the site in a
background thread and returns at once, so the upload's response is not held up by a
review of the whole site.  Uploads that arrive while a run is going are coalesced into
ONE more run after it (the data they brought is reviewed, not dropped).  A run skipped
because another one holds the site's review lock (the scheduler, POST /reviews/run) is
retried.  Live log streams (forti-event / syslog lines) do not trigger it - the real-time
checks and the scheduled reviews cover them.

IACS_REVIEW_ON_UPLOAD=false switches it off (the test suite does; tests that need it
call ``run_now`` / enable it explicitly).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

_lock = threading.Lock()
_state: dict = {}          # site_id -> {"running": bool, "pending": bool, "reasons": [...], "last": {...}}
_RETRY_SECONDS = 15
_RETRIES = 40              # up to ~10 minutes behind a scheduled / manual run


def enabled() -> bool:
    return os.environ.get("IACS_REVIEW_ON_UPLOAD", "true").strip().lower() not in ("0", "false", "no", "off")


def request(site_id: Optional[int], what: str) -> str:
    """Queue a review of ``site_id`` after an upload of ``what``.  Returns
    "queued", "queued after the running review", "off" or "no site"."""
    if not enabled():
        return "off"
    if site_id is None:
        return "no site"
    sid = int(site_id)
    with _lock:
        st = _state.setdefault(sid, {"running": False, "pending": False, "reasons": [], "last": None})
        st["reasons"].append(what)
        if st["running"]:
            st["pending"] = True
            return "queued after the running review"
        st["running"] = True
    t = threading.Thread(target=_worker, args=(sid,), name=f"review-on-upload-{sid}", daemon=True)
    t.start()
    return "queued"


def status(site_id: Optional[int] = None) -> dict:
    """{site_id: {"running", "pending", "last"}} (or one site's entry)."""
    with _lock:
        snap = {k: {"running": v["running"], "pending": v["pending"], "last": v["last"]}
                for k, v in _state.items()}
    return snap.get(int(site_id), {"running": False, "pending": False, "last": None}) \
        if site_id is not None else snap


def run_now(site_id: int) -> dict:
    """Run one review pass for the site synchronously (the worker's body; also
    used by tests).  Returns the review stats ({} when the site's run lock
    stayed busy)."""
    from app.db import WriteSessionLocal
    from app.parsers.alert_engine import REVIEW_SKIPPED_STAT, run_periodic_reviews
    for attempt in range(_RETRIES + 1):
        db = WriteSessionLocal()
        try:
            stats = run_periodic_reviews(db, site_id=site_id) or {}
        finally:
            db.close()
        if REVIEW_SKIPPED_STAT not in stats:
            return stats
        if attempt < _RETRIES:
            time.sleep(_RETRY_SECONDS)
    log.warning("Review after upload for site %s: the review lock stayed busy - "
                "left to the scheduled run", site_id)
    return {}


def _worker(site_id: int) -> None:
    while True:
        with _lock:
            st = _state[site_id]
            reasons, st["reasons"], st["pending"] = st["reasons"], [], False
        started = datetime.now(timezone.utc)
        ok, n = True, 0
        try:
            stats = run_now(site_id)
            n = sum(v for v in stats.values() if isinstance(v, (int, float)))
            log.info("Review after upload (%s) for site %s: %d new finding(s)",
                     ", ".join(dict.fromkeys(reasons)), site_id, n)
        except Exception:                                   # noqa: BLE001 - never kill the server
            ok = False
            log.exception("Review after upload for site %s failed", site_id)
        with _lock:
            st["last"] = {"started_at": started.isoformat(),
                          "finished_at": datetime.now(timezone.utc).isoformat(),
                          "ok": ok, "new_findings": n, "after": list(dict.fromkeys(reasons))}
            if not st["pending"]:
                st["running"] = False
                return
