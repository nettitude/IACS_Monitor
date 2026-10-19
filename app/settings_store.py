"""Server-wide operator settings stored in the ``app_settings`` table.

RS-01: the switch for the scheduled periodic reviews lives here so it can be
changed at runtime (API / console) without restarting the server, and so it
survives restarts and container rebuilds (it is in the database on /data).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import AppSetting

#: {"enabled": bool} - scheduled periodic reviews on / paused (default on)
PERIODIC_REVIEWS = "periodic_reviews"
#: {"at": iso, "status": "completed"|"skipped"|"failed", "sites": n, "detail": str}
PERIODIC_REVIEWS_LAST = "periodic_reviews_last_run"


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    return default if row is None or row.value is None else row.value


def get_row(db: Session, key: str) -> Optional[AppSetting]:
    return db.get(AppSetting, key)


def set_setting(db: Session, key: str, value: Any, by: Optional[str] = None) -> AppSetting:
    row = db.get(AppSetting, key)
    now = datetime.now(timezone.utc)
    if row is None:
        row = AppSetting(key=key, value=value, updated_at=now, updated_by=by)
        db.add(row)
    else:
        row.value = value
        row.updated_at = now
        row.updated_by = by
    return row


def periodic_reviews_enabled(db: Session) -> bool:
    """The operator switch (default: on).  The IACS_REVIEW_ENABLED
    environment variable is a separate, stronger off switch: with it off the
    scheduler is not started at all."""
    v = get_setting(db, PERIODIC_REVIEWS, {"enabled": True})
    return bool(v.get("enabled", True)) if isinstance(v, dict) else bool(v)
