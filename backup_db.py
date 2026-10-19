#!/usr/bin/env python3
"""Consistent online backup of the IACS_Monitor SQLite database.

Uses SQLite's backup API, so it is safe while the application is running
(a plain file copy of a database in WAL mode can be inconsistent).

    python backup_db.py                 # -> /data/backups/iasc_monitor-YYYYmmdd-HHMMSS.db
    python backup_db.py /path/out.db    # explicit target
    python backup_db.py --keep 14       # also delete all but the newest 14 backups

In the container:  docker compose exec iasc-monitor python backup_db.py
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def _db_path() -> Path:
    url = os.environ.get("IACS_DATABASE_URL", "sqlite:///./iasc_monitor.db")
    if not url.startswith("sqlite:///"):
        sys.exit("backup_db.py backs up SQLite only; for PostgreSQL use pg_dump")
    return Path(url[len("sqlite:///"):])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", nargs="?", help="backup file (default: <db dir>/backups/<name>-<UTC time>.db)")
    ap.add_argument("--keep", type=int, default=0, help="keep only the newest N backups in the default folder")
    a = ap.parse_args(argv)
    src = _db_path()
    if not src.exists():
        sys.exit(f"database not found: {src}")
    folder = src.parent / "backups"
    target = Path(a.target) if a.target else \
        folder / f"{src.stem}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    target.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(target)
    with d:
        s.backup(d)
    ok = d.execute("PRAGMA integrity_check").fetchone()[0]
    s.close()
    d.close()
    if ok != "ok":
        print(f"integrity check of {target} failed: {ok}", file=sys.stderr)
        return 1
    print(target)
    if a.keep and not a.target:
        old = sorted(folder.glob(f"{src.stem}-*.db"))[:-a.keep]
        for p in old:
            p.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
