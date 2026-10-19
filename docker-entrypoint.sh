#!/bin/sh
# IACS_Monitor container entrypoint: prepare /data, bring the database schema
# to the Alembic head, then exec the container command (uvicorn by default).
#
#   IACS_SKIP_MIGRATIONS=true      skip the migration step entirely
#   IACS_LEGACY_DB_REVISION=<rev>  override the revision an unversioned legacy
#                                  database is stamped at (default
#                                  0001baseline0, which is safe for any legacy DB).
set -eu

# /data must be writable by the container user (uid 1000).  A bind-mounted
# host folder owned by another uid is the usual cause of a start failure.
if ! touch /data/.write-test 2>/dev/null; then
    echo "entrypoint: /data is not writable by uid $(id -u) - for a host folder run: sudo chown -R 1000:1000 <folder>" >&2
    exit 1
fi
rm -f /data/.write-test

# Upload spool files (TMPDIR=/data/tmp): left-overs of an interrupted upload
# are never resumed, so clear them at start.
mkdir -p "${TMPDIR:-/data/tmp}" /data/backups
find "${TMPDIR:-/data/tmp}" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true

if [ "${IACS_SKIP_MIGRATIONS:-false}" != "true" ]; then
    state="$(python - <<'PY'
import os
from sqlalchemy import create_engine, inspect
url = os.environ.get("IACS_DATABASE_URL", "sqlite:///./iasc_monitor.db")
tables = inspect(create_engine(url)).get_table_names()
print("unstamped" if tables and "alembic_version" not in tables else "ok")
PY
)"
    if [ "$state" = "unstamped" ]; then
        # Legacy DB created by create_all before migrations were tracked.
        rev="${IACS_LEGACY_DB_REVISION:-0001baseline0}"
        echo "entrypoint: stamping existing unversioned database at ${rev}" >&2
        alembic -c /app/alembic.ini stamp "${rev}"
    fi
    alembic -c /app/alembic.ini upgrade head
fi

exec "$@"
