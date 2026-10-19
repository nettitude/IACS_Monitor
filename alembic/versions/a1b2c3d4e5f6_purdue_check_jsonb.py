"""purdue-level-check-and-jsonb

Two schema improvements applied together:

1. CHECK constraint on hosts.purdue_level (0–5 or NULL).
   Rejects bad imports before they propagate through reachability / compliance.

2. JSONB upgrade for JSON columns on PostgreSQL only.
   Finding.detail and ProtocolDetail.detail are converted from TEXT (how
   SQLAlchemy stores generic JSON on PG) to native JSONB so that:
     - GIN indexes can be added for JSON key lookups
     - Operators @>, ?, ?| work without casting
     - Storage is binary (more compact, faster to deserialise)
   SQLite stores JSON as TEXT and has no JSONB type — those ALTER TABLE
   calls are skipped on SQLite so the migration is safe for both backends.

Revision ID: a1b2c3d4e5f6
Revises: 946998cf677b
Create Date: 2026-09-29 00:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# alembic/ holds the shared helpers; make them importable even for commands
# (heads, history) that load revisions without running env.py.
_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (
    get_column,
    has_check_constraint,
    has_column,
    has_table,
    is_offline,
    offline_assume_exists,
)


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "946998cf677b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    """Return True when the target DB is PostgreSQL."""
    return op.get_context().dialect.name == "postgresql"


# (table, column) pairs converted JSON -> JSONB on PostgreSQL.
# NB: the FortiAnalyzer table is ``fortiana_events`` (models.FortiAnalyzerEvent);
# this revision previously targeted a non-existent ``forti_analyzer_events``
# table and failed on PostgreSQL (T1-04).
_JSONB_COLUMNS = (
    ("findings", "detail"),              # primary evidence dict; most-queried
    ("protocol_details", "fields"),      # per-frame decoded OT data
    ("hosts", "sources"),                # array of ingest source tags
    ("fortiana_events", "raw_fields"),   # raw parsed FortiAnalyzer fields
    ("firewall_interfaces", "allowaccess"),  # allowed management protocols
)


def _is_jsonb(table: str, column: str) -> bool:
    """True when the column is already JSONB (e.g. created by the baseline)."""
    if is_offline():
        return offline_assume_exists()
    col = get_column(table, column)
    return col is not None and isinstance(col["type"], postgresql.JSONB)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    # Idempotent (T1-02): skipped where the object already exists.

    # ------------------------------------------------------------------
    # 1. Purdue level CHECK constraint on hosts
    # ------------------------------------------------------------------
    if has_table("hosts") and not has_check_constraint("hosts", "ck_host_purdue_level_range"):
        with op.batch_alter_table("hosts") as batch_op:
            batch_op.create_check_constraint(
                "ck_host_purdue_level_range",
                sa.text("purdue_level IS NULL OR (purdue_level >= 0 AND purdue_level <= 5)"),
            )

    # ------------------------------------------------------------------
    # 2. JSONB upgrade (PostgreSQL only)
    # ------------------------------------------------------------------
    if _is_postgresql():
        for table, column in _JSONB_COLUMNS:
            if (is_offline() or has_column(table, column)) and not _is_jsonb(table, column):
                op.execute(
                    f"ALTER TABLE {table} "
                    f"ALTER COLUMN {column} TYPE JSONB USING {column}::JSONB"
                )
        # GIN indexes on the two most-queried evidence columns
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_findings_detail_gin "
            "ON findings USING GIN (detail)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_protocol_details_fields_gin "
            "ON protocol_details USING GIN (fields)"
        )


# ---------------------------------------------------------------------------
# Downgrade
# ---------------------------------------------------------------------------

def downgrade() -> None:
    if _is_postgresql():
        op.execute("DROP INDEX IF EXISTS ix_protocol_details_fields_gin")
        op.execute("DROP INDEX IF EXISTS ix_findings_detail_gin")
        for table, column in reversed(_JSONB_COLUMNS):
            if is_offline() or has_column(table, column):
                op.execute(
                    f"ALTER TABLE {table} "
                    f"ALTER COLUMN {column} TYPE JSON USING {column}::JSON"
                )

    if has_check_constraint("hosts", "ck_host_purdue_level_range") or is_offline():
        with op.batch_alter_table("hosts") as batch_op:
            batch_op.drop_constraint("ck_host_purdue_level_range", type_="check")
