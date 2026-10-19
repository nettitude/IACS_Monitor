"""multi-site-phase3: site device registry + unmapped log queue

docs/multi-site-design.md, phase 3.

  site_devices         (id, site_id FK sites NOT NULL, device_name, serial,
                        vendor, source, created_at, updated_at)
                       ix_site_devices_site_id,
                       ux_site_devices_name_serial (device_name, serial),
                       ux_site_devices_serial (serial) WHERE serial IS NOT NULL
  unmapped_log_events  (id, raw_line, device_key, serial, vendor, source_route,
                        received_at, dedup_hash, upload_ref, status)
                       ux_unmapped_log_events_dedup_hash,
                       ix_unmapped_log_events_device_key,
                       ix_unmapped_log_events_status

Both tables are new, so there is nothing to backfill.  Idempotent
(alembic/iasc_migration_utils.py): on an online upgrade of a legacy
database d4e5f6a7b8c9 (reconcile) may already have created the tables from
the live models - they and their indexes are then found and skipped.
Offline (--sql) always renders CREATE TABLE / INDEX ... IF NOT EXISTS (the
baseline predates these tables, so even a render from base needs them);
plain DDL, so it renders on PostgreSQL and SQLite alike.  No table rebuild
(batch mode) is needed: nothing existing is altered.

Revision ID: f1a2b3c4d5e6
Revises: e1f2a3b4c5d6
Create Date: 2026-10-02 18:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, has_index, has_table, is_offline  # noqa: E402

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (name, table, columns, unique, where)
_INDEXES = [
    ("ix_site_devices_site_id", "site_devices", ["site_id"], False, None),
    ("ux_site_devices_name_serial", "site_devices", ["device_name", "serial"], True, None),
    ("ux_site_devices_serial", "site_devices", ["serial"], True, "serial IS NOT NULL"),
    ("ux_unmapped_log_events_dedup_hash", "unmapped_log_events", ["dedup_hash"], True, None),
    ("ix_unmapped_log_events_device_key", "unmapped_log_events", ["device_key"], False, None),
    ("ix_unmapped_log_events_status", "unmapped_log_events", ["status"], False, None),
]


def _create_tables(if_not_exists: bool) -> None:
    """Offline: CREATE TABLE IF NOT EXISTS; online: only missing tables."""
    if if_not_exists or not has_table("site_devices"):
        _site_devices(if_not_exists)
    if if_not_exists or not has_table("unmapped_log_events"):
        _unmapped(if_not_exists)


def _site_devices(if_not_exists: bool) -> None:
    op.create_table(
        "site_devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=True),
        sa.Column("vendor", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], name="site_devices_site_id_fkey"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def _unmapped(if_not_exists: bool) -> None:
    op.create_table(
        "unmapped_log_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("raw_line", sa.Text(), nullable=False),
        sa.Column("device_key", sa.String(length=255), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=True),
        sa.Column("vendor", sa.String(length=32), nullable=True),
        sa.Column("source_route", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=True),
        sa.Column("dedup_hash", sa.String(length=40), nullable=False),
        sa.Column("upload_ref", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def _create_index(name, table, cols, unique, where, *, if_not_exists=False):
    kw = {}
    if where:
        kw["sqlite_where"] = sa.text(where)
        kw["postgresql_where"] = sa.text(where)
    op.create_index(name, table, cols, unique=unique, if_not_exists=if_not_exists, **kw)


def upgrade() -> None:
    if is_offline():
        _create_tables(if_not_exists=True)
        for name, table, cols, unique, where in _INDEXES:
            _create_index(name, table, cols, unique, where, if_not_exists=True)
        return
    _create_tables(if_not_exists=False)
    for name, table, cols, unique, where in _INDEXES:
        # A table built from the live models by d4e5f6a7b8c9 (reconcile) no
        # longer has site_devices.serial (B-12, d5e6f7a8b9c0 moved serials to
        # site_device_serials): skip indexes over columns that do not exist.
        if not has_index(table, name) and all(has_column(table, c) for c in cols):
            _create_index(name, table, cols, unique, where)


def downgrade() -> None:
    if is_offline():
        op.execute("DROP TABLE IF EXISTS unmapped_log_events")
        op.execute("DROP TABLE IF EXISTS site_devices")
        return
    for table in ("unmapped_log_events", "site_devices"):
        if has_table(table):
            op.drop_table(table)
