"""b11-device-conflicts: serial binding, held conflicts, resolution audit (B-11)

docs/multi-site-design.md, "B-11: device routing conflicts".

  site_devices.serial_source      VARCHAR(24) NULL  (config_upload | manual |
                                                     first_seen | conflict_resolution)
  site_devices.serial_bound_at    DATETIME NULL
  unmapped_log_events.kind        VARCHAR(16) NOT NULL DEFAULT 'unmapped'
                                  (unmapped | serial_conflict | site_mismatch)
  unmapped_log_events.registered_device_id / registered_site_id  INTEGER NULL
  unmapped_log_events.registered_serial                          VARCHAR(128) NULL
  unmapped_log_events.map_site_id                                INTEGER NULL
  ix_unmapped_log_events_kind_status (kind, status)
  device_conflict_resolutions (id, resolved_at, action, kind, device_key,
      serial, registered_device_id, registered_site_id, registered_serial,
      target_site_id, device_id, lines, events_created, findings_created,
      resolved_by)
  ix_device_conflict_resolutions_resolved_at

Nothing is backfilled (fresh installs; existing held rows get kind
'unmapped' from the server default).  The ``registered_*`` / ``map_site_id``
/ ``device_id`` columns are snapshots without foreign keys: a held line or
an audit row must survive the deletion of the device or site it refers to.

Idempotent (alembic/iasc_migration_utils.py): every step checks the live
schema first.  Column adds run in batch mode (plain ADD COLUMN on both
SQLite and PostgreSQL - nothing is rebuilt).  Offline (--sql) renders emit
the full DDL (the baseline predates these objects); an offline SQLite render
uses plain ADD COLUMN because batch mode cannot reflect without a
connection.  No app.models import.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-10-04 18:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (  # noqa: E402
    dialect_name, has_column, has_index, has_table, is_offline,
)

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "b3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RES_TABLE = "device_conflict_resolutions"
_RES_IDX = "ix_device_conflict_resolutions_resolved_at"
_KIND_IDX = "ix_unmapped_log_events_kind_status"


def _site_device_cols():
    return [
        sa.Column("serial_source", sa.String(length=24), nullable=True),
        sa.Column("serial_bound_at", sa.DateTime(), nullable=True),
    ]


def _unmapped_cols():
    return [
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="unmapped"),
        sa.Column("registered_device_id", sa.Integer(), nullable=True),
        sa.Column("registered_site_id", sa.Integer(), nullable=True),
        sa.Column("registered_serial", sa.String(length=128), nullable=True),
        sa.Column("map_site_id", sa.Integer(), nullable=True),
    ]


def _add_columns(table: str, cols) -> None:
    if not (is_offline() or has_table(table)):
        return
    missing = [c for c in cols if is_offline() or not has_column(table, c.name)]
    if not missing:
        return
    if is_offline() and dialect_name() == "sqlite":
        for c in missing:
            op.add_column(table, c)
        return
    with op.batch_alter_table(table) as batch_op:
        for c in missing:
            batch_op.add_column(c)


def _create_resolutions(if_not_exists: bool) -> None:
    op.create_table(
        _RES_TABLE,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=False),
        sa.Column("action", sa.String(length=24), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("device_key", sa.String(length=255), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=True),
        sa.Column("registered_device_id", sa.Integer(), nullable=True),
        sa.Column("registered_site_id", sa.Integer(), nullable=True),
        sa.Column("registered_serial", sa.String(length=128), nullable=True),
        sa.Column("target_site_id", sa.Integer(), nullable=True),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("lines", sa.Integer(), nullable=False),
        sa.Column("events_created", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("resolved_by", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    _add_columns("site_devices", _site_device_cols())
    _add_columns("unmapped_log_events", _unmapped_cols())
    if is_offline():
        op.create_index(_KIND_IDX, "unmapped_log_events", ["kind", "status"], if_not_exists=True)
        _create_resolutions(if_not_exists=True)
        op.create_index(_RES_IDX, _RES_TABLE, ["resolved_at"], if_not_exists=True)
        return
    if has_table("unmapped_log_events") and not has_index("unmapped_log_events", _KIND_IDX):
        op.create_index(_KIND_IDX, "unmapped_log_events", ["kind", "status"])
    if not has_table(_RES_TABLE):
        _create_resolutions(if_not_exists=False)
    if not has_index(_RES_TABLE, _RES_IDX):
        op.create_index(_RES_IDX, _RES_TABLE, ["resolved_at"])


def downgrade() -> None:
    if is_offline():
        if dialect_name() == "sqlite":
            raise NotImplementedError("offline SQLite downgrade of c4d5e6f7a8b9 is not supported "
                                      "(batch mode needs a live connection)")
        op.execute(f"DROP TABLE IF EXISTS {_RES_TABLE}")
        op.execute(f"DROP INDEX IF EXISTS {_KIND_IDX}")
        for table, cols in (("unmapped_log_events", _unmapped_cols()),
                            ("site_devices", _site_device_cols())):
            for c in cols:
                op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {c.name}")
        return
    if has_table(_RES_TABLE):
        op.drop_table(_RES_TABLE)
    if has_index("unmapped_log_events", _KIND_IDX):
        op.drop_index(_KIND_IDX, table_name="unmapped_log_events")
    for table, cols in (("unmapped_log_events", _unmapped_cols()),
                        ("site_devices", _site_device_cols())):
        present = [c.name for c in cols if has_column(table, c.name)]
        if present:
            with op.batch_alter_table(table) as batch_op:
                for name in present:
                    batch_op.drop_column(name)
