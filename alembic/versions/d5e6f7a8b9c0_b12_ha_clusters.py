"""b12-ha-clusters: device serials child table + HA cluster fields (B-12)

docs/multi-site-design.md, "B-12: HA clusters".

  site_device_serials (id, device_id FK site_devices ON DELETE CASCADE,
                       serial VARCHAR(128) NOT NULL, source VARCHAR(24) NOT NULL,
                       added_at DATETIME NOT NULL, last_seen_at DATETIME NULL,
                       last_role VARCHAR(16) NULL)
      ux_site_device_serials_serial (serial) UNIQUE   - one unit, one device
      ix_site_device_serials_device_id (device_id)
  site_devices.is_ha          BOOLEAN NOT NULL DEFAULT false
  site_devices.ha_mode        VARCHAR(8) NULL   (a-p | a-a)
  site_devices.ha_group_name  VARCHAR(64) NULL
  site_devices.ha_group_id    INTEGER NULL
  site_devices.serial / serial_source / serial_bound_at   DROPPED
      (with ux_site_devices_name_serial, ux_site_devices_serial); the
      single-serial view is derived from site_device_serials in the model
  ix_site_devices_device_name (device_name)  - replaces the name-leading
      ux_site_devices_name_serial for name lookups

Fresh installs only (owner decision): an existing serial is nevertheless
copied into site_device_serials before the column is dropped (one INSERT ...
SELECT, skipped when nothing qualifies), so a stamped database loses no
binding.  Downgrade restores the columns and copies each device's first
serial back (HA member serials beyond the first are lost on downgrade).

Idempotent (alembic/iasc_migration_utils.py): every step checks the live
schema first.  Column adds / drops run in batch mode (SQLite rebuilds
site_devices for the drop; indexes on the dropped columns are removed
first).  Offline (--sql) renders emit the full DDL (the baseline predates
these objects); an offline SQLite render uses plain ADD / DROP COLUMN
(SQLite >= 3.35) because batch mode cannot reflect without a connection.
No app.models import.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-04 21:00:00.000000
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

revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, Sequence[str], None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SER = "site_device_serials"
_SER_UX = "ux_site_device_serials_serial"
_SER_IX = "ix_site_device_serials_device_id"
_NAME_IX = "ix_site_devices_device_name"
_OLD_IDX = (
    ("ux_site_devices_name_serial", ["device_name", "serial"], None),
    ("ux_site_devices_serial", ["serial"], "serial IS NOT NULL"),
)

_BACKFILL = (
    f"INSERT INTO {_SER} (device_id, serial, source, added_at) "
    "SELECT d.id, d.serial, COALESCE(d.serial_source, d.source, 'manual'), "
    "COALESCE(d.serial_bound_at, d.created_at, CURRENT_TIMESTAMP) "
    "FROM site_devices d WHERE d.serial IS NOT NULL "
    f"AND NOT EXISTS (SELECT 1 FROM {_SER} s WHERE s.serial = d.serial)"
)
_RESTORE = (
    "UPDATE site_devices SET serial = (SELECT s.serial FROM site_device_serials s "
    "WHERE s.device_id = site_devices.id ORDER BY s.id LIMIT 1), "
    "serial_source = (SELECT s.source FROM site_device_serials s "
    "WHERE s.device_id = site_devices.id ORDER BY s.id LIMIT 1), "
    "serial_bound_at = (SELECT s.added_at FROM site_device_serials s "
    "WHERE s.device_id = site_devices.id ORDER BY s.id LIMIT 1)"
)


def _ha_cols():
    return [
        sa.Column("is_ha", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ha_mode", sa.String(length=8), nullable=True),
        sa.Column("ha_group_name", sa.String(length=64), nullable=True),
        sa.Column("ha_group_id", sa.Integer(), nullable=True),
    ]


def _old_serial_cols():
    return [
        sa.Column("serial", sa.String(length=128), nullable=True),
        sa.Column("serial_source", sa.String(length=24), nullable=True),
        sa.Column("serial_bound_at", sa.DateTime(), nullable=True),
    ]


def _create_serials(if_not_exists: bool) -> None:
    op.create_table(
        _SER,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("added_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_role", sa.String(length=16), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["site_devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def _old_index(name, cols, where, *, if_not_exists=False):
    kw = {}
    if where:
        kw["sqlite_where"] = sa.text(where)
        kw["postgresql_where"] = sa.text(where)
    op.create_index(name, "site_devices", cols, unique=True, if_not_exists=if_not_exists, **kw)


def _upgrade_offline() -> None:
    _create_serials(if_not_exists=True)
    op.create_index(_SER_UX, _SER, ["serial"], unique=True, if_not_exists=True)
    op.create_index(_SER_IX, _SER, ["device_id"], if_not_exists=True)
    for c in _ha_cols():
        op.add_column("site_devices", c)
    op.execute(_BACKFILL)
    for name, _cols, _where in _OLD_IDX:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    pg = dialect_name() == "postgresql"
    for c in _old_serial_cols():
        op.execute(f"ALTER TABLE site_devices DROP COLUMN {'IF EXISTS ' if pg else ''}{c.name}")
    op.create_index(_NAME_IX, "site_devices", ["device_name"], if_not_exists=True)


def upgrade() -> None:
    if is_offline():
        _upgrade_offline()
        return
    if not has_table("site_devices"):      # pragma: no cover - f1a2b3c4d5e6 creates it
        return
    if not has_table(_SER):
        _create_serials(if_not_exists=False)
    if not has_index(_SER, _SER_UX):
        op.create_index(_SER_UX, _SER, ["serial"], unique=True)
    if not has_index(_SER, _SER_IX):
        op.create_index(_SER_IX, _SER, ["device_id"])
    missing = [c for c in _ha_cols() if not has_column("site_devices", c.name)]
    if missing:
        with op.batch_alter_table("site_devices") as batch_op:
            for c in missing:
                batch_op.add_column(c)
    present = [c.name for c in _old_serial_cols() if has_column("site_devices", c.name)]
    if "serial" in present:
        op.execute(_BACKFILL if {"serial_source", "serial_bound_at"} <= set(present) else
                   _BACKFILL.replace("d.serial_source, ", "").replace("d.serial_bound_at, ", ""))
    for name, _cols, _where in _OLD_IDX:
        if has_index("site_devices", name):
            op.drop_index(name, table_name="site_devices")
    if present:
        with op.batch_alter_table("site_devices") as batch_op:
            for name in present:
                batch_op.drop_column(name)
    if not has_index("site_devices", _NAME_IX):
        op.create_index(_NAME_IX, "site_devices", ["device_name"])


def downgrade() -> None:
    if is_offline():
        if dialect_name() == "sqlite":
            raise NotImplementedError("offline SQLite downgrade of d5e6f7a8b9c0 is not supported "
                                      "(batch mode needs a live connection)")
        op.execute(f"DROP INDEX IF EXISTS {_NAME_IX}")
        for c in _old_serial_cols():
            op.add_column("site_devices", c)
        op.execute(_RESTORE)
        for name, cols, where in _OLD_IDX:
            _old_index(name, cols, where, if_not_exists=True)
        for c in _ha_cols():
            op.execute(f"ALTER TABLE site_devices DROP COLUMN IF EXISTS {c.name}")
        op.execute(f"DROP TABLE IF EXISTS {_SER}")
        return
    if has_index("site_devices", _NAME_IX):
        op.drop_index(_NAME_IX, table_name="site_devices")
    missing = [c for c in _old_serial_cols() if not has_column("site_devices", c.name)]
    if missing:
        with op.batch_alter_table("site_devices") as batch_op:
            for c in missing:
                batch_op.add_column(c)
    if has_table(_SER):
        op.execute(_RESTORE)
    for name, cols, where in _OLD_IDX:
        if not has_index("site_devices", name):
            _old_index(name, cols, where)
    present = [c.name for c in _ha_cols() if has_column("site_devices", c.name)]
    if present:
        with op.batch_alter_table("site_devices") as batch_op:
            for name in present:
                batch_op.drop_column(name)
    if has_table(_SER):
        op.drop_table(_SER)
