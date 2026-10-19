"""firewall-groups: HA clusters and paired firewalls

  firewall_groups (id, site_id FK sites NOT NULL, kind VARCHAR(16) NOT NULL
                   CHECK kind IN ('ha','paired'), name VARCHAR(64) NOT NULL,
                   primary_firewall_id INTEGER (no FK: avoids a table cycle),
                   note TEXT, created_by VARCHAR(128), created_at DATETIME)
      ux_firewall_groups_site_kind_name (site_id, kind, name) UNIQUE
      ix_firewall_groups_site_id (site_id)
  firewalls.ha_group_id / paired_group_id  FK firewall_groups ON DELETE SET NULL
      (+ ix_firewalls_ha_group_id / ix_firewalls_paired_group_id)
  firewalls.ha_mode VARCHAR(8), firewalls.ha_cfg_group VARCHAR(80)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  The firewalls
columns use batch mode so the FKs exist on SQLite too.  No app.models import.

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
Create Date: 2026-10-05 15:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import dialect_name, has_column, has_index, has_table, is_offline  # noqa: E402

revision: str = "c1d2e3f4a5b6"
down_revision: Union[str, Sequence[str], None] = "b0c1d2e3f4a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "firewall_groups"
_UX = "ux_firewall_groups_site_kind_name"
_IX = "ix_firewall_groups_site_id"
_FW = "firewalls"
_COLS = (
    ("ha_group_id", "fk_firewalls_ha_group_id", "ix_firewalls_ha_group_id"),
    ("paired_group_id", "fk_firewalls_paired_group_id", "ix_firewalls_paired_group_id"),
)


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("primary_firewall_id", sa.Integer(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("kind IN ('ha', 'paired')", name="ck_firewall_groups_kind"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def _has_fk(table: str, column: str, ref: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return any(fk.get("referred_table") == ref and column in (fk.get("constrained_columns") or [])
               for fk in insp.get_foreign_keys(table))


def _add_fw_columns(offline: bool) -> None:
    # The reconcile revision (d4e5f6a7b8c9) builds from the live models and
    # may already have added these columns - without their FKs on SQLite -
    # so a present column whose FK is missing still gets the constraint.
    add = [c for c in _COLS if offline or not has_column(_FW, c[0])]
    fk_only = [c for c in _COLS if not offline and c not in add
               and not _has_fk(_FW, c[0], _T)]
    plain = [c for c in (("ha_mode", 8), ("ha_cfg_group", 80))
             if offline or not has_column(_FW, c[0])]
    if not add and not fk_only and not plain:
        return
    with op.batch_alter_table(_FW) as batch_op:
        for col, fk, _ix in add:
            batch_op.add_column(sa.Column(col, sa.Integer(), nullable=True))
        for col, fk, _ix in add + fk_only:
            batch_op.create_foreign_key(fk, _T, [col], ["id"], ondelete="SET NULL")
        for col, n in plain:
            batch_op.add_column(sa.Column(col, sa.String(length=n), nullable=True))


def _add_fw_columns_offline() -> None:
    """--sql render: batch mode cannot reflect without a database, so plain
    ADD COLUMN; the FKs as ALTER TABLE on dialects that support it (SQLite
    cannot add a constraint to an existing table - the online path does it
    with batch move-and-copy)."""
    for col, _fk, _ix in _COLS:
        op.add_column(_FW, sa.Column(col, sa.Integer(), nullable=True))
    for col, n in (("ha_mode", 8), ("ha_cfg_group", 80)):
        op.add_column(_FW, sa.Column(col, sa.String(length=n), nullable=True))
    if dialect_name() != "sqlite":
        for col, fk, _ix in _COLS:
            op.create_foreign_key(fk, _FW, _T, [col], ["id"], ondelete="SET NULL")


def upgrade() -> None:
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_UX, _T, ["site_id", "kind", "name"], unique=True, if_not_exists=True)
        op.create_index(_IX, _T, ["site_id"], if_not_exists=True)
        _add_fw_columns_offline()
        for col, _fk, ix in _COLS:
            op.create_index(ix, _FW, [col], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "kind", "name"], unique=True)
    if not has_index(_T, _IX):
        op.create_index(_IX, _T, ["site_id"])
    if has_table(_FW):
        _add_fw_columns(offline=False)
        for col, _fk, ix in _COLS:
            if not has_index(_FW, ix):
                op.create_index(ix, _FW, [col])


def downgrade() -> None:
    if is_offline():
        for _col, _fk, ix in _COLS:
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        if dialect_name() != "sqlite":
            for _col, fk, _ix in _COLS:
                op.drop_constraint(fk, _FW, type_="foreignkey")
        for col in [c[0] for c in _COLS] + ["ha_mode", "ha_cfg_group"]:
            op.drop_column(_FW, col)
        op.execute(f"DROP INDEX IF EXISTS {_IX}")
        op.execute(f"DROP INDEX IF EXISTS {_UX}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_FW):
        for _col, _fk, ix in _COLS:
            if has_index(_FW, ix):
                op.drop_index(ix, table_name=_FW)
        with op.batch_alter_table(_FW) as batch_op:
            for col, fk, _ix in _COLS:
                if has_column(_FW, col):
                    if _has_fk(_FW, col, _T):
                        batch_op.drop_constraint(fk, type_="foreignkey")
                    batch_op.drop_column(col)
            for col in ("ha_mode", "ha_cfg_group"):
                if has_column(_FW, col):
                    batch_op.drop_column(col)
    if has_table(_T):
        for ix in (_IX, _UX):
            if has_index(_T, ix):
                op.drop_index(ix, table_name=_T)
        op.drop_table(_T)
