"""IEC 62443-3-2 zones and conduits (documentation only)

  iec_zones        (site_id, name, sl_t 1-4, description, owner, created_by, created_at, updated_at)
                   unique (site_id, name)
  iec_zone_members (site_id, zone_id -> iec_zones ON DELETE CASCADE, kind host|subnet|interface|fw_zone,
                    ref, note, created_by, created_at) unique (site_id, kind, ref)
  iec_conduits     (site_id, zone_a_id, zone_b_id -> iec_zones ON DELETE CASCADE, name, sl_t, description,
                    created_by, created_at, updated_at) unique (site_id, zone_a_id, zone_b_id), zone_a_id < zone_b_id

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 3b4c5d6e7f8a
Revises: 2a3b4c5d6e7f
Create Date: 2026-10-10 23:30:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_index, has_table, is_offline  # noqa: E402

revision: str = "3b4c5d6e7f8a"
down_revision: Union[str, Sequence[str], None] = "2a3b4c5d6e7f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_Z, _M, _C = "iec_zones", "iec_zone_members", "iec_conduits"
_IDX = [
    (_Z, "ux_iec_zones_site_name", ["site_id", "name"], True),
    (_Z, "ix_iec_zones_site_id", ["site_id"], False),
    (_M, "ux_iec_zone_members_site_kind_ref", ["site_id", "kind", "ref"], True),
    (_M, "ix_iec_zone_members_site_id", ["site_id"], False),
    (_M, "ix_iec_zone_members_zone_id", ["zone_id"], False),
    (_C, "ux_iec_conduits_site_pair", ["site_id", "zone_a_id", "zone_b_id"], True),
    (_C, "ix_iec_conduits_site_id", ["site_id"], False),
    (_C, "ix_iec_conduits_zone_a_id", ["zone_a_id"], False),
    (_C, "ix_iec_conduits_zone_b_id", ["zone_b_id"], False),
]


def _zones(ine: bool) -> None:
    op.create_table(
        _Z,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("sl_t", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("sl_t IS NULL OR sl_t IN (1, 2, 3, 4)", name="ck_iec_zones_sl_t"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=ine,
    )


def _members(ine: bool) -> None:
    op.create_table(
        _M,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("zone_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("ref", sa.String(length=255), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("kind IN ('host', 'subnet', 'interface', 'fw_zone')", name="ck_iec_zone_members_kind"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.ForeignKeyConstraint(["zone_id"], ["iec_zones.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=ine,
    )


def _conduits(ine: bool) -> None:
    op.create_table(
        _C,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("zone_a_id", sa.Integer(), nullable=False),
        sa.Column("zone_b_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=True),
        sa.Column("sl_t", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("sl_t IS NULL OR sl_t IN (1, 2, 3, 4)", name="ck_iec_conduits_sl_t"),
        sa.CheckConstraint("zone_a_id < zone_b_id", name="ck_iec_conduits_pair_order"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.ForeignKeyConstraint(["zone_a_id"], ["iec_zones.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["zone_b_id"], ["iec_zones.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=ine,
    )


_MAKERS = ((_Z, _zones), (_M, _members), (_C, _conduits))


def upgrade() -> None:
    if is_offline():
        for _t, mk in _MAKERS:
            mk(True)
        for t, ix, cols, uq in _IDX:
            op.create_index(ix, t, cols, unique=uq, if_not_exists=True)
        return
    for t, mk in _MAKERS:
        if not has_table(t):
            mk(False)
    for t, ix, cols, uq in _IDX:
        if not has_index(t, ix):
            op.create_index(ix, t, cols, unique=uq)


def downgrade() -> None:
    if is_offline():
        for _t, ix, _c, _u in _IDX:
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        for t in (_C, _M, _Z):
            op.execute(f"DROP TABLE IF EXISTS {t}")
        return
    for t, ix, _c, _u in _IDX:
        if has_table(t) and has_index(t, ix):
            op.drop_index(ix, table_name=t)
    for t in (_C, _M, _Z):
        if has_table(t):
            op.drop_table(t)
