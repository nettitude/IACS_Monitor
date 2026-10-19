"""Routed-OT tabletop G3: operator zones per subnet

  subnet_zones (site_id, cidr, purdue_level NUMERIC(2,1), zone_name, note,
                created_by, created_at, updated_at), unique (site_id, cidr)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 9e0f1a2b3c4d
Revises: 8d9e0f1a2b3c
Create Date: 2026-10-09 20:00:00.000000
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

revision: str = "9e0f1a2b3c4d"
down_revision: Union[str, Sequence[str], None] = "8d9e0f1a2b3c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "subnet_zones"
_UX = "ux_subnet_zones_site_cidr"
_IX_SITE = "ix_subnet_zones_site_id"


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("purdue_level", sa.Numeric(precision=2, scale=1, asdecimal=False), nullable=True),
        sa.Column("zone_name", sa.String(length=128), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_UX, _T, ["site_id", "cidr"], unique=True, if_not_exists=True)
        op.create_index(_IX_SITE, _T, ["site_id"], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "cidr"], unique=True)
    if not has_index(_T, _IX_SITE):
        op.create_index(_IX_SITE, _T, ["site_id"])


def downgrade() -> None:
    if is_offline():
        for ix in (_IX_SITE, _UX):
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_T):
        for ix in (_IX_SITE, _UX):
            if has_index(_T, ix):
                op.drop_index(ix, table_name=_T)
        op.drop_table(_T)
