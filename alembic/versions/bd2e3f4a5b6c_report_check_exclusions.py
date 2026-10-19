"""Checks left out of the compliance report, per site (owner 2026-10-14)

  report_check_exclusions (site_id, check_name, reason, excluded_by, excluded_at)
      unique (site_id, check_name)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: bd2e3f4a5b6c
Revises: ac1d2e3f4a5b
Create Date: 2026-10-14 15:00:00.000000
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

revision: str = "bd2e3f4a5b6c"
down_revision: Union[str, Sequence[str], None] = "ac1d2e3f4a5b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "report_check_exclusions"
_IDX = [
    ("ux_report_check_exclusions_site_check", ["site_id", "check_name"], True),
    ("ix_report_check_exclusions_site_id", ["site_id"], False),
]


def _create(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("check_name", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("excluded_by", sa.String(length=128), nullable=True),
        sa.Column("excluded_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create(if_not_exists=True)
        for ix, cols, uq in _IDX:
            op.create_index(ix, _T, cols, unique=uq, if_not_exists=True)
        return
    if not has_table(_T):
        _create(if_not_exists=False)
    for ix, cols, uq in _IDX:
        if not has_index(_T, ix):
            op.create_index(ix, _T, cols, unique=uq)


def downgrade() -> None:
    if is_offline():
        for ix, _c, _u in _IDX:
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    for ix, _c, _u in _IDX:
        if has_table(_T) and has_index(_T, ix):
            op.drop_index(ix, table_name=_T)
    if has_table(_T):
        op.drop_table(_T)
