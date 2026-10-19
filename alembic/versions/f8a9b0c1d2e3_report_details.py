"""Report details per site (owner 2026-10-18)

  report_details (site_id unique, client_name, project_name, author, author_email,
  version, classification, distribution JSON, revisions JSON, constraints,
  updated_by, updated_at)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: f8a9b0c1d2e3
Revises: df4a5b6c7d8e
Create Date: 2026-10-18 09:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import dialect_name, has_index, has_table, is_offline  # noqa: E402

revision: str = "f8a9b0c1d2e3"
down_revision: Union[str, Sequence[str], None] = "df4a5b6c7d8e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "report_details"
_IDX = [
    ("ux_report_details_site", ["site_id"], True),
    ("ix_report_details_site_id", ["site_id"], False),
]


def _json_type():
    from sqlalchemy.dialects import postgresql
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _create(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("client_name", sa.String(length=200), nullable=True),
        sa.Column("project_name", sa.String(length=200), nullable=True),
        sa.Column("author", sa.String(length=128), nullable=True),
        sa.Column("author_email", sa.String(length=200), nullable=True),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("classification", sa.String(length=128), nullable=True),
        sa.Column("distribution", _json_type(), nullable=True),
        sa.Column("revisions", _json_type(), nullable=True),
        sa.Column("constraints", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
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
