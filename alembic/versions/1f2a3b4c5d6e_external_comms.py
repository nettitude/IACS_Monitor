"""Routed-OT tabletop G5: external communications

  observed_names        (site_id, ip, name, source, count, first_seen, last_seen)
                        unique (site_id, ip, name, source)
  external_flow_reviews (site_id, src, dest_key, status approved|remove, note,
                         created_by, created_at, updated_at) unique (site_id, src, dest_key)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 1f2a3b4c5d6e
Revises: 9e0f1a2b3c4d
Create Date: 2026-10-09 23:00:00.000000
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

revision: str = "1f2a3b4c5d6e"
down_revision: Union[str, Sequence[str], None] = "9e0f1a2b3c4d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_N, _R = "observed_names", "external_flow_reviews"
_IDX = [
    (_N, "ux_observed_names_site_ip_name_source", ["site_id", "ip", "name", "source"], True),
    (_N, "ix_observed_names_site_id", ["site_id"], False),
    (_N, "ix_observed_names_ip", ["ip"], False),
    (_R, "ux_external_flow_reviews_site_src_dest", ["site_id", "src", "dest_key"], True),
    (_R, "ix_external_flow_reviews_site_id", ["site_id"], False),
]


def _create(if_not_exists: bool) -> None:
    op.create_table(
        _N,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )
    op.create_table(
        _R,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("src", sa.String(length=64), nullable=False),
        sa.Column("dest_key", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("status IN ('approved', 'remove')", name="ck_external_flow_reviews_status"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create(if_not_exists=True)
        for t, ix, cols, uq in _IDX:
            op.create_index(ix, t, cols, unique=uq, if_not_exists=True)
        return
    if not has_table(_N) or not has_table(_R):
        if not has_table(_N) and not has_table(_R):
            _create(if_not_exists=False)
        else:
            _create(if_not_exists=True)
    for t, ix, cols, uq in _IDX:
        if not has_index(t, ix):
            op.create_index(ix, t, cols, unique=uq)


def downgrade() -> None:
    if is_offline():
        for t, ix, _c, _u in _IDX:
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_R}")
        op.execute(f"DROP TABLE IF EXISTS {_N}")
        return
    for t, ix, _c, _u in _IDX:
        if has_table(t) and has_index(t, ix):
            op.drop_index(ix, table_name=t)
    for t in (_R, _N):
        if has_table(t):
            op.drop_table(t)
