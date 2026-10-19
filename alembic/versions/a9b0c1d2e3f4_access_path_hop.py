"""access-path-hop: operator-declared hop between two hosts of one segment

  access_path_hop (id, site_id FK sites NOT NULL, from_ip VARCHAR(64) NOT NULL,
                   to_ip VARCHAR(64) NOT NULL, service VARCHAR(255) NULL,
                   note TEXT NULL, created_by VARCHAR(128) NULL,
                   created_at DATETIME NULL)
      ux_access_path_hop_site_pair (site_id, from_ip, to_ip) UNIQUE
      ix_access_path_hop_site_id (site_id)

Hosts are referenced by address (no FK): host rows are re-created by
re-ingests.  Fresh installs only.  Idempotent (alembic/iasc_migration_utils.py);
offline (--sql) renders emit the full DDL with IF NOT EXISTS.  A new table
needs no batch mode on SQLite.  No app.models import.

Revision ID: a9b0c1d2e3f4
Revises: f7a8b9c0d1e2
Create Date: 2026-10-05 12:00:00.000000
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

revision: str = "a9b0c1d2e3f4"
down_revision: Union[str, Sequence[str], None] = "f7a8b9c0d1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "access_path_hop"
_UX = "ux_access_path_hop_site_pair"
_IX = "ix_access_path_hop_site_id"


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("from_ip", sa.String(length=64), nullable=False),
        sa.Column("to_ip", sa.String(length=64), nullable=False),
        sa.Column("service", sa.String(length=255), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_UX, _T, ["site_id", "from_ip", "to_ip"], unique=True, if_not_exists=True)
        op.create_index(_IX, _T, ["site_id"], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "from_ip", "to_ip"], unique=True)
    if not has_index(_T, _IX):
        op.create_index(_IX, _T, ["site_id"])


def downgrade() -> None:
    if is_offline():
        op.execute(f"DROP INDEX IF EXISTS {_IX}")
        op.execute(f"DROP INDEX IF EXISTS {_UX}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_T):
        if has_index(_T, _IX):
            op.drop_index(_IX, table_name=_T)
        if has_index(_T, _UX):
            op.drop_index(_UX, table_name=_T)
        op.drop_table(_T)
