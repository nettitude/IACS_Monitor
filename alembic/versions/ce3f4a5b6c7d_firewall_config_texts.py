"""Stored firewall configuration text, latest upload per firewall (owner 2026-10-14)

  firewall_config_texts (site_id, firewall_id unique, device_name, vendor, filename,
      uploaded_at, size_bytes, line_count, sha256, masked_count, content)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: ce3f4a5b6c7d
Revises: bd2e3f4a5b6c
Create Date: 2026-10-14 20:30:00.000000
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

revision: str = "ce3f4a5b6c7d"
down_revision: Union[str, Sequence[str], None] = "bd2e3f4a5b6c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "firewall_config_texts"
_IDX = [
    ("ux_firewall_config_texts_firewall", ["firewall_id"], True),
    ("ix_firewall_config_texts_site_id", ["site_id"], False),
]


def _create(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("firewall_id", sa.Integer(), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=32), nullable=True),
        sa.Column("filename", sa.String(length=512), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("line_count", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("masked_count", sa.Integer(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.ForeignKeyConstraint(["firewall_id"], ["firewalls.id"], ondelete="CASCADE"),
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
