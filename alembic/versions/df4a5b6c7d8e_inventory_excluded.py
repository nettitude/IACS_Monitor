"""Hosts excluded from the asset inventory (owner 2026-10-14)

  hosts.inventory_excluded (bool, default false), inventory_excluded_reason,
  inventory_excluded_by, inventory_excluded_at

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: df4a5b6c7d8e
Revises: ce3f4a5b6c7d
Create Date: 2026-10-15 09:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import dialect_name, has_column, has_table, is_offline  # noqa: E402

revision: str = "df4a5b6c7d8e"
down_revision: Union[str, Sequence[str], None] = "ce3f4a5b6c7d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "hosts"


def _cols():
    return [
        sa.Column("inventory_excluded", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("inventory_excluded_reason", sa.String(length=500), nullable=True),
        sa.Column("inventory_excluded_by", sa.String(length=128), nullable=True),
        sa.Column("inventory_excluded_at", sa.DateTime(), nullable=True),
    ]


def upgrade() -> None:
    if not (is_offline() or has_table(_T)):
        return
    missing = [c for c in _cols() if is_offline() or not has_column(_T, c.name)]
    if not missing:
        return
    if is_offline() and dialect_name() == "sqlite":
        for c in missing:
            op.add_column(_T, c)
        return
    with op.batch_alter_table(_T) as batch_op:
        for c in missing:
            batch_op.add_column(c)


def downgrade() -> None:
    if not (is_offline() or has_table(_T)):
        return
    names = [c.name for c in _cols()]
    if is_offline():
        for n in names:
            op.execute(f"ALTER TABLE {_T} DROP COLUMN {n}")
        return
    with op.batch_alter_table(_T) as batch_op:
        for n in names:
            if has_column(_T, n):
                batch_op.drop_column(n)
