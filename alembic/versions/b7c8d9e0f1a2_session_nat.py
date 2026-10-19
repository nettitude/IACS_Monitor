"""session-nat: the captured (pre-translation) view of NAT'd sessions

  network_sessions.nat_orig_src_ip VARCHAR(64)  - translated source as captured
  network_sessions.nat_orig_dst_ip VARCHAR(64)  - VIP external address as captured
  network_sessions.nat JSON (JSONB on PostgreSQL) - translations / unattributed source NAT

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
Create Date: 2026-10-06 01:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, has_table, is_offline  # noqa: E402

revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, Sequence[str], None] = "a6b7c8d9e0f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "network_sessions"


def _cols():
    return [sa.Column("nat_orig_src_ip", sa.String(length=64), nullable=True),
            sa.Column("nat_orig_dst_ip", sa.String(length=64), nullable=True),
            sa.Column("nat", postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
                      nullable=True)]


def upgrade() -> None:
    for col in _cols():
        if is_offline():
            op.add_column(_T, col)
        elif has_table(_T) and not has_column(_T, col.name):
            op.add_column(_T, col)


def downgrade() -> None:
    names = [c.name for c in _cols()]
    if is_offline():
        for n in names:
            op.drop_column(_T, n)
        return
    if has_table(_T):
        with op.batch_alter_table(_T) as batch_op:
            for n in names:
                if has_column(_T, n):
                    batch_op.drop_column(n)
