"""management-purpose: management vs engineering declarations

  management_networks.purpose VARCHAR(16) NOT NULL DEFAULT 'management'
      management  - administering infrastructure (firewalls, switches, servers)
      engineering - programming / configuring controllers and field devices (L0-L2)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-10-05 20:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, has_table, is_offline  # noqa: E402

revision: str = "e3f4a5b6c7d8"
down_revision: Union[str, Sequence[str], None] = "d2e3f4a5b6c7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "management_networks"
_COL = "purpose"


def _column():
    return sa.Column(_COL, sa.String(length=16), server_default="management", nullable=False)


def upgrade() -> None:
    if is_offline():
        op.add_column(_T, _column())
        return
    if has_table(_T) and not has_column(_T, _COL):
        op.add_column(_T, _column())


def downgrade() -> None:
    if is_offline():
        op.drop_column(_T, _COL)
        return
    if has_table(_T) and has_column(_T, _COL):
        with op.batch_alter_table(_T) as batch_op:
            batch_op.drop_column(_COL)
