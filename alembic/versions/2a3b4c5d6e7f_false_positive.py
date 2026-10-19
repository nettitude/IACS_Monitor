"""Segmented-firewall tabletop (SF): false-positive findings

  findings.false_positive_reason VARCHAR(1024)  the operator's reason
  findings.false_positive_by     VARCHAR(128)
  findings.false_positive_at     DATETIME
  findings.status gains the value "false_positive" (no constraint change).

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 2a3b4c5d6e7f
Revises: 1f2a3b4c5d6e
Create Date: 2026-10-10 22:00:00.000000
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

revision: str = "2a3b4c5d6e7f"
down_revision: Union[str, Sequence[str], None] = "1f2a3b4c5d6e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "findings"
_COLS = [("false_positive_reason", sa.String(length=1024)),
         ("false_positive_by", sa.String(length=128)),
         ("false_positive_at", sa.DateTime())]


def upgrade() -> None:
    for name, typ in _COLS:
        if is_offline() or (has_table(_T) and not has_column(_T, name)):
            op.add_column(_T, sa.Column(name, typ, nullable=True))


def downgrade() -> None:
    for name, _typ in _COLS:
        if is_offline() or has_column(_T, name):
            with op.batch_alter_table(_T) as b:
                b.drop_column(name)
