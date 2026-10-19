"""rule-identity: identity-based firewall rules (user groups)

  firewall_rules.src_identity TEXT  - FortiOS groups / users / fsso-groups (comma list);
                                      NULL = any user (IP-only rule)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
Create Date: 2026-10-05 22:00:00.000000
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

revision: str = "f4a5b6c7d8e9"
down_revision: Union[str, Sequence[str], None] = "e3f4a5b6c7d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "firewall_rules"
_COL = "src_identity"


def upgrade() -> None:
    if is_offline():
        op.add_column(_T, sa.Column(_COL, sa.Text(), nullable=True))
        return
    if has_table(_T) and not has_column(_T, _COL):
        op.add_column(_T, sa.Column(_COL, sa.Text(), nullable=True))


def downgrade() -> None:
    if is_offline():
        op.drop_column(_T, _COL)
        return
    if has_table(_T) and has_column(_T, _COL):
        with op.batch_alter_table(_T) as batch_op:
            batch_op.drop_column(_COL)
