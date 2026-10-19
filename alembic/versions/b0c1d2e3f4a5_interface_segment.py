"""interface-segment: shared-segment label on firewall interfaces (D-07)

  firewall_interfaces.segment VARCHAR(64) NULL + ix_firewall_interfaces_segment

Three or more firewalls on one network (the DMZ switch) cannot be recorded
with the one-peer connects_to_interface_id; members of a confirmed shared
segment carry the same label and cross-firewall checks pair them all.
Idempotent; offline renders emit the full DDL.  No app.models import.

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
Create Date: 2026-10-05 13:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, has_index, has_table, is_offline  # noqa: E402

revision: str = "b0c1d2e3f4a5"
down_revision: Union[str, Sequence[str], None] = "a9b0c1d2e3f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "firewall_interfaces"
_C = "segment"
_IX = "ix_firewall_interfaces_segment"


def upgrade() -> None:
    if is_offline():
        op.add_column(_T, sa.Column(_C, sa.String(length=64), nullable=True))
        op.create_index(_IX, _T, [_C], if_not_exists=True)
        return
    if not has_table(_T):
        return
    if not has_column(_T, _C):
        op.add_column(_T, sa.Column(_C, sa.String(length=64), nullable=True))
    if not has_index(_T, _IX):
        op.create_index(_IX, _T, [_C])


def downgrade() -> None:
    if is_offline():
        op.execute(f"DROP INDEX IF EXISTS {_IX}")
        with op.batch_alter_table(_T) as batch_op:
            batch_op.drop_column(_C)
        return
    if not has_table(_T):
        return
    if has_index(_T, _IX):
        op.drop_index(_IX, table_name=_T)
    if has_column(_T, _C):
        with op.batch_alter_table(_T) as batch_op:
            batch_op.drop_column(_C)
