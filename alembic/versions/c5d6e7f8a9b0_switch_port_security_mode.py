"""FortiSwitch port security mode (owner 2026-11-09)

  switch_interfaces.port_security_mode ("802.1x" / "802.1x-mab" / "open-auth" / NULL)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-11-09 12:00:00.000000
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

revision: str = "c5d6e7f8a9b0"
down_revision: Union[str, Sequence[str], None] = "b4c5d6e7f8a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "switch_interfaces"


def _cols():
    return [sa.Column("port_security_mode", sa.String(length=32), nullable=True)]


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
    with op.batch_alter_table(_T) as batch_op:
        for c in _cols():
            if is_offline() or has_column(_T, c.name):
                batch_op.drop_column(c.name)
