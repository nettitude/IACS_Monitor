"""session-carrier: the router MAC a captured session was carried by (LS-03 / MV-07)

  network_sessions.carrier_mac VARCHAR(17) - the gateway MAC on the session's frames
      (a firewall / routing-switch interface MAC), NULL when the hosts talked
      directly on one segment or the router is unknown

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
Create Date: 2026-10-06 12:00:00.000000
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

revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, Sequence[str], None] = "b7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "network_sessions"


def upgrade() -> None:
    col = sa.Column("carrier_mac", sa.String(length=17), nullable=True)
    if is_offline() or (has_table(_T) and not has_column(_T, "carrier_mac")):
        op.add_column(_T, col)


def downgrade() -> None:
    if is_offline():
        op.drop_column(_T, "carrier_mac")
        return
    if has_table(_T) and has_column(_T, "carrier_mac"):
        with op.batch_alter_table(_T) as batch_op:
            batch_op.drop_column("carrier_mac")
