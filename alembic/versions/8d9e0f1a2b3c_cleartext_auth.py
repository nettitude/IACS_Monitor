"""Flat OT tabletop FO-07: cleartext logins seen on a session

  network_sessions.cleartext_auth VARCHAR(128) - kinds of cleartext login the capture showed
                                                 (FTP login, Telnet login, HTTP Basic auth,
                                                 SNMPv1/v2c community ...); never the secret

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 8d9e0f1a2b3c
Revises: 7c8d9e0f1a2b
Create Date: 2026-10-08 23:00:00.000000
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

revision: str = "8d9e0f1a2b3c"
down_revision: Union[str, Sequence[str], None] = "7c8d9e0f1a2b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T, _C = "network_sessions", "cleartext_auth"


def upgrade() -> None:
    if is_offline() or (has_table(_T) and not has_column(_T, _C)):
        op.add_column(_T, sa.Column(_C, sa.String(length=128), nullable=True))


def downgrade() -> None:
    if is_offline() or has_column(_T, _C):
        with op.batch_alter_table(_T) as b:
            b.drop_column(_C)
