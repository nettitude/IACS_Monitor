"""firewall_interfaces.remote_access: SSL-VPN / dial-up IPsec tunnel kind (DR-03)

  firewall_interfaces.remote_access VARCHAR(16) - "ssl" | "ipsec_dialup" | NULL

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: e0f1a2b3c4d5
Revises: d9e0f1a2b3c4
Create Date: 2026-10-07 10:00:00.000000
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

revision: str = "e0f1a2b3c4d5"
down_revision: Union[str, Sequence[str], None] = "d9e0f1a2b3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "firewall_interfaces"


def upgrade() -> None:
    if is_offline() or (has_table(_T) and not has_column(_T, "remote_access")):
        op.add_column(_T, sa.Column("remote_access", sa.String(length=16), nullable=True))


def downgrade() -> None:
    if is_offline() or has_column(_T, "remote_access"):
        with op.batch_alter_table(_T) as b:
            b.drop_column("remote_access")
