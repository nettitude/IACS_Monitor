"""app_settings: server-wide operator settings (RS-01: periodic reviews switch)

  app_settings(key VARCHAR(64) PK, value JSON, updated_at, updated_by VARCHAR(128))

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 5a6b7c8d9e0f
Revises: e0f1a2b3c4d5
Create Date: 2026-10-07 23:30:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_table, is_offline  # noqa: E402

revision: str = "5a6b7c8d9e0f"
down_revision: Union[str, Sequence[str], None] = "e0f1a2b3c4d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if is_offline() or not has_table("app_settings"):
        op.create_table(
            "app_settings",
            sa.Column("key", sa.String(length=64), nullable=False),
            sa.Column("value", sa.JSON(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.Column("updated_by", sa.String(length=128), nullable=True),
            sa.PrimaryKeyConstraint("key"),
        )


def downgrade() -> None:
    if is_offline() or has_table("app_settings"):
        op.drop_table("app_settings")
