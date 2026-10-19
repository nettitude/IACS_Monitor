"""vpn-user-groups: operator classification of SSL-VPN user groups

  vpn_user_groups (id, site_id FK sites NOT NULL, key VARCHAR(160) NOT NULL,
                   name VARCHAR(128) NOT NULL, firewall_id FK firewalls ON DELETE CASCADE,
                   category VARCHAR(16) NOT NULL CHECK category IN ('it','vendor','other'),
                   note TEXT, finding_id INTEGER, created_by VARCHAR(128), created_at DATETIME)
      ux_vpn_user_groups_site_key (site_id, key) UNIQUE
      ix_vpn_user_groups_site_id (site_id)
      ix_vpn_user_groups_firewall_id (firewall_id)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: a6b7c8d9e0f1
Revises: f4a5b6c7d8e9
Create Date: 2026-10-05 23:30:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_index, has_table, is_offline  # noqa: E402

revision: str = "a6b7c8d9e0f1"
down_revision: Union[str, Sequence[str], None] = "f4a5b6c7d8e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "vpn_user_groups"
_UX = "ux_vpn_user_groups_site_key"
_IX_SITE = "ix_vpn_user_groups_site_id"
_IX_FW = "ix_vpn_user_groups_firewall_id"


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("firewall_id", sa.Integer(), nullable=True),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("category IN ('it', 'vendor', 'other')",
                           name="ck_vpn_user_groups_category"),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.ForeignKeyConstraint(["firewall_id"], ["firewalls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_UX, _T, ["site_id", "key"], unique=True, if_not_exists=True)
        op.create_index(_IX_SITE, _T, ["site_id"], if_not_exists=True)
        op.create_index(_IX_FW, _T, ["firewall_id"], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "key"], unique=True)
    if not has_index(_T, _IX_SITE):
        op.create_index(_IX_SITE, _T, ["site_id"])
    if not has_index(_T, _IX_FW):
        op.create_index(_IX_FW, _T, ["firewall_id"])


def downgrade() -> None:
    if is_offline():
        for ix in (_IX_FW, _IX_SITE, _UX):
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_T):
        for ix in (_IX_FW, _IX_SITE, _UX):
            if has_index(_T, ix):
                op.drop_index(ix, table_name=_T)
        op.drop_table(_T)
