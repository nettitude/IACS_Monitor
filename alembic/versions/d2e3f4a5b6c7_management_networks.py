"""management-networks: declared management subnets, hosts, VLANs and names

  management_networks (id, site_id FK sites NOT NULL, kind VARCHAR(16) NOT NULL
                       CHECK kind IN ('subnet','host','vlan','name'),
                       key VARCHAR(320) NOT NULL, cidr VARCHAR(64), role VARCHAR(32),
                       vlan_id INTEGER, firewall_id FK firewalls ON DELETE CASCADE,
                       name VARCHAR(128), is_management BOOLEAN NOT NULL DEFAULT true,
                       label VARCHAR(128), note TEXT, finding_id INTEGER,
                       created_by VARCHAR(128), created_at DATETIME)
      ux_management_networks_site_key (site_id, key) UNIQUE
      ix_management_networks_site_id (site_id)
      ix_management_networks_firewall_id (firewall_id)
  firewalls.admin_trusthosts JSON (JSONB on PostgreSQL)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-10-05 18:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, has_index, has_table, is_offline  # noqa: E402

revision: str = "d2e3f4a5b6c7"
down_revision: Union[str, Sequence[str], None] = "c1d2e3f4a5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "management_networks"
_UX = "ux_management_networks_site_key"
_IX_SITE = "ix_management_networks_site_id"
_IX_FW = "ix_management_networks_firewall_id"
_FW = "firewalls"
_COL = "admin_trusthosts"


def _json():
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("key", sa.String(length=320), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("firewall_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=True),
        sa.Column("is_management", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("kind IN ('subnet', 'host', 'vlan', 'name')",
                           name="ck_management_networks_kind"),
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
        op.add_column(_FW, sa.Column(_COL, _json(), nullable=True))
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "key"], unique=True)
    if not has_index(_T, _IX_SITE):
        op.create_index(_IX_SITE, _T, ["site_id"])
    if not has_index(_T, _IX_FW):
        op.create_index(_IX_FW, _T, ["firewall_id"])
    if has_table(_FW) and not has_column(_FW, _COL):
        op.add_column(_FW, sa.Column(_COL, _json(), nullable=True))


def downgrade() -> None:
    if is_offline():
        op.drop_column(_FW, _COL)
        for ix in (_IX_FW, _IX_SITE, _UX):
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_FW) and has_column(_FW, _COL):
        with op.batch_alter_table(_FW) as batch_op:
            batch_op.drop_column(_COL)
    if has_table(_T):
        for ix in (_IX_FW, _IX_SITE, _UX):
            if has_index(_T, ix):
                op.drop_index(ix, table_name=_T)
        op.drop_table(_T)
