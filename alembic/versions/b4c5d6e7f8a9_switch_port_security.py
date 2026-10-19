"""FortiLink-managed FortiSwitch ports and IPsec tunnel selectors (owner 2026-10-19)

  switch_interfaces.port_security_policy, admin_status, uplink (bool, default false)
  firewall_interfaces.tunnel_info (JSON: peer, wan interface, backup_of, members, phase 2 selectors)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: b4c5d6e7f8a9
Revises: f8a9b0c1d2e3
Create Date: 2026-10-19 12:00:00.000000
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

revision: str = "b4c5d6e7f8a9"
down_revision: Union[str, Sequence[str], None] = "f8a9b0c1d2e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "switch_interfaces"


def _cols():
    return [
        sa.Column("port_security_policy", sa.String(length=128), nullable=True),
        sa.Column("admin_status", sa.String(length=8), nullable=True),
        sa.Column("uplink", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    ]


_T2 = "firewall_interfaces"


def _cols2():
    from sqlalchemy.dialects import postgresql
    return [sa.Column("tunnel_info", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True)]


def _add(table, cols):
    if not (is_offline() or has_table(table)):
        return
    missing = [c for c in cols if is_offline() or not has_column(table, c.name)]
    if not missing:
        return
    if is_offline() and dialect_name() == "sqlite":
        for c in missing:
            op.add_column(table, c)
        return
    with op.batch_alter_table(table) as batch_op:
        for c in missing:
            batch_op.add_column(c)


def upgrade() -> None:
    _add(_T, _cols())
    _add(_T2, _cols2())


def downgrade() -> None:
    for table, cols in ((_T, _cols()), (_T2, _cols2())):
        if not (is_offline() or has_table(table)):
            continue
        with op.batch_alter_table(table) as batch_op:
            for c in cols:
                if is_offline() or has_column(table, c.name):
                    batch_op.drop_column(c.name)
