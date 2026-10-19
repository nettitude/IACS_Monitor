"""nat-central-vdom: VDOM-qualified policy identity (N-24) + richer NAT rows (N-25)

N-24 (VDOM part): a FortiOS policy id is unique only inside its VDOM, so the
same id in two VDOMs used to collapse into one row.
  firewall_rules.vdom        VARCHAR(64) NULL
  ix_firewall_rule_fw_vdom_policy (firewall_id, vdom, policy_id)
Existing rows keep vdom NULL (no VDOM was stored; a NULL vdom means "no VDOM
wrapper in the config" and is treated as its own identity everywhere).

N-25: central SNAT / VIP46 / VIP64 rows need to say what produced them and
which egress interface / destination they are limited to.
  nat_rules.nat_kind  VARCHAR(24) NULL   vip | vip46 | vip64 | policy-nat | central-snat
  nat_rules.dst_intf  VARCHAR(255) NULL  SNAT egress interface(s)
  nat_rules.orig_dst  VARCHAR(255) NULL  SNAT destination limit (central-snat dst-addr)
  nat_rules.vdom      VARCHAR(64) NULL

Only nullable columns and one index are added, so no table rebuild (batch
mode) is needed on upgrade; the downgrade drops them in batch mode (SQLite).
Idempotent (alembic/iasc_migration_utils.py): on an online upgrade of a
legacy database d4e5f6a7b8c9 (reconcile) may already have added the columns
from the live models - they are then found and skipped.  Offline (--sql)
renders always emit the DDL (the baseline predates these columns).

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-10-02 20:00:00.000000
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

revision: str = "a2b3c4d5e6f7"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_IDX = "ix_firewall_rule_fw_vdom_policy"
_COLUMNS = (
    ("firewall_rules", "vdom", lambda: sa.Column("vdom", sa.String(length=64), nullable=True)),
    ("nat_rules", "nat_kind", lambda: sa.Column("nat_kind", sa.String(length=24), nullable=True)),
    ("nat_rules", "dst_intf", lambda: sa.Column("dst_intf", sa.String(length=255), nullable=True)),
    ("nat_rules", "orig_dst", lambda: sa.Column("orig_dst", sa.String(length=255), nullable=True)),
    ("nat_rules", "vdom", lambda: sa.Column("vdom", sa.String(length=64), nullable=True)),
)


def upgrade() -> None:
    for table, name, make in _COLUMNS:
        if is_offline() or (has_table(table) and not has_column(table, name)):
            op.add_column(table, make())
    if is_offline() or (has_table("firewall_rules") and not has_index("firewall_rules", _IDX)):
        op.create_index(_IDX, "firewall_rules", ["firewall_id", "vdom", "policy_id"])


def downgrade() -> None:
    if is_offline() or has_index("firewall_rules", _IDX):
        op.drop_index(_IDX, table_name="firewall_rules")
    for table in ("firewall_rules", "nat_rules"):
        names = [n for t, n, _ in _COLUMNS if t == table]
        todo = names if is_offline() else [n for n in names if has_column(table, n)]
        if not todo:
            continue
        with op.batch_alter_table(table) as batch_op:
            for n in todo:
                batch_op.drop_column(n)
