"""c-audit: widen firewall_rules zone columns (C-16), add nat_rules.orig_port (C-04)

C-16: a multi-interface FortiOS policy stores a comma-joined srcintf / dstintf
list in firewall_rules.src_zone / dst_zone.  Those columns were String(128); a
14-interface policy produces a 139-char value that overflows on PostgreSQL
(the whole config upload 500s).  Widen both to TEXT (unbounded).  SQLite never
enforced the length, so this only matters on PostgreSQL, but the column type
must still match the models everywhere (zero drift).

C-04: FortiOS central-snat-map `orig-port` limits which flows a translation /
`nat disable` exemption matches.  Add nat_rules.orig_port VARCHAR(255) NULL
(canonical FirewallRule.dst_port form); NULL = no port limit.

The type change and the column add run in batch mode (SQLite rebuilds the
table; PostgreSQL issues plain ALTERs).  Idempotent
(alembic/iasc_migration_utils.py): a database built by init_db() from the
current models already has everything and every step is skipped.  Offline
(--sql) renders always emit the DDL (the baseline predates these columns).
No app.models import.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-04 17:30:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (  # noqa: E402
    dialect_name, get_column, has_column, has_table, is_offline,
)

revision: str = "e6f7a8b9c0d1"
down_revision: Union[str, Sequence[str], None] = "d5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# firewall_rules columns widened to TEXT (old String length kept for downgrade)
_RULE_TEXT = (("src_zone", 128), ("dst_zone", 128))


def _is_text(table: str, column: str) -> bool:
    col = get_column(table, column)
    if col is None:
        return False
    t = col["type"]
    return isinstance(t, sa.Text) or (
        isinstance(t, sa.String) and getattr(t, "length", None) is None)


def upgrade() -> None:
    # --- C-04: nat_rules.orig_port -----------------------------------------
    if is_offline() or has_table("nat_rules"):
        if is_offline() or not has_column("nat_rules", "orig_port"):
            op.add_column("nat_rules",
                          sa.Column("orig_port", sa.String(length=255), nullable=True))

    # --- C-16: widen firewall_rules.src_zone / dst_zone to TEXT ------------
    if not (is_offline() or has_table("firewall_rules")):
        return
    widen = [(c, n) for c, n in _RULE_TEXT
             if is_offline() or (has_column("firewall_rules", c) and not _is_text("firewall_rules", c))]
    if is_offline() and dialect_name() == "sqlite":
        # Offline SQLite render: batch mode cannot reflect the table, and
        # SQLite does not enforce VARCHAR lengths, so the TEXT widening is a
        # no-op there (an online upgrade rebuilds the table in batch mode to
        # match the models exactly).  Nothing to emit for src_zone/dst_zone.
        return
    if widen:
        with op.batch_alter_table("firewall_rules") as batch_op:
            for col, length in widen:
                batch_op.alter_column(col, existing_type=sa.String(length=length),
                                      type_=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    if is_offline() and dialect_name() == "sqlite":
        raise NotImplementedError("offline SQLite downgrade of e6f7a8b9c0d1 is not supported "
                                  "(batch mode needs a live connection)")
    if is_offline() or has_table("firewall_rules"):
        narrow = [(c, n) for c, n in _RULE_TEXT
                  if is_offline() or _is_text("firewall_rules", c)]
        if narrow:
            # NOTE: narrowing truncates values longer than the old length on
            # backends that allow it (PostgreSQL raises instead).
            with op.batch_alter_table("firewall_rules") as batch_op:
                for col, length in narrow:
                    batch_op.alter_column(col, existing_type=sa.Text(),
                                          type_=sa.String(length=length),
                                          existing_nullable=True)
    if is_offline() or has_table("nat_rules"):
        if is_offline() or has_column("nat_rules", "orig_port"):
            with op.batch_alter_table("nat_rules") as batch_op:
                batch_op.drop_column("orig_port")
