"""firewall-rule-enabled: keep disabled rules, flagged, instead of dropping them

Adds firewall_rules.enabled (BOOLEAN NOT NULL DEFAULT true).  Parsers now
store administratively disabled rules (FortiOS `set status disable`, pfSense
<disabled/>, PAN-OS `disabled yes`, Cisco ASA `inactive`) with enabled=false
so review_disabled_rules can flag them for removal (checklist 3.8, SR 7.7);
every other analysis filters them out.  Existing rows default to true, which
matches the old behaviour (disabled rules were never stored).

Idempotent.  Note: d4e5f6a7b8c9 (reconcile) may already have added this
column from the live models on an online upgrade; then this is a no-op.
Offline (--sql) renders always emit the ADD COLUMN because the baseline
revision predates the column.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-30 00:00:00.000000
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

revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, Sequence[str], None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if not is_offline():
        if not has_table("firewall_rules") or has_column("firewall_rules", "enabled"):
            return
    op.add_column(
        "firewall_rules",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    if is_offline() or has_column("firewall_rules", "enabled"):
        # Without the column, disabled rules would silently read as ACTIVE
        # rules in every analysis. The old schema never stored them, so
        # remove them before dropping the flag.
        op.execute("DELETE FROM firewall_rules WHERE enabled = false"
                   if op.get_context().dialect.name == "postgresql"
                   else "DELETE FROM firewall_rules WHERE enabled = 0")
        with op.batch_alter_table("firewall_rules") as batch_op:
            batch_op.drop_column("enabled")
