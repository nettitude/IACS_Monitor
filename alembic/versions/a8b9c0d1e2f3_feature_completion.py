"""feature-completion: schema for the missing-features round (F-xx / N-xx)

Contents (all additive):
  * nat_rules table (F-05 NAT modelling)
  * host_address_history table + hosts.stale (F-09 host identity / staleness)
  * findings.last_seen, findings.occurrence_count (F-04 finding lifecycle)
  * fortiana_events.vendor (F-11 multi-vendor syslog)

Idempotent like every revision in this project (see
alembic/iasc_migration_utils.py): on an online upgrade d4e5f6a7b8c9
(reconcile) may already have created these objects from the live models,
in which case each step is skipped. Offline (--sql) renders always emit the
DDL because the baseline revision predates these objects.

Revision ID: a8b9c0d1e2f3
Revises: f6a7b8c9d0e1
Create Date: 2026-10-01 00:00:00.000000
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

# Timestamps: plain DateTime - app.models.UTCDateTime stores naive UTC in an
# ordinary TIMESTAMP column, so the DDL is identical (and migrations must not
# import the live models).

revision: str = "a8b9c0d1e2f3"
down_revision: Union[str, Sequence[str], None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _missing_table(name: str) -> bool:
    return is_offline() or not has_table(name)


def _missing_index(table: str, name: str) -> bool:
    return is_offline() or not has_index(table, name)


def _missing_column(table: str, name: str) -> bool:
    return is_offline() or not has_column(table, name)


def upgrade() -> None:
    # F-05: address translation rules
    if _missing_table("nat_rules"):
        op.create_table(
            "nat_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("firewall_id", sa.Integer(),
                      sa.ForeignKey("firewalls.id", ondelete="CASCADE"), nullable=True),
            sa.Column("firewall_device_id", sa.Integer(),
                      sa.ForeignKey("firewall_devices.id", ondelete="CASCADE"), nullable=True),
            sa.Column("device_name", sa.String(255), nullable=True),
            sa.Column("device_type", sa.String(32), nullable=True),
            sa.Column("nat_type", sa.String(8), nullable=False),
            sa.Column("name", sa.String(255), nullable=True),
            sa.Column("policy_id", sa.String(64), nullable=True),
            sa.Column("protocol", sa.String(16), nullable=True),
            sa.Column("src_intf", sa.String(255), nullable=True),
            sa.Column("orig_src", sa.String(128), nullable=True),
            sa.Column("ext_ip", sa.String(128), nullable=True),
            sa.Column("ext_port", sa.String(255), nullable=True),
            sa.Column("mapped_ip", sa.String(128), nullable=True),
            sa.Column("mapped_port", sa.String(255), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("source_file", sa.String(512), nullable=True),
            sa.Column("raw", sa.Text(), nullable=True),
        )
    if _missing_index("nat_rules", "ix_nat_rules_firewall_id"):
        op.create_index("ix_nat_rules_firewall_id", "nat_rules", ["firewall_id"])
    if _missing_index("nat_rules", "ix_nat_rules_firewall_device_id"):
        op.create_index("ix_nat_rules_firewall_device_id", "nat_rules", ["firewall_device_id"])

    # F-09: host identity history + staleness
    if _missing_column("hosts", "stale"):
        op.add_column("hosts", sa.Column("stale", sa.Boolean(), nullable=False,
                                         server_default=sa.false()))
    if _missing_table("host_address_history"):
        op.create_table(
            "host_address_history",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("host_id", sa.Integer(),
                      sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ip", sa.String(45), nullable=True),
            sa.Column("mac", sa.String(17), nullable=True),
            sa.Column("first_seen", sa.DateTime(), nullable=True),
            sa.Column("last_seen", sa.DateTime(), nullable=True),
            sa.Column("source", sa.String(32), nullable=False, server_default=sa.text("'unknown'")),
            sa.Column("observation_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        )
    for ix_name, cols, unique in (
        ("ix_host_address_history_host_id", ["host_id"], False),
        ("ix_host_address_history_ip", ["ip"], False),
        ("ix_host_address_history_mac", ["mac"], False),
        ("ux_host_address_history", ["host_id", "ip", "mac", "source"], True),
    ):
        if _missing_index("host_address_history", ix_name):
            op.create_index(ix_name, "host_address_history", cols, unique=unique)

    # F-04: finding lifecycle
    if _missing_column("findings", "last_seen"):
        op.add_column("findings", sa.Column("last_seen", sa.DateTime(), nullable=True))
    if _missing_column("findings", "occurrence_count"):
        op.add_column("findings", sa.Column("occurrence_count", sa.Integer(), nullable=False,
                                            server_default=sa.text("1")))

    # F-11: multi-vendor syslog
    if _missing_column("fortiana_events", "vendor"):
        op.add_column("fortiana_events", sa.Column("vendor", sa.String(32), nullable=True))


def downgrade() -> None:
    for table, column in (("fortiana_events", "vendor"), ("findings", "occurrence_count"),
                          ("findings", "last_seen"), ("hosts", "stale")):
        if is_offline() or has_column(table, column):
            with op.batch_alter_table(table) as batch_op:
                batch_op.drop_column(column)
    for table in ("host_address_history", "nat_rules"):
        if is_offline() or has_table(table):
            op.drop_table(table)
