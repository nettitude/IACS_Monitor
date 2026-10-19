"""fortios-zones-nat-order: zones (B-07), NAT order/exemption (B-13), NAT text + iface vdom (B-15)

B-07: FortiOS zones (`config system zone`, SD-WAN zones) and their member
interfaces, per (firewall, VDOM), so analysis can expand a zone named in a
policy's srcintf / dstintf without re-parsing the config:
  firewall_zone_defs (id, firewall_id FK firewalls ON DELETE CASCADE, vdom,
                      name, kind, intrazone, members JSON, members_resolved,
                      source_file)
  ix_fw_zone_def_fw_vdom_name (firewall_id, vdom, name)

B-13: central-snat-map is first-match in configured order and a `nat
disable` entry is an exemption:
  nat_rules.sequence    INTEGER NULL
  nat_rules.nat_exempt  BOOLEAN NOT NULL DEFAULT false

B-15(a): interfaces are pruned per VDOM scope on re-ingest:
  firewall_interfaces.vdom  VARCHAR(64) NULL

B-15(b): NAT address / interface / policy lists were cut to 64-255 chars:
  nat_rules.policy_id, src_intf, dst_intf, orig_src, orig_dst, ext_ip,
  mapped_ip  ->  TEXT

The type changes and the FK-less column adds run in batch mode (SQLite
rebuilds the table; PostgreSQL issues plain ALTERs).  Idempotent
(alembic/iasc_migration_utils.py): a database built by init_db() from the
current models already has everything and every step is skipped.  Offline
(--sql) renders always emit the DDL (the baseline predates these objects).
No app.models import.

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-10-04 12:00:00.000000
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

from iasc_migration_utils import (  # noqa: E402
    dialect_name, get_column, has_column, has_index, has_table, is_offline,
)

revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, Sequence[str], None] = "a2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ZONE_TABLE = "firewall_zone_defs"
_ZONE_IDX = "ix_fw_zone_def_fw_vdom_name"

# nat_rules columns widened to TEXT: name -> previous type (for downgrade)
_NAT_TEXT = (
    ("policy_id", 64), ("src_intf", 255), ("dst_intf", 255), ("orig_src", 128),
    ("orig_dst", 255), ("ext_ip", 128), ("mapped_ip", 128),
)


def _json():
    """JSONB on PostgreSQL, generic JSON elsewhere (mirrors models._json_column)."""
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def _is_text(table: str, column: str) -> bool:
    col = get_column(table, column)
    if col is None:
        return False
    t = col["type"]
    return isinstance(t, sa.Text) or (
        isinstance(t, sa.String) and getattr(t, "length", None) is None)


def upgrade() -> None:
    # --- B-07: zone definitions ---------------------------------------------
    if is_offline() or not has_table(_ZONE_TABLE):
        op.create_table(
            _ZONE_TABLE,
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("firewall_id", sa.Integer(), nullable=False),
            sa.Column("vdom", sa.String(length=64), nullable=True),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("kind", sa.String(length=16), server_default="zone", nullable=False),
            sa.Column("intrazone", sa.String(length=8), nullable=True),
            sa.Column("members", _json(), nullable=True),
            sa.Column("members_resolved", sa.Boolean(), server_default=sa.true(),
                      nullable=False),
            sa.Column("source_file", sa.String(length=512), nullable=True),
            sa.ForeignKeyConstraint(["firewall_id"], ["firewalls.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
    if is_offline() or not has_index(_ZONE_TABLE, _ZONE_IDX):
        op.create_index(_ZONE_IDX, _ZONE_TABLE, ["firewall_id", "vdom", "name"])

    # --- B-15(a): interface VDOM ----------------------------------------------
    if is_offline() or (has_table("firewall_interfaces")
                        and not has_column("firewall_interfaces", "vdom")):
        op.add_column("firewall_interfaces",
                      sa.Column("vdom", sa.String(length=64), nullable=True))

    # --- B-13 / B-15(b): nat_rules ----------------------------------------------
    if not (is_offline() or has_table("nat_rules")):
        return
    add_seq = is_offline() or not has_column("nat_rules", "sequence")
    add_exempt = is_offline() or not has_column("nat_rules", "nat_exempt")
    widen = [(c, n) for c, n in _NAT_TEXT
             if is_offline() or (has_column("nat_rules", c) and not _is_text("nat_rules", c))]
    if is_offline() and dialect_name() == "sqlite":
        # Offline SQLite render: batch mode cannot reflect the table.  The new
        # columns are plain ADD COLUMNs; SQLite does not enforce VARCHAR
        # lengths, so the TEXT widening is a no-op there (an online upgrade
        # rebuilds the table in batch mode to match the models exactly).
        if add_seq:
            op.add_column("nat_rules", sa.Column("sequence", sa.Integer(), nullable=True))
        if add_exempt:
            op.add_column("nat_rules", sa.Column("nat_exempt", sa.Boolean(), nullable=False,
                                                 server_default=sa.false()))
        return
    if add_seq or add_exempt or widen:
        with op.batch_alter_table("nat_rules") as batch_op:
            if add_seq:
                batch_op.add_column(sa.Column("sequence", sa.Integer(), nullable=True))
            if add_exempt:
                batch_op.add_column(sa.Column("nat_exempt", sa.Boolean(), nullable=False,
                                              server_default=sa.false()))
            for col, length in widen:
                batch_op.alter_column(col, existing_type=sa.String(length=length),
                                      type_=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    if is_offline() and dialect_name() == "sqlite":
        raise NotImplementedError("offline SQLite downgrade of b3c4d5e6f7a8 is not supported "
                                  "(batch mode needs a live connection)")
    if is_offline() or has_table("nat_rules"):
        drop = [c for c in ("sequence", "nat_exempt")
                if is_offline() or has_column("nat_rules", c)]
        narrow = [(c, n) for c, n in _NAT_TEXT
                  if is_offline() or _is_text("nat_rules", c)]
        if drop or narrow:
            # NOTE: narrowing truncates values longer than the old length on
            # backends that allow it (PostgreSQL raises instead).
            with op.batch_alter_table("nat_rules") as batch_op:
                for c in drop:
                    batch_op.drop_column(c)
                for col, length in narrow:
                    batch_op.alter_column(col, existing_type=sa.Text(),
                                          type_=sa.String(length=length),
                                          existing_nullable=True)
    if is_offline() or has_column("firewall_interfaces", "vdom"):
        with op.batch_alter_table("firewall_interfaces") as batch_op:
            batch_op.drop_column("vdom")
    if is_offline() or has_index(_ZONE_TABLE, _ZONE_IDX):
        op.drop_index(_ZONE_IDX, table_name=_ZONE_TABLE)
    if is_offline() or has_table(_ZONE_TABLE):
        op.drop_table(_ZONE_TABLE)
