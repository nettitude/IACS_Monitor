"""Flat OT tabletop FO-01 / FO-04: capture segment and connection attempts

  pcap_captures.segment  TEXT  - JSON: the L2 segment the capture shows (networks, basis,
                                 gateway MACs, on-link address count)
  connection_attempts          - refused / unanswered / data-less TCP attempts and
                                 unanswered ARP requests seen in a capture (not sessions)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 7c8d9e0f1a2b
Revises: 6b7c8d9e0f1a
Create Date: 2026-10-08 22:00:00.000000
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

revision: str = "7c8d9e0f1a2b"
down_revision: Union[str, Sequence[str], None] = "6b7c8d9e0f1a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "connection_attempts"
_IX_SITE = "ix_connection_attempts_site_id"
_IX_CAP = "ix_connection_attempts_pcap_capture_id"
_IX_SRC = "ix_connection_attempts_src"


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("pcap_capture_id", sa.Integer(), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=False),
        sa.Column("src_mac", sa.String(length=17), nullable=True),
        sa.Column("dst_ip", sa.String(length=64), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("transport", sa.String(length=8), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline() or (has_table("pcap_captures") and not has_column("pcap_captures", "segment")):
        op.add_column("pcap_captures", sa.Column("segment", sa.Text(), nullable=True))
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_IX_SITE, _T, ["site_id"], if_not_exists=True)
        op.create_index(_IX_CAP, _T, ["pcap_capture_id"], if_not_exists=True)
        op.create_index(_IX_SRC, _T, ["site_id", "src_ip"], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    for name, cols in ((_IX_SITE, ["site_id"]), (_IX_CAP, ["pcap_capture_id"]), (_IX_SRC, ["site_id", "src_ip"])):
        if not has_index(_T, name):
            op.create_index(name, _T, cols)


def downgrade() -> None:
    if is_offline() or has_table(_T):
        op.drop_table(_T)
    if is_offline() or has_column("pcap_captures", "segment"):
        with op.batch_alter_table("pcap_captures") as b:
            b.drop_column("segment")
