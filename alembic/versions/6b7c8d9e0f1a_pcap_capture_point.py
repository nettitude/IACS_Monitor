"""pcap_captures: capture point of a PCAP upload (VD-02a)

  pcap_captures.capture_networks TEXT     - comma-separated CIDRs of the segment the capture
                                            was taken on (a switch SPAN that is no firewall port)
  pcap_captures.gateway_macs     TEXT     - JSON list of the router / firewall MACs the
                                            capture point identified
  pcap_captures.reprocessed_at   DATETIME - last associate-and-reprocess run
  pcap_captures.association      VARCHAR  - interface | firewall | segment | none (operator
                                            vouched); NULL = legacy / suggested only

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 6b7c8d9e0f1a
Revises: 5a6b7c8d9e0f
Create Date: 2026-10-08 18:00:00.000000
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

revision: str = "6b7c8d9e0f1a"
down_revision: Union[str, Sequence[str], None] = "5a6b7c8d9e0f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "pcap_captures"
_COLS = (("capture_networks", sa.Text()), ("gateway_macs", sa.Text()), ("reprocessed_at", sa.DateTime()),
         ("association", sa.String(16)))


def upgrade() -> None:
    for name, typ in _COLS:
        if is_offline() or (has_table(_T) and not has_column(_T, name)):
            op.add_column(_T, sa.Column(name, typ, nullable=True))


def downgrade() -> None:
    for name, _typ in reversed(_COLS):
        if is_offline() or has_column(_T, name):
            with op.batch_alter_table(_T) as b:
                b.drop_column(name)
