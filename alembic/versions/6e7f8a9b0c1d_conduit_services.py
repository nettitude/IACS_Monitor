"""IEC 62443 conduit services and sources (option 3: service-aware severity)

  iec_conduits.services  TEXT  comma list of service names / proto/port tokens, or "any"
  iec_conduits.sources   TEXT  comma list of addresses / CIDRs allowed to use the conduit

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 6e7f8a9b0c1d
Revises: 5d6e7f8a9b0c
Create Date: 2026-10-11 18:00:00.000000
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

revision: str = "6e7f8a9b0c1d"
down_revision: Union[str, Sequence[str], None] = "5d6e7f8a9b0c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLS = (("services", sa.Text()), ("sources", sa.Text()))


def upgrade() -> None:
    for name, typ in _COLS:
        if is_offline() or (has_table("iec_conduits") and not has_column("iec_conduits", name)):
            op.add_column("iec_conduits", sa.Column(name, typ, nullable=True))


def downgrade() -> None:
    for name, _typ in _COLS:
        if is_offline() or has_column("iec_conduits", name):
            with op.batch_alter_table("iec_conduits") as b:
                b.drop_column(name)
