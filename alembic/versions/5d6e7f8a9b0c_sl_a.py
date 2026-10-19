"""IEC 62443 achieved security level (SL-A) on zones and conduits

  iec_zones.sl_a           INTEGER       1-4, NULL = not assessed
  iec_zones.sl_a_note      VARCHAR(255)  assessment reference / date
  iec_conduits.sl_a        INTEGER
  iec_conduits.sl_a_note   VARCHAR(255)

Documentation only.  Fresh installs; idempotent (alembic/iasc_migration_utils.py).
No app.models import.

Revision ID: 5d6e7f8a9b0c
Revises: 4c5d6e7f8a9b
Create Date: 2026-10-11 12:00:00.000000
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

revision: str = "5d6e7f8a9b0c"
down_revision: Union[str, Sequence[str], None] = "4c5d6e7f8a9b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLS = [(t, name, typ) for t in ("iec_zones", "iec_conduits")
         for name, typ in (("sl_a", sa.Integer()), ("sl_a_note", sa.String(length=255)))]


def upgrade() -> None:
    for t, name, typ in _COLS:
        if is_offline() or (has_table(t) and not has_column(t, name)):
            op.add_column(t, sa.Column(name, typ, nullable=True))


def downgrade() -> None:
    for t, name, _typ in _COLS:
        if is_offline() or has_column(t, name):
            with op.batch_alter_table(t) as b:
                b.drop_column(name)
