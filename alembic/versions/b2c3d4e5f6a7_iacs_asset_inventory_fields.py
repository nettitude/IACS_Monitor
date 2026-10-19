"""iacs-asset-inventory-fields

Adds IACS asset inventory columns to the hosts table:

  Physical identity:  model, serial_number, firmware_version
  Physical location:  site, building, panel
  Operational:        criticality, is_safety_function
  Ownership:          owner, asset_tag, notes
  Approval workflow:  approved, approved_by, approved_at,
                      last_reviewed_at, last_reviewed_by

All columns are nullable — existing hosts are unaffected and the new
fields are populated gradually via the PATCH /assets/{id} endpoint or
the extended asset-inventory CSV import.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-29 00:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# alembic/ holds the shared helpers; make them importable even for commands
# (heads, history) that load revisions without running env.py.
_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_column, is_offline

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_COLUMNS = (
    # Physical identity
    ("model",            sa.String(128)),
    ("serial_number",    sa.String(128)),
    ("firmware_version", sa.String(128)),
    # Physical location
    ("site",             sa.String(128)),
    ("building",         sa.String(128)),
    ("panel",            sa.String(128)),
    # Operational classification
    ("criticality",         sa.String(16)),
    ("is_safety_function",  sa.Boolean()),
    # Ownership
    ("owner",      sa.String(128)),
    ("asset_tag",  sa.String(64)),
    ("notes",      sa.Text()),
    # Approval workflow
    ("approved",         sa.Boolean()),
    ("approved_by",      sa.String(128)),
    ("approved_at",      sa.DateTime()),
    ("last_reviewed_at", sa.DateTime()),
    ("last_reviewed_by", sa.String(128)),
)


def upgrade() -> None:
    # Idempotent (T1-02): only columns that are missing are added.
    missing = [(n, t) for n, t in _COLUMNS if not has_column("hosts", n)]
    if not missing:
        return
    with op.batch_alter_table("hosts") as batch_op:
        for name, type_ in missing:
            batch_op.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    present = [n for n, _ in _COLUMNS if is_offline() or has_column("hosts", n)]
    if not present:
        return
    with op.batch_alter_table("hosts") as batch_op:
        for col in present:
            batch_op.drop_column(col)
