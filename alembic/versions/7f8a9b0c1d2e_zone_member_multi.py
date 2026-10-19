"""IEC 62443 zone members: a host may be in several zones

  iec_zone_members: unique (site_id, kind, ref) -> unique (site_id, zone_id, kind, ref)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: 7f8a9b0c1d2e
Revises: 6e7f8a9b0c1d
Create Date: 2026-10-11 20:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_index, has_table, is_offline  # noqa: E402

revision: str = "7f8a9b0c1d2e"
down_revision: Union[str, Sequence[str], None] = "6e7f8a9b0c1d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "iec_zone_members"
_OLD = "ux_iec_zone_members_site_kind_ref"
_NEW = "ux_iec_zone_members_zone_kind_ref"


def upgrade() -> None:
    if not is_offline() and not has_table(_T):
        return
    if is_offline() or has_index(_T, _OLD):
        op.drop_index(_OLD, table_name=_T)
    if is_offline() or not has_index(_T, _NEW):
        op.create_index(_NEW, _T, ["site_id", "zone_id", "kind", "ref"], unique=True)


def downgrade() -> None:
    if is_offline() or has_index(_T, _NEW):
        op.drop_index(_NEW, table_name=_T)
    if is_offline() or not has_index(_T, _OLD):
        op.create_index(_OLD, _T, ["site_id", "kind", "ref"], unique=True)
