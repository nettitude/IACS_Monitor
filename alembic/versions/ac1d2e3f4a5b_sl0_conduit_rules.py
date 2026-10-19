"""SL0 security level and conduit firewall rules (owner 2026-10-13)

  iec_zones / iec_conduits: ck_*_sl_t now allows 0 (SL0 - No Requirements):
      sl_t IS NULL OR sl_t IN (0, 1, 2, 3, 4)
  iec_conduit_rules (site_id, conduit_id -> iec_conduits ON DELETE CASCADE,
                     firewall_name, vdom, policy_id, note, created_by, created_at)
      unique (conduit_id, firewall_name, vdom, policy_id)

Fresh installs; idempotent (alembic/iasc_migration_utils.py).  No app.models import.

Revision ID: ac1d2e3f4a5b
Revises: 9b0c1d2e3f4a
Create Date: 2026-10-14 09:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import dialect_name, has_index, has_table, is_offline  # noqa: E402

revision: str = "ac1d2e3f4a5b"
down_revision: Union[str, Sequence[str], None] = "9b0c1d2e3f4a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SL_CHECKS = (("iec_zones", "ck_iec_zones_sl_t"), ("iec_conduits", "ck_iec_conduits_sl_t"))
_NEW = "sl_t IS NULL OR sl_t IN (0, 1, 2, 3, 4)"
_OLD = "sl_t IS NULL OR sl_t IN (1, 2, 3, 4)"

_T = "iec_conduit_rules"
_IDX = [
    ("ux_iec_conduit_rules_policy", ["conduit_id", "firewall_name", "vdom", "policy_id"], True),
    ("ix_iec_conduit_rules_conduit_id", ["conduit_id"], False),
    ("ix_iec_conduit_rules_site_id", ["site_id"], False),
]


def _check_sql(table: str, name: str):
    """SQL text of the named CHECK constraint, None when it is not there."""
    insp = sa.inspect(op.get_bind())
    if not insp.has_table(table):
        return None
    try:
        for ck in insp.get_check_constraints(table):
            if ck.get("name") == name:
                return str(ck.get("sqltext") or "")
    except NotImplementedError:  # pragma: no cover
        return None
    return None


def _replace_check(table: str, name: str, sqltext: str) -> None:
    with op.batch_alter_table(table, recreate="auto") as b:
        b.drop_constraint(name, type_="check")
        b.create_check_constraint(name, sqltext)


def _offline_checks(sqltext: str) -> None:
    """--sql: PostgreSQL gets plain ALTER statements; SQLite cannot rebuild a table
    without a live connection (batch mode reflects it), so it gets a note."""
    if dialect_name() != "postgresql":
        op.execute("-- ac1d2e3f4a5b: SL-T CHECK constraints allowing 0 (SL0) "
                   "require an online upgrade on SQLite (table rebuild)")
        return
    for table, name in _SL_CHECKS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({sqltext})")


def _create(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("conduit_id", sa.Integer(), nullable=False),
        sa.Column("firewall_name", sa.String(length=128), nullable=False),
        sa.Column("vdom", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.ForeignKeyConstraint(["conduit_id"], ["iec_conduits.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _offline_checks(_NEW)
        _create(if_not_exists=True)
        for ix, cols, uq in _IDX:
            op.create_index(ix, _T, cols, unique=uq, if_not_exists=True)
        return
    for table, name in _SL_CHECKS:
        cur = _check_sql(table, name)
        if cur is not None and "0," not in cur.replace(" ", ""):
            _replace_check(table, name, _NEW)
    if not has_table(_T):
        _create(if_not_exists=False)
    for ix, cols, uq in _IDX:
        if not has_index(_T, ix):
            op.create_index(ix, _T, cols, unique=uq)


def downgrade() -> None:
    if is_offline():
        for ix, _c, _u in _IDX:
            op.execute(f"DROP INDEX IF EXISTS {ix}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        if dialect_name() == "postgresql":
            for table, _name in _SL_CHECKS:
                op.execute(f"UPDATE {table} SET sl_t = NULL WHERE sl_t = 0")
        _offline_checks(_OLD)
        return
    for ix, _c, _u in _IDX:
        if has_table(_T) and has_index(_T, ix):
            op.drop_index(ix, table_name=_T)
    if has_table(_T):
        op.drop_table(_T)
    for table, name in _SL_CHECKS:
        cur = _check_sql(table, name)
        if cur is not None and "0," in cur.replace(" ", ""):
            op.execute(f"UPDATE {table} SET sl_t = NULL WHERE sl_t = 0")
            _replace_check(table, name, _OLD)
