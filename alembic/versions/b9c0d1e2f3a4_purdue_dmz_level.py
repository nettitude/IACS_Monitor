"""purdue-dmz-level: Purdue level columns store L3.5 (industrial DMZ) (F-08)

Every Purdue level column changes from INTEGER to NUMERIC(2,1) so the
industrial DMZ can be stored as exactly 3.5, and gets a CHECK constraint
limiting it to the valid set (app.purdue.VALID_LEVELS):

    <col> IS NULL OR <col> IN (0, 1, 2, 3, 3.5, 4, 5)

  table                column(s)                                 constraint(s)
  hosts                purdue_level                              ck_host_purdue_level_valid
                                                                 (replaces ck_host_purdue_level_range, 0-5)
  firewall_devices     purdue_zone_from, purdue_zone_to          ck_fw_device_zone_{from,to}_purdue
  firewalls            purdue_level_ingress, purdue_level_egress ck_firewall_{ingress,egress}_purdue
  firewall_interfaces  purdue_level, suggested_purdue_level      ck_fw_iface_purdue_level,
                                                                 ck_fw_iface_suggested_purdue
  switch_vlans         purdue_level                              ck_switch_vlan_purdue_level

Why NUMERIC(2,1): exact fixed-point on PostgreSQL (INTEGER -> NUMERIC is an
implicit assignment cast, so ALTER COLUMN ... TYPE needs no USING); on
SQLite NUMERIC affinity keeps whole numbers as INTEGER, so existing rows are
byte-identical after the table rebuild and only 3.5 is stored as REAL.
Existing integer data (0-5) is valid under the new constraints; any value
outside the valid set (only possible on columns that had no CHECK before) is
set to NULL with a WARNING, because the new CHECK would otherwise abort the
upgrade.

SQLite: batch mode table rebuild (recreate="always") per table - type change
and constraints in one copy.  PostgreSQL: ALTER COLUMN TYPE + DROP/ADD
CONSTRAINT.

Idempotent (see alembic/iasc_migration_utils.py): a column whose reflected
type is already NUMERIC(2,1) is not altered and a constraint that already
exists (by name) is not re-added - e.g. when d4e5f6a7b8c9 (reconcile)
created a missing table from the live models.  Offline (--sql) renders emit
the full PostgreSQL DDL (DROP CONSTRAINT IF EXISTS before each ADD so the
script is safe on either starting state); on SQLite the rebuild needs a live
connection, so offline emits a comment only.

Downgrade: 3.5 cannot be represented in INTEGER, so DMZ levels are set to
NULL (unknown) first, then the columns go back to INTEGER and the original
0-5 range CHECK on hosts is restored.

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-10-01 00:00:00.000000
"""
import logging
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (  # noqa: E402
    dialect_name,
    get_column,
    has_check_constraint,
    has_column,
    has_table,
    is_offline,
)

revision: str = "b9c0d1e2f3a4"
down_revision: Union[str, Sequence[str], None] = "a8b9c0d1e2f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")

# Kept in sync with app.purdue.VALID_LEVELS / check_sql by hand: migrations
# must not import the application.
_VALID_SQL = "(0, 1, 2, 3, 3.5, 4, 5)"

# table -> [(column, constraint name)]
_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "hosts": [("purdue_level", "ck_host_purdue_level_valid")],
    "firewall_devices": [("purdue_zone_from", "ck_fw_device_zone_from_purdue"),
                         ("purdue_zone_to", "ck_fw_device_zone_to_purdue")],
    "firewalls": [("purdue_level_ingress", "ck_firewall_ingress_purdue"),
                  ("purdue_level_egress", "ck_firewall_egress_purdue")],
    "firewall_interfaces": [("purdue_level", "ck_fw_iface_purdue_level"),
                            ("suggested_purdue_level", "ck_fw_iface_suggested_purdue")],
    "switch_vlans": [("purdue_level", "ck_switch_vlan_purdue_level")],
}

# Pre-F-08 constraint replaced by ck_host_purdue_level_valid.
_OLD_HOST_CK = "ck_host_purdue_level_range"
_OLD_HOST_CK_SQL = "purdue_level IS NULL OR (purdue_level >= 0 AND purdue_level <= 5)"


def _new_type() -> sa.Numeric:
    return sa.Numeric(precision=2, scale=1)


def _check_sql(col: str) -> str:
    return f"{col} IS NULL OR {col} IN {_VALID_SQL}"


def _is_level_type(reflected) -> bool:
    t = (reflected or {}).get("type")
    return (isinstance(t, sa.Numeric) and not isinstance(t, sa.Float)
            and getattr(t, "precision", None) == 2 and getattr(t, "scale", None) == 1)


def _null_invalid(table: str, col: str) -> None:
    """Invalid values would violate the new CHECK and abort the rebuild."""
    where = f"{col} IS NOT NULL AND {col} NOT IN {_VALID_SQL}"
    if not is_offline():
        n = op.get_bind().execute(sa.text(f"SELECT COUNT(*) FROM {table} WHERE {where}")).scalar()
        if not n:
            return
        log.warning("b9c0d1e2f3a4: %s.%s - %d row(s) with a value outside the valid "
                    "Purdue levels %s set to NULL", table, col, n, _VALID_SQL)
    op.execute(f"UPDATE {table} SET {col} = NULL WHERE {where}")


# ---------------------------------------------------------------- offline --

def _offline_upgrade() -> None:
    if dialect_name() != "postgresql":
        op.execute("-- b9c0d1e2f3a4: Purdue level NUMERIC(2,1) + CHECK constraints "
                   "require an online upgrade on SQLite (table rebuild)")
        return
    for table, cols in _COLUMNS.items():
        if table == "hosts":
            op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {_OLD_HOST_CK}")
        for col, ck in cols:
            op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {ck}")
            op.alter_column(table, col, type_=_new_type(), existing_type=sa.Integer(),
                            existing_nullable=True)
            _null_invalid(table, col)
            op.create_check_constraint(ck, table, _check_sql(col))


# ----------------------------------------------------------------- online --

def _plan(table: str):
    """(columns to retype, constraints to add, drop old host CK?)"""
    retype, add_ck = [], []
    for col, ck in _COLUMNS[table]:
        if not has_column(table, col):
            continue
        if not _is_level_type(get_column(table, col)):
            retype.append(col)
        if not has_check_constraint(table, ck):
            add_ck.append((col, ck))
    drop_old = table == "hosts" and has_check_constraint(table, _OLD_HOST_CK)
    return retype, add_ck, drop_old


def _online_upgrade() -> None:
    sqlite = dialect_name() == "sqlite"
    for table in _COLUMNS:
        if not has_table(table):
            continue
        retype, add_ck, drop_old = _plan(table)
        if not (retype or add_ck or drop_old):
            continue
        for col, _ck in add_ck:
            _null_invalid(table, col)
        log.info("b9c0d1e2f3a4: %s - retype %s, add %s%s", table, retype,
                 [ck for _c, ck in add_ck], f", drop {_OLD_HOST_CK}" if drop_old else "")
        if sqlite:
            with op.batch_alter_table(table, recreate="always") as batch:
                if drop_old:
                    batch.drop_constraint(_OLD_HOST_CK, type_="check")
                for col in retype:
                    batch.alter_column(col, type_=_new_type(), existing_type=sa.Integer(),
                                       existing_nullable=True)
                for col, ck in add_ck:
                    batch.create_check_constraint(ck, sa.text(_check_sql(col)))
        else:
            if drop_old:
                op.drop_constraint(_OLD_HOST_CK, table, type_="check")
            for col in retype:
                op.alter_column(table, col, type_=_new_type(), existing_type=sa.Integer(),
                                existing_nullable=True)
            for col, ck in add_ck:
                op.create_check_constraint(ck, table, _check_sql(col))


def upgrade() -> None:
    if is_offline():
        _offline_upgrade()
    else:
        _online_upgrade()


# --------------------------------------------------------------- downgrade --

def downgrade() -> None:
    offline = is_offline()
    sqlite = dialect_name() == "sqlite"
    if offline and sqlite:
        op.execute("-- b9c0d1e2f3a4 downgrade requires an online connection on SQLite")
        return
    for table, cols in _COLUMNS.items():
        if not offline and not has_table(table):
            continue
        present = [(c, ck) for c, ck in cols if offline or has_column(table, c)]
        if not present:
            continue
        # INTEGER cannot hold the DMZ level: it becomes "unknown".
        for col, _ck in present:
            op.execute(f"UPDATE {table} SET {col} = NULL WHERE {col} = 3.5")
        drop_ck = [ck for _c, ck in present if offline or has_check_constraint(table, ck)]
        add_old = table == "hosts" and (offline or not has_check_constraint(table, _OLD_HOST_CK))
        if sqlite:
            with op.batch_alter_table(table, recreate="always") as batch:
                for ck in drop_ck:
                    batch.drop_constraint(ck, type_="check")
                for col, _ck in present:
                    batch.alter_column(col, type_=sa.Integer(), existing_type=_new_type(),
                                       existing_nullable=True)
                if add_old:
                    batch.create_check_constraint(_OLD_HOST_CK, sa.text(_OLD_HOST_CK_SQL))
        else:
            for ck in drop_ck:
                if offline:
                    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {ck}")
                else:
                    op.drop_constraint(ck, table, type_="check")
            for col, _ck in present:
                op.alter_column(table, col, type_=sa.Integer(), existing_type=_new_type(),
                                existing_nullable=True, postgresql_using=f"{col}::integer")
            if add_old:
                op.create_check_constraint(_OLD_HOST_CK, table, _OLD_HOST_CK_SQL)
