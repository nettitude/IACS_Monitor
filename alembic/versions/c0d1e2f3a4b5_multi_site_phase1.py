"""multi-site-phase1: sites table, Default site, site_id on every root table

docs/multi-site-design.md, phase 1.

  1. CREATE TABLE sites (id, name, code, description, created_at) with
     unique indexes ux_sites_name / ux_sites_code;
  2. INSERT the Default site (name "Default", code "default") unless a site
     with that code (or name) already exists;
  3. for every root table (_TABLES): ADD COLUMN site_id (nullable), backfill
     every row with the Default site, then make it NOT NULL with a FOREIGN
     KEY to sites.id (<table>_site_id_fkey) and index ix_<table>_site_id.

Children (firewall_interfaces, network_sessions, protocol_details,
host_address_history, approved_comms, approved_hosts) inherit their site
through their NOT NULL parent FK and get no column; firewall_rules and
nat_rules get one because both of their parent FKs are nullable (see
app.models.SiteScoped).

Idempotent (alembic/iasc_migration_utils.py).  In particular d4e5f6a7b8c9
(reconcile) adds missing model columns from the LIVE models on an online
upgrade, so on a legacy database stamped at an older revision it will
already have created ``sites`` (empty) and added every site_id column as
NULLable (NOT NULL without a server default is downgraded to NULL there),
possibly with an inline FK and the ix_*_site_id index.  This revision then
finds those objects, inserts the Default site, backfills the NULLs and only
tightens / adds what is still missing.  Rows are backfilled whether or not
the column already existed, so the NOT NULL step can never fail on a NULL.

SQLite: NOT NULL + FK need a table rebuild (batch mode, recreate="always",
only for tables that still need it).  PostgreSQL: ALTER COLUMN SET NOT NULL
+ ADD CONSTRAINT.  Offline (--sql) renders emit the full PostgreSQL DDL
with IF [NOT] EXISTS guards (always - the baseline predates sites, so even
a render from base needs it); on SQLite the rebuild needs a live
connection, so offline emits a comment only.

Downgrade drops site_id from every root table and the sites table (all
data then belongs to the single implicit site again).

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-10-01 12:00:00.000000
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
    has_column,
    has_index,
    has_table,
    is_offline,
)

revision: str = "c0d1e2f3a4b5"
down_revision: Union[str, Sequence[str], None] = "b9c0d1e2f3a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")

# Kept in sync with app.models (classes mixing in SiteScoped) by hand:
# migrations must not import the application.
_TABLES = (
    "baselines",
    "firewalls",
    "firewall_devices",
    "firewall_rules",
    "nat_rules",
    "firewall_zones",
    "hosts",
    "pcap_captures",
    "fortiana_events",
    "findings",
    "attestations",
    "switch_interfaces",
    "switch_vlans",
    "mac_table_entries",
)

_DEFAULT_CODE = "default"
_DEFAULT_NAME = "Default"
_DEFAULT_DESC = "Created by migration c0d1e2f3a4b5; holds data uploaded before sites existed."

# The Default site's id, resolved in SQL so the same statement works online
# and in an offline render.
_DEFAULT_ID_SQL = (f"(SELECT MIN(id) FROM sites WHERE code = '{_DEFAULT_CODE}' "
                   f"OR name = '{_DEFAULT_NAME}')")


def _fk_name(table: str) -> str:
    # PostgreSQL's default name for an unnamed column FK (what the models'
    # unnamed ForeignKey would get from create_all).
    return f"{table}_site_id_fkey"


def _ix_name(table: str) -> str:
    return f"ix_{table}_site_id"


def _sites_table_ddl() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        if_not_exists=is_offline(),
    )


def _insert_default_site(tables=None) -> None:
    """The Default site holds rows that existed before sites did.  EI-01: it
    is inserted only when one of ``tables`` (default: all root tables) has
    rows to backfill - a fresh install starts with no site at all."""
    tables = list(_TABLES if tables is None else tables)
    if not tables:
        return
    has_rows = " OR ".join(f"EXISTS (SELECT 1 FROM {t})" for t in tables)
    op.execute(
        "INSERT INTO sites (name, code, description, created_at) "
        f"SELECT '{_DEFAULT_NAME}', '{_DEFAULT_CODE}', '{_DEFAULT_DESC}', CURRENT_TIMESTAMP "
        f"WHERE NOT EXISTS (SELECT 1 FROM sites WHERE code = '{_DEFAULT_CODE}' "
        f"OR name = '{_DEFAULT_NAME}') AND ({has_rows})"
    )


def _backfill(table: str) -> None:
    op.execute(f"UPDATE {table} SET site_id = {_DEFAULT_ID_SQL} WHERE site_id IS NULL")


# ---------------------------------------------------------------- offline --

def _offline_upgrade() -> None:
    if dialect_name() != "postgresql":
        op.execute("-- c0d1e2f3a4b5: sites + NOT NULL site_id (table rebuilds) require "
                   "an online upgrade on SQLite")
        return
    _sites_table_ddl()
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_sites_name ON sites (name)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_sites_code ON sites (code)")
    _insert_default_site()
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS site_id INTEGER")
        _backfill(table)
        op.execute(f"ALTER TABLE {table} ALTER COLUMN site_id SET NOT NULL")
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {_fk_name(table)}")
        op.create_foreign_key(_fk_name(table), table, "sites", ["site_id"], ["id"])
        op.execute(f"CREATE INDEX IF NOT EXISTS {_ix_name(table)} ON {table} (site_id)")


# ----------------------------------------------------------------- online --

def _site_fk(table: str):
    for fk in sa.inspect(op.get_bind()).get_foreign_keys(table):
        if fk.get("constrained_columns") == ["site_id"] and fk.get("referred_table") == "sites":
            return fk
    return None


def _online_upgrade() -> None:
    sqlite = dialect_name() == "sqlite"
    if not has_table("sites"):
        _sites_table_ddl()
    if not has_index("sites", "ux_sites_name"):
        op.create_index("ux_sites_name", "sites", ["name"], unique=True)
    if not has_index("sites", "ux_sites_code"):
        op.create_index("ux_sites_code", "sites", ["code"], unique=True)
    _insert_default_site([t for t in _TABLES if has_table(t)])

    for table in _TABLES:
        if not has_table(table):
            continue
        if not has_column(table, "site_id"):
            # Nullable first: existing rows have no site yet.
            op.add_column(table, sa.Column("site_id", sa.Integer(), nullable=True))
        _backfill(table)

        needs_not_null = bool((get_column(table, "site_id") or {}).get("nullable", True))
        needs_fk = _site_fk(table) is None
        if needs_not_null or needs_fk:
            log.info("c0d1e2f3a4b5: %s.site_id%s%s", table,
                     " -> NOT NULL" if needs_not_null else "",
                     " + FK sites.id" if needs_fk else "")
            if sqlite:
                with op.batch_alter_table(table, recreate="always") as batch:
                    if needs_not_null:
                        batch.alter_column("site_id", existing_type=sa.Integer(),
                                           nullable=False)
                    if needs_fk:
                        batch.create_foreign_key(_fk_name(table), "sites",
                                                 ["site_id"], ["id"])
            else:
                if needs_not_null:
                    op.alter_column(table, "site_id", existing_type=sa.Integer(),
                                    nullable=False)
                if needs_fk:
                    op.create_foreign_key(_fk_name(table), table, "sites",
                                          ["site_id"], ["id"])
        if not has_index(table, _ix_name(table)):
            op.create_index(_ix_name(table), table, ["site_id"], unique=False)


def upgrade() -> None:
    if is_offline():
        _offline_upgrade()
    else:
        _online_upgrade()


# --------------------------------------------------------------- downgrade --

def downgrade() -> None:
    offline = is_offline()
    sqlite = dialect_name() == "sqlite"
    if offline:
        if sqlite:
            op.execute("-- c0d1e2f3a4b5 downgrade requires an online connection on SQLite")
            return
        for table in _TABLES:
            # Dropping the column drops its FK and index with it.
            op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS site_id")
        op.execute("DROP TABLE IF EXISTS sites")
        return

    for table in _TABLES:
        if not has_table(table) or not has_column(table, "site_id"):
            continue
        if has_index(table, _ix_name(table)):
            op.drop_index(_ix_name(table), table_name=table)
        if sqlite:
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.drop_column("site_id")
        else:
            fk = _site_fk(table)
            if fk is not None and fk.get("name"):
                op.drop_constraint(fk["name"], table, type_="foreignkey")
            op.drop_column(table, "site_id")
    if has_table("sites"):
        op.drop_table("sites")
