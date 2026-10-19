"""multi-site-phase2: site-scoped identity (unique indexes include site_id)

docs/multi-site-design.md, phase 2 ("Identity scoped by site").  Sites are
isolated, so every natural-key uniqueness becomes per site:

  hosts             uq_host_mac_ip / ix_host_ip_only / ix_host_mac_only
                    -> ux_hosts_site_mac_ip (site_id, mac, ip),
                       ux_hosts_site_ip_only (site_id, ip) WHERE mac IS NULL,
                       ux_hosts_site_mac_only (site_id, mac) WHERE ip IS NULL
  firewall_devices  UNIQUE(name)      -> ux_firewall_devices_site_name
  firewalls         (none)            -> ux_firewalls_site_name (NEW)
  baselines         UNIQUE(name)      -> ux_baselines_site_name, plus
                    ux_baselines_site_active (site_id) WHERE is_active (NEW:
                    one active baseline per site)
  switch_interfaces uq_switch_iface_device_port -> ux_switch_iface_site_device_port
  switch_vlans      uq_switch_vlan_device_vid   -> ux_switch_vlan_site_device_vid
  firewall_zones    uq_fw_zone_device_iface     -> ux_fw_zone_site_device_iface
  findings          ux_findings_source_ref_open -> ux_findings_site_source_ref_open
  fortiana_events   ux_fortiana_events_dedup_hash -> ux_fortiana_events_site_dedup_hash
  attestations      ix_attestation_one_current[_nobaseline]
                    -> ux_attestation_site_one_current[_nobaseline]

network_sessions.ux_session_5tuple is unchanged: its host ids are already
site-scoped (a host belongs to exactly one site), so the 5-tuple is
inherently unique per site.

Conflicts: adding site_id to an existing unique key only WIDENS it, so the
old global uniqueness guarantees the new one.  The two genuinely new rules
are resolved before their index is built:
  * several active baselines in one site -> only the newest stays active;
  * duplicate firewall / firewall_device / baseline names inside one site
    -> the later rows are renamed "<name> (#<id>)".
Any other duplicate (impossible unless the old index was missing) makes the
new index be skipped with a warning, like d4e5f6a7b8c9 does, so the upgrade
completes and the operator can clean up and re-run.

Order: new indexes are created first, then the old ones dropped, so the
table is never without a uniqueness guarantee.  On an online upgrade of a
legacy database d4e5f6a7b8c9 (reconcile) may already have created the new
indexes from the live models; they are then simply found.

SQLite: dropping a table-level UNIQUE needs a table rebuild (batch mode,
only for tables that still carry one; unnamed constraints are addressed via
a batch naming convention).  Offline (--sql) renders: full PostgreSQL DDL
with IF [NOT] EXISTS guards; SQLite gets a comment (rebuilds need a live
connection).

Downgrade restores the global uniques (skipped with a warning when rows of
different sites now collide) and drops the per-site indexes.

Revision ID: e1f2a3b4c5d6
Revises: c0d1e2f3a4b5
Create Date: 2026-10-02 12:00:00.000000
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
    has_index,
    has_table,
    is_offline,
)

revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "c0d1e2f3a4b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")

# (name, table, columns, sqlite_where, postgresql_where)
_NEW = [
    ("ux_hosts_site_mac_ip", "hosts", ["site_id", "mac", "ip"], None, None),
    ("ux_hosts_site_ip_only", "hosts", ["site_id", "ip"], "mac IS NULL", "mac IS NULL"),
    ("ux_hosts_site_mac_only", "hosts", ["site_id", "mac"], "ip IS NULL", "ip IS NULL"),
    ("ux_firewall_devices_site_name", "firewall_devices", ["site_id", "name"], None, None),
    ("ux_firewalls_site_name", "firewalls", ["site_id", "name"], None, None),
    ("ux_baselines_site_name", "baselines", ["site_id", "name"], None, None),
    ("ux_baselines_site_active", "baselines", ["site_id"], "is_active = 1", "is_active = true"),
    ("ux_switch_iface_site_device_port", "switch_interfaces",
     ["site_id", "device_name", "port_name"], None, None),
    ("ux_switch_vlan_site_device_vid", "switch_vlans",
     ["site_id", "device_name", "vlan_id"], None, None),
    ("ux_fw_zone_site_device_iface", "firewall_zones",
     ["site_id", "device_name", "interface_name"], None, None),
    ("ux_findings_site_source_ref_open", "findings", ["site_id", "source_ref"],
     "status = 'open'", "status = 'open'"),
    ("ux_fortiana_events_site_dedup_hash", "fortiana_events", ["site_id", "dedup_hash"],
     None, None),
    ("ux_attestation_site_one_current", "attestations",
     ["site_id", "checklist_id", "baseline_id"], "is_current = 1", "is_current = true"),
    ("ux_attestation_site_one_current_nobaseline", "attestations",
     ["site_id", "checklist_id"], "is_current = 1 AND baseline_id IS NULL",
     "is_current = true AND baseline_id IS NULL"),
]

# Old global partial / unique INDEXES: (name, table, columns, sqlite_where, pg_where)
_OLD_INDEXES = [
    ("ix_host_ip_only", "hosts", ["ip"], "mac IS NULL", "mac IS NULL"),
    ("ix_host_mac_only", "hosts", ["mac"], "ip IS NULL", "ip IS NULL"),
    ("ux_findings_source_ref_open", "findings", ["source_ref"],
     "status = 'open'", "status = 'open'"),
    ("ux_fortiana_events_dedup_hash", "fortiana_events", ["dedup_hash"], None, None),
    ("ix_attestation_one_current", "attestations", ["checklist_id", "baseline_id"],
     "is_current = 1", "is_current = true"),
    ("ix_attestation_one_current_nobaseline", "attestations", ["checklist_id"],
     "is_current = 1 AND baseline_id IS NULL", "is_current = true AND baseline_id IS NULL"),
]

# Old global table-level UNIQUE constraints: (pg/default name, table, columns)
_OLD_CONSTRAINTS = [
    ("uq_host_mac_ip", "hosts", ["mac", "ip"]),
    ("firewall_devices_name_key", "firewall_devices", ["name"]),
    ("baselines_name_key", "baselines", ["name"]),
    ("uq_switch_iface_device_port", "switch_interfaces", ["device_name", "port_name"]),
    ("uq_switch_vlan_device_vid", "switch_vlans", ["device_name", "vlan_id"]),
    ("uq_fw_zone_device_iface", "firewall_zones", ["device_name", "interface_name"]),
]

_RENAME_TABLES = ("firewalls", "firewall_devices", "baselines")

# Unnamed reflected UNIQUE constraints get this name inside batch mode.
_BATCH_NAMING = {"uq": "uq_%(table_name)s_%(column_0_N_name)s"}


def _true() -> str:
    return "1" if dialect_name() == "sqlite" else "true"


# ------------------------------------------------------------ resolution --

def _resolve_sql() -> list:
    t = _true()
    out = [
        # One active baseline per site: keep the newest active row.
        f"UPDATE baselines SET is_active = {'0' if t == '1' else 'false'} "
        f"WHERE is_active = {t} AND id <> (SELECT MAX(b2.id) FROM baselines b2 "
        f"WHERE b2.site_id = baselines.site_id AND b2.is_active = {t})",
    ]
    for table in _RENAME_TABLES:
        out.append(
            f"UPDATE {table} SET name = name || ' (#' || CAST(id AS VARCHAR(20)) || ')' "
            f"WHERE EXISTS (SELECT 1 FROM {table} k WHERE k.site_id = {table}.site_id "
            f"AND k.name = {table}.name AND k.id < {table}.id)")
    return out


def _has_duplicates(table: str, cols: list, where: str | None) -> bool:
    cond = " AND ".join(f"{c} IS NOT NULL" for c in cols)
    if where:
        cond = f"({where}) AND {cond}"
    sql = (f"SELECT 1 FROM {table} WHERE {cond} GROUP BY {', '.join(cols)} "
           f"HAVING COUNT(*) > 1 LIMIT 1")
    return op.get_bind().execute(sa.text(sql)).first() is not None


def _create_index(name, table, cols, swhere, pwhere, *, if_not_exists=False):
    kw = {}
    if swhere:
        kw["sqlite_where"] = sa.text(swhere)
    if pwhere:
        kw["postgresql_where"] = sa.text(pwhere)
    op.create_index(name, table, cols, unique=True, if_not_exists=if_not_exists, **kw)


# ---------------------------------------------------------------- offline --

def _offline_upgrade() -> None:
    if dialect_name() != "postgresql":
        op.execute("-- e1f2a3b4c5d6: per-site unique indexes (table rebuilds) require "
                   "an online upgrade on SQLite")
        return
    for stmt in _resolve_sql():
        op.execute(stmt)
    for name, table, cols, swhere, pwhere in _NEW:
        _create_index(name, table, cols, swhere, pwhere, if_not_exists=True)
    for name, table, *_ in _OLD_INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    for name, table, _cols in _OLD_CONSTRAINTS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")


# ----------------------------------------------------------------- online --

def _old_uniques(table: str, cols: list) -> tuple[list, list]:
    """(constraint names (None = unnamed), non-partial unique index names)
    exactly covering ``cols`` on ``table``."""
    insp = sa.inspect(op.get_bind())
    ucs = [uc.get("name") for uc in insp.get_unique_constraints(table)
           if list(uc.get("column_names") or []) == list(cols)]
    ixs = []
    for ix in insp.get_indexes(table):
        if not ix.get("unique") or list(ix.get("column_names") or []) != list(cols):
            continue
        opts = ix.get("dialect_options") or {}
        if opts.get("sqlite_where") is not None or opts.get("postgresql_where") is not None:
            continue
        if ix.get("name") in ucs:   # PG: the index backing a constraint
            continue
        ixs.append(ix["name"])
    return ucs, ixs


def _online_upgrade() -> None:
    sqlite = dialect_name() == "sqlite"
    for stmt in _resolve_sql():
        op.execute(stmt)

    for name, table, cols, swhere, pwhere in _NEW:
        if not has_table(table) or has_index(table, name):
            continue
        where = swhere if sqlite else pwhere
        if _has_duplicates(table, cols, where):
            log.warning("e1f2a3b4c5d6: NOT creating unique index %s on %s - duplicate %s "
                        "rows exist; resolve them and re-run the upgrade", name, table, cols)
            continue
        _create_index(name, table, cols, swhere, pwhere)

    for name, table, *_ in _OLD_INDEXES:
        if has_table(table) and has_index(table, name):
            op.drop_index(name, table_name=table)

    for pg_name, table, cols in _OLD_CONSTRAINTS:
        if not has_table(table):
            continue
        ucs, ixs = _old_uniques(table, cols)
        for ix in ixs:
            op.drop_index(ix, table_name=table)
        if not ucs:
            continue
        log.info("e1f2a3b4c5d6: dropping global UNIQUE%s on %s", tuple(cols), table)
        if sqlite:
            conv = "uq_%s_%s" % (table, "_".join(cols))
            with op.batch_alter_table(table, recreate="always",
                                      naming_convention=_BATCH_NAMING) as batch:
                for uc in ucs:
                    batch.drop_constraint(uc or conv, type_="unique")
        else:
            for uc in ucs:
                op.drop_constraint(uc, table, type_="unique")


def upgrade() -> None:
    if is_offline():
        _offline_upgrade()
    else:
        _online_upgrade()


# --------------------------------------------------------------- downgrade --

def downgrade() -> None:
    sqlite = dialect_name() == "sqlite"
    if is_offline():
        if sqlite:
            op.execute("-- e1f2a3b4c5d6 downgrade requires an online connection on SQLite")
            return
        for name, table, cols in _OLD_CONSTRAINTS:
            op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
            op.create_unique_constraint(name, table, cols)
        for name, table, cols, swhere, pwhere in _OLD_INDEXES:
            _create_index(name, table, cols, swhere, pwhere, if_not_exists=True)
        for name, table, *_ in _NEW:
            op.execute(f"DROP INDEX IF EXISTS {name}")
        return

    for name, table, cols in _OLD_CONSTRAINTS:
        if not has_table(table):
            continue
        ucs, _ixs = _old_uniques(table, cols)
        if ucs:
            continue
        if _has_duplicates(table, cols, None):
            log.warning("e1f2a3b4c5d6 downgrade: NOT restoring global UNIQUE%s on %s - "
                        "rows of different sites collide", tuple(cols), table)
            continue
        if sqlite:
            with op.batch_alter_table(table, recreate="always") as batch:
                batch.create_unique_constraint(name, cols)
        else:
            op.create_unique_constraint(name, table, cols)

    for name, table, cols, swhere, pwhere in _OLD_INDEXES:
        if not has_table(table) or has_index(table, name):
            continue
        if _has_duplicates(table, cols, swhere if sqlite else pwhere):
            log.warning("e1f2a3b4c5d6 downgrade: NOT restoring %s - rows of different "
                        "sites collide", name)
            continue
        _create_index(name, table, cols, swhere, pwhere)

    for name, table, *_ in _NEW:
        if has_table(table) and has_index(table, name):
            op.drop_index(name, table_name=table)
