"""reconcile-legacy-schema: add any columns/indexes a legacy DB is missing

Databases created by ``Base.metadata.create_all`` before Alembic was used
consistently can be missing columns and indexes that the historical
migration chain never added (e.g. firewall_rules.rule_order,
firewall_rules.firewall_device_id, firewall_interfaces.parent_interface_id,
network_sessions pcap_capture index, the hosts partial unique indexes).
No single revision stamp describes such a database, so ``alembic stamp X``
followed by ``alembic upgrade head`` could leave it silently out of date.

This revision closes that gap.  It is ADDITIVE ONLY:
  * tables missing entirely are created;
  * columns missing from existing tables are added.  A NOT NULL column with
    no server default is added as NULLable (existing rows have no value for
    it) and a WARNING is logged;
  * indexes missing by name are created.  A UNIQUE index that cannot be
    built because existing rows violate it is skipped with a WARNING naming
    the index, so the upgrade still completes and the operator can clean up
    the duplicates and re-run ``alembic upgrade head`` after stamping back
    one revision (or create the index by hand).
  * on PostgreSQL, length-limited VARCHAR columns that the models now declare
    as TEXT are widened (SQLite ignores VARCHAR lengths, so nothing to do).
It never drops, renames or narrows anything.

Target schema: the application's ``Base.metadata`` at the time the upgrade
runs.  That couples this revision to the live models, which is acceptable
ONLY because (a) it is additive, and (b) every migration in this project is
written idempotently (see alembic/iasc_migration_utils.py), so a later
revision that adds the same column/index simply finds it present and skips.
Keep both properties for all future revisions.

Legacy / unversioned databases: stamp at the baseline and upgrade:
    alembic stamp 0001baseline0 && alembic upgrade head
(install.sh, docker-entrypoint.sh and app.db.init_db do this automatically.)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-30 00:00:00.000000
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
_PROJECT_ROOT = os.path.dirname(_ALEMBIC_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from iasc_migration_utils import dialect_name, is_offline  # noqa: E402

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")


def _target_metadata() -> sa.MetaData:
    from app.db import Base
    from app import models  # noqa: F401  (registers tables on Base.metadata)
    return Base.metadata


def _add_missing_columns(insp, table: sa.Table) -> None:
    existing = {c["name"] for c in insp.get_columns(table.name)}
    missing = [c for c in table.columns if c.name not in existing]
    if not missing:
        return
    for col in missing:
        new_col = col._copy()
        new_col.primary_key = False
        # ADD COLUMN can't carry a UNIQUE constraint on SQLite. Uniqueness must
        # be modelled as a named unique Index (created below by
        # _add_missing_indexes); a column-level unique=True is dropped here.
        if new_col.unique:
            log.warning(
                "reconcile: %s.%s declares unique=True at column level; added "
                "without it. Model uniqueness as a named unique Index instead.",
                table.name, col.name,
            )
            new_col.unique = False
        # Keep the FK in the column definition where the dialect allows it
        # inline (SQLite ADD COLUMN ... REFERENCES; PostgreSQL ADD COLUMN ...
        # REFERENCES both work), but never make an existing table's new
        # column NOT NULL without a default: existing rows have no value.
        if not col.nullable and col.server_default is None:
            new_col.nullable = True
            if col.name == "site_id":
                # Multi-site: c0d1e2f3a4b5 (later in the chain) backfills the
                # Default site and makes it NOT NULL - nothing to do by hand.
                log.info("reconcile: added %s.site_id NULLable; c0d1e2f3a4b5 "
                         "backfills and tightens it", table.name)
                op.add_column(table.name, new_col)
                continue
            log.warning(
                "reconcile: %s.%s is NOT NULL in the models but has no server "
                "default; added as NULLable. Backfill it, then tighten manually.",
                table.name, col.name,
            )
        op.add_column(table.name, new_col)
        log.info("reconcile: added column %s.%s", table.name, col.name)


def _widen_text_columns(insp, table: sa.Table) -> None:
    if dialect_name() != "postgresql":
        return
    live = {c["name"]: c for c in insp.get_columns(table.name)}
    for col in table.columns:
        if not isinstance(col.type, sa.Text) or col.name not in live:
            continue
        live_type = live[col.name]["type"]
        if isinstance(live_type, sa.String) and getattr(live_type, "length", None):
            op.alter_column(table.name, col.name, type_=sa.Text(),
                            existing_type=live_type,
                            existing_nullable=live[col.name]["nullable"])
            log.info("reconcile: widened %s.%s to TEXT", table.name, col.name)


def _add_missing_indexes(insp, table: sa.Table) -> None:
    existing = {ix["name"] for ix in insp.get_indexes(table.name)}
    # Unique constraints can also back a same-named index on some dialects.
    existing |= {uc["name"] for uc in insp.get_unique_constraints(table.name) if uc.get("name")}
    bind = op.get_bind()
    for ix in sorted(table.indexes, key=lambda i: i.name or ""):
        if not ix.name or ix.name in existing:
            continue
        if not all(c.name in {x["name"] for x in insp.get_columns(table.name)} for c in ix.columns):
            continue
        if ix.unique:
            # A unique index over existing duplicates would abort the whole
            # upgrade; build it in a savepoint and skip with a warning.
            try:
                with bind.begin_nested():
                    ix.create(bind)
                log.info("reconcile: created unique index %s", ix.name)
            except sa.exc.IntegrityError as exc:
                log.warning(
                    "reconcile: could NOT create unique index %s on %s - existing "
                    "rows violate it (%s). Resolve the duplicates and create it "
                    "manually; the rest of the upgrade continues.",
                    ix.name, table.name, exc.orig,
                )
        else:
            ix.create(bind)
            log.info("reconcile: created index %s", ix.name)


def upgrade() -> None:
    if is_offline():
        # Offline renders always start at or after the baseline, which already
        # contains the full head schema; nothing to reconcile.
        return
    metadata = _target_metadata()
    bind = op.get_bind()
    insp = sa.inspect(bind)
    live_tables = set(insp.get_table_names())

    missing_tables = [t for t in metadata.sorted_tables if t.name not in live_tables]
    if missing_tables:
        metadata.create_all(bind, tables=missing_tables, checkfirst=True)
        for t in missing_tables:
            log.info("reconcile: created missing table %s", t.name)

    for table in metadata.sorted_tables:
        if table.name not in live_tables:
            continue
        _add_missing_columns(insp, table)
    insp = sa.inspect(bind)  # refresh after column adds
    for table in metadata.sorted_tables:
        if table.name not in live_tables:
            continue
        _widen_text_columns(insp, table)
        _add_missing_indexes(insp, table)


def downgrade() -> None:
    """Additive reconciliation is not reversed: the objects it adds belong to
    the head schema and removing them would break the application."""
    pass
