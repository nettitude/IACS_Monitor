"""findings-open-unique, attestation-nobaseline, fw-rule-dst-port-255

Three schema changes from the T1 remediation:

1. findings.source_ref (T1-10): the global UNIQUE made a recurrence of a
   closed/acknowledged finding fail with IntegrityError.  Drop it (on SQLite
   it is an unnamed table-level constraint when the DB came from
   ``create_all``, or ``uq_findings_source_ref`` when it came through
   946998cf677b; on PostgreSQL typically ``findings_source_ref_key``; the name
   is looked up via the inspector), then create
     - ix_findings_source_ref        (plain, non-unique)
     - ux_findings_source_ref_open   (UNIQUE ... WHERE status = 'open')

2. attestations (T1-35): NULL baseline_id rows bypass
   ix_attestation_one_current because NULLs are distinct.  Add
     - ix_attestation_one_current_nobaseline
         UNIQUE (checklist_id) WHERE is_current AND baseline_id IS NULL
   Any pre-existing duplicate "current" NULL-baseline rows are demoted first
   (the newest row per checklist_id stays current).

3. firewall_rules.dst_port: String(32) -> String(255) so canonical port
   lists ("80,443,1000-2000", ...) fit.

Idempotent: every step checks the live schema first, so this is a no-op on a
DB built by 0001baseline0 (which already has the head schema).

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-30 00:00:00.000000
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

from iasc_migration_utils import (
    dialect_name,
    get_column,
    has_index,
    has_table,
    is_offline,
    offline_assume_exists,
    unique_constraints_on,
    unique_nonpartial_indexes_on,
)

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OPEN_WHERE = dict(
    sqlite_where=sa.text("status = 'open'"),
    postgresql_where=sa.text("status = 'open'"),
)
_NOBASELINE_WHERE = dict(
    postgresql_where=sa.text("is_current = true AND baseline_id IS NULL"),
    sqlite_where=sa.text("is_current = 1 AND baseline_id IS NULL"),
)
_DST_PORT_OLD = 32
_DST_PORT_NEW = 255

# Batch-mode naming convention: gives SQLite's unnamed column-level
# UNIQUE(source_ref) the name uq_findings_source_ref when the table is
# reflected, so it can be dropped by name during the table rebuild.
_BATCH_NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


# ---------------------------------------------------------------------------
# 1. findings.source_ref
# ---------------------------------------------------------------------------

def _drop_global_source_ref_unique() -> None:
    if is_offline():
        if offline_assume_exists():
            return
        if dialect_name() == "postgresql":
            # No inspector offline: drop both names this constraint has had.
            op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_source_ref_key")
            op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS uq_findings_source_ref")
        else:
            with op.batch_alter_table("findings", recreate="always",
                                      naming_convention=_BATCH_NAMING) as batch_op:
                batch_op.drop_constraint("uq_findings_source_ref", type_="unique")
        return

    ucs = unique_constraints_on("findings", ["source_ref"])
    uixs = unique_nonpartial_indexes_on(
        "findings", ["source_ref"], exclude=("ux_findings_source_ref_open",)
    )
    if not ucs and not uixs:
        return

    if dialect_name() == "sqlite":
        # SQLite cannot drop a constraint in place: rebuild the table.  The
        # partial unique index is (re)created afterwards by the caller, so
        # reflection of its WHERE clause does not matter here.
        with op.batch_alter_table("findings", recreate="always",
                                  naming_convention=_BATCH_NAMING) as batch_op:
            for uc in ucs:
                batch_op.drop_constraint(uc["name"] or "uq_findings_source_ref", type_="unique")
            for ix in uixs:
                batch_op.drop_index(ix["name"])
    else:
        for uc in ucs:
            op.drop_constraint(uc["name"], "findings", type_="unique")
        for ix in uixs:
            op.drop_index(ix["name"], table_name="findings")


def _upgrade_findings() -> None:
    if not has_table("findings"):
        return
    _drop_global_source_ref_unique()
    if not has_index("findings", "ix_findings_source_ref"):
        op.create_index("ix_findings_source_ref", "findings", ["source_ref"], unique=False)
    if not has_index("findings", "ux_findings_source_ref_open"):
        _close_duplicate_open_findings()
        op.create_index("ux_findings_source_ref_open", "findings", ["source_ref"],
                        unique=True, **_OPEN_WHERE)


def _close_duplicate_open_findings() -> None:
    """Close all but the oldest open finding per source_ref.

    Databases whose findings table never had the global UNIQUE (older
    create_all builds) can hold several OPEN rows with the same source_ref
    (seen in practice for cross_fw_* checks).  The partial unique index can't
    be built over them, so keep the oldest (lowest id) open row and close the
    rest with an explanatory note.  Nothing is deleted.
    """
    f = sa.table(
        "findings",
        sa.column("id", sa.Integer),
        sa.column("source_ref", sa.String),
        sa.column("status", sa.String),
        sa.column("closed_at", sa.DateTime),
        sa.column("notes", sa.String),
    )
    f2 = f.alias("f2")
    keep = (
        sa.select(sa.func.min(f2.c.id))
        .where(f2.c.status == "open", f2.c.source_ref.is_not(None))
        .group_by(f2.c.source_ref)
    )
    note = "Auto-closed by migration c3d4e5f6a7b8: duplicate of an older open finding with the same source_ref."
    op.execute(
        f.update()
        .where(
            f.c.status == "open",
            f.c.source_ref.is_not(None),
            f.c.id.not_in(keep),
        )
        .values(status="closed", closed_at=sa.func.current_timestamp(), notes=note)
    )


# ---------------------------------------------------------------------------
# 2. attestations: one current NULL-baseline row per checklist_id
# ---------------------------------------------------------------------------

def _upgrade_attestations() -> None:
    if not has_table("attestations") or has_index("attestations", "ix_attestation_one_current_nobaseline"):
        return

    # Demote duplicates so the unique index can be built: keep the newest
    # (highest id) current NULL-baseline row per checklist_id.
    att = sa.table(
        "attestations",
        sa.column("id", sa.Integer),
        sa.column("checklist_id", sa.String),
        sa.column("baseline_id", sa.Integer),
        sa.column("is_current", sa.Boolean),
    )
    att2 = att.alias("a2")
    keep = (
        sa.select(sa.func.max(att2.c.id))
        .where(att2.c.is_current == sa.true(), att2.c.baseline_id.is_(None))
        .group_by(att2.c.checklist_id)
    )
    op.execute(
        att.update()
        .where(
            att.c.is_current == sa.true(),
            att.c.baseline_id.is_(None),
            att.c.id.not_in(keep),
        )
        .values(is_current=False)
    )
    op.create_index("ix_attestation_one_current_nobaseline", "attestations", ["checklist_id"],
                    unique=True, **_NOBASELINE_WHERE)


# ---------------------------------------------------------------------------
# 3. firewall_rules.dst_port -> String(255)
# ---------------------------------------------------------------------------

def _dst_port_length():
    col = get_column("firewall_rules", "dst_port")
    if col is None:
        return None
    return getattr(col["type"], "length", None)


def _upgrade_dst_port() -> None:
    if is_offline():
        if offline_assume_exists():
            return
    else:
        if not has_table("firewall_rules"):
            return
        length = _dst_port_length()
        if length is None or length >= _DST_PORT_NEW:
            return
    with op.batch_alter_table("firewall_rules") as batch_op:
        batch_op.alter_column(
            "dst_port",
            existing_type=sa.String(length=_DST_PORT_OLD),
            type_=sa.String(length=_DST_PORT_NEW),
            existing_nullable=True,
        )


def upgrade() -> None:
    _upgrade_findings()
    _upgrade_attestations()
    _upgrade_dst_port()


def downgrade() -> None:
    """Restore the pre-c3d4e5f6a7b8 schema.

    NB: re-adding the global UNIQUE on findings.source_ref fails if closed and
    open findings now share a source_ref, and narrowing dst_port fails on
    PostgreSQL if any value exceeds 32 characters - resolve such rows first.
    """
    if has_table("firewall_rules") and (is_offline() or (_dst_port_length() or 0) > _DST_PORT_OLD):
        with op.batch_alter_table("firewall_rules") as batch_op:
            batch_op.alter_column(
                "dst_port",
                existing_type=sa.String(length=_DST_PORT_NEW),
                type_=sa.String(length=_DST_PORT_OLD),
                existing_nullable=True,
            )

    if has_index("attestations", "ix_attestation_one_current_nobaseline"):
        op.drop_index("ix_attestation_one_current_nobaseline", table_name="attestations",
                      **_NOBASELINE_WHERE)

    if has_table("findings"):
        if has_index("findings", "ux_findings_source_ref_open"):
            op.drop_index("ux_findings_source_ref_open", table_name="findings", **_OPEN_WHERE)
        drop_ix = has_index("findings", "ix_findings_source_ref")
        add_uq = is_offline() or not unique_constraints_on("findings", ["source_ref"])
        if drop_ix or add_uq:
            with op.batch_alter_table("findings") as batch_op:
                if drop_ix:
                    batch_op.drop_index("ix_findings_source_ref")
                if add_uq:
                    batch_op.create_unique_constraint("uq_findings_source_ref", ["source_ref"])
