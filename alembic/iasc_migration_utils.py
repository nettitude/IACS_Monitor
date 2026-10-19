"""
Schema-inspection helpers shared by the IACS_Monitor migrations.

Every revision after the baseline (0001baseline0) is idempotent: it checks
the live schema and only adds/changes what is missing, so the chain works
both for a database built from empty (baseline already created everything)
and for an existing database stamped at an older revision.

``alembic/env.py`` puts this directory on ``sys.path`` so revisions can
``import iasc_migration_utils``.  (It deliberately does not live in
``versions/`` - Alembic would try to load it as a revision.)

Offline (``--sql``) mode has no connection to inspect.  There we assume:
  * tables always exist (every render range starts at or after the baseline);
  * rendering from base / the baseline  -> every column/index/constraint
    already exists too (the baseline created it), so later revisions emit
    nothing;
  * rendering from any later revision   -> the objects a revision adds do
    not exist yet, so each revision emits its full DDL.
"""
from __future__ import annotations

from alembic import context, op
import sqlalchemy as sa

BASELINE_REVISION = "0001baseline0"


def is_offline() -> bool:
    return context.is_offline_mode()


def dialect_name() -> str:
    return op.get_context().dialect.name


def offline_assume_exists() -> bool:
    """In offline mode: True when the render starts at base or the baseline."""
    try:
        start = context.get_starting_revision_argument()
    except Exception:  # pragma: no cover - defensive
        start = None
    if isinstance(start, (tuple, list)):
        start = start[0] if start else None
    return start in (None, "base", BASELINE_REVISION)


def _insp():
    return sa.inspect(op.get_bind())


def has_table(table: str) -> bool:
    # Offline, every rendered range starts at or after the baseline, which
    # creates every table - so tables always "exist".
    if is_offline():
        return True
    return _insp().has_table(table)


def has_column(table: str, column: str) -> bool:
    if is_offline():
        return offline_assume_exists()
    insp = _insp()
    if not insp.has_table(table):
        return False
    return any(c["name"] == column for c in insp.get_columns(table))


def get_column(table: str, column: str):
    """Reflected column dict, or None (always None offline)."""
    if is_offline():
        return None
    insp = _insp()
    if not insp.has_table(table):
        return None
    for c in insp.get_columns(table):
        if c["name"] == column:
            return c
    return None


def has_index(table: str, name: str) -> bool:
    if is_offline():
        return offline_assume_exists()
    insp = _insp()
    if not insp.has_table(table):
        return False
    return any(ix["name"] == name for ix in insp.get_indexes(table))


def has_check_constraint(table: str, name: str) -> bool:
    if is_offline():
        return offline_assume_exists()
    insp = _insp()
    if not insp.has_table(table):
        return False
    try:
        return any(ck.get("name") == name for ck in insp.get_check_constraints(table))
    except NotImplementedError:  # pragma: no cover
        return False


def unique_constraints_on(table: str, columns: list[str]) -> list[dict]:
    """Reflected UNIQUE constraints whose column list is exactly ``columns``.

    Names may be None for unnamed constraints on SQLite.
    """
    if is_offline():
        return []
    insp = _insp()
    if not insp.has_table(table):
        return []
    return [
        uc for uc in insp.get_unique_constraints(table)
        if list(uc.get("column_names") or []) == list(columns)
    ]


def unique_nonpartial_indexes_on(
    table: str, columns: list[str], exclude: tuple[str, ...] = ()
) -> list[dict]:
    """Reflected non-partial UNIQUE indexes whose column list is exactly ``columns``.

    ``exclude`` lists known partial-index names to skip even if the running
    SQLAlchemy version does not reflect the WHERE clause.
    """
    if is_offline():
        return []
    insp = _insp()
    if not insp.has_table(table):
        return []
    out = []
    for ix in insp.get_indexes(table):
        if ix.get("name") in exclude:
            continue
        if not ix.get("unique") or list(ix.get("column_names") or []) != list(columns):
            continue
        opts = ix.get("dialect_options") or {}
        if opts.get("postgresql_where") is not None or opts.get("sqlite_where") is not None:
            continue
        # PostgreSQL reports the backing index of a UNIQUE constraint too;
        # the caller handles those via unique_constraints_on().
        if ix.get("duplicates_constraint"):
            continue
        out.append(ix)
    return out
