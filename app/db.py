"""
Database engine and session management for IACS_Monitor.

SQLite is used for the scaffold since it requires no external service and
is trivial to inspect during development. Swap DATABASE_URL for a
Postgres DSN when moving toward production (the SQLAlchemy models are
already Postgres-compatible; only the JSON column type may need a
dialect-specific import in models.py if you want native JSONB).
"""
import logging
import os
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from starlette.requests import Request

log = logging.getLogger(__name__)

# Project root (the directory holding alembic.ini), resolved from this file
# rather than the CWD so init_db() stamps correctly however it is launched.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


DATABASE_URL = os.environ.get(
    "IACS_DATABASE_URL", "sqlite:///./iasc_monitor.db"
)



def _env_flag(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() not in ("0", "false", "no", "off")


def _is_sqlite_memory(url) -> bool:
    db = url.database
    return (
        not db
        or db == ":memory:"
        or db.startswith("file::memory:")
        or url.query.get("mode") == "memory"
    )


#: Execution option selecting the SQLite BEGIN flavour ("IMMEDIATE" or
#: default deferred) - B-09.
SQLITE_BEGIN_OPTION = "iasc_sqlite_begin"


def sqlite_busy_timeout_ms() -> int:
    """busy_timeout in ms (IACS_SQLITE_BUSY_TIMEOUT_MS, default 30000)."""
    try:
        return max(0, int(os.environ.get("IACS_SQLITE_BUSY_TIMEOUT_MS", "30000")))
    except ValueError:
        return 30000


# C-12: connection-pool sizing.  A burst of writers that each hold a pool
# connection while queued on BEGIN IMMEDIATE (busy_timeout, up to 30 s) must
# not consume the whole pool and starve readers into a pool-checkout
# TimeoutError (which the route layer turns into a 503, never a 500).  So the
# pool is large enough to leave readers headroom, and pool_timeout (how long a
# checkout waits for a free connection) is kept SHORTER than busy_timeout so a
# reader that does hit an exhausted pool fails fast with 503 instead of
# blocking for the full busy window.  All three are plain create_engine()
# kwargs, so they apply identically on SQLite and PostgreSQL (no SQLite
# PRAGMAs are involved).
def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def db_pool_size() -> int:
    """QueuePool persistent connections (IACS_DB_POOL_SIZE, default 15)."""
    return _env_int("IACS_DB_POOL_SIZE", 15)


def db_max_overflow() -> int:
    """QueuePool burst connections above pool_size (IACS_DB_MAX_OVERFLOW,
    default 25).  pool_size + max_overflow (default 40) is the hard ceiling on
    concurrent checkouts; it must exceed the expected concurrent-writer count
    so queued writers cannot occupy every slot."""
    return _env_int("IACS_DB_MAX_OVERFLOW", 25)


def db_pool_timeout_s() -> int:
    """Seconds a checkout waits for a free pool connection before raising
    sqlalchemy.exc.TimeoutError (IACS_DB_POOL_TIMEOUT, default 10).  Kept
    shorter than busy_timeout (default 30 s) on purpose - see above."""
    return _env_int("IACS_DB_POOL_TIMEOUT", 10)


def write_engine(eng: Engine) -> Engine:
    """``eng`` whose SQLite transactions start with BEGIN IMMEDIATE (B-09).
    Shares the pool and event hooks; a no-op difference on other dialects."""
    return eng.execution_options(**{SQLITE_BEGIN_OPTION: "IMMEDIATE"})


def configure_sqlite_engine(eng: Engine) -> Engine:
    """Apply IACS_Monitor's SQLite connection setup to ``eng`` (T3-08).

    Public so tests / scripts that build their own engines get identical
    behaviour.  Idempotent; a no-op for non-SQLite engines.

    * pysqlite transaction fix (SQLAlchemy's documented recipe): the driver's
      own implicit BEGIN handling is disabled (``isolation_level = None``)
      and SQLAlchemy emits ``BEGIN`` itself on every transaction start.
      Without it SAVEPOINT / ``Session.begin_nested()`` misbehave - e.g. a
      savepoint RELEASE could commit a row early, and a failed savepoint
      could not be rolled back in isolation.
    * ``foreign_keys=ON`` - SQLite ignores every declared FK (including
      ON DELETE SET NULL) unless this is set on each connection.  Escape
      hatch: IACS_SQLITE_FOREIGN_KEYS=false.
    * ``journal_mode=WAL`` - readers no longer block the writer (a long
      PCAP ingest used to stall every GET).  Skipped for in-memory DBs.
    * ``busy_timeout`` - wait up to IACS_SQLITE_BUSY_TIMEOUT_MS (default
      30000 ms) for a competing writer instead of failing immediately with
      "database is locked".
    * B-09: transactions start with plain (deferred) ``BEGIN`` unless the
      connection carries the execution option ``iasc_sqlite_begin=
      "IMMEDIATE"`` (see ``write_engine`` / ``get_write_db``).  A deferred
      transaction that reads first and writes later cannot upgrade to the
      write lock once another writer committed in between (SQLITE_BUSY_
      SNAPSHOT - busy_timeout does NOT retry that), so every write-capable
      session takes the write lock up front with ``BEGIN IMMEDIATE`` and
      concurrent writers queue on busy_timeout instead of failing.
    """
    if eng.dialect.name != "sqlite" or getattr(eng, "_iasc_sqlite_configured", False):
        return eng
    use_wal = not _is_sqlite_memory(eng.url)
    fk_on = _env_flag("IACS_SQLITE_FOREIGN_KEYS", True)
    busy_ms = sqlite_busy_timeout_ms()

    @event.listens_for(eng, "connect")
    def _sqlite_on_connect(dbapi_conn, _record):
        # Disable pysqlite's implicit transaction management; "begin" below
        # takes over.  (PRAGMAs run here, outside any transaction - WAL and
        # foreign_keys cannot be changed inside one.)
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        try:
            cur.execute(f"PRAGMA foreign_keys={'ON' if fk_on else 'OFF'}")
            cur.execute(f"PRAGMA busy_timeout={busy_ms}")
            if use_wal:
                cur.execute("PRAGMA journal_mode=WAL")
        finally:
            cur.close()

    @event.listens_for(eng, "begin")
    def _sqlite_on_begin(conn):
        mode = str(conn.get_execution_options().get(SQLITE_BEGIN_OPTION) or "").upper()
        conn.exec_driver_sql("BEGIN IMMEDIATE" if mode == "IMMEDIATE" else "BEGIN")

    eng._iasc_sqlite_configured = True
    return eng


def make_engine(url: str, **kwargs) -> Engine:
    """Create an engine with IACS_Monitor's connection settings.

    For SQLite: ``check_same_thread=False`` (sessions are used from
    FastAPI's threadpool, and ingest work is handed to worker threads via
    run_in_threadpool - T3-01) plus the PRAGMAs of configure_sqlite_engine.
    """
    connect_args = dict(kwargs.pop("connect_args", {}) or {})
    parsed_url = make_url(url)
    is_sqlite = parsed_url.get_backend_name() == "sqlite"
    if is_sqlite:
        connect_args.setdefault("check_same_thread", False)
    # C-12: give the QueuePool headroom and a short checkout timeout so a
    # burst of queued writers cannot starve readers (see db_pool_* above).
    # In-memory SQLite uses a single-connection pool that rejects these
    # kwargs, so skip it there; a caller may still override any of them.
    if not (is_sqlite and _is_sqlite_memory(parsed_url)):
        kwargs.setdefault("pool_size", db_pool_size())
        kwargs.setdefault("max_overflow", db_max_overflow())
        kwargs.setdefault("pool_timeout", db_pool_timeout_s())
    eng = create_engine(url, connect_args=connect_args, **kwargs)
    return configure_sqlite_engine(eng)


# Kept for backward compatibility (imported by scripts/tests).
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = make_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# B-09: sessions that write (POST/PUT/PATCH/DELETE handlers, ingest,
# background jobs) take the SQLite write lock when their transaction begins.
WriteSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=write_engine(engine))

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class Base(DeclarativeBase):
    pass


def _yield_session(factory):
    db = factory()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_write_db():
    """FastAPI dependency: a write-capable session (SQLite: BEGIN IMMEDIATE)."""
    yield from _yield_session(WriteSessionLocal)


def get_db(request: Request = None):
    """FastAPI dependency that yields a DB session and guarantees closure.

    Rolls back on any unhandled exception so aborted transactions are never
    silently committed (critical for PostgreSQL connection-pool correctness).

    B-09: for a request whose method can write (anything but GET / HEAD /
    OPTIONS) the session is write-capable - on SQLite its transactions
    start with ``BEGIN IMMEDIATE`` so a long ingest can never lose its
    write-lock upgrade to a short writer that committed meanwhile.  Read
    requests (and direct calls without a request) keep deferred BEGIN, so
    GETs never queue behind an ingest under WAL.
    """
    method = getattr(request, "method", None)
    write = method is not None and method.upper() not in _READ_METHODS
    db = (WriteSessionLocal if write else SessionLocal)()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """
    Create all tables on first run. Called once at application startup.

    IMPORTANT — schema migrations (I-2):
    ``create_all`` is idempotent for *new* databases: it creates any tables
    that do not yet exist and leaves existing ones untouched.  It does NOT
    add columns, drop columns, or alter indexes on a database that already
    has those tables.  Any schema change in ``models.py`` (new column, new
    index, renamed column, changed type) requires an explicit migration step
    before it takes effect on an existing installation.

    Schema changes are shipped as Alembic revisions (``alembic/versions``);
    apply them with ``alembic upgrade head`` before starting the service
    (the Docker entrypoint does this automatically).

    Alembic bookkeeping done here (T1-03):
      * database had NO tables  -> create_all builds the head schema and the
        database is stamped at the Alembic head, so a later
        ``alembic upgrade head`` is a no-op instead of failing with
        "table ... already exists";
      * tables but no alembic_version -> WARNING (schema revision unknown;
        the operator must ``alembic stamp <rev>`` then upgrade);
      * alembic_version behind head   -> WARNING naming current vs head.
    If Alembic is not importable this logs and continues.

    For development resets (SQLite only) you can simply delete
    ``iasc_monitor.db`` and let create_all rebuild from scratch; never do
    this against a production database that has real findings in it.
    """
    # Import models here so they are registered on Base.metadata before
    # create_all is called.
    from app import models  # noqa: F401

    with engine.connect() as conn:
        had_tables = bool(inspect(conn).get_table_names())

    Base.metadata.create_all(bind=engine)

    # FI-01 (fresh install): a new database starts with NO site - the
    # operator creates the first one (or loads the sample data).  The Default
    # site exists only on databases upgraded from before sites (migration
    # c0d1e2f3a4b5 backfills their rows into it) or when a request names
    # site=default explicitly.

    if not had_tables:
        # Brand-new database: create_all just built the head schema, so record
        # that in alembic_version.  Without this a later `alembic upgrade head`
        # tries to re-create every table and fails (T1-03).
        _stamp_head()
    else:
        _check_migration_state()


def _alembic_config():
    """Alembic Config for this project, independent of the process CWD."""
    from alembic.config import Config

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    return cfg


def _head_revision(cfg) -> Optional[str]:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(cfg).get_current_head()


def _stamp_head() -> None:
    """Stamp a freshly created database at the Alembic head revision."""
    try:
        from alembic import command
    except ImportError as exc:
        log.warning(
            "Alembic is not importable (%s); new database was NOT stamped. "
            "Run 'alembic stamp head' before the first 'alembic upgrade'.", exc
        )
        return
    try:
        cfg = _alembic_config()
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            command.stamp(cfg, "head")
        log.info("New database created and stamped at Alembic revision %s", _head_revision(cfg))
    except Exception:
        log.exception(
            "Failed to stamp the new database at Alembic head; run "
            "'alembic stamp head' manually before the next 'alembic upgrade head'."
        )


def _check_migration_state() -> None:
    """Warn loudly when an existing database is not at the Alembic head."""
    try:
        from alembic.runtime.migration import MigrationContext
        cfg = _alembic_config()
        head = _head_revision(cfg)
    except Exception as exc:
        log.warning("Alembic unavailable - schema migration state not checked (%s)", exc)
        return

    try:
        with engine.connect() as conn:
            if not inspect(conn).has_table("alembic_version"):
                log.warning(
                    "Database has tables but no alembic_version table: its schema "
                    "revision is unknown and pending migrations will NOT be applied "
                    "automatically. Run 'alembic stamp 0001baseline0' then "
                    "'alembic upgrade head' - later revisions are idempotent and "
                    "d4e5f6a7b8c9 adds any missing columns/indexes (head: %s).", head,
                )
                return
            current = MigrationContext.configure(conn).get_current_heads()
    except Exception as exc:
        log.warning("Could not read alembic_version: %s", exc)
        return

    if not current:
        log.warning(
            "alembic_version table exists but is empty - run 'alembic stamp "
            "<revision>' then 'alembic upgrade head' (head is %s) before "
            "starting the service.", head,
        )
    elif tuple(current) != (head,):
        log.warning(
            "Database schema is at Alembic revision %s but the code expects "
            "head %s - run 'alembic upgrade head' before starting the service.",
            ", ".join(current), head,
        )
