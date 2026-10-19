"""
Alembic environment for IACS_Monitor.

Database URL resolution (first match wins):
  1. ``config.attributes["connection"]`` - an existing SQLAlchemy Connection
     passed in programmatically (used by ``app.db.init_db`` to stamp, and by
     tests).
  2. ``config.attributes["sqlalchemy.url"]`` - a URL passed programmatically.
  3. ``-x url=...`` on the alembic command line.
  4. The ``IACS_DATABASE_URL`` environment variable, read at migration time.
  5. ``app.db.DATABASE_URL`` (same env var, read at import; default
     ``sqlite:///./iasc_monitor.db`` relative to the CWD).

Offline mode (``alembic upgrade head --sql``) is supported; the revisions
use ``iasc_migration_utils`` which knows how to behave without a live
connection to inspect.
"""
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging - but not when called
# programmatically with an existing connection (init_db / tests), where it
# would clobber the application's logging configuration.
if config.config_file_name is not None and "connection" not in config.attributes \
        and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Make the shared migration helpers importable from the revision scripts,
# and make sure the project root is importable regardless of the CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _PROJECT_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Wire up IACS_Monitor models and DATABASE_URL
from app.db import Base, DATABASE_URL  # noqa: E402
import app.models  # noqa: F401, E402 — registers all models on Base.metadata

target_metadata = Base.metadata


def _resolve_url() -> str:
    url = config.attributes.get("sqlalchemy.url")
    if url:
        return str(url)
    x_url = context.get_x_argument(as_dictionary=True).get("url")
    if x_url:
        return x_url
    return os.environ.get("IACS_DATABASE_URL") or DATABASE_URL


def _configure_kwargs(url_or_conn_dialect: str) -> dict:
    return dict(
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most things in place; batch mode makes
        # autogenerate emit copy-and-move table rebuilds instead.
        render_as_batch=url_or_conn_dialect == "sqlite",
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    url = _resolve_url()
    dialect = url.split(":", 1)[0].split("+", 1)[0]
    context.configure(
        url=url,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **_configure_kwargs(dialect),
    )

    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection) -> None:
    context.configure(connection=connection, **_configure_kwargs(connection.dialect.name))
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connection = config.attributes.get("connection")
    if connection is not None:
        _run_with_connection(connection)
        return

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _resolve_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        _run_with_connection(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
