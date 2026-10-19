"""
F-01: app/main.py (scheduler helpers, single-instance lock, lifespan,
request-size middleware) and app/db.py (get_db, init_db Alembic
bookkeeping). Every database here is a tmp_path file built in-process;
app.db.engine is monkeypatched, never the operator's database.
"""
import logging
import os

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

import app.db as db_mod
import app.main as main_mod
from app.db import Base
from app.models import Finding


# ------------------------------------------------------------- scheduler --

@pytest.mark.parametrize("val,expected", [(None, True), ("true", True), ("1", True),
                                          ("false", False), ("0", False), (" OFF ", False),
                                          ("no", False)])
def test_scheduler_enabled(monkeypatch, val, expected):
    if val is None:
        monkeypatch.delenv("IACS_REVIEW_ENABLED", raising=False)
    else:
        monkeypatch.setenv("IACS_REVIEW_ENABLED", val)
    assert main_mod._scheduler_enabled() is expected


def test_review_cron(monkeypatch):
    monkeypatch.delenv("IACS_REVIEW_SCHEDULE", raising=False)
    assert main_mod._review_cron() == "0 2 * * 0"
    monkeypatch.setenv("IACS_REVIEW_SCHEDULE", " 0 */6 * * * ")
    assert main_mod._review_cron() == "0 */6 * * *"


@pytest.fixture
def file_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'infra.db'}")
    db_mod.configure_sqlite_engine(engine)
    monkeypatch.setattr(db_mod, "engine", engine)
    monkeypatch.setattr(db_mod, "SessionLocal", sessionmaker(bind=engine, autoflush=False))
    # background jobs write through WriteSessionLocal (B-09 follow-up)
    monkeypatch.setattr(db_mod, "WriteSessionLocal",
                        sessionmaker(bind=db_mod.write_engine(engine), autoflush=False))
    yield engine
    engine.dispose()


def test_run_scheduled_reviews_commits_and_survives_errors(file_db, monkeypatch, caplog):
    Base.metadata.create_all(file_db)
    with db_mod.SessionLocal() as s:            # FI-01: the scheduler never creates a site
        from app.models import Site
        s.add(Site(name="Plant", code="plant"))
        s.commit()
    main_mod._run_scheduled_reviews()
    with db_mod.SessionLocal() as s:  # zone documentation findings were committed
        assert s.query(Finding).filter(Finding.check_name.like("zone_doc_%")).count() == 6

    import app.parsers.alert_engine as ae

    def boom(db):
        raise RuntimeError("review run failed")
    monkeypatch.setattr(ae, "run_periodic_reviews", boom)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        main_mod._run_scheduled_reviews()  # must not raise
    assert "Scheduled periodic reviews failed" in caplog.text


def test_scheduler_lock_path(monkeypatch, tmp_path):
    monkeypatch.setenv("IACS_SCHEDULER_LOCK", str(tmp_path / "x.lock"))
    assert main_mod._scheduler_lock_path() == tmp_path / "x.lock"
    monkeypatch.setenv("IACS_SCHEDULER_LOCK", "")
    monkeypatch.setattr(db_mod, "DATABASE_URL", f"sqlite:///{tmp_path / 'sub' / 'a.db'}")
    assert main_mod._scheduler_lock_path() == (tmp_path / "sub").resolve() / "iasc_scheduler.lock"
    import tempfile
    from pathlib import Path
    for url in ("postgresql://u:p@db/iasc", "sqlite:///:memory:"):
        monkeypatch.setattr(db_mod, "DATABASE_URL", url)
        assert main_mod._scheduler_lock_path() == Path(tempfile.gettempdir()) / "iasc_scheduler.lock"


def test_scheduler_lock_is_exclusive(tmp_path):
    lock = tmp_path / "locks" / "sched.lock"
    first = main_mod._acquire_scheduler_lock(lock)
    assert first is not None
    assert lock.read_text().strip() == str(os.getpid())
    assert main_mod._acquire_scheduler_lock(lock) is None  # held
    main_mod._release_scheduler_lock(first)
    main_mod._release_scheduler_lock(None)                  # no-op
    again = main_mod._acquire_scheduler_lock(lock)
    assert again is not None
    main_mod._release_scheduler_lock(again)
    # unopenable path (a directory) -> None, not an exception
    assert main_mod._acquire_scheduler_lock(tmp_path) is None


def _lifespan_env(monkeypatch, tmp_path, cron="0 3 * * *"):
    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "true")
    monkeypatch.setenv("IACS_SCHEDULER_LOCK", str(tmp_path / "life.lock"))
    monkeypatch.setenv("IACS_REVIEW_SCHEDULE", cron)


def test_lifespan_starts_and_stops_scheduler(monkeypatch, tmp_path, caplog):
    _lifespan_env(monkeypatch, tmp_path)
    with caplog.at_level(logging.INFO, logger="app.main"):
        with TestClient(main_mod.app) as c:
            assert c.get("/health").json() == {"status": "ok"}
            # this process holds the scheduler lock while the app runs
            assert main_mod._acquire_scheduler_lock(tmp_path / "life.lock") is None
    assert "Periodic review scheduler started" in caplog.text
    assert "Periodic review scheduler stopped" in caplog.text
    fh = main_mod._acquire_scheduler_lock(tmp_path / "life.lock")  # released on shutdown
    assert fh is not None
    main_mod._release_scheduler_lock(fh)


def test_lifespan_skips_scheduler_when_lock_held_or_cron_invalid(monkeypatch, tmp_path, caplog):
    _lifespan_env(monkeypatch, tmp_path)
    held = main_mod._acquire_scheduler_lock(tmp_path / "life.lock")
    try:
        with caplog.at_level(logging.INFO, logger="app.main"):
            with TestClient(main_mod.app) as c:
                assert c.get("/health").status_code == 200
        assert "scheduler NOT started" in caplog.text
    finally:
        main_mod._release_scheduler_lock(held)
    caplog.clear()
    _lifespan_env(monkeypatch, tmp_path, cron="not a cron")
    with caplog.at_level(logging.INFO, logger="app.main"):
        with TestClient(main_mod.app) as c:
            assert c.get("/health").status_code == 200
    assert "Failed to start periodic review scheduler" in caplog.text
    caplog.clear()
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    with caplog.at_level(logging.INFO, logger="app.main"):
        with TestClient(main_mod.app):
            pass
    assert "scheduler disabled" in caplog.text


# ---------------------------------------------------- request size guard --

@pytest.fixture
def tiny_app():
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        return {"n": len(await request.body())}

    @app.get("/echo")
    def get_echo():
        return {"ok": True}

    app.add_middleware(main_mod._BodySizeLimitMiddleware, max_bytes=10)
    return TestClient(app)


def test_body_limit_declared_length(tiny_app):
    assert tiny_app.post("/echo", content=b"x" * 10).json() == {"n": 10}
    r = tiny_app.post("/echo", content=b"x" * 11)
    assert r.status_code == 413 and r.json()["detail"] == main_mod._too_large_detail(10)
    assert tiny_app.get("/echo").status_code == 200


def test_body_limit_streamed_body(tiny_app):
    def chunks():
        for _ in range(5):
            yield b"abcd"
    r = tiny_app.post("/echo", content=chunks())  # chunked: no Content-Length
    assert r.status_code == 413


def test_body_limit_on_real_app(monkeypatch, tmp_path):
    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    with TestClient(main_mod.app) as c:
        r = c.post("/ingest/arp", headers={"content-length": str(main_mod._MAX_REQUEST_BYTES + 1),
                                           "content-type": "application/octet-stream"},
                   content=b"")
    assert r.status_code == 413


# -------------------------------------------------------------------- db --

def test_get_db_rolls_back_and_closes(monkeypatch):
    calls = []

    class FakeSession:
        def rollback(self):
            calls.append("rollback")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(db_mod, "SessionLocal", FakeSession)
    gen = db_mod.get_db()
    assert isinstance(next(gen), FakeSession)
    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("handler failed"))
    assert calls == ["rollback", "close"]
    calls.clear()
    gen = db_mod.get_db()
    next(gen)
    gen.close()
    assert calls == ["close"]


def test_env_flag_and_memory_url(monkeypatch):
    from sqlalchemy.engine import make_url
    monkeypatch.delenv("IACS_COV_FLAG", raising=False)
    assert db_mod._env_flag("IACS_COV_FLAG") is True
    assert db_mod._env_flag("IACS_COV_FLAG", default=False) is False
    monkeypatch.setenv("IACS_COV_FLAG", "off")
    assert db_mod._env_flag("IACS_COV_FLAG") is False
    for url, mem in (("sqlite://", True), ("sqlite:///:memory:", True),
                     ("sqlite:///file::memory:?cache=shared", True),
                     ("sqlite:///x.db?mode=memory", True), ("sqlite:///x.db", False)):
        assert db_mod._is_sqlite_memory(make_url(url)) is mem, url


def test_init_db_stamps_new_database_and_checks_state(file_db, caplog):
    db_mod.init_db()
    insp = inspect(file_db)
    assert "hosts" in insp.get_table_names() and "alembic_version" in insp.get_table_names()
    head = db_mod._head_revision(db_mod._alembic_config())
    with file_db.connect() as conn:
        assert [r[0] for r in conn.execute(text("SELECT version_num FROM alembic_version"))] == [head]

    # at head: no warning
    with caplog.at_level(logging.WARNING, logger="app.db"):
        db_mod.init_db()
    assert "alembic" not in caplog.text.lower()

    # behind head
    with file_db.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '0001baseline0'"))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.db"):
        db_mod.init_db()
    assert "0001baseline0" in caplog.text and "alembic upgrade head" in caplog.text

    # empty alembic_version
    with file_db.begin() as conn:
        conn.execute(text("DELETE FROM alembic_version"))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.db"):
        db_mod.init_db()
    assert "is empty" in caplog.text

    # tables but no alembic_version
    with file_db.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.db"):
        db_mod.init_db()
    assert "no alembic_version table" in caplog.text


def test_stamp_and_check_tolerate_alembic_failures(file_db, monkeypatch, caplog):
    def broken(*a, **k):
        raise RuntimeError("alembic config broken")
    monkeypatch.setattr(db_mod, "_alembic_config", broken)
    with caplog.at_level(logging.WARNING, logger="app.db"):
        db_mod.init_db()                   # new DB: stamp fails, logged, no raise
        assert "Failed to stamp" in caplog.text
        caplog.clear()
        db_mod.init_db()                   # existing DB: check skipped, logged
    assert "migration state not checked" in caplog.text
    assert "hosts" in inspect(file_db).get_table_names()
