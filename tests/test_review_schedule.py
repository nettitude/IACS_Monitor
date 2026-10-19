"""RS-01: runtime switch for the scheduled periodic reviews
(GET / PUT /reviews/schedule, app_settings, the scheduler job)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main as main_mod
from app import settings_store as ss
from app.db import Base
from app.models import Site
from tests.test_cov_routes import _api, _ok


@pytest.fixture
def c(tmp_path):
    with _api(tmp_path / "rs.db") as client:
        yield client


def test_default_on_and_toggle_persists(c, monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "true")
    j = _ok(c.get("/reviews/schedule"))
    assert (j["enabled"], j["effective"], j["env_enabled"], j["timezone"]) == (True, "on", True, "UTC")
    assert j["next_run"] and j["cron"] == main_mod._review_cron() and j["last_run"] is None
    j = _ok(c.put("/reviews/schedule", json={"enabled": False, "changed_by": "alice"}))
    assert (j["enabled"], j["effective"], j["next_run"], j["updated_by"]) == (False, "paused", None, "alice")
    assert _ok(c.get("/reviews/schedule"))["effective"] == "paused"          # stored, not per request
    j = _ok(c.put("/reviews/schedule", json={"enabled": True}))
    assert j["effective"] == "on" and j["updated_by"] is None


def test_environment_off_wins(c, monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    j = _ok(c.put("/reviews/schedule", json={"enabled": True}))
    assert (j["enabled"], j["effective"], j["env_enabled"]) == (True, "disabled", False)
    assert "IACS_REVIEW_ENABLED" in j["note"]


def test_manual_run_unaffected_when_paused(c):
    _ok(c.put("/reviews/schedule", json={"enabled": False}))
    c.post("/sites", json={"name": "A", "code": "a"})
    r = _ok(c.post("/reviews/run", params={"site": "a"}))
    assert "by_review" in r and r["failed_reviews"] == []


def _scheduled_db(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    import app.db as dbmod
    monkeypatch.setattr(dbmod, "WriteSessionLocal", S)
    calls = []
    import app.parsers.alert_engine as ae
    monkeypatch.setattr(ae, "run_periodic_reviews", lambda db, site_id=None: calls.append(site_id) or {"x": 1})
    return S, calls


def test_scheduler_job_skips_when_paused_and_records(monkeypatch):
    S, calls = _scheduled_db(monkeypatch)
    with S() as db:
        db.add(Site(name="A", code="a"))
        ss.set_setting(db, ss.PERIODIC_REVIEWS, {"enabled": False}, by="op")
        db.commit()
    main_mod._run_scheduled_reviews()
    assert calls == []
    with S() as db:
        last = ss.get_setting(db, ss.PERIODIC_REVIEWS_LAST)
        assert last["status"] == "skipped" and "paused" in last["detail"]
        ss.set_setting(db, ss.PERIODIC_REVIEWS, {"enabled": True})
        db.commit()
    main_mod._run_scheduled_reviews()
    assert len(calls) == 1
    with S() as db:
        last = ss.get_setting(db, ss.PERIODIC_REVIEWS_LAST)
        assert (last["status"], last["sites"]) == ("completed", 1)


def test_scheduler_job_no_site_creates_none(monkeypatch):
    """FI-01: a fresh install (no site) is skipped - the job never creates a site."""
    S, calls = _scheduled_db(monkeypatch)
    main_mod._run_scheduled_reviews()
    with S() as db:
        assert db.query(Site).count() == 0 and calls == []
        assert ss.get_setting(db, ss.PERIODIC_REVIEWS_LAST)["detail"] == "no site exists yet"
