"""
POST /attestation current-row bookkeeping (T1-34 / T1-35).

Uses a temp-file SQLite DB created from Base.metadata (so both partial
unique indexes on attestations are real), with get_db overridden and the
lifespan's init_db() / scheduler disabled so the project DB is never touched.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Attestation, Baseline


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'att.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    with Session() as s:
        # One active baseline per site (multi-site phase 2): B1 is inactive.
        s.add_all([Baseline(name="B1", is_active=False), Baseline(name="B2")])
        s.commit()
    yield Session
    engine.dispose()


@pytest.fixture
def client(session_factory, monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        db = session_factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)


def _post(client, checklist_id="1.1", baseline=None, who="alice"):
    data = {"checklist_id": checklist_id, "attested_by": who, "attested_at": "2026-09-01"}
    if baseline:
        data["baseline_name"] = baseline
    return client.post("/attestation", data=data)


def _current(session_factory, checklist_id="1.1"):
    with session_factory() as s:
        return {
            (a.baseline_id, a.attested_by)
            for a in s.query(Attestation).filter(
                Attestation.checklist_id == checklist_id, Attestation.is_current == True  # noqa: E712
            )
        }


def _baseline_id(session_factory, name):
    with session_factory() as s:
        return s.query(Baseline).filter_by(name=name).one().id


def test_second_attestation_same_baseline_demotes_first(client, session_factory):
    r1 = _post(client, baseline="B1", who="alice")
    assert r1.status_code == 201, r1.text
    r2 = _post(client, baseline="B1", who="bob")
    assert r2.status_code == 201, r2.text  # previously always 409 (T1-34)

    body = r2.json()
    assert body["is_current"] is True and body["attested_by"] == "bob"
    assert set(body) >= {"id", "checklist_id", "baseline_id", "has_proof", "created_at"}

    b1 = _baseline_id(session_factory, "B1")
    assert _current(session_factory) == {(b1, "bob")}
    with session_factory() as s:
        first = s.get(Attestation, r1.json()["id"])
        assert first.is_current is False  # history preserved, just demoted


def test_no_baseline_attestation_does_not_demote_baselined_one(client, session_factory):
    assert _post(client, baseline="B1", who="alice").status_code == 201
    assert _post(client, baseline="B2", who="carol").status_code == 201
    r = _post(client, baseline=None, who="bob")
    assert r.status_code == 201, r.text

    b1 = _baseline_id(session_factory, "B1")
    b2 = _baseline_id(session_factory, "B2")
    assert _current(session_factory) == {(b1, "alice"), (b2, "carol"), (None, "bob")}


def test_baselined_attestation_does_not_demote_no_baseline_one(client, session_factory):
    assert _post(client, baseline=None, who="bob").status_code == 201
    assert _post(client, baseline="B1", who="alice").status_code == 201
    b1 = _baseline_id(session_factory, "B1")
    assert _current(session_factory) == {(None, "bob"), (b1, "alice")}


def test_two_null_baseline_attestations_leave_one_current(client, session_factory):
    assert _post(client, who="alice").status_code == 201
    r = _post(client, who="bob")
    assert r.status_code == 201, r.text
    assert _current(session_factory) == {(None, "bob")}
    # other checklist rows are unaffected
    assert _post(client, checklist_id="1.2", who="dave").status_code == 201
    assert _current(session_factory) == {(None, "bob")}
    assert _current(session_factory, "1.2") == {(None, "dave")}


def test_nobaseline_partial_index_enforced(session_factory):
    """ix_attestation_one_current_nobaseline rejects a second current
    NULL-baseline row for the same checklist (the race the 409 guards)."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    with session_factory() as s:
        s.add(Attestation(checklist_id="1.3", attested_by="a", attested_at=now, is_current=True))
        s.commit()
        s.add(Attestation(checklist_id="1.3", attested_by="b", attested_at=now, is_current=True))
        with pytest.raises(IntegrityError):
            s.commit()
