"""Regression tests for audit findings A-26 (proof MIME / security headers)
and A-28 (LIKE wildcard escaping in host site/search filters)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Baseline, Host


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'a2.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    with Session() as s:
        s.add(Baseline(name="B1"))
        s.add_all([
            Host(ip="10.0.0.1", site="plant_a", hostname="plc_1"),
            Host(ip="10.0.0.2", site="plantXa", hostname="plcX1"),
            Host(ip="10.0.0.3", site="100%site", hostname="hmi"),
            Host(ip="10.0.0.4", site="100site", hostname="hmi2"),
        ])
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
        finally:
            db.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)


def _ips(resp):
    assert resp.status_code == 200, resp.text
    return sorted(h["ip"] for h in resp.json())


# --- A-28 -----------------------------------------------------------------

def test_site_filter_underscore_literal(client):
    assert _ips(client.get("/assets", params={"location": "plant_a"})) == ["10.0.0.1"]


def test_site_filter_percent_literal(client):
    assert _ips(client.get("/assets", params={"location": "100%"})) == ["10.0.0.3"]


def test_search_underscore_literal(client):
    assert _ips(client.get("/assets", params={"search": "plc_"})) == ["10.0.0.1"]


def test_export_site_filter_escaped(client):
    r = client.get("/assets/export", params={"location": "plant_a"})
    assert r.status_code == 200
    assert "10.0.0.1" in r.text and "10.0.0.2" not in r.text


# --- A-26 -----------------------------------------------------------------

def _upload(client, mime, name="p.bin", body=b"<script>alert(1)</script>"):
    r = client.post("/attestation",
                    data={"checklist_id": "1.1", "attested_by": "a", "attested_at": "2026-09-01"},
                    files={"proof": (name, body, mime)})
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


@pytest.mark.parametrize("mime,expected", [
    ("text/html", "application/octet-stream"),
    ("image/svg+xml", "application/octet-stream"),
    ("application/pdf", "application/pdf"),
    ("IMAGE/PNG", "image/png"),
    ("text/plain; charset=utf-8", "text/plain"),
])
def test_proof_mime_allowlist(client, mime, expected):
    aid = _upload(client, mime)
    r = client.get(f"/attestation/{aid}/proof")
    assert r.status_code == 200
    assert r.headers["content-type"].split(";")[0] == expected
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_proof_mime_sanitised_for_legacy_rows(client, session_factory):
    from app.models import Attestation
    aid = _upload(client, "application/pdf")
    with session_factory() as s:
        s.get(Attestation, aid).proof_mime = "text/html"
        s.commit()
    r = client.get(f"/attestation/{aid}/proof")
    assert r.headers["content-type"].startswith("application/octet-stream")


def test_nosniff_on_api_and_csp_on_ui(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" not in r.headers
    for path in ("/ui", "/ui/findings", "/ui/upload", "/ui/topology"):
        r = client.get(path)
        if r.status_code != 200:
            continue
        csp = r.headers["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert r.headers["x-content-type-options"] == "nosniff"
