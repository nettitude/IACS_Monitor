"""
API additions made for the Tier 2 UI work:
  * GET /findings: offset + bounded limit + X-Total-Count header
  * GET /findings/summary: by_status
  * GET /firewall-rules: firewall_device_id / firewall_id filters and fields
  * GET /ui, /ui/, / : unified console served same-origin
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Finding

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'ui.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with Session() as s:
        for i in range(30):
            s.add(Finding(category="periodic_review", check_name="unused_policy",
                          severity="low", title=f"f{i}",
                          status=("open", "acknowledged", "closed")[i % 3]))
        s.commit()
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def test_findings_paging_is_stable_and_counted(client):
    everything = client.get("/findings", params={"limit": 1000})
    assert everything.headers["X-Total-Count"] == "30"
    ids = [f["id"] for f in everything.json()]
    page = client.get("/findings", params={"limit": 7, "offset": 10})
    assert page.headers["X-Total-Count"] == "30"
    assert [f["id"] for f in page.json()] == ids[10:17]
    opened = client.get("/findings", params={"status": "open", "limit": 3})
    assert opened.headers["X-Total-Count"] == "10" and len(opened.json()) == 3


@pytest.mark.parametrize("params", [{"limit": -1}, {"limit": 0}, {"limit": 5001}, {"offset": -1}])
def test_findings_rejects_unbounded_or_negative(client, params):
    assert client.get("/findings", params=params).status_code == 422


def test_summary_has_status_counts(client):
    s = client.get("/findings/summary").json()
    assert s["total_open"] == 10
    assert s["by_status"] == {"open": 10, "acknowledged": 10, "closed": 10}


def test_firewall_rules_filter_by_device_id(client):
    for name, fname in (("CISCO-EDGE", "sample_firewall_cisco.txt"),
                        ("PFSENSE-LAB", "sample_firewall_pfsense.xml")):
        r = client.post("/ingest/firewall", params={"firewall_device_name": name},
                        files={"file": (fname, (SAMPLES / fname).read_bytes())})
        assert r.status_code == 200, r.text
    devs = {d["name"]: d for d in client.get("/firewall-devices").json()}
    total = 0
    for name, d in devs.items():
        rows = client.get("/firewall-rules", params={"firewall_device_id": d["id"]}).json()
        assert len(rows) == d["rule_count"] + d["disabled_rule_count"] > 0
        assert all(r["firewall_device_id"] == d["id"] for r in rows)
        assert all("rule_order" in r and "firewall_id" in r for r in rows)
        total += len(rows)
    assert total == len(client.get("/firewall-rules").json())


def test_console_served_same_origin(client):
    for path in ("/ui", "/ui/"):
        r = client.get(path)
        assert r.status_code == 200 and "<html" in r.text.lower()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/ui"
