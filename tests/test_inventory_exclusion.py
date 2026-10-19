"""
Hosts excluded from the asset inventory (owner 2026-10-14: "Asset Inventory need
a [way] to not include the host in the asset Inventory but not [stop it] from being
seen on other pages"; the exclusion is treated as a decision - unknown_device
counts the host as reviewed).
"""
import contextlib
import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Host


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'ie.db'}", connect_args={"check_same_thread": False})
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
    with TestClient(main_mod.app) as c:
        sid = c.post("/sites", json={"name": "E", "code": "e"}).json()["id"]
        with Session() as s:
            s.add_all([Host(site_id=sid, ip="10.9.0.10", mac="aa:00:00:00:00:10", device_type="plc", purdue_level=1,
                            classification_source="manual", sources=["pcap"]),
                       Host(site_id=sid, ip="10.9.0.99", mac="aa:00:00:00:00:99", vendor="Apple, Inc.", sources=["pcap"])])
            s.commit()
            ids = {h.ip: h.id for h in s.query(Host)}
        try:
            yield c, sid, ids, Session
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _ips(rows):
    return sorted(r["ip"] for r in rows)


def test_exclude_hides_from_inventory_only(api):
    c, sid, ids, Session = api
    hid = ids["10.9.0.99"]
    r = c.patch(f"/assets/{hid}", params={"inventory_excluded": "true", "inventory_excluded_reason": "visitor laptop",
                                          "inventory_excluded_by": "pat"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["inventory_excluded"] is True and j["inventory_excluded_reason"] == "visitor laptop"
    assert j["inventory_excluded_by"] == "pat" and j["inventory_excluded_at"]
    q = {"site_id": sid}
    assert _ips(c.get("/assets", params=q).json()) == ["10.9.0.10"]                               # hidden by default
    assert _ips(c.get("/assets", params={**q, "include_excluded": "true"}).json()) == ["10.9.0.10", "10.9.0.99"]
    assert _ips(c.get("/assets", params={**q, "inventory": "all"}).json()) == ["10.9.0.10", "10.9.0.99"]
    assert _ips(c.get("/assets", params={**q, "inventory": "excluded"}).json()) == ["10.9.0.99"]
    assert _ips(c.get("/assets", params={**q, "inventory": "unlisted"}).json()) == ["10.9.0.10"]
    # still on the other pages: topology and hosts
    topo = c.get("/topology", params=q).json()
    nodes = [n for n in topo.get("nodes", topo.get("hosts", [])) if n.get("ip") == "10.9.0.99"]
    assert nodes and nodes[0]["inventory_excluded"] is True
    assert "10.9.0.99" in [h["ip"] for h in c.get("/hosts", params=q).json()]
    # export leaves it out unless asked
    rows = list(csv.DictReader(io.StringIO(c.get("/assets/export", params=q).text)))
    assert [r["ip"] for r in rows] == ["10.9.0.10"] and "inventory_excluded" in rows[0]
    rows = list(csv.DictReader(io.StringIO(c.get("/assets/export", params={**q, "include_excluded": "true"}).text)))
    assert {r["ip"]: r["inventory_excluded"] for r in rows} == {"10.9.0.10": "no", "10.9.0.99": "yes"}
    assert [r["inventory_excluded_reason"] for r in rows if r["ip"] == "10.9.0.99"] == ["visitor laptop"]
    # include again clears the reason / by / at
    j = c.patch(f"/assets/{hid}", params={"inventory_excluded": "false"}).json()
    assert j["inventory_excluded"] is False and j["inventory_excluded_reason"] is None and j["inventory_excluded_at"] is None
    assert _ips(c.get("/assets", params=q).json()) == ["10.9.0.10", "10.9.0.99"]
    assert c.get("/assets", params={**q, "inventory": "bogus"}).status_code == 422


def test_exclusion_counts_as_reviewed_for_unknown_device(api):
    c, sid, ids, Session = api
    from app.parsers.alert_engine import review_unknown_devices
    from app.parsers.site_scope import analysis_site
    with Session() as s:
        with analysis_site(s, sid):
            before = [f.detail.get("ip") for f in review_unknown_devices(s) if f.check_name == "unknown_device"]
    assert "10.9.0.99" in before
    assert c.patch(f"/assets/{ids['10.9.0.99']}", params={"inventory_excluded": "true", "inventory_excluded_reason": "scanner"}).status_code == 200
    with Session() as s:
        with analysis_site(s, sid):
            after = [f.detail.get("ip") for f in review_unknown_devices(s) if f.check_name == "unknown_device"]
    assert "10.9.0.99" not in after


def test_repeated_exclude_keeps_reason_and_author(api):
    c, sid, ids, Session = api
    hid = ids["10.9.0.99"]
    first = c.patch(f"/assets/{hid}", params={"inventory_excluded": "true", "inventory_excluded_reason": "scanner",
                                              "inventory_excluded_by": "pat"}).json()
    again = c.patch(f"/assets/{hid}", params={"inventory_excluded": "true"}).json()
    assert again["inventory_excluded_reason"] == "scanner" and again["inventory_excluded_by"] == "pat"
    assert again["inventory_excluded_at"] == first["inventory_excluded_at"]
