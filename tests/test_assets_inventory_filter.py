"""SF-5 follow-up: the asset inventory tells listed hosts (Asset Inventory
CSV, Approved Host List, approved on the page) from hosts known only from
traffic, and `inventory=listed|unlisted|unknown` filters /assets and the CSV
export."""
import csv
import io
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import ApprovedHost, Baseline, Host, Site


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'inv.db'}", connect_args={"check_same_thread": False})
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
    now = datetime.now(timezone.utc)
    with Session() as s:
        site = Site(name="Plant", code="p")
        s.add(site)
        s.flush()
        bl = Baseline(site_id=site.id, name="audit", is_active=True)
        s.add(bl)
        s.flush()

        def host(ip, mac, **kw):
            h = Host(ip=ip, mac=mac, site_id=site.id, first_seen=now, last_seen=now, **kw)
            s.add(h)
            return h
        host("10.0.0.1", "00:00:00:00:00:01", sources=["pcap", "baseline"], device_type="plc", purdue_level=1,
             classification_source="manual")                                   # from an inventory CSV
        host("10.0.0.2", "00:00:00:00:00:02", sources=["pcap"], device_type="hmi", purdue_level=2,
             classification_source="manual")                                   # pcap only, classified -> unlisted
        host("10.0.0.3", "00:00:00:00:00:03", sources=["pcap"])                # pcap only, unclassified -> unknown
        host("10.0.0.4", "00:00:00:00:00:04", sources=["mac_table"], approved=True)      # approved on the page
        host("10.0.0.5", "AA:BB:CC:DD:EE:05", sources=["pcap"], device_type="ics_protocol_client_unclassified")
        s.add(ApprovedHost(baseline_id=bl.id, mac="aa:bb:cc:dd:ee:05", role="engineering_ws"))   # listed by MAC
        host("10.0.0.6", None, sources=["fortigate_config"])                   # config only -> unknown
        s.commit()
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.clear()


def _ips(rows):
    return sorted(r["ip"] for r in rows)


def test_assets_carry_inventory_membership(client):
    rows = {r["ip"]: r for r in client.get("/assets").json()}
    assert rows["10.0.0.1"]["in_inventory"] and rows["10.0.0.1"]["inventory_evidence"] == ["asset_inventory"]
    assert rows["10.0.0.4"]["inventory_evidence"] == ["approved"]
    assert rows["10.0.0.5"]["inventory_evidence"] == ["approved_host_list"]
    for ip in ("10.0.0.2", "10.0.0.3", "10.0.0.6"):
        assert rows[ip]["in_inventory"] is False and rows[ip]["inventory_evidence"] == []


def test_inventory_filter_values(client):
    assert _ips(client.get("/assets", params={"inventory": "listed"}).json()) == ["10.0.0.1", "10.0.0.4", "10.0.0.5"]
    assert _ips(client.get("/assets", params={"inventory": "unlisted"}).json()) == ["10.0.0.2", "10.0.0.3", "10.0.0.6"]
    # unknown = unlisted and not classified by the operator (the SF-5 rogue laptop)
    assert _ips(client.get("/assets", params={"inventory": "unknown"}).json()) == ["10.0.0.3", "10.0.0.6"]
    assert client.get("/assets", params={"inventory": "bogus"}).status_code == 422
    # combines with the site filter
    assert _ips(client.get("/assets", params={"inventory": "unknown", "site": "p"}).json()) == ["10.0.0.3", "10.0.0.6"]


def test_inventory_filter_in_csv_export(client):
    def rows(**params):
        r = client.get("/assets/export", params=params)
        assert r.status_code == 200
        return list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    allrows = {r["ip"]: r for r in rows()}
    assert allrows["10.0.0.1"]["in_inventory"] == "yes" and allrows["10.0.0.1"]["inventory_evidence"] == "asset_inventory"
    assert allrows["10.0.0.3"]["in_inventory"] == "no" and allrows["10.0.0.3"]["inventory_evidence"] == ""
    assert sorted(r["ip"] for r in rows(inventory="unknown")) == ["10.0.0.3", "10.0.0.6"]
    assert sorted(r["ip"] for r in rows(inventory="listed")) == ["10.0.0.1", "10.0.0.4", "10.0.0.5"]
    assert client.get("/assets/export", params={"inventory": "x"}).status_code == 422
