"""
Periodic reviews at upload time (owner, 2026-10-12: "period findings should be ran at
upload time").  app/review_trigger.py + the _reviews_after_upload decorator on the upload
routes: a successful upload queues one background review of its site, uploads during a run
are coalesced into one more run, a run behind a busy review lock is retried, live log
streams do not trigger it, IACS_REVIEW_ON_UPLOAD=false switches it off.
"""
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import review_trigger as rt
from app.db import Base, configure_sqlite_engine, get_db, get_write_db
from app.main import app


@pytest.fixture(autouse=True)
def _clean_state():
    rt._state.clear()
    yield
    rt._state.clear()


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ON_UPLOAD", "true")


def _wait(pred, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_off_switch(monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ON_UPLOAD", "false")
    assert rt.request(1, "x") == "off"
    assert rt._state == {}


def test_no_site(on):
    assert rt.request(None, "x") == "no site"


def test_uploads_during_a_run_are_coalesced(on, monkeypatch):
    gate, calls = threading.Event(), []

    def fake_run(site_id):
        calls.append(site_id)
        if len(calls) == 1:
            gate.wait(5)
        return {"review_x": 2}
    monkeypatch.setattr(rt, "run_now", fake_run)
    assert rt.request(7, "FortiGate config") == "queued"
    assert _wait(lambda: len(calls) == 1)
    assert rt.request(7, "pcap") == "queued after the running review"
    assert rt.request(7, "MAC table") == "queued after the running review"
    gate.set()
    assert _wait(lambda: not rt.status(7)["running"])
    assert calls == [7, 7]                                     # two uploads during the run -> ONE more run
    last = rt.status(7)["last"]
    assert last["ok"] and last["new_findings"] == 2 and last["after"] == ["pcap", "MAC table"]


def test_worker_survives_a_failing_run(on, monkeypatch):
    def boom(site_id):
        raise RuntimeError("x")
    monkeypatch.setattr(rt, "run_now", boom)
    rt.request(3, "pcap")
    assert _wait(lambda: rt.status(3)["last"] is not None and not rt.status(3)["running"])
    assert rt.status(3)["last"]["ok"] is False


def test_run_now_retries_behind_a_busy_lock(monkeypatch):
    from app.parsers import alert_engine as ae
    seq = [{ae.REVIEW_SKIPPED_STAT: 0}, {ae.REVIEW_SKIPPED_STAT: 0}, {"review_y": 1}]
    monkeypatch.setattr(ae, "run_periodic_reviews", lambda db, site_id=None: seq.pop(0))
    monkeypatch.setattr(rt, "_RETRY_SECONDS", 0)
    assert rt.run_now(5) == {"review_y": 1} and seq == []


# ─── routes ───────────────────────────────────────────────────────────────────

@pytest.fixture
def client(on, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    def _db():
        yield db
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_write_db] = _db
    calls = []
    monkeypatch.setattr(rt, "request", lambda site_id, what: calls.append((site_id, what)) or "queued")
    with TestClient(app) as c:
        c.calls = calls
        r = c.post("/sites", json={"name": "Upload", "code": "upload"})
        assert r.status_code == 201
        c.site_id = r.json()["id"]
        yield c
    app.dependency_overrides.clear()
    db.close()


def test_config_upload_queues_the_site_review(client):
    with open("sample_data/sample_fortigate_config.txt", "rb") as fh:
        r = client.post("/ingest/fortigate-config?site=upload&firewall_name=FW-U", files={"file": ("fw.conf", fh)})
    assert r.status_code == 200 and r.json()["reviews"] == "queued"
    assert client.calls == [(client.site_id, "FortiGate config")]


def test_pcap_upload_queues_the_site_review(client):
    with open("sample_data/modbus_sample.pcap", "rb") as fh:
        r = client.post("/ingest/pcap?site=upload", files={"file": ("m.pcap", fh)})
    assert r.status_code == 200, r.text
    assert r.json()["reviews"] == "queued" and client.calls == [(client.site_id, "pcap")]


def test_failed_upload_queues_nothing(client):
    r = client.post("/ingest/fortigate-config?site=upload", files={"file": ("x.conf", b"not a config")})
    assert r.status_code >= 400 and client.calls == []


def test_live_syslog_does_not_queue(client):
    line = ('date=2026-10-12 time=10:00:00 devname="FW-U" devid="FG100F" logid="0000000013" type="traffic" '
            'subtype="forward" srcip=10.0.1.5 dstip=10.0.2.6 dstport=502 action="accept" policyid=1')
    client.post("/ingest/forti-syslog?site=upload", content=line, headers={"Content-Type": "text/plain"})
    assert client.calls == []


def test_every_upload_route_is_decorated():
    from app.api.routes import router
    wrapped = [r for r in router.routes if getattr(r, "path", "").startswith(("/ingest", "/baselines"))
               and getattr(getattr(r, "endpoint", None), "__wrapped__", None) is not None]
    paths = {r.path for r in wrapped}
    assert {"/ingest/pcap", "/ingest/pcap-fw", "/ingest/arp", "/ingest/firewall", "/ingest/fortigate-config",
            "/ingest/switch", "/ingest/mac-table", "/ingest/forti-report", "/ingest/baseline/comms-matrix",
            "/ingest/baseline/approved-hosts", "/ingest/baseline/asset-inventory",
            "/ingest/baseline/reviewed-policies", "/baselines/{baseline_name}/activate",
            "/ingest/pcap/{capture_id}/confirm", "/ingest/pcap/{capture_id}/associate"} <= paths
    assert not {"/ingest/forti-event", "/ingest/forti-syslog", "/ingest/syslog",
                "/ingest/baseline/asset-inventory/preview"} & paths
