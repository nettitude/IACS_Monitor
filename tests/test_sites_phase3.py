"""
Multi-site phase 3 (docs/multi-site-design.md): site device registry,
per-line log routing, unmapped-device queue, mapping + replay, retention.

The whole module opts out of the conftest auto-site (log routes would get
site=default otherwise): every upload names its site explicitly.
"""
import os
import subprocess
import sys
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    Finding, FortiAnalyzerEvent, Site, SiteDevice, SiteDeviceSerial, UnmappedLogEvent, utcnow,
)
from app import site_devices as sd

pytestmark = pytest.mark.no_auto_site

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"
ALEMBIC_INI = ROOT / "alembic.ini"


@contextmanager
def _api(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("IACS_REVIEW_ENABLED", "false")
        mp.setattr(main_mod, "init_db", lambda: None)
        prev = main_mod.app.dependency_overrides.get(get_db)
        main_mod.app.dependency_overrides[get_db] = _get_db
        try:
            with TestClient(main_mod.app) as c:
                c.Session = Session
                yield c
        finally:
            if prev is None:
                main_mod.app.dependency_overrides.pop(get_db, None)
            else:
                main_mod.app.dependency_overrides[get_db] = prev
            engine.dispose()


def _ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.text[:800])
    return r.json()


def up(c, url, name, content, params=None):
    if isinstance(content, str):
        content = content.encode()
    return c.post(url, params=params or {}, files={"file": (name, content, "text/plain")})


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "p3.db") as c:
        _ok(c.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit (no implicit Default)
        c.site_a = _ok(c.post("/sites", json={"name": "Plant A", "code": "a"}), 201)["id"]
        c.site_b = _ok(c.post("/sites", json={"name": "Plant B", "code": "b"}), 201)["id"]
        yield c


def cfg_change(dev=None, serial=None, n=1):
    """FortiGate CEF config-change line (fw_config_change check -> finding)."""
    ident = ""
    if serial:
        ident += f"deviceExternalId={serial} "
    if dev:
        ident += f"dvchost={dev} "
    return (f"CEF:0|Fortinet|FortiGate|7.2.0|0000000020|event:system config-change|7|"
            f"{ident}rt={1705320000000 + n * 1000} src=10.0.4.5 duser=admin act=change "
            f"msg=vdom root changed policy {n} cs1=99 cs1Label=policyid")


def asa(host, n=1):
    return (f"<166>Sep 30 2026 12:00:{n:02d} {host} : %ASA-6-106100: access-list outside_access_in "
            f"permitted tcp outside/203.0.113.5(5123{n}) -> inside/10.10.1.20(502) hit-cnt 1 "
            f"first hit [0x1a2b3c4d, 0x0]")


def events(c, **filt):
    with c.Session() as s:
        q = s.query(FortiAnalyzerEvent)
        for k, v in filt.items():
            q = q.filter(getattr(FortiAnalyzerEvent, k) == v)
        return q.all()


def pending(c, key=None):
    with c.Session() as s:
        q = s.query(UnmappedLogEvent).filter(UnmappedLogEvent.status == "pending")
        if key is not None:
            q = q.filter(UnmappedLogEvent.device_key == key)
        return q.count()


FORTI_CFG = (SAMPLES / "sample_fortigate_config.txt").read_text()   # hostname FG-OT-PERIMETER-01
PF_CFG = """<?xml version="1.0"?>
<pfsense><system><hostname>pf-edge</hostname><domain>lan</domain></system>
<filter><rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
<source><any/></source><destination><address>10.0.0.5</address><port>502</port></destination>
<descr>modbus</descr></rule></filter></pfsense>"""


# ------------------------------------------------------- registration ------

def test_config_upload_registers_device(client):
    r = _ok(up(client, "/ingest/fortigate-config", "fg.txt", FORTI_CFG, {"site": "a"}))
    assert r["site_device_conflicts"] == []
    assert r["site_devices"][0]["device_name"] == "fg-ot-perimeter-01"
    assert r["site_devices"][0]["source"] == "config_upload"
    devs = _ok(client.get("/site-devices", params={"site_id": client.site_a}))
    assert [d["device_name"] for d in devs] == ["fg-ot-perimeter-01"]
    assert devs[0]["site"] == "Plant A" and devs[0]["vendor"] == "fortinet"

    r = _ok(up(client, "/ingest/firewall", "pf.xml", PF_CFG, {"site": "b", "vendor_hint": "pfsense"}))
    assert r["site_devices"][0]["device_name"] == "pf-edge"
    assert r["site_devices"][0]["vendor"] == "pfsense"
    sites = {s["id"]: s for s in _ok(client.get("/sites"))}
    assert sites[client.site_a]["counts"]["devices"] == 1
    assert sites[client.site_b]["counts"]["devices"] == 1


def test_config_upload_conflict_warns_and_does_not_move(client):
    _ok(up(client, "/ingest/fortigate-config", "fg.txt", FORTI_CFG, {"site": "a"}))
    r = _ok(up(client, "/ingest/fortigate-config", "fg.txt", FORTI_CFG, {"site": "b"}))
    assert r["site_devices"] == []
    (conf,) = r["site_device_conflicts"]
    assert conf["registered_site_id"] == client.site_a and conf["upload_site_id"] == client.site_b
    with client.Session() as s:
        (row,) = s.query(SiteDevice).all()
        assert row.site_id == client.site_a


def test_same_name_two_sites_only_with_distinct_serials(client):
    with client.Session() as s:
        assert sd.register(s, client.site_a, "FW-1", "S1").status == "created"
        assert sd.register(s, client.site_b, "fw-1", "S2").status == "created"
        assert sd.register(s, client.site_b, "fw-1").status in ("unchanged", "updated")
        assert sd.register(s, client.site_b, "fw-x", "S1").conflict      # serial is global
        assert sd.register(s, client.site_a, "solo").status == "created"
        assert sd.register(s, client.site_b, "solo", "S9").conflict      # A's row has no serial
        s.commit()
        with pytest.raises(sa.exc.IntegrityError):     # B-12: unique in site_device_serials
            s.add(SiteDevice(site_id=client.site_b, device_name="z", source="manual",
                             serials=[SiteDeviceSerial(serial="S2", source="manual")]))
            s.flush()
        s.rollback()


# ------------------------------------------------------------ routing ------

def test_routing_by_serial_and_by_name(client):
    with client.Session() as s:
        sd.register(s, client.site_a, "fw-a", "FGTSERIALA")
        sd.register(s, client.site_b, "asa-b")
        s.commit()
    text = "\n".join([cfg_change(serial="FGTSERIALA", n=1),          # serial only
                      cfg_change(dev="renamed", serial="FGTSERIALA", n=2),
                      asa("ASA-B", 1)])                              # name (case-insensitive)
    st = _ok(up(client, "/ingest/syslog", "s.log", text))["stats"]
    assert st["events_created"] == 3 and st["unmapped"] == 0
    routed = st["routing"]["routed"]
    assert routed["Plant A"]["events_created"] == 2
    assert routed["Plant B"]["events_created"] == 1
    assert {e.site_id for e in events(client, vendor="fortinet")} == {client.site_a}
    assert {e.site_id for e in events(client, vendor="cisco_asa")} == {client.site_b}
    # findings follow the event's site
    with client.Session() as s:
        f = s.query(Finding).filter(Finding.forti_event_id.isnot(None)).all()
        assert f
        for x in f:
            assert x.site_id == s.get(FortiAnalyzerEvent, x.forti_event_id).site_id


def test_ambiguous_name_without_serial_is_held(client):
    with client.Session() as s:
        sd.register(s, client.site_a, "dup", "S1")
        sd.register(s, client.site_b, "dup", "S2")
        s.commit()
        assert sd.resolve(s, "dup") is None
        assert sd.resolve(s, "dup", "S2").id == client.site_b
    st = _ok(up(client, "/ingest/syslog", "s.log", asa("dup")))["stats"]
    assert st["events_created"] == 0 and st["unmapped"] == 1
    assert pending(client, "dup") == 1


def test_unknown_device_is_queued_without_checks(client):
    text = "\n".join([cfg_change(dev="ghost", n=1), cfg_change(dev="ghost", n=2),
                      cfg_change(n=3)])       # last line: no device identity at all
    st = _ok(up(client, "/ingest/forti-syslog", "g.cef", text))["stats"]
    assert st["events_created"] == 0 and st["findings_created"] == 0
    assert st["unmapped"] == 3 and st["routing"]["unmapped"] == 3
    assert events(client) == []
    with client.Session() as s:
        assert s.query(Finding).count() == 0
    # re-upload: deduplicated in the queue
    st = _ok(up(client, "/ingest/forti-syslog", "g.cef", text))["stats"]
    assert st["routing"]["unmapped"] == 0 and st["routing"]["unmapped_duplicates"] == 3
    q = _ok(client.get("/site-devices/unmapped"))
    assert q["pending_lines"] == 3
    groups = {g["device_key"]: g for g in q["devices"]}
    assert groups["ghost"]["count"] == 2 and groups[""]["count"] == 1
    assert "ghost" in groups["ghost"]["sample_line"] and groups["ghost"]["vendor"] == "fortinet"
    detail = _ok(client.get("/site-devices/unmapped", params={"detail": True, "device_key": "ghost"}))
    assert len(detail["devices"][0]["lines"]) == 2
    assert _ok(client.get("/sites"))[0]["counts"]["unmapped_pending"] == 3


def test_site_param_maps_unknown_only_and_counts_conflicts(client):
    with client.Session() as s:
        sd.register(s, client.site_b, "known-b")
        s.commit()
    text = "\n".join([asa("new-1", 1), asa("known-b", 2), asa("known-b", 3)])
    st = _ok(up(client, "/ingest/syslog", "s.log", text, {"site": "a"}))["stats"]
    r = st["routing"]
    assert r["new_mappings"] == 1 and r["mapped_devices"][0]["device_name"] == "new-1"
    # B-11: a device registered to another site is never routed by guess -
    # its lines are held as site_mismatch conflicts (tests/test_b11_conflicts.py)
    assert r["site_conflicts"] == 2 and r["conflicts"] == 2 and st["conflicts"] == 2
    assert r["routed"]["Plant A"]["events_created"] == 1
    assert "Plant B" not in r["routed"]
    with client.Session() as s:
        rows = {d.device_name: d for d in s.query(SiteDevice)}
        assert rows["new-1"].site_id == client.site_a and rows["new-1"].source == "manual"
        assert rows["known-b"].site_id == client.site_b          # never overridden
    # lines without identity go to the ?site
    st = _ok(up(client, "/ingest/forti-syslog", "n.cef", cfg_change(n=7), {"site": "b"}))["stats"]
    assert st["routing"]["routed"]["Plant B"]["events_created"] == 1
    # unknown ?site -> 422
    assert up(client, "/ingest/syslog", "s.log", asa("x"), {"site": "nope"}).status_code == 422


def test_forti_event_and_report_routing(client):
    p = {"devname": "fw-r", "devid": "FGTR1", "type": "traffic", "srcip": "10.0.0.1",
         "dstip": "10.0.0.2", "dstport": 502, "action": "accept", "policyid": 3}
    r = _ok(client.post("/ingest/forti-event", json=p))
    assert r["status"] == "unmapped" and r["unmapped"] is True and r["event_id"] is None
    csv_text = (SAMPLES / "sample_forti_traffic.csv").read_text()
    r = _ok(up(client, "/ingest/forti-report", "r.csv", csv_text))
    assert r["events_imported"] == 0 and r["unmapped"] > 0
    held = r["unmapped"]
    # map the report's devices to B through the queue (replay)
    keys = [g["device_key"] for g in _ok(client.get("/site-devices/unmapped"))["devices"]]
    replayed = 0
    for k in keys:
        if k == "fw-r":
            continue
        body = {"site": "b", "device_name": k} if k else None
        if body:
            replayed += _ok(client.post("/site-devices", json=body), 201)["replay"]["events_created"]
    assert replayed > 0
    rep = _ok(client.post("/site-devices", json={"site": "a", "serial": "FGTR1"}), 201)["replay"]
    assert rep["events_created"] == 1
    (ev,) = events(client, device_name="fw-r")
    assert ev.site_id == client.site_a
    assert held >= replayed


# ------------------------------------------------------ mapping / replay ----

def test_mapping_replays_into_the_right_site(client):
    text = "\n".join([cfg_change(dev="late", n=1), cfg_change(dev="late", n=2)])
    _ok(up(client, "/ingest/forti-syslog", "l.cef", text))
    r = _ok(client.post("/site-devices", json={"site": "b", "device_name": "LATE",
                                               "vendor": "fortinet"}), 201)
    assert r["status"] == "created" and r["site"] == "Plant B"
    assert r["replay"]["lines"] == 2 and r["replay"]["events_created"] == 2
    assert r["replay"]["findings_created"] >= 1
    assert {e.site_id for e in events(client)} == {client.site_b}
    with client.Session() as s:
        f = s.query(Finding).all()
        assert f and {x.site_id for x in f} == {client.site_b}
        assert s.query(UnmappedLogEvent).filter_by(status="replayed").count() == 2
    assert pending(client) == 0
    # mapping the same device again: 200, nothing to replay; other site: 409
    again = client.post("/site-devices", json={"site": "b", "device_name": "late"})
    assert again.status_code == 200 and again.json()["replay"]["lines"] == 0
    assert client.post("/site-devices", json={"site": "a", "device_name": "late"}).status_code == 409


def test_remap_affects_new_lines_only(client):
    dev = _ok(client.post("/site-devices", json={"site": "a", "device_name": "mover"}), 201)
    _ok(up(client, "/ingest/syslog", "1.log", asa("mover", 1)))
    r = _ok(client.patch(f"/site-devices/{dev['id']}", json={"site": "b"}))
    assert r["remapped"] is True and r["previous_site_id"] == client.site_a
    _ok(up(client, "/ingest/syslog", "2.log", asa("mover", 2)))
    by_site = sorted(e.site_id for e in events(client))
    assert by_site == sorted([client.site_a, client.site_b])     # old event NOT moved


def test_discard_purge_and_delete(client, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")  # B-21: discard/purge are gated
    _ok(up(client, "/ingest/syslog", "d.log", "\n".join([asa("junk", 1), asa("keep", 2)])))
    r = _ok(client.post("/site-devices/unmapped/discard", json={"device_key": "JUNK"}))
    assert r["discarded"] == 1 and r["pending_lines"] == 1
    # age the remaining pending line past retention
    with client.Session() as s:
        s.query(UnmappedLogEvent).filter_by(device_key="keep").update(
            {UnmappedLogEvent.received_at: utcnow() - timedelta(days=40)})
        s.commit()
    out = _ok(client.post("/site-devices/unmapped/purge"))
    assert out == {"retention_days": 30, "replayed_or_discarded": 1, "expired_pending": 1,
                   "pending_lines": 0}
    monkeypatch.setenv("IACS_UNMAPPED_RETENTION_DAYS", "5")
    assert sd.retention_days() == 5
    # scheduler job target runs the same purge
    assert callable(main_mod._run_unmapped_retention)

    dev = _ok(client.post("/site-devices", json={"site": "a", "device_name": "gone"}), 201)
    monkeypatch.delenv("IACS_ENABLE_DELETE")
    assert client.delete(f"/site-devices/{dev['id']}").status_code == 403
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    assert _ok(client.delete(f"/site-devices/{dev['id']}"))["deleted"] == "site_device"
    _ok(up(client, "/ingest/syslog", "g.log", asa("gone", 3)))
    assert pending(client, "gone") == 1


# ---------------------------------------------------------- migration ------

def _cfg(url):
    from alembic.config import Config
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def test_migration_idempotent_and_no_drift(tmp_path):
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    url = f"sqlite:///{tmp_path / 'm.db'}"
    command.upgrade(_cfg(url), "head")
    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    assert {"site_devices", "unmapped_log_events"} <= set(insp.get_table_names())
    ix = {i["name"] for i in insp.get_indexes("site_devices")}
    # B-12 (d5e6f7a8b9c0): serials moved to site_device_serials
    assert {"ix_site_devices_site_id", "ix_site_devices_device_name"} <= ix
    assert {i["name"] for i in insp.get_indexes("site_device_serials")} >= {
        "ux_site_device_serials_serial", "ix_site_device_serials_device_id"}
    # re-run the revision on a schema that already has everything
    command.downgrade(_cfg(url), "e1f2a3b4c5d6")
    assert "site_devices" not in sa.inspect(eng).get_table_names()
    command.upgrade(_cfg(url), "head")
    command.stamp(_cfg(url), "e1f2a3b4c5d6")
    command.upgrade(_cfg(url), "head")                       # finds everything, no error
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff
    eng.dispose()


@pytest.mark.parametrize("dialect_url", ["postgresql+psycopg2://u:p@localhost/iasc",
                                         "sqlite:///offline-render-only.db"])
def test_offline_render(dialect_url):
    if dialect_url.startswith("postgresql"):
        pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade",
         "e1f2a3b4c5d6:head", "--sql"],
        cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL=dialect_url))
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout
    assert "CREATE TABLE IF NOT EXISTS site_devices" in sql
    assert "CREATE TABLE IF NOT EXISTS unmapped_log_events" in sql
    assert ("CREATE UNIQUE INDEX IF NOT EXISTS ux_site_devices_serial ON site_devices (serial) "
            "WHERE serial IS NOT NULL") in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_unmapped_log_events_dedup_hash" in sql
    assert not Path(ROOT / "offline-render-only.db").exists()
