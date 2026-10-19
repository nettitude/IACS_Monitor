"""
B-11 (docs/multi-site-design.md "B-11: device routing conflicts"): a site is
never guessed for a conflicting log line - it is held until an operator
decides; the resolution replays the held lines (normal ingest path) and
applies to new lines; stored data is never moved.

Opts out of the conftest auto-site: every upload names its site (or none).
"""
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    DeviceConflictResolution, Finding, FortiAnalyzerEvent, SiteDevice, UnmappedLogEvent,
)
from app import site_devices as sd

pytestmark = pytest.mark.no_auto_site

ROOT = Path(__file__).resolve().parent.parent
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
        mp.delenv("IACS_ENABLE_DELETE", raising=False)
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
    return c.post(url, params=params or {}, files={"file": (name, content.encode(), "text/plain")})


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "b11.db") as c:
        _ok(c.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit
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


def syslog(c, text, **params):
    return _ok(up(c, "/ingest/forti-syslog", "x.cef", text, params))["stats"]


def events(c, **filt):
    with c.Session() as s:
        q = s.query(FortiAnalyzerEvent)
        for k, v in filt.items():
            q = q.filter(getattr(FortiAnalyzerEvent, k) == v)
        return q.all()


def n_findings(c):
    with c.Session() as s:
        return s.query(Finding).count()


def register(c, site, name, serial=None):
    with c.Session() as s:
        row = sd.register(s, site, name, serial).row
        s.commit()
        return row.id


def device(c, dev_id):
    with c.Session() as s:
        return s.get(SiteDevice, dev_id)


def conflicts(c, **params):
    return _ok(c.get("/site-devices/conflicts", params=params))


def resolve(c, code=200, **body):
    return _ok(c.post("/site-devices/conflicts/resolve", json=body), code)


# ------------------------------------------------------------ binding ------

def test_serial_bound_on_first_sight(client):
    dev_id = register(client, client.site_a, "fw-a")
    st = syslog(client, cfg_change(dev="fw-a", serial="FGTFIRST1"))
    assert st["events_created"] == 1 and st["conflicts"] == 0
    (b,) = st["routing"]["serial_bindings"]
    assert b == {"device_id": dev_id, "device_name": "fw-a", "serial": "FGTFIRST1",
                 "site_id": client.site_a}
    d = device(client, dev_id)
    assert d.serial == "FGTFIRST1" and d.serial_source == "first_seen" and d.serial_bound_at
    out = _ok(client.get("/site-devices"))[0]
    assert out["serial_source"] == "first_seen" and out["serial_bound_at"]
    # a second, different serial for the now-bound name is a conflict
    st = syslog(client, cfg_change(dev="fw-a", serial="FGTOTHER2", n=2))
    assert st["events_created"] == 0 and st["conflicts"] == 1


def test_serial_registered_elsewhere_routes_by_serial(client):
    register(client, client.site_a, "fw-a", "S-A")
    register(client, client.site_b, "fw-x", "S-B")
    st = syslog(client, cfg_change(dev="fw-a", serial="S-B"))
    assert st["events_created"] == 1 and st["conflicts"] == 0
    assert st["routing"]["routed"]["Plant B"]["events_created"] == 1
    assert conflicts(client)["pending_conflicts"] == 0


# ---------------------------------------------------- serial conflict ------

def test_serial_conflict_held_then_same_device(client):
    dev_id = register(client, client.site_a, "fw-a", "S-OLD")
    st = syslog(client, "\n".join([cfg_change(dev="fw-a", serial="S-NEW", n=1),
                                   cfg_change(dev="fw-a", serial="S-NEW", n=2)]))
    assert st["events_created"] == 0 and st["findings_created"] == 0 and st["conflicts"] == 2
    assert st["unmapped"] == 0 and st["routing"]["serial_conflicts"] == 2
    assert events(client) == [] and n_findings(client) == 0
    # re-upload: deduplicated in the queue
    st = syslog(client, cfg_change(dev="fw-a", serial="S-NEW", n=1))
    assert st["routing"]["conflict_duplicates"] == 1 and st["routing"]["conflicts"] == 0
    q = conflicts(client)
    assert q["pending_conflicts"] == 2 and q["pending_lines"] == 0 and q["group_count"] == 1
    (g,) = q["conflicts"]
    assert (g["device_key"], g["kind"], g["serial"], g["count"]) == ("fw-a", "serial_conflict", "S-NEW", 2)
    assert g["registered"]["id"] == dev_id and g["registered"]["serial"] == "S-OLD"
    assert g["registered"]["site"] == "Plant A" and g["vendor"] == "fortinet"
    assert "S-NEW" in g["sample_line"] and g["different_device_allowed"] is True
    assert len(conflicts(client, detail=True)["conflicts"][0]["lines"]) == 2
    # not in the unmapped list, not replayed by mapping
    assert _ok(client.get("/site-devices/unmapped"))["devices"] == []
    sites = {x["id"]: x for x in _ok(client.get("/sites"))}
    assert sites[client.site_a]["counts"]["conflicts_pending"] == 2
    assert sites[client.site_a]["counts"]["unmapped_pending"] == 0
    assert _ok(client.get("/sites/rollup"))["conflicts_pending"] == 2

    r = resolve(client, device_key="fw-a", kind="serial_conflict", serial="S-NEW",
                action="same_device", resolved_by="alice")
    assert r["replay"]["lines"] == 2 and r["replay"]["events_created"] == 2
    assert r["replay"]["findings_created"] >= 1
    assert r["device"]["serial"] == "S-NEW" and r["device"]["serial_source"] == "conflict_resolution"
    assert r["pending_conflicts"] == 0
    assert {e.site_id for e in events(client)} == {client.site_a}
    with client.Session() as s:
        assert {f.site_id for f in s.query(Finding)} == {client.site_a}
        assert s.query(UnmappedLogEvent).filter_by(status="replayed").count() == 2
    rec = r["resolution"]
    assert rec["action"] == "same_device" and rec["registered_serial"] == "S-OLD"
    assert rec["target_site"] == "Plant A" and rec["resolved_at"] and rec["resolved_by"] == "alice"
    # new lines with the new serial route; the old serial is now a conflict
    st = syslog(client, cfg_change(dev="fw-a", serial="S-NEW", n=3))
    assert st["events_created"] == 1
    st = syslog(client, cfg_change(dev="fw-a", serial="S-OLD", n=4))
    assert st["conflicts"] == 1


def test_serial_conflict_different_device(client):
    a_id = register(client, client.site_a, "fw-a", "S-A")
    syslog(client, cfg_change(dev="fw-a", serial="S-B", n=1))
    # site required
    assert client.post("/site-devices/conflicts/resolve", json={
        "device_key": "fw-a", "kind": "serial_conflict", "serial": "S-B",
        "action": "different_device"}).status_code == 422
    r = resolve(client, device_key="fw-a", kind="serial_conflict", serial="S-B",
                action="different_device", site="b")
    assert r["replay"]["events_created"] == 1
    new = r["device"]
    assert new["site_id"] == client.site_b and new["serial"] == "S-B" and new["id"] != a_id
    assert new["device_name"] == "fw-a" and new["serial_source"] == "conflict_resolution"
    assert device(client, a_id).serial == "S-A"            # registered device unchanged
    assert [e.site_id for e in events(client)] == [client.site_b]
    # future lines route by serial
    st = syslog(client, "\n".join([cfg_change(dev="fw-a", serial="S-B", n=2),
                                   cfg_change(dev="fw-a", serial="S-A", n=3)]))
    assert st["routing"]["routed"]["Plant A"]["events_created"] == 1
    assert st["routing"]["routed"]["Plant B"]["events_created"] == 1
    assert _ok(client.get("/site-devices/conflicts/resolutions"))[0]["device_id"] == new["id"]


def test_ha_peer_same_site_different_device(client):
    """FortiGate HA pair: same hostname, second serial -> a second registry
    row at the SAME site (resolution different_device, same site)."""
    register(client, client.site_a, "fw-ha", "S-PRI")
    syslog(client, cfg_change(dev="fw-ha", serial="S-SEC"))
    r = resolve(client, device_key="fw-ha", kind="serial_conflict", serial="S-SEC",
                action="different_device", site="a")
    assert r["device"]["site_id"] == client.site_a and r["replay"]["events_created"] == 1
    st = syslog(client, "\n".join([cfg_change(dev="fw-ha", serial="S-SEC", n=2),
                                   cfg_change(dev="fw-ha", serial="S-PRI", n=3),
                                   cfg_change(dev="fw-ha", n=4)]))       # name only: one site
    assert st["events_created"] == 3 and st["conflicts"] == 0


def test_same_device_refuses_serial_registered_elsewhere(client):
    register(client, client.site_a, "fw-a", "S-1")
    syslog(client, cfg_change(dev="fw-a", serial="S-2"))
    register(client, client.site_b, "other", "S-2")   # registered meanwhile
    r = client.post("/site-devices/conflicts/resolve", json={
        "device_key": "fw-a", "kind": "serial_conflict", "serial": "S-2", "action": "same_device"})
    assert r.status_code == 409 and "registered" in r.text
    assert conflicts(client)["pending_conflicts"] == 1
    with client.Session() as s:
        assert s.query(DeviceConflictResolution).count() == 0


# ------------------------------------------------------ site mismatch ------

def test_site_mismatch_held_and_resolved(client):
    b_id = register(client, client.site_b, "asa-b")
    text = "\n".join([asa("asa-b", 1), asa("asa-b", 2), asa("new-a", 3)])
    st = _ok(up(client, "/ingest/syslog", "s.log", text, {"site": "a"}))["stats"]
    assert st["events_created"] == 1 and st["conflicts"] == 2           # new-a mapped to A
    assert st["routing"]["site_conflicts"] == 2 and st["routing"]["new_mappings"] == 1
    assert [e.site_id for e in events(client)] == [client.site_a]
    (g,) = conflicts(client)["conflicts"]
    assert g["kind"] == "site_mismatch" and g["serial"] is None and g["count"] == 2
    assert g["registered"]["id"] == b_id and g["registered"]["site"] == "Plant B"
    assert g["requested_sites"] == ["Plant A"] and g["different_device_allowed"] is False
    # site filter: registered (B) or requested (A) site
    assert conflicts(client, site_id=client.site_a)["group_count"] == 1
    assert conflicts(client, site_id=client.site_b)["group_count"] == 1
    default = next(x["id"] for x in _ok(client.get("/sites")) if x["code"] == "default")
    assert conflicts(client, site_id=default)["group_count"] == 0
    assert conflicts(client, kind="serial_conflict")["group_count"] == 0
    # indistinguishable from the registered device -> 409, nothing changed
    r = client.post("/site-devices/conflicts/resolve", json={
        "device_key": "asa-b", "kind": "site_mismatch", "action": "different_device", "site": "a"})
    assert r.status_code == 409
    r = resolve(client, device_key="asa-b", kind="site_mismatch", action="same_device")
    assert r["replay"]["events_created"] == 2 and r["resolution"]["target_site_id"] == client.site_b
    assert sorted(e.site_id for e in events(client)) == sorted([client.site_a, client.site_b, client.site_b])
    # name-only device with a unique name keeps routing by name (no ?site)
    st = _ok(up(client, "/ingest/syslog", "s2.log", asa("asa-b", 9)))["stats"]
    assert st["events_created"] == 1 and st["conflicts"] == 0


def test_site_mismatch_after_remap_goes_to_new_site(client):
    b_id = register(client, client.site_b, "mover")
    _ok(up(client, "/ingest/syslog", "s.log", asa("mover", 1), {"site": "a"}))
    _ok(client.patch(f"/site-devices/{b_id}", json={"site": "a"}))     # it really moved
    r = resolve(client, device_key="mover", kind="site_mismatch", action="same_device")
    assert r["replay"]["events_created"] == 1
    assert [e.site_id for e in events(client)] == [client.site_a]


# ------------------------------------------------------------ dedup --------

def test_held_dedup_includes_fallback_device(client):
    line = cfg_change(n=5)                       # no devname / devid
    st = syslog(client, line, device_name="fwA")
    assert st["unmapped"] == 1
    st = syslog(client, line, device_name="fwB")
    assert st["unmapped"] == 1 and st["routing"]["unmapped_duplicates"] == 0
    st = syslog(client, line, device_name="fwB")
    assert st["routing"]["unmapped_duplicates"] == 1
    keys = sorted(g["device_key"] for g in _ok(client.get("/site-devices/unmapped"))["devices"])
    assert keys == ["fwa", "fwb"]
    r = _ok(client.post("/site-devices", json={"site": "b", "device_name": "fwB"}), 201)
    assert r["replay"]["events_created"] == 1
    r = _ok(client.post("/site-devices", json={"site": "a", "device_name": "fwA"}), 201)
    assert r["replay"]["events_created"] == 1
    assert sorted(e.site_id for e in events(client)) == sorted([client.site_a, client.site_b])
    assert sd.held_dedup_hash("a", None, "h") != sd.held_dedup_hash("b", None, "h")
    assert sd.held_dedup_hash("a", "S1", "h") != sd.held_dedup_hash("a", "S2", "h")


def test_mapping_binds_first_serial_and_reclassifies_others(client):
    syslog(client, "\n".join([cfg_change(dev="late", serial="S-1", n=1),
                              cfg_change(dev="late", serial="S-2", n=2)]))
    assert _ok(client.get("/site-devices/unmapped"))["pending_lines"] == 2
    r = _ok(client.post("/site-devices", json={"site": "a", "device_name": "late"}), 201)
    assert r["replay"]["events_created"] == 1
    with client.Session() as s:
        d = s.query(SiteDevice).filter_by(device_name="late").one()
        assert d.serial == "S-1" and d.serial_source == "first_seen"
    (g,) = conflicts(client)["conflicts"]
    assert g["serial"] == "S-2" and g["registered"]["serial"] == "S-1"


# ---------------------------------------------------- discard / audit ------

def test_discard_gated_and_recorded(client, monkeypatch):
    register(client, client.site_a, "fw-a", "S-1")
    syslog(client, cfg_change(dev="fw-a", serial="S-X"))
    body = {"device_key": "fw-a", "kind": "serial_conflict", "serial": "S-X", "action": "discard"}
    assert client.post("/site-devices/conflicts/resolve", json=body).status_code == 403
    assert conflicts(client)["pending_conflicts"] == 1
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    r = resolve(client, **body)
    assert r["replay"] is None and r["device"] is None and r["pending_conflicts"] == 0
    assert r["resolution"]["action"] == "discard" and r["resolution"]["lines"] == 1
    assert events(client) == []
    # unknown group -> 404; bad kind / action -> 422
    assert client.post("/site-devices/conflicts/resolve", json=body).status_code == 404
    assert client.post("/site-devices/conflicts/resolve",
                       json={**body, "kind": "unmapped"}).status_code == 422
    assert client.post("/site-devices/conflicts/resolve",
                       json={**body, "action": "move"}).status_code == 422
    audit = _ok(client.get("/site-devices/conflicts/resolutions"))
    assert [a["action"] for a in audit] == ["discard"] and audit[0]["resolved_at"]
    # the unmapped-queue discard does not touch conflicts
    syslog(client, cfg_change(dev="fw-a", serial="S-Y", n=2))
    _ok(client.post("/site-devices/unmapped/discard", json={"device_key": "fw-a"}))
    assert conflicts(client)["pending_conflicts"] == 1


def test_resolutions_recorded_for_each_action(client, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    register(client, client.site_a, "fw-1", "A1")
    register(client, client.site_a, "fw-2", "A2")
    register(client, client.site_a, "fw-3", "A3")
    syslog(client, "\n".join([cfg_change(dev="fw-1", serial="B1", n=1),
                              cfg_change(dev="fw-2", serial="B2", n=2),
                              cfg_change(dev="fw-3", serial="B3", n=3)]))
    resolve(client, device_key="fw-1", kind="serial_conflict", serial="B1", action="same_device")
    resolve(client, device_key="fw-2", kind="serial_conflict", serial="B2",
            action="different_device", site="b", device_name="fw-2-spare")
    resolve(client, device_key="fw-3", kind="serial_conflict", serial="B3", action="discard")
    with client.Session() as s:
        rows = s.query(DeviceConflictResolution).order_by(DeviceConflictResolution.id).all()
        assert [r.action for r in rows] == ["same_device", "different_device", "discard"]
        assert all(r.resolved_at is not None for r in rows)
        assert rows[1].target_site_id == client.site_b and rows[1].events_created == 1
        assert s.query(SiteDevice).filter_by(device_name="fw-2-spare").one().serial == "B2"
    assert _ok(client.get("/sites/rollup"))["conflicts_pending"] == 0


def test_forti_event_conflict_status(client):
    register(client, client.site_a, "fw-r", "R-1")
    p = {"devname": "fw-r", "devid": "R-2", "type": "traffic", "srcip": "10.0.0.1",
         "dstip": "10.0.0.2", "dstport": 502, "action": "accept", "policyid": 3}
    r = _ok(client.post("/ingest/forti-event", json=p))
    assert r["status"] == "conflict" and r["conflict"] is True and r["event_id"] is None
    assert r["routing"]["conflicts"] == 1


# ---------------------------------------------------------- migration ------

@pytest.mark.parametrize("dialect_url", ["postgresql+psycopg2://u:p@localhost/iasc",
                                         "sqlite:///offline-render-only.db"])
def test_offline_render(dialect_url):
    if dialect_url.startswith("postgresql"):
        pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade",
         "b3c4d5e6f7a8:c4d5e6f7a8b9", "--sql"],
        cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL=dialect_url))
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout
    assert "ALTER TABLE site_devices ADD COLUMN serial_source VARCHAR(24)" in sql
    assert "ALTER TABLE unmapped_log_events ADD COLUMN kind VARCHAR(16) DEFAULT 'unmapped' NOT NULL" in sql
    assert "CREATE TABLE IF NOT EXISTS device_conflict_resolutions" in sql
    assert "CREATE INDEX IF NOT EXISTS ix_unmapped_log_events_kind_status" in sql
    assert not Path(ROOT / "offline-render-only.db").exists()


def test_revision_reruns_idempotently(tmp_path):
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    import sqlalchemy as sa
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "b3c4d5e6f7a8")
    eng = sa.create_engine(url)
    assert "device_conflict_resolutions" not in sa.inspect(eng).get_table_names()
    command.upgrade(cfg, "head")
    command.stamp(cfg, "b3c4d5e6f7a8")
    command.upgrade(cfg, "head")                  # finds everything, no error
    with eng.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    eng.dispose()


def test_replay_claims_rows_once(tmp_path):
    """C-19: rows another transaction already replayed are not replayed
    again; the claim is a conditional UPDATE on status."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    from app.models import Site, UnmappedLogEvent
    from app import site_devices as sd
    engine = create_engine(f"sqlite:///{tmp_path / 'claim.db'}")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine, autoflush=False)
    db = S()
    site = Site(name="A", code="a")
    db.add(site)
    db.flush()
    rows = [UnmappedLogEvent(device_key="fw1", kind="unmapped", status="pending",
                             source_route="/ingest/forti-syslog", raw_line="garbage",
                             dedup_hash=f"h{k}") for k in range(3)]
    db.add_all(rows)
    db.commit()
    # another resolver already took row 1
    other = S()
    other.query(UnmappedLogEvent).filter(UnmappedLogEvent.id == rows[1].id) \
        .update({UnmappedLogEvent.status: "replayed"}, synchronize_session=False)
    other.commit()
    out = sd._replay_rows(db, db.query(UnmappedLogEvent).order_by(UnmappedLogEvent.id).all(),
                          site.id, evaluate=lambda ev, s: [])
    assert out["claimed"] == 2 and out["lines"] == 2
    db.commit()
    assert {r.status for r in db.query(UnmappedLogEvent)} <= {"replayed", "discarded"}
