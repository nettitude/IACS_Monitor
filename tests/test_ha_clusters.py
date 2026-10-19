"""
B-12 (docs/multi-site-design.md "B-12: HA clusters"): an FGCP HA cluster is
ONE registered device with one serial per member unit.  Lines carrying any
member serial route to the device's site; a new serial under an HA device's
name is added automatically when an HA event log from a known member names
it as a peer (or it was pre-registered), otherwise it is held as an
``ha_candidate`` for "Add as HA member".  Never across sites, never more
than HA_MAX_MEMBERS.  An a-p cluster whose active member changes raises an
``ha_failover`` finding.

Opts out of the conftest auto-site: every upload names its site (or none).
"""
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app import site_devices as sd
from app.db import Base, get_db
from app.models import (
    DeviceConflictResolution, Finding, FortiAnalyzerEvent, SiteDevice, SiteDeviceSerial,
    UnmappedLogEvent,
)

pytestmark = pytest.mark.no_auto_site

ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = ROOT / "alembic.ini"
SAMPLE_CFG = (ROOT / "sample_data" / "sample_fortigate_config.txt").read_text()


def ha_cfg(host="FW-HA", mode="a-p", group="plant-a-ha", gid=7):
    """The sample FortiGate config with another hostname and HA block."""
    text = SAMPLE_CFG.replace("set hostname FG-OT-PERIMETER-01", f"set hostname {host}")
    start = text.index("config system ha")
    end = text.index("end", start) + 3
    body = [f"    set mode {mode}"] if mode else []
    if group:
        body.append(f'    set group-name "{group}"')
    if gid is not None:
        body.append(f"    set group-id {gid}")
    return text[:start] + "config system ha\n" + "\n".join(body) + "\nend" + text[end:]


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
    with _api(tmp_path / "ha.db") as c:
        _ok(c.get("/sites"))
        c.site_a = _ok(c.post("/sites", json={"name": "Plant A", "code": "a"}), 201)["id"]
        c.site_b = _ok(c.post("/sites", json={"name": "Plant B", "code": "b"}), 201)["id"]
        yield c


def traffic(serial, n=1, dev="FW-HA", subtype="forward", hour=10):
    return (f'date=2026-10-01 time={hour:02d}:00:{n:02d} devname="{dev}" devid="{serial}" '
            f'logid="0000000013" type="traffic" subtype="{subtype}" srcip=10.0.1.{20 + n} '
            f'dstip=10.0.1.10 srcport={50000 + n} dstport=502 proto=6 action="accept" '
            f'policyid=7 service="MODBUS"')


def ha_join(logger, peer, group=7, dev="FW-HA", n=1):
    """FortiOS 0108037894 'Virtual cluster member joined' (sn = the peer)."""
    return (f'date=2026-10-01 time=09:59:{n:02d} devname="{dev}" devid="{logger}" '
            f'logid="0108037894" type="event" subtype="ha" level="critical" vd="root" '
            f'logdesc="Virtual cluster member joined" msg="Virtual cluster detected member join" '
            f'vcluster=1 ha_group={group} sn="{peer}"')


def ha_state(logger, member, role="master", dev="FW-HA", n=1, hour=11):
    """FortiOS 0108037892 'Virtual cluster member state moved'."""
    return (f'date=2026-10-01 time={hour:02d}:30:{n:02d} devname="{dev}" devid="{logger}" '
            f'logid="0108037892" type="event" subtype="ha" level="notice" vd="root" '
            f'logdesc="Virtual cluster member state moved" msg="Virtual cluster\'s member state moved" '
            f'ha_role="{role}" vcluster=1 vcluster_state="work" vcluster_member=0 '
            f'hostname="{dev}" sn="{member}"')


def syslog(c, *lines, **params):
    return _ok(up(c, "/ingest/forti-syslog", "ha.log", "\n".join(lines) + "\n", params))["stats"]


def ha_device(c, site="a", **kw):
    r = _ok(up(c, "/ingest/fortigate-config", "ha.txt", ha_cfg(**kw), {"site": site}))
    (dev,) = r["site_devices"]
    return dev


def get_dev(c, dev_id):
    return next(d for d in _ok(c.get("/site-devices")) if d["id"] == dev_id)


def members(c, dev_id):
    return {m["serial"]: m for m in get_dev(c, dev_id)["members"]}


def events_of(c, serial):
    with c.Session() as s:
        return [e for e in s.query(FortiAnalyzerEvent).all()
                if (e.raw_fields or {}).get("devid") == serial]


def pending(c, serial, kind=None):
    with c.Session() as s:
        q = s.query(UnmappedLogEvent).filter_by(status="pending", serial=serial)
        if kind:
            q = q.filter_by(kind=kind)
        return q.count()


def failovers(c):
    with c.Session() as s:
        return s.query(Finding).filter_by(check_name="ha_failover").all()


# ------------------------------------------------------------ detection ----

def test_ha_detected_from_config_and_standalone_turns_it_off(client):
    dev = ha_device(client)
    assert dev["device_name"] == "fw-ha" and dev["is_ha"] is True
    assert dev["ha_mode"] == "a-p" and dev["ha_group_name"] == "plant-a-ha" and dev["ha_group_id"] == 7
    assert dev["members"] == [] and dev["max_members"] == sd.HA_MAX_MEMBERS == 4
    d = get_dev(client, dev["id"])
    assert d["is_ha"] and d["ha_mode"] == "a-p"
    # same device re-uploaded as standalone -> not HA
    r = _ok(up(client, "/ingest/fortigate-config", "ha.txt", ha_cfg(mode="standalone"), {"site": "a"}))
    assert r["site_devices"][0]["ha"]["is_ha"] is False
    d = get_dev(client, dev["id"])
    assert d["is_ha"] is False and d["ha_mode"] is None and d["ha_group_name"] is None
    # mode absent = FortiOS default standalone; a-a recognised
    assert sd.ha_config("config system ha\n    set group-name x\nend\n").is_ha is False
    assert sd.ha_config("config system ha\n    set mode a-a\nend\n").mode == "a-a"
    assert sd.ha_config("config system global\n    set hostname x\nend\n") is None


def test_ha_config_inside_global_vdom_wrapper():
    text = ("config global\nconfig system global\n    set hostname FW\nend\n"
            "config system ha\n    set mode a-p\n    set group-name g1\n    set group-id 3\nend\n"
            "end\nconfig vdom\nedit root\nend\n")
    ha = sd.ha_config(text)
    assert (ha.mode, ha.group_name, ha.group_id) == ("a-p", "g1", 3)


# --------------------------------------------------------------- binding ---

def test_second_serial_with_evidence_auto_added_and_routed(client):
    dev = ha_device(client)
    st = syslog(client, traffic("FGT-A", 1), ha_join("FGT-A", "FGT-B"), traffic("FGT-B", 2))
    r = st["routing"]
    assert r["conflicts"] == 0 and r["ha_candidates"] == 0
    assert [m["status"] for m in r["ha_members"]] == ["added"]
    m = members(client, dev["id"])
    assert m["FGT-A"]["source"] == "first_seen" and m["FGT-B"]["source"] == "ha_evidence"
    (ev,) = events_of(client, "FGT-B")
    assert ev.site_id == client.site_a
    audit = _ok(client.get("/site-devices/conflicts/resolutions"))
    assert audit[0]["action"] == "ha_evidence" and audit[0]["serial"] == "FGT-B"
    assert audit[0]["resolved_by"] == sd.AUTO_RESOLVED_BY and audit[0]["device_id"] == dev["id"]


def test_held_candidate_replayed_when_evidence_arrives_later_in_same_file(client):
    dev = ha_device(client)
    st = syslog(client, traffic("FGT-A", 1), traffic("FGT-B", 2), traffic("FGT-B", 3),
                ha_join("FGT-A", "FGT-B"), traffic("FGT-B", 4))
    r = st["routing"]
    assert r["ha_candidates"] == 2                     # held before the evidence
    (added,) = r["ha_members"]
    assert added["replay"]["lines"] == 2 and added["replay"]["events_created"] == 2
    assert pending(client, "FGT-B") == 0
    assert len(events_of(client, "FGT-B")) == 3
    assert {e.site_id for e in events_of(client, "FGT-B")} == {client.site_a}
    assert set(members(client, dev["id"])) == {"FGT-A", "FGT-B"}


def test_evidence_in_later_upload_auto_replays_held_lines(client):
    dev = ha_device(client)
    syslog(client, traffic("FGT-A", 1))
    st = syslog(client, traffic("FGT-B", 2))
    assert st["conflicts"] == 1 and st["routing"]["ha_candidates"] == 1
    assert pending(client, "FGT-B", "ha_candidate") == 1
    st = syslog(client, ha_join("FGT-A", "FGT-B", n=5))
    assert st["routing"]["ha_members"][0]["replay"]["lines"] == 1
    assert pending(client, "FGT-B") == 0 and len(events_of(client, "FGT-B")) == 1
    assert "FGT-B" in members(client, dev["id"])


def test_without_evidence_held_as_candidate_then_add_ha_member(client):
    dev = ha_device(client)
    syslog(client, traffic("FGT-A", 1))
    st = syslog(client, traffic("FGT-B", 2), traffic("FGT-B", 3))
    assert st["conflicts"] == 2 and st["routing"]["serial_conflicts"] == 0
    (g,) = _ok(client.get("/site-devices/conflicts"))["conflicts"]
    assert g["kind"] == "ha_candidate" and g["serial"] == "FGT-B"
    assert g["add_ha_member_allowed"] is True and g["add_ha_member_needs_mark_ha"] is False
    assert g["registered"]["is_ha"] is True and g["registered"]["members"] == ["FGT-A"]
    assert _ok(client.get("/site-devices/conflicts", params={"kind": "ha_candidate"}))["group_count"] == 1
    r = _ok(client.post("/site-devices/conflicts/resolve", json={
        "device_key": "fw-ha", "kind": "ha_candidate", "serial": "FGT-B", "action": "add_ha_member"}))
    assert r["replay"]["lines"] == 2 and r["replay"]["events_created"] == 2
    assert r["resolution"]["action"] == "add_ha_member" and r["resolution"]["target_site_id"] == client.site_a
    assert members(client, dev["id"])["FGT-B"]["source"] == "conflict_resolution"
    st = syslog(client, traffic("FGT-B", 4))                    # future lines route
    assert st["events_created"] == 1 and st["conflicts"] == 0


def test_add_ha_member_on_standalone_needs_mark_ha(client):
    sd_id = _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-solo",
                                                    "serial": "S-1"}), 201)["id"]
    syslog(client, traffic("S-2", 1, dev="fw-solo"))
    (g,) = _ok(client.get("/site-devices/conflicts"))["conflicts"]
    assert g["kind"] == "serial_conflict" and g["add_ha_member_needs_mark_ha"] is True
    body = {"device_key": "fw-solo", "kind": "serial_conflict", "serial": "S-2",
            "action": "add_ha_member"}
    r = client.post("/site-devices/conflicts/resolve", json=body)
    assert r.status_code == 409 and "mark_ha" in r.text
    r = _ok(client.post("/site-devices/conflicts/resolve", json={**body, "mark_ha": True}))
    assert r["replay"]["lines"] == 1
    d = get_dev(client, sd_id)
    assert d["is_ha"] is True and d["ha_mode"] is None
    assert [m["serial"] for m in d["members"]] == ["S-1", "S-2"]


def test_max_members_enforced(client, monkeypatch):
    monkeypatch.setattr(sd, "HA_MAX_MEMBERS", 2)
    dev = ha_device(client)
    syslog(client, traffic("FGT-A", 1), ha_join("FGT-A", "FGT-B"))
    st = syslog(client, ha_join("FGT-A", "FGT-C", n=2), traffic("FGT-C", 3))
    assert st["routing"]["ha_members"][0]["status"] == "refused"
    assert set(members(client, dev["id"])) == {"FGT-A", "FGT-B"}
    assert pending(client, "FGT-C", "ha_candidate") == 1
    (g,) = _ok(client.get("/site-devices/conflicts"))["conflicts"]
    assert g["add_ha_member_allowed"] is False and "maximum 2" in g["add_ha_member_hint"]
    r = client.post("/site-devices/conflicts/resolve", json={
        "device_key": "fw-ha", "kind": "ha_candidate", "serial": "FGT-C", "action": "add_ha_member"})
    assert r.status_code == 409
    r = client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-C"})
    assert r.status_code == 409 and "maximum" in r.text


def test_never_across_sites(client):
    dev = ha_device(client)                                       # fw-ha at Plant A
    other = _ok(client.post("/site-devices", json={"site": "b", "device_name": "fw-b",
                                                    "serial": "FGT-X"}), 201)
    syslog(client, traffic("FGT-A", 1))
    # an HA log naming a serial registered at Plant B does not move it
    st = syslog(client, ha_join("FGT-A", "FGT-X", n=2))
    assert st["routing"]["ha_members"][0]["status"] == "registered_elsewhere"
    assert set(members(client, dev["id"])) == {"FGT-A"}
    assert [m["serial"] for m in get_dev(client, other["id"])["members"]] == ["FGT-X"]
    r = client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-X"})
    assert r.status_code == 409 and "Plant B" in r.text
    # held lines of the peer from a Plant B upload are not replayed into Plant A
    st = syslog(client, traffic("FGT-B", 3), site="b")
    assert st["conflicts"] == 1
    st = syslog(client, ha_join("FGT-A", "FGT-B", n=4))
    assert st["routing"]["ha_members"][0]["status"] == "added"
    assert st["routing"]["ha_members"][0]["replay"] is None
    assert pending(client, "FGT-B") == 1 and events_of(client, "FGT-B") == []


def test_group_mismatch_is_not_evidence(client):
    dev = ha_device(client, gid=7)
    syslog(client, traffic("FGT-A", 1))
    st = syslog(client, ha_join("FGT-A", "FGT-B", group=9), traffic("FGT-B", 2))
    assert st["routing"]["ha_members"][0]["status"] == "group_mismatch"
    assert set(members(client, dev["id"])) == {"FGT-A"} and pending(client, "FGT-B") == 1


def test_non_ha_device_unchanged(client):
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-solo", "serial": "S-1"}), 201)
    st = syslog(client, traffic("S-1", 1, dev="fw-solo"), ha_join("S-1", "S-2", dev="fw-solo"),
                traffic("S-2", 2, dev="fw-solo"))
    r = st["routing"]
    assert r["ha_members"] == [] and r["serial_conflicts"] == 1 and r["ha_candidates"] == 0
    (g,) = _ok(client.get("/site-devices/conflicts"))["conflicts"]
    assert g["kind"] == "serial_conflict"
    # B-11 first-seen binding still applies to a serial-less device
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-new"}), 201)
    st = syslog(client, traffic("N-1", 3, dev="fw-new"))
    assert st["events_created"] == 1 and st["routing"]["serial_bindings"][0]["serial"] == "N-1"


def test_marking_ha_retags_held_serial_conflicts(client):
    syslog(client, traffic("FGT-A", 1))                            # unknown device: held
    dev = ha_device(client, mode="standalone")                     # register fw-ha, replays
    assert dev["is_ha"] is False and set(members(client, dev["id"])) == {"FGT-A"}
    syslog(client, traffic("FGT-B", 2))
    assert pending(client, "FGT-B", "serial_conflict") == 1
    r = _ok(up(client, "/ingest/fortigate-config", "ha.txt", ha_cfg(), {"site": "a"}))
    assert r["site_devices"][0]["ha"]["held_lines_retagged"] == 1
    assert pending(client, "FGT-B", "ha_candidate") == 1


# ------------------------------------------------------- manual members ----

def test_manual_preregistration_routes_and_replays(client):
    dev = ha_device(client)
    syslog(client, traffic("FGT-A", 1), traffic("FGT-B", 2))
    assert pending(client, "FGT-B", "ha_candidate") == 1
    r = _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": " FGT-B "}), 201)
    assert r["added"]["serial"] == "FGT-B" and r["added"]["source"] == "manual"
    assert r["replay"]["lines"] == 1 and r["pending_conflicts"] == 0
    assert [m["serial"] for m in r["members"]] == ["FGT-A", "FGT-B"]
    # pre-registered before any line: routes directly
    _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-C"}), 201)
    st = syslog(client, traffic("FGT-C", 3))
    assert st["events_created"] == 1 and st["conflicts"] == 0
    assert _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-C"}))["created"] is False
    audit = _ok(client.get("/site-devices/conflicts/resolutions"))
    assert {a["action"] for a in audit} == {"manual_member"}


def test_serial_registered_elsewhere_409(client):
    dev = ha_device(client)
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-z", "serial": "Z-1"}), 201)
    r = client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "Z-1"})
    assert r.status_code == 409 and "fw-z" in r.text
    assert client.post("/site-devices/99999/serials", json={"serial": "Q"}).status_code == 404
    solo = _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-s", "serial": "S-1"}), 201)
    r = client.post(f"/site-devices/{solo['id']}/serials", json={"serial": "S-2"})
    assert r.status_code == 409 and "not an HA cluster" in r.text


def test_patch_serial_refused_for_multi_member_cluster(client):
    dev = ha_device(client)
    for s in ("FGT-A", "FGT-B"):
        _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": s}), 201)
    r = client.patch(f"/site-devices/{dev['id']}", json={"serial": "FGT-Q"})
    assert r.status_code == 409 and "/serials" in r.text
    # remap moves the whole cluster (all member serials) to the new site
    r = _ok(client.patch(f"/site-devices/{dev['id']}", json={"site": "b"}))
    assert r["site_id"] == client.site_b and len(r["members"]) == 2
    st = syslog(client, traffic("FGT-B", 1))
    assert "Plant B" in st["routing"]["routed"]


def test_delete_member_serial_gated(client, monkeypatch):
    dev = ha_device(client)
    _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-A"}), 201)
    _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "FGT-B"}), 201)
    assert client.delete(f"/site-devices/{dev['id']}/serials/FGT-B").status_code == 403
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    assert client.delete(f"/site-devices/{dev['id']}/serials/NOPE").status_code == 404
    r = _ok(client.delete(f"/site-devices/{dev['id']}/serials/FGT-B"))
    assert [m["serial"] for m in r["device"]["members"]] == ["FGT-A"]
    st = syslog(client, traffic("FGT-B", 1))
    assert st["conflicts"] == 1 and pending(client, "FGT-B", "ha_candidate") == 1
    # deleting the device removes its serials (cascade)
    _ok(client.delete(f"/site-devices/{dev['id']}"))
    with client.Session() as s:
        assert s.query(SiteDeviceSerial).count() == 0


# --------------------------------------------------------------- failover --

def test_failover_finding_on_active_passive(client):
    dev = ha_device(client, mode="a-p")
    syslog(client, traffic("FGT-A", 1), ha_join("FGT-A", "FGT-B"))
    assert failovers(client) == []                       # first active member: baseline
    st = syslog(client, traffic("FGT-B", 2, hour=12), traffic("FGT-B", 3, hour=12))
    (f,) = failovers(client)
    assert f.site_id == client.site_a and f.severity == "low" and f.category == "real_time"
    assert f.detail["from_serial"] == "FGT-A" and f.detail["to_serial"] == "FGT-B"
    assert f.detail["site_device_id"] == dev["id"] and f.detail["detected_via"] == "traffic"
    assert f.id in st["finding_ids"]
    m = members(client, dev["id"])
    assert m["FGT-B"]["last_role"] == "primary" and m["FGT-A"]["last_role"] == "secondary"
    assert m["FGT-B"]["last_seen_at"]
    # local-out traffic of the passive unit is not a failover
    syslog(client, traffic("FGT-A", 4, subtype="local", hour=13))
    assert len(failovers(client)) == 1
    # HA "member state moved" log naming FGT-A primary -> failover back
    syslog(client, ha_state("FGT-B", "FGT-A", "master", hour=14))
    fs = failovers(client)
    assert len(fs) == 2 and fs[-1].detail["to_serial"] == "FGT-A"
    assert fs[-1].detail["detected_via"] == "ha_state_log"
    # an older line (out-of-order upload) of FGT-B does not flip it again
    syslog(client, traffic("FGT-B", 9, hour=8))
    assert len(failovers(client)) == 2


def test_no_failover_on_active_active_or_standalone(client):
    dev = ha_device(client, mode="a-a")
    syslog(client, traffic("FGT-A", 1), ha_join("FGT-A", "FGT-B"),
           traffic("FGT-B", 2), traffic("FGT-A", 3), traffic("FGT-B", 4))
    assert set(members(client, dev["id"])) == {"FGT-A", "FGT-B"}
    assert failovers(client) == []
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw-s", "serial": "S-1"}), 201)
    syslog(client, traffic("S-1", 5, dev="fw-s"))
    assert failovers(client) == []


# -------------------------------------------------------------- migration --

def test_offline_render_postgresql():
    pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade",
         "c4d5e6f7a8b9:d5e6f7a8b9c0", "--sql"],
        cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"))
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout
    assert "CREATE TABLE IF NOT EXISTS site_device_serials" in sql
    assert "ON DELETE CASCADE" in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_site_device_serials_serial" in sql
    assert "ALTER TABLE site_devices ADD COLUMN is_ha BOOLEAN DEFAULT false NOT NULL" in sql
    assert "ALTER TABLE site_devices DROP COLUMN IF EXISTS serial;" in sql
    assert "INSERT INTO site_device_serials" in sql


def test_revision_reruns_idempotently_with_backfill(tmp_path):
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "c4d5e6f7a8b9")
    eng = sa.create_engine(url)
    with eng.begin() as conn:
        assert "serial" in {c["name"] for c in sa.inspect(conn).get_columns("site_devices")}
        conn.execute(sa.text("INSERT INTO sites (id, name, code) VALUES (77, 'S', 's')"))
        conn.execute(sa.text(
            "INSERT INTO site_devices (site_id, device_name, serial, source, serial_source) "
            "VALUES (77, 'fw', 'SER-1', 'manual', 'first_seen')"))
    command.upgrade(cfg, "head")
    command.stamp(cfg, "c4d5e6f7a8b9")
    command.upgrade(cfg, "head")                                 # finds everything
    with eng.connect() as conn:
        rows = conn.execute(sa.text("SELECT serial, source FROM site_device_serials")).all()
        assert rows == [("SER-1", "first_seen")]
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    eng.dispose()
