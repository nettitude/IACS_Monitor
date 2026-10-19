"""
Audit batch C - device registry (app/site_devices.py + the /site-devices
route handlers).  Regression tests for the "never guess a site" findings:

* C-06 - an ambiguous (same name at >1 site) name-only held line is NOT
  replayed into a site by an unrelated create/update; a unique-name mapping
  still replays.
* C-07 - HA evidence is not spoofable: a log's hostname must name the logging
  device, the device's HA group must match (absent group is not evidence),
  and a serial a line just first-sight bound cannot vouch for a peer in the
  same line.
* C-11 - an out-of-order 37892 state log does not raise a false failover; a
  second same-name row is refused for a full HA cluster.
* C-16 - an over-long devid / devname is held as malformed, never routed
  (no DataError / 500, nothing misidentified).

Opts out of the conftest auto-site: every upload names its site (or none).
"""
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app import site_devices as sd
from app.db import Base, get_db
from app.models import Finding, FortiAnalyzerEvent, SiteDevice, UnmappedLogEvent

pytestmark = pytest.mark.no_auto_site

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CFG = (ROOT / "sample_data" / "sample_fortigate_config.txt").read_text()


# ------------------------------------------------------------- harness -----

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


def syslog(c, *lines, **params):
    return _ok(up(c, "/ingest/forti-syslog", "x.log", "\n".join(lines) + "\n", params))["stats"]


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "auditc.db") as c:
        _ok(c.get("/sites"))
        c.site_a = _ok(c.post("/sites", json={"name": "Plant A", "code": "a"}), 201)["id"]
        c.site_b = _ok(c.post("/sites", json={"name": "Plant B", "code": "b"}), 201)["id"]
        yield c


# -------------------------------------------------------- log line builders

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


def traffic(serial, n=1, dev="FW-HA", subtype="forward", hour=10):
    return (f'date=2026-10-01 time={hour:02d}:00:{n:02d} devname="{dev}" devid="{serial}" '
            f'logid="0000000013" type="traffic" subtype="{subtype}" srcip=10.0.1.{20 + n} '
            f'dstip=10.0.1.10 srcport={50000 + n} dstport=502 proto=6 action="accept" '
            f'policyid=7 service="MODBUS"')


def ha_evt(logid, logger, sn, dev="FW-HA", group=None, hostname=None, role=None, n=1, hour=9):
    """A FortiOS HA event log (37892 / 37894) with fully controlled fields."""
    parts = [f'date=2026-10-01 time={hour:02d}:30:{n:02d}', f'devname="{dev}"',
             f'devid="{logger}"', f'logid="{logid}"', 'type="event"', 'subtype="ha"',
             f'sn="{sn}"', 'vcluster=1']
    if group is not None:
        parts.append(f"ha_group={group}")
    if hostname is not None:
        parts.append(f'hostname="{hostname}"')
    if role is not None:
        parts.append(f'ha_role="{role}"')
    return " ".join(parts)


JOIN = "0108037894"
STATE = "0108037892"


def ha_cfg(host="FW-HA", mode="a-p", group="plant-a-ha", gid=7):
    text = SAMPLE_CFG.replace("set hostname FG-OT-PERIMETER-01", f"set hostname {host}")
    start = text.index("config system ha")
    end = text.index("end", start) + 3
    body = [f"    set mode {mode}"] if mode else []
    if group:
        body.append(f'    set group-name "{group}"')
    if gid is not None:
        body.append(f"    set group-id {gid}")
    return text[:start] + "config system ha\n" + "\n".join(body) + "\nend" + text[end:]


def ha_device(c, site="a", **kw):
    r = _ok(up(c, "/ingest/fortigate-config", "ha.txt", ha_cfg(**kw), {"site": site}))
    (dev,) = r["site_devices"]
    return dev


# ------------------------------------------------------------ helpers ------

def device_ids(c, name):
    with c.Session() as s:
        return [d.id for d in s.query(SiteDevice).filter(SiteDevice.device_name == name).all()]


def members(c, dev_id):
    return {m["serial"] for m in next(d for d in _ok(c.get("/site-devices")) if d["id"] == dev_id)["members"]}


def add_serial(c, dev_id, serial, code=201):
    return _ok(c.post(f"/site-devices/{dev_id}/serials", json={"serial": serial}), code)


def pending_rows(c, **filt):
    with c.Session() as s:
        q = s.query(UnmappedLogEvent).filter_by(status="pending", **filt)
        return q.all()


def n_events(c):
    with c.Session() as s:
        return s.query(FortiAnalyzerEvent).count()


def failovers(c):
    with c.Session() as s:
        return s.query(Finding).filter_by(check_name="ha_failover").all()


# =============================================================== C-06 ======
# An ambiguous name-only held line is never auto-replayed into a site.

def _ambiguous_fw(client):
    """fw at BOTH sites (distinct serials) -> the name 'fw' is ambiguous."""
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw", "serial": "S-A"}), 201)
    _ok(client.post("/site-devices", json={"site": "b", "device_name": "fw", "serial": "S-B"}), 201)


def test_c06_noop_post_does_not_replay_ambiguous_name_only_line(client):
    _ambiguous_fw(client)
    # a devname-only line (no serial) for an ambiguous name is held unmapped
    st = syslog(client, cfg_change(dev="fw", n=1))
    assert st["unmapped"] == 1 and st["events_created"] == 0
    held = pending_rows(client, kind="unmapped", device_key="fw")
    assert len(held) == 1 and held[0].serial is None

    # a no-op POST (device already mapped here, nothing changes) must NOT
    # replay the held serial-less line into site A - that would guess a site.
    out = _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw"}))
    assert out["status"] == "unchanged" and out["replay"]["lines"] == 0
    assert n_events(client) == 0
    assert len(pending_rows(client, kind="unmapped", device_key="fw")) == 1


def test_c06_patch_vendor_does_not_replay_ambiguous_name_only_line(client):
    _ambiguous_fw(client)
    syslog(client, cfg_change(dev="fw", n=1))
    (fw_a,) = [d for d in device_ids(client, "fw")
               if next(x for x in _ok(client.get("/site-devices")) if x["id"] == d)["site"] == "Plant A"]
    # PATCH touching only the vendor must not drag the held serial-less line
    out = _ok(client.patch(f"/site-devices/{fw_a}", json={"vendor": "fortinet"}))
    assert out["replay"]["lines"] == 0
    assert n_events(client) == 0
    assert len(pending_rows(client, kind="unmapped", device_key="fw")) == 1


def test_c06_unique_name_mapping_still_replays(client):
    # 'lonely' is registered nowhere: its line is held unmapped
    st = syslog(client, cfg_change(dev="lonely", n=1))
    assert st["unmapped"] == 1
    # mapping it (unique name) DOES replay the held line into the chosen site
    out = _ok(client.post("/site-devices", json={"site": "a", "device_name": "lonely"}), 201)
    assert out["status"] == "created" and out["replay"]["lines"] == 1
    assert out["replay"]["events_created"] == 1
    assert len(pending_rows(client, kind="unmapped", device_key="lonely")) == 0
    with client.Session() as s:
        assert {e.site_id for e in s.query(FortiAnalyzerEvent)} == {client.site_a}


# =============================================================== C-07 ======
# HA evidence is not spoofable / misattributed.

def test_c07a_hostname_must_name_the_logging_device(client):
    dev = ha_device(client, gid=None)            # HA, group unknown (isolate hostname)
    add_serial(client, dev["id"], "MEMBER-A")    # a known member to log evidence
    # a join whose hostname names ANOTHER device is not evidence
    st = syslog(client, ha_evt(JOIN, "MEMBER-A", "SPOOF", hostname="SOMEONE-ELSE"))
    assert st["routing"]["ha_members"][0]["status"] == "hostname_mismatch"
    assert members(client, dev["id"]) == {"MEMBER-A"}
    # the matching hostname is genuine evidence
    st = syslog(client, ha_evt(JOIN, "MEMBER-A", "REAL", hostname="FW-HA", n=2))
    assert st["routing"]["ha_members"][0]["status"] == "added"
    assert members(client, dev["id"]) == {"MEMBER-A", "REAL"}


def test_c07b_absent_or_wrong_group_is_not_evidence(client):
    dev = ha_device(client, gid=7)               # HA group is known (7)
    add_serial(client, dev["id"], "MEMBER-A")
    # a join that omits ha_group is NOT evidence when the group is known
    st = syslog(client, ha_evt(JOIN, "MEMBER-A", "NOGRP"))
    assert st["routing"]["ha_members"][0]["status"] == "group_mismatch"
    assert members(client, dev["id"]) == {"MEMBER-A"}
    # a join carrying another group is not evidence either
    st = syslog(client, ha_evt(JOIN, "MEMBER-A", "OTHGRP", group=9, n=2))
    assert st["routing"]["ha_members"][0]["status"] == "group_mismatch"
    assert members(client, dev["id"]) == {"MEMBER-A"}
    # the matching group is genuine evidence
    st = syslog(client, ha_evt(JOIN, "MEMBER-A", "RIGHT", group=7, n=3))
    assert st["routing"]["ha_members"][0]["status"] == "added"
    assert members(client, dev["id"]) == {"MEMBER-A", "RIGHT"}


def test_c07c_first_sight_bind_line_cannot_vouch_for_a_peer(client):
    dev = ha_device(client, gid=None)            # HA, no serials yet
    assert members(client, dev["id"]) == set()
    # ONE line both first-sight binds its own devid AND names a peer; the
    # peer must NOT be added off a serial that this very line just bound.
    st = syslog(client, ha_evt(JOIN, "EVIL", "VICTIM", hostname="FW-HA"))
    assert st["routing"]["ha_members"] == []     # nothing added as evidence
    assert members(client, dev["id"]) == {"EVIL"}   # only the first-sight bind
    assert "VICTIM" not in members(client, dev["id"])
    # a LATER line from the now-known member may legitimately add a peer
    st = syslog(client, ha_evt(JOIN, "EVIL", "PEER", hostname="FW-HA", n=2))
    assert st["routing"]["ha_members"][0]["status"] == "added"
    assert members(client, dev["id"]) == {"EVIL", "PEER"}


# =============================================================== C-11 ======

def test_c11a_out_of_order_state_log_is_not_a_false_failover(client):
    dev = ha_device(client, mode="a-p", gid=7)
    add_serial(client, dev["id"], "FGT-A")
    add_serial(client, dev["id"], "FGT-B")
    syslog(client, traffic("FGT-A", 1, hour=10))        # baseline primary
    assert failovers(client) == []
    syslog(client, traffic("FGT-B", 2, hour=12))        # genuine failover -> FGT-B
    assert len(failovers(client)) == 1
    # an OLDER "member master" state log for FGT-A arriving late must not
    # flip the active member backward (last-write-wins by the log's time).
    syslog(client, ha_evt(STATE, "FGT-A", "FGT-A", role="master", hostname="FW-HA",
                          group=7, hour=8))
    assert len(failovers(client)) == 1                  # still just the one


def test_c11b_second_same_name_row_refused_for_full_cluster(client, monkeypatch):
    monkeypatch.setattr(sd, "HA_MAX_MEMBERS", 2)
    dev = ha_device(client, mode="a-p", gid=7)
    add_serial(client, dev["id"], "S1")
    add_serial(client, dev["id"], "S2")                 # cluster now full (max 2)
    assert members(client, dev["id"]) == {"S1", "S2"}
    # POST a THIRD serial under the same name must not spawn a second row
    r = client.post("/site-devices", json={"site": "a", "device_name": "fw-ha", "serial": "S3"})
    assert r.status_code == 409 and "maximum" in r.text.lower()
    assert device_ids(client, "fw-ha") == [dev["id"]]   # exactly one row
    assert members(client, dev["id"]) == {"S1", "S2"}


# =============================================================== C-16 ======

def test_c16_over_long_serial_is_held_malformed_not_500(client):
    _ok(client.post("/site-devices", json={"site": "a", "device_name": "fw", "serial": "S-OK"}), 201)
    long_serial = "F" * 300                              # > 128 (String(128))
    st = syslog(client, cfg_change(dev="fw", serial=long_serial, n=1))
    assert st["unmapped"] == 1 and st["events_created"] == 0
    rows = pending_rows(client, device_key=sd.MALFORMED_KEY)
    assert len(rows) == 1 and rows[0].serial is None
    assert n_events(client) == 0
    # nothing was misidentified: the real device is untouched
    assert members(client, device_ids(client, "fw")[0]) == {"S-OK"}


def test_c16_over_long_devname_is_held_malformed(client):
    long_name = "n" * 300                                # > 255 (String(255))
    st = syslog(client, cfg_change(dev=long_name, serial="S-X", n=1))
    assert st["unmapped"] == 1 and st["events_created"] == 0
    rows = pending_rows(client, device_key=sd.MALFORMED_KEY)
    assert len(rows) == 1
    assert device_ids(client, long_name.lower()) == []   # no device registered
    assert n_events(client) == 0
