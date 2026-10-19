"""
Phase 2 of docs/access-path-review.md: traffic overlay on GET /access-paths
(seen / not_seen / no_capture, rule hits, unexplained crossing flows) and the
composed conduit_through_dmz rows deferred from phase 1.

Fixture pattern as tests/test_access_paths.py (in-memory SQLite +
ingest_fortigate_config); sessions and FAZ events are inserted directly.
Built on the PLANT1-FGT tabletop scenario.
"""
import textwrap
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import insert

from app.models import FortiAnalyzerEvent, Host, NetworkSession
from app.parsers.access_paths import enumerate_access_paths
from tests.test_access_paths import (  # noqa: F401  (db fixture re-used)
    PLANT1_CFG, PLANT1_LEVELS, _ingest, _site, db,
)

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)

HISTORIAN, RELAY, PLC, HMI_VIP, FIELD, OT_L3 = (
    "10.10.5.10", "10.40.0.10", "10.30.0.100", "10.30.0.50", "10.60.0.5", "10.20.0.9")
HOST_LEVELS = {HISTORIAN: 4, RELAY: 3.5, PLC: 2, HMI_VIP: 2, FIELD: 0, OT_L3: 3}


def _host(db, sid, ip, level):
    h = db.query(Host).filter(Host.ip == ip, Host.site_id == sid).first()
    if h is None:
        h = Host(ip=ip, site_id=sid, sources=["test"])
        db.add(h)
    h.purdue_level = level
    db.flush()
    return h


def _plant(db, name="Plant 1", fw="PLANT1-FGT"):
    sid = _site(db, name)
    _ingest(db, PLANT1_CFG, fw, sid, PLANT1_LEVELS)
    hosts = {ip: _host(db, sid, ip, lv) for ip, lv in HOST_LEVELS.items()}
    db.commit()
    return sid, hosts


def _sess(db, src, dst, sport, dport, transport="tcp", seen=T0):
    db.add(NetworkSession(src_host_id=src.id, dst_host_id=dst.id, src_port=sport,
                          dst_port=dport, transport=transport, protocol="unknown",
                          packet_count=4, first_seen=seen, last_seen=seen))


def _event(db, sid, policy_id, device="PLANT1-FGT", action="accept", ts=T0):
    db.add(FortiAnalyzerEvent(source_type="syslog_cef", vendor="fortinet", device_name=device,
                              log_type="traffic", action=action, policy_id=policy_id,
                              src_ip=HISTORIAN, dst_ip=RELAY, dst_port=443,
                              event_time=ts, site_id=sid))


def _by_pid(paths, pid):
    """The single-chain row whose (only) policy is ``pid``."""
    rows = [p for p in paths if p["direction"] != "composed"
            and [c["policy_id"] for c in p["chain"]] == [pid]]
    assert len(rows) == 1, (pid, rows)
    return rows[0]


def _composed(paths):
    return [p for p in paths if p["direction"] == "composed"]


# ================================================================= traffic ==
def test_session_makes_row_seen_either_orientation(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[PLC], 50123, 502)
    # same logical flow captured server-first: canonical_flow re-orients it
    _sess(db, h[PLC], h[HISTORIAN], 502, 50999, seen=T0 + timedelta(hours=1))
    db.commit()
    out = enumerate_access_paths(db, sid)
    bypass = _by_pid(out["paths"], "6")["traffic"]
    assert bypass["status"] == "seen"
    assert bypass["sessions"] == 2
    assert bypass["last_seen"].startswith("2026-10-01T13:00")
    assert bypass["rule_hits"] == 0
    # the site has a capture, but nothing on #5 -> not_seen (not no_capture)
    assert _by_pid(out["paths"], "5")["traffic"]["status"] == "not_seen"
    assert out["unmatched_total"] == 0


def test_overlapping_policies_do_not_double_count(db):
    sid = _site(db, "Overlap")
    cfg = PLANT1_CFG.replace('''    edit 5
        set name "remote-hmi-vip"''', '''    edit 50
        set name "broad-modbus-first"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "MODBUS"
    next
    edit 5
        set name "remote-hmi-vip"''')
    _ingest(db, cfg, "PLANT1-FGT", sid, PLANT1_LEVELS)
    h = {ip: _host(db, sid, ip, lv) for ip, lv in HOST_LEVELS.items()}
    _sess(db, h[HISTORIAN], h[PLC], 40000, 502)
    db.commit()
    paths = enumerate_access_paths(db, sid)["paths"]
    broad, narrow = _by_pid(paths, "50"), _by_pid(paths, "6")
    # both rows carry the flow on paper; first-match (#50 precedes #6) wins
    assert broad["traffic"]["sessions"] == 1
    assert narrow["traffic"]["sessions"] == 0
    assert sum((p["traffic"]["sessions"] or 0) for p in paths
               if p["direction"] != "composed") == 1


def test_rule_hits_without_sessions(db):
    sid, _h = _plant(db)
    _event(db, sid, "1")
    _event(db, sid, "1", ts=T0 + timedelta(minutes=5))
    db.commit()
    paths = enumerate_access_paths(db, sid)["paths"]
    hist = _by_pid(paths, "1")["traffic"]
    assert hist["status"] == "seen"
    assert hist["sessions"] == 0 and hist["rule_hits"] == 2
    assert hist["last_matched"] is not None
    # same firewall has hit data, #2 had none -> not_seen
    assert _by_pid(paths, "2")["traffic"]["status"] == "not_seen"


def test_no_traffic_at_all_is_no_capture_not_not_seen(db):
    sid, h = _plant(db)
    paths = enumerate_access_paths(db, sid)["paths"]
    assert paths and {p["traffic"]["status"] for p in paths} == {"no_capture"}
    # one session anywhere in the site turns silent paths into "not_seen"
    _sess(db, h[HISTORIAN], h[PLC], 40000, 502)
    db.commit()
    paths = enumerate_access_paths(db, sid)["paths"]
    assert _by_pid(paths, "9")["traffic"]["status"] == "not_seen"


def test_deny_event_counts_as_firewall_data_but_not_a_hit(db):
    sid, _h = _plant(db)
    _event(db, sid, "7", action="deny")
    db.commit()
    paths = enumerate_access_paths(db, sid)["paths"]
    row = _by_pid(paths, "6")["traffic"]
    assert row["rule_hits"] == 0 and row["status"] == "not_seen"


# =============================================================== unmatched ==
def test_crossing_session_without_permit_is_unmatched(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[FIELD], 41000, 502)       # L4 -> L0: no permit
    _sess(db, h[HISTORIAN], h[FIELD], 41001, 502)
    _sess(db, h[HISTORIAN], h[PLC], 41002, 502)         # explained by #6
    db.commit()
    out = enumerate_access_paths(db, sid)
    assert out["unmatched_total"] == 1 and out["counts"]["unmatched_total"] == 1
    flow = out["unmatched_observed"][0]
    assert flow["client"] == {"ip": HISTORIAN, "level": 4}
    assert flow["server"] == {"ip": FIELD, "level": 0, "port": 502}
    assert flow["direction"] == "down" and flow["sessions"] == 2
    assert "it_ot_bypass" in flow["flags"]
    assert "industrial_proto_out_of_zone" in flow["flags"]
    # excluded on request
    off = enumerate_access_paths(db, sid, include_unmatched=False)
    assert "unmatched_observed" not in off


def test_wrong_port_is_unmatched_not_attributed(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[PLC], 41000, 22)          # #6 allows 502 only
    db.commit()
    out = enumerate_access_paths(db, sid)
    assert _by_pid(out["paths"], "6")["traffic"]["sessions"] == 0
    assert [f["server"]["port"] for f in out["unmatched_observed"]] == [22]


# ================================================================ composed ==
def test_composed_historian_conduit_through_specific_host(db):
    sid, _h = _plant(db)
    comp = _composed(enumerate_access_paths(db, sid)["paths"])
    assert len(comp) == 1
    row = comp[0]
    assert row["pivot"] == {"ip": RELAY, "level": 3.5}
    assert [c["policy_id"] for c in row["chain"]] == ["1", "2"]
    assert row["src"]["level"] == 4 and row["dst"]["level"] == 2
    assert "conduit_through_dmz" in row["flags"]
    assert "it_ot_bypass" not in row["flags"]
    assert row["service"] == ["tcp/502"]


def test_composed_never_through_all_scope(db):
    sid = _site(db, "Any pivot")
    # leg 1 delivers to dstaddr all: no specific pivot host -> no join
    cfg = PLANT1_CFG.replace('''        set srcaddr "historian"
        set dstaddr "dmz-relay"''', '''        set srcaddr "historian"
        set dstaddr "all"''')
    _ingest(db, cfg, "PLANT1-FGT", sid, PLANT1_LEVELS)
    assert _composed(enumerate_access_paths(db, sid)["paths"]) == []


def test_composed_seen_requires_both_legs(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[RELAY], 52000, 443)        # leg 1 only
    db.commit()
    comp = _composed(enumerate_access_paths(db, sid)["paths"])[0]["traffic"]
    assert comp["status"] == "partial"
    assert [leg["status"] for leg in comp["by_leg"]] == ["seen", "not_seen"]
    _sess(db, h[RELAY], h[PLC], 52001, 502)              # leg 2 too
    db.commit()
    comp = _composed(enumerate_access_paths(db, sid)["paths"])[0]["traffic"]
    assert comp["status"] == "seen" and comp["sessions"] == 1


def test_composed_rows_count_toward_budget(db, monkeypatch):
    sid, _h = _plant(db)
    n = len([p for p in enumerate_access_paths(db, sid)["paths"]
             if p["direction"] != "composed"])
    monkeypatch.setenv("IACS_MAX_ACCESS_PATH_ROWS", str(n + 1))
    out = enumerate_access_paths(db, sid)
    assert len(out["paths"]) == n + 1 and out["truncated"] is True
    assert out["unmatched_incomplete"] is True


# ================================================================== sites ==
def test_two_sites_overlay_isolated(db):
    sid_a, ha = _plant(db, "Plant A", "PLANT1-FGT")
    sid_b, hb = _plant(db, "Plant B", "PLANT1-FGT")
    _sess(db, ha[HISTORIAN], ha[PLC], 40000, 502)
    _sess(db, ha[HISTORIAN], ha[FIELD], 40001, 502)
    _event(db, sid_a, "1")
    db.commit()
    a = enumerate_access_paths(db, sid_a)
    b = enumerate_access_paths(db, sid_b)
    assert _by_pid(a["paths"], "6")["traffic"]["sessions"] == 1
    assert _by_pid(a["paths"], "1")["traffic"]["rule_hits"] == 1
    assert a["unmatched_total"] == 1
    # site B has the same IPs, names and policies but no traffic of its own
    assert {p["traffic"]["status"] for p in b["paths"]} == {"no_capture"}
    assert b["unmatched_total"] == 0


# ============================================================ performance ==
def test_overlay_200k_sessions_is_fast(db):
    sid, h = _plant(db)
    flows = [(h[HISTORIAN].id, h[PLC].id, 502), (h[HISTORIAN].id, h[RELAY].id, 443),
             (h[RELAY].id, h[PLC].id, 502), (h[HISTORIAN].id, h[FIELD].id, 502),
             (h[PLC].id, h[FIELD].id, 502)]
    n = 200_000
    rows = []
    for i in range(n):
        s, d, port = flows[i % len(flows)]
        rows.append({"src_host_id": s, "dst_host_id": d, "src_port": 1025 + i // len(flows),
                     "dst_port": port, "transport": "tcp", "protocol": "unknown",
                     "packet_count": 1, "first_seen": T0, "last_seen": T0})
    db.execute(insert(NetworkSession), rows)
    db.commit()
    t = time.perf_counter()
    out = enumerate_access_paths(db, sid)
    elapsed = time.perf_counter() - t
    per = n // len(flows)
    assert _by_pid(out["paths"], "6")["traffic"]["sessions"] == per
    assert _by_pid(out["paths"], "1")["traffic"]["sessions"] == per
    assert _by_pid(out["paths"], "2")["traffic"]["sessions"] == per
    # HISTORIAN->FIELD and PLC(L2)->FIELD(L0) have no permit (#8/#9 are
    # L2->L1 / L1->L0): both unexplained
    assert out["unmatched_sessions"] == 2 * per
    assert elapsed < 20, f"overlay of {n} sessions took {elapsed:.1f}s"


# =============================================================== endpoint ==
def test_endpoint_traffic_filter_and_counts(tmp_path, monkeypatch):
    import app.main as main_mod
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.db import Base as DBase, get_db, make_engine

    engine = make_engine(f"sqlite:///{tmp_path / 'ov.db'}")
    DBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    try:
        s = Session()
        _sid, h = _plant(s)
        _sess(s, h[HISTORIAN], h[PLC], 40000, 502)
        _sess(s, h[HISTORIAN], h[FIELD], 40001, 502)
        s.commit()
        s.close()
        c = TestClient(main_mod.app)
        j = c.get("/access-paths").json()
        assert j["counts"]["by_traffic"]["seen"] >= 1
        assert j["counts"]["unmatched_total"] == 1
        obs = c.get("/access-paths", params={"traffic": "seen"}).json()
        assert obs["paths"] and all(p["traffic"]["status"] == "seen" for p in obs["paths"])
        assert c.get("/access-paths", params={"traffic": "observed"}).status_code == 422
        nu = c.get("/access-paths", params={"include_unmatched": "false"}).json()
        assert "unmatched_observed" not in nu
    finally:
        main_mod.app.dependency_overrides.pop(get_db, None)
        engine.dispose()
