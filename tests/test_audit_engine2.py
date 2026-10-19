"""Regression tests for audit findings A-12..A-17 and A-32 (findings engine:
alert_engine.py, traffic_findings.py, CHECK_TYPE_REFERENCE)."""
import glob
import logging
import os
import re
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import configure_sqlite_engine
from app.models import (
    ApprovedHost, Base, Baseline, CHECK_TYPE_REFERENCE, Finding, Firewall,
    FirewallRule, FortiAnalyzerEvent, Host, NetworkSession, ProtocolDetail,
)
import app.parsers.alert_engine as ae
import app.parsers.rule_shadow as rs
from app.parsers.traffic_findings import check_unauthorized_industrial_writes

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")


@pytest.fixture
def db():
    logging.disable(logging.CRITICAL)
    eng = configure_sqlite_engine(create_engine("sqlite://"))
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()
    eng.dispose()
    logging.disable(logging.NOTSET)


def _ev(db, **k):
    e = FortiAnalyzerEvent(source_type="api_push", **k)
    db.add(e)
    db.flush()
    return e


def _open(db, check):
    return (db.query(Finding)
            .filter(Finding.check_name == check, Finding.status.in_(("open", "acknowledged")))
            .order_by(Finding.id).all())


# ------------------------------------------------------------------ A-12 --

def _rule(db, fw, pid, port, action="accept", raw=None, dtype="fortigate"):
    r = FirewallRule(device_type=dtype, device_name=fw.name, firewall_id=fw.id,
                     policy_id=pid, action=action, enabled=True, src_zone="a",
                     dst_zone="b", src="all", dst="all", protocol="tcp",
                     dst_port=port, raw_line=raw)
    db.add(r)
    db.flush()
    return r


def _shadow_entry(a, b):
    def summ(r):
        return {"rule_id": r.id, "policy_id": r.policy_id, "device_name": r.device_name,
                "action": r.action, "src": "all", "dst": "all", "dst_port": "any"}
    return {"shadow_type": "duplicate", "shadowing_rule": summ(a), "shadowed_rule": summ(b),
            "severity": "low"}


def test_a12_same_policy_pair_on_two_firewalls_not_merged(db, monkeypatch):
    fw1, fw2 = Firewall(name="fw1"), Firewall(name="fw2")
    db.add_all([fw1, fw2]); db.flush()
    pairs = [(_rule(db, fw, "1", "any"), _rule(db, fw, "2", "any")) for fw in (fw1, fw2)]
    monkeypatch.setattr(rs, "find_shadowed_rules", lambda *a, **k: {
        "shadows": [_shadow_entry(a, b) for a, b in pairs], "devices_failed": []})
    ae.review_shadow_rules(db)
    assert len(_open(db, "shadow_rule")) == 2


def test_a12_rules_without_policy_id_not_merged(db, monkeypatch):
    fw = Firewall(name="asa1"); db.add(fw); db.flush()
    r = [_rule(db, fw, None, "any", raw=f"access-list X permit tcp any any eq {p}", dtype="cisco_asa")
         for p in (1, 2, 3, 4)]
    monkeypatch.setattr(rs, "find_shadowed_rules", lambda *a, **k: {
        "shadows": [_shadow_entry(r[0], r[1]), _shadow_entry(r[2], r[3])], "devices_failed": []})
    ae.review_shadow_rules(db)
    ae.review_shadow_rules(db)  # stable on re-run
    fs = _open(db, "shadow_rule")
    assert len(fs) == 2
    assert {f.detail["rule_key_b"] for f in fs} == {
        ae._group_rule_key(ae._rule_group_key(r[1])), ae._group_rule_key(ae._rule_group_key(r[3]))}


def test_a12_legacy_open_finding_is_adopted_not_duplicated(db, monkeypatch):
    fw = Firewall(name="fw1"); db.add(fw); db.flush()
    a, b = _rule(db, fw, "1", "any"), _rule(db, fw, "2", "any")
    legacy = ae._dedup_key("shadow_rule", {"policy_id_a": "1", "policy_id_b": "2", "dst_port": "any"})
    db.add(Finding(category="periodic_review", check_name="shadow_rule", severity="low",
                   title="old", detail={}, source_ref=legacy, status="open"))
    db.flush()
    monkeypatch.setattr(rs, "find_shadowed_rules", lambda *a_, **k: {
        "shadows": [_shadow_entry(a, b)], "devices_failed": []})
    ae.review_shadow_rules(db)
    fs = _open(db, "shadow_rule")
    assert len(fs) == 1 and fs[0].source_ref != legacy and fs[0].occurrence_count == 2


# ------------------------------------------------------------------ A-13 --

def test_a13_devices_failed_blocks_auto_resolve(db, monkeypatch):
    db.add(Finding(category="periodic_review", check_name="shadow_rule", severity="low",
                   title="x", detail={}, source_ref="deadbeef00000000", status="open"))
    db.commit()
    monkeypatch.setattr(rs, "find_shadowed_rules", lambda *a, **k: {
        "shadows": [], "devices_failed": [{"group": "device_name:fw1", "error": "boom"}]})
    ae.run_periodic_reviews(db)
    assert db.query(Finding).filter_by(source_ref="deadbeef00000000").one().status == "open"
    monkeypatch.setattr(rs, "find_shadowed_rules", lambda *a, **k: {
        "shadows": [], "devices_failed": []})
    ae.run_periodic_reviews(db)
    assert db.query(Finding).filter_by(source_ref="deadbeef00000000").one().status == "closed"


# ------------------------------------------------------------------ A-14 --

def test_a14_ips_distinct_attacks_and_severity(db):
    a = ae.evaluate_event(_ev(db, log_type="ips", src_ip="10.1.1.5", dst_ip="10.2.2.9",
                              attack_name="Port.Scan", policy_id="7", severity="low"), db)
    b = ae.evaluate_event(_ev(db, log_type="ips", src_ip="10.1.1.5", dst_ip="10.2.2.9",
                              attack_name="Modbus.Write.Exploit", policy_id="7",
                              severity="critical"), db)
    assert [f.check_name for f in a] == ["ips_ot_conduit"]
    assert [f.check_name for f in b] == ["ips_ot_conduit"]
    sev = {f.detail["attack_name"]: f.severity for f in _open(db, "ips_ot_conduit")}
    assert sev == {"Port.Scan": "low", "Modbus.Write.Exploit": "critical"}
    # no event severity -> registered default
    ae.evaluate_event(_ev(db, log_type="ips", src_ip="10.1.1.6", dst_ip="10.2.2.9",
                          attack_name="X", policy_id="7"), db)
    assert _open(db, "ips_ot_conduit")[-1].severity == CHECK_TYPE_REFERENCE["ips_ot_conduit"][2]


def test_a14_remote_access_app_per_app(db):
    for app in ("TeamViewer", "AnyDesk"):
        ae.check_remote_access_app(_ev(db, log_type="traffic", app=app, src_ip="10.0.0.1",
                                       dst_ip="1.2.3.4", policy_id="3", action="accept"), db)
    assert len(_open(db, "remote_access_app")) == 2


def test_a14_auth_non_admin_per_device_per_day(db):
    bl = Baseline(name="b", is_active=True); db.add(bl); db.flush()
    db.add(ApprovedHost(baseline_id=bl.id, ip="10.0.0.9", role="admin_ws")); db.flush()

    def login(dev, day):
        return ae.check_auth_failure(_ev(
            db, log_type="event", subtype="login", action="success", src_ip="10.0.0.50",
            device_name=dev, received_at=datetime(2026, 9, day, 10, tzinfo=timezone.utc)), db)
    assert login("fw1", 1) is not None
    assert login("fw1", 1) is None        # same day: deduped
    assert login("fw2", 1) is not None    # other device
    assert login("fw1", 2) is not None    # next day: no permanent suppression


# ------------------------------------------------------------------ A-15 --

def test_a15_login_attempt_is_not_ha_event(db):
    out = ae.evaluate_event(_ev(db, log_type="event", subtype="user", device_name="fw1",
                                raw_fields={"msg": "Administrator admin login attempt from 10.0.0.1"}), db)
    assert "ha_system_error" not in [f.check_name for f in out]


def test_a15_addr_is_not_config_change(db):
    e = _ev(db, log_type="event", subtype="system", device_name="fw1",
            raw_fields={"msg": "DHCP lease", "srcaddr": "10.0.0.1", "dstaddr": "10.0.0.2",
                        "logdesc": "IP address assigned"})
    assert ae.check_fw_config_change(e, db) is None


def test_a15_real_events_still_fire(db):
    cfg = _ev(db, log_type="event", subtype="system", device_name="fw1", action="Edit",
              raw_fields={"logid": "0100044547", "cfgpath": "firewall.policy", "msg": "Edit firewall.policy 5"})
    assert ae.check_fw_config_change(cfg, db) is not None
    cfg2 = _ev(db, log_type="event", subtype="config", device_name="fw2",
               raw_fields={"msg": "User admin added a new address object"})
    assert ae.check_fw_config_change(cfg2, db) is not None
    ha = _ev(db, log_type="event", subtype="ha", device_name="fw1",
             raw_fields={"msg": "Virtual cluster member state moved to primary"})
    assert ae.check_ha_system_error(ha, db) is not None
    fan = _ev(db, log_type="event", subtype="system", device_name="fw3",
              raw_fields={"msg": "Fan failure detected, temperature high"})
    assert ae.check_ha_system_error(fan, db) is not None
    noise = _ev(db, log_type="event", subtype="system", device_name="fw4",
                raw_fields={"msg": "powerful fanout settings attempted"})
    assert ae.check_ha_system_error(noise, db) is None


# ------------------------------------------------------------------ A-16 --

def _write_detail(db):
    c = Host(ip="10.0.0.50"); s = Host(ip="10.10.0.5")
    db.add_all([c, s]); db.flush()
    sess = NetworkSession(src_host_id=c.id, dst_host_id=s.id, src_port=40000, dst_port=502,
                          transport="tcp", protocol="modbus")
    db.add(sess); db.flush()
    db.add(ProtocolDetail(session_id=sess.id, protocol="modbus",
                          fields={"operation": "write", "summary": "write_single_register"}))
    db.flush()


def test_a16_acknowledged_is_active_and_redetected(db):
    _write_detail(db)
    assert check_unauthorized_industrial_writes(db)["findings_created"] == 1
    f = _open(db, "unauthorized_industrial_write")[0]
    f.status = "acknowledged"; db.commit()
    st = check_unauthorized_industrial_writes(db)
    assert st["findings_created"] == 0 and st["already_flagged"] == 1
    fs = db.query(Finding).filter_by(check_name="unauthorized_industrial_write").all()
    assert len(fs) == 1 and fs[0].occurrence_count == 2 and fs[0].last_seen is not None


_NAME_PATTERNS = [
    r'_make_finding\(\s*\w+,\s*"([a-z0-9_]+)"',
    r'\bcheck_name\s*=\s*"([a-z0-9_]+)"',
    r'"check_name"\s*:\s*"([a-z0-9_]+)"',
    r'\bfinding\(\s*"([a-z0-9_]+)"',
]


def test_a16_every_written_check_name_is_registered():
    names = {}
    for path in glob.glob(os.path.join(APP_DIR, "**", "*.py"), recursive=True):
        with open(path, encoding="utf-8") as fh:
            src = "\n".join(l for l in fh.read().splitlines() if not l.lstrip().startswith("#"))
        for pat in _NAME_PATTERNS:
            for m in re.finditer(pat, src):
                names.setdefault(m.group(1), path)
    assert len(names) > 60
    missing = {n: p for n, p in names.items() if n not in CHECK_TYPE_REFERENCE}
    assert not missing, missing
    assert CHECK_TYPE_REFERENCE["unauthorized_industrial_write"] == (
        "SR 2.1, SR 3.5", "8.4", "critical", "periodic_review")


# ------------------------------------------------------------------ A-17 --

def test_a17_limit_counts_flows_not_sessions(db, monkeypatch):
    src = Host(ip="10.40.0.5", purdue_level=4)
    dsts = [Host(ip=f"10.10.0.{i}", purdue_level=1) for i in range(1, 4)]
    db.add_all([src, *dsts]); db.flush()
    # many sessions of the first flow must not crowd out the others
    for _ in range(10):
        db.add(NetworkSession(src_host_id=src.id, dst_host_id=dsts[0].id, dst_port=23,
                              transport="tcp", protocol="telnet", packet_count=1))
    for d in dsts[1:]:
        db.add(NetworkSession(src_host_id=src.id, dst_host_id=d.id, dst_port=23,
                              transport="tcp", protocol="telnet", packet_count=1))
    db.flush()
    flows = list(ae._flow_sessions(db, [NetworkSession.dst_port == 23], "t"))
    assert len(flows) == 3
    assert flows[0][1] == 10
    out = ae.review_cleartext_protocols(db)
    assert len(out) == 3
    # B-06: no flow cap any more -> every flow evaluated, never incomplete
    db.info[ae._SEEN_KEY] = set()
    assert len(list(ae._flow_sessions(db, [NetworkSession.dst_port == 23], "t"))) == 3
    assert db.info.pop(ae._INCOMPLETE_KEY, None) is None
    db.info.pop(ae._SEEN_KEY)


# ------------------------------------------------------------------ A-32 --

def test_a32_concurrent_run_is_skipped(db):
    assert ae._REVIEW_RUN_LOCK.acquire(blocking=False)
    try:
        stats = ae.run_periodic_reviews(db)
    finally:
        ae._REVIEW_RUN_LOCK.release()
    assert stats == {ae.REVIEW_SKIPPED_STAT: 0}
    assert sum(stats.values()) == 0
    assert ae._review_run_skipped(db)
    stats = ae.run_periodic_reviews(db)
    assert ae.REVIEW_SKIPPED_STAT not in stats and not ae._review_run_skipped(db)
    assert not ae._REVIEW_RUN_LOCK.locked()
