"""
Analysis-engine audit remediations (stream C). Regression tests for:

  C-01  session orientation no longer splits one logical flow into several
        findings, and pcap findings share identity with the real-time FAZ
        finding (shared canonical (client, server, server_port)).
  C-08  session_no_permitting_rule marks the review incomplete (no per-flow
        storm) when a site has NO firewall policy loaded at all.
  C-11  ha_failover dedup incorporates site_device_id + to_serial, not just
        the window hour.
  C-14  auth_failure dedup incorporates `user`; _redetected merges evidence
        instead of overwriting it.
  C-15  FAZ per-flow suppression windows on event_time (coalesced with
        received_at), so a bulk upload of stale events cannot suppress a
        current pcap finding.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import (
    Finding, FortiAnalyzerEvent, Host, NetworkSession, Firewall, FirewallRule,
)
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import (
    _dedup_key, _make_finding, _redetected, check_auth_failure,
    review_ns_it_ot_bypass, review_session_no_permitting_rule,
)
from app.parsers.traffic_findings import canonical_flow


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def _host(db, ip, level=None):
    h = Host(ip=ip, purdue_level=level)
    db.add(h)
    db.flush()
    return h


def _sess(db, src_host, src_port, dst_host, dst_port, transport="tcp"):
    ns = NetworkSession(src_host_id=src_host.id, dst_host_id=dst_host.id,
                        src_port=src_port, dst_port=dst_port, transport=transport,
                        protocol="unknown", packet_count=5)
    db.add(ns)
    db.flush()
    return ns


def _rt_bypass_finding(db, src_ip, dst_ip, dst_port):
    """A real-time it_ot_bypass finding, as the FAZ path would create."""
    f = Finding(category="real_time", check_name="it_ot_bypass", severity="critical",
                status="open", isa62443_sr="SR 5.2", checklist_id="2.1, 2.2",
                title="rt bypass", source_ref=f"rt:{src_ip}:{dst_ip}:{dst_port}",
                detail={"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})
    db.add(f)
    db.flush()
    return f


def _faz_traffic(db, src_ip, dst_ip, dst_port, *, event_time, received_at,
                 action="accept", protocol="tcp"):
    ev = FortiAnalyzerEvent(source_type="syslog_cef", log_type="traffic",
                            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                            action=action, protocol=protocol,
                            event_time=event_time, received_at=received_at)
    db.add(ev)
    db.flush()
    return ev


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check,
                                    Finding.status == "open").all()


# --------------------------------------------------------------------------- C-01
def test_canonical_flow_orientation_and_server_port():
    # Normal orientation: ephemeral client -> well-known server.
    assert canonical_flow("IT", 50001, "OT", 502) == ("IT", "OT", 502)
    # Reversed capture (server packet seen first): same canonical identity.
    assert canonical_flow("OT", 502, "IT", 50001) == ("IT", "OT", 502)
    # A lone ephemeral source port must NOT masquerade as the server.
    assert canonical_flow("A", 50001, "B", None) == ("A", "B", None)
    # Registered (non-privileged) server port, reversed: lower port wins.
    assert canonical_flow("DB", 1433, "C", 50007) == ("C", "DB", 1433)


def test_three_captures_of_one_flow_dedup_to_one_finding(db):
    it = _host(db, "10.3.0.5", level=3)     # IT / operations
    ot = _host(db, "10.0.0.9", level=0)     # field device
    # Same logical IT->OT:502 flow, captured 3x mid-stream (server packet
    # first), each with a different ephemeral client port.
    for cport in (50001, 50002, 50003):
        _sess(db, ot, 502, it, cport)
    db.commit()
    out = review_ns_it_ot_bypass(db)
    assert len(out) == 1
    f = out[0]
    # Keyed on the canonical server identity, and displayed IT->OT correctly.
    assert (f.detail["it_host_ip"], f.detail["ot_host_ip"]) == ("10.3.0.5", "10.0.0.9")
    assert f.occurrence_count == 3        # the other two re-detected the same finding


def test_matching_faz_event_suppresses_pcap_finding(db):
    it = _host(db, "10.3.0.5", level=3)
    ot = _host(db, "10.0.0.9", level=0)
    _sess(db, ot, 502, it, 50001)         # reversed capture of IT->OT:502
    # Real-time FAZ finding + a recent permitted FAZ traffic event for the
    # SAME logical flow, keyed on the server port (:502).
    _rt_bypass_finding(db, "10.3.0.5", "10.0.0.9", 502)
    now = datetime.now(timezone.utc)
    _faz_traffic(db, "10.3.0.5", "10.0.0.9", 502, event_time=now, received_at=now)
    db.commit()
    out = review_ns_it_ot_bypass(db)
    assert out == []                      # suppressed by the FAZ counterpart


def test_genuinely_different_flow_still_reported(db):
    it = _host(db, "10.3.0.5", level=3)
    ot = _host(db, "10.0.0.9", level=0)
    other_it = _host(db, "10.3.0.6", level=3)
    _sess(db, ot, 502, it, 50001)         # covered flow
    _rt_bypass_finding(db, "10.3.0.5", "10.0.0.9", 502)
    now = datetime.now(timezone.utc)
    _faz_traffic(db, "10.3.0.5", "10.0.0.9", 502, event_time=now, received_at=now)
    _sess(db, other_it, 50010, ot, 502)   # a DIFFERENT client -> same OT:502
    db.commit()
    out = review_ns_it_ot_bypass(db)
    assert len(out) == 1
    assert out[0].detail["it_host_ip"] == "10.3.0.6"


# --------------------------------------------------------------------------- C-15
def test_stale_faz_event_does_not_suppress_current_finding(db):
    it = _host(db, "10.3.0.5", level=3)
    ot = _host(db, "10.0.0.9", level=0)
    _sess(db, ot, 502, it, 50001)
    _rt_bypass_finding(db, "10.3.0.5", "10.0.0.9", 502)
    now = datetime.now(timezone.utc)
    # Uploaded now, but the traffic HAPPENED 10 days ago -> outside the window.
    _faz_traffic(db, "10.3.0.5", "10.0.0.9", 502,
                 event_time=now - timedelta(days=10), received_at=now)
    db.commit()
    out = review_ns_it_ot_bypass(db)
    assert len(out) == 1                  # NOT suppressed by a stale event


def test_recent_faz_event_still_suppresses(db):
    it = _host(db, "10.3.0.5", level=3)
    ot = _host(db, "10.0.0.9", level=0)
    _sess(db, ot, 502, it, 50001)
    _rt_bypass_finding(db, "10.3.0.5", "10.0.0.9", 502)
    now = datetime.now(timezone.utc)
    _faz_traffic(db, "10.3.0.5", "10.0.0.9", 502,
                 event_time=now - timedelta(hours=1), received_at=now)
    db.commit()
    assert review_ns_it_ot_bypass(db) == []


# --------------------------------------------------------------------------- C-08
def test_no_firewall_policy_marks_incomplete_and_emits_nothing(db):
    _sess(db, _host(db, "10.0.1.5", 3), 50001, _host(db, "10.0.2.9", 1), 23)
    db.commit()
    db.info[ae._SEEN_KEY] = set()         # as run_periodic_reviews would
    out = review_session_no_permitting_rule(db)
    assert out == []
    assert db.info.get(ae._INCOMPLETE_KEY) == "no firewall policy loaded"


def test_with_firewall_policy_behaviour_unchanged(db):
    fw = Firewall(name="FW", device_name="FW", vendor="fortigate")
    db.add(fw)
    db.flush()
    # A policy exists but does not permit this flow.
    db.add(FirewallRule(firewall_id=fw.id, device_name="FW", device_type="fortigate",
                        policy_id="1", src="10.9.9.0/24", dst="10.8.8.0/24",
                        protocol="tcp", dst_port="443", action="accept", enabled=True))
    _sess(db, _host(db, "10.0.1.5", 3), 50001, _host(db, "10.0.2.9", 1), 23)
    db.commit()
    db.info[ae._SEEN_KEY] = set()
    out = review_session_no_permitting_rule(db)
    assert len(out) == 1
    assert ae._INCOMPLETE_KEY not in db.info


# --------------------------------------------------------------------------- C-11
def test_ha_failover_dedup_keys_distinguish_direction_and_cluster():
    base = {"site_device_id": 1, "to_serial": "FGT-B", "window_hour": "2026-10-04T12"}
    # SA->SB vs SB->SA in the same hour on the same cluster: different serial.
    reverse = {**base, "to_serial": "FGT-A"}
    assert _dedup_key("ha_failover", base) != _dedup_key("ha_failover", reverse)
    # Two different clusters in the same hour: different site_device_id.
    other_cluster = {**base, "site_device_id": 2}
    assert _dedup_key("ha_failover", base) != _dedup_key("ha_failover", other_cluster)


def test_ha_failover_two_findings_in_one_hour(db):
    common = dict(device_name="fw", ha_mode="a-p", ha_group_name="g")
    win = "2026-10-04T12"
    f1 = _make_finding(db, "ha_failover", "A->B", "t",
                       {**common, "from_serial": "A", "to_serial": "B"},
                       dedup_evidence={"site_device_id": 1, "to_serial": "B", "window_hour": win})
    f2 = _make_finding(db, "ha_failover", "B->A", "t",
                       {**common, "from_serial": "B", "to_serial": "A"},
                       dedup_evidence={"site_device_id": 1, "to_serial": "A", "window_hour": win})
    assert f1 is not None and f2 is not None
    assert f1.source_ref != f2.source_ref
    # A different cluster in the same hour is also distinct.
    f3 = _make_finding(db, "ha_failover", "A->B@2", "t",
                       {**common, "from_serial": "A", "to_serial": "B"},
                       dedup_evidence={"site_device_id": 2, "to_serial": "B", "window_hour": win})
    assert f3 is not None and f3.source_ref not in (f1.source_ref, f2.source_ref)


# --------------------------------------------------------------------------- C-14
def _login_fail(db, src_ip, user, when):
    ev = FortiAnalyzerEvent(source_type="syslog_cef", log_type="event",
                            subtype="login", action="failed", src_ip=src_ip,
                            user=user, device_name="fw1", received_at=when)
    db.add(ev)
    db.flush()
    return ev


def test_auth_failure_distinct_per_user_same_ip_hour(db):
    hour = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    f_alice = check_auth_failure(_login_fail(db, "10.0.0.50", "alice", hour), db)
    db.flush()
    f_bob = check_auth_failure(_login_fail(db, "10.0.0.50", "bob", hour), db)
    db.flush()
    assert f_alice is not None and f_bob is not None
    assert f_alice.source_ref != f_bob.source_ref
    users = {f.detail["user"] for f in _open(db, "auth_failure")}
    assert users == {"alice", "bob"}       # both preserved, neither overwritten


def test_auth_failure_same_user_same_hour_still_deduped(db):
    hour = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    f1 = check_auth_failure(_login_fail(db, "10.0.0.50", "alice", hour), db)
    db.flush()
    f2 = check_auth_failure(_login_fail(db, "10.0.0.50", "alice",
                                        hour + timedelta(minutes=20)), db)
    assert f1 is not None and f2 is None   # same (ip,user,hour) -> one finding


def test_redetected_merges_evidence_rather_than_overwriting(db):
    f = Finding(category="real_time", check_name="auth_failure", severity="high",
                status="open", source_ref="x", occurrence_count=1, title="t",
                detail={"description": "first", "user": "alice", "src_ip": "10.0.0.1"})
    db.add(f)
    db.flush()
    # A re-detection whose dict omits "description" must not erase it.
    _redetected(f, {"user": "alice", "src_ip": "10.0.0.1", "window_hour": "H"})
    assert f.occurrence_count == 2
    assert f.detail["description"] == "first"      # preserved
    assert f.detail["window_hour"] == "H"          # new value merged in
