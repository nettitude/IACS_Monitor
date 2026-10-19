"""
Findings-engine lifecycle and accuracy items (docs/code-review-remediation.md):

  F-04  re-detection bumps last_seen / occurrence_count and refreshes detail;
        auto-resolve of periodic findings no longer detected (IACS_AUTO_RESOLVE)
  N-15  conduit_matrix_drift = observed sessions vs the ACTIVE baseline's
        ApprovedCommsEntry set; old rule-coverage behaviour kept as
        session_no_permitting_rule
  F-18  rule-twin traffic confirmation scoped to the rule's concrete src/dst
  N-17  evaluate_event: one savepoint per event, per-check fallback on failure
  N-02  escalations / auto_resolved in API responses
  F-17  GET /diagnostics
"""
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app.db import Base, configure_sqlite_engine, get_db
from app.models import (
    ApprovedCommsEntry, Baseline, CHECK_TYPE_REFERENCE, Finding, Firewall,
    FirewallInterface, FirewallRule, FirewallZone, FortiAnalyzerEvent, Host,
    NetworkSession,
)
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import (
    _make_finding, _rule_traffic_confirmed, _TrafficIndex, auto_resolved_counts,
    escalation_count, evaluate_event, failed_reviews, review_conduit_matrix_drift,
    review_rule_cleartext_protocols, review_session_no_permitting_rule,
    run_periodic_reviews,
)
from app.parsers.rule_match import parse_address


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


@pytest.fixture(autouse=True)
def _auto_resolve_default(monkeypatch):
    monkeypatch.delenv("IACS_AUTO_RESOLVE", raising=False)


def _host(db, ip, level=None, **kw):
    h = db.query(Host).filter(Host.ip == ip).first()
    if h is None:
        h = Host(ip=ip, purdue_level=level, **kw)
        db.add(h)
        db.flush()
    return h


_SRC_PORT = iter(range(40000, 60000))


def _sess(db, src_ip, dst_ip, dst_port, transport="tcp", src_level=None, dst_level=None,
          packets=10, protocol="unknown"):
    s, d = _host(db, src_ip, src_level), _host(db, dst_ip, dst_level)
    ns = NetworkSession(src_host_id=s.id, dst_host_id=d.id, src_port=next(_SRC_PORT),
                        dst_port=dst_port, transport=transport, packet_count=packets,
                        protocol=protocol)
    db.add(ns)
    db.flush()
    return ns


def _policy(db, src="all", dst="all", dst_port="443", protocol="tcp", action="accept",
            policy_id="1", device_name="FWP"):
    """C-08: a minimal enabled FirewallRule so a site has *a* firewall policy
    loaded. Defaults deliberately do NOT match the sessions these tests build,
    so the sessions remain 'no permitting rule' while a policy exists."""
    fw = db.query(Firewall).filter(Firewall.device_name == device_name).first()
    if fw is None:
        fw = Firewall(name=device_name, device_name=device_name, vendor="fortigate")
        db.add(fw)
        db.flush()
    r = FirewallRule(firewall_id=fw.id, device_name=device_name, device_type="fortigate",
                     policy_id=policy_id, src=src, dst=dst, protocol=protocol,
                     dst_port=dst_port, action=action, enabled=True)
    db.add(r)
    db.flush()
    return r


def _baseline(db, name="b1", active=True):
    b = Baseline(name=name, is_active=active)
    db.add(b)
    db.flush()
    return b


def _entry(db, b, src, dst, dst_port=None, dst_port_end=None, protocol="any"):
    e = ApprovedCommsEntry(baseline_id=b.id, src=src, dst=dst, dst_port=dst_port,
                           dst_port_end=dst_port_end, protocol=protocol)
    db.add(e)
    db.flush()
    return e


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


# ─── F-04 (a) re-detection ────────────────────────────────────────────────────

class TestRedetection:
    def test_redetection_bumps_last_seen_count_and_detail(self, db):
        ev = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 23}
        f = _make_finding(db, "cleartext_protocol", "t", "first", {**ev, "packet_count": 1})
        db.commit()
        assert f.occurrence_count == 1
        first_seen = f.last_seen
        assert first_seen is not None
        # make the stored timestamp clearly older
        f.last_seen = first_seen - timedelta(hours=1)
        db.commit()

        assert _make_finding(db, "cleartext_protocol", "t", "second",
                             {**ev, "packet_count": 99}) is None
        assert _make_finding(db, "cleartext_protocol", "t", "third",
                             {**ev, "packet_count": 120}) is None
        db.commit()
        db.refresh(f)
        assert f.occurrence_count == 3
        assert f.last_seen > first_seen - timedelta(hours=1)
        assert f.detail["description"] == "third"
        assert f.detail["packet_count"] == 120
        assert f.severity == CHECK_TYPE_REFERENCE["cleartext_protocol"][2]
        assert escalation_count(db) == 0

    def test_redetection_with_escalation_keeps_rules(self, db):
        ev = {"device_name": "fw9"}
        f = _make_finding(db, "log_silence", "low", "a", ev, severity="low")
        _make_finding(db, "log_silence", "high", "b", ev, severity="high")
        _make_finding(db, "log_silence", "lower again", "c", ev, severity="medium")
        db.commit()
        db.refresh(f)
        assert (f.severity, f.title) == ("high", "high")  # not lowered
        assert f.detail["description"] == "c"              # evidence refreshed
        assert f.occurrence_count == 3
        assert escalation_count(db) == 1

    def test_realtime_redetection_through_evaluate_event(self, db):
        def _ev():
            e = FortiAnalyzerEvent(source_type="syslog", log_type="event", subtype="system",
                                   device_name="fgt-a", raw_message="device offline",
                                   raw_fields={"msg": "device offline"},
                                   received_at=datetime.now(timezone.utc))
            db.add(e)
            db.flush()
            return e
        assert len(evaluate_event(_ev(), db)) == 1
        assert evaluate_event(_ev(), db) == []
        db.commit()
        (f,) = _open(db, "log_silence")
        assert f.occurrence_count == 2

    def test_closed_finding_not_bumped_new_one_opened(self, db):
        ev = {"ip": "10.5.5.5", "mac": "aa:bb:cc:dd:ee:ff"}
        f = _make_finding(db, "unknown_device", "t", "d", ev)
        f.status = "closed"
        db.commit()
        g = _make_finding(db, "unknown_device", "t", "d", ev)
        db.commit()
        assert g is not None and g.id != f.id
        db.refresh(f)
        assert f.occurrence_count == 1


# ─── F-04 (b) auto-resolve ────────────────────────────────────────────────────

def _historian(db, ip="10.2.0.50", level=2):
    return _host(db, ip, level, role="historian")


class TestAutoResolve:
    def test_closes_finding_no_longer_detected(self, db):
        h = _historian(db)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "historian_in_control_zone")
        # still present -> stays open, re-detected
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "open" and f.occurrence_count == 2
        assert "review_historian_in_control_zone" not in auto_resolved_counts(db)

        h.purdue_level = 3  # moved to Site Operations
        db.commit()
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "closed"
        assert f.closed_at is not None
        assert f.notes.startswith(
            "Auto-resolved: condition no longer detected by review_historian_in_control_zone on ")
        assert auto_resolved_counts(db)["review_historian_in_control_zone"] == 1
        assert ae.last_review_info()["auto_resolved"]["review_historian_in_control_zone"] == 1

    def test_skips_acknowledged_and_realtime_and_excluded(self, db):
        h = _historian(db)
        h2 = _historian(db, "10.2.0.51")
        db.commit()
        run_periodic_reviews(db)
        f_ack = next(f for f in _open(db, "historian_in_control_zone") if f.detail["ip"] == h2.ip)
        f_ack.status = "acknowledged"
        f_ack.acknowledged_by = "alice"
        f_ack.notes = "owned by OT team"
        rt = _make_finding(db, "log_silence", "rt", "x", {"device_name": "fw1"})
        # denied_trend is not auto-resolvable (time-windowed report item)
        dt = _make_finding(db, "denied_trend", "trend", "x", {"src_ip": "10.9.9.9"})
        db.commit()
        h.purdue_level = 3
        h2.purdue_level = 3
        db.commit()
        run_periodic_reviews(db)
        for f in (f_ack, rt, dt):
            db.refresh(f)
        assert f_ack.status == "acknowledged" and f_ack.notes == "owned by OT team"
        assert rt.status == "open"
        assert dt.status == "open"
        assert _open(db, "historian_in_control_zone") == []

    def test_failed_review_does_not_auto_resolve(self, db, monkeypatch):
        _historian(db)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "historian_in_control_zone")

        def broken(db):
            raise RuntimeError("boom")
        broken.__name__ = "review_historian_in_control_zone"
        monkeypatch.setattr(ae, "review_historian_in_control_zone", broken)
        run_periodic_reviews(db)
        assert "review_historian_in_control_zone" in failed_reviews(db)
        db.refresh(f)
        assert f.status == "open"
        assert "review_historian_in_control_zone" not in auto_resolved_counts(db)

    def test_env_switch_disables(self, db, monkeypatch):
        h = _historian(db)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "historian_in_control_zone")
        h.purdue_level = 3
        db.commit()
        monkeypatch.setenv("IACS_AUTO_RESOLVE", "false")
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "open"
        assert auto_resolved_counts(db) == {}
        monkeypatch.setenv("IACS_AUTO_RESOLVE", "true")
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "closed"

    def test_no_baseline_no_auto_close_of_drift(self, db):
        b = _baseline(db)
        _entry(db, b, "10.0.1.0/24", "10.0.2.0/24", 502, protocol="tcp")
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "conduit_matrix_drift")
        b.is_active = False  # no active baseline any more
        db.commit()
        stats = run_periodic_reviews(db)
        assert stats["review_conduit_matrix_drift"] == 0
        db.refresh(f)
        assert f.status == "open"
        assert "review_conduit_matrix_drift" not in auto_resolved_counts(db)

    def test_no_sessions_no_auto_close_of_drift(self, db):
        b = _baseline(db)
        _entry(db, b, "10.0.1.0/24", "10.0.2.0/24", 502, protocol="tcp")
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "conduit_matrix_drift")
        db.query(Finding).update({"session_id": None})
        db.query(NetworkSession).delete()
        db.commit()
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "open"

    def test_drift_closed_when_entry_approves_flow(self, db):
        b = _baseline(db)
        _entry(db, b, "10.0.1.0/24", "10.0.2.0/24", 502, protocol="tcp")
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        db.commit()
        run_periodic_reviews(db)
        (f,) = _open(db, "conduit_matrix_drift")
        _entry(db, b, "10.0.1.5", "10.0.2.9", 23, protocol="tcp")
        db.commit()
        run_periodic_reviews(db)
        db.refresh(f)
        assert f.status == "closed"
        assert auto_resolved_counts(db)["review_conduit_matrix_drift"] == 1

    def test_truncated_input_marks_incomplete(self, db, monkeypatch):
        # Limit hit -> the review is incomplete and must not auto-resolve.
        db.info[ae._SEEN_KEY] = set()
        ae._limit_hit(db, [1, 2, 3], 3, "x")
        assert db.info.get(ae._INCOMPLETE_KEY)
        db.info.pop(ae._SEEN_KEY)
        db.info.pop(ae._INCOMPLETE_KEY)
        # outside a tracked review it is a no-op
        ae._limit_hit(db, [1, 2, 3], 3, "x")
        assert ae._INCOMPLETE_KEY not in db.info


# ─── N-15 session-vs-baseline drift ───────────────────────────────────────────

class TestBaselineDrift:
    def _drift(self, db):
        db.info[ae._SEEN_KEY] = set()  # track incomplete like run_periodic_reviews
        db.info[ae._RUN_FINDINGS_KEY] = {}
        try:
            out = review_conduit_matrix_drift(db)
            incomplete = db.info.pop(ae._INCOMPLETE_KEY, None)
        finally:
            db.info.pop(ae._SEEN_KEY, None)
            db.info.pop(ae._RUN_FINDINGS_KEY, None)
        db.flush()
        return out, incomplete

    def test_no_active_baseline_skips(self, db):
        _baseline(db, active=False)
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        out, incomplete = self._drift(db)
        assert out == [] and incomplete

    def test_baseline_without_entries_skips(self, db):
        _baseline(db)
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        out, incomplete = self._drift(db)
        assert out == [] and incomplete

    def test_cidr_ip_port_range_any_and_protocol(self, db):
        b = _baseline(db)
        _entry(db, b, "10.0.1.0/24", "10.0.2.10", 502, protocol="tcp")      # Modbus
        _entry(db, b, "10.0.1.0/24", "10.0.2.10", 20000, 20010, "tcp")       # DNP3-ish range
        _entry(db, b, "10.0.3.7", "10.0.2.0/24", None, protocol="any")       # any port/proto
        _entry(db, b, "any", "10.0.9.9", 123, protocol="udp")                # NTP from anywhere
        _entry(db, b, "OT_OBJECT", "10.0.2.10", 80, protocol="tcp")          # unresolved name
        covered = [
            ("10.0.1.4", "10.0.2.10", 502, "tcp"),
            ("10.0.1.4", "10.0.2.10", 20000, "tcp"),
            ("10.0.1.4", "10.0.2.10", 20010, "tcp"),
            ("10.0.3.7", "10.0.2.44", 3389, "tcp"),
            ("10.0.3.7", "10.0.2.44", 161, "udp"),
            ("10.0.3.7", "10.0.2.44", None, "icmp"),
            ("192.168.7.7", "10.0.9.9", 123, "udp"),
        ]
        drift = [
            ("10.0.1.4", "10.0.2.10", 502, "udp"),     # protocol mismatch
            ("10.0.1.4", "10.0.2.10", 20011, "tcp"),   # just outside range
            ("10.0.1.4", "10.0.2.11", 502, "tcp"),     # dst IP outside
            ("10.0.4.4", "10.0.2.10", 502, "tcp"),     # src outside CIDR
            ("10.0.1.4", "10.0.2.10", None, "tcp"),    # no port vs port-specific entry
            ("10.0.1.4", "10.0.2.10", 80, "tcp"),      # only an unresolved entry
            ("192.168.7.7", "10.0.9.9", 123, "tcp"),
        ]
        for f in covered + drift:
            _sess(db, f[0], f[1], f[2], f[3])
        out, incomplete = self._drift(db)
        assert not incomplete
        got = {(f.detail["src_ip"], f.detail["dst_ip"], f.detail["dst_port"], f.detail["transport"])
               for f in out}
        assert got == set(drift)
        f = out[0]
        assert (f.isa62443_sr, f.checklist_id, f.category) == ("SR 5.2, ZCR 3", "8.1, 8.2",
                                                              "periodic_review")
        assert f.detail["baseline_id"] == b.id

    def test_one_finding_per_flow_with_occurrence_evidence(self, db):
        b = _baseline(db)
        _entry(db, b, "10.0.1.0/24", "10.0.2.0/24", 502, protocol="tcp")
        for _ in range(3):
            _sess(db, "10.0.1.5", "10.0.2.9", 23, packets=7)
        _sess(db, "10.0.1.5", "10.0.2.9", 23, transport="udp")
        out, _ = self._drift(db)
        assert len(out) == 2
        tcp = next(f for f in out if f.detail["transport"] == "tcp")
        assert tcp.detail["session_count"] == 3
        assert tcp.detail["packet_count"] == 21
        assert tcp.detail["first_seen"] and tcp.detail["last_seen"]
        # re-run: dedup on (src, dst, port, transport, baseline)
        out2, _ = self._drift(db)
        assert out2 == []
        db.refresh(tcp)
        assert tcp.occurrence_count == 2

    def test_only_active_baseline_used(self, db):
        old = _baseline(db, "old", active=False)
        _entry(db, old, "any", "any", None)                      # would approve everything
        b = _baseline(db, "new")
        _entry(db, b, "10.0.1.0/24", "10.0.2.0/24", 502, protocol="tcp")
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        out, _ = self._drift(db)
        assert len(out) == 1 and out[0].detail["baseline_id"] == b.id


class TestSessionNoPermittingRule:
    def test_registered(self):
        assert CHECK_TYPE_REFERENCE["session_no_permitting_rule"] == (
            "SR 5.2", "8.1, 8.2", "medium", "periodic_review")

    def test_old_rule_coverage_behaviour_kept(self, db):
        # A session with no PERMITTING firewall rule, and NO baseline at all:
        # the policy-coverage check still fires; baseline drift does not.
        # C-08: a firewall policy must exist (an unrelated rule here) - with
        # zero rules loaded the review is incomplete, not a per-flow storm.
        _policy(db, src="10.99.0.0/24", dst="10.98.0.0/24", dst_port="443")
        _sess(db, "10.0.1.5", "10.0.2.9", 23, src_level=3, dst_level=1)
        db.commit()
        stats = run_periodic_reviews(db)
        assert stats["review_session_no_permitting_rule"] == 1
        assert stats["review_conduit_matrix_drift"] == 0
        (f,) = _open(db, "session_no_permitting_rule")
        assert (f.detail["src_ip"], f.detail["dst_ip"], f.detail["dst_port"]) == (
            "10.0.1.5", "10.0.2.9", 23)
        assert f.isa62443_sr == "SR 5.2" and f.session_id is not None
        assert _open(db, "conduit_matrix_drift") == []

    def test_direct_call_matches_diff(self, db):
        _policy(db, src="10.99.0.0/24", dst="10.98.0.0/24", dst_port="443")  # C-08
        _sess(db, "10.0.1.5", "10.0.2.9", 23)
        _sess(db, "10.0.1.6", "10.0.2.9", 502)
        out = review_session_no_permitting_rule(db)
        assert {f.detail["src_ip"] for f in out} == {"10.0.1.5", "10.0.1.6"}


# ─── F-18 rule-twin confirmation scoped to rule src/dst ──────────────────────

@pytest.fixture
def fw(db):
    fw = Firewall(name="FGT1", device_name="FGT1", vendor="fortigate")
    db.add(fw)
    db.flush()
    for name, lvl in [("port1", 3), ("port2", 1)]:
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl))
    for zone, iface in [("IT_ZONE", "port1"), ("OT_ZONE", "port2")]:
        db.add(FirewallZone(device_name="FGT1", interface_name=iface, zone_name=zone))
    db.flush()
    return fw


def _rule(db, fw, src="all", dst="all", policy_id="10", dst_port="23"):
    r = FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                     policy_id=policy_id, src_zone="IT_ZONE", dst_zone="OT_ZONE",
                     src=src, dst=dst, protocol="tcp", dst_port=dst_port,
                     action="accept", enabled=True)
    db.add(r)
    db.flush()
    return r


class TestTwinCidrScoping:
    def test_traffic_outside_rule_cidrs_does_not_confirm(self, db, fw):
        _rule(db, fw, src="10.3.0.0/24", dst="10.1.0.0/24")
        _sess(db, "10.3.9.5", "10.1.0.7", 23, src_level=3, dst_level=1)  # src outside
        _sess(db, "10.3.0.5", "10.1.5.7", 23, src_level=3, dst_level=1)  # dst outside
        (f,) = review_rule_cleartext_protocols(db)
        assert f.detail["confirmed_by_traffic"] is False
        assert f.severity == "medium"

    def test_traffic_inside_rule_cidrs_confirms(self, db, fw):
        _rule(db, fw, src="10.3.0.0/24", dst="host 10.1.0.7")
        _sess(db, "10.3.0.5", "10.1.0.7", 23, src_level=3, dst_level=1)
        (f,) = review_rule_cleartext_protocols(db)
        assert f.detail["confirmed_by_traffic"] is True
        assert f.severity == "critical"

    def test_any_and_unresolved_addresses_stay_level_scoped(self, db, fw):
        _rule(db, fw, src="all", dst="OT_PLC_GROUP", policy_id="11")
        _sess(db, "10.3.9.5", "10.1.5.7", 23, src_level=3, dst_level=1)
        (f,) = review_rule_cleartext_protocols(db)
        assert f.detail["confirmed_by_traffic"] is True

    def test_range_address_and_index_vs_query_path(self, db, fw):
        _sess(db, "10.3.0.20", "10.1.0.7", 23, src_level=3, dst_level=1)
        _sess(db, "10.3.0.90", "10.1.0.7", 21, src_level=3, dst_level=1)
        idx = _TrafficIndex(db)
        cases = [
            ("range:10.3.0.10-10.3.0.30", "any", [23], True),
            ("range:10.3.0.21-10.3.0.30", "any", [23], False),
            ("10.3.0.0/24", "10.1.0.7", [21], True),
            ("10.3.0.0/25", "10.1.0.7", [21], True),
            ("10.3.0.0/26", "10.1.0.7", [21], False),
            ("10.3.0.0/24", "10.1.0.8", [21, 23], False),
            ("any", "any", [21], True),
        ]
        for src, dst, ports, want in cases:
            kw = dict(ports=ports, transport="tcp",
                      src_addr=parse_address(src), dst_addr=parse_address(dst))
            assert _rule_traffic_confirmed(db, {3}, {1}, **kw) is want, (src, dst, ports)
            assert _rule_traffic_confirmed(db, {3}, {1}, _traffic=idx, **kw) is want, (src, dst)
        # port_ranges path too
        kw = dict(port_ranges=[(20, 22)], src_addr=parse_address("10.3.0.64/26"))
        assert _rule_traffic_confirmed(db, {3}, {1}, _traffic=idx, **kw)
        assert _rule_traffic_confirmed(db, {3}, {1}, **kw)

    def test_no_extra_queries_per_rule(self, db, fw):
        for i in range(60):
            _rule(db, fw, src=f"10.3.{i}.0/24", dst="10.1.0.0/16", policy_id=str(100 + i))
        for i in range(20):
            _sess(db, f"10.3.{i}.5", f"10.1.0.{i + 1}", 23, src_level=3, dst_level=1)
        db.commit()
        n = {"q": 0}

        def _c(conn, cur, stmt, params, ctx, many):
            if stmt.lstrip().upper().startswith("SELECT"):
                n["q"] += 1
        event.listen(db.get_bind(), "before_cursor_execute", _c)
        try:
            out = review_rule_cleartext_protocols(db)
        finally:
            event.remove(db.get_bind(), "before_cursor_execute", _c)
        assert len(out) == 60
        assert sum(f.detail["confirmed_by_traffic"] for f in out) == 20
        assert n["q"] <= 15      # +3 fixed: the VPN context the twins build once (MP-23)


# ─── N-17 evaluate_event savepoints ──────────────────────────────────────────

def _count_all(db):
    c = {"stmts": 0, "savepoints": 0}

    def _c(conn, cur, stmt, params, ctx, many):
        c["stmts"] += 1
        if stmt.lstrip().upper().startswith("SAVEPOINT"):
            c["savepoints"] += 1
    event.listen(db.get_bind(), "before_cursor_execute", _c)
    return c, lambda: event.remove(db.get_bind(), "before_cursor_execute", _c)


def _legacy_evaluate(ev, db):
    # pre-N-17 behaviour: one savepoint per check
    out = []
    for fn in ae._RT_CHECKS:
        ok, a = ae._run_isolated(db, fn.__name__, fn, ev, db)
        if ok and a:
            out.append(a)
    return out


def _traffic_deny(db, i=0):
    e = FortiAnalyzerEvent(source_type="syslog", log_type="traffic", action="deny",
                           src_ip=f"10.3.0.{i % 250 + 1}", dst_ip="10.1.0.7", dst_port=443,
                           device_name="fgt", raw_fields={},
                           received_at=datetime.now(timezone.utc))
    db.add(e)
    db.flush()
    return e


class TestEvaluateEventSavepoints:
    def test_statement_counts_before_after(self, db):
        # SQLAlchemy emits a SAVEPOINT lazily (only when a check touches the
        # DB), so legacy cost = 2 statements per DB-touching check; N-17
        # makes it 2 per event. Measured (SQLite): deny 6 -> 4, IT->OT accept
        # with 2 findings 18 -> 14 statements.
        _host(db, "10.3.0.9", 3)
        _host(db, "10.1.0.9", 1)
        db.commit()

        def _accept():
            e = FortiAnalyzerEvent(source_type="syslog", log_type="traffic", action="accept",
                                   src_ip="10.3.0.9", dst_ip="10.1.0.9", dst_port=502,
                                   device_name="fgt", app="Modbus", raw_fields={},
                                   received_at=datetime.now(timezone.utc))
            db.add(e)
            db.flush()
            return e

        for make in (lambda: _traffic_deny(db, 1), _accept):
            c, stop = _count_all(db)
            legacy_out = _legacy_evaluate(make(), db)
            legacy = dict(c)
            db.rollback()
            c["stmts"] = c["savepoints"] = 0
            new_out = evaluate_event(make(), db)
            stop()
            db.rollback()
            assert len(new_out) == len(legacy_out)
            per_finding = len(new_out)  # _make_finding's own insert savepoint
            assert legacy["savepoints"] - per_finding >= 2
            assert c["savepoints"] - per_finding == 1
            assert c["stmts"] == legacy["stmts"] - 2 * (legacy["savepoints"] - c["savepoints"])

    def test_failure_falls_back_to_per_check_isolation(self, db, monkeypatch):
        calls = []

        def good(ev, db):
            calls.append("good")
            return _make_finding(db, "ha_system_error", "good", "x",
                                 {"device_name": f"good-{ev.id}"})

        def bad(ev, db):
            calls.append("bad")
            _make_finding(db, "log_silence", "partial", "x", {"device_name": "bad"})
            db.execute(text("SELECT * FROM no_such_table"))

        monkeypatch.setattr(ae, "_RT_CHECKS", [good, bad, good])
        ev = _traffic_deny(db)
        c, stop = _count_all(db)
        out = evaluate_event(ev, db)
        stop()
        db.commit()
        assert [f.title for f in out] == ["good"]
        assert {f.title for f in db.query(Finding)} == {"good"}
        assert calls == ["good", "bad", "good", "bad", "good"]  # combined, then 1-by-1
        assert c["savepoints"] >= 1 + 3
        # the re-detection in the 2nd "good" counted once (combined pass rolled back)
        (f,) = db.query(Finding).all()
        assert f.occurrence_count == 2


# ─── N-02 / F-17 API ─────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'lc.db'}",
                           connect_args={"check_same_thread": False})
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
        c.Session = Session
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


class TestApi:
    def test_reviews_run_returns_escalations_and_auto_resolved(self, client):
        with client.Session() as s:
            _host(s, "10.2.0.50", 2, role="historian")
            s.commit()
        r = client.post("/reviews/run")
        assert r.status_code == 200
        body = r.json()
        assert body["escalations"] == 0
        assert body["auto_resolved"] == {}
        assert body["by_review"]["review_historian_in_control_zone"] == 1
        with client.Session() as s:
            s.query(Host).filter(Host.ip == "10.2.0.50").update({"purdue_level": 3})
            s.commit()
        body = client.post("/reviews/run").json()
        assert body["auto_resolved"] == {"review_historian_in_control_zone": 1}

        d = client.get("/diagnostics").json()
        assert d["last_review"]["auto_resolved"] == {"review_historian_in_control_zone": 1}
        assert d["last_review"]["failed_reviews"] == []
        assert d["last_review"]["escalations"] == 0
        assert isinstance(d["unknown_check_names"], dict)

    def test_reviews_run_counts_escalation(self, client):
        with client.Session() as s:
            _host(s, "10.2.0.50", 2, role="historian")
            s.commit()
            _make_finding(s, "historian_in_control_zone", "t", "x",
                          {"ip": "10.2.0.50", "mac": None}, severity="low")
            s.commit()
        body = client.post("/reviews/run").json()
        assert body["escalations"] == 1
        assert client.get("/diagnostics").json()["last_review"]["escalations"] == 1

    def test_diagnostics_unknown_check_names(self, client, monkeypatch):
        monkeypatch.setattr(ae, "_unknown_check_name_count", {})
        with client.Session() as s:
            _make_finding(s, "no_such_check_xyz", "t", "x", {})
        d = client.get("/diagnostics").json()
        assert d["unknown_check_names"] == {"no_such_check_xyz": 1}

    def test_ingest_endpoints_report_escalations(self, client):
        line = ('date=2026-09-30 time=10:00:00 devname="fgt1" type="event" subtype="system" '
                'level="warning" msg="device offline" logdesc="device offline"')
        files = {"file": ("x.log", io.BytesIO(line.encode()), "text/plain")}
        r = client.post("/ingest/forti-syslog", files=files)
        assert r.status_code == 200, r.text
        assert r.json()["stats"]["escalations"] == 0

        payload = {"devname": "fgt2", "type": "event", "subtype": "system",
                   "msg": "device offline", "date": "2026-09-30", "time": "10:00:01"}
        r = client.post("/ingest/forti-event", json=payload)
        assert r.status_code == 200, r.text
        assert "escalations" in r.json()

        csv = "srcip,dstip,dstport,action,type\n10.3.0.1,10.1.0.1,23,deny,traffic\n"
        files = {"file": ("r.csv", io.BytesIO(csv.encode()), "text/csv")}
        r = client.post("/ingest/forti-report", files=files)
        assert r.status_code == 200, r.text
        assert r.json()["escalations"] == 0
