"""
Tests for app/parsers/alert_engine.py — priority-first coverage of the
8 highest-risk functions.

Coverage matrix
───────────────
  check_it_ot_bypass            Purdue path, heuristic path, no-trigger paths
  check_ot_internet_egress      confirmed OT (critical), unclassified (high),
                                 unknown host (medium), IT host (no finding)
  review_unknown_devices        unknown device flagged, approved device skipped,
                                 no-baseline short-circuit
  review_ip_conflicts           conflict detected, single-MAC host skipped
  review_shadow_rules           redundant rules, conflicting rules, single-rule (skip)
  review_cleartext_credentials  OT dest flagged (M-7 fix: NULL purdue_level included),
                                 IT dest skipped
  check_auth_failure            failure path (auth_failure check_name),
                                 non-admin-host path (auth_from_non_admin_host key, I-5),
                                 no dedup collision between the two
  _make_finding / _upsert_*     dedup — duplicate open finding suppressed (same
                                 source_ref); closed/acknowledged finding re-fires
                                 as a new open finding (T1-10); open finding
                                 escalated in place on higher severity (T1-11)

All tests use an in-memory SQLite database populated with the minimal set
of rows needed for each assertion.  No network calls, no files on disk.
"""
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import (
    ApprovedHost,
    Baseline,
    Finding,
    FirewallRule,
    FortiAnalyzerEvent,
    Host,
    NetworkSession,
)
from app.parsers.alert_engine import (
    _dedup_key,
    _already_open,
    _make_finding,
    escalation_count,
    check_it_ot_bypass,
    check_ot_internet_egress,
    check_auth_failure,
    review_cleartext_credentials,
    review_ip_conflicts,
    review_shadow_rules,
    review_unknown_devices,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def db():
    """In-memory SQLite session, created fresh for each test."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _now():
    return datetime.now(timezone.utc)


def _host(db, ip=None, mac=None, purdue_level=None, device_type=None):
    h = Host(ip=ip, mac=mac, purdue_level=purdue_level, device_type=device_type)
    db.add(h)
    db.flush()
    return h


def _event(db, log_type="traffic", action="allow", src_ip=None, dst_ip=None,
           dst_port=None, subtype=None, user=None, src_user=None,
           device_name="fw1", received_at=None, raw_fields=None,
           policy_id=None, service=None, app=None):
    ev = FortiAnalyzerEvent(
        source_type="api_push",
        log_type=log_type,
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        subtype=subtype,
        user=user,
        src_user=src_user,
        device_name=device_name,
        received_at=received_at or _now(),
        raw_fields=raw_fields or {},
        policy_id=policy_id,
        service=service,
        app=app,
    )
    db.add(ev)
    db.flush()
    return ev


def _rule(db, fw_name, policy_id, src, dst, dst_port, action="allow"):
    r = FirewallRule(
        device_name=fw_name,
        device_type="fortigate",
        policy_id=policy_id,
        src=src,
        dst=dst,
        dst_port=str(dst_port),
        action=action,
    )
    db.add(r)
    db.flush()
    return r


def _session(db, src_host, dst_host, dst_port, packet_count=10, protocol="tcp"):
    ns = NetworkSession(
        src_host_id=src_host.id,
        dst_host_id=dst_host.id,
        dst_port=dst_port,
        packet_count=packet_count,
        protocol=protocol,
    )
    db.add(ns)
    db.flush()
    return ns


def _baseline(db, name="test-baseline", is_active=True):
    b = Baseline(name=name, is_active=is_active, created_at=_now())
    db.add(b)
    db.flush()
    return b


def _approved_host(db, baseline, ip=None, mac=None, role="admin_ws"):
    ah = ApprovedHost(baseline_id=baseline.id, ip=ip, mac=mac, role=role)
    db.add(ah)
    db.flush()
    return ah


# ═══════════════════════════════════════════════════════════════════════════════
# _dedup_key / _make_finding / _already_open  (core dedup machinery)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDedupKey:
    def test_same_evidence_same_key(self):
        ev = {"src_ip": "10.0.1.1", "dst_ip": "8.8.8.8", "dst_port": 443}
        assert _dedup_key("it_ot_bypass", ev) == _dedup_key("it_ot_bypass", ev)

    def test_different_check_name_different_key(self):
        ev = {"src_ip": "10.0.1.1", "dst_ip": "8.8.8.8", "dst_port": 443}
        assert _dedup_key("it_ot_bypass", ev) != _dedup_key("ot_internet_egress", ev)

    def test_different_src_ip_different_key(self):
        ev_a = {"src_ip": "10.0.1.1", "dst_ip": "8.8.8.8", "dst_port": 443}
        ev_b = {"src_ip": "10.0.1.2", "dst_ip": "8.8.8.8", "dst_port": 443}
        assert _dedup_key("it_ot_bypass", ev_a) != _dedup_key("it_ot_bypass", ev_b)

    def test_key_length_16_chars(self):
        key = _dedup_key("auth_failure", {"src_ip": "10.1.1.1"})
        assert len(key) == 16

    def test_auth_failure_vs_non_admin_host_keys_differ(self):
        """I-5 regression: the two auth sub-paths must never share a dedup slot."""
        evidence = {"src_ip": "10.0.1.50", "device_name": "fw1"}
        k1 = _dedup_key("auth_failure", evidence)
        k2 = _dedup_key("auth_from_non_admin_host", evidence)
        assert k1 != k2


class TestMakeFinding:
    def test_creates_finding_when_no_open_duplicate(self, db):
        ev = _event(db, src_ip="10.0.1.1", dst_ip="192.0.2.1", dst_port=443)
        f = _make_finding(
            db, "ot_internet_egress", "title", "detail",
            {"src_ip": "10.0.1.1", "dst_ip": "192.0.2.1", "dst_port": 443},
            forti_event_id=ev.id,
        )
        assert f is not None
        assert f.check_name == "ot_internet_egress"
        assert f.source_ref is not None

    def test_suppresses_duplicate_open_finding(self, db):
        ev = _event(db, src_ip="10.0.1.1", dst_ip="192.0.2.1", dst_port=443)
        evidence = {"src_ip": "10.0.1.1", "dst_ip": "192.0.2.1", "dst_port": 443}
        f1 = _make_finding(db, "ot_internet_egress", "title", "detail", evidence,
                           forti_event_id=ev.id)
        db.flush()
        # Same check + evidence → already open → should return None
        f2 = _make_finding(db, "ot_internet_egress", "title", "detail", evidence,
                           forti_event_id=ev.id)
        assert f1 is not None
        assert f2 is None

    @pytest.mark.parametrize("prior_status", ["closed"])
    def test_new_finding_after_closed(self, db, prior_status):
        """
        T1-10: once the prior finding is CLOSED, a recurrence of the same
        condition must insert a NEW open finding with the same source_ref
        (the unique index only covers status='open'). Acknowledged findings
        behave differently - see test_acknowledged_finding_absorbs_recurrence.
        """
        ev = _event(db, src_ip="10.0.1.1", dst_ip="192.0.2.1", dst_port=443)
        evidence = {"src_ip": "10.0.1.1", "dst_ip": "192.0.2.1", "dst_port": 443}
        f1 = _make_finding(db, "ot_internet_egress", "t", "d", evidence,
                           forti_event_id=ev.id)
        db.flush()
        f1.status = prior_status
        db.flush()

        f2 = _make_finding(db, "ot_internet_egress", "t", "d", evidence,
                           forti_event_id=ev.id)
        db.commit()
        assert f2 is not None
        assert f2.id != f1.id
        assert f2.source_ref == f1.source_ref
        assert f2.status == "open"
        rows = db.query(Finding).filter(Finding.source_ref == f1.source_ref).all()
        assert sorted(r.status for r in rows) == sorted(["open", prior_status])

        # ...and the recurrence is itself deduplicated while open.
        assert _make_finding(db, "ot_internet_egress", "t", "d", evidence) is None
        assert db.query(Finding).filter(Finding.source_ref == f1.source_ref).count() == 2

    def test_two_open_findings_same_source_ref_rejected_by_index(self, db):
        from sqlalchemy.exc import IntegrityError
        f1 = _make_finding(db, "ot_internet_egress", "t", "d", {"src_ip": "10.9.9.9"})
        db.commit()
        db.add(Finding(category="real_time", check_name="ot_internet_egress",
                       severity="high", title="dup", source_ref=f1.source_ref))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

    def test_escalates_existing_open_finding_on_higher_severity(self, db):
        """T1-11: higher-severity recurrence updates the open finding in place."""
        evidence = {"src_ip": "10.0.3.1", "dst_ip": "8.8.4.4", "dst_port": 53}
        f1 = _make_finding(db, "ot_internet_egress", "low title", "low detail",
                           evidence, severity="medium")
        db.commit()
        fid, created = f1.id, f1.created_at

        again = _make_finding(db, "ot_internet_egress", "high title", "high detail",
                              {**evidence, "extra": 1}, severity="critical")
        db.commit()
        assert again is None  # not reported as a new finding
        assert db.query(Finding).count() == 1
        f = db.get(Finding, fid)
        assert f.severity == "critical"
        assert f.title == "high title"
        assert f.detail["description"] == "high detail"
        assert f.detail["extra"] == 1
        assert f.status == "open"
        assert f.created_at == created
        assert escalation_count(db) == 1

    @pytest.mark.parametrize("new_sev", ["medium", "low", "info"])
    def test_equal_or_lower_severity_does_not_modify(self, db, new_sev):
        evidence = {"src_ip": "10.0.3.2", "dst_ip": "8.8.4.4", "dst_port": 53}
        f1 = _make_finding(db, "ot_internet_egress", "orig", "orig detail",
                           evidence, severity="medium")
        db.commit()
        assert _make_finding(db, "ot_internet_egress", "new", "new detail",
                             evidence, severity=new_sev) is None
        db.commit()
        f = db.get(Finding, f1.id)
        assert (f.severity, f.title) == ("medium", "orig")
        # F-04: a re-detection refreshes evidence and bumps the occurrence
        # counter, but severity/title follow the escalation rules only.
        assert f.detail["description"] == "new detail"
        assert f.occurrence_count == 2
        assert escalation_count(db) == 0

    def test_already_open_true_for_open(self, db):
        evidence = {"src_ip": "10.0.2.1", "dst_ip": "8.8.8.8", "dst_port": 80}
        f = _make_finding(db, "ot_internet_egress", "t", "d", evidence)
        db.flush()
        assert _already_open(db, f.source_ref)

    def test_acknowledged_finding_absorbs_recurrence(self, db):
        """An acknowledged finding is owned by a person: a persisting
        condition updates it (last_seen / occurrence_count) instead of
        opening a duplicate every review run."""
        evidence = {"src_ip": "10.0.2.2", "dst_ip": "8.8.8.8", "dst_port": 80}
        f = _make_finding(db, "ot_internet_egress", "t", "d", evidence)
        db.flush()
        f.status = "acknowledged"
        db.flush()
        assert _already_open(db, f.source_ref)          # active for dedup
        n = f.occurrence_count or 1
        assert _make_finding(db, "ot_internet_egress", "t", "d", evidence) is None
        db.flush()
        assert db.query(Finding).filter(Finding.source_ref == f.source_ref).count() == 1
        assert f.status == "acknowledged" and f.occurrence_count == n + 1

    def test_acknowledged_finding_reopens_on_escalation(self, db):
        evidence = {"src_ip": "10.0.2.3", "dst_ip": "8.8.4.4", "dst_port": 80}
        f = _make_finding(db, "ot_internet_egress", "t", "d", evidence, severity="medium")
        db.flush()
        f.status = "acknowledged"
        db.flush()
        assert _make_finding(db, "ot_internet_egress", "t2", "d", evidence, severity="critical") is None
        db.flush()
        assert f.status == "open" and f.severity == "critical"
        assert "Re-opened" in (f.notes or "")


# ═══════════════════════════════════════════════════════════════════════════════
# check_it_ot_bypass
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckItOtBypass:
    # ── Path 1: Purdue-level (definitive) ────────────────────────────────────

    def test_purdue_it_to_ot_fires(self, db):
        _host(db, ip="10.3.0.10", purdue_level=3)  # IT / operations
        _host(db, ip="10.1.0.20", purdue_level=1)  # Basic control
        ev = _event(db, src_ip="10.3.0.10", dst_ip="10.1.0.20", dst_port=502)
        f = check_it_ot_bypass(ev, db)
        assert f is not None
        assert f.check_name == "it_ot_bypass"
        assert f.severity == "critical"
        assert "purdue_level" in str(f.detail)

    def test_purdue_ot_to_it_fires(self, db):
        _host(db, ip="10.1.0.5", purdue_level=1)
        _host(db, ip="10.4.0.1", purdue_level=4)  # Enterprise
        ev = _event(db, src_ip="10.1.0.5", dst_ip="10.4.0.1", dst_port=80)
        f = check_it_ot_bypass(ev, db)
        assert f is not None

    def test_purdue_same_zone_no_finding(self, db):
        """Two OT hosts (L1 ↔ L2) should not fire."""
        _host(db, ip="10.1.0.10", purdue_level=1)
        _host(db, ip="10.2.0.20", purdue_level=2)
        ev = _event(db, src_ip="10.1.0.10", dst_ip="10.2.0.20", dst_port=502)
        assert check_it_ot_bypass(ev, db) is None

    def test_purdue_both_it_no_finding(self, db):
        """L3 → L3 is normal IT traffic."""
        _host(db, ip="10.3.0.1", purdue_level=3)
        _host(db, ip="10.3.0.2", purdue_level=3)
        ev = _event(db, src_ip="10.3.0.1", dst_ip="10.3.0.2", dst_port=445)
        assert check_it_ot_bypass(ev, db) is None

    # ── Path 2: subnet heuristic ─────────────────────────────────────────────

    def test_heuristic_different_slash16_fires(self, db):
        """No hosts in DB → falls through to heuristic; different /16 → fires."""
        ev = _event(db, src_ip="10.3.0.1", dst_ip="192.168.0.1", dst_port=80)
        f = check_it_ot_bypass(ev, db)
        assert f is not None
        assert "heuristic" in f.title.lower() or "heuristic" in str(f.detail)

    def test_heuristic_same_slash16_no_finding(self, db):
        ev = _event(db, src_ip="10.0.1.5", dst_ip="10.0.2.6", dst_port=80)
        assert check_it_ot_bypass(ev, db) is None

    # ── Guard rails ──────────────────────────────────────────────────────────

    def test_deny_action_no_finding(self, db):
        ev = _event(db, action="deny", src_ip="10.3.0.1", dst_ip="192.168.1.1",
                    dst_port=80)
        assert check_it_ot_bypass(ev, db) is None

    def test_non_rfc1918_src_no_finding(self, db):
        ev = _event(db, src_ip="8.8.8.8", dst_ip="192.168.1.1", dst_port=80)
        assert check_it_ot_bypass(ev, db) is None

    def test_non_traffic_type_no_finding(self, db):
        ev = _event(db, log_type="event", action="allow",
                    src_ip="10.3.0.1", dst_ip="192.168.0.1")
        assert check_it_ot_bypass(ev, db) is None


# ═══════════════════════════════════════════════════════════════════════════════
# check_ot_internet_egress
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckOtInternetEgress:
    def test_confirmed_ot_host_critical(self, db):
        _host(db, ip="10.1.0.5", purdue_level=1)
        ev = _event(db, src_ip="10.1.0.5", dst_ip="8.8.8.8", dst_port=53)
        f = check_ot_internet_egress(ev, db)
        assert f is not None
        assert f.severity == "critical"

    def test_unclassified_known_host_high(self, db):
        """Host in DB but no Purdue level → severity high."""
        _host(db, ip="10.1.0.6", purdue_level=None)
        ev = _event(db, src_ip="10.1.0.6", dst_ip="1.2.3.4", dst_port=80)
        f = check_ot_internet_egress(ev, db)
        assert f is not None
        assert f.severity == "high"

    def test_unknown_host_medium(self, db):
        """IP not in Host table → severity medium."""
        ev = _event(db, src_ip="10.2.0.99", dst_ip="5.6.7.8", dst_port=443)
        f = check_ot_internet_egress(ev, db)
        assert f is not None
        assert f.severity == "medium"

    def test_confirmed_it_host_no_finding(self, db):
        """Purdue level > 3 (DMZ / IT) → internet is expected, no finding."""
        _host(db, ip="10.4.0.10", purdue_level=4)
        ev = _event(db, src_ip="10.4.0.10", dst_ip="8.8.8.8", dst_port=53)
        assert check_ot_internet_egress(ev, db) is None

    def test_site_operations_is_ot_for_internet(self, db):
        """H-13: L3 (site operations) is OT - direct internet egress is a finding (high)."""
        _host(db, ip="10.3.0.10", purdue_level=3)
        ev = _event(db, src_ip="10.3.0.10", dst_ip="8.8.8.8", dst_port=53)
        f = check_ot_internet_egress(ev, db)
        assert f is not None and f.severity == "high"

    def test_rfc1918_dst_no_finding(self, db):
        """Destination is private → not internet egress."""
        _host(db, ip="10.1.0.5", purdue_level=1)
        ev = _event(db, src_ip="10.1.0.5", dst_ip="10.2.0.1", dst_port=80)
        assert check_ot_internet_egress(ev, db) is None

    def test_deny_action_no_finding(self, db):
        _host(db, ip="10.1.0.5", purdue_level=1)
        ev = _event(db, action="deny", src_ip="10.1.0.5", dst_ip="8.8.8.8",
                    dst_port=80)
        assert check_ot_internet_egress(ev, db) is None


# ═══════════════════════════════════════════════════════════════════════════════
# review_unknown_devices
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewUnknownDevices:
    def test_no_baseline_returns_empty(self, db):
        _host(db, ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01")
        assert review_unknown_devices(db) == []

    def test_unknown_device_flagged(self, db):
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01")
        # A second host not in the approved list
        _host(db, ip="10.0.0.99", mac="de:ad:be:ef:00:99")
        findings = review_unknown_devices(db)
        assert len(findings) == 1
        assert "10.0.0.99" in findings[0].title or "de:ad:be:ef:00:99" in findings[0].title

    def test_approved_by_ip_not_flagged(self, db):
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.0.10")
        _host(db, ip="10.0.0.10")
        assert review_unknown_devices(db) == []

    def test_approved_by_mac_not_flagged(self, db):
        b = _baseline(db)
        _approved_host(db, b, mac="11:22:33:44:55:66")
        _host(db, ip="10.0.0.20", mac="11:22:33:44:55:66")
        assert review_unknown_devices(db) == []

    def test_page_approved_host_is_known(self, db):
        """Owner 2026-10-14: a host approved on the Inventory page counts as in the
        inventory (by address and MAC - the device's other address too); a host
        marked unapproved / rogue stays reported."""
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.0.1")
        ok = _host(db, ip="10.0.0.30", mac="aa:00:00:00:00:30")
        ok.approved = True
        _host(db, ip="10.0.9.30", mac="aa:00:00:00:00:30")          # same device, other subnet
        rogue = _host(db, ip="10.0.0.31", mac="aa:00:00:00:00:31")
        rogue.approved = False
        db.flush()
        findings = review_unknown_devices(db)
        assert [f.detail["ip"] for f in findings] == ["10.0.0.31"]

    def test_page_approved_host_without_baseline(self, db):
        """No baseline: the unidentified / consumer device findings skip an approved device."""
        h = _host(db, ip="10.0.0.40", mac="f0:18:98:00:00:40")
        h.vendor = "Apple, Inc."
        db.flush()
        before = [f for f in review_unknown_devices(db) if f.check_name == "unknown_device"]
        h.approved = True
        db.flush()
        after = [f for f in review_unknown_devices(db) if f.check_name == "unknown_device"]
        assert before and not after

    def test_multiple_unknown_devices_all_flagged(self, db):
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.0.1")
        _host(db, ip="10.0.0.2", mac="aa:00:00:00:00:02")
        _host(db, ip="10.0.0.3", mac="aa:00:00:00:00:03")
        findings = review_unknown_devices(db)
        assert len(findings) == 2

    def test_empty_approved_list_returns_empty(self, db):
        """Baseline exists but no approved entries → no findings (not fail-open)."""
        _baseline(db)
        _host(db, ip="10.0.0.5", mac="ff:ff:ff:ff:ff:01")
        assert review_unknown_devices(db) == []


# ═══════════════════════════════════════════════════════════════════════════════
# review_ip_conflicts
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewIpConflicts:
    def test_conflict_detected(self, db):
        """Same IP, two different MACs → conflict finding."""
        _host(db, ip="10.0.0.50", mac="aa:bb:cc:dd:ee:01")
        _host(db, ip="10.0.0.50", mac="ff:ee:dd:cc:bb:01")
        findings = review_ip_conflicts(db)
        assert len(findings) == 1
        f = findings[0]
        assert "10.0.0.50" in f.title
        assert f.check_name == "ip_conflict"

    def test_single_mac_no_conflict(self, db):
        _host(db, ip="10.0.0.51", mac="aa:bb:cc:dd:ee:99")
        assert review_ip_conflicts(db) == []

    def test_different_ips_no_conflict(self, db):
        _host(db, ip="10.0.0.52", mac="aa:bb:cc:dd:ee:01")
        _host(db, ip="10.0.0.53", mac="aa:bb:cc:dd:ee:02")
        assert review_ip_conflicts(db) == []

    def test_three_macs_one_ip_one_finding(self, db):
        """Multiple MACs for same IP still produce only one finding."""
        for i in range(3):
            _host(db, ip="10.0.0.55", mac=f"aa:bb:cc:dd:ee:{i:02x}")
        findings = review_ip_conflicts(db)
        assert len(findings) == 1
        assert findings[0].detail["mac_count"] == 3

    def test_dedup_suppresses_re_run(self, db):
        """Running review twice on same data: second call returns None (already open)."""
        _host(db, ip="10.0.0.60", mac="aa:bb:cc:11:11:01")
        _host(db, ip="10.0.0.60", mac="aa:bb:cc:11:11:02")
        findings1 = review_ip_conflicts(db)
        db.flush()
        findings2 = review_ip_conflicts(db)
        assert len(findings1) == 1
        # Second run: already open → _make_finding returns None → list filtered
        assert all(f is None for f in findings2) or findings2 == []


# ═══════════════════════════════════════════════════════════════════════════════
# review_shadow_rules
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewShadowRules:
    def test_redundant_rules_flagged(self, db):
        """Two rules with identical src/dst/port/action → redundant finding."""
        _rule(db, "fw1", "100", "any", "10.0.0.1", 80, action="allow")
        _rule(db, "fw1", "200", "any", "10.0.0.1", 80, action="allow")
        findings = review_shadow_rules(db)
        assert len(findings) == 1
        assert findings[0].check_name == "shadow_rule"
        assert findings[0].detail["finding_type"] == "redundant"

    def test_conflicting_rules_flagged(self, db):
        """Same src/dst/port but different actions → shadowed finding.

        When two rules have identical match criteria but opposite actions the
        earlier rule is a full superset of the later rule (in all dimensions:
        src, dst, port) — that is the definition of full_shadow, which maps
        to finding_type "shadowed".  The "conflicting" type requires a
        *partial* overlap where at least one dimension differs, e.g. the
        first rule covers a wider src range.  Identical-match-different-action
        is therefore classified as "shadowed", not "conflicting".
        """
        _rule(db, "fw1", "10", "any", "10.0.0.2", 22, action="allow")
        _rule(db, "fw1", "20", "any", "10.0.0.2", 22, action="deny")
        findings = review_shadow_rules(db)
        assert len(findings) == 1
        assert findings[0].detail["finding_type"] == "shadowed"

    def test_different_ports_no_finding(self, db):
        _rule(db, "fw1", "1", "any", "10.0.0.3", 80, action="allow")
        _rule(db, "fw1", "2", "any", "10.0.0.3", 443, action="allow")
        assert review_shadow_rules(db) == []

    def test_single_rule_no_finding(self, db):
        _rule(db, "fw1", "1", "any", "10.0.0.4", 80, action="allow")
        assert review_shadow_rules(db) == []

    def test_different_devices_independent(self, db):
        """Rules on different devices are never compared against each other."""
        _rule(db, "fw1", "1", "any", "10.0.0.5", 80, action="allow")
        _rule(db, "fw2", "1", "any", "10.0.0.5", 80, action="allow")
        # Each device has only one rule → no pairs to compare → no findings
        assert review_shadow_rules(db) == []

    def test_pair_dedup_one_finding_per_pair(self, db):
        """Adding a third rule with same criteria doesn't multiply the finding."""
        for pid in ("10", "20", "30"):
            _rule(db, "fw1", pid, "any", "10.0.0.6", 9999, action="allow")
        findings = review_shadow_rules(db)
        # 3 rules → up to 3 pairs (10,20), (10,30), (20,30) → 3 findings possible,
        # but each distinct pair is counted exactly once.
        assert len(findings) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# review_cleartext_credentials (validates M-7 NULL-inclusive SQL fix)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewCleartextCredentials:
    def test_telnet_to_ot_host_flagged(self, db):
        src = _host(db, ip="10.5.0.100", purdue_level=3)
        dst = _host(db, ip="10.1.0.200", purdue_level=1)  # OT device
        _session(db, src, dst, dst_port=23)
        findings = review_cleartext_credentials(db)
        assert len(findings) == 1
        assert findings[0].check_name == "cleartext_credentials"

    def test_ftp_to_ot_host_flagged(self, db):
        src = _host(db, ip="10.5.0.101", purdue_level=3)
        dst = _host(db, ip="10.1.0.201", purdue_level=0)
        _session(db, src, dst, dst_port=21)
        assert len(review_cleartext_credentials(db)) == 1

    def test_null_purdue_level_dst_flagged(self, db):
        """
        M-7 regression test: hosts with purdue_level IS NULL must be included
        by the SQL filter (or_(Host.purdue_level <= 2, Host.purdue_level.is_(None))).
        Without the fix, SQLite silently drops NULL <= 2 comparisons, so an
        unclassified OT-adjacent host that uses Telnet would produce zero findings.
        """
        src = _host(db, ip="10.5.0.102", purdue_level=3)
        dst = _host(db, ip="10.1.0.202", purdue_level=None)  # unclassified
        _session(db, src, dst, dst_port=23)
        findings = review_cleartext_credentials(db)
        assert len(findings) == 1
        assert findings[0].detail.get("dst_level") is None
        assert "classification_note" in findings[0].detail

    def test_telnet_to_it_host_not_flagged(self, db):
        """Destination is confirmed IT (L4) → not flagged by this check."""
        src = _host(db, ip="10.5.0.103", purdue_level=3)
        dst = _host(db, ip="10.4.0.1", purdue_level=4)  # Enterprise IT
        _session(db, src, dst, dst_port=23)
        # The dst's purdue_level is 4 (> 2) so neither `<= 2` nor `IS NULL`
        # matches → SQL filter excludes it → empty result
        assert review_cleartext_credentials(db) == []

    def test_https_port_not_in_cleartext_list(self, db):
        """Port 443 (TLS) is not a cleartext protocol → no finding."""
        src = _host(db, ip="10.5.0.104", purdue_level=3)
        dst = _host(db, ip="10.1.0.204", purdue_level=1)
        _session(db, src, dst, dst_port=443)
        assert review_cleartext_credentials(db) == []

    def test_unclassified_dst_no_ip_still_flagged(self, db):
        """
        Destination host with purdue_level=None and no IP is still captured
        by the null-inclusive SQL filter and flagged as unclassified OT risk.
        """
        src = _host(db, ip="10.5.0.105", purdue_level=3)
        dst = _host(db, ip=None, mac="de:ad:be:ef:11:05", purdue_level=None)
        _session(db, src, dst, dst_port=23)
        findings = review_cleartext_credentials(db)
        # dst exists, purdue_level is None → dst_unclassified=True → finding created
        assert len(findings) == 1
        assert findings[0].detail.get("dst_level") is None


# ═══════════════════════════════════════════════════════════════════════════════
# check_auth_failure  (auth_failure path + auth_from_non_admin_host path, I-5)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckAuthFailure:
    # ── auth_failure path ─────────────────────────────────────────────────────

    def test_failed_login_produces_auth_failure_finding(self, db):
        ev = _event(
            db, log_type="event", subtype="login", action="failed",
            src_ip="10.0.1.50", user="admin", received_at=_now(),
        )
        f = check_auth_failure(ev, db)
        assert f is not None
        assert f.check_name == "auth_failure"

    def test_auth_failure_dedup_key_includes_window_hour(self, db):
        """Two failures from the same IP in the same hour share a dedup key."""
        ev1 = _event(
            db, log_type="event", subtype="authentication", action="failure",
            src_ip="10.0.1.51", user="user1",
            received_at=datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc),
        )
        ev2 = _event(
            db, log_type="event", subtype="authentication", action="failure",
            src_ip="10.0.1.51", user="user1",
            received_at=datetime(2026, 9, 1, 14, 30, 0, tzinfo=timezone.utc),
        )
        f1 = check_auth_failure(ev1, db)
        db.flush()
        f2 = check_auth_failure(ev2, db)
        assert f1 is not None
        assert f2 is None  # same hour → deduped

    def test_auth_failure_different_hours_not_deduped(self, db):
        """Failures in different hours each get a finding (rolling window)."""
        for hour in (10, 11):
            ev = _event(
                db, log_type="event", subtype="login", action="failed",
                src_ip="10.0.1.52", user="hacker",
                received_at=datetime(2026, 9, 1, hour, 0, 0, tzinfo=timezone.utc),
            )
            f = check_auth_failure(ev, db)
            db.flush()
            assert f is not None, f"expected finding for hour {hour}"

    def test_non_event_type_no_finding(self, db):
        ev = _event(db, log_type="traffic", subtype="login", action="failed",
                    src_ip="10.0.1.53")
        assert check_auth_failure(ev, db) is None

    def test_wrong_subtype_no_finding(self, db):
        ev = _event(db, log_type="event", subtype="config", action="failed",
                    src_ip="10.0.1.54")
        assert check_auth_failure(ev, db) is None

    # ── auth_from_non_admin_host path (I-5) ───────────────────────────────────

    def test_login_from_non_admin_host_produces_auth_from_non_admin_host(self, db):
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.1.10", role="admin_ws")
        ev = _event(
            db, log_type="event", subtype="login", action="success",
            src_ip="10.0.1.99",  # NOT the approved admin WS
        )
        f = check_auth_failure(ev, db)
        assert f is not None
        assert f.check_name == "auth_from_non_admin_host"

    def test_login_from_approved_admin_host_no_finding(self, db):
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.1.10", role="admin_ws")
        ev = _event(
            db, log_type="event", subtype="login", action="success",
            src_ip="10.0.1.10",  # IS the approved admin WS
        )
        assert check_auth_failure(ev, db) is None

    def test_i5_dedup_keys_differ(self, db):
        """
        I-5 regression: auth_failure and auth_from_non_admin_host must not
        share a source_ref slot.  If they did, a failed-login finding could
        suppress a subsequent non-admin-host finding (or vice versa) even
        though they describe completely different security conditions.
        """
        b = _baseline(db)
        _approved_host(db, b, ip="10.0.1.15", role="admin_ws")

        # First: auth failure from the non-admin host
        ev_fail = _event(
            db, log_type="event", subtype="login", action="failed",
            src_ip="10.0.1.80", user="bob",
            received_at=datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc),
        )
        f_fail = check_auth_failure(ev_fail, db)
        db.flush()
        assert f_fail is not None
        assert f_fail.check_name == "auth_failure"

        # Second: successful login from that same non-admin host
        ev_success = _event(
            db, log_type="event", subtype="login", action="success",
            src_ip="10.0.1.80",
        )
        f_success = check_auth_failure(ev_success, db)
        assert f_success is not None
        assert f_success.check_name == "auth_from_non_admin_host"
        # Different check_names → different source_refs → both persist
        assert f_fail.source_ref != f_success.source_ref

    def test_no_baseline_success_login_no_finding(self, db):
        """No baseline → no approved admin WS set → non-admin-host path skipped."""
        ev = _event(
            db, log_type="event", subtype="login", action="success",
            src_ip="10.0.1.99",
        )
        assert check_auth_failure(ev, db) is None

    def test_empty_admin_ws_list_no_finding(self, db):
        """Baseline exists but no admin_ws hosts defined → non-admin path quiet."""
        _baseline(db)
        # No _approved_host call → admin_ips is empty
        ev = _event(
            db, log_type="event", subtype="login", action="success",
            src_ip="10.0.1.99",
        )
        assert check_auth_failure(ev, db) is None
