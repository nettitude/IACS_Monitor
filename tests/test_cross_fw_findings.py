"""
Tests for app/parsers/cross_fw_findings.py

Coverage:
  - _upsert_finding idempotency (source_ref deduplication)
  - _check_no_rules
  - _check_missing_deny_all (+ FortiGate severity downgrade)
  - _check_any_any_permit (CRITICAL)
  - _check_asymmetric_permits (MEDIUM, both directions)
  - run_cross_fw_checks: summary counts, skips same-FW links, deduplicates pairs
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Finding, Firewall, FirewallInterface, FirewallRule
from app.parsers.cross_fw_findings import (
    run_cross_fw_checks,
    _check_no_rules,
    _check_missing_deny_all,
    _check_any_any_permit,
    _check_asymmetric_permits,
    _upsert_finding,
)


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _fw(db, name, vendor="cisco"):
    fw = Firewall(name=name, vendor=vendor, is_multi_fw=True, topology_confirmed=False)
    db.add(fw)
    db.flush()
    return fw


def _iface(db, fw, name, side="outside"):
    iface = FirewallInterface(
        firewall_id=fw.id, name=name, side=side,
        is_ha=False, is_mgmt_only=False,
    )
    db.add(iface)
    db.flush()
    return iface


def _rule(db, fw, action, src=None, dst=None, dst_port=None, protocol=None,
          policy_id=None, src_zone=None, device_type="fortigate"):
    rule = FirewallRule(
        firewall_id=fw.id,
        device_type=device_type,
        action=action,
        src=src,
        dst=dst,
        dst_port=dst_port,
        protocol=protocol,
        policy_id=policy_id,
        src_zone=src_zone,
    )
    db.add(rule)
    db.flush()
    return rule


def _link(db, i1, i2):
    """Confirm a bi-directional link between two interfaces."""
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()


# ─── _upsert_finding idempotency ──────────────────────────────────────────────

def test_upsert_finding_inserts_first_time(db):
    f = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    assert f is not None
    assert db.query(Finding).count() == 1


def test_upsert_finding_skips_duplicate_open(db):
    _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    result = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    assert result is None
    assert db.query(Finding).count() == 1


def test_upsert_finding_reopens_after_closed(db):
    """After a finding is closed, upserting the same source_ref reopens the
    existing row rather than inserting a duplicate.  The result is the
    existing Finding with status reset to 'open', and only one DB row exists.
    """
    f = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    f.status = "closed"
    db.flush()
    result = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    assert result is not None
    assert result.status == "open"            # reopened in place
    assert db.query(Finding).count() == 1    # no duplicate row


def test_upsert_finding_skips_acknowledged(db):
    f = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    db.flush()
    f.status = "acknowledged"
    db.flush()
    result = _upsert_finding(db,
        category="config_review", check_name="test_check",
        severity="high", title="Test", source_ref="test:1-2",
    )
    assert result is None


# ─── _check_no_rules ──────────────────────────────────────────────────────────

def test_no_rules_fires_when_fw_has_no_rules(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    findings = _check_no_rules(db, fw1, fw2, iface)
    db.flush()
    assert len(findings) == 1
    assert findings[0].check_name == "cross_fw_no_rules"
    assert findings[0].severity == "high"


def test_no_rules_does_not_fire_when_fw_has_rules(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit")
    findings = _check_no_rules(db, fw1, fw2, iface)
    assert findings == []


# ─── _check_missing_deny_all ──────────────────────────────────────────────────

def test_missing_deny_all_fires_high_for_non_fortigate(db):
    # T3-39: PAN-OS/Cisco/pfSense are implicit-deny (-> info); only a vendor
    # without a known implicit deny stays high.
    fw1 = _fw(db, "FW-A", vendor="generic_router")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit", src="10.0.0.0/8")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_missing_deny_all(db, fw1, fw2, iface, rules)
    db.flush()
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].check_name == "cross_fw_missing_deny_all"


def test_missing_deny_all_fires_info_for_fortigate(db):
    fw1 = _fw(db, "FG-A", vendor="fortigate")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit", src="10.0.0.0/8")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_missing_deny_all(db, fw1, fw2, iface, rules)
    db.flush()
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_missing_deny_all_no_finding_when_deny_exists(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz", side="outside")
    _rule(db, fw1, "permit", src="10.0.0.0/8")
    _rule(db, fw1, "deny",   src="any", src_zone="outside")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_missing_deny_all(db, fw1, fw2, iface, rules)
    assert findings == []


# ─── _check_any_any_permit ────────────────────────────────────────────────────

def test_any_any_permit_fires_critical(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit", src="any", dst="any", policy_id="1")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_any_any_permit(db, fw1, fw2, iface, rules)
    db.flush()
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_name == "cross_fw_any_any_permit"
    assert findings[0].isa62443_sr == "SR 5.1 RE1"


def test_any_any_permit_ignores_deny_rules(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "deny", src="any", dst="any")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_any_any_permit(db, fw1, fw2, iface, rules)
    assert findings == []


def test_any_any_permit_specific_src_not_flagged(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit", src="10.0.0.1", dst="any")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_any_any_permit(db, fw1, fw2, iface, rules)
    assert findings == []


def test_any_any_permit_multiple_rules_multiple_findings(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    iface = _iface(db, fw1, "dmz")
    _rule(db, fw1, "permit", src="any", dst="any", policy_id="1")
    _rule(db, fw1, "permit", src="any", dst="any", policy_id="2")
    rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_any_any_permit(db, fw1, fw2, iface, rules)
    db.flush()
    assert len(findings) == 2


# ─── _check_asymmetric_permits ────────────────────────────────────────────────

def test_asymmetric_permits_fires_medium(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    # fw1 permits 10→20 on port 502, fw2 has nothing
    _rule(db, fw1, "permit", src="10.0.0.0/8", dst="20.0.0.0/8",
          dst_port="502", protocol="tcp", policy_id="fw1-p1")
    rules_a = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    rules_b = []
    findings = _check_asymmetric_permits(db, fw1, fw2, i1, i2, rules_a, rules_b)
    db.flush()
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].check_name == "cross_fw_asymmetric_permit"
    assert findings[0].isa62443_sr == "SR 5.2"


def test_asymmetric_permits_no_finding_when_peer_has_return(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _rule(db, fw1, "permit", src="10.0.0.0/8", dst="20.0.0.0/8",
          dst_port="502", protocol="tcp")
    # fw2 has the return direction: src=20, dst=10, same port/proto
    _rule(db, fw2, "permit", src="20.0.0.0/8", dst="10.0.0.0/8",
          dst_port="502", protocol="tcp")
    rules_a = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    rules_b = db.query(FirewallRule).filter_by(firewall_id=fw2.id).all()
    findings = _check_asymmetric_permits(db, fw1, fw2, i1, i2, rules_a, rules_b)
    assert findings == []


def test_asymmetric_permits_skips_any_any(db):
    """any→any rules are flagged by a different check; don't double-count."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _rule(db, fw1, "permit", src="any", dst="any")
    rules_a = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    findings = _check_asymmetric_permits(db, fw1, fw2, i1, i2, rules_a, [])
    assert findings == []


# ─── run_cross_fw_checks ─────────────────────────────────────────────────────

def test_run_checks_returns_summary(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    stats = run_cross_fw_checks(db)
    assert "links_analysed" in stats
    assert "findings_created" in stats
    assert "findings_skipped" in stats
    assert "by_check" in stats
    assert stats["links_analysed"] == 1


def test_run_checks_no_rules_detected(db):
    """Both FWs have no rules — should get no_rules finding for each."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    stats = run_cross_fw_checks(db)
    db.commit()
    assert stats["by_check"].get("cross_fw_no_rules", 0) == 2  # one per FW


def test_run_checks_any_any_permit_detected(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    _rule(db, fw1, "permit", src="any", dst="any", policy_id="bad-rule")
    _rule(db, fw2, "deny")  # give fw2 at least one rule
    stats = run_cross_fw_checks(db)
    db.commit()
    assert stats["by_check"].get("cross_fw_any_any_permit", 0) >= 1


def test_run_checks_idempotent_on_rerun(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    first = run_cross_fw_checks(db)
    db.commit()
    second = run_cross_fw_checks(db)
    db.commit()
    # Second run creates 0 new findings; they all skip
    assert second["findings_created"] == 0
    total_findings = db.query(Finding).count()
    assert total_findings == first["findings_created"]


def test_run_checks_skips_unconfirmed_links(db):
    """Interfaces with no connects_to_interface_id should not generate findings."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "dmz")   # no link
    _iface(db, fw2, "wan1")  # no link
    stats = run_cross_fw_checks(db)
    assert stats["links_analysed"] == 0
    assert stats["findings_created"] == 0


def test_run_checks_deduplicates_pair(db):
    """(A→B) and (B→A) are the same pair — only analysed once."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    stats = run_cross_fw_checks(db)
    assert stats["links_analysed"] == 1   # not 2


def test_run_checks_skips_same_fw_links(db):
    """Self-links on the same firewall (should never exist, but guard works)."""
    fw1 = _fw(db, "FW-A")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw1, "internal")
    # Manually create same-FW link — guard should filter it out
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()
    stats = run_cross_fw_checks(db)
    assert stats["links_analysed"] == 0


def test_run_checks_source_ref_stable_across_directions(db):
    """
    Confirming (A,B) vs (B,A) produces same source_ref, so findings are
    not duplicated if the same pair appears twice in the interface table.
    """
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    stats1 = run_cross_fw_checks(db)
    db.commit()
    # Reverse the "active" interface direction by checking from i2's side
    stats2 = run_cross_fw_checks(db)
    db.commit()
    # All findings from second run are skipped (source_ref already exists)
    assert stats2["findings_created"] == 0


def test_asymmetric_permit_finding_has_correct_isa_ref(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw2, "wan1")
    _link(db, i1, i2)
    _rule(db, fw1, "permit", src="10.0.0.0/8", dst="20.0.0.0/8",
          dst_port="502", protocol="tcp", policy_id="fw1-p1")
    _rule(db, fw2, "deny")
    run_cross_fw_checks(db)
    db.commit()
    finding = db.query(Finding).filter_by(
        check_name="cross_fw_asymmetric_permit"
    ).first()
    assert finding is not None
    assert finding.isa62443_sr == "SR 5.2"
    assert finding.severity == "medium"


def test_upsert_dedups_same_ref_within_one_run_without_autoflush():
    """A policy that expands to several rows yields the same source_ref more
    than once per run; with autoflush off (the app's sessions) the second must
    still be recognised as a duplicate instead of failing the commit."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, autoflush=False)()
    kw = dict(category="config_review", check_name="cross_fw_asymmetric_permit",
              severity="medium", title="t", detail={}, source_ref="dup:ref")
    assert _upsert_finding(s, **kw) is not None
    assert _upsert_finding(s, **kw) is None
    s.commit()
    assert s.query(Finding).filter(Finding.source_ref == "dup:ref").count() == 1
    s.close()


# ─── D-06: serial pairs only; destinations on the link segment ────────────────

def _levelled(db, fw, name, level, cidr=None, side="outside"):
    i = _iface(db, fw, name, side)
    i.purdue_level = level
    i.network_cidr = cidr
    db.flush()
    return i


def test_asymmetric_skipped_between_different_boundaries(db):
    """Two boundaries' firewalls sharing the DMZ segment: a permit on the
    inner one is not expected on the outer one (62 of 68 tabletop findings)."""
    edge, dmzl3 = _fw(db, "FG-EDGE-2"), _fw(db, "FG-DMZL3-1")
    _levelled(db, edge, "port1", 5)
    i_e = _levelled(db, edge, "port2", 3.5, "10.40.1.0/24")
    i_d = _levelled(db, dmzl3, "port1", 3.5, "10.40.1.0/24")
    _levelled(db, dmzl3, "port2", 3)
    _rule(db, dmzl3, "permit", src="10.40.1.20/32", dst="10.20.0.0/16", dst_port="3389", protocol="tcp")
    rules_d = db.query(FirewallRule).filter_by(firewall_id=dmzl3.id).all()
    assert _check_asymmetric_permits(db, dmzl3, edge, i_d, i_e, rules_d, []) == []
    # the same two firewalls on the SAME boundary: the check runs as before
    for i in db.query(FirewallInterface).filter_by(firewall_id=edge.id):
        i.purdue_level = {"port1": 3, "port2": 3.5}[i.name]
    db.flush()
    assert len(_check_asymmetric_permits(db, dmzl3, edge, i_d, i_e, rules_d, [])) == 1


def test_asymmetric_unknown_levels_still_compares(db):
    fw1, fw2 = _fw(db, "FW-A"), _fw(db, "FW-B")
    i1, i2 = _iface(db, fw1, "dmz"), _iface(db, fw2, "wan1")
    _rule(db, fw1, "permit", src="10.0.0.0/8", dst="20.0.0.0/8", dst_port="502", protocol="tcp")
    rules_a = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    assert len(_check_asymmetric_permits(db, fw1, fw2, i1, i2, rules_a, [])) == 1


def test_asymmetric_skips_destinations_on_the_link_segment(db):
    """A permit to a host that sits between the two firewalls never
    transits the peer, so the peer needs no counterpart."""
    fw1, fw2 = _fw(db, "FW-A"), _fw(db, "FW-B")
    i1 = _levelled(db, fw1, "p2", 3.5, "10.40.1.0/24")
    i2 = _levelled(db, fw2, "p1", 3.5, "10.40.1.0/24")
    _levelled(db, fw1, "p1", 4)
    _levelled(db, fw2, "p2", 4)
    _rule(db, fw1, "permit", src="10.10.0.0/16", dst="10.40.1.30/32", dst_port="443", protocol="tcp")
    _rule(db, fw1, "permit", src="10.10.0.0/16", dst="10.20.0.0/16", dst_port="443", protocol="tcp")
    rules_a = db.query(FirewallRule).filter_by(firewall_id=fw1.id).all()
    out = _check_asymmetric_permits(db, fw1, fw2, i1, i2, rules_a, [])
    assert len(out) == 1 and out[0].detail["dst"] == "10.20.0.0/16"


def test_run_checks_counts_skipped_links(db):
    edge, dmzl3 = _fw(db, "E"), _fw(db, "D")
    _levelled(db, edge, "port1", 5)
    i_e = _levelled(db, edge, "port2", 3.5)
    i_d = _levelled(db, dmzl3, "port1", 3.5)
    _levelled(db, dmzl3, "port2", 3)
    i_e.connects_to_interface_id = i_d.id
    i_d.connects_to_interface_id = i_e.id
    db.flush()
    out = run_cross_fw_checks(db)
    assert out["links_analysed"] == 1 and out["asymmetric_skipped_links"] == 1


# ─── D-07: shared segments ────────────────────────────────────────────────────

def test_segment_members_are_pairwise_checked(db):
    a, b, c = _fw(db, "A"), _fw(db, "B"), _fw(db, "C")
    for fw in (a, b, c):
        i = _levelled(db, fw, "dmz", 3.5, "10.40.1.0/24")
        i.segment = "seg-10.40.1.0/24"
    db.flush()
    out = run_cross_fw_checks(db)
    assert out["links_analysed"] == 3        # A-B, A-C, B-C
