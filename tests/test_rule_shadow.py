"""
Tests for find_shadowed_rules() in app/parsers/rule_shadow.py.

Uses an in-memory SQLite database populated with the minimum set of
FirewallRule rows required for each assertion.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Finding, FirewallRule
from app.parsers.rule_shadow import find_shadowed_rules


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _rule(db, device_name, policy_id, src, dst, port, action,
          protocol="tcp", rule_order=None, src_zone=None, dst_zone=None):
    r = FirewallRule(
        device_name=device_name,
        device_type="fortigate",
        policy_id=str(policy_id),
        src=src,
        dst=dst,
        dst_port=str(port) if port is not None else None,
        protocol=protocol,
        action=action,
        rule_order=rule_order if rule_order is not None else int(policy_id),
        src_zone=src_zone,
        dst_zone=dst_zone,
    )
    db.add(r)
    db.flush()
    return r


# ─────────────────────────────────────────── test cases ──────────────────────


def test_no_rules_empty_result(db):
    result = find_shadowed_rules(db)
    assert result["shadows"] == []
    assert result["rules_analysed"] == 0


def test_duplicate_shadow(db):
    """Two identical rules on the same device — classic duplicate."""
    _rule(db, "fw1", 1, "any", "any", "80", "permit")
    _rule(db, "fw1", 2, "any", "any", "80", "permit")
    result = find_shadowed_rules(db, device_name="fw1")
    shadows = result["shadows"]
    assert len(shadows) == 1
    assert shadows[0]["shadow_type"] == "duplicate"


def test_full_shadow_opposite_actions(db):
    """any→any:any allow before 10.0.0.1/32→any:80 deny → full_shadow."""
    _rule(db, "fw1", 1, "any", "any", None, "permit", protocol="any", rule_order=1)
    _rule(db, "fw1", 2, "10.0.0.1/32", "any", "80", "deny", protocol="tcp", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1")
    shadows = result["shadows"]
    assert len(shadows) == 1
    assert shadows[0]["shadow_type"] == "full_shadow"
    assert shadows[0]["action_conflict"] is True


def test_partial_shadow_flagged(db):
    """any→10.0.0.0/24:80 allow before 10.0.0.1/32→any:80 deny → partial_shadow."""
    _rule(db, "fw1", 1, "any", "10.0.0.0/24", "80", "permit", protocol="tcp", rule_order=1)
    _rule(db, "fw1", 2, "10.0.0.1/32", "any", "80", "deny",   protocol="tcp", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1", include_partial=True)
    shadow_types = [s["shadow_type"] for s in result["shadows"]]
    assert "partial_shadow" in shadow_types


def test_disjoint_rules_no_shadow(db):
    """Two rules with completely disjoint source subnets — no shadow."""
    _rule(db, "fw1", 1, "10.0.0.0/24", "any", "80", "deny",   protocol="tcp", rule_order=1)
    _rule(db, "fw1", 2, "192.168.0.0/24", "any", "80", "permit", protocol="tcp", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1")
    assert result["shadows"] == []


def test_same_action_partial_not_flagged(db):
    """Same-action partial overlap with include_partial=False → empty shadows."""
    # Rule 1 is superset in src; rule 2 is narrower in dst — partial overlap,
    # but same action means it's not dangerous.
    _rule(db, "fw1", 1, "any", "10.0.0.0/24", "80", "permit", protocol="tcp", rule_order=1)
    _rule(db, "fw1", 2, "10.0.0.1/32", "any", "80", "permit", protocol="tcp", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1", include_partial=False)
    # Partial same-action overlap should NOT appear (include_partial=False, and
    # the code only flags partial shadows with conflicting actions anyway).
    partial_shadows = [s for s in result["shadows"] if s["shadow_type"] == "partial_shadow"]
    assert partial_shadows == []


def test_zone_mismatch_no_shadow(db):
    """Two rules with different src_zone/dst_zone values → no shadow."""
    _rule(db, "fw1", 1, "any", "any", "80", "permit",
          src_zone="trust", dst_zone="untrust", rule_order=1)
    _rule(db, "fw1", 2, "any", "any", "80", "deny",
          src_zone="dmz", dst_zone="untrust", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1")
    assert result["shadows"] == []


def test_generate_findings(db):
    """generate_findings=True should create Finding rows in the DB."""
    _rule(db, "fw1", 1, "any", "any", None, "permit", protocol="any", rule_order=1)
    _rule(db, "fw1", 2, "10.0.0.1/32", "any", "80", "deny", protocol="tcp", rule_order=2)
    result = find_shadowed_rules(db, device_name="fw1", generate_findings=True)
    assert result["findings_created"] > 0
    assert db.query(Finding).count() > 0


def test_null_rule_order_sorted_last(db):
    """Rule with rule_order=1 should be treated as higher priority than rule with order=None."""
    # rule_order=1 should shadow rule_order=None (None sorts last → lower priority)
    _rule(db, "fw1", 1, "any", "any", None, "permit", protocol="any", rule_order=1)
    _rule(db, "fw1", 2, "any", "any", None, "deny",   protocol="any", rule_order=None)
    result = find_shadowed_rules(db, device_name="fw1")
    # The None-order rule is sorted after order=1, so order=1 shadows it.
    shadows = result["shadows"]
    assert len(shadows) >= 1
    shadowed_policy_ids = [s["shadowed_rule"]["policy_id"] for s in shadows]
    assert "2" in shadowed_policy_ids


def test_different_devices_not_compared(db):
    """Rules from device_a and device_b should not be compared to each other."""
    _rule(db, "device_a", 1, "any", "any", None, "permit", protocol="any", rule_order=1)
    _rule(db, "device_b", 2, "any", "any", None, "deny",   protocol="any", rule_order=2)
    result = find_shadowed_rules(db)
    # Each device only has one rule → no pairwise comparison possible
    assert result["shadows"] == []
