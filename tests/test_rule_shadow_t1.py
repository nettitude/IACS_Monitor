"""
Tier-1 regression tests for app/parsers/rule_shadow.py (T1-33, part of T3-38).
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import FirewallRule
from app.parsers import rule_shadow
from app.parsers.rule_shadow import find_shadowed_rules


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _rule(db, device, order, src, dst, port, action, protocol="tcp"):
    r = FirewallRule(device_name=device, device_type="fortigate", policy_id=str(order),
                     src=src, dst=dst, dst_port=port, protocol=protocol,
                     action=action, rule_order=order)
    db.add(r)
    db.flush()
    return r


def test_mixed_ipv4_ipv6_does_not_crash(db):
    _rule(db, "fw1", 1, "2001:db8::/32", "any", "80", "permit")
    _rule(db, "fw1", 2, "10.0.0.0/24", "any", "80", "deny")
    _rule(db, "fw1", 3, "10.0.0.0/8", "2001:db8::1/128", "80", "deny")
    _rule(db, "fw1", 4, "10.0.0.5/32", "any", "80", "permit")
    _rule(db, "fw2", 1, "any", "any", "80", "permit")
    _rule(db, "fw2", 2, "any", "any", "80", "permit")
    result = find_shadowed_rules(db)
    assert result["devices_failed"] == []
    # the IPv6 rule must not shadow IPv4 rules
    assert not any(s["shadowing_rule"]["src"] == "2001:db8::/32" for s in result["shadows"])
    # fw1: 10.0.0.5/32 permit is fully shadowed by 10.0.0.0/24 deny
    fw1 = [s for s in result["shadows"] if s["shadowed_rule"]["device_name"] == "fw1"]
    assert any(s["shadowed_rule"]["policy_id"] == "4" and s["shadow_type"] == "full_shadow"
               for s in fw1)
    # fw2 still analysed
    assert any(s["shadowed_rule"]["device_name"] == "fw2" and s["shadow_type"] == "duplicate"
               for s in result["shadows"])


@pytest.mark.parametrize("anyaddr,host", [("0.0.0.0/0", "10.0.0.1/32"),
                                          ("::/0", "2001:db8::1/128")])
def test_default_route_cidrs_are_any(db, anyaddr, host):
    # F-07: a family-wide CIDR covers every address of ITS family only.
    _rule(db, "fw1", 1, anyaddr, anyaddr, None, "permit", protocol="any")
    _rule(db, "fw1", 2, host, "any", "80", "deny")
    result = find_shadowed_rules(db, device_name="fw1")
    assert [s["shadow_type"] for s in result["shadows"]] == ["full_shadow"]


def test_ipv6_default_route_does_not_shadow_ipv4(db):
    _rule(db, "fw1", 1, "::/0", "::/0", None, "permit", protocol="any")
    _rule(db, "fw1", 2, "10.0.0.1/32", "any", "80", "deny")
    assert find_shadowed_rules(db, device_name="fw1")["shadows"] == []


def test_per_device_errors_are_isolated(db, monkeypatch):
    _rule(db, "bad", 1, "any", "any", "80", "permit")
    _rule(db, "bad", 2, "any", "any", "80", "permit")
    _rule(db, "good", 1, "any", "any", "80", "permit")
    _rule(db, "good", 2, "any", "any", "80", "permit")
    real = rule_shadow._check_shadow

    def boom(earlier, later):
        if earlier.rule.device_name == "bad":
            raise TypeError("simulated")
        return real(earlier, later)

    monkeypatch.setattr(rule_shadow, "_check_shadow", boom)
    result = find_shadowed_rules(db)
    assert len(result["devices_failed"]) == 1
    assert "bad" in result["devices_failed"][0]["group"]
    assert [s["shadowed_rule"]["device_name"] for s in result["shadows"]] == ["good"]


def test_canonical_port_list_superset(db):
    _rule(db, "fw1", 1, "any", "any", "80,443,1000-2000", "permit")
    _rule(db, "fw1", 2, "any", "any", "443", "deny")
    _rule(db, "fw1", 3, "any", "any", "1500-1600", "deny")
    _rule(db, "fw1", 4, "any", "any", "22", "deny")
    result = find_shadowed_rules(db, device_name="fw1")
    shadowed = sorted(s["shadowed_rule"]["policy_id"] for s in result["shadows"]
                      if s["shadow_type"] == "full_shadow")
    assert shadowed == ["2", "3"]


def test_legacy_and_canonical_ports_compare(db):
    _rule(db, "fw1", 1, "any", "any", "gt 1023", "permit")
    _rule(db, "fw1", 2, "any", "any", "2000-3000", "deny")
    result = find_shadowed_rules(db, device_name="fw1")
    assert [s["shadow_type"] for s in result["shadows"]] == ["full_shadow"]


@pytest.mark.parametrize("raw", ["unknown:SVC", "alias:WEB"])
def test_unresolved_port_is_unanalysed(db, raw):
    _rule(db, "fw1", 1, "any", "any", None, "permit", protocol="any")
    _rule(db, "fw1", 2, "any", "any", raw, "deny")
    result = find_shadowed_rules(db, device_name="fw1")
    assert result["rules_unanalysed"] == 1
    assert result["shadows"] == []
