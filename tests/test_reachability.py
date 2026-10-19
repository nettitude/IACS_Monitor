"""
Tests for app/parsers/reachability.py
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, FirewallDevice, FirewallRule, Host
from app.parsers.reachability import compute_reachability, compute_path


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


def _make_fw(db, name, zone_from, zone_to):
    """Helper: create a FirewallDevice with boundary zones."""
    fw = FirewallDevice(
        name=name,
        vendor="fortigate",
        purdue_zone_from=zone_from,
        purdue_zone_to=zone_to,
    )
    db.add(fw)
    db.flush()
    return fw


def _make_rule(db, fw, action, src="any", dst="any", protocol="any",
               dst_port=None, rule_order=1):
    """Helper: create a FirewallRule for a device."""
    rule = FirewallRule(
        firewall_device_id=fw.id,
        device_name=fw.name,
        device_type="fortigate",
        src=src,
        dst=dst,
        protocol=protocol,
        dst_port=dst_port,
        action=action,
        rule_order=rule_order,
    )
    db.add(rule)
    db.flush()
    return rule


def _make_host(db, ip, purdue_level):
    """Helper: create a Host at a given Purdue level."""
    host = Host(ip=ip, purdue_level=purdue_level, sources=["test"])
    db.add(host)
    db.flush()
    return host


# ------------------------------------------------------------------ compute_reachability

def test_no_firewalls_matrix_all_no_policy(db):
    result = compute_reachability(db)
    assert result["matrix"] is not None
    assert result["enforcement_points"] == []
    # All pairs should be no_policy when there are no devices
    for key, entry in result["matrix"].items():
        assert entry["overall"] == "no_policy"


def test_permit_rule_yields_permitted(db):
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_reachability(db)
    entry = result["matrix"].get("3→2")
    assert entry is not None
    assert entry["overall"] == "permitted"


def test_deny_rule_yields_denied(db):
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="deny")
    db.commit()

    result = compute_reachability(db)
    entry = result["matrix"].get("3→2")
    assert entry is not None
    assert entry["overall"] == "denied"


def test_no_rules_on_device_yields_no_policy(db):
    # Device exists but has no rules
    _make_fw(db, "fw1", zone_from=3, zone_to=2)
    db.commit()

    result = compute_reachability(db)
    entry = result["matrix"].get("3→2")
    assert entry is not None
    assert entry["overall"] == "no_policy"


def test_enforcement_points_listed(db):
    _make_fw(db, "fw1", zone_from=3, zone_to=2)
    db.commit()

    result = compute_reachability(db)
    assert len(result["enforcement_points"]) == 1
    ep = result["enforcement_points"][0]
    assert ep["zone_lo"] == 2
    assert ep["zone_hi"] == 3


def test_levels_with_hosts(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    _make_host(db, "10.0.2.1", purdue_level=2)
    db.commit()

    result = compute_reachability(db)
    assert 3 in result["levels_with_hosts"]
    assert 2 in result["levels_with_hosts"]


def test_permit_overrides_deny_on_alternate_path(db):
    # Two paths: 3->2 (denied) and 3->4->2 (permitted via separate FWs)
    fw_direct = _make_fw(db, "fw-direct", zone_from=3, zone_to=2)
    _make_rule(db, fw_direct, action="deny")

    fw_34 = _make_fw(db, "fw-34", zone_from=3, zone_to=4)
    _make_rule(db, fw_34, action="permit")

    fw_42 = _make_fw(db, "fw-42", zone_from=4, zone_to=2)
    _make_rule(db, fw_42, action="permit")
    db.commit()

    result = compute_reachability(db)
    entry = result["matrix"].get("3→2")
    # There's a permitted alternate path
    assert entry["overall"] == "permitted"


def test_named_object_yields_unknown(db):
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    # Use a named object that can't be resolved
    _make_rule(db, fw, action="permit", src="group:IT-SERVERS")
    db.commit()

    result = compute_reachability(db)
    entry = result["matrix"].get("3→2")
    assert entry is not None
    assert entry["overall"] == "unknown"


def test_traffic_filter_applied(db):
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_reachability(db, src_ip="10.0.3.1", dst_ip="10.0.2.1")
    assert result["traffic_filter"]["src_ip"] == "10.0.3.1"
    assert result["traffic_filter"]["dst_ip"] == "10.0.2.1"


# ------------------------------------------------------------------ compute_path

def test_compute_path_no_src_level(db):
    # Host with no purdue_level set
    _make_host(db, "10.0.3.1", purdue_level=None)
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_level=2)
    assert result["overall"] == "unknown"
    assert result["error"] is not None


def test_compute_path_src_not_in_db(db):
    result = compute_path(db, src_ip="99.99.99.99", dst_level=2)
    assert result["overall"] == "unknown"
    assert result["error"] is not None


def test_compute_path_same_level_intra(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    _make_host(db, "10.0.3.2", purdue_level=3)
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_ip="10.0.3.2")
    assert result["overall"] == "intra_level"


def test_compute_path_permit(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    _make_host(db, "10.0.2.1", purdue_level=2)
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_ip="10.0.2.1")
    assert result["overall"] == "permitted"
    assert result["src_level"] == 3
    assert result["dst_level"] == 2


def test_compute_path_denied(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    _make_host(db, "10.0.2.1", purdue_level=2)
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="deny")
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_ip="10.0.2.1")
    assert result["overall"] == "denied"


def test_compute_path_no_policy(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_level=2)
    assert result["overall"] == "no_policy"


def test_compute_path_dst_level_explicit(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_level=2)
    assert result["overall"] == "permitted"
    assert result["dst_level"] == 2


def test_compute_path_contains_hop_info(db):
    _make_host(db, "10.0.3.1", purdue_level=3)
    _make_host(db, "10.0.2.1", purdue_level=2)
    fw = _make_fw(db, "fw1", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_path(db, src_ip="10.0.3.1", dst_ip="10.0.2.1")
    assert len(result["hops"]) >= 1
    hop = result["hops"][0]
    assert "boundary" in hop
    assert "boundary_decision" in hop


# --------------------------------------------------------- level filter tests

def test_src_level_filter_returns_only_matching_rows(db):
    # Two boundary devices: L4→L3 and L3→L2
    fw43 = _make_fw(db, "fw43", zone_from=4, zone_to=3)
    fw32 = _make_fw(db, "fw32", zone_from=3, zone_to=2)
    _make_rule(db, fw43, action="permit")
    _make_rule(db, fw32, action="permit")
    db.commit()

    result = compute_reachability(db, src_level=4)
    for key, cell in result["matrix"].items():
        assert cell["src_level"] == 4, f"Expected src_level=4 but got {cell['src_level']} in cell {key!r}"
    # L4→L3 direct path must be present
    assert "4→3" in result["matrix"]
    # L3→L2 (src=3) must NOT be present
    assert "3→2" not in result["matrix"]


def test_dst_level_filter_returns_only_matching_rows(db):
    fw43 = _make_fw(db, "fw43", zone_from=4, zone_to=3)
    fw32 = _make_fw(db, "fw32", zone_from=3, zone_to=2)
    _make_rule(db, fw43, action="permit")
    _make_rule(db, fw32, action="permit")
    db.commit()

    result = compute_reachability(db, dst_level=2)
    for key, cell in result["matrix"].items():
        assert cell["dst_level"] == 2, f"Expected dst_level=2 but got {cell['dst_level']} in cell {key!r}"
    # L3→L2 and L4→L2 (multi-hop) must both be present
    assert "3→2" in result["matrix"]
    assert "4→2" in result["matrix"]
    # L4→L3 (dst=3) must NOT be present
    assert "4→3" not in result["matrix"]


def test_src_and_dst_level_filter_single_cell(db):
    fw = _make_fw(db, "fw1", zone_from=4, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_reachability(db, src_level=4, dst_level=2)
    assert list(result["matrix"].keys()) == ["4→2"]
    assert result["matrix"]["4→2"]["overall"] == "permitted"
    assert result["traffic_filter"]["src_level"] == 4
    assert result["traffic_filter"]["dst_level"] == 2


def test_level_filter_combined_with_traffic_filter(db):
    # Permit rule only for TCP/502 — any other port is denied
    fw = _make_fw(db, "fw1", zone_from=4, zone_to=2)
    _make_rule(db, fw, action="permit", protocol="tcp", dst_port="502", rule_order=1)
    _make_rule(db, fw, action="deny",   protocol="any",                  rule_order=2)
    db.commit()

    result_permit = compute_reachability(db, src_level=4, dst_level=2, dst_port=502, protocol="tcp")
    assert result_permit["matrix"]["4→2"]["overall"] == "permitted"

    result_deny = compute_reachability(db, src_level=4, dst_level=2, dst_port=80, protocol="tcp")
    assert result_deny["matrix"]["4→2"]["overall"] == "denied"


def test_level_filter_no_policy_when_no_boundary(db):
    # No firewall devices at all
    result = compute_reachability(db, src_level=4, dst_level=2)
    assert "4→2" in result["matrix"]
    assert result["matrix"]["4→2"]["overall"] == "no_policy"


def test_level_filter_empty_matrix_when_no_match(db):
    # Only a L3→L2 boundary exists; asking for src_level=4 returns empty matrix
    fw = _make_fw(db, "fw32", zone_from=3, zone_to=2)
    _make_rule(db, fw, action="permit")
    db.commit()

    result = compute_reachability(db, src_level=4, dst_level=3)
    # No path from 4 to 3 — cell will say no_policy, not absent
    cell = result["matrix"].get("4→3")
    assert cell is not None
    assert cell["overall"] == "no_policy"
