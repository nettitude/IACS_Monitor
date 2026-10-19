"""
Phase 2 integration tests: LLDP/CDP role inference and the four new
periodic review checks that depend on Host.role.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import (
    Host, SwitchInterface, ApprovedHost, Baseline,
    FirewallZone, CHECK_TYPE_REFERENCE,
)
from app.parsers.device_classification import (
    classify_hosts_by_lldp_role,
    infer_role_from_platform,
    infer_role_from_hostname,
)
from app.parsers.alert_engine import (
    review_historian_in_control_zone,
    review_wireless_in_ot_zone,
    review_single_path_critical_devices,
    review_undocumented_lldp_devices,
)


# ─── fixture ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ─── CHECK_TYPE_REFERENCE completeness ────────────────────────────────────────

def test_phase2_ctr_entries_present():
    """All 8 new Phase 2 check_names are registered in CHECK_TYPE_REFERENCE."""
    expected = {
        "historian_in_control_zone",
        "mgmt_access_not_restricted",
        "wireless_in_ot_zone",
        "mgmt_access_from_wrong_zone",
        "single_path_critical_device",
        "no_path_redundancy_verified",
        "undocumented_lldp_device",
        "firmware_not_documented",
    }
    missing = expected - set(CHECK_TYPE_REFERENCE.keys())
    assert not missing, f"Missing CTR entries: {missing}"


def test_phase2_ctr_format():
    """Phase 2 CTR entries have the correct 4-tuple format."""
    phase2_keys = [
        "historian_in_control_zone", "mgmt_access_not_restricted",
        "wireless_in_ot_zone", "mgmt_access_from_wrong_zone",
        "single_path_critical_device", "no_path_redundancy_verified",
        "undocumented_lldp_device", "firmware_not_documented",
    ]
    valid_severities = {"critical", "high", "medium", "low", "info"}
    valid_categories = {"real_time", "periodic_review", "config_review"}
    for k in phase2_keys:
        sr, checklist, sev, cat = CHECK_TYPE_REFERENCE[k]
        assert sr, f"{k}: empty sr_ref"
        assert checklist, f"{k}: empty checklist_id"
        assert sev in valid_severities, f"{k}: unknown severity {sev!r}"
        assert cat in valid_categories, f"{k}: unknown category {cat!r}"


# ─── role inference unit tests ─────────────────────────────────────────────────

def test_infer_role_from_platform_plc():
    assert infer_role_from_platform("Siemens S7-300 CPU315-2 DP") == "plc"
    assert infer_role_from_platform("Rockwell CompactLogix 5370 L3") == "plc"
    assert infer_role_from_platform("Modicon M340 CPU") == "plc"


def test_infer_role_from_platform_switch():
    assert infer_role_from_platform("cisco WS-C3750X-24T-S") == "switch"
    assert infer_role_from_platform("Cisco Catalyst 2960") == "switch"


def test_infer_role_from_platform_ap():
    assert infer_role_from_platform("Cisco AIR-CAP2702I-A-K9") == "ap"
    assert infer_role_from_platform("Cisco Aironet 3500") == "ap"


def test_infer_role_from_platform_historian():
    assert infer_role_from_platform("OSIsoft PI Server 2018") == "historian"
    assert infer_role_from_platform("Wonderware InSQL") == "historian"


def test_infer_role_from_platform_no_match():
    assert infer_role_from_platform(None) is None
    assert infer_role_from_platform("Unknown Generic Device") is None


def test_infer_role_from_hostname_plc():
    assert infer_role_from_hostname("plc-line-01") == "plc"
    assert infer_role_from_hostname("plc01") == "plc"


def test_infer_role_from_hostname_hmi():
    assert infer_role_from_hostname("hmi-press-02") == "hmi"


def test_infer_role_from_hostname_historian():
    assert infer_role_from_hostname("historian-srv") == "historian"


def test_infer_role_from_hostname_switch():
    assert infer_role_from_hostname("sw-floor-01") == "switch"


def test_infer_role_from_hostname_no_match():
    assert infer_role_from_hostname(None) is None
    assert infer_role_from_hostname("device-42") is None
    assert infer_role_from_hostname("srv01") is None  # "srv" is NOT in the table (intentional)


# ─── classify_hosts_by_lldp_role ──────────────────────────────────────────────

def test_classify_lldp_role_from_cdp_platform(db):
    """CDP platform string drives role assignment on the neighbor host."""
    plc_host = Host(ip="10.0.1.10", mac="aa:bb:cc:dd:ee:01", sources=[])
    db.add(plc_host)
    db.flush()

    iface = SwitchInterface(
        device_name="sw-floor",
        port_name="GigabitEthernet1/0/1",
        neighbor_ip="10.0.1.10",
        neighbor_device="plc-line-01",
        neighbor_platform="Siemens S7-300 CPU315-2 DP",
        neighbor_protocol="cdp",
    )
    db.add(iface)
    db.flush()

    stats = classify_hosts_by_lldp_role(db)
    db.refresh(plc_host)

    assert plc_host.role == "plc"
    assert plc_host.role_source == "cdp"
    assert stats["role_applied"] == 1


def test_classify_lldp_role_from_hostname_fallback(db):
    """LLDP hostname token drives role when no platform string is present."""
    hmi_host = Host(ip="10.0.2.20", mac="aa:bb:cc:dd:ee:02", sources=[])
    db.add(hmi_host)
    db.flush()

    iface = SwitchInterface(
        device_name="sw-floor",
        port_name="GigabitEthernet1/0/2",
        neighbor_ip="10.0.2.20",
        neighbor_device="hmi-press-02",
        neighbor_platform=None,  # LLDP: no platform
        neighbor_protocol="lldp",
    )
    db.add(iface)
    db.flush()

    stats = classify_hosts_by_lldp_role(db)
    db.refresh(hmi_host)

    assert hmi_host.role == "hmi"
    assert hmi_host.role_source == "lldp"
    assert stats["role_applied"] == 1


def test_classify_lldp_role_does_not_overwrite_manual(db):
    """manual role_source is never touched by automatic inference."""
    host = Host(ip="10.0.1.30", mac="aa:bb:cc:dd:ee:03", sources=[],
                role="historian", role_source="manual")
    db.add(host)
    db.flush()

    iface = SwitchInterface(
        device_name="sw-floor",
        port_name="GigabitEthernet1/0/3",
        neighbor_ip="10.0.1.30",
        neighbor_device="plc-line-01",
        neighbor_platform="Siemens S7-300",
        neighbor_protocol="cdp",
    )
    db.add(iface)
    db.flush()

    classify_hosts_by_lldp_role(db)
    db.refresh(host)

    # Must not be overwritten by the CDP "plc" inference
    assert host.role == "historian"
    assert host.role_source == "manual"


def test_classify_lldp_cdp_wins_over_lldp_hostname(db):
    """CDP inference (from platform) is not downgraded by a later LLDP pass."""
    host = Host(ip="10.0.1.40", mac="aa:bb:cc:dd:ee:04", sources=[])
    db.add(host)
    db.flush()

    # First iface: LLDP, hostname says "switch"
    db.add(SwitchInterface(
        device_name="sw-core",
        port_name="GigabitEthernet2/0/1",
        neighbor_ip="10.0.1.40",
        neighbor_device="sw-floor-01",
        neighbor_platform=None,
        neighbor_protocol="lldp",
    ))
    # Second iface: CDP, platform says it's a PLC
    db.add(SwitchInterface(
        device_name="sw-floor",
        port_name="GigabitEthernet1/0/4",
        neighbor_ip="10.0.1.40",
        neighbor_device="plc-line-01",
        neighbor_platform="Siemens S7-300 CPU315",
        neighbor_protocol="cdp",
    ))
    db.flush()

    classify_hosts_by_lldp_role(db)
    db.refresh(host)

    # CDP platform inference wins; LLDP hostname should not downgrade it
    assert host.role == "plc"
    assert host.role_source == "cdp"


# ─── review_historian_in_control_zone ─────────────────────────────────────────

def test_historian_in_control_zone_fires(db):
    host = Host(ip="10.0.1.50", mac="aa:bb:cc:dd:ee:05", sources=[],
                role="historian", role_source="lldp", purdue_level=1)
    db.add(host)
    db.flush()

    findings = review_historian_in_control_zone(db)
    db.commit()

    assert len(findings) == 1
    assert "historian" in findings[0].title.lower()
    assert findings[0].checklist_id == "2.3"
    assert findings[0].severity == "high"


def test_historian_at_level3_does_not_fire(db):
    host = Host(ip="10.0.3.50", mac="aa:bb:cc:dd:ee:06", sources=[],
                role="historian", role_source="lldp", purdue_level=3)
    db.add(host)
    db.flush()

    findings = review_historian_in_control_zone(db)
    assert len(findings) == 0


def test_historian_no_purdue_level_does_not_fire(db):
    """Historian without a purdue_level doesn't fire (no data = no assertion)."""
    host = Host(ip="10.0.3.51", mac="aa:bb:cc:dd:ee:07", sources=[],
                role="historian", role_source="lldp", purdue_level=None)
    db.add(host)
    db.flush()

    findings = review_historian_in_control_zone(db)
    assert len(findings) == 0


# ─── review_wireless_in_ot_zone ───────────────────────────────────────────────

def test_wireless_in_ot_zone_fires(db):
    host = Host(ip="10.0.1.60", mac="aa:bb:cc:dd:ee:08", sources=[],
                role="ap", role_source="cdp", purdue_level=1)
    db.add(host)
    db.flush()

    findings = review_wireless_in_ot_zone(db)
    db.commit()

    assert len(findings) == 1
    assert "wireless" in findings[0].title.lower() or "ap" in findings[0].title.lower()
    assert findings[0].checklist_id == "2.6"


def test_wireless_at_level4_does_not_fire(db):
    host = Host(ip="10.0.4.60", mac="aa:bb:cc:dd:ee:09", sources=[],
                role="ap", role_source="cdp", purdue_level=4)
    db.add(host)
    db.flush()

    findings = review_wireless_in_ot_zone(db)
    assert len(findings) == 0


# ─── review_single_path_critical_devices ──────────────────────────────────────

def test_single_path_fires_for_plc_with_one_port(db):
    plc = Host(ip="10.0.1.70", mac="aa:bb:cc:dd:ee:10", sources=[],
               role="plc", role_source="cdp", purdue_level=1)
    db.add(plc)
    db.flush()

    db.add(SwitchInterface(
        device_name="sw-floor", port_name="Gi1/0/1",
        neighbor_ip="10.0.1.70",
        neighbor_device="plc-01",
        neighbor_platform="Siemens S7-300",
        neighbor_protocol="cdp",
    ))
    db.flush()

    findings = review_single_path_critical_devices(db)
    db.commit()

    assert len(findings) == 1
    assert findings[0].checklist_id == "7.1"
    assert "single" in findings[0].title.lower()


def test_single_path_does_not_fire_for_plc_with_two_ports(db):
    plc = Host(ip="10.0.1.71", mac="aa:bb:cc:dd:ee:11", sources=[],
               role="plc", role_source="cdp", purdue_level=1)
    db.add(plc)
    db.flush()

    for port in ("Gi1/0/1", "Gi2/0/1"):
        db.add(SwitchInterface(
            device_name="sw-floor", port_name=port,
            neighbor_ip="10.0.1.71",
            neighbor_device="plc-01",
            neighbor_platform="Siemens S7-300",
            neighbor_protocol="cdp",
        ))
    db.flush()

    findings = review_single_path_critical_devices(db)
    assert len(findings) == 0


def test_single_path_returns_empty_when_no_switch_data(db):
    plc = Host(ip="10.0.1.72", mac="aa:bb:cc:dd:ee:12", sources=[],
               role="plc", role_source="cdp", purdue_level=1)
    db.add(plc)
    db.flush()
    # No SwitchInterface rows at all

    findings = review_single_path_critical_devices(db)
    assert len(findings) == 0


# ─── review_undocumented_lldp_devices ─────────────────────────────────────────

def test_undocumented_lldp_device_fires(db):
    baseline = Baseline(name="test", is_active=True)
    db.add(baseline)
    db.flush()

    known = ApprovedHost(baseline_id=baseline.id, ip="10.0.1.80", role="plc")
    db.add(known)
    db.flush()

    # Unknown host with a role (would have been identified by LLDP)
    unknown = Host(ip="10.0.1.81", mac="aa:bb:cc:dd:ee:13", sources=[],
                   role="plc", role_source="lldp")
    db.add(unknown)
    db.flush()

    findings = review_undocumented_lldp_devices(db)
    db.commit()

    assert len(findings) == 1
    assert findings[0].checklist_id == "7.7"
    assert "10.0.1.81" in findings[0].title


def test_undocumented_lldp_device_does_not_fire_when_in_inventory(db):
    baseline = Baseline(name="test2", is_active=True)
    db.add(baseline)
    db.flush()

    db.add(ApprovedHost(baseline_id=baseline.id, ip="10.0.1.90", role="plc"))
    db.flush()

    host = Host(ip="10.0.1.90", mac="aa:bb:cc:dd:ee:14", sources=[],
                role="plc", role_source="cdp")
    db.add(host)
    db.flush()

    findings = review_undocumented_lldp_devices(db)
    assert len(findings) == 0


def test_undocumented_lldp_device_does_not_fire_without_baseline(db):
    """No baseline = review_undocumented_lldp_devices returns empty (correct)."""
    host = Host(ip="10.0.1.91", mac="aa:bb:cc:dd:ee:15", sources=[],
                role="hmi", role_source="lldp")
    db.add(host)
    db.flush()

    findings = review_undocumented_lldp_devices(db)
    assert len(findings) == 0


def test_host_without_role_not_flagged_by_undocumented(db):
    """Hosts with no LLDP/CDP role are NOT flagged by this check (covered by review_unknown_devices)."""
    baseline = Baseline(name="test3", is_active=True)
    db.add(baseline)
    db.flush()

    db.add(ApprovedHost(baseline_id=baseline.id, ip="10.0.1.100", role="plc"))
    db.flush()

    # Host with no role - should not appear in this check
    host = Host(ip="10.0.1.99", mac="aa:bb:cc:dd:ee:16", sources=[],
                role=None, role_source=None)
    db.add(host)
    db.flush()

    findings = review_undocumented_lldp_devices(db)
    assert len(findings) == 0
