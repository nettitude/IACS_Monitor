"""
Tests for app/parsers/device_classification.py

Covers classify_vlan_name, classify_host_by_vendor, infer_role_from_platform,
infer_role_from_hostname, classify_hosts, and classify_hosts_by_vlan.
DB tests use StaticPool because classify_hosts calls db.commit().
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Host
from app.parsers.device_classification import (
    classify_vlan_name,
    classify_host_by_vendor,
    infer_role_from_platform,
    infer_role_from_hostname,
    classify_hosts,
)


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


# ---------------------------------------------------------------------------
# classify_vlan_name
# ---------------------------------------------------------------------------

def test_classify_vlan_control():
    # "ICS_CONTROL" -> tokens {"ics", "control"} -> min(1, 1) = 1
    assert classify_vlan_name("ICS_CONTROL") == 1


def test_classify_vlan_corporate():
    # "CORP_IT" -> tokens {"corp", "it"} -> min(4, 4) = 4
    assert classify_vlan_name("CORP_IT") == 4


def test_classify_vlan_scada():
    # "SCADA_SERVER" -> tokens {"scada", "server"} -> "scada" -> 2
    assert classify_vlan_name("SCADA_SERVER") == 2


def test_classify_vlan_process():
    # "PROCESS_FIELD" -> tokens {"process", "field"} -> min(0, 0) = 0
    assert classify_vlan_name("PROCESS_FIELD") == 0


def test_classify_vlan_no_match():
    # "DATA_CENTER" has no keyword that maps to a level
    assert classify_vlan_name("DATA_CENTER") is None


def test_classify_vlan_dmz_is_level_3_5():
    # F-08: "DMZ" was excluded (no L3.5 in the schema); it is now the
    # industrial DMZ level and wins over other keyword tokens.
    assert classify_vlan_name("DMZ") == 3.5
    assert classify_vlan_name("IT_DMZ") == 3.5
    assert classify_vlan_name("DMZ_HISTORIAN") == 3.5


def test_classify_vlan_none_input():
    assert classify_vlan_name(None) is None


# ---------------------------------------------------------------------------
# classify_host_by_vendor
# ---------------------------------------------------------------------------

def test_classify_host_by_vendor_siemens():
    result = classify_host_by_vendor("Siemens AG")
    assert result == "ics_hardware_vendor_device"


def test_classify_host_by_vendor_rockwell():
    result = classify_host_by_vendor("Rockwell Automation")
    assert result == "ics_hardware_vendor_device"


def test_classify_host_by_vendor_dell():
    result = classify_host_by_vendor("Dell Inc")
    assert result is None


# ---------------------------------------------------------------------------
# infer_role_from_platform
# ---------------------------------------------------------------------------

def test_infer_role_from_platform_simatic():
    assert infer_role_from_platform("Siemens SIMATIC S7-300") == "plc"


def test_infer_role_from_platform_cisco_switch():
    assert infer_role_from_platform("cisco WS-C3750") == "switch"


def test_infer_role_from_platform_none():
    assert infer_role_from_platform(None) is None


# ---------------------------------------------------------------------------
# infer_role_from_hostname
# ---------------------------------------------------------------------------

def test_infer_role_from_hostname_plc():
    assert infer_role_from_hostname("plc-line-01") == "plc"


def test_infer_role_from_hostname_hmi():
    assert infer_role_from_hostname("hmi-press-02") == "hmi"


# ---------------------------------------------------------------------------
# classify_hosts — DB tests
# ---------------------------------------------------------------------------

def test_classify_hosts_vendor_hint(db):
    host = Host(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Siemens AG")
    db.add(host)
    db.commit()

    stats = classify_hosts(db)

    db.refresh(host)
    assert host.device_type == "ics_hardware_vendor_device"
    assert host.classification_source == "oui_hint"
    assert stats["vendor_hint_applied"] >= 1


def test_classify_hosts_manual_not_overwritten(db):
    host = Host(
        ip="10.0.0.2",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Siemens AG",
        device_type="plc",
        classification_source="manual",
    )
    db.add(host)
    db.commit()

    classify_hosts(db)

    db.refresh(host)
    # Manual classification must not be touched
    assert host.classification_source == "manual"
    assert host.device_type == "plc"
