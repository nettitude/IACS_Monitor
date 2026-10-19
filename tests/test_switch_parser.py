"""
Tests for app/parsers/switch_parser.py
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, SwitchInterface
from app.parsers.switch_parser import (
    parse_cisco_running_config_interfaces,
    parse_vlan_brief,
    parse_cdp_neighbors,
    parse_lldp_neighbors,
    parse_hp_running_config_interfaces,
    parse_hp_lldp_brief,
    parse_hp_lldp_detail,
    detect_switch_config_type,
    ingest_switch_config,
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


# ------------------------------------------------------------------ cisco running-config

CISCO_RUNNING_CONFIG = """\
hostname CORE-SW-01
!
vlan 10
 name ENGINEERING
!
vlan 20
 name ICS_CONTROL
!
interface GigabitEthernet1/0/1
 description Uplink to PLC-01
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/2
 description Trunk to Distribution
 switchport trunk allowed vlan 10,20-25
 switchport mode trunk
!
interface GigabitEthernet1/0/3
 description Unused
!
"""


def test_cisco_running_config_hostname():
    hostname, interfaces = parse_cisco_running_config_interfaces(CISCO_RUNNING_CONFIG)
    assert hostname == "CORE-SW-01"


def test_cisco_running_config_access_vlan():
    _, interfaces = parse_cisco_running_config_interfaces(CISCO_RUNNING_CONFIG)
    gi1 = next(i for i in interfaces if i["port_name"] == "GigabitEthernet1/0/1")
    assert gi1["vlan"] == "10"
    assert gi1["mode"] == "access"
    assert gi1["description"] == "Uplink to PLC-01"


def test_cisco_running_config_vlan_name_populated_for_access():
    _, interfaces = parse_cisco_running_config_interfaces(CISCO_RUNNING_CONFIG)
    gi1 = next(i for i in interfaces if i["port_name"] == "GigabitEthernet1/0/1")
    assert gi1["vlan_name"] == "ENGINEERING"


def test_cisco_running_config_trunk_vlan():
    _, interfaces = parse_cisco_running_config_interfaces(CISCO_RUNNING_CONFIG)
    gi2 = next(i for i in interfaces if i["port_name"] == "GigabitEthernet1/0/2")
    assert gi2["vlan"] == "10,20-25"
    assert gi2["mode"] == "trunk"
    assert gi2["vlan_name"] is None


def test_cisco_running_config_no_vlan():
    _, interfaces = parse_cisco_running_config_interfaces(CISCO_RUNNING_CONFIG)
    gi3 = next(i for i in interfaces if i["port_name"] == "GigabitEthernet1/0/3")
    assert gi3["vlan"] is None
    assert gi3["mode"] is None


def test_cisco_running_config_empty_input():
    hostname, interfaces = parse_cisco_running_config_interfaces("")
    assert hostname is None
    assert interfaces == []


# ------------------------------------------------------------------ cisco vlan brief

VLAN_BRIEF_TEXT = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------
1    default                          active
10   ENGINEERING                      active    Gi1/0/1, Gi1/0/3
20   ICS_CONTROL                      active    Gi1/0/2, Gi1/0/4,
                                                Gi1/0/5
"""


def test_vlan_brief_parses_vlan_and_name():
    entries = parse_vlan_brief(VLAN_BRIEF_TEXT)
    vlan10 = next(e for e in entries if e["vlan_id"] == "10")
    assert vlan10["vlan_name"] == "ENGINEERING"
    assert "Gi1/0/1" in vlan10["ports"]
    assert "Gi1/0/3" in vlan10["ports"]


def test_vlan_brief_continuation_ports():
    entries = parse_vlan_brief(VLAN_BRIEF_TEXT)
    vlan20 = next(e for e in entries if e["vlan_id"] == "20")
    assert "Gi1/0/4" in vlan20["ports"]
    assert "Gi1/0/5" in vlan20["ports"]


def test_vlan_brief_empty_ports():
    entries = parse_vlan_brief(VLAN_BRIEF_TEXT)
    vlan1 = next(e for e in entries if e["vlan_id"] == "1")
    assert vlan1["ports"] == []


def test_vlan_brief_empty_input():
    assert parse_vlan_brief("") == []


# ------------------------------------------------------------------ CDP neighbors

CDP_TEXT = """\
-------------------------
Device ID: PLC-SWITCH-01
Entry address(es):
  IP address: 192.168.1.10
Platform: cisco WS-C2960X-24TS-L,  Capabilities: Switch
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet0/1
-------------------------
Device ID: HMI-WORKSTATION
Entry address(es):
  IP address: 192.168.1.20
Platform: cisco WS-C3750X,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): GigabitEthernet0/2
"""


def test_cdp_neighbor_device_id():
    neighbors = parse_cdp_neighbors(CDP_TEXT)
    assert len(neighbors) == 2
    assert neighbors[0]["neighbor_device"] == "PLC-SWITCH-01"
    assert neighbors[1]["neighbor_device"] == "HMI-WORKSTATION"


def test_cdp_neighbor_interfaces():
    neighbors = parse_cdp_neighbors(CDP_TEXT)
    assert neighbors[0]["local_interface"] == "GigabitEthernet1/0/1"
    assert neighbors[0]["neighbor_port"] == "GigabitEthernet0/1"
    assert neighbors[0]["neighbor_ip"] == "192.168.1.10"


def test_cdp_neighbor_protocol():
    neighbors = parse_cdp_neighbors(CDP_TEXT)
    assert all(n["neighbor_protocol"] == "cdp" for n in neighbors)


def test_cdp_empty_input():
    assert parse_cdp_neighbors("") == []


# ------------------------------------------------------------------ LLDP neighbors

LLDP_TEXT = """\
------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 0011.2233.4455
Port id: Gi0/1
System Name: PLC-HMI-01
Management Addresses:
    IP: 10.0.1.10
------------------------------------------------
Local Intf: Gi1/0/3
Chassis id: aabb.ccdd.eeff
Port id: Gi0/2
System Name: ENG-WS-02
"""


def test_lldp_neighbor_local_intf():
    neighbors = parse_lldp_neighbors(LLDP_TEXT)
    assert len(neighbors) == 2
    assert neighbors[0]["local_interface"] == "Gi1/0/2"


def test_lldp_neighbor_device_name():
    neighbors = parse_lldp_neighbors(LLDP_TEXT)
    assert neighbors[0]["neighbor_device"] == "PLC-HMI-01"


def test_lldp_neighbor_protocol():
    neighbors = parse_lldp_neighbors(LLDP_TEXT)
    assert all(n["neighbor_protocol"] == "lldp" for n in neighbors)


def test_lldp_empty_input():
    assert parse_lldp_neighbors("") == []


# ------------------------------------------------------------------ HP running-config

HP_CONFIG = """\
hostname "HP-SWITCH-01"

vlan 10
   name "ENGINEERING"
   untagged 1-4,6
   exit
vlan 20
   name "ICS_CONTROL"
   tagged 5
   untagged 7
   exit
interface 1
   name "Uplink to Engineering Workstation"
   exit
interface 5
   name "Trunk port"
   exit
"""


def test_hp_running_config_hostname():
    hostname, _ = parse_hp_running_config_interfaces(HP_CONFIG)
    assert hostname == "HP-SWITCH-01"


def test_hp_running_config_access_vlan():
    _, interfaces = parse_hp_running_config_interfaces(HP_CONFIG)
    port1 = next(i for i in interfaces if i["port_name"] == "1")
    assert port1["vlan"] == "10"
    assert port1["mode"] == "access"
    assert port1["vlan_name"] == "ENGINEERING"


def test_hp_running_config_trunk_port():
    _, interfaces = parse_hp_running_config_interfaces(HP_CONFIG)
    port5 = next(i for i in interfaces if i["port_name"] == "5")
    assert port5["mode"] == "trunk"
    assert "20" in port5["vlan"]


def test_hp_running_config_description():
    _, interfaces = parse_hp_running_config_interfaces(HP_CONFIG)
    port1 = next(i for i in interfaces if i["port_name"] == "1")
    assert port1["description"] == "Uplink to Engineering Workstation"


def test_hp_running_config_empty():
    hostname, interfaces = parse_hp_running_config_interfaces("")
    assert hostname is None
    assert interfaces == []


# ------------------------------------------------------------------ HP LLDP brief

HP_LLDP_BRIEF = """\
LocalPort | ChassisId               PortId   PortDescr SysName
--------- + ------------------------ -------- --------- ----------
1         | 00 00 00 12 34 ab        1        Port 1    plc-hmi-01
2         | aa bb cc dd ee ff        2        Port 2    eng-ws-01
"""


def test_hp_lldp_brief_parse():
    neighbors = parse_hp_lldp_brief(HP_LLDP_BRIEF)
    assert len(neighbors) == 2
    assert neighbors[0]["local_interface"] == "1"
    assert neighbors[0]["neighbor_device"] == "plc-hmi-01"
    assert neighbors[0]["neighbor_protocol"] == "lldp"


def test_hp_lldp_brief_mac_normalization():
    neighbors = parse_hp_lldp_brief(HP_LLDP_BRIEF)
    # The chassis ID "00 00 00 12 34 ab" should get normalized
    assert neighbors[0]["neighbor_device"] == "plc-hmi-01"


# ------------------------------------------------------------------ HP LLDP detail

HP_LLDP_DETAIL = """\
 Local Port   : 1
 Chassis Id     : 00 00 00 12 34 ab
 Port Id        : 1
 System Name    : plc-hmi-01
 Remote Management Address
      Type    : ipv4
      Address : 10.0.1.10
 Local Port   : 2
 Chassis Id     : aa bb cc dd ee ff
 Port Id        : 2
 System Name    : eng-ws-01
"""


def test_hp_lldp_detail_parse():
    neighbors = parse_hp_lldp_detail(HP_LLDP_DETAIL)
    assert len(neighbors) == 2
    assert neighbors[0]["local_interface"] == "1"
    assert neighbors[0]["neighbor_device"] == "plc-hmi-01"
    assert neighbors[0]["neighbor_ip"] == "10.0.1.10"


# ------------------------------------------------------------------ detect type

def test_detect_cisco_running_config():
    assert detect_switch_config_type(CISCO_RUNNING_CONFIG) == "running_config"


def test_detect_vlan_brief():
    assert detect_switch_config_type(VLAN_BRIEF_TEXT) == "vlan_brief"


def test_detect_cdp():
    assert detect_switch_config_type(CDP_TEXT) == "cdp_neighbors"


def test_detect_lldp():
    assert detect_switch_config_type(LLDP_TEXT) == "lldp_neighbors"


def test_detect_hp_running_config():
    assert detect_switch_config_type(HP_CONFIG) == "hp_running_config"


def test_detect_hp_lldp_brief():
    assert detect_switch_config_type(HP_LLDP_BRIEF) == "hp_lldp_brief"


def test_detect_hp_lldp_detail():
    assert detect_switch_config_type(HP_LLDP_DETAIL) == "hp_lldp_detail"


def test_detect_unknown():
    assert detect_switch_config_type("nothing relevant here") == "unknown"


# ------------------------------------------------------------------ ingest / DB

def test_ingest_cisco_running_config_creates_rows(db):
    stats = ingest_switch_config(CISCO_RUNNING_CONFIG, db, device_name="CORE-SW-01")
    assert stats["config_type"] == "running_config"
    assert stats["interfaces_touched"] >= 3
    ifaces = db.query(SwitchInterface).filter(SwitchInterface.device_name == "CORE-SW-01").all()
    assert len(ifaces) >= 3


def test_ingest_cisco_running_config_vlan_set(db):
    ingest_switch_config(CISCO_RUNNING_CONFIG, db, device_name="CORE-SW-01")
    gi1 = db.query(SwitchInterface).filter(
        SwitchInterface.device_name == "CORE-SW-01",
        SwitchInterface.port_name == "GigabitEthernet1/0/1",
    ).first()
    assert gi1 is not None
    assert gi1.vlan == "10"
    assert gi1.vlan_name == "ENGINEERING"


def test_ingest_no_duplicate_rows_on_re_ingest(db):
    ingest_switch_config(CISCO_RUNNING_CONFIG, db, device_name="CORE-SW-01")
    count_before = db.query(SwitchInterface).count()
    ingest_switch_config(CISCO_RUNNING_CONFIG, db, device_name="CORE-SW-01")
    count_after = db.query(SwitchInterface).count()
    assert count_after == count_before


def test_ingest_cdp_neighbor_data(db):
    ingest_switch_config(CDP_TEXT, db, device_name="CORE-SW-01")
    iface = db.query(SwitchInterface).filter(
        SwitchInterface.device_name == "CORE-SW-01",
        SwitchInterface.port_name == "GigabitEthernet1/0/1",
    ).first()
    assert iface is not None
    assert iface.neighbor_device == "PLC-SWITCH-01"
    assert iface.neighbor_protocol == "cdp"


def test_ingest_empty_input_no_rows(db):
    stats = ingest_switch_config("", db, device_name="CORE-SW-01")
    assert stats["interfaces_touched"] == 0
    assert db.query(SwitchInterface).count() == 0


def test_ingest_hp_config_creates_rows(db):
    stats = ingest_switch_config(HP_CONFIG, db, device_name="HP-SWITCH-01")
    assert stats["config_type"] == "hp_running_config"
    assert stats["interfaces_touched"] > 0


def test_ingest_vlan_brief_creates_rows(db):
    stats = ingest_switch_config(VLAN_BRIEF_TEXT, db, device_name="CORE-SW-01")
    assert stats["config_type"] == "vlan_brief"
    assert stats["interfaces_touched"] > 0
    gi1 = db.query(SwitchInterface).filter(
        SwitchInterface.port_name == "Gi1/0/1",
    ).first()
    assert gi1 is not None
    assert gi1.vlan == "10"
    assert gi1.vlan_name == "ENGINEERING"
