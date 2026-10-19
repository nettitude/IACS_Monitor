"""
Interface aliases on the firewall pages (owner, 2026-10-12): "can the vlan's alias be
shown like the Subnets & Zones page".  GET /firewall-zones and GET /topology/state carry
each interface's config alias (FortiOS `set alias`); the console shows it in grey next
to / under the interface name (display only - rules and findings keep the real name).
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes import list_firewall_zones
from app.db import Base, configure_sqlite_engine
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.topology_manager import get_topology_state

_CFG = """config system global
    set hostname "fg-host"
end
config system interface
    edit "vlan_20"
        set ip 10.70.20.1 255.255.255.0
        set alias "Process Control"
        set vlanid 20
        set interface "port1"
    next
    edit "vlan_22"
        set ip 10.70.22.1 255.255.255.0
        set vlanid 22
        set interface "port1"
    next
end
config firewall policy
    edit 1
        set srcintf "vlan_22"
        set dstintf "vlan_20"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.mark.parametrize("fw_name", ["FW-DRUM", None])   # by firewall name, or by config hostname
def test_alias_on_zones_and_topology(db, fw_name):
    ingest_fortigate_config(_CFG, db, firewall_name=fw_name)
    db.commit()
    zones = {z["interface_name"]: z for z in list_firewall_zones(device_name=None, site_id=None, db=db)}
    assert zones["vlan_20"]["alias"] == "Process Control"
    assert zones["vlan_22"]["alias"] is None
    (fw,) = get_topology_state(db)["firewalls"]
    by = {i["name"]: i for i in fw["interfaces"]}
    assert by["vlan_20"]["alias"] == "Process Control" and by["vlan_22"]["alias"] is None
