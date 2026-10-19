"""
Host VLAN from the firewall / routing-switch VLAN interface (owner, 2026-10-12: "for the
asset inventory, why does the VLAN not show based on the uploaded config" -> "yes, do the
VLAN from firewall interface").

A host with no VLAN of its own takes the VLAN id of the interface whose subnet holds its
address (FortiOS `set vlanid`), vlan_source "fw_interface"; MAC tables, 802.1Q captures
and the inventory keep theirs; the /24 guess is replaced; interfaces of the same network
that disagree give no VLAN; /assets says which interface it came from.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import Firewall, FirewallInterface, Host, Site
from app.parsers.device_classification import (
    assign_vlans_from_interfaces, classify_hosts, interface_vlan_for, vlan_interfaces,
)
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.site_scope import ingest_site

CFG = """config system global
    set hostname "FW-V"
end
config system interface
    edit "port1"
        set ip 10.90.0.1 255.255.255.0
    next
    edit "vlan_20"
        set ip 10.90.20.1 255.255.255.0
        set alias "Process Control"
        set vlanid 20
        set interface "port1"
    next
    edit "vlan_22"
        set ip 10.90.22.1 255.255.255.0
        set vlanid 22
        set interface "port1"
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


@pytest.fixture
def site(db):
    s = Site(name="V", code="v")
    db.add(s)
    db.flush()
    with ingest_site(db, s.id):
        ingest_fortigate_config(CFG, db, firewall_name="FW-V")
    db.commit()
    return s.id


def _host(db, sid, ip, vlan=None, src=None):
    h = Host(site_id=sid, ip=ip, vlan=vlan, vlan_source=src)
    db.add(h)
    db.flush()
    return h


def test_hosts_take_the_interface_vlan(db, site):
    a = _host(db, site, "10.90.20.15")
    b = _host(db, site, "10.90.22.7")
    c = _host(db, site, "10.90.0.9")                 # port1: no VLAN id
    d = _host(db, site, "192.168.1.1")               # no interface
    stats = assign_vlans_from_interfaces(db)
    assert (a.vlan, a.vlan_source) == ("20", "fw_interface")
    assert (b.vlan, b.vlan_source) == ("22", "fw_interface")
    assert c.vlan is None and d.vlan is None
    assert stats["vlan_from_interface"] == 2


@pytest.mark.parametrize("src", ["mac_table", "pcap_8021q", "manual"])
def test_stronger_sources_kept(db, site, src):
    h = _host(db, site, "10.90.20.15", vlan="99", src=src)
    assign_vlans_from_interfaces(db)
    assert (h.vlan, h.vlan_source) == ("99", src)


def test_subnet_guess_replaced(db, site):
    h = _host(db, site, "10.90.20.15", vlan="99", src="subnet_inference")
    assign_vlans_from_interfaces(db)
    assert (h.vlan, h.vlan_source) == ("20", "fw_interface")


def test_value_cleared_when_no_interface_supports_it(db, site):
    h = _host(db, site, "10.90.20.15")
    assign_vlans_from_interfaces(db)
    db.query(FirewallInterface).filter(FirewallInterface.name == "vlan_20").update({FirewallInterface.vlan_id: None})
    db.flush()
    stats = assign_vlans_from_interfaces(db)
    assert h.vlan is None and h.vlan_source is None and stats["vlan_from_interface_cleared"] == 1


def test_disagreeing_interfaces_give_no_vlan(db, site):
    fw2 = Firewall(name="FW-W", site_id=site)
    db.add(fw2)
    db.flush()
    db.add(FirewallInterface(firewall_id=fw2.id, name="vlan_30", network_cidr="10.90.20.0/24",
                             ip_cidr="10.90.20.2/24", vlan_id="30"))
    db.flush()
    h = _host(db, site, "10.90.20.15")
    assign_vlans_from_interfaces(db)
    assert h.vlan is None
    idx = vlan_interfaces(db)[site]
    assert interface_vlan_for("10.90.22.7", idx)[1] == "22"


def test_other_site_interfaces_ignored(db, site):
    other = Site(name="O", code="o")
    db.add(other)
    db.flush()
    h = _host(db, other.id, "10.90.20.15")
    assign_vlans_from_interfaces(db)
    assert h.vlan is None


def test_runs_inside_classify_hosts(db, site):
    h = _host(db, site, "10.90.20.15")
    db.commit()
    stats = classify_hosts(db, site_id=site)
    db.refresh(h)
    assert h.vlan == "20" and stats["vlan_from_interface"] == 1


def test_assets_api_names_the_interface(db, site):
    from app.api.routes import list_assets
    from fastapi import Response
    _host(db, site, "10.90.20.15")
    assign_vlans_from_interfaces(db)
    db.commit()
    rows = list_assets(Response(), limit=100, offset=0, purdue_level=None, device_type=None, role=None,
                       criticality=None, approved=None, location=None, search=None, inventory=None,
                       site=None, site_id=site, db=db)
    (r,) = [x for x in rows if x["ip"] == "10.90.20.15"]
    assert r["vlan"] == "20" and r["vlan_source"] == "fw_interface"
    assert r["vlan_origin"] == "FW-V vlan_20 (Process Control), 10.90.20.0/24"
