"""
FW Topology Builder: interface admin state (owner, 2026-10-12): "have a default view
of only enabled ports and interfaces. Disable interfaces should be greyed out when
shown. Have a toggle or check box to show disabled interfaces."

GET /topology/state interfaces carry `status` (config admin state) and `enabled`
(False for `set status down`); a re-ingest refreshes it.  The console hides
disabled interfaces by default (smoke: ui_smoke_index.fwtopo_disabled).
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.topology_manager import get_topology_state

_CFG = """config system global
    set hostname "FW-T"
end
config system interface
    edit "port1"
        set ip 10.60.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.60.2.1 255.255.255.0
{STATUS}    next
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port1"
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


def _ifaces(db):
    (fw,) = get_topology_state(db)["firewalls"]
    return {i["name"]: i for i in fw["interfaces"]}


def test_status_down_is_disabled_and_reingest_refreshes_it(db):
    ingest_fortigate_config(_CFG.replace("{STATUS}", "        set status down\n"), db, firewall_name="FW-T")
    db.commit()
    i = _ifaces(db)
    assert i["port1"]["status"] is None and i["port1"]["enabled"] is True     # absent = up
    assert i["port2"]["status"] == "down" and i["port2"]["enabled"] is False

    # the interface is brought up in the next config: the same row is updated
    ingest_fortigate_config(_CFG.replace("{STATUS}", ""), db, firewall_name="FW-T")
    db.commit()
    i2 = _ifaces(db)
    assert i2["port2"]["id"] == i["port2"]["id"]
    assert i2["port2"]["enabled"] is True and i2["port2"]["status"] is None


@pytest.mark.parametrize("status,enabled", [("up", True), ("down", False), ("DOWN", False), ("disable", False), (None, True)])
def test_enabled_flag_values(db, status, enabled):
    ingest_fortigate_config(_CFG.replace("{STATUS}", ""), db, firewall_name="FW-T")
    db.commit()
    from app.models import FirewallInterface
    row = db.query(FirewallInterface).filter(FirewallInterface.name == "port2").one()
    row.status = status
    db.commit()
    assert _ifaces(db)["port2"]["enabled"] is enabled


def test_mgmt_interface_inventory_carries_enabled(db):
    """Mgmt & Engineering lists interfaces with their admin state (owner 2026-10-12:
    disabled ones hidden / greyed like the FW Topology Builder)."""
    from app.parsers.mgmt_networks import interface_inventory
    ingest_fortigate_config(_CFG.replace("{STATUS}", "        set status down\n"), db, firewall_name="FW-T")
    db.commit()
    rows = {r["name"]: r for r in interface_inventory(db)}
    assert rows["port2"]["enabled"] is False and rows["port2"]["status"] == "down"
    assert rows["port1"]["enabled"] is True
