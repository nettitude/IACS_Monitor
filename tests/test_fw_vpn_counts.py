"""
Firewall Devices: VPN policies and grouped counts (owner, 2026-10-12: "do 1, 2 and 3. On the
firewall devices UI page for active rules, disable rules and NAT rules use the grouped row
counts").

  GET /firewall-devices  policy_count / disabled_policy_count / vpn_policy_count - one per
                         policy line (device, VDOM, policy id, action, state), as the rules
                         drill-down groups them; rule_count / disabled_rule_count stay rows
  GET /firewall-zones    "tunnel": SSL / dial-up IPsec / site-to-site IPsec / L2TP per
                         interface (the console's VPN badges and filter)
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes import _tunnel_kind, list_firewall_devices, list_firewall_zones
from app.db import Base, configure_sqlite_engine
from app.parsers.forti_config_parser import ingest_fortigate_config

CFG = """config system global
    set hostname "FW-VPN"
end
config system interface
    edit "port1"
        set ip 10.168.1.1 255.255.255.0
        set alias "Monitoring"
    next
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
    edit "Dialup_ipsec"
        set type tunnel
        set interface "wan1"
    next
    edit "ipsecgw"
        set type tunnel
        set interface "wan1"
    next
    edit "ssl.root"
        set type tunnel
    next
end
config vpn ipsec phase1-interface
    edit "Dialup_ipsec"
        set type dynamic
        set interface "wan1"
        set peertype any
        set mode-cfg enable
        set psksecret ENC xxx
    next
    edit "ipsecgw"
        set interface "wan1"
        set remote-gw 198.51.100.7
        set psksecret ENC xxx
    next
end
config user group
    edit "PE_users"
        set member "pe1"
    next
    edit "SSL_users"
        set member "u1"
    next
end
config vpn ssl settings
    set servercert "self-sign"
    set source-interface "wan1"
end
config firewall address
    edit "h1"
        set subnet 10.168.1.100 255.255.255.255
    next
    edit "h2"
        set subnet 10.168.1.101 255.255.255.255
    next
end
config firewall addrgrp
    edit "HOSTS"
        set member "h1" "h2"
    next
end
config firewall policy
    edit 200
        set name "PE_VPN_Monitoring"
        set srcintf "Dialup_ipsec"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "HOSTS"
        set service "HTTPS" "SSH"
        set action accept
        set groups "PE_users"
    next
    edit 1
        set name "Site_To_Jumphost"
        set srcintf "ipsecgw"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "h1"
        set service "ALL"
        set action accept
    next
    edit 2
        set name "Jumphost_To_Site"
        set srcintf "port1"
        set dstintf "ipsecgw"
        set srcaddr "HOSTS"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 300
        set name "SSL_to_Monitoring"
        set srcintf "ssl.root"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "h1"
        set service "HTTPS"
        set action accept
        set groups "SSL_users"
    next
    edit 400
        set name "Plain"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "HOSTS"
        set dstaddr "all"
        set service "HTTPS" "DNS"
        set action accept
    next
    edit 401
        set name "Old"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "HOSTS"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set status disable
    next
end
"""


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    ingest_fortigate_config(CFG, s, firewall_name="FW-VPN")
    s.commit()
    yield s
    s.close()


def _devices(db):
    import inspect
    params = inspect.signature(list_firewall_devices).parameters
    kw = {k: None for k in params if k not in ("db",)}
    return list_firewall_devices(**kw, db=db)


def test_grouped_counts(db):
    (d,) = _devices(db)
    assert (d["rule_count"], d["disabled_rule_count"]) == (14, 2)           # expanded rows
    assert (d["policy_count"], d["disabled_policy_count"]) == (5, 1)        # policy lines
    assert d["vpn_policy_count"] == 4                                       # 200, 1, 2, 300


def test_tunnel_kinds(db):
    z = {r["interface_name"]: r["tunnel"] for r in list_firewall_zones(device_name=None, site_id=None, db=db)}
    assert z["Dialup_ipsec"] == "dial-up IPsec"
    assert z["ipsecgw"] == "site-to-site IPsec"
    assert z["ssl.root"] == "SSL"
    assert z["port1"] is None and z["wan1"] is None


@pytest.mark.parametrize("args,kind", [
    (("tunnel", "ssl", "ssl.root"), "SSL"), (("tunnel", "ipsec_dialup", "dial"), "dial-up IPsec"),
    (("tunnel", None, "l2t.root"), "L2TP"), (("tunnel", None, "naf.root"), None),
    (("tunnel", None, "to-hq"), "site-to-site IPsec"), (("physical", None, "port1"), None),
])
def test_tunnel_kind(args, kind):
    assert _tunnel_kind(*args) == kind
