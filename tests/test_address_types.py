"""FortiOS address-object types the owner's config uses (tabletop 2026-10-19): ``interface-subnet``
objects (static subnet, or 0.0.0.0 = the interface's own network), ``*.name`` in a plain fqdn object
(a wildcard), and ``dynamic`` EMS-tag objects (run-time membership -> an uncertain token)."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG

ADDR = """config system interface
    edit "vlan_20"
        set vdom "root"
        set ip 10.168.20.1 255.255.255.224
        set interface "port1"
        set vlanid 20
        set type vlan
    next
    edit "dmz"
        set vdom "root"
        set ip 10.168.99.1 255.255.255.0
        set type physical
    next
end
config firewall address
    edit "vlan_20 address"
        set type interface-subnet
        set subnet 10.168.20.0 255.255.255.224
        set interface "vlan_20"
    next
    edit "dmz"
        set type interface-subnet
        set subnet 0.0.0.0 255.255.255.255
        set interface "dmz"
    next
    edit "wildcard.google.com"
        set type fqdn
        set fqdn "*.google.com"
    next
    edit "EMS_ALL_UNKNOWN_CLIENTS"
        set type dynamic
        set sub-type ems-tag
    next
end
config firewall policy
    edit 20
        set name "to_vlan20"
        set srcintf "port1"
        set dstintf "vlan_20"
        set srcaddr "all"
        set dstaddr "vlan_20 address"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
    edit 21
        set name "to_dmz"
        set srcintf "port1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "dmz"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
    edit 22
        set name "google"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "EMS_ALL_UNKNOWN_CLIENTS"
        set dstaddr "wildcard.google.com"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_resolver_tokens():
    from app.parsers.forti_config_parser import _resolve_address, _addr_objects
    parsed = {"system interface": {"dmz": {"ip": ["10.168.99.1", "255.255.255.0"]}},
              "firewall address": {
                  "vlan_20 address": {"type": "interface-subnet", "subnet": ["10.168.20.0", "255.255.255.224"], "interface": "vlan_20"},
                  "dmz": {"type": "interface-subnet", "subnet": ["0.0.0.0", "255.255.255.255"], "interface": "dmz"},
                  "bond0 address": {"type": "interface-subnet", "subnet": ["0.0.0.0", "255.255.255.255"], "interface": "bond0"},
                  "wildcard.google.com": {"type": "fqdn", "fqdn": "*.google.com"},
                  "gmail.com": {"type": "fqdn", "fqdn": "gmail.com"},
                  "EMS_ALL_UNKNOWN_CLIENTS": {"type": "dynamic", "sub-type": "ems-tag"}}}
    ao = _addr_objects(parsed)
    r = lambda n: _resolve_address(n, ao, {})
    assert r("vlan_20 address") == ["10.168.20.0/27"]
    assert r("dmz") == ["10.168.99.0/24"]                    # the interface's network
    assert r("bond0 address") == ["unresolved:bond0 address"]  # no such interface / no address
    assert r("wildcard.google.com") == ["wildcard-fqdn:*.google.com"]
    assert r("gmail.com") == ["fqdn:gmail.com"]
    assert r("EMS_ALL_UNKNOWN_CLIENTS") == ["dynamic:EMS_ALL_UNKNOWN_CLIENTS"]
    assert parsed["firewall address"]["dmz"]["subnet"] == ["0.0.0.0", "255.255.255.255"]   # not mutated


def test_rules_and_fqdn_finding(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", ADDR))
    rules = {r["policy_id"]: r for r in c.get("/firewall-rules", params={"site_id": sid, "limit": 500}).json()}
    assert rules["20"]["dst"] == "10.168.20.0/27"
    assert rules["21"]["dst"] == "10.168.99.0/24"
    assert rules["22"]["src"] == "dynamic:EMS_ALL_UNKNOWN_CLIENTS"
    assert rules["22"]["dst"] == "wildcard-fqdn:*.google.com"
    fq = [f for f in _by(c, sid)["fqdn_in_policy"] if f["detail"].get("policy_id") in (22, "22")]
    assert fq and fq[0]["severity"] == "high"       # a wildcard, even in a plain fqdn object
    assert fq[0]["detail"]["obj_type"] == "wildcard-fqdn"
