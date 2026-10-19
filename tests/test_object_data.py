"""Address objects tighten and clarify checks (owner 2026-10-19): local-in sources resolved, the dial-up
tunnel bounded by its pool and split-include, dial-up policy groups in the VPN MFA check, object names
as classification hints, the user-group evidence row."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG
from tests.test_wireless_ot import _label

OBJ = """config system interface
    edit "vlan_101"
        set vdom "root"
        set ip 10.168.1.1 255.255.255.0
        set interface "port1"
        set vlanid 101
        set type vlan
    next
    edit "Dialup_ipsec"
        set vdom "root"
        set type tunnel
    next
end
config firewall address
    edit "DRUMCROSS.TRI.OM.PPC_C3"
        set subnet 10.168.1.31 255.255.255.255
    next
    edit "DRUMCROSS.AGS.OM.NTP_01"
        set subnet 10.168.1.5 255.255.255.255
    next
    edit "DRUMCROSS.TRI.OM.SWIT01"
        set subnet 10.168.1.2 255.255.255.255
    next
    edit "plants_jumphost"
        set subnet 10.168.1.100 255.255.255.255
    next
    edit "vendor_access1"
        set subnet 8.8.8.50 255.255.255.255
    next
    edit "devops_management"
        set subnet 10.0.0.0 255.0.0.0
    next
    edit "vlan_101 address"
        set subnet 10.168.1.0 255.255.255.0
    next
    edit "remote_vpc"
        set subnet 10.250.1.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "ian_to_wan"
        set member "devops_management" "plants_jumphost" "vendor_access1" "remote_vpc"
    next
    edit "Dial_Up_Devices"
        set member "vlan_101 address"
    next
end
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "ian_to_wan"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set schedule "always"
    next
end
config user ldap
    edit "FortiTrust"
        set server "10.1.1.9"
    next
end
config user group
    edit "PE_users"
        set member "FortiTrust" "vendor1"
    next
end
config vpn ipsec phase1-interface
    edit "pri-ipsec"
        set interface "wan1"
        set remote-gw 203.0.113.9
        set psksecret ENC x
    next
    edit "Dialup_ipsec"
        set type dynamic
        set interface "wan1"
        set ike-version 2
        set mode-cfg enable
        set eap enable
        set ipv4-start-ip 192.168.201.1
        set ipv4-end-ip 192.168.201.254
        set ipv4-split-include "Dial_Up_Devices"
        set psksecret ENC x
    next
end
config vpn ipsec phase2-interface
    edit "pri-ipsec"
        set phase1name "pri-ipsec"
        set src-subnet 10.168.1.0 255.255.255.0
        set dst-subnet 10.250.1.0 255.255.255.0
    next
end
config firewall policy
    edit 10
        set name "Dialup_to_plant"
        set srcintf "Dialup_ipsec"
        set dstintf "vlan_101"
        set srcaddr "all"
        set dstaddr "all"
        set groups "PE_users"
        set service "RDP"
        set action accept
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_object_names_classify_hosts(api):
    from app.parsers.device_classification import classify_object_name
    assert classify_object_name("DRUMCROSS.TRI.OM.PPC_C3") == ("plc", None)
    assert classify_object_name("DRUMCROSS.AGS.OM.NTP_01") == ("site_ntp_server", None)
    assert classify_object_name("DRUMCROSS.TRI.OM.SWIT01") == (None, "switch")
    assert classify_object_name("plants_jumphost") == ("jump_host", None) and classify_object_name("vendor_access1") == (None, None)
    c, sid = api
    _upload(c, CFG.replace("{CM}", OBJ))
    hosts = {h["ip"]: h for h in c.get("/hosts", params={"site_id": sid, "limit": 500}).json()}
    assert hosts["10.168.1.31"]["device_type"] == "plc" and hosts["10.168.1.31"]["classification_source"] == "object_name"
    assert hosts["10.168.1.31"]["hostname"] == "DRUMCROSS.TRI.OM.PPC_C3"
    assert hosts["10.168.1.2"]["role"] == "switch" and hosts["10.168.1.5"]["device_type"] == "site_ntp_server"
    # a public address keeps the object name but is never classified by it (external service)
    assert hosts["8.8.8.50"]["hostname"] == "vendor_access1" and hosts["8.8.8.50"]["device_type"] is None


def test_local_in_sources_resolved(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", OBJ))
    f = _by(c, sid)["config_local_in_permits_all"][0]
    d = f["detail"]
    assert f["severity"] == "high" and d["external_sources"] == ["8.8.8.50/32"] and d["wide_sources"] == ["10.0.0.0/8"]
    # owner 2026-10-19: a network behind a tunnel (phase 2 selector of pri-ipsec) is remote = outside the site
    assert d["remote_sources"] == ["10.250.1.0/24"] and d["unplaced_sources"] == []
    assert d["source_places"]["10.250.1.0/24"] == "behind IPsec tunnel pri-ipsec (10.250.1.0/24)"
    assert d["source_places"]["10.168.1.100/32"] == "interface vlan_101"
    assert d["source_places"]["10.0.0.0/8"].startswith("contains this firewall's network 10.")
    assert d["source_count"] == 4 and "(4 address(es), 2 outside the site)" in f["title"]
    assert "1 are behind a VPN tunnel (remote)" in d["reason"]


def test_source_placement_kinds():
    from app.parsers.forti_config_parser import _place_source, _tunnel_nets, parse_forti_block
    ctx = {"local_nets": [("10.168.1.0/24", "vlan_101", 3)], "routed_nets": [("10.9.0.0/16", "port2"), ("10.250.2.0/24", "ipsecgw")],
           "tunnel_interfaces": ["ipsecgw"], "tunnel_nets": [("192.168.201.0/24", "Dialup_ipsec", "dial-up IPsec"), ("10.212.134.200/29", "ssl.root", "SSL-VPN")]}
    k = lambda t: (_place_source(t, ctx)["kind"], _place_source(t, ctx)["outside"])
    assert k("10.168.1.5/32") == ("local", False) and k("10.9.3.0/24") == ("internal", False)
    assert k("10.250.2.7/32") == ("remote", True) and k("192.168.201.10/32") == ("remote", True)
    assert k("10.212.134.201/32") == ("remote", True) and k("8.8.8.8/32") == ("external", True)
    assert k("fqdn:x.example.com") == ("external", True) and k("172.31.0.0/16") == ("unplaced", True)
    assert k("10.0.0.0/8") == ("wide", False)
    nets = _tunnel_nets(parse_forti_block(CFG.replace("{CM}", OBJ)))
    import ipaddress
    assert ("10.250.1.0/24", "pri-ipsec", "IPsec") in nets
    assert any(t == "Dialup_ipsec" and k == "dial-up IPsec" and ipaddress.ip_address("192.168.201.200") in ipaddress.ip_network(c) for c, t, k in nets)


def test_dialup_groups_and_evidence(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", OBJ))
    f = [x for x in _by(c, sid)["config_vpn_user_no_mfa"] if x["detail"]["group"] == "PE_users"][0]
    assert f["detail"]["group"] == "PE_users" and f["detail"]["users_without_mfa"] == ["FortiTrust", "vendor1"]
    assert f["detail"]["auth_sources"]["FortiTrust"] == "ldap server"
    from app.parsers.forti_config_parser import parse_forti_block, _config_evidence, _extract_dns_ntp
    parsed = parse_forti_block(CFG.replace("{CM}", OBJ))
    secs = {s["section"]: {r["setting"]: r["value"] for r in s["rows"]} for s in _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})}
    v = secs["Remote access and user groups (row 4.3)"]["User groups and who authenticates them (user group)"]
    assert "PE_users: LDAP server (MFA not visible), local" in v and "vendors: local" in v
    assert secs["Remote access and user groups (row 4.3)"]["SAML identity providers (user saml)"] == "not set (FortiOS default)"


SAML = """config user saml
    edit "FortiTrust"
        set entity-id "http://fw.example.net:9443/remote/saml/metadata/"
        set idp-entity-id "http://abc.fortitrustid.forticloud.com/saml-idp/x/metadata/"
        set idp-single-sign-on-url "https://abc.fortitrustid.forticloud.com/saml-idp/x/login/"
    next
    edit "Corp_IdP"
        set idp-single-sign-on-url "https://login.example.com/saml/sso"
    next
end
"""


def test_fortitrust_saml_counts_as_mfa(api):
    c, sid = api
    text = CFG.replace("{CM}", OBJ.replace('config user ldap\n    edit "FortiTrust"\n        set server "10.1.1.9"\n    next\nend\n', SAML)
                       .replace('set eap enable', 'set eap enable\n        set ike-saml-server "FortiTrust"')
                       .replace('set vlanid 101', 'set vlanid 101\n        set ike-saml-server "FortiTrust"'))
    assert "ike-saml-server" in text and text.count('edit "FortiTrust"') == 1
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_vpn_user_no_mfa"] if x["detail"]["group"] == "PE_users"][0]
    assert f["detail"]["users_without_mfa"] == ["vendor1"]
    assert f["detail"]["remote_sources"] == {"FortiTrust": "saml (FortiTrust ID, cloud MFA)"}
    from app.parsers.forti_config_parser import parse_forti_block, _config_evidence, _extract_dns_ntp, _saml_idps
    parsed = parse_forti_block(text)
    idps = _saml_idps(parsed)
    assert idps["FortiTrust"] == {"idp": "abc.fortitrustid.forticloud.com", "mfa": True, "used_by": ["Dialup_ipsec", "interface vlan_101"]}
    assert idps["Corp_IdP"] == {"idp": "login.example.com", "mfa": False, "used_by": []}
    secs = {s["section"]: {r["setting"]: r["value"] for r in s["rows"]} for s in _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})}
    v = secs["Remote access and user groups (row 4.3)"]
    assert "PE_users: SAML (FortiTrust ID, cloud MFA), local" in v["User groups and who authenticates them (user group)"]
    assert v["SAML identity providers (user saml)"] == ("FortiTrust: abc.fortitrustid.forticloud.com - FortiTrust ID (cloud MFA), IKE on Dialup_ipsec, interface vlan_101; "
                                                        "Corp_IdP: login.example.com (MFA not visible)")


def test_dialup_tunnel_bounded_by_pool_and_split_include(api):
    c, sid = api
    from app.parsers.forti_config_parser import parse_forti_block, extract_tunnels
    t = extract_tunnels(parse_forti_block(CFG.replace("{CM}", OBJ)))["dialup_ipsec"]
    assert t["dynamic"] and t["selectors"] == [{"name": "dial-up pool", "local": "10.168.1.0/24", "remote": "192.168.201.1-192.168.201.254",
                                               "split_include": ["Dial_Up_Devices"]}]
    _upload(c, CFG.replace("{CM}", OBJ))
    _label(c, "vlan_101", 3)
    _upload(c, CFG.replace("{CM}", OBJ))
    rows = c.get("/access-paths", params={"site_id": sid, "boundary_only": "true"}).json()["paths"]
    r = [x for x in rows if any(h.get("policy_id") in ("10", 10) for h in x["chain"])][0]
    assert "tunnel_selector" in r["flags"] and r["src"]["scope"] == "range:192.168.201.1-192.168.201.254" and r["dst"]["scope"] == "10.168.1.0/24"
