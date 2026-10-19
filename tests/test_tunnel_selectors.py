"""IPsec phase 2 selectors bound the Access Review; VPN resilience evidence (owner 2026-10-19)."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG
from tests.test_wireless_ot import _label

VPN = """config system interface
    edit "wan2"
        set ip 198.51.100.2 255.255.255.248
        set role wan
    next
    edit "vlan_101"
        set vdom "root"
        set ip 10.168.1.1 255.255.255.0
        set interface "port1"
        set vlanid 101
        set type vlan
    next
    edit "ipsecgw"
        set vdom "root"
        set type tunnel
    next
end
config system ipsec-aggregate
    edit "ipsecgw"
        set member "pri-ipsec" "sec-ipsec"
    next
end
config vpn ipsec phase1-interface
    edit "pri-ipsec"
        set interface "wan1"
        set ike-version 2
        set remote-gw 198.51.100.7
        set aggregate-member enable
        set proposal aes256-sha512
        set dhgrp 19
        set psksecret ENC x
    next
    edit "sec-ipsec"
        set interface "wan2"
        set ike-version 2
        set monitor "pri-ipsec"
        set remote-gw 198.51.100.7
        set aggregate-member enable
        set proposal aes256-sha512
        set dhgrp 19
        set psksecret ENC x
    next
end
config vpn ipsec phase2-interface
    edit "pri-ipsec"
        set phase1name "pri-ipsec"
        set src-subnet 172.17.201.95 255.255.255.255
        set dst-subnet 10.250.1.0 255.255.255.0
    next
    edit "sec-ipsec"
        set phase1name "sec-ipsec"
        set src-subnet 172.17.201.95 255.255.255.255
        set dst-subnet 10.250.1.0 255.255.255.0
    next
end
config firewall address
    edit "Jumphost"
        set subnet 10.168.1.100 255.255.255.255
    next
    edit "Elsewhere"
        set subnet 10.99.0.0 255.255.0.0
    next
end
config firewall policy
    edit 1
        set name "Insolar_To_Jumphost"
        set srcintf "ipsecgw"
        set dstintf "vlan_101"
        set srcaddr "all"
        set dstaddr "Jumphost"
        set service "ALL"
        set action accept
    next
    edit 2
        set name "Dead"
        set srcintf "ipsecgw"
        set dstintf "vlan_101"
        set srcaddr "Elsewhere"
        set dstaddr "Jumphost"
        set service "HTTPS"
        set action accept
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_extract_tunnels_and_interface_info(api):
    from app.parsers.forti_config_parser import parse_forti_block, extract_tunnels
    t = extract_tunnels(parse_forti_block(CFG.replace("{CM}", VPN)))
    assert t["pri-ipsec"]["peer"] == "198.51.100.7" and t["pri-ipsec"]["wan_interface"] == "wan1" and t["pri-ipsec"]["backup_of"] is None
    assert t["sec-ipsec"]["backup_of"] == "pri-ipsec" and t["sec-ipsec"]["selectors"][0] == {"name": "sec-ipsec", "local": "172.17.201.95/32", "remote": "10.250.1.0/24"}
    assert t["ipsecgw"]["members"] == ["pri-ipsec", "sec-ipsec"] and len(t["ipsecgw"]["selectors"]) == 2 and t["ipsecgw"]["wan_interface"] == "wan1, wan2"
    c, sid = api
    _upload(c, CFG.replace("{CM}", VPN))
    from app.models import FirewallInterface
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    gw = s.query(FirewallInterface).filter(FirewallInterface.name == "ipsecgw").one()
    assert gw.tunnel_info["members"] == ["pri-ipsec", "sec-ipsec"] and gw.tunnel_info["selectors"][0]["remote"] == "10.250.1.0/24"
    s.close()


def test_access_review_rows_bounded_by_selectors(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", VPN))
    _label(c, "ipsecgw", 4)
    _label(c, "vlan_101", 3)
    _upload(c, CFG.replace("{CM}", VPN))
    rows = c.get("/access-paths", params={"site_id": sid, "boundary_only": "true"}).json()["paths"]
    mine = [r for r in rows if any(h.get("policy_id") in ("1", 1) for h in r["chain"])]
    assert mine, rows[:2]
    r = mine[0]
    assert r["src"]["scope"] == "10.250.1.0/24" and r["src"].get("policy_scope") == "any" and "tunnel_selector" in r["flags"]
    assert not [x for x in rows if any(h.get("policy_id") in ("2", 2) for h in x["chain"])]     # outside the selectors: no row


def test_resilience_evidence_rows(api):
    from app.parsers.forti_config_parser import parse_forti_block, _config_evidence, _extract_dns_ntp
    parsed = parse_forti_block(CFG.replace("{CM}", VPN))
    secs = {s["section"]: {r["setting"]: r["value"] for r in s["rows"]} for s in _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})}
    av = secs["Availability (rows 7.x, 9.9)"]
    assert av["Site-to-site IPsec tunnels (vpn ipsec phase1/phase2)"] == ("pri-ipsec via wan1 -> 198.51.100.7 [172.17.201.95/32 <-> 10.250.1.0/24]; "
                                                                        "sec-ipsec via wan2 -> 198.51.100.7 [172.17.201.95/32 <-> 10.250.1.0/24]")
    assert av["Redundant VPN tunnels"] == "sec-ipsec backs up pri-ipsec (wan2 / wan1); aggregate ipsecgw = pri-ipsec + sec-ipsec"
