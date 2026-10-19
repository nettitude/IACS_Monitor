"""Audit of the .36 additions (2026-10-19): the corrections the four reviewers' findings asked for."""
import ipaddress
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG
from tests.test_wireless_ot import _label, WIFI
from tests.test_fortiswitch import FSW
from app.parsers.forti_config_parser import (parse_forti_block, _resolve_address, _addr_objects, _place_source, extract_tunnels,
                                             _tunnel_nets, _config_evidence, _extract_dns_ntp, _is_default_dst)


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _sess():
    import app.main as main_mod
    from app.db import get_db
    return next(main_mod.app.dependency_overrides[get_db]())


# ---------------------------------------------------------------- FortiGate parser
LOCALIN_ALL = """config firewall addrgrp
    edit "grp_all"
        set member "all"
    next
end
config firewall local-in-policy
    edit 7
        set intf "wan1"
        set srcaddr "grp_all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set schedule "always"
    next
end
"""


def test_local_in_group_containing_all_is_high(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", LOCALIN_ALL))
    f = [x for x in _by(c, sid)["config_local_in_permits_all"] if x["detail"]["local_in_policy"] == "7"][0]
    assert f["severity"] == "high" and "outside the site" not in f["title"]


def test_default_route_row_reads_the_full_backup_form():
    assert _is_default_dst(None) and _is_default_dst(["0.0.0.0", "0.0.0.0"]) and _is_default_dst("0.0.0.0/0")
    assert not _is_default_dst(["10.1.0.0", "255.255.0.0"])
    parsed = parse_forti_block(CFG.replace("{CM}", """config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 203.0.113.1
        set device "wan1"
    next
end
"""))
    secs = {s["section"]: {r["setting"]: r["value"] for r in s["rows"]} for s in _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})}
    assert secs["Availability (rows 7.x, 9.9)"]["Default routes (router static)"].startswith("wan1 (distance 10")


def test_wireless_zone_membership_comes_from_system_zone(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wpa2-only-enterprise") + """config system zone
    edit "Wireless"
        set interface "ot-tunnel-ssid"
    next
end
""")
    _upload(c, text)
    assert not [f for f in _by(c, sid).get("config_wireless_not_isolated", []) if f["detail"]["interface"] == "ot-tunnel-ssid"]


def test_place_source_prefers_the_sites_own_networks_and_names_tokens():
    ctx = {"local_nets": [("10.168.1.0/24", "vlan_101", 3)], "routed_nets": [], "tunnel_interfaces": [],
           "tunnel_nets": [("10.0.0.0/8", "hub", "IPsec")]}
    assert _place_source("10.168.1.5/32", ctx)["kind"] == "local"          # not "remote" behind the /8 selector
    assert _place_source("10.9.9.9/32", ctx)["kind"] == "remote"
    assert _place_source("dynamic:EMS_ALL", ctx)["where"].startswith("EMS tag") and _place_source("any", ctx)["outside"]
    assert _place_source("cycle:g", ctx)["where"] == "group references itself"


def test_ntp_server_behind_a_selector_without_a_route_is_remote(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", """config vpn ipsec phase1-interface
    edit "hub"
        set interface "wan1"
        set remote-gw 203.0.113.9
        set psksecret ENC x
    next
end
config vpn ipsec phase2-interface
    edit "hub"
        set phase1name "hub"
        set dst-subnet 10.250.7.0 255.255.255.0
    next
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.250.7.5"
        next
        edit 2
            set server "0.pool.ntp.org"
        next
    end
end
"""))
    f = _by(c, sid)["config_ntp_fortiguard"][0]
    srv = {s["server"]: s for s in f["detail"]["servers"]}
    assert srv["10.250.7.5"]["kind"] == "remote" and "behind IPsec tunnel hub" in srv["10.250.7.5"]["where"]


def test_phase2_named_and_range_selectors_and_dialup_defaults():
    parsed = parse_forti_block(CFG.replace("{CM}", """config firewall address
    edit "remote_lan"
        set subnet 10.250.9.0 255.255.255.0
    next
end
config vpn ipsec phase1-interface
    edit "s2s"
        set interface "wan1"
        set remote-gw 203.0.113.9
        set psksecret ENC x
    next
    edit "dial"
        set type dynamic
        set interface "wan1"
        set mode-cfg enable
        set ipv4-start-ip 192.168.201.1
        set ipv4-end-ip 192.168.201.254
        set psksecret ENC x
    next
end
config vpn ipsec phase2-interface
    edit "s2s-named"
        set phase1name "s2s"
        set dst-addr-type name
        set dst-name "remote_lan"
    next
    edit "s2s-range"
        set phase1name "s2s"
        set src-addr-type range
        set src-start-ip 10.168.1.10
        set src-end-ip 10.168.1.20
        set dst-subnet 10.250.10.0 255.255.255.0
    next
    edit "dial"
        set phase1name "dial"
        set src-subnet 0.0.0.0 0.0.0.0
        set dst-subnet 0.0.0.0 0.0.0.0
    next
end
"""))
    t = extract_tunnels(parsed)
    sels = {s["name"]: s for s in t["s2s"]["selectors"]}
    assert sels["s2s-named"]["remote"] == "10.250.9.0/24" and sels["s2s-range"]["local"] == "10.168.1.10-10.168.1.20"
    # the dial-up's mandatory all-zero phase 2 does not undo the pool bound
    assert [s["name"] for s in t["dial"]["selectors"]] == ["dial-up pool"]
    nets = _tunnel_nets(parsed, t)
    assert ("10.250.9.0/24", "s2s", "IPsec") in nets and ("10.250.10.0/24", "s2s", "IPsec") in nets


def test_link_monitor_site_names_are_not_third_parties(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", """config system link-monitor
    edit "wan1_monitor"
        set srcintf "wan1"
        set server "gw.plant.local" "8.8.8.8"
    next
end
"""))
    assert "config_link_monitor_external" not in _by(c, sid)


def test_bridged_ssid_prefers_the_labelled_parent_for_a_reused_tag(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wpa2-only-personal").replace('''    edit "port1.20"''', '''    edit "wan1.20"
        set vdom "root"
        set ip 10.10.21.1 255.255.255.0
        set interface "wan1"
        set vlanid 20
        set type vlan
    next
    edit "port1.20"'''))
    _upload(c, text)
    _label(c, "port1.20", 1)
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_wireless_in_ot"] if x["detail"].get("vlan_id") in (20, "20")][0]
    assert f["detail"]["interface"] == "port1.20" and f["severity"] == "high"


# ---------------------------------------------------------------- Access Review narrowing
def test_narrowing_leaves_other_families_and_flags_only_real_cuts():
    from app.parsers import access_paths as ap, rule_match as rm

    class R:
        firewall_id, src_zone, dst_zone = 1, "ipsecgw", "vlan_101"
    tok = ap._TUNNEL_SELECTORS.set({(1, "ipsecgw"): (rm.parse_address("10.250.1.0/24", v6_default_is_any=False), None)})
    try:
        v6 = (rm.parse_address("2001:db8::/32", v6_default_is_any=False), rm.parse_address("2001:db8:1::/48", v6_default_is_any=False),
              rm.parse_protocols("tcp"), rm.parse_ports("443"))
        piece, narrowed = ap._narrow_by_selectors(R(), v6)
        assert piece[0] == v6[0] and narrowed is False                         # IPv6 rule, IPv4 selector: untouched
        inside = (rm.parse_address("10.250.1.0/25", v6_default_is_any=False), rm.parse_address("10.168.1.0/24", v6_default_is_any=False),
                  rm.parse_protocols("tcp"), rm.parse_ports("443"))
        assert ap._narrow_by_selectors(R(), inside)[1] is False               # already inside the selector: not "narrowed"
        wide = (rm.parse_address("10.0.0.0/8", v6_default_is_any=False),) + inside[1:]
        assert ap._narrow_by_selectors(R(), wide)[1] is True
    finally:
        ap._TUNNEL_SELECTORS.reset(tok)
    assert ap._TUNNEL_SELECTORS.get() is None


def test_enumeration_resets_the_selector_map(api):
    from app.parsers import access_paths as ap
    c, sid = api
    _upload(c, CFG.replace("{CM}", ""))
    c.get("/access-paths", params={"site_id": sid})
    assert ap._TUNNEL_SELECTORS.get() is None


# ---------------------------------------------------------------- classification
def test_object_name_vetoes_and_declaration_precedence(api):
    from app.parsers.device_classification import classify_object_name as k
    assert k("Domain_Controller_01") == (None, None) and k("Wireless-Controller") == (None, None)
    assert k("SMTP_Relay") == (None, None) and k("Fire_Panel_Host") == (None, None) and k("SW_Update_Server") == (None, None)
    assert k("AP_Server") == (None, None) and k("Eng_Printer") == (None, None) and k("james") == (None, None)
    assert k("Vendor_Controller") == ("plc", None) and k("Operator_HMI_2") == ("hmi", None) and k("FortiAP_01") == (None, "ap")
    from app.parsers.subnet_zones import _WEAK
    assert "object_name" in _WEAK
    # re-uploads do not flip a labelled host back and forth
    c, sid = api
    from tests.test_object_data import OBJ
    text = CFG.replace("{CM}", OBJ)
    _upload(c, text)
    _label(c, "vlan_101", 3)
    _upload(c, text)
    h = {x["ip"]: x for x in c.get("/hosts", params={"site_id": sid, "limit": 500}).json()}["10.168.1.31"]
    assert h["device_type"] == "plc" and h["classification_source"] == "interface_label" and float(h["purdue_level"]) == 3
    _upload(c, text)
    h2 = {x["ip"]: x for x in c.get("/hosts", params={"site_id": sid, "limit": 500}).json()}["10.168.1.31"]
    assert h2["classification_source"] == "interface_label"


# ---------------------------------------------------------------- FortiSwitch
FSW2 = FSW.replace('''            edit "port24"
                set fortilink-port enable
                set type trunk
            next''', '''            edit "port24"
                set fortilink-port enable
                set type trunk
            next
            edit "port47"
                set isl-peer-device-name "sw-ot-02"
                set isl-peer-port-name "port48"
                set isl-peer-device-sn "S124EPTF00000002"
            next
            edit "port10"
            next
            edit "port11"
            next
            edit "lag1"
                set type trunk
                set members "port10" "port11"
            next''').replace('''    edit "vlan_30"
        set vdom "root"
        set ip 10.10.30.1 255.255.255.0
        set interface "fortilink"
        set vlanid 30
        set type vlan
    next''', '''    edit "port2.20"
        set vdom "root"
        set ip 10.10.21.1 255.255.255.0
        set interface "port2"
        set vlanid 20
        set type vlan
    next
    edit "vlan_30"
        set vdom "root"
        set ip 10.10.30.1 255.255.255.0
        set interface "fortilink"
        set vlanid 30
        set type vlan
    next''')


def test_isl_and_lag_ports_are_uplinks_and_vlan_names_follow_the_ports(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FSW2))
    from app.models import SwitchInterface, SwitchVlan
    s = _sess()
    ports = {r.port_name: r for r in s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-01")}
    assert ports["port47"].uplink and ports["port47"].neighbor_device == "sw-ot-02" and ports["port47"].neighbor_protocol == "isl"
    assert ports["lag1"].uplink and ports["port10"].uplink and ports["port11"].uplink and ports["port24"].vlan is None
    v20 = s.query(SwitchVlan).filter(SwitchVlan.device_name == "sw-ot-01", SwitchVlan.vlan_id == 20).one()
    assert v20.vlan_name == "vlan_20"                       # not "port2.20", the other parent's interface with tag 20
    s.close()
    c.post("/reviews/run", params={"site_id": sid})
    by = _by(c, sid)
    assert [p["port"] for p in by["switch_port_no_nac"][0]["detail"]["ports"]] == ["port2", "port4"]
    assert by["switch_unused_port_enabled"][0]["detail"]["ports"] == ["port2"]


def test_removed_switch_rows_go_and_other_firewalls_rows_stay(api):
    c, sid = api
    from app.models import SwitchInterface
    two = FSW.replace('''    edit "S124EPTF00000001"''', '''    edit "S124EPTF00000009"
        set fsw-wan1-peer "fortilink"
        set name "sw-ot-09"
        config ports
            edit "port1"
                set vlan "vlan_20"
            next
        end
    next
    edit "S124EPTF00000001"''')
    _upload(c, CFG.replace("{CM}", two))
    s = _sess()
    assert s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-09").count() == 1
    s.close()
    _upload(c, CFG.replace("{CM}", FSW))                    # FGT-MFA no longer manages sw-ot-09
    s = _sess()
    assert s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-09").count() == 0
    s.close()
    # a second firewall naming the same switch takes it over (one row per site / switch / port), never a 500
    _upload(c, CFG.replace("{CM}", FSW).replace('set hostname "FGT-MFA"', 'set hostname "FGT-B"'), name="FGT-B")
    s = _sess()
    rows = s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-01").all()
    assert len(rows) == 6 and {r.source_file for r in rows} == {"fortilink:FGT-B"}
    s.close()


def test_malformed_vlan_ranges_are_skipped():
    from app.parsers.switch_parser import _vlan_tokens
    assert _vlan_tokens("20-22,40") == ["20", "21", "22", "40"] and _vlan_tokens("20-") == [] and _vlan_tokens("-5") == []
