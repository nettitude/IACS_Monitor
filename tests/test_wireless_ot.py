"""Wireless in OT (owner 2026-10-19): SSID placement, PSK on an OT SSID, WEP, evidence."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG
from tests.test_ntp_source import _label_port1

WIFI = """config system interface
    edit "port1.20"
        set vdom "root"
        set ip 10.10.20.1 255.255.255.0
        set interface "port1"
        set vlanid 20
        set type vlan
    next
    edit "ot-tunnel-ssid"
        set vdom "root"
        set ip 10.10.30.1 255.255.255.0
        set type vap-switch
    next
end
config wireless-controller wtp
    edit "FP231FTF00000001"
        set wtp-profile "FAP231F-default"
    next
end
config wireless-controller wtp-profile
    edit "FAP231F-default"
        set wids-profile "default"
        config radio-1
            set vaps "plant-bridged" "ot-tunnel-ssid"
        end
        config radio-2
            set mode disabled
        end
    next
end
config wireless-controller vap
    edit "plant-bridged"
        set ssid "PLANT-BRIDGED"
        set security {SEC}
        set passphrase ENC p
        set local-bridging enable
        set vlanid 20
    next
    edit "ot-tunnel-ssid"
        set ssid "OT-TUNNEL"
        set security wpa2-only-enterprise
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _label(c, name, level):
    from app.models import FirewallInterface
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    for i in s.query(FirewallInterface).filter(FirewallInterface.name == name):
        i.purdue_level = level
    s.commit(); s.close()


def test_bridged_psk_ssid_on_an_ot_vlan(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wpa2-only-personal"))
    _upload(c, text)
    assert "config_wireless_in_ot" not in _by(c, sid)                     # no labels yet
    _label(c, "port1.20", 1)
    _upload(c, text)
    by = _by(c, sid)
    f = by["config_wireless_in_ot"][0]
    assert f["severity"] == "high" and f["detail"]["lands_on"] == "VLAN 20 (port1.20)" and f["detail"]["mode"] == "bridge"
    assert f["detail"]["managed_aps"] == ["FP231FTF00000001"] and f["detail"]["passphrase_set"] is True
    psk = [x for x in by["config_wireless_weak_security"] if x["detail"]["vap"] == "plant-bridged"][0]
    assert psk["severity"] == "low" and "pre-shared key" in psk["title"]
    assert not [x for x in by["config_wireless_weak_security"] if x["detail"]["vap"] == "ot-tunnel-ssid"]   # enterprise


def test_wep_on_an_ot_vlan_is_high_and_medium_elsewhere(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wep128"))
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["detail"]["vap"] == "plant-bridged"][0]
    assert f["severity"] == "medium" and f["detail"]["in_ot"] is False
    _label(c, "port1.20", 2)
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["detail"]["vap"] == "plant-bridged"][0]
    assert f["severity"] == "high" and "in an OT network" in f["title"]


def test_tunnel_mode_ssid_on_a_labelled_interface(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wpa2-only-personal"))
    _upload(c, text)
    _label(c, "ot-tunnel-ssid", 1)
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_wireless_in_ot"] if x["detail"]["vap"] == "ot-tunnel-ssid"][0]
    assert f["detail"]["mode"] == "tunnel" and f["detail"]["lands_on"].startswith("tunnel-mode interface ot-tunnel-ssid")
    iso = _by(c, sid).get("config_wireless_not_isolated", [])
    assert any(x["detail"]["interface"] == "ot-tunnel-ssid" for x in iso)       # vap-switch now recognised


def test_evidence_section_and_registration(api):
    from app.parsers.forti_config_parser import parse_forti_block, _config_evidence, _extract_dns_ntp, FORTIGATE_CONFIG_CHECKS
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app import writeup as wu
    from app.config_store import CHECK_SECTIONS
    parsed = parse_forti_block(CFG.replace("{CM}", WIFI.replace("{SEC}", "wpa2-only-personal")))
    secs = {s["section"]: {r["setting"]: r["value"] for r in s["rows"]} for s in _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})}
    w = secs["Wireless (row 2.5)"]
    assert w["Wireless SSIDs (wireless-controller vap)"] == "plant-bridged: wpa2-only-personal, bridged to VLAN 20; ot-tunnel-ssid: wpa2-only-enterprise, tunnel mode"
    assert w["Managed access points (wireless-controller wtp)"] == "1" and w["WIDS profile on AP profiles (wtp-profile wids-profile)"] == "FAP231F-default: default"
    n = "config_wireless_in_ot"
    assert n in CHECK_TYPE_REFERENCE and n in FORTIGATE_CONFIG_CHECKS and n in EXPLAIN and n in CHECK_SECTIONS and n in wu.FORTI and n in wu.CIS


def test_ssid_not_broadcast_is_informational(api):
    c, sid = api
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wep128").replace('set vaps "plant-bridged" "ot-tunnel-ssid"', 'set vaps "ot-tunnel-ssid"'))
    _upload(c, text)
    f = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["detail"]["vap"] == "plant-bridged"][0]
    assert f["severity"] == "info" and "not broadcast (not assigned to any radio of an AP profile)" in f["title"] and f["detail"]["active"] is False
    # controller disabled: every SSID is dead configuration
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wep128")).replace('set hostname "FGT-MFA"', 'set hostname "FGT-MFA"\n    set wireless-controller disable')
    _upload(c, text, name="FGT-MFA-2")
    offs = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["device_name"] == "FGT-MFA-2"]
    assert offs and all("wireless controller disabled" in x["title"] for x in offs)
    # no managed AP and no FortiWiFi profile -> not broadcast; a FortiWiFi profile stands in for the built-in radio
    text = CFG.replace("{CM}", WIFI.replace("{SEC}", "wep128").replace('edit "FP231FTF00000001"', 'edit "FP231FTF00000001"\n        set admin disable'))
    _upload(c, text, name="FGT-MFA-3")
    f = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["device_name"] == "FGT-MFA-3" and x["detail"]["vap"] == "plant-bridged"][0]
    assert "no managed access point" in f["title"]
    text = text.replace('edit "FAP231F-default"', 'edit "FWF60F-default"')
    _upload(c, text, name="FGT-MFA-3")
    f = [x for x in _by(c, sid)["config_wireless_weak_security"] if x["device_name"] == "FGT-MFA-3" and x["detail"]["vap"] == "plant-bridged" and x["status"] == "open"][0]
    assert f["detail"]["active"] is True and f["severity"] == "medium"
