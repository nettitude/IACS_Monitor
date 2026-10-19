"""FortiLink-managed FortiSwitches from the FortiGate backup (owner 2026-10-19)."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG
from tests.test_wireless_ot import _label

FSW = """config system interface
    edit "fortilink"
        set vdom "root"
        set ip 169.254.1.1 255.255.255.0
        set type aggregate
        set member "port5" "port6"
        set fortilink enable
    next
    edit "vlan_20"
        set vdom "root"
        set ip 10.10.20.1 255.255.255.0
        set interface "fortilink"
        set vlanid 20
        set type vlan
    next
    edit "vlan_30"
        set vdom "root"
        set ip 10.10.30.1 255.255.255.0
        set interface "fortilink"
        set vlanid 30
        set type vlan
    next
end
config switch-controller security-policy 802-1X
    edit "802-1X-policy-default"
        set user-group "SSO_Guest_Users"
        set open-auth disable
    next
end
config switch-controller managed-switch
    edit "S124EPTF00000001"
        set fsw-wan1-peer "fortilink"
        set name "sw-ot-01"
        config ports
            edit "port1"
                set vlan "vlan_20"
                set port-security-policy "802-1X-policy-default"
                set description "PLC-01"
            next
            edit "port2"
                set vlan "vlan_20"
            next
            edit "port3"
                set vlan "vlan_30"
                set status down
            next
            edit "port4"
                set vlan "vlan_30"
                set description "HMI"
            next
            edit "port23"
                set vlan "vlan_20"
                set allowed-vlans "vlan_30"
            next
            edit "port24"
                set fortilink-port enable
                set type trunk
            next
        end
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_fortilink_switch_rows(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FSW))
    from app.models import SwitchInterface, SwitchVlan
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    ports = {r.port_name: r for r in s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-01")}
    assert set(ports) == {"port1", "port2", "port3", "port4", "port23", "port24"}
    assert ports["port1"].mode == "access" and ports["port1"].vlan == "20" and ports["port1"].vlan_name == "vlan_20"
    assert ports["port1"].port_security_policy == "802-1X-policy-default" and ports["port2"].port_security_policy is None
    assert ports["port3"].admin_status == "down" and ports["port23"].mode == "trunk" and ports["port23"].vlan == "20,30"
    assert ports["port24"].uplink is True and ports["port24"].neighbor_port == "fortilink" and ports["port24"].neighbor_device == "FGT-MFA"
    vl = {v.vlan_id: v for v in s.query(SwitchVlan).filter(SwitchVlan.device_name == "sw-ot-01")}
    assert set(vl) == {20, 30} and vl[20].vlan_name == "vlan_20" and vl[20].port_count == 3 and vl[20].purdue_level is None
    s.close()
    # the VLAN interface label flows to the switch VLAN on the next upload
    _label(c, "vlan_20", 1)
    _upload(c, CFG.replace("{CM}", FSW))
    s = next(main_mod.app.dependency_overrides[get_db]())
    v20 = s.query(SwitchVlan).filter(SwitchVlan.device_name == "sw-ot-01", SwitchVlan.vlan_id == 20).one()
    assert float(v20.purdue_level) == 1 and v20.purdue_level_source in ("fortilink_label", "firewall_propagated")
    assert s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-01").count() == 6     # replaced, not duplicated
    s.close()


def test_reviews_nac_and_unused_ports(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FSW))
    _label(c, "vlan_20", 1)
    _upload(c, CFG.replace("{CM}", FSW))
    r = c.post("/reviews/run", params={"site_id": sid})
    assert r.status_code == 200, r.text
    by = _by(c, sid)
    nac = by["switch_port_no_nac"][0]
    # port1 has a policy, port3 is down, port23 is a trunk, port24 the uplink -> port2 (L1) and port4 (unlabelled)
    assert nac["severity"] == "medium" and [p["port"] for p in nac["detail"]["ports"]] == ["port2", "port4"] and nac["detail"]["ot_ports"] == ["port2"]
    un = by["switch_unused_port_enabled"][0]
    assert un["severity"] == "low" and un["detail"]["ports"] == ["port2"]          # port1 / port4 described, port3 down
    # the switch hangs off the FortiLink aggregate on the Firewall Ports page
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    fl = next(p for p in j["firewalls"][0]["ports"] if p["name"] == "fortilink")
    assert fl["fortiswitches"] == ["sw-ot-01"]


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app import writeup as wu
    for n in ("switch_port_no_nac", "switch_unused_port_enabled"):
        assert n in CHECK_TYPE_REFERENCE and n in EXPLAIN and n in wu.FORTI and n in wu.CONCERN
    assert 'edit "sw-ot-01"' in wu.forti_example("switch_port_no_nac", {"switch_device": "sw-ot-01", "ports": [{"port": "port2"}]})


# ---- standalone FortiSwitchOS configuration -----------------------------------------------------

FSOS = """#config-version=FS1E48-7.2.5-FW-build0400
config system global
    set hostname "sw-standalone"
end
config system interface
    edit "internal"
        set ip 10.10.250.5 255.255.255.0
        set allowaccess ping https ssh telnet
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config switch physical-port
    edit "port1"
        set description "PLC-01"
    next
    edit "port3"
        set status down
    next
end
config switch vlan
    edit 20
        set description "ot-control"
    next
    edit 30
        set description "ot-hmi"
    next
end
config switch trunk
    edit "T1"
        set members "port23" "port24"
    next
end
config switch interface
    edit "port1"
        set native-vlan 20
        set security-mode 802.1X-mac-based
    next
    edit "port2"
        set native-vlan 20
    next
    edit "port3"
        set native-vlan 30
    next
    edit "port4"
        set native-vlan 30
        set allowed-vlans 20,40-41
    next
    edit "T1"
        set native-vlan 1
        set allowed-vlans "20" "30"
    next
end
"""


def test_parse_fortinet_switch_config():
    from app.parsers.switch_parser import parse_fortinet_switch_config, detect_switch_vendor, detect_switch_config_type
    assert detect_switch_vendor(FSOS) == "fortinet" and detect_switch_config_type(FSOS) == "fortinet_running_config"
    host, ifs, vlans = parse_fortinet_switch_config(FSOS)
    by = {i["port_name"]: i for i in ifs}
    assert host == "sw-standalone" and vlans == {"20": "ot-control", "30": "ot-hmi"}
    assert by["port1"] == {"port_name": "port1", "mode": "access", "vlan": "20", "vlan_name": "ot-control", "description": "PLC-01",
                           "admin_status": "up", "port_security_policy": "802.1X-mac-based", "uplink": False}
    assert by["port3"]["admin_status"] == "down" and by["port2"]["port_security_policy"] is None
    assert by["port4"]["mode"] == "trunk" and by["port4"]["vlan"] == "20,30,40,41"
    assert by["T1"]["uplink"] is True and by["T1"]["vlan"] == "1,20,30"


def test_standalone_ingest_reviews_and_hardening(api):
    c, sid = api
    r = c.post("/ingest/switch", params={"site": "mfa", "vendor_hint": "fortinet"}, files={"file": ("sw.conf", FSOS.encode())})
    assert r.status_code == 200, r.text
    assert r.json()["stats"]["config_type"] == "fortinet_running_config" and r.json()["stats"]["interfaces_touched"] == 5
    r2 = c.post("/ingest/switch", params={"site": "mfa"}, files={"file": ("sw2.conf", FSOS.replace("sw-standalone", "sw-auto").encode())})
    assert r2.status_code == 200 and r2.json()["stats"]["config_type"] == "fortinet_running_config"      # auto-detected
    bad = c.post("/ingest/switch", params={"site": "mfa", "vendor_hint": "cisco"}, files={"file": ("sw.conf", FSOS.encode())})
    assert bad.status_code in (400, 409, 422)
    assert c.post("/reviews/run", params={"site_id": sid}).status_code == 200
    by = _by(c, sid)
    nac = {f["device_name"]: f for f in by["switch_port_no_nac"]}["sw-standalone"]
    assert [p["port"] for p in nac["detail"]["ports"]] == ["port2"]                    # port1 has 802.1X, port3 down, port4 / T1 trunks
    un = {f["device_name"]: f for f in by["switch_unused_port_enabled"]}["sw-standalone"]
    assert un["detail"]["ports"] == ["port2"]
    hard = {f["check_name"]: f for f in c.get("/findings", params={"site_id": sid, "limit": 500}).json() if f["device_name"] == "sw-standalone"}
    assert hard["switch_snmp_default_community"]["detail"]["community"] == "public"
    assert "telnet" in hard["switch_insecure_mgmt_protocol"]["detail"]["config_line"]
