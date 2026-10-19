"""
Batch A of the Evidence Automation Matrix gap analysis (owner 2026-10-15,
"implement batch A"): 14 config-only FortiOS checks.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db

BAD = """config system global
    set hostname "FGT-A"
    set strong-crypto disable
    set pre-login-banner disable
    set revision-backup-on-logout disable
    set admintimeout 5
    set admin-lockout-threshold 3
    set timezone 26
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
        set role lan
    next
    edit "port2"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set allowaccess ping https
        set type physical
        set device-identification enable
    next
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.0
        set allowaccess ping
        set type physical
        set role wan
    next
    edit "ssl.root"
        set vdom "root"
        set type tunnel
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set two-factor fortitoken
        set fortitoken "FTKMOB0000000001"
        set password ENC x
    next
    edit "ops1"
        set accprofile "super_admin"
        set password ENC y
    next
    edit "ops2"
        set accprofile "super_admin"
        set password ENC z
    next
    edit "ro"
        set accprofile "super_admin"
        set remote-auth enable
        set password ENC w
    next
end
config system snmp community
    edit 1
        set name "public"
        set status enable
    next
    edit 2
        set name "ot-monitor"
    next
end
config system ha
    set group-name "ha1"
    set mode a-p
    set password ENC q
    set authentication enable
    set encryption enable
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.10.9.9"
        next
        edit 2
            set server "10.10.9.10"
            set authentication enable
            set key ENC k
        next
    end
end
config log setting
    set fwpolicy-implicit-log disable
end
config log syslogd setting
    set status enable
    set server "10.10.9.50"
end
config firewall address
    edit "PLC"
        set subnet 10.10.1.10 255.255.255.255
    next
    edit "HMI"
        set subnet 10.10.2.10 255.255.255.255
    next
    edit "VPN_POOL"
        set type iprange
        set start-ip 10.212.134.200
        set end-ip 10.212.134.210
    next
end
config firewall service custom
    edit "Modbus"
        set tcp-portrange 502
    next
end
config vpn ssl settings
    set source-interface "wan1"
    set tunnel-ip-pools "VPN_POOL"
    set default-portal "full-access"
end
config firewall policy
    edit 1
        set name "HMI-to-PLC"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HMI"
        set dstaddr "PLC"
        set service "Modbus"
        set action accept
        set schedule "always"
    next
    edit 2
        set name "any-if"
        set srcintf "any"
        set dstintf "port1"
        set srcaddr "HMI"
        set dstaddr "PLC"
        set service "Modbus"
        set action accept
        set schedule "always"
    next
    edit 3
        set name "ping-across"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HMI"
        set dstaddr "PLC"
        set service "PING"
        set action accept
        set schedule "always"
    next
    edit 4
        set name "vendor-vpn"
        set srcintf "ssl.root"
        set dstintf "port2"
        set srcaddr "VPN_POOL"
        set dstaddr "HMI"
        set service "HTTPS"
        set action accept
        set schedule "always"
    next
end
"""

GOOD = """config system global
    set hostname "FGT-B"
    set strong-crypto enable
    set pre-login-banner enable
    set post-login-banner enable
    set revision-backup-on-logout enable
    set admintimeout 5
    set admin-lockout-threshold 3
    set timezone 26
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
        set device-identification enable
    next
    edit "port2"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set allowaccess ping https
        set type physical
        set device-identification enable
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set two-factor fortitoken
        set password ENC x
    next
    edit "ops1"
        set accprofile "prof_admin"
        set two-factor fortitoken
        set password ENC y
    next
end
config system ha
    set group-name "ha1"
    set mode a-p
    set password ENC q
    set authentication enable
    set encryption enable
    set monitor "port1" "port2"
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.10.9.9"
            set authentication enable
            set key ENC k
        next
    end
end
config log setting
    set fwpolicy-implicit-log enable
end
config log syslogd setting
    set status enable
    set server "10.10.9.50"
end
config firewall address
    edit "PLC"
        set subnet 10.10.1.10 255.255.255.255
    next
    edit "HMI"
        set subnet 10.10.2.10 255.255.255.255
    next
end
config firewall service custom
    edit "Modbus"
        set tcp-portrange 502
    next
end
config firewall policy
    edit 1
        set name "HMI-to-PLC"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HMI"
        set dstaddr "PLC"
        set service "Modbus"
        set action accept
        set schedule "always"
    next
    edit 5
        set name "same-zone-ping"
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "PLC"
        set dstaddr "PLC"
        set service "PING"
        set action accept
        set schedule "always"
    next
end
"""

BATCH_A = {
    "config_strong_crypto_disabled", "config_snmp_v1v2c_enabled", "config_snmp_default_community",
    "config_admin_no_two_factor", "config_admin_profile_overprivileged", "config_no_login_banner",
    "config_ha_no_monitor_interfaces", "config_policy_any_interface", "config_device_detection_disabled",
    "config_ntp_unauthenticated", "config_no_revision_backup", "config_vendor_rule_permanent",
    "config_icmp_across_boundary", "config_implicit_deny_not_logged",
}


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'ba.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        sid = c.post("/sites", json={"name": "BA", "code": "ba"}).json()["id"]
        try:
            yield c, sid
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _findings(c, sid, name=None):
    rows = c.get("/findings", params={"site_id": sid, "limit": 500, **({"check_name": name} if name else {})}).json()
    return rows


def test_bad_config_raises_every_batch_a_check(api):
    c, sid = api
    r = c.post("/ingest/fortigate-config", params={"site": "ba", "firewall_name": "FGT-A"},
               files={"file": ("a.conf", BAD.encode())})
    assert r.status_code == 200, r.text
    names = {f["check_name"] for f in _findings(c, sid)}
    missing = BATCH_A - names
    assert not missing, missing
    by = {}
    for f in _findings(c, sid):
        by.setdefault(f["check_name"], []).append(f)
    d = by["config_snmp_v1v2c_enabled"][0]["detail"]
    assert d["communities"] == 2 and d["default_names"] == 1 and "public" not in str(d["entries"])
    assert by["config_snmp_default_community"][0]["severity"] == "high"
    # ops1 and ops2 lack MFA while tokens exist; admin has it, ro is a remote-auth admin
    assert sorted(f["detail"]["username"] for f in by["config_admin_no_two_factor"]) == ["ops1", "ops2"]
    assert by["config_admin_profile_overprivileged"][0]["detail"]["count"] == 4
    assert by["config_ha_no_monitor_interfaces"][0]["detail"]["ha_mode"] == "a-p"
    assert [f["detail"]["policy_id"] for f in by["config_policy_any_interface"]] == ["2"]
    assert by["config_policy_any_interface"][0]["detail"]["any_sides"] == ["src_intf"]
    # device detection: port1 (lan, no setting) only - port2 has it, wan1 is WAN, ssl.root is a tunnel
    assert by["config_device_detection_disabled"][0]["detail"]["interfaces"] == ["port1"]
    assert by["config_ntp_unauthenticated"][0]["detail"]["servers"] == ["10.10.9.9"]
    assert by["config_no_revision_backup"][0]["detail"]["central_management_type"] == "not set"
    assert [f["detail"]["policy_id"] for f in by["config_vendor_rule_permanent"]] == ["4"]
    assert [f["detail"]["policy_id"] for f in by["config_icmp_across_boundary"]] == ["3"]
    assert by["config_implicit_deny_not_logged"][0]["severity"] == "medium"
    # the readiness roll-up no longer repeats the implicit-deny gap
    for f in by.get("config_monitoring_readiness", []):
        assert "implicit_deny_not_logged" not in {g.get("gap") for g in f["detail"].get("gaps", [])}
    # every new finding has an explanation and a config snippet
    for name in BATCH_A:
        f = by[name][0]
        assert c.get(f"/findings/{f['id']}/explanation").status_code == 200
        snip = c.get(f"/findings/{f['id']}/config-snippet").json()
        assert snip["available"], (name, snip)


def test_good_config_raises_none(api):
    c, sid = api
    r = c.post("/ingest/fortigate-config", params={"site": "ba", "firewall_name": "FGT-B"},
               files={"file": ("b.conf", GOOD.encode())})
    assert r.status_code == 200, r.text
    names = {f["check_name"] for f in _findings(c, sid)}
    assert not (names & BATCH_A), names & BATCH_A


def test_mfa_check_silent_without_any_mfa_means(api):
    """No tokens, no RADIUS / TACACS, no admin with two-factor: config_no_central_auth covers the
    firewall and (owner 2026-10-18) every local admin is still listed by the per-admin check."""
    c, sid = api
    text = BAD.replace("        set two-factor fortitoken\n        set fortitoken \"FTKMOB0000000001\"\n", "")
    r = c.post("/ingest/fortigate-config", params={"site": "ba", "firewall_name": "FGT-C"},
               files={"file": ("c.conf", text.encode())})
    assert r.status_code == 200, r.text
    names = {f["check_name"] for f in _findings(c, sid)}
    assert "config_admin_no_two_factor" in names and "config_no_central_auth" in names


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    from app.config_store import CHECK_SECTIONS
    for name in BATCH_A:
        assert name in CHECK_TYPE_REFERENCE and name in FORTIGATE_CONFIG_CHECKS, name
        assert name in EXPLAIN, name
    for name in ("config_strong_crypto_disabled", "config_no_login_banner", "config_no_revision_backup",
                 "config_ha_no_monitor_interfaces", "config_ntp_unauthenticated", "config_implicit_deny_not_logged",
                 "config_admin_profile_overprivileged", "config_snmp_v1v2c_enabled", "config_snmp_default_community",
                 "config_device_detection_disabled"):
        assert name in CHECK_SECTIONS, name


def test_audit_cases_radius_only_snmp_off_pingserver(api):
    """Audit 2026-10-15: a RADIUS server for VPN users is not an admin MFA means; communities of a
    switched-off SNMP agent are dead config; remote link monitoring counts as HA monitoring."""
    c, sid = api
    text = (BAD.replace("        set two-factor fortitoken\n        set fortitoken \"FTKMOB0000000001\"\n", "")
            .replace("        set remote-auth enable\n", "")                  # no admin uses the RADIUS server
            .replace("config system snmp community", "config system snmp sysinfo\n    set status disable\nend\nconfig system snmp community")
            .replace("    set encryption enable\nend", "    set encryption enable\n    set pingserver-monitor-interface \"port1\"\nend")
            + "config user radius\n    edit \"vpn-radius\"\n        set server \"10.10.9.60\"\n        set secret ENC r\n    next\nend\n")
    r = c.post("/ingest/fortigate-config", params={"site": "ba", "firewall_name": "FGT-D"},
               files={"file": ("d.conf", text.encode())})
    assert r.status_code == 200, r.text
    names = {f["check_name"] for f in _findings(c, sid)}
    assert "config_admin_no_two_factor" in names                  # owner 2026-10-18: local admins are always listed
    assert "config_snmp_v1v2c_enabled" not in names and "config_snmp_default_community" not in names
    assert "config_ha_no_monitor_interfaces" not in names
