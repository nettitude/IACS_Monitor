"""
Batch B of the Evidence Automation Matrix gap analysis (owner 2026-10-15, "do Batch B"):
VPN users without MFA, weak IPsec / SSL-VPN crypto, DoS policy on OT interfaces, weak
wireless security (FortiOS config); the SIS isolation review is tested in
tests/test_cov_alert_engine.py::test_review_sis_isolation.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db

BASE = """config system global
    set hostname "FGT-BB"
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
    next
    edit "port2"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set allowaccess ping https
        set type physical
    next
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.0
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
        set password ENC x
    next
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
config user local
    edit "vendor1"
        set type password
        set passwd ENC a
    next
    edit "vendor2"
        set type password
        set two-factor fortitoken
        set passwd ENC b
    next
    edit "old-vendor"
        set type password
        set status disable
        set passwd ENC c
    next
    edit "ad-user"
        set type ldap
        set ldap-server "corp-ad"
    next
end
config user group
    edit "vendors"
        set member "vendor1" "vendor2" "old-vendor" "ad-user"
    next
    edit "ops-vpn"
        set member "vendor2"
    next
    edit "unused"
        set member "vendor1"
    next
end
config vpn ipsec phase1-interface
    edit "site-b"
        set interface "wan1"
        set proposal aes256-sha256 3des-md5
        set dhgrp 14 5
        set remote-gw 198.51.100.9
        set psksecret ENC k
    next
    edit "site-c"
        set interface "wan1"
        set proposal aes256gcm-prfsha384
        set dhgrp 20
        set remote-gw 198.51.100.10
        set psksecret ENC k2
    next
    edit "vendor-dialup"
        set type dynamic
        set interface "wan1"
        set usrgrp "vendors"
        set proposal aes256-sha1
        set dhgrp 14
        set psksecret ENC k3
    next
end
config vpn ipsec phase2-interface
    edit "site-c-p2"
        set phase1name "site-c"
        set proposal aes256gcm
        set pfs disable
    next
end
config vpn ssl settings
    set source-interface "wan1"
    set ssl-min-proto-ver tls1-1
    set algorithm medium
    set tunnel-ip-pools "VPN_POOL"
    config authentication-rule
        edit 1
            set groups "ops-vpn"
            set portal "full-access"
        next
    end
end
config wireless-controller vap
    edit "plant-wifi"
        set ssid "PLANT-OT"
        set security wpa-personal
        set passphrase ENC p
        set broadcast-ssid enable
    next
    edit "corp-wifi"
        set ssid "CORP"
        set security wpa2-only-enterprise
    next
end
config wireless-controller wtp-profile
    edit "FAP231F-default"
        config radio-1
            set vap-all tunnel
        end
    next
end
config wireless-controller wtp
    edit "FP231FTF00000001"
        set wtp-profile "FAP231F-default"
    next
end
{DOS}config firewall policy
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
end
"""
DOS = """config firewall DoS-policy
    edit 1
        set interface "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
BATCH_B_CFG = {"config_vpn_user_no_mfa", "config_weak_ipsec_crypto", "config_sslvpn_weak_tls",
               "config_no_dos_policy_ot", "config_wireless_weak_security"}


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'bb.db'}", connect_args={"check_same_thread": False})
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
        sid = c.post("/sites", json={"name": "BB", "code": "bb"}).json()["id"]
        try:
            yield c, sid
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _by_check(c, sid):
    out = {}
    for f in c.get("/findings", params={"site_id": sid, "limit": 500}).json():
        out.setdefault(f["check_name"], []).append(f)
    return out


def test_batch_b_config_checks(api):
    c, sid = api
    r = c.post("/ingest/fortigate-config", params={"site": "bb", "firewall_name": "FGT-BB", "purdue_zone_from": "3", "purdue_zone_to": "1"},
               files={"file": ("bb.conf", BASE.replace("{DOS}", "").encode())})
    assert r.status_code == 200, r.text
    by = _by_check(c, sid)
    assert not (BATCH_B_CFG - set(by)), BATCH_B_CFG - set(by)
    # MFA: 'vendors' (dial-up usrgrp) -> vendor1 and ad-user (LDAP is a password too, owner 2026-10-18):
    # vendor2 has a token, old-vendor is disabled; 'ops-vpn' (SSL-VPN rule) is clean; 'unused' is not a remote-access group
    mfa = {f["detail"]["group"]: f["detail"]["users_without_mfa"] for f in by["config_vpn_user_no_mfa"]}
    assert mfa == {"vendors": ["vendor1", "ad-user"]}
    assert by["config_vpn_user_no_mfa"][0]["detail"]["remote_members"] == []
    assert by["config_vpn_user_no_mfa"][0]["detail"]["auth_sources"]["ad-user"] == "ldap"
    # IPsec: site-b medium (3des-md5, dh5); site-c low (no PFS); vendor-dialup low (sha1)
    ipsec = {f["detail"]["phase1"]: f for f in by["config_weak_ipsec_crypto"]}
    assert set(ipsec) == {"site-b", "site-c", "vendor-dialup"}
    assert ipsec["site-b"]["severity"] == "medium" and set(ipsec["site-b"]["detail"]["weak_phase1"]) == {"3des-md5", "dh5"}
    assert ipsec["site-c"]["severity"] == "low" and ipsec["site-c"]["detail"]["phase2_without_pfs"] == ["site-c-p2"]
    assert ipsec["vendor-dialup"]["severity"] == "low" and ipsec["vendor-dialup"]["detail"]["legacy_sha1"] == ["aes256-sha1"]
    d = by["config_sslvpn_weak_tls"][0]["detail"]
    assert d["ssl_min_proto_ver"] == "tls1-1" and d["algorithm"] == "medium"
    # DoS: no OT labels yet -> "no DoS policy configured"
    assert by["config_no_dos_policy_ot"][0]["title"].startswith("No DoS policy configured")
    wifi = {f["detail"]["ssid"]: f["detail"]["security"] for f in by["config_wireless_weak_security"]}
    assert wifi == {"PLANT-OT": "wpa-personal"}
    for name in BATCH_B_CFG:
        f = by[name][0]
        assert c.get(f"/findings/{f['id']}/explanation").status_code == 200


def test_dos_policy_judged_per_ot_interface(api):
    """With port1 labelled L1 and a DoS policy on it, port2 (L2, no policy) is named; a
    policy on both closes the finding at the next upload."""
    c, sid = api
    r = c.post("/ingest/fortigate-config", params={"site": "bb", "firewall_name": "FGT-BB"},
               files={"file": ("bb.conf", BASE.replace("{DOS}", DOS).encode())})
    assert r.status_code == 200, r.text
    assert "config_no_dos_policy_ot" not in _by_check(c, sid)      # no OT labels and no into-OT boundary: not judged
    st = c.get("/topology/state", params={"site_id": sid}).json()
    fw = st["firewalls"][0]
    ifaces = {i["name"]: i["id"] for i in fw["interfaces"]}
    for name, lvl in (("port1", 1), ("port2", 2)):
        assert c.post("/topology/set-interface-side", json={"interface_id": ifaces[name], "purdue_level": lvl}).status_code == 200
    r = c.post("/ingest/fortigate-config", params={"site": "bb", "firewall_name": "FGT-BB"},
               files={"file": ("bb.conf", BASE.replace("{DOS}", DOS).encode())})
    assert r.status_code == 200
    by = _by_check(c, sid)
    assert by["config_no_dos_policy_ot"][0]["detail"]["ot_interfaces_without_dos_policy"] == ["port2"]
    both = DOS.replace("    next\nend\n", '    next\n    edit 2\n        set interface "port2"\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n    next\nend\n')
    assert c.post("/ingest/fortigate-config", params={"site": "bb", "firewall_name": "FGT-BB"},
                  files={"file": ("bb.conf", BASE.replace("{DOS}", both).encode())}).status_code == 200
    assert "config_no_dos_policy_ot" not in {f["check_name"] for f in c.get("/findings", params={"site_id": sid, "status": "open", "limit": 500}).json()}


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    from app.parsers import alert_engine as ae
    for name in BATCH_B_CFG | {"sis_zone_not_isolated"}:
        assert name in CHECK_TYPE_REFERENCE and name in EXPLAIN, name
    for name in BATCH_B_CFG:
        assert name in FORTIGATE_CONFIG_CHECKS, name
    assert ae._AUTO_RESOLVE_CHECKS["review_sis_isolation"] == ("sis_zone_not_isolated",)


def test_audit_cases_groups_with_spaces_xauth_ssl_off(api):
    """Audit 2026-10-15: group / user names with spaces are kept whole; XAuth dial-up groups count;
    an SSL-VPN that is switched off is dead config."""
    c, sid = api
    text = (BASE.replace("{DOS}", "")
            .replace('edit "vendors"\n        set member "vendor1" "vendor2" "old-vendor" "ad-user"',
                     'edit "Vendor Access Team"\n        set member "vendor one" "vendor2" "old-vendor" "ad-user"')
            .replace('edit "vendor1"', 'edit "vendor one"')
            .replace('set usrgrp "vendors"', 'set authusrgrp "Vendor Access Team"')
            .replace('set source-interface "wan1"', 'set status disable\n    set source-interface "wan1"'))
    r = c.post("/ingest/fortigate-config", params={"site": "bb", "firewall_name": "FGT-BB2"},
               files={"file": ("bb2.conf", text.encode())})
    assert r.status_code == 200, r.text
    by = _by_check(c, sid)
    mfa = {f["detail"]["group"]: f["detail"]["users_without_mfa"] for f in by["config_vpn_user_no_mfa"]}
    assert mfa == {"Vendor Access Team": ["vendor one", "ad-user"]}
    assert "config_sslvpn_weak_tls" not in by                      # SSL-VPN disabled
