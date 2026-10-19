"""
MFA coverage (owner 2026-10-18: "make sure the MFA findings cover local and
FortiManager"): every local admin without two-factor is a finding (high for
super_admin), LDAP-backed VPN users count as password-only, and a
FortiManager-managed device gets an informational finding about administrator
MFA on FortiManager (low when the FortiManager address is public).
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db

CFG = """config system global
    set hostname "FGT-MFA"
end
config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
    next
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
    next
    edit "ops"
        set accprofile "prof_admin"
        set vdom "root"
    next
    edit "secure"
        set accprofile "prof_admin"
        set two-factor fortitoken
        set fortitoken "FTKMOB0000000001"
    next
    edit "central"
        set accprofile "prof_admin"
        set remote-auth enable
        set remote-group "RADIUS-OT"
    next
end
config user ldap
    edit "corp-ad"
        set server "10.10.9.10"
    next
end
config user radius
    edit "nps-mfa"
        set server "10.10.9.20"
        set secret ENC x
    next
end
config user local
    edit "vendor1"
        set type password
        set passwd ENC a
    next
    edit "ad-user"
        set type ldap
        set ldap-server "corp-ad"
    next
    edit "ad-user-token"
        set type ldap
        set ldap-server "corp-ad"
        set two-factor fortitoken
        set fortitoken "FTKMOB0000000002"
    next
end
config user group
    edit "vendors"
        set member "vendor1" "ad-user" "ad-user-token" "corp-ad" "nps-mfa"
    next
end
config vpn ipsec phase1-interface
    edit "vendor-dialup"
        set type dynamic
        set interface "wan1"
        set usrgrp "vendors"
        set psksecret ENC s
    next
end
{CM}"""
FMG = """config system central-management
    set type fortimanager
    set fmg "{ADDR}"
end
"""


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'mfa.db'}", connect_args={"check_same_thread": False})
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
        sid = c.post("/sites", json={"name": "MFA", "code": "mfa"}).json()["id"]
        try:
            yield c, sid
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _by(c, sid):
    out = {}
    for f in c.get("/findings", params={"site_id": sid, "limit": 500}).json():
        out.setdefault(f["check_name"], []).append(f)
    return out


def _upload(c, text, name="FGT-MFA"):
    r = c.post("/ingest/fortigate-config", params={"site": "mfa", "firewall_name": name},
               files={"file": (name + ".conf", text.encode())})
    assert r.status_code == 200, r.text


def test_local_admins_without_two_factor_always_flagged(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", ""))
    by = _by(c, sid)
    adm = {f["detail"]["username"]: f for f in by["config_admin_no_two_factor"]}
    assert set(adm) == {"admin", "ops"}                                   # secure has a token, central is remote
    assert adm["admin"]["severity"] == "high" and adm["ops"]["severity"] == "medium"
    assert adm["admin"]["detail"]["auth_source"].startswith("local") and adm["admin"]["detail"]["mfa_kind"] == "none"
    assert "config_fortimanager_admin_access" not in by


def test_local_admins_flagged_without_any_mfa_means(api):
    """The old gate (only when the firewall had tokens or a remote admin) is gone."""
    c, sid = api
    text = (CFG.replace("{CM}", "")
            .replace('        set two-factor fortitoken\n        set fortitoken "FTKMOB0000000001"\n', "")
            .replace('        set remote-auth enable\n        set remote-group "RADIUS-OT"\n', ""))
    _upload(c, text)
    by = _by(c, sid)
    assert {f["detail"]["username"] for f in by["config_admin_no_two_factor"]} == {"admin", "ops", "secure", "central"}
    assert by["config_admin_no_two_factor"][0]["detail"]["mfa_available"] in ("none configured", "radius / tacacs")


def test_ldap_users_and_ldap_server_members_count_as_password_only(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", ""))
    by = _by(c, sid)
    f = by["config_vpn_user_no_mfa"][0]
    d = f["detail"]
    assert d["group"] == "vendors"
    assert sorted(d["users_without_mfa"]) == ["ad-user", "corp-ad", "vendor1"]        # LDAP user, LDAP server, local
    assert d["auth_sources"]["ad-user"] == "ldap" and d["auth_sources"]["corp-ad"] == "ldap server"
    assert d["auth_sources"]["vendor1"].startswith("local")
    assert d["remote_members"] == ["ad-user-token", "nps-mfa"]                        # token user and RADIUS server are covered


def test_fortimanager_finding_info_or_low_when_public(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FMG.replace("{ADDR}", "192.168.250.50")))
    by = _by(c, sid)
    f = by["config_fortimanager_admin_access"][0]
    assert f["severity"] == "info" and f["detail"]["fortimanager"] == "192.168.250.50" and f["detail"]["fortimanager_public"] is False
    assert "config_updates_from_internet" not in by
    _upload(c, CFG.replace("{CM}", FMG.replace("{ADDR}", "8.8.4.4")), name="FGT-MFA-2")
    by = _by(c, sid)
    pub = [f for f in by["config_fortimanager_admin_access"] if f["device_name"] == "FGT-MFA-2"][0]
    assert pub["severity"] == "low" and pub["detail"]["fortimanager_public"] is True and "public" in pub["title"]
    # a re-upload without central management closes it
    _upload(c, CFG.replace("{CM}", ""), name="FGT-MFA-2")
    by = _by(c, sid)
    left = [f for f in by.get("config_fortimanager_admin_access", []) if f["device_name"] == "FGT-MFA-2"]
    assert left and all(f["status"] == "closed" for f in left), [f["status"] for f in left]


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app import writeup as wu
    from app.config_store import CHECK_SECTIONS
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    n = "config_fortimanager_admin_access"
    assert n in CHECK_TYPE_REFERENCE and n in FORTIGATE_CONFIG_CHECKS and n in EXPLAIN and n in CHECK_SECTIONS
    assert n in wu.FORTI and n in wu.CIS and n in wu.CONCERN
    assert "fortimanager" in wu.forti_example(n, {"fortimanager": "10.1.1.5"}) and "10.1.1.5" in wu.forti_example(n, {"fortimanager": "10.1.1.5"})


# ---- audit 2026-10-18 -------------------------------------------------------------------------

def test_remote_auth_admin_on_ldap_group_is_password_only(api):
    c, sid = api
    text = CFG.replace("{CM}", "").replace('''config user group
    edit "vendors"''', '''config user group
    edit "RADIUS-OT"
        set member "nps-mfa"
    next
    edit "ldap-admins"
        set member "corp-ad"
    next
    edit "vendors"''').replace('''    edit "central"
        set accprofile "prof_admin"
        set remote-auth enable
        set remote-group "RADIUS-OT"
    next''', '''    edit "central"
        set accprofile "prof_admin"
        set remote-auth enable
        set remote-group "RADIUS-OT"
    next
    edit "ldapadmin"
        set accprofile "super_admin"
        set remote-auth enable
        set remote-group "ldap-admins"
    next''')
    _upload(c, text)
    adm = {f["detail"]["username"]: f for f in _by(c, sid)["config_admin_no_two_factor"]}
    assert "central" not in adm                                           # RADIUS group: covered
    assert adm["ldapadmin"]["severity"] == "high" and adm["ldapadmin"]["detail"]["auth_source"].startswith("remote group ldap-admins: ldap server corp-ad")


def test_fortimanager_name_is_reported_not_judged(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FMG.replace("{ADDR}", "fmg.corp.local")))
    f = _by(c, sid)["config_fortimanager_admin_access"][0]
    assert f["severity"] == "info" and f["detail"]["fortimanager_public"] is None and "not judged" in f["title"]


def test_report_details_rows_are_sanitised(api):
    c, sid = api
    body = {"client_name": "A\x00B\nC", "distribution": ["junk", 5, None, {"name": {"nested": 1}, "role": ["x"], "email": "e\x07", "side": "banana"}]
            + [{"name": f"p{i}", "side": "assessor"} for i in range(60)], "revisions": [{"version": ["1"], "date": "", "status": ""}]}
    d = c.put("/reports/details", params={"site_id": sid}, json=body).json()
    assert d["client_name"] == "A B C"
    assert len(d["distribution"]) == 51 and d["distribution"][0] == {"name": "", "role": "", "email": "e", "side": "client"}
    assert d["distribution"][1] == {"name": "p0", "role": "", "email": "", "side": "assessor"}      # 50 assessors kept after the client row
    assert d["revisions"] == []
