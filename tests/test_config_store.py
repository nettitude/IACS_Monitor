"""
Stored firewall configuration text and the config lines behind a finding
(owner 2026-10-14: "Firewall devices need a means to see the uploaded config to
check findings ... can the findings have a snip of the firewall config that is
causing the finding?"; decisions: mask secrets before storing, latest upload
only, console only).
"""
import contextlib
import zlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app import config_store as cs
from app.db import Base, get_db
from app.models import Finding, Firewall, FirewallConfigText

CFG = """#config-version=FGT60F-7.0.12-FW-build0523-230425:opmode=0:vdom=0:user=admin
config system global
    set hostname "FGT-C"
    set admintimeout 480
    set admin-lockout-threshold 3
end
config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping https ssh http telnet
    next
    edit "port2"
        set ip 10.10.2.1 255.255.255.0
        set alias "Control"
    next
    edit "port3"
        set ip 10.40.1.1 255.255.255.0
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC AK1abcdef0123456789
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config vpn ipsec phase1-interface
    edit "vendor-dialup"
        set type dynamic
        set interface "port3"
        set psksecret ENC XYZ123
    next
end
config log syslogd setting
    set status disable
end
config firewall address
    edit "PLC"
        set subnet 10.10.1.10 255.255.255.255
    next
    edit "HMI"
        set subnet 10.10.2.10 255.255.255.255
    next
    edit "IT"
        set subnet 10.40.1.50 255.255.255.255
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
    next
    edit 2
        set name "IT-to-PLC-any"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

CISCO = """hostname ASA-C
enable secret 5 $1$abcd$efghijklmnop
username ops password 7 0822455D0A16 privilege 15
snmp-server community s3cr3t RO
radius-server host 10.1.1.5 key 7 0123456789
crypto isakmp key verysecret address 203.0.113.9
interface GigabitEthernet0/0
 nameif outside
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 ip address 10.50.1.1 255.255.255.0
access-list OUT extended permit tcp any host 10.50.1.10 eq 502
access-group OUT in interface outside
"""


# ---------------------------------------------------------------- masking --

def test_mask_fortios_secrets_keep_line_numbers():
    masked, n = cs.mask_secrets(CFG)
    assert masked.count("\n") == CFG.count("\n")
    assert 'set password ***' in masked and 'set psksecret ***' in masked
    assert 'set name ***' in masked               # SNMP community string
    assert "AK1abcdef" not in masked and "XYZ123" not in masked and "public" not in masked
    assert 'set hostname "FGT-C"' in masked        # nothing else touched
    assert n == 3


def test_mask_cisco_and_xml_and_pem():
    masked, n = cs.mask_secrets(CISCO)
    for secret in ("$1$abcd", "0822455D0A16", "s3cr3t", "0123456789", "verysecret"):
        assert secret not in masked, secret
    assert "enable secret 5 ***" in masked and "snmp-server community ***" in masked
    assert "username ops password 7 *** privilege 15" in masked and "snmp-server community *** RO" in masked
    assert "crypto isakmp key *** address 203.0.113.9" in masked
    assert "access-list OUT extended permit tcp any host 10.50.1.10 eq 502" in masked
    assert n == 5
    xml = "<user><name>admin</name><password>hunter2</password><phash>$6$x</phash></user>\n"
    m, k = cs.mask_secrets(xml)
    assert "<password>***</password>" in m and "<phash>***</phash>" in m and "<name>admin</name>" in m and k == 1
    pem = 'set private-key "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----"\nset x 1\n'
    m, k = cs.mask_secrets(pem)
    assert "MIIEow" not in m and "AAAA" not in m and m.count("\n") == pem.count("\n") and "set x 1" in m and k == 1


# ----------------------------------------------------------------- blocks --

def test_find_block_section_edit_and_vdom():
    lines = CFG.splitlines()
    b = cs.find_block(lines, "firewall policy", 2)
    assert lines[b[0] - 1].strip() == "edit 2" and lines[b[1] - 1].strip() == "next"
    assert any("IT-to-PLC-any" in l for l in lines[b[0] - 1:b[1]])
    s = cs.find_block(lines, "log syslogd setting")
    assert lines[s[0] - 1].strip() == "config log syslogd setting" and lines[s[1] - 1].strip() == "end"
    assert cs.find_block(lines, "system interface", "PORT2")      # case-insensitive key
    assert cs.find_block(lines, "firewall policy", 99) is None
    vd = ("config vdom\n    edit root\n    config firewall policy\n        edit 7\n            set name \"a\"\n        next\n    end\n"
          "    next\n    edit ot\n    config firewall policy\n        edit 7\n            set name \"b\"\n        next\n    end\n    next\nend\n").splitlines()
    b = cs.find_block(vd, "firewall policy", 7, vdom="ot")
    assert 'set name "b"' in vd[b[0]]
    b = cs.find_block(vd, "firewall policy", 7, vdom="root")
    assert 'set name "a"' in vd[b[0]]


# -------------------------------------------------------------------- API --

@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    """The seeded API (also used by tests/test_cov_routes.py)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'cs.db'}", connect_args={"check_same_thread": False})
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
        sid = c.post("/sites", json={"name": "C", "code": "c"}).json()["id"]
        r = c.post("/ingest/fortigate-config", params={"site": "c", "firewall_name": "FW-C"},
                   files={"file": ("fw-c.conf", CFG.encode())})
        assert r.status_code == 200, r.text
        assert r.json()["stats"]["config_stored"] is True
        fw_id = r.json()["stats"]["firewall_id"]
        try:
            yield c, sid, fw_id, Session
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_config_stored_masked_and_served(api):
    c, sid, fw_id, Session = api
    with Session() as s:
        row = s.query(FirewallConfigText).filter_by(firewall_id=fw_id).one()
        raw = zlib.decompress(row.content).decode()
        assert "AK1abcdef" not in raw and row.masked_count == 3 and row.site_id == sid
        assert row.line_count == CFG.count("\n") and row.filename == "fw-c.conf" and row.vendor == "fortigate"
    r = c.get(f"/firewalls/{fw_id}/config", params={"site_id": sid})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["masked_count"] == 3 and j["line_count"] == CFG.count("\n") and j["firewall_name"] == "FW-C"
    assert "set password ***" in j["text"] and "ENC AK1" not in j["text"]
    d = c.get(f"/firewalls/{fw_id}/config", params={"site_id": sid, "download": "true"})
    assert d.status_code == 200 and d.headers["content-disposition"].endswith('"fw-c.conf"')
    assert d.text == j["text"] and "AK1abcdef" not in d.text
    # another site / unknown firewall -> 404
    other = c.post("/sites", json={"name": "D", "code": "d"}).json()["id"]
    assert c.get(f"/firewalls/{fw_id}/config", params={"site_id": other}).status_code == 404
    assert c.get("/firewalls/999/config", params={"site_id": sid}).status_code == 404


def test_latest_upload_replaces_the_text(api):
    c, sid, fw_id, Session = api
    r = c.post("/ingest/fortigate-config", params={"site": "c", "firewall_name": "FW-C"},
               files={"file": ("fw-c-v2.conf", CFG.replace('set admintimeout 480', 'set admintimeout 5').encode())})
    assert r.status_code == 200, r.text
    assert r.json()["stats"]["firewall_id"] == fw_id
    with Session() as s:
        rows = s.query(FirewallConfigText).filter_by(firewall_id=fw_id).all()
        assert len(rows) == 1 and rows[0].filename == "fw-c-v2.conf"
    j = c.get(f"/firewalls/{fw_id}/config", params={"site_id": sid}).json()
    assert "set admintimeout 5\n" in j["text"] and "admintimeout 480" not in j["text"]


def _finding(c, sid, check):
    rows = c.get("/findings", params={"site_id": sid, "check_name": check, "limit": 50}).json()
    assert rows, check
    return rows[0]


def test_snippets_policy_interface_admin_and_section(api):
    c, sid, fw_id, Session = api
    f = _finding(c, sid, "config_permit_any_any_any")
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] and j["what"].startswith("policy 2") and j["firewall_id"] == fw_id
    assert j["lines"][0].strip() == "edit 2" and j["lines"][-1].strip() == "next"
    assert any("IT-to-PLC-any" in l for l in j["lines"]) and j["filename"] == "fw-c.conf" and not j["truncated"]
    assert j["start_line"] >= 1 and j["end_line"] - j["start_line"] + 1 == len(j["lines"])
    f = _finding(c, sid, "config_insecure_mgmt_protocol")
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] and j["what"] == "interface port1" and any("allowaccess" in l for l in j["lines"])
    f = _finding(c, sid, "config_no_syslog_forwarding")
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] and j["what"] == "section log syslogd setting" and j["lines"][0].strip() == "config log syslogd setting"
    f = _finding(c, sid, "config_admin_no_trusted_hosts")
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] and j["what"] == "admin admin" and any("set password ***" in l for l in j["lines"])
    f = _finding(c, sid, "config_ipsec_dialup_psk")
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] and j["what"] == "IPsec phase1 vendor-dialup" and any("psksecret ***" in l for l in j["lines"])
    f = _finding(c, sid, "config_no_admin_idle_timeout") if c.get("/findings", params={"site_id": sid, "check_name": "config_no_admin_idle_timeout"}).json() else None
    assert c.get("/findings/999999/config-snippet").status_code == 404


def test_snippet_unavailable_cases(api):
    c, sid, fw_id, Session = api
    f = _finding(c, sid, "config_permit_any_any_any")
    # the policy disappears from the stored config after a re-upload: told so, not a wrong block
    smaller = CFG.replace('''    edit 2
        set name "IT-to-PLC-any"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
''', '')
    assert c.post("/ingest/fortigate-config", params={"site": "c", "firewall_name": "FW-C"},
                  files={"file": ("fw-c.conf", smaller.encode())}).status_code == 200
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] is False and "policy 2" in j["reason"].lower() and j["firewall_id"] == fw_id
    # a finding about no firewall
    with Session() as s:
        s.add(Finding(site_id=sid, category="network", check_name="unknown_device", severity="low", status="open",
                      title="x", detail={"ip": "10.10.1.99"}))
        s.commit()
        fid = s.query(Finding).filter_by(check_name="unknown_device").one().id
    j = c.get(f"/findings/{fid}/config-snippet").json()
    assert j["available"] is False and "no firewall" in j["reason"]
    # no text stored (config uploaded before this release)
    with Session() as s:
        s.query(FirewallConfigText).delete()
        s.commit()
    j = c.get(f"/findings/{f['id']}/config-snippet").json()
    assert j["available"] is False and "upload its config again" in j["reason"]
    assert c.get(f"/firewalls/{fw_id}/config", params={"site_id": sid}).status_code == 404


def test_cisco_config_stored_and_rule_line_snippet(api):
    c, sid, fw_id, Session = api
    r = c.post("/ingest/firewall", params={"site": "c", "firewall_device_name": "ASA-C", "vendor_hint": "cisco"},
               files={"file": ("asa.cfg", CISCO.encode())})
    assert r.status_code == 200, r.text
    st = r.json()["stats"]
    assert st.get("firewall_id") and st["config_stored"] is True
    j = c.get(f"/firewalls/{st['firewall_id']}/config", params={"site_id": sid}).json()
    assert "enable secret 5 ***" in j["text"] and "s3cr3t" not in j["text"] and j["masked_count"] == 5
    with Session() as s:
        fw = s.get(Firewall, st["firewall_id"])
        rule = [x for x in fw.rules if (x.raw_line or "").startswith("access-list OUT")][0] if hasattr(fw, "rules") else None
        if rule is None:
            from app.models import FirewallRule
            rule = s.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id, FirewallRule.raw_line.like("access-list OUT%")).first()
        s.add(Finding(site_id=sid, category="firewall", check_name="rule_cleartext_protocol", severity="medium", status="open",
                      title="x", device_name="ASA-C", detail={"firewall_rule_id": rule.id, "policy_id": rule.policy_id}))
        s.commit()
        fid = s.query(Finding).filter_by(check_name="rule_cleartext_protocol").one().id
    j = c.get(f"/findings/{fid}/config-snippet").json()
    assert j["available"] and j["what"] == "rule line" and j["lines"] == ["access-list OUT extended permit tcp any host 10.50.1.10 eq 502"]


def test_purge_removes_the_text(api, monkeypatch):
    c, sid, fw_id, Session = api
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")  # B-21: delete / purge are gated
    assert c.post("/sites", json={"name": "Keep", "code": "keep"}).status_code in (200, 201)   # not the last site
    r = c.delete(f"/sites/{sid}", params={"force": "true"})
    assert r.status_code == 200, r.text
    assert r.json()["data_removed"]["firewall_config_texts"] == 1
    with Session() as s:
        assert s.query(FirewallConfigText).count() == 0


# ----------------------------------------- interface settings block (option 3) --

def test_forti_settings_table_and_nested_tables():
    block = '''    edit "port5"
        set vdom "root"
        set ip 10.5.0.1 255.255.255.0
        set allowaccess ping https ssh http
        set alias "OT core"
        set type vlan
        set vlanid 50
        set interface "port1"
        config secondaryip
            edit 1
                set ip 10.5.1.1 255.255.255.0
                set allowaccess ping
            next
        end
        unset description
    next'''.splitlines()
    rows = {r["key"]: r["value"] for r in cs.forti_settings(block)}
    assert rows["ip"] == "10.5.0.1 255.255.255.0" and rows["allowaccess"] == "ping https ssh http"
    assert rows["alias"] == "OT core" and rows["vlanid"] == "50" and rows["interface"] == "port1"
    assert rows["secondaryip"] == "1 ip 10.5.1.1 255.255.255.0 allowaccess ping"
    assert rows["description"] == "(unset)"


def test_interface_block_fortios(api):
    c, sid, fw_id, Session = api
    j = c.get(f"/firewalls/{fw_id}/config/block", params={"site_id": sid, "key": "port1"}).json()
    assert j["available"] and j["what"] == "system interface port1"
    assert j["lines"][0].strip() == 'edit "port1"' and j["lines"][-1].strip() == "next"
    rows = {r["key"]: r["value"] for r in j["settings"]}
    assert rows["ip"] == "10.10.1.1 255.255.255.0" and "telnet" in rows["allowaccess"]
    assert j["filename"] == "fw-c.conf" and j["end_line"] - j["start_line"] + 1 == len(j["lines"])
    j = c.get(f"/firewalls/{fw_id}/config/block", params={"site_id": sid, "key": "PORT2", "vdom": "root"}).json()
    assert j["available"] and {r["key"]: r["value"] for r in j["settings"]}["alias"] == "Control"   # no VDOM mode: whole config
    j = c.get(f"/firewalls/{fw_id}/config/block", params={"site_id": sid, "key": "port9"}).json()
    assert j["available"] is False and "port9" in j["reason"]
    j = c.get(f"/firewalls/{fw_id}/config/block", params={"site_id": sid, "section": "firewall policy", "key": "2"}).json()
    assert j["available"] and {r["key"]: r["value"] for r in j["settings"]}["name"] == "IT-to-PLC-any"
    assert c.get(f"/firewalls/{fw_id}/config/block", params={"site_id": sid}).status_code == 422   # key required
    assert c.get("/firewalls/999/config/block", params={"site_id": sid, "key": "port1"}).status_code == 404


def test_interface_block_cisco_by_name_and_nameif(api):
    c, sid, fw_id, Session = api
    r = c.post("/ingest/firewall", params={"site": "c", "firewall_device_name": "ASA-C", "vendor_hint": "cisco"},
               files={"file": ("asa.cfg", CISCO.encode())})
    assert r.status_code == 200, r.text
    afw = r.json()["stats"]["firewall_id"]
    j = c.get(f"/firewalls/{afw}/config/block", params={"site_id": sid, "key": "GigabitEthernet0/0"}).json()
    assert j["available"] and j["lines"][0].strip() == "interface GigabitEthernet0/0" and len(j["lines"]) == 3
    rows = {r["key"]: r["value"] for r in j["settings"]}
    assert rows["nameif"] == "outside" and rows["ip address"] == "203.0.113.2 255.255.255.0"
    assert rows["access-group (in)"] == "OUT"
    j2 = c.get(f"/firewalls/{afw}/config/block", params={"site_id": sid, "key": "outside"}).json()
    assert j2["available"] and j2["start_line"] == j["start_line"]
    j3 = c.get(f"/firewalls/{afw}/config/block", params={"site_id": sid, "key": "dmz"}).json()
    assert j3["available"] is False
    assert c.get(f"/firewalls/{afw}/config/block", params={"site_id": sid, "section": "firewall policy", "key": "1"}).json()["available"] is False


def test_xml_element_pfsense_and_panos():
    pf = """<pfsense>
  <interfaces>
    <wan>
      <if>em0</if>
      <ipaddr>dhcp</ipaddr>
      <enable/>
    </wan>
    <lan>
      <if>em1</if>
      <ipaddr>10.1.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
</pfsense>""".splitlines()
    b = cs.xml_element(pf, "lan")
    assert pf[b[0] - 1].strip() == "<lan>" and pf[b[1] - 1].strip() == "</lan>"
    assert {r["key"]: r["value"] for r in cs.xml_settings(pf[b[0] - 1:b[1]])} == {"if": "em1", "ipaddr": "10.1.1.1", "subnet": "24"}
    pan = """<entry name="ethernet1/1">
  <layer3>
    <ip><entry name="10.0.0.1/24"/></ip>
    <interface-management-profile>mgmt</interface-management-profile>
  </layer3>
</entry>
<entry name="ethernet1/2">
  <layer3/>
</entry>""".splitlines()
    b = cs.xml_element(pan, "entry", attr_name="ethernet1/1")
    assert b == (1, 6)
    assert cs.xml_element(pan, "entry", attr_name="ethernet1/2") == (7, 9)


def test_audit_masking_forms():
    """Audit 2026-10-15: Cisco keyword forms, IKEv2 keyrings, key chains, XML tags by suffix,
    FortiOS policy names that are not secrets."""
    cisco = """username bob privilege 15 algorithm-type scrypt secret 9 $9$abc
snmp-server host 10.1.1.1 version 2c MYCOMM
snmp-server user u1 grp v3 auth sha AUTHPW priv aes 128 PRIVPW
crypto ikev2 keyring k
 peer p
  pre-shared-key local LKEY
  pre-shared-key address 1.2.3.4 key AKEY
key chain kc
 key 1
  key-string KSECRET
ip ospf message-digest-key 1 md5 OSPFKEY
ntp authentication-key 1 md5 NTPKEY
failover key FOKEY
radius-server host 10.1.1.5 auth-port 1812 acct-port 1813 key RKEY
"""
    m, n = cs.mask_secrets(cisco)
    for secret in ("$9$abc", "MYCOMM", "AUTHPW", "PRIVPW", "LKEY", "AKEY", "KSECRET", "OSPFKEY", "NTPKEY", "FOKEY", "RKEY"):
        assert secret not in m, secret
    assert " key 1\n" in m and "pre-shared-key local ***" in m and "pre-shared-key address 1.2.3.4 key ***" in m
    xml = "<a><prv>BASE64KEY</prv><rocommunity>pub</rocommunity><ldap_bindpw>bp</ldap_bindpw><snmp-community-string>c</snmp-community-string><name>ok</name></a>\n"
    m, _ = cs.mask_secrets(xml)
    assert "BASE64KEY" not in m and ">pub<" not in m and ">bp<" not in m and "<snmp-community-string>***<" in m and "<name>ok</name>" in m
    forti = 'set passwd-policy "strict"\nset password ENC x\nset password-expire 90\n'
    m, n = cs.mask_secrets(forti)
    assert 'set passwd-policy "strict"' in m and "set password ***" in m and "set password-expire 90" in m and n == 1


def test_find_block_skips_the_vdom_declaration_stub():
    """A real multi-VDOM backup: config vdom / edit root / next ... end (declarations), config global,
    then one config vdom / edit root ... block per VDOM with the sections."""
    cfg = """config vdom
edit root
next
edit ot
next
end
config global
config system global
    set hostname "x"
end
end
config vdom
edit root
config firewall policy
    edit 7
        set name "a"
    next
end
end
config vdom
edit ot
config firewall policy
    edit 7
        set name "b"
    next
end
end
""".splitlines()
    b = cs.find_block(cfg, "firewall policy", 7, vdom="ot")
    assert b and 'set name "b"' in cfg[b[0]]
    b = cs.find_block(cfg, "firewall policy", 7, vdom="root")
    assert b and 'set name "a"' in cfg[b[0]]
