"""Owner batch 2026-11-09 ("build 1, 3 and AV a with the plus items"):

  1  address groups with `exclude enable` / `exclude-member` resolve to members minus the exclusions
  3  a remote-access tunnel (dial-up IPsec, ssl.<vdom>) as the source of a service-ALL permit is high
  AV `config_av_missing_on_file_policy` is informational when the destination is labelled L0-L3
  +  switch_port_no_nac: a port whose 802.1X policy has open-auth enabled is unprotected
  +  Access Review: a FortiOS zone made only of tunnel interfaces narrows like the tunnel
  +  config_local_in_permits_all: local-in ids judged per VDOM
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Finding, FirewallRule, SwitchInterface
from app.parsers.forti_config_parser import (_build_addr_registry, _groups_with_exclusions, _resolve_address,
                                             _subtract_addresses, ingest_fortigate_config, parse_forti_block)
from tests.test_fortiswitch import FSW
from tests.test_mfa_coverage import CFG, _by, _upload, api_ctx
from tests.test_tunnel_selectors import VPN
from tests.test_wireless_ot import _label


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


# ------------------------------------------------------------------ 1. address-group exclusions
EXCL = """config firewall address
    edit "OT_net"
        set subnet 10.20.0.0 255.255.0.0
    next
    edit "Hist_net"
        set subnet 10.20.5.0 255.255.255.0
    next
    edit "Historian"
        set subnet 10.20.5.10 255.255.255.255
    next
    edit "vendor_fqdn"
        set type fqdn
        set fqdn "vendor.example.com"
    next
end
config firewall addrgrp
    edit "OT_minus_hist"
        set member "OT_net"
        set exclude enable
        set exclude-member "Hist_net"
    next
    edit "outer"
        set member "OT_minus_hist" "Historian"
    next
    edit "not_excluding"
        set member "OT_net"
        set exclude-member "Hist_net"
    next
    edit "all_but_ot"
        set member "all"
        set exclude enable
        set exclude-member "OT_net"
    next
    edit "fqdn_cut"
        set member "vendor_fqdn" "OT_net"
        set exclude enable
        set exclude-member "Hist_net"
    next
end
"""


def test_group_exclusions_resolve_to_members_minus_exclusions():
    ao, ag = _build_addr_registry(parse_forti_block(EXCL))
    st: dict = {}
    cut = _resolve_address("OT_minus_hist", ao, ag, stats=st)
    assert "10.20.5.0/24" not in cut and "10.20.4.0/24" in cut and "10.20.6.0/23" in cut
    assert not any(ipn.startswith("10.20.5.") for ipn in cut) and st["addrgrp_exclusions"] == 1
    # the cut is inherited by a group that contains the excluding group; a direct member is kept
    outer = _resolve_address("outer", ao, ag)
    assert "10.20.5.10/32" in outer and "10.20.5.0/24" not in outer
    # `exclude-member` without `exclude enable` is inert (FortiOS ignores it)
    assert _resolve_address("not_excluding", ao, ag) == ["10.20.0.0/16"]
    # "all" minus a network: concrete networks, no 'any'
    allbut = _resolve_address("all_but_ot", ao, ag)
    assert "any" not in allbut and "10.20.0.0/16" not in allbut and "10.16.0.0/14" in allbut
    # an FQDN member is not touched by a network exclusion
    fq = _resolve_address("fqdn_cut", ao, ag)
    assert "fqdn:vendor.example.com" in fq and "10.20.5.0/24" not in fq
    assert _groups_with_exclusions(ag) == {"OT_minus_hist": ["Hist_net"], "all_but_ot": ["OT_net"],
                                           "fqdn_cut": ["Hist_net"], "outer": ["Hist_net"]}


def test_subtract_addresses_leaves_unresolvable_tokens_alone():
    toks, changed = _subtract_addresses(["10.0.0.0/8", "fqdn:x", "range:1-2", "unresolved:y"], ["fqdn:z", "range:3-4"])
    assert not changed and toks == ["10.0.0.0/8", "fqdn:x", "range:1-2", "unresolved:y"]
    toks, changed = _subtract_addresses(["10.0.0.0/8", "2001:db8::/32"], ["10.0.0.0/8", "10.1.0.0/16"])
    assert changed and toks == ["2001:db8::/32"]                 # wholly excluded v4, v6 untouched


def test_policy_rows_carry_the_exclusion_note(db):
    cfg = """config system interface
    edit "port1"
        set ip 10.20.0.1 255.255.0.0
    next
    edit "port2"
        set ip 10.30.0.1 255.255.255.0
    next
end
""" + EXCL + """config firewall policy
    edit 1
        set name "to_ot_except_hist"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "OT_minus_hist"
        set service "HTTPS"
        set action accept
    next
end
"""
    st = ingest_fortigate_config(cfg, db, firewall_name="FW", generate_findings=False)
    db.commit()
    rows = db.query(FirewallRule).filter(FirewallRule.policy_id == "1").all()
    assert rows and not any(r.dst.startswith("10.20.5.") for r in rows)
    assert all("dstaddr group OT_minus_hist excludes Hist_net" in (r.raw_line or "") for r in rows)
    assert st.get("addrgrp_exclusions", 0) >= 1


# ------------------------------------------------------------------ 3. remote-access source + service ALL
RA_POL = """config system interface
    edit "ssl.root"
        set vdom "root"
        set type tunnel
    next
end
config firewall address
    edit "jump"
        set subnet 10.10.1.9 255.255.255.255
    next
end
config firewall policy
    edit 20
        set name "vendor_everything"
        set srcintf "vendor-dialup"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "jump"
        set groups "vendors"
        set service "ALL"
        set action accept
    next
    edit 21
        set name "sslvpn_everything"
        set srcintf "ssl.root"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "jump"
        set service "ALL"
        set action accept
    next
    edit 22
        set name "vendor_rdp"
        set srcintf "vendor-dialup"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "jump"
        set service "RDP"
        set action accept
    next
    edit 23
        set name "lan_everything"
        set srcintf "wan1"
        set dstintf "port1"
        set srcaddr "jump"
        set dstaddr "jump"
        set service "ALL"
        set action accept
    next
end
"""


def test_vpn_sourced_service_all_is_high(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", RA_POL))
    by = {f["detail"]["policy_id"]: f for f in _by(c, sid)["config_permit_any_any_any"]}
    assert by["20"]["severity"] == "high" and by["20"]["detail"]["from_remote_access"]
    assert by["20"]["detail"]["remote_access_interfaces"] == ["vendor-dialup"] and by["20"]["detail"]["identity"] == ["vendors"]
    assert "remote-access tunnel vendor-dialup" in by["20"]["detail"]["severity_reason"]
    assert by["21"]["severity"] == "high" and by["21"]["detail"]["remote_access_interfaces"] == ["ssl.root"]
    # service ALL from an inside interface stays medium; the VPN policy with one service is only "source all"
    assert by["23"]["severity"] == "medium" and not by["23"]["detail"]["from_remote_access"]
    assert by["22"]["severity"] == "medium" and by["22"]["detail"]["all_positions"] == ["source"] and not by["22"]["detail"]["from_remote_access"]


# ------------------------------------------------------------------ AV (option a): destination level
AV_POL = """config system interface
    edit "vlan_20"
        set vdom "root"
        set ip 10.10.20.1 255.255.255.0
        set interface "port1"
        set vlanid 20
        set type vlan
    next
    edit "dmz"
        set vdom "root"
        set ip 10.10.99.1 255.255.255.0
    next
end
config firewall address
    edit "hist"
        set subnet 10.10.20.9 255.255.255.255
    next
    edit "share"
        set subnet 10.10.99.9 255.255.255.255
    next
end
config firewall policy
    edit 30
        set name "ftp_into_ot"
        set srcintf "port1"
        set dstintf "vlan_20"
        set srcaddr "all"
        set dstaddr "hist"
        set service "FTP"
        set action accept
    next
    edit 31
        set name "smb_to_dmz"
        set srcintf "port1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "share"
        set service "SMB"
        set action accept
    next
end
"""


def test_av_finding_informational_when_destination_is_ot(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", AV_POL))
    by = {f["detail"]["policy_id"]: f for f in _by(c, sid)["config_av_missing_on_file_policy"]}
    assert by["30"]["severity"] == "medium" and by["31"]["severity"] == "medium"     # nothing labelled yet
    _label(c, "vlan_20", 2)
    _label(c, "dmz", 3.5)
    _upload(c, CFG.replace("{CM}", AV_POL))
    by = {f["detail"]["policy_id"]: f for f in _by(c, sid)["config_av_missing_on_file_policy"]}
    assert by["30"]["severity"] == "info" and by["30"]["detail"]["destination_in_ot"] and by["30"]["detail"]["dst_level"] == 2
    assert "informational" in by["30"]["title"]
    assert by["31"]["severity"] == "medium" and not by["31"]["detail"]["destination_in_ot"]


# ------------------------------------------------------------------ + NAC open-auth
FSW_OPEN = FSW.replace('''config switch-controller security-policy 802-1X
    edit "802-1X-policy-default"
        set user-group "SSO_Guest_Users"
        set open-auth disable
    next
end''', '''config switch-controller security-policy 802-1X
    edit "802-1X-policy-default"
        set user-group "SSO_Guest_Users"
        set open-auth disable
    next
    edit "open-door"
        set user-group "SSO_Guest_Users"
        set open-auth enable
    next
    edit "mab"
        set user-group "SSO_Guest_Users"
        set mac-auth-bypass enable
    next
end''').replace('''            edit "port2"
                set vlan "vlan_20"
            next''', '''            edit "port2"
                set vlan "vlan_20"
                set port-security-policy "open-door"
            next
            edit "port5"
                set vlan "vlan_20"
                set port-security-policy "mab"
            next''')


def test_open_auth_ports_are_unprotected(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FSW_OPEN))
    _label(c, "vlan_20", 1)
    _upload(c, CFG.replace("{CM}", FSW_OPEN))
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    modes = {r.port_name: r.port_security_mode for r in s.query(SwitchInterface).filter(SwitchInterface.device_name == "sw-ot-01")}
    s.close()
    assert modes["port1"] == "802.1x" and modes["port2"] == "open-auth" and modes["port5"] == "802.1x-mab" and modes["port4"] is None
    assert c.post("/reviews/run", params={"site_id": sid}).status_code == 200
    nac = _by(c, sid)["switch_port_no_nac"][0]
    d = nac["detail"]
    assert [p["port"] for p in d["ports"]] == ["port2", "port4"] and d["open_auth_ports"] == ["port2"]
    assert d["no_policy_ports"] == ["port4"] and d["mab_ports"] == ["port5"] and d["ot_ports"] == ["port2"]
    assert nac["severity"] == "medium" and "open-auth" in nac["title"]
    assert next(p for p in d["ports"] if p["port"] == "port2")["why"].startswith("open-auth")


def test_standalone_fortiswitch_port_security_mode():
    from app.parsers.switch_parser import parse_fortinet_switch_config
    text = """config system global
    set hostname "sw-x"
end
config switch interface
    edit "port1"
        set native-vlan 20
        set security-mode 802.1X
        config port-security
            set open-auth enable
        end
    next
    edit "port2"
        set native-vlan 20
        set security-mode 802.1X
        config port-security
            set mac-auth-bypass enable
        end
    next
    edit "port3"
        set native-vlan 20
        set security-mode 802.1X
    next
    edit "port4"
        set native-vlan 20
    next
end
"""
    _h, ifs, _v = parse_fortinet_switch_config(text)
    by = {i["port_name"]: i["port_security_mode"] for i in ifs}
    assert by == {"port1": "open-auth", "port2": "802.1x-mab", "port3": "802.1x", "port4": None}


def test_nac_review_reads_the_mode(db):
    from app.parsers import alert_engine as ae
    from app.models import SwitchVlan
    from app.sites import scope_site_id
    s_id = scope_site_id(db)
    db.add_all([SwitchVlan(site_id=s_id, device_name="sw1", vlan_id=20, purdue_level=1),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="p1", vlan="20", mode="access", source_file="fortilink:fw",
                                port_security_policy="x", port_security_mode="open-auth"),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="p2", vlan="20", mode="access", source_file="fortilink:fw",
                                port_security_policy="y", port_security_mode="802.1x-mab"),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="p3", vlan="20", mode="access", source_file="fortilink:fw",
                                port_security_policy="z")])          # mode unknown: the policy counts
    db.flush()
    out = ae.review_switch_port_nac(db)
    assert len(out) == 1 and out[0].detail["open_auth_ports"] == ["p1"] and out[0].detail["mab_ports"] == ["p2"]
    assert out[0].detail["port_count"] == 1 and out[0].severity == "medium"


# ------------------------------------------------------------------ + zone made of tunnel interfaces
ZONE_POL = """config system zone
    edit "vpnzone"
        set interface "ipsecgw"
    next
    edit "mixed"
        set interface "ipsecgw" "wan2"
    next
end
config firewall policy
    edit 3
        set name "Via_zone"
        set srcintf "vpnzone"
        set dstintf "vlan_101"
        set srcaddr "all"
        set dstaddr "Jumphost"
        set service "SSH"
        set action accept
    next
    edit 4
        set name "Via_mixed_zone"
        set srcintf "mixed"
        set dstintf "vlan_101"
        set srcaddr "all"
        set dstaddr "Jumphost"
        set service "RDP"
        set action accept
    next
end
"""


def test_zone_of_tunnels_is_narrowed_by_the_selectors(api):
    c, sid = api
    text = CFG.replace("{CM}", VPN + ZONE_POL)
    _upload(c, text)
    _label(c, "ipsecgw", 4)
    _label(c, "wan2", 4)
    _label(c, "vlan_101", 3)
    _upload(c, text)
    rows = c.get("/access-paths", params={"site_id": sid, "boundary_only": "true"}).json()["paths"]

    def _of(pid):
        return [r for r in rows if any(h.get("policy_id") in (pid, int(pid)) for h in r["chain"])]
    z = _of("3")
    assert z and z[0]["src"]["scope"] == "10.250.1.0/24" and "tunnel_selector" in z[0]["flags"]
    m = _of("4")                                  # a LAN member in the zone: nothing bounds it
    assert m and m[0]["src"]["scope"] == "any" and "tunnel_selector" not in m[0]["flags"]


def test_tunnel_selector_map_keys_tunnel_only_zones(api):
    from app.parsers.access_paths import tunnel_selector_map
    from app.parsers.site_scope import analysis_site
    c, sid = api
    _upload(c, CFG.replace("{CM}", VPN + ZONE_POL))
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    with analysis_site(s, sid):
        m = tunnel_selector_map(s)
    s.close()
    names = {k[1] for k in m}
    assert "ipsecgw" in names and "vpnzone" in names and "mixed" not in names
    assert m[next(k for k in m if k[1] == "vpnzone")][1] is None


# ------------------------------------------------------------------ + local-in per VDOM
MV_LOCALIN = """
    config vdom
    edit root
    next
    edit ot
    next
    end
    config global
    config system global
        set hostname "FGT-MV"
    end
    config system interface
        edit "wan1"
            set vdom "root"
            set ip 203.0.113.2 255.255.255.248
            set role wan
        next
        edit "port3"
            set vdom "ot"
            set ip 10.13.0.1 255.255.255.0
        next
    end
    end
    config vdom
    edit root
    config firewall address
        edit "src"
            set subnet 198.51.100.7 255.255.255.255
        next
    end
    config firewall local-in-policy
        edit 1
            set intf "wan1"
            set srcaddr "src"
            set dstaddr "all"
            set action accept
            set service "ALL"
            set schedule "always"
        next
    end
    next
    edit ot
    config firewall address
        edit "src"
            set subnet 10.13.0.50 255.255.255.255
        next
    end
    config firewall local-in-policy
        edit 1
            set intf "port3"
            set srcaddr "src"
            set dstaddr "all"
            set action accept
            set service "ALL"
            set schedule "always"
        next
    end
    next
    end
"""


def test_local_in_policies_judged_per_vdom(db):
    ingest_fortigate_config(textwrap.dedent(MV_LOCALIN), db, firewall_name="FGT-MV", generate_findings=True)
    db.commit()
    f = {x.detail["ref_key"]: x for x in db.query(Finding).filter(Finding.check_name == "config_local_in_permits_all")}
    assert set(f) == {"local-in:root/1", "local-in:ot/1"}
    root, ot = f["local-in:root/1"], f["local-in:ot/1"]
    assert root.detail["vdom"] == "root" and "(vdom root)" in root.title and root.severity == "high"      # public source on the WAN leg
    assert ot.detail["vdom"] == "ot" and ot.detail["sources_resolved"] == ["10.13.0.50/32"] and ot.severity == "medium"
    assert len({x.source_ref for x in f.values()}) == 2
