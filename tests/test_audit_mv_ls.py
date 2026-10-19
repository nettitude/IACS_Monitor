"""Audit 2026-10-06 (MV / LS round): regression tests for the confirmed
findings - see docs/code-review-remediation.md, section "Audit 2026-10-06"."""
import ipaddress

import pytest

from app.models import Firewall, FirewallInterface, FirewallRule, Host, NetworkSession, Site
from app.parsers import fw_interfaces as fwi
from app.parsers import l3_switch as l3
from app.parsers.firewall_parser import ingest_firewall_config, parse_cisco_acl
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.site_scope import analysis_site
from app.parsers.switch_parser import ingest_switch_config
from app.sites import ingest_site
from tests.test_access_paths import _site, db  # noqa: F401

SW = """hostname SW
ip routing
interface Vlan10
 ip address 10.10.0.254 255.255.0.0
 ip access-group OT_IN in
interface Vlan20
 ip address 10.20.0.254 255.255.255.0
 ip access-group OT_IN in
interface Vlan50
 ip address 10.50.0.254 255.255.255.0
 ip access-group GHOST in
ip access-list extended OT_IN
 permit tcp 10.10.0.0 0.0.255.255 host 10.50.0.10 eq 502
 deny ip any any
"""

FG = """config system global
    set hostname FG
end
config system interface
    edit "port1"
        set ip 10.10.0.1 255.255.0.0
    next
    edit "port2"
        set ip 10.50.0.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""


def _rules(db, fw):
    return db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id).order_by(FirewallRule.rule_order).all()


# ------------------------------------------------------------ L3 switch --
def test_acl_bound_on_two_svis_and_undefined_acl(db):
    """AU-01: an ACL bound on two SVIs keeps its entries on both; an ACL that
    is bound but not defined yields no made-up deny."""
    sid = _site(db, "AU")
    with ingest_site(db, sid):
        st = ingest_switch_config(SW, db, device_name="SW", vendor_hint="cisco")
    fw = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.vendor == l3.VENDOR).one()
    rows = _rules(db, fw)
    by_zone = {}
    for r in rows:
        by_zone.setdefault(r.src_zone, []).append(r)
    assert st["l3"]["acl_rules"] == 4                       # 2 ACEs x 2 SVIs
    assert {r.policy_id for r in by_zone["Vlan10"]} == {"OT_IN:1", "OT_IN:2", "implicit:acldeny:1"}
    assert {r.policy_id for r in by_zone["Vlan20"]} == {"OT_IN:1", "OT_IN:2", "implicit:acldeny:2"}
    assert "Vlan50" not in by_zone                          # GHOST: no rows, no deny-all
    assert st["l3"]["acls_not_found"] == ["GHOST (Vlan50 in)"]
    assert all(len(r.policy_id) <= 32 for r in rows)
    assert l3.bindings_of(rows) == {"vlan10": {"in": "OT_IN"}, "vlan20": {"in": "OT_IN"}}


def test_switch_name_taken_by_a_firewall_does_not_break_the_upload(db):
    """AU-04: a switch named like a firewall of the site is not modelled as a
    routing device, and the upload (VLANs, hardening) still succeeds."""
    sid = _site(db, "AU2")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="SW")
        st = ingest_switch_config(SW, db, device_name="SW", vendor_hint="cisco")
    assert "error" in st["l3"] and not st["l3"]["enforcement_point"]
    assert db.query(Firewall).filter(Firewall.site_id == sid).count() == 1
    assert db.query(Firewall).filter(Firewall.site_id == sid).one().vendor == "fortigate"
    assert st["interfaces_touched"] > 0


def test_svi_levels_follow_relabelling_after_run_checks(db):
    """AU-02: run_purdue_suggestions must not freeze auto-derived SVI levels."""
    from app.parsers.topology_manager import run_purdue_suggestions, set_interface_labels
    sid = _site(db, "AU3")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="FG")
        ingest_switch_config(SW, db, device_name="SW", vendor_hint="cisco")
    db.commit()
    fg = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == "FG").one()
    port2 = next(i for i in fg.interfaces if i.name == "port2")
    with analysis_site(db, sid):
        set_interface_labels(db, port2.id, purdue_level=1, site_id=sid)
        db.commit()
        sw = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.vendor == l3.VENDOR).one()
        vl50 = next(i for i in sw.interfaces if i.name == "Vlan50")
        assert (vl50.purdue_level, vl50.purdue_suggestion_source) == (1, l3.AUTO_SOURCE)
        run_purdue_suggestions(db)
        db.commit()
        db.expire_all()
        assert vl50.purdue_suggestion_source == l3.AUTO_SOURCE
        set_interface_labels(db, port2.id, purdue_level=2, site_id=sid)
        db.commit()
        db.expire_all()
        assert vl50.purdue_level == 2


def test_switch_helpers_are_site_scoped(db):
    """AU-03: another site's firewall labels / interface MACs never reach a
    site's switch levels or router knowledge."""
    a, b = _site(db, "AU-A"), _site(db, "AU-B")
    with ingest_site(db, a):
        ingest_fortigate_config(FG, db, firewall_name="FG")
    db.commit()
    fg = db.query(Firewall).filter(Firewall.site_id == a).one()
    for i in fg.interfaces:
        i.purdue_level = {"port1": 4, "port2": 1}[i.name]
    db.add(Host(ip="10.50.0.1", mac="00:09:0f:00:00:01", site_id=a, sources=["arp"]))
    db.commit()
    with ingest_site(db, b):
        ingest_switch_config(SW, db, device_name="SW", vendor_hint="cisco")
        assert l3.known_router_macs(db) == {}
    sw = db.query(Firewall).filter(Firewall.site_id == b, Firewall.vendor == l3.VENDOR).one()
    assert all(i.purdue_level is None for i in sw.interfaces)
    with analysis_site(db, a):
        assert "00:09:0f:00:00:01" in l3.known_router_macs(db)
        assert ipaddress.ip_network("10.50.0.0/24") in l3.known_networks(db)


def test_router_macs_treats_ha_members_as_one_device(db):
    """AU-06: HA members share interface addresses; the MAC is not ambiguous."""
    from app.models import FirewallGroup
    from app.parsers.firewall_groups import KIND_HA
    sid = _site(db, "AU-HA")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="FG-A")
        ingest_fortigate_config(FG, db, firewall_name="FG-B")
    db.commit()
    fa = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == "FG-A").one()
    fb = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == "FG-B").one()
    g = FirewallGroup(site_id=sid, kind=KIND_HA, name="ha", primary_firewall_id=fa.id)
    db.add(g)
    db.flush()
    fa.ha_group_id = fb.ha_group_id = g.id
    db.add(Host(ip="10.50.0.1", mac="00:09:0f:00:00:aa", site_id=sid, sources=["arp"]))
    db.commit()
    with analysis_site(db, sid):
        assert l3.router_macs(db) == {"00:09:0f:00:00:aa": fa.id}


def test_mgmt_svi_out_acl_and_permit_any_in_acl():
    """AU-11: an 'in' ACL ending in permit-any does not filter; an 'out' ACL
    on the management SVI does."""
    class R:
        def __init__(self, pid, name, action, src="any", dst="any", port="any", sz=None, dz=None, order=0):
            self.policy_id, self.policy_name, self.action = pid, name, action
            self.src, self.dst, self.dst_port, self.src_zone, self.dst_zone, self.rule_order = src, dst, port, sz, dz, order
    rows = [R("X:1", "X", "permit", "10.0.0.0/8", "10.99.0.0/24", "22", "Vlan10", None, 1),
            R("X:2", "X", "permit", sz="Vlan10", order=2),
            R("implicit:acldeny:1", "X", "deny", sz="Vlan10", order=3),
            R("Y:1", "Y", "permit", "10.0.0.5", "any", "22", None, "Vlan99", 4),
            R("implicit:acldeny:2", "Y", "deny", dz="Vlan99", order=5)]
    assert l3.bindings_of(rows) == {"vlan10": {"in": "X"}, "vlan99": {"out": "Y"}}


# ---------------------------------------------------------------- ASA --
ASA = """ASA Version 9.12
hostname ASA
interface Management0/0
 management-only
 nameif management
 security-level 100
 ip address 10.99.0.1 255.255.255.0
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
interface GigabitEthernet0/1
 nameif inside_long_name_for_the_control_network
 security-level 90
 ip address 10.20.0.1 255.255.0.0
interface GigabitEthernet0/2
 nameif dmz
 security-level 50
 ip address 10.40.1.1 255.255.255.0
interface GigabitEthernet0/3
 nameif dmz2
 security-level 50
 ip address 10.41.1.1 255.255.255.0
access-list DMZ_OUT extended permit tcp any any eq 443
access-group DMZ_OUT out interface dmz
"""


def test_asa_implicit_rules_edge_cases():
    """AU-07/08: management-only never forwards; a destination with an
    outbound ACL has no any/any permit; equal levels only with
    same-security-traffic; long nameifs get distinct ids."""
    info = fwi.parse_cisco_interfaces(ASA)
    rows = fwi.implicit_rules(info)
    pairs = {(r["src_zone"], r["dst_zone"]) for r in rows}
    assert not any("management" in p for p in pairs)
    assert ("inside_long_name_for_the_control_network", "dmz") not in pairs      # DMZ_OUT decides
    assert ("inside_long_name_for_the_control_network", "dmz2") in pairs
    assert ("dmz", "dmz2") not in pairs
    ids = [r["policy_id"] for r in rows]
    assert len(set(ids)) == len(ids) and all(len(i) <= 32 for i in ids)
    info2 = fwi.parse_cisco_interfaces(ASA + "same-security-traffic permit inter-interface\n")
    assert ("dmz", "dmz2") in {(r["src_zone"], r["dst_zone"]) for r in fwi.implicit_rules(info2)}
    info3 = fwi.parse_cisco_interfaces(ASA + "access-group GLOBAL global\n")
    assert fwi.implicit_rules(info3) == []


def test_ace_ids_fit_and_stay_distinct():
    """AU-09: long ACL names keep their sequence in a 32-char id."""
    acl = "Inside_To_DMZ_Servers_Allowed_Long"
    rows = parse_cisco_acl(f"ip access-list extended {acl}\n 12 permit ip any any\n 123 deny ip any any\n")
    ids = [r["policy_id"] for r in rows]
    assert len(set(ids)) == 2 and all(len(i) <= 32 for i in ids)
    assert ids[0].endswith(":12") and ids[1].endswith(":123")


def test_cisco_finding_identity_survives_insertion():
    """AU-10: findings are keyed on the ACE text, not its position."""
    from app.parsers.alert_engine import _disabled_rule_group_key
    r1 = FirewallRule(device_type="cisco_asa", policy_id="OT:2", policy_name="OT", raw_line="permit tcp any any eq 502")
    r2 = FirewallRule(device_type="cisco_asa", policy_id="OT:3", policy_name="OT",
                      raw_line="permit tcp any any eq 502  ! remark: moved down")
    assert _disabled_rule_group_key(r1) == _disabled_rule_group_key(r2)


def test_generic_config_never_converts_a_fortigate_row(db):
    """AU-05: a generic config named like a FortiGate keeps its rules but
    leaves the FortiGate's interfaces alone."""
    sid = _site(db, "AU-FG")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="EDGE")
        st = ingest_firewall_config(ASA, db, vendor_hint="cisco", firewall_device_name="EDGE")
    assert "interfaces_skipped" in st and "firewall_id" not in st
    fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
    assert fw.vendor == "fortigate" and {i.name for i in fw.interfaces} == {"port1", "port2"}


def test_acl_only_reupload_keeps_rules_attached(db):
    """AU-12: an ACL-only paste of a device with interfaces keeps firewall_id."""
    sid = _site(db, "AU-ACL")
    with ingest_site(db, sid):
        ingest_firewall_config(ASA + "access-list DMZ_IN extended permit tcp any any eq 22\n"
                               "access-group DMZ_IN in interface dmz\n", db, vendor_hint="cisco",
                               firewall_device_name="ASA")
        st = ingest_firewall_config("access-list DMZ_IN extended permit tcp any any eq 22\n", db,
                                    vendor_hint="cisco", firewall_device_name="ASA")
    assert st.get("firewall_id")
    assert {r.firewall_id for r in db.query(FirewallRule).filter(FirewallRule.device_name == "ASA")} == {st["firewall_id"]}


def test_pfsense_disabled_interface():
    """AU-13: no <enable/> means disabled."""
    xml = ("<pfsense><system><hostname>pf</hostname></system><interfaces>"
           "<lan><if>em1</if><enable/><ipaddr>10.1.0.1</ipaddr><subnet>24</subnet></lan>"
           "<opt1><if>em2</if><ipaddr>10.60.0.1</ipaddr><subnet>24</subnet></opt1>"
           "</interfaces></pfsense>")
    st = {i["name"]: i["status"] for i in fwi.parse_pfsense_interfaces(xml)["interfaces"]}
    assert st == {"lan": "up", "opt1": "down"}


def test_panos_multi_vsys_zones_and_loopback():
    """AU-14: zone names repeat per vsys; loopback / tunnel units are interfaces."""
    xml = """<config><devices><entry name="x"><network><interface>
      <ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.1.0.1/24"/></ip></layer3></entry></ethernet>
      <loopback><units><entry name="loopback.1"><ip><entry name="10.9.9.9/32"/></ip></entry></units></loopback>
      <tunnel><units><entry name="tunnel.1"/></units></tunnel>
    </interface></network><vsys>
      <entry name="vsys1"><zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry>
      <entry name="vsys2"><zone><entry name="trust"><network><layer3><member>loopback.1</member></layer3></network></entry></zone></entry>
    </vsys></entry></devices></config>"""
    info = fwi.parse_panos_xml_interfaces(xml)
    assert {i["name"]: i["type"] for i in info["interfaces"]} == {"ethernet1/1": "physical", "loopback.1": "loopback",
                                                                  "tunnel.1": "tunnel"}
    assert info["zones"] == {"vsys1/trust": ["ethernet1/1"], "vsys2/trust": ["loopback.1"]}


def test_jump_host_membership_not_description_match(db):
    """AU-15: a jump host inside a declared management subnet is still a jump
    host; a subnet whose label says 'jump host' is not one."""
    from app.models import ApprovedHost, Baseline
    from app.parsers import mgmt_networks as mn
    sid = _site(db, "AU-JH")
    bl = Baseline(site_id=sid, name="b", is_active=True)
    db.add(bl)
    db.flush()
    db.add(ApprovedHost(baseline_id=bl.id, ip="10.40.1.20", role="jump_host"))
    db.commit()
    with analysis_site(db, sid):
        mn.declare(db, sid, kind="subnet", cidr="10.40.1.0/24", label="DMZ mgmt (jump host segment)")
        db.commit()
        ctx = mn.build_context(db)
        assert ctx.is_jump_host("10.40.1.20")
        assert not ctx.is_jump_host("10.40.1.99")


# ----------------------------------------------------------- carriers --
def test_carrier_kept_on_session_fold(db):
    from app.parsers.host_identity import merge_hosts
    sid = _site(db, "AU-C")
    a = Host(ip="10.1.0.5", mac="aa:aa:aa:aa:aa:01", site_id=sid, sources=["pcap"])
    a2 = Host(ip="10.1.0.5", site_id=sid, sources=["pcap"])
    b = Host(ip="10.2.0.9", mac="bb:bb:bb:bb:bb:02", site_id=sid, sources=["pcap"])
    db.add_all([a, a2, b])
    db.flush()
    s1 = NetworkSession(src_host_id=a.id, dst_host_id=b.id, src_port=1000, dst_port=502, transport="tcp")
    s2 = NetworkSession(src_host_id=a2.id, dst_host_id=b.id, src_port=1000, dst_port=502, transport="tcp",
                        carrier_mac="00:09:0f:00:00:01")
    db.add_all([s1, s2])
    db.commit()
    merge_hosts(db, a, a2)
    db.commit()
    assert db.query(NetworkSession).count() == 1
    assert db.query(NetworkSession).one().carrier_mac == "00:09:0f:00:00:01"


def test_mac_only_row_not_folded_into_a_routed_binding(db):
    """AU-16: a MAC seen with several addresses (router-like) keeps its own
    MAC-table row; a hand-classified MAC-only row is never folded."""
    from app.parsers.host_identity import HostIdentityResolver
    sid = _site(db, "AU-M")
    db.add(Host(ip="10.5.0.7", site_id=sid, sources=["config"]))
    sw = Host(mac="00:a3:d1:f0:00:01", site_id=sid, sources=["mac_table"], vlan="10")
    db.add(sw)
    db.commit()
    r = HostIdentityResolver(db, "pcap", observed={"00:a3:d1:f0:00:01": {"10.5.0.7", "10.6.0.8"}})
    with ingest_site(db, sid):
        r.reconcile("10.5.0.7", "00:a3:d1:f0:00:01")
    db.commit()
    assert db.query(Host).filter(Host.id == sw.id).one().ip is None       # still the switch row
