"""
Config-parser feature tests: N-03 (PAN-OS address objects), N-04 / F-07
(IPv6 rules), F-15 (parser coverage), F-05 (NAT parsing), rule identity for
log correlation, F-04 (config-side auto-resolve).
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Finding, FirewallRule, NatRule
from app.parsers.firewall_parser import (
    SKIP_STAT_KEYS,
    ingest_firewall_config,
    parse_cisco_acl,
    parse_cisco_nat,
    parse_firewall_config,
    parse_paloalto_nat_set,
    parse_paloalto_nat_xml,
    parse_paloalto_set,
    parse_paloalto_xml,
    parse_pfsense_nat,
    parse_pfsense_xml,
)
from app.parsers.forti_config_parser import ingest_fortigate_config


def _stats():
    return {k: 0 for k in SKIP_STAT_KEYS}


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _by(rows, key, val):
    return [r for r in rows if r[key] == val]


# ═══════════════════════════════════════════ N-03 PAN-OS address objects ══

_PAN_ADDR_XML = """<?xml version="1.0"?>
<config>
  <shared>
    <address>
      <entry name="plc"><ip-netmask>10.9.9.9</ip-netmask></entry>
      <entry name="hist"><ip-netmask>10.0.5.0/24</ip-netmask></entry>
      <entry name="vendor"><fqdn>updates.vendor.example</fqdn></entry>
    </address>
  </shared>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <address>
      <entry name="plc"><ip-netmask>10.0.1.10/32</ip-netmask></entry>
      <entry name="eng-range"><ip-range>10.0.2.0-10.0.2.255</ip-range></entry>
      <entry name="odd-range"><ip-range>10.0.3.1-10.0.3.2</ip-range></entry>
      <entry name="wild"><ip-wildcard>10.0.0.1/0.0.255.0</ip-wildcard></entry>
      <entry name="plc6"><ip-netmask>2001:db8:1::10</ip-netmask></entry>
    </address>
    <address-group>
      <entry name="inner"><static><member>hist</member><member>wild</member></static></entry>
      <entry name="outer"><static><member>eng-range</member><member>inner</member></static></entry>
      <entry name="dyn"><dynamic><filter>'quarantine'</filter></dynamic></entry>
      <entry name="loop"><static><member>loop</member><member>plc</member></static></entry>
    </address-group>
    <rulebase><security><rules>
      <entry name="eng-to-plc">
        <from><member>eng</member></from><to><member>ot</member></to>
        <source><member>outer</member></source>
        <destination><member>plc</member><member>vendor</member></destination>
        <service><member>any</member></service><action>allow</action></entry>
      <entry name="ranges">
        <source><member>odd-range</member><member>10.7.0.1-10.7.0.1</member></source>
        <destination><member>dyn</member><member>missing-obj</member><member>loop</member></destination>
        <service><member>any</member></service><action>deny</action></entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>"""


def test_panos_xml_address_objects_and_groups_resolved():
    st = _stats()
    rules = parse_paloalto_xml(_PAN_ADDR_XML, st)
    r1 = _by(rules, "policy_name", "eng-to-plc")
    srcs = {r["src"] for r in r1}
    dsts = {r["dst"] for r in r1}
    # nested static groups: eng-range (exact CIDR) + inner(hist + wildcard)
    assert srcs == {"10.0.2.0/24", "10.0.5.0/24", "wildcard:10.0.0.1/0.0.255.0"}
    # vsys object wins over the shared one of the same name; fqdn kept
    assert dsts == {"10.0.1.10", "fqdn:updates.vendor.example"}
    assert len(r1) == 3 * 2            # src x dst expanded
    assert r1[0]["src_zone"] == "eng" and r1[0]["dst_zone"] == "ot"

    r2 = _by(rules, "policy_name", "ranges")
    assert {r["src"] for r in r2} == {"10.0.3.1", "10.0.3.2", "10.7.0.1"}
    assert {r["dst"] for r in r2} == {"dynamic-group:dyn", "object:missing-obj", "10.0.1.10"}
    assert st["dynamic_address_groups"] >= 1
    assert st["unresolved_object_groups"] >= 1


def test_panos_shared_scope_used_when_no_local_definition():
    xml = """<config><shared><address>
        <entry name="h"><ip-netmask>10.1.1.1</ip-netmask></entry></address></shared>
      <devices><entry><device-group><entry name="DG1">
        <pre-rulebase><security><rules><entry name="r">
          <source><member>h</member></source><destination><member>any</member></destination>
          <service><member>any</member></service><action>allow</action></entry>
        </rules></security></pre-rulebase></entry></device-group></entry></devices></config>"""
    rules = parse_paloalto_xml(xml)
    assert rules[0]["src"] == "10.1.1.1" and rules[0]["dst"] == "any"


def test_panos_set_addresses_scopes_vsys_dg_and_quoted_names():
    text = textwrap.dedent("""\
        set shared address plc ip-netmask 10.9.9.9
        set device-group DG1 address plc ip-netmask 10.0.1.10
        set device-group DG1 address-group ot-hosts static [ plc hmi ]
        set device-group DG1 address hmi ip-range 10.0.1.20-10.0.1.21
        set device-group DG1 address-group tagged dynamic filter "'ot' and 'prod'"
        set device-group DG1 pre-rulebase security rules "Allow Modbus" source any
        set device-group DG1 pre-rulebase security rules "Allow Modbus" destination ot-hosts
        set device-group DG1 pre-rulebase security rules "Allow Modbus" service tcp-502
        set device-group DG1 pre-rulebase security rules "Allow Modbus" description "operator's rule"
        set device-group DG1 pre-rulebase security rules "Allow Modbus" action allow
        set device-group DG1 post-rulebase security rules "Deny Tagged" destination tagged
        set device-group DG1 post-rulebase security rules "Deny Tagged" action deny
        set vsys vsys1 address web ip-netmask 192.168.10.5
        set vsys vsys1 rulebase security rules "Local Web" destination web
        set vsys vsys1 rulebase security rules "Local Web" source plc
        set vsys vsys1 rulebase security rules "Local Web" action allow
        """)
    assert parse_firewall_config(text)[0] == "panos_set"
    st = _stats()
    rules = parse_paloalto_set(text, st)
    names = {r["policy_name"] for r in rules}
    assert names == {"Allow Modbus", "Deny Tagged", "Local Web"}
    modbus = _by(rules, "policy_name", "Allow Modbus")
    assert {r["dst"] for r in modbus} == {"10.0.1.10", "10.0.1.20/31"}
    assert all(r["dst_port"] == "502" and r["protocol"] == "tcp" for r in modbus)
    assert _by(rules, "policy_name", "Deny Tagged")[0]["dst"] == "dynamic-group:tagged"
    web = _by(rules, "policy_name", "Local Web")[0]
    # vsys rule: plc not in vsys1 -> shared definition
    assert (web["src"], web["dst"]) == ("10.9.9.9", "192.168.10.5")
    order = {r["policy_name"]: r["rule_order"] for r in rules}
    assert order["Allow Modbus"] < order["Local Web"] < order["Deny Tagged"]
    assert st["dynamic_address_groups"] == 1


# ═══════════════════════════════════════════════════════ F-07 / N-04 IPv6 ══

def test_cisco_asa_mixed_family_group_and_any6():
    text = textwrap.dedent("""\
        object-group network MIXED
         network-object host 10.0.0.5
         network-object 2001:db8:5::/64
        access-list OUT extended permit tcp object-group MIXED host 10.0.1.10 eq 502
        access-list OUT extended permit tcp object-group MIXED host 2001:db8::10 eq 502
        access-list OUT extended deny ip any6 any6
        """)
    st = _stats()
    rules = parse_cisco_acl(text, st)
    pairs = {(r["src"], r["dst"]) for r in rules}
    assert pairs == {("10.0.0.5", "10.0.1.10"), ("2001:db8:5::/64", "2001:db8::10"),
                     ("::/0", "::/0")}
    assert st["mixed_family_pairs_skipped"] == 2       # v6 member x v4 dst and vice versa
    assert st["rules_ipv6"] == 2
    assert st["rules_skipped_ipv6"] == 0


_PF_V6 = """<?xml version="1.0"?>
<pfsense>
  <aliases>
    <alias><name>SERVERS</name><type>host</type><address>10.0.0.5 2001:db8::5</address></alias>
  </aliases>
  <filter>
    <rule><tracker>1700000001</tracker><type>pass</type><interface>lan</interface>
      <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><address>SERVERS</address><port>443</port></destination>
      <descr>v4 to servers</descr></rule>
    <rule><tracker>1700000002</tracker><type>pass</type><interface>lan</interface>
      <ipprotocol>inet6</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><address>SERVERS</address><port>443</port></destination>
      <descr>v6 to servers</descr></rule>
    <rule><tracker>1700000003</tracker><type>block</type><interface>wan</interface>
      <ipprotocol>inet46</ipprotocol>
      <source><any/></source><destination><any/></destination>
      <descr>block all</descr></rule>
  </filter>
</pfsense>"""


def test_pfsense_inet6_inet46_and_v6_alias_members():
    st = _stats()
    rules = parse_pfsense_xml(_PF_V6, st)
    v4 = _by(rules, "policy_name", "v4 to servers")
    assert [(r["src"], r["dst"]) for r in v4] == [("any", "10.0.0.5")]
    v6 = _by(rules, "policy_name", "v6 to servers")
    assert [(r["src"], r["dst"]) for r in v6] == [("::/0", "2001:db8::5")]
    both = _by(rules, "policy_name", "block all")
    assert {(r["src"], r["dst"]) for r in both} == {("any", "any"), ("::/0", "::/0")}
    assert st["rules_ipv6"] == 2
    assert st["mixed_family_pairs_skipped"] == 2     # v6 member in inet rule, v4 in inet6 rule


_FORTI_V6 = """\
config firewall address
    edit "PLC"
        set subnet 10.0.1.10 255.255.255.255
    next
end
config firewall address6
    edit "PLC6"
        set ip6 2001:db8:1::10/128
    next
    edit "ENG6"
        set ip6 2001:db8:2::/64
    next
end
config firewall addrgrp6
    edit "OT6"
        set member "PLC6"
    next
end
config firewall policy
    edit 1
        set name "unified"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "PLC"
        set srcaddr6 "ENG6"
        set dstaddr6 "OT6"
        set action accept
        set service "MODBUS"
    next
    edit 2
        set name "v6-only"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr6 "all"
        set dstaddr6 "PLC6"
        set action accept
        set service "HTTPS"
    next
end
config firewall policy6
    edit 1
        set name "legacy6"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "ENG6"
        set dstaddr "all"
        set action deny
        set service "ALL"
    next
end
"""


def test_fortios_ipv6_policies_stored(db):
    stats = ingest_fortigate_config(_FORTI_V6, db, firewall_name="FW6")
    rows = db.query(FirewallRule).order_by(FirewallRule.id).all()
    got = {(r.policy_id, r.src, r.dst) for r in rows}
    assert got == {
        ("1", "any", "10.0.1.10/32"),
        ("1", "2001:db8:2::/64", "2001:db8:1::10/128"),
        ("2", "::/0", "2001:db8:1::10/128"),       # no IPv4 "all -> all" row
        ("policy6:1", "2001:db8:2::/64", "::/0"),
    }
    assert stats["rules_ipv6"] == 3
    order = {r.policy_id: r.rule_order for r in rows}
    assert order["policy6:1"] > order["2"] > order["1"]


def test_panos_v6_address_rows():
    xml = """<config><shared><address>
        <entry name="h6"><ip-netmask>2001:db8::7/128</ip-netmask></entry></address></shared>
      <rulebase><security><rules><entry name="r6">
        <source><member>2001:db8:9::/48</member></source><destination><member>h6</member></destination>
        <service><member>any</member></service><action>allow</action></entry>
      </rules></security></rulebase></config>"""
    st = _stats()
    rules = parse_paloalto_xml(xml, st)
    assert [(r["src"], r["dst"]) for r in rules] == [("2001:db8:9::/48", "2001:db8::7")]
    assert st["rules_ipv6"] == 1


# ═══════════════════════════════════════════════════ F-15 parser coverage ══

def test_cisco_ip_access_group_binding_sets_zones():
    text = textwrap.dedent("""\
        interface GigabitEthernet0/1
         description OT side
         ip address 10.0.1.1 255.255.255.0
         ip access-group OT-IN in
        !
        interface GigabitEthernet0/2
         ip access-group IT-OUT out
         ip access-group OT-IN in
        !
        ip access-list extended OT-IN
         10 permit tcp any host 10.0.1.10 eq 502
        ip access-list extended IT-OUT
         permit ip any any
        ip access-list extended UNBOUND
         deny ip any any
        """)
    st = _stats()
    rules = parse_cisco_acl(text, st)
    ot = _by(rules, "policy_name", "OT-IN")
    assert len(ot) == 1
    assert ot[0]["src_zone"] == "GigabitEthernet0/1,GigabitEthernet0/2" and ot[0]["dst_zone"] is None
    out = _by(rules, "policy_name", "IT-OUT")[0]
    assert out["dst_zone"] == "GigabitEthernet0/2" and out["src_zone"] is None
    unb = _by(rules, "policy_name", "UNBOUND")[0]
    assert unb["src_zone"] is None and unb["dst_zone"] is None
    assert st["acl_bindings"] == 3


def test_asa_access_group_binding():
    text = textwrap.dedent("""\
        access-list OUTSIDE_IN extended permit tcp any host 10.0.0.5 eq 443
        access-list INSIDE_OUT extended permit ip any any
        access-group OUTSIDE_IN in interface outside
        access-group INSIDE_OUT out interface inside
        access-group GLOBAL_ACL global
        """)
    rules = parse_cisco_acl(text)
    assert _by(rules, "policy_name", "OUTSIDE_IN")[0]["src_zone"] == "outside"
    assert _by(rules, "policy_name", "INSIDE_OUT")[0]["dst_zone"] == "inside"


def test_fortios_internet_service_destination(db):
    cfg = """\
config firewall policy
    edit 7
        set name "to-cloud"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set internet-service enable
        set internet-service-name "Amazon-AWS" "Microsoft-Azure"
        set action accept
        set service "HTTPS"
    next
end
"""
    stats = ingest_fortigate_config(cfg, db, firewall_name="FW-ISDB")
    rows = db.query(FirewallRule).all()
    assert {r.dst for r in rows} == {"internet-service:Amazon-AWS",
                                     "internet-service:Microsoft-Azure"}
    assert all(r.dst != "any" for r in rows)
    assert all((r.protocol, r.dst_port) == ("any", "any") for r in rows)
    assert stats["internet_service_refs"] == 2
    assert stats["unresolved_objects"] == 2


# ═══════════════════════════════════════════════════════════ F-05 NAT ══

_FORTI_NAT = """\
config firewall address
    edit "OT-NET"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config firewall vip
    edit "VIP-HMI"
        set extip 203.0.113.10
        set extintf "wan1"
        set portforward enable
        set extport 8443
        set mappedport 443
        set mappedip "10.0.1.20"
    next
    edit "VIP-HIST"
        set extip 203.0.113.11
        set extintf "wan1"
        set mappedip "10.0.1.30-10.0.1.31"
    next
end
config firewall vipgrp
    edit "VIPS"
        set interface "wan1"
        set member "VIP-HIST"
    next
end
config firewall ippool
    edit "POOL1"
        set startip 198.51.100.8
        set endip 198.51.100.15
    next
end
config firewall policy
    edit 10
        set name "in-hmi"
        set srcintf "wan1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "VIP-HMI"
        set action accept
        set service "HTTPS"
    next
    edit 11
        set name "in-hist"
        set srcintf "wan1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "VIPS"
        set action accept
        set service "HTTPS"
    next
    edit 20
        set name "out-pool"
        set srcintf "port2"
        set dstintf "wan1"
        set srcaddr "OT-NET"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "POOL1"
    next
    edit 21
        set name "out-if"
        set srcintf "port3"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
end
"""


def test_fortios_vip_dnat_snat_and_policy_dst_mapped(db):
    stats = ingest_fortigate_config(_FORTI_NAT, db, firewall_name="FW-NAT")
    rules = db.query(FirewallRule).all()
    by = {}
    for r in rules:
        by.setdefault(r.policy_id, []).append(r)
    assert {r.dst for r in by["10"]} == {"10.0.1.20/32"}          # VIP -> mapped address
    assert "VIP-HMI" in by["10"][0].raw_line
    assert {r.dst for r in by["11"]} == {"10.0.1.30/31"}          # via vipgrp
    assert stats["vip_refs_resolved"] == 2
    assert stats["unresolved_objects"] == 0

    nats = {(n.nat_type, n.name): n for n in db.query(NatRule).all()}
    hmi = nats[("dnat", "VIP-HMI")]
    assert (hmi.ext_ip, hmi.ext_port, hmi.mapped_ip, hmi.mapped_port, hmi.protocol) == (
        "203.0.113.10/32", "8443", "10.0.1.20/32", "443", "tcp")
    assert hmi.policy_id == "10" and hmi.src_intf == "wan1"
    hist = nats[("dnat", "VIP-HIST")]
    assert (hist.ext_port, hist.mapped_ip, hist.policy_id) == ("any", "10.0.1.30/31", "11")
    pool = nats[("snat", "POOL1")]
    assert (pool.policy_id, pool.orig_src, pool.mapped_ip) == ("20", "10.0.1.0/24", "198.51.100.8/29")
    intf = nats[("snat", "out-if")]
    assert (intf.orig_src, intf.mapped_ip, intf.src_intf) == ("any", "interface:wan1", "port3")
    assert stats["nat_rules_created"] == 4
    assert all(n.firewall_id == stats["firewall_id"] for n in nats.values())

    # re-ingest replaces this firewall's NAT rows (no duplicates)
    stats2 = ingest_fortigate_config(_FORTI_NAT.replace('        set nat enable\n    next\nend', '    next\nend'),
                                     db, firewall_name="FW-NAT")
    assert stats2["nat_rules_created"] == 3
    assert db.query(NatRule).count() == 3


_PAN_NAT_XML = """<config><devices><entry><vsys><entry name="vsys1">
  <address><entry name="hmi"><ip-netmask>10.0.1.20</ip-netmask></entry>
           <entry name="pub-hmi"><ip-netmask>203.0.113.20</ip-netmask></entry>
           <entry name="ot"><ip-netmask>10.0.1.0/24</ip-netmask></entry></address>
  <rulebase><nat><rules>
    <entry name="dnat-hmi"><from><member>untrust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>pub-hmi</member></destination>
      <service>service-https</service>
      <destination-translation><translated-address>hmi</translated-address>
        <translated-port>8443</translated-port></destination-translation></entry>
    <entry name="snat-ot"><from><member>ot</member></from><to><member>untrust</member></to>
      <source><member>ot</member></source><destination><member>any</member></destination>
      <service>any</service>
      <source-translation><dynamic-ip-and-port><interface-address>
        <interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation></entry>
    <entry name="static-plc"><source><member>10.0.1.10</member></source>
      <destination><member>any</member></destination><service>any</service>
      <source-translation><static-ip><translated-address>203.0.113.30</translated-address>
      </static-ip></source-translation><disabled>yes</disabled></entry>
  </rules></nat></rulebase></entry></vsys></entry></devices></config>"""


def test_panos_nat_xml():
    nats = parse_paloalto_nat_xml(_PAN_NAT_XML)
    by = {n["name"]: n for n in nats}
    d = by["dnat-hmi"]
    assert (d["nat_type"], d["ext_ip"], d["ext_port"], d["mapped_ip"], d["mapped_port"],
            d["protocol"], d["src_intf"]) == (
        "dnat", "203.0.113.20/32", "443", "10.0.1.20/32", "8443", "tcp", "untrust")
    s = by["snat-ot"]
    assert (s["nat_type"], s["orig_src"], s["mapped_ip"]) == ("snat", "10.0.1.0/24", "interface:ethernet1/1")
    st = by["static-plc"]
    assert (st["orig_src"], st["mapped_ip"], st["enabled"]) == ("10.0.1.10/32", "203.0.113.30/32", False)
    # the security parser still ignores the NAT rulebase
    assert parse_paloalto_xml(_PAN_NAT_XML) == []


def test_panos_nat_set():
    text = textwrap.dedent("""\
        set address web ip-netmask 10.0.2.5
        set rulebase nat rules "Web In" destination 198.51.100.5
        set rulebase nat rules "Web In" service tcp-80
        set rulebase nat rules "Web In" destination-translation translated-address web
        set rulebase nat rules "Web In" destination-translation translated-port 8080
        set rulebase nat rules Out source 10.0.0.0/16
        set rulebase nat rules Out source-translation dynamic-ip-and-port translated-address [ 198.51.100.9 198.51.100.10 ]
        set rulebase security rules A action allow
        """)
    by = {n["name"]: n for n in parse_paloalto_nat_set(text)}
    assert (by["Web In"]["ext_ip"], by["Web In"]["ext_port"], by["Web In"]["mapped_ip"],
            by["Web In"]["mapped_port"]) == ("198.51.100.5/32", "80", "10.0.2.5/32", "8080")
    assert (by["Out"]["orig_src"], by["Out"]["mapped_ip"]) == (
        "10.0.0.0/16", "198.51.100.9/32,198.51.100.10/32")


_PF_NAT = """<?xml version="1.0"?>
<pfsense>
  <aliases><alias><name>HMI</name><type>host</type><address>10.0.1.20</address></alias></aliases>
  <nat>
    <outbound>
      <mode>hybrid</mode>
      <rule><interface>wan</interface><source><network>10.0.1.0/24</network></source>
        <destination><any/></destination><target></target><descr>ot out</descr></rule>
      <rule><interface>wan</interface><source><network>10.0.9.0/24</network></source>
        <destination><any/></destination><nonat/></rule>
    </outbound>
    <rule><interface>wan</interface><protocol>tcp/udp</protocol>
      <source><any/></source>
      <destination><network>wanip</network><port>8000-8001</port></destination>
      <target>HMI</target><local-port>9000</local-port><descr>hmi fwd</descr></rule>
  </nat>
  <filter/>
</pfsense>"""


def test_pfsense_nat():
    nats = parse_pfsense_nat(_PF_NAT)
    d = [n for n in nats if n["nat_type"] == "dnat"]
    assert {n["protocol"] for n in d} == {"tcp", "udp"}
    assert all((n["ext_ip"], n["ext_port"], n["mapped_ip"], n["mapped_port"], n["src_intf"]) ==
               ("interface:wan", "8000-8001", "10.0.1.20/32", "9000-9001", "wan") for n in d)
    s = [n for n in nats if n["nat_type"] == "snat"]
    assert len(s) == 1                                   # <nonat/> exclusion skipped
    assert (s[0]["orig_src"], s[0]["mapped_ip"], s[0]["name"]) == ("10.0.1.0/24", "interface:wan", "ot out")


_CISCO_NAT = """\
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
 ip nat outside
interface GigabitEthernet0/1
 ip nat inside
ip nat pool PUB 198.51.100.8 198.51.100.15 netmask 255.255.255.248
ip nat inside source static tcp 10.0.1.20 443 203.0.113.20 8443 extendable
ip nat inside source static 10.0.1.30 203.0.113.30
ip nat inside source list NAT-ACL interface GigabitEthernet0/0 overload
ip nat inside source list POOL-ACL pool PUB overload
ip access-list standard NAT-ACL
 permit 10.0.1.0 0.0.0.255
 permit 10.0.2.0 0.0.0.255
access-list 5 permit 10.0.3.0 0.0.0.255
"""


def test_cisco_ios_nat():
    nats = parse_cisco_nat(_CISCO_NAT)
    d = [n for n in nats if n["nat_type"] == "dnat"]
    assert {(n["protocol"], n["ext_ip"], n["ext_port"], n["mapped_ip"], n["mapped_port"]) for n in d} == {
        ("tcp", "203.0.113.20/32", "8443", "10.0.1.20/32", "443"),
        ("any", "203.0.113.30/32", "any", "10.0.1.30/32", "any")}
    assert all(n["src_intf"] == "GigabitEthernet0/0" for n in d)
    s = [n for n in nats if n["nat_type"] == "snat"]
    assert {(n["orig_src"], n["mapped_ip"]) for n in s} == {
        ("10.0.1.0/24", "interface:GigabitEthernet0/0"),
        ("10.0.2.0/24", "interface:GigabitEthernet0/0"),
        ("acl:POOL-ACL", "198.51.100.8/29")}


def test_asa_object_and_twice_nat():
    text = textwrap.dedent("""\
        object network HMI
         host 10.0.1.20
         nat (inside,outside) static 203.0.113.20 service tcp 443 8443
        object network OT-NET
         subnet 10.0.1.0 255.255.255.0
         nat (inside,outside) dynamic interface
        object network PUB
         host 203.0.113.40
        object network PLC
         host 10.0.1.40
        nat (inside,outside) source static PLC PUB
        access-list X extended permit ip any any
        """)
    by = {(n["nat_type"], n["name"]): n for n in parse_cisco_nat(text)}
    h = by[("dnat", "HMI")]
    assert (h["ext_ip"], h["ext_port"], h["mapped_ip"], h["mapped_port"], h["src_intf"]) == (
        "203.0.113.20/32", "8443", "10.0.1.20/32", "443", "outside")
    o = by[("snat", "OT-NET")]
    assert (o["orig_src"], o["mapped_ip"], o["src_intf"]) == ("10.0.1.0/24", "interface:outside", "inside")
    t = by[("dnat", "twice-nat")]
    assert (t["ext_ip"], t["mapped_ip"]) == ("203.0.113.40/32", "10.0.1.40/32")


def test_generic_ingest_nat_rows_replaced_per_device(db):
    st = ingest_firewall_config(_CISCO_NAT, db, vendor_hint="cisco",
                                firewall_device_name="EDGE", source_file="edge.txt")
    assert st["nat_rules_created"] == 5
    rows = db.query(NatRule).all()
    assert all(n.firewall_device_id == st["firewall_device_id"] and n.device_type == "cisco_ios"
               for n in rows)
    n_rules = db.query(FirewallRule).count()
    st2 = ingest_firewall_config(_CISCO_NAT, db, vendor_hint="cisco",
                                 firewall_device_name="EDGE", source_file="edge.txt")
    assert st2["nat_rules_created"] == 5
    assert db.query(NatRule).count() == 5
    assert db.query(FirewallRule).count() == n_rules       # rules replaced too


def test_generic_reingest_does_not_touch_fortigate_rows(db):
    ingest_fortigate_config(_FORTI_NAT, db, firewall_name="SHARED")
    forti_rules = db.query(FirewallRule).count()
    forti_nat = db.query(NatRule).count()
    ingest_firewall_config(_CISCO_NAT, db, vendor_hint="cisco", firewall_device_name="SHARED")
    ingest_firewall_config(_CISCO_NAT, db, vendor_hint="cisco", firewall_device_name="SHARED")
    assert db.query(FirewallRule).filter(FirewallRule.device_type == "fortigate").count() == forti_rules
    assert db.query(NatRule).filter(NatRule.device_type == "fortigate").count() == forti_nat


# ═════════════════════════════════════════════════════════ rule identity ══

def test_rule_identity_fields_per_vendor(db):
    pf = parse_pfsense_xml(_PF_V6)
    r = _by(pf, "policy_name", "v4 to servers")[0]
    assert (r["policy_id"], r["device_name"], r["src_zone"]) == ("1700000001", "v4 to servers", "lan")

    long_name = "Allow-Engineering-Workstations-To-PLC-Modbus"
    xml = f"""<config><rulebase><security><rules>
      <entry name="short"><action>allow</action></entry>
      <entry name="{long_name}"><action>allow</action></entry>
    </rules></security></rulebase></config>"""
    pan = parse_paloalto_xml(xml)
    assert (pan[0]["policy_id"], pan[0]["policy_name"]) == ("short", "short")
    assert (pan[1]["policy_id"], pan[1]["policy_name"]) == (None, long_name)

    cis = parse_cisco_acl("ip access-list extended OT\n 10 permit ip any any\n 20 deny ip any any\n")
    # MV-04: an ACE's identity is <acl>:<sequence / line>
    assert [(r["policy_name"], r["policy_id"], r["rule_order"]) for r in cis] == [
        ("OT", "OT:10", 1), ("OT", "OT:20", 2)]

    ingest_firewall_config(_PF_V6, db, vendor_hint="pfsense")
    row = db.query(FirewallRule).filter(FirewallRule.policy_id == "1700000002").first()
    assert row.policy_name == "v6 to servers" and row.dst == "2001:db8::5"


# ═══════════════════════════════════════════════════ F-04 auto-resolve ══

_FORTI_FIND = """\
config system global
    set hostname "FW-F04"
end
config firewall policy
    edit 1
        set name "nolog"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic disable
    next
    edit 2
        set name "nolog2"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
        set logtraffic disable
    next
end
"""


def _logging_findings(db):
    return {f.detail.get("policy_id"): f for f in db.query(Finding).filter(
        Finding.check_name == "config_logging_disabled").all()}


def test_f04_reingest_closes_missing_findings_keeps_acknowledged(db, monkeypatch):
    monkeypatch.delenv("IACS_AUTO_RESOLVE", raising=False)
    ingest_fortigate_config(_FORTI_FIND, db, generate_findings=True, source_file="v1.conf")
    f = _logging_findings(db)
    assert set(f) == {"1", "2"} and all(x.status == "open" for x in f.values())
    f["2"].status = "acknowledged"
    db.commit()

    fixed = _FORTI_FIND.replace("set logtraffic disable", "set logtraffic all")
    st = ingest_fortigate_config(fixed, db, generate_findings=True, source_file="v2.conf")
    f = _logging_findings(db)
    assert f["1"].status == "closed"
    assert f["1"].notes == "Auto-resolved: not present in config re-ingest v2.conf"
    assert f["1"].closed_at is not None
    assert f["2"].status == "acknowledged"              # never touched
    assert st["findings_auto_resolved"] >= 1

    # condition comes back -> the auto-resolved finding is re-opened, not duplicated
    ingest_fortigate_config(_FORTI_FIND, db, generate_findings=True, source_file="v3.conf")
    f = _logging_findings(db)
    assert f["1"].status == "open" and f["1"].closed_at is None
    assert db.query(Finding).filter(Finding.check_name == "config_logging_disabled").count() == 2


def test_f04_disabled_by_env(db, monkeypatch):
    monkeypatch.setenv("IACS_AUTO_RESOLVE", "false")
    ingest_fortigate_config(_FORTI_FIND, db, generate_findings=True)
    fixed = _FORTI_FIND.replace("set logtraffic disable", "set logtraffic all")
    st = ingest_fortigate_config(fixed, db, generate_findings=True)
    assert st["findings_auto_resolved"] == 0
    assert all(x.status == "open" for x in _logging_findings(db).values())


def test_f04_no_findings_run_no_resolution(db, monkeypatch):
    monkeypatch.delenv("IACS_AUTO_RESOLVE", raising=False)
    ingest_fortigate_config(_FORTI_FIND, db, generate_findings=True)
    fixed = _FORTI_FIND.replace("set logtraffic disable", "set logtraffic all")
    ingest_fortigate_config(fixed, db, generate_findings=False)
    assert all(x.status == "open" for x in _logging_findings(db).values())
