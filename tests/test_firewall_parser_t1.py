"""
Tier-1 remediation tests for app/parsers/firewall_parser.py
(T1-20, T1-21, T1-22, T1-25, T1-26, T1-27 in docs/code-review-remediation.md).
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import FirewallRule
from app.parsers.firewall_parser import (
    SKIP_STAT_KEYS,
    canonical_ports,
    ingest_firewall_config,
    parse_canonical_ports,
    parse_cisco_acl,
    parse_paloalto_set,
    parse_paloalto_xml,
    parse_pfsense_xml,
    split_port_field,
)


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


# ───────────────────────────────────────────── canonical port helpers ──

def test_canonical_ports_sorted_merged():
    assert canonical_ports([(443, 443), (80, 80)]) == "80,443"
    assert canonical_ports([(1000, 2000), (443, 443), (80, 80), (1500, 2500)]) == "80,443,1000-2500"
    assert canonical_ports([(1, 65535)]) == "any"
    assert canonical_ports([(0, 65535)]) == "any"
    assert canonical_ports([(22, 22)]) == "22"


def test_parse_canonical_roundtrip():
    assert parse_canonical_ports("80,443,1000-2000") == [(80, 80), (443, 443), (1000, 2000)]
    assert parse_canonical_ports("any") is None
    with pytest.raises(ValueError):
        parse_canonical_ports("eq 22")


def test_split_long_port_field():
    field = canonical_ports([(p, p) for p in range(1000, 1200, 2)])
    assert len(field) > 255
    parts = split_port_field(field)
    assert len(parts) > 1
    assert all(len(p) <= 255 for p in parts)
    assert ",".join(parts) == field


def test_long_port_list_split_into_rows():
    ports = " ".join(str(p) for p in range(1000, 1200, 2))
    text = f"ip access-list extended BIG\n permit tcp any host 10.0.0.1 eq {ports}\n"
    rules = parse_cisco_acl(text)
    assert len(rules) > 1
    assert all(len(r["dst_port"]) <= 255 for r in rules)
    assert len({r["rule_order"] for r in rules}) == 1


# ─────────────────────────────────────────────────── T1-27 Cisco ports ──

@pytest.mark.parametrize("spec,expected", [
    ("eq 22", "22"),
    ("eq telnet", "23"),
    ("eq www", "80"),
    ("eq domain", "53"),
    ("eq cmd", "514"),
    ("eq www 443", "80,443"),
    ("range 1000 2000", "1000-2000"),
    ("range ftp-data ftp", "20-21"),
    ("gt 1023", "1024-65535"),
    ("lt 1024", "1-1023"),
    ("neq 53", "1-52,54-65535"),
])
def test_cisco_port_operators(spec, expected):
    rules = parse_cisco_acl(f"permit tcp any host 10.0.0.1 {spec}")
    assert len(rules) == 1
    assert rules[0]["dst_port"] == expected


def test_cisco_unknown_port_name_not_widened():
    st = _stats()
    rules = parse_cisco_acl("permit tcp any host 10.0.0.1 eq frobnicate", st)
    assert rules[0]["dst_port"] == "unknown:frobnicate"
    assert st["unknown_port_names"] == 1


def test_cisco_source_port_not_stored_as_dst():
    rules = parse_cisco_acl("permit udp any eq 123 host 10.0.0.1 eq ntp")
    assert rules[0]["dst_port"] == "123"
    assert rules[0]["dst"] == "10.0.0.1"


def test_cisco_icmp_port_any():
    rules = parse_cisco_acl("permit icmp any any echo")
    assert rules[0]["protocol"] == "icmp"
    assert rules[0]["dst_port"] == "any"


# ─────────────────────────────────── T1-26 ACL forms, masks, ipv6 ──

def test_named_acl_sequence_numbers_and_remarks():
    text = textwrap.dedent("""\
        ip access-list extended OT-IN
         remark allow engineering
         10 permit tcp 10.0.1.0 0.0.0.255 host 10.0.2.10 eq 502 log
         20 remark done
         30 deny ip any any log
        """)
    rules = parse_cisco_acl(text)
    assert len(rules) == 2
    assert rules[0]["device_name"] == "OT-IN"
    assert rules[0]["src"] == "10.0.1.0/24"
    assert rules[0]["dst_port"] == "502"
    assert rules[1]["action"] == "deny"
    assert [r["rule_order"] for r in rules] == [1, 2]


def test_asa_extended_and_line_numbers():
    text = textwrap.dedent("""\
        access-list OUTSIDE_IN remark permit historian
        access-list OUTSIDE_IN extended permit tcp 10.1.0.0 255.255.0.0 host 10.0.0.5 eq 443
        access-list OUTSIDE_IN line 2 extended deny ip any4 any4 log
        """)
    rules = parse_cisco_acl(text)
    assert len(rules) == 2
    assert rules[0]["device_name"] == "OUTSIDE_IN"
    assert rules[0]["src"] == "10.1.0.0/16"       # netmask, not wildcard
    assert rules[0]["dst_port"] == "443"
    assert rules[1]["src"] == "any" and rules[1]["action"] == "deny"


def test_asa_inactive_is_disabled():
    st = _stats()
    rules = parse_cisco_acl(
        "access-list X extended permit tcp any host 10.0.0.5 eq 22 inactive", st)
    # Kept, flagged disabled (reported by review_disabled_rules), not dropped.
    assert len(rules) == 1 and rules[0]["enabled"] is False
    assert rules[0]["dst_port"] == "22"
    assert st["rules_disabled"] == 1


def test_standard_numbered_acl():
    rules = parse_cisco_acl("access-list 10 permit 10.0.0.0 0.0.0.255")
    assert len(rules) == 1
    r = rules[0]
    assert r["device_name"] == "10"
    assert r["src"] == "10.0.0.0/24"
    assert r["dst"] == "any"
    assert r["protocol"] == "any"
    assert r["dst_port"] == "any"


def test_standard_named_acl_host():
    text = "ip access-list standard MGMT\n permit host 10.9.9.9\n deny any log\n"
    rules = parse_cisco_acl(text)
    assert [(r["src"], r["protocol"], r["action"]) for r in rules] == [
        ("10.9.9.9", "any", "permit"), ("any", "any", "deny")]
    assert all(r["device_name"] == "MGMT" for r in rules)


def test_extended_numbered_acl_wildcard():
    rules = parse_cisco_acl(
        "access-list 101 permit tcp 10.0.1.0 0.0.0.255 host 10.0.1.10 eq 502")
    assert rules[0]["device_name"] == "101"
    assert rules[0]["src"] == "10.0.1.0/24"


def test_ipv6_acl_section_stored_as_v6_rows():
    # F-07: IPv6 ACLs are stored (no longer skipped); "any" in a v6 ACL is
    # written as ::/0 so a v6 row can never match an IPv4 query.
    text = textwrap.dedent("""\
        ip access-list extended V4
         permit tcp any host 10.0.0.1 eq 22
        ipv6 access-list V6
         permit tcp any host 2001:db8::1 eq 22
         deny ipv6 any any
        """)
    st = _stats()
    rules = parse_cisco_acl(text, st)
    assert len(rules) == 3
    assert rules[0]["device_name"] == "V4" and rules[0]["src"] == "any"
    v6 = [r for r in rules if r["device_name"] == "V6"]
    assert [(r["src"], r["dst"], r["protocol"], r["dst_port"], r["action"]) for r in v6] == [
        ("::/0", "2001:db8::1", "tcp", "22", "permit"),
        ("::/0", "::/0", "any", "any", "deny")]
    assert st["rules_ipv6"] == 2
    assert st["rules_skipped_ipv6"] == 0


def test_established_time_range_trailing():
    rules = parse_cisco_acl(
        "permit tcp any 10.0.0.0 0.0.255.255 established time-range WORK")
    assert rules[0]["dst"] == "10.0.0.0/16"
    assert rules[0]["dst_port"] == "any"


@pytest.mark.parametrize("mask,expected", [
    ("0.0.0.255", "10.0.0.0/24"),         # wildcard
    ("255.255.255.0", "10.0.0.0/24"),     # netmask (bit pattern wins)
    ("0.0.0.0", "10.0.0.0"),              # IOS default: wildcard -> host
])
def test_mask_detection_ios(mask, expected):
    rules = parse_cisco_acl(f"permit ip 10.0.0.0 {mask} any")
    assert rules[0]["src"] == expected


def test_noncontiguous_wildcard_preserved():
    rules = parse_cisco_acl("permit ip 10.0.0.1 0.0.255.0 any")
    assert rules[0]["src"].startswith("wildcard:")


# ─────────────────────────────────────────────── T1-25 object-groups ──

def test_ios_object_group_network_and_service_expansion():
    text = textwrap.dedent("""\
        object-group network ENG
         host 10.0.1.5
         10.0.2.0 255.255.255.0
         range 10.0.3.0 10.0.3.3
        object-group network PLCS
         host 10.0.1.10
        object-group service OT-SVC
         tcp eq 502
         tcp eq 102
        ip access-list extended OT
         10 permit tcp object-group ENG host 10.0.1.10 eq 502
         20 permit object-group OT-SVC object-group ENG object-group PLCS
        """)
    rules = parse_cisco_acl(text)
    first = [r for r in rules if r["rule_order"] == 1]
    assert {r["src"] for r in first} == {"10.0.1.5", "10.0.2.0/24", "10.0.3.0/30"}
    assert all(r["dst"] == "10.0.1.10" and r["dst_port"] == "502" for r in first)
    second = [r for r in rules if r["rule_order"] == 2]
    assert len(second) == 3 * 2
    assert {r["dst_port"] for r in second} == {"502", "102"}
    assert all(r["protocol"] == "tcp" for r in second)


def test_asa_object_groups():
    text = textwrap.dedent("""\
        object network HMI-1
         host 10.0.5.20
        object network SCADA-NET
         subnet 10.0.6.0 255.255.255.0
        object-group network HMIS
         network-object object HMI-1
         network-object host 10.0.5.21
         network-object 10.0.7.0 255.255.255.128
        object-group network NESTED
         group-object HMIS
         network-object object SCADA-NET
        object-group service WEB tcp
         port-object eq www
         port-object range 8000 8080
        object-group service MIXED
         service-object tcp destination eq 502
         service-object udp destination eq 47808
        access-list IN extended permit tcp object-group NESTED any object-group WEB
        access-list IN extended permit object-group MIXED any object SCADA-NET
        """)
    rules = parse_cisco_acl(text)
    r1 = [r for r in rules if r["rule_order"] == 1]
    assert {r["src"] for r in r1} == {"10.0.5.20", "10.0.5.21", "10.0.7.0/25", "10.0.6.0/24"}
    assert {r["dst_port"] for r in r1} == {"80,8000-8080"}
    r2 = [r for r in rules if r["rule_order"] == 2]
    assert {(r["protocol"], r["dst_port"]) for r in r2} == {("tcp", "502"), ("udp", "47808")}
    assert all(r["dst"] == "10.0.6.0/24" for r in r2)


def test_unresolved_object_group_tagged_and_counted():
    st = _stats()
    rules = parse_cisco_acl("permit tcp object-group NOPE host 10.0.0.1 eq 22", st)
    assert rules[0]["src"] == "object-group:NOPE"
    assert rules[0]["dst"] == "10.0.0.1"
    assert st["unresolved_object_groups"] == 1


# ───────────────────────────────────────────────────────── pfSense ──

_PF = """<?xml version="1.0"?>
<pfsense>
  <aliases>
    <alias><name>WEBPORTS</name><type>port</type><address>80 443 8000:8080</address></alias>
    <alias><name>PLCS</name><type>host</type><address>10.0.1.10 10.0.1.11</address></alias>
  </aliases>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
      <disabled/>
      <source><any/></source><destination><address>10.0.1.10</address><port>502</port></destination>
      <descr>disabled rule</descr></rule>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
      <source><not/><address>10.9.0.0/16</address></source>
      <destination><address>PLCS</address><port>WEBPORTS</port></destination>
      <descr>negated permit</descr></rule>
    <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
      <source><any/></source><destination><not/><address>10.0.0.0/8</address></destination>
      <descr>negated deny</descr></rule>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp/udp</protocol>
      <source><any/></source><destination><any/><port>1000:2000</port></destination>
      <descr>range</descr></rule>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
      <source><any/></source><destination><any/><port>NOSUCH</port></destination>
      <descr>bad alias</descr></rule>
  </filter>
</pfsense>"""


def test_pfsense_disabled_negation_ports_aliases():
    st = _stats()
    rules = parse_pfsense_xml(_PF, st)
    assert st["rules_disabled"] == 1
    assert st["rules_skipped_negated_deny"] == 1
    neg = [r for r in rules if r["device_name"] == "negated permit"]
    assert {r["dst"] for r in neg} == {"10.0.1.10", "10.0.1.11"}
    assert all(r["src"] == "any" for r in neg)
    assert all("[negated src: 10.9.0.0/16]" in r["raw_line"] for r in neg)
    assert all(r["dst_port"] == "80,443,8000-8080" for r in neg)
    rng = [r for r in rules if r["device_name"] == "range"]
    assert {(r["protocol"], r["dst_port"]) for r in rng} == {("tcp", "1000-2000"), ("udp", "1000-2000")}
    bad = [r for r in rules if r["device_name"] == "bad alias"]
    assert bad[0]["dst_port"] == "alias:NOSUCH"
    dis = [r for r in rules if r["device_name"] == "disabled rule"]
    assert dis and all(r["enabled"] is False for r in dis)
    assert all(r["enabled"] is True for r in rules if r["device_name"] != "disabled rule")


# ─────────────────────────────────────────────────────── PAN-OS XML ──

_PAN_PANORAMA = """<?xml version="1.0"?>
<config>
  <shared>
    <service>
      <entry name="svc-modbus"><protocol><tcp><port>502</port></tcp></protocol></entry>
      <entry name="svc-multi"><protocol><tcp><port>443,80,1000-2000</port></tcp></protocol></entry>
    </service>
    <service-group>
      <entry name="grp-ot"><members><member>svc-modbus</member><member>svc-multi</member></members></entry>
    </service-group>
  </shared>
  <devices><entry><device-group><entry name="DG1">
    <post-rulebase><security><rules>
      <entry name="post-1"><source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><action>deny</action></entry>
    </rules></security></post-rulebase>
    <pre-rulebase><security><rules>
      <entry name="pre-1"><source><member>10.0.0.0/8</member></source><destination><member>10.0.1.10</member></destination>
        <service><member>grp-ot</member></service><action>allow</action></entry>
    </rules></security>
    <nat><rules>
      <entry name="nat-1"><source><member>any</member></source><destination><member>any</member></destination>
        <service>any</service></entry>
    </rules></nat>
    <decryption><rules>
      <entry name="decrypt-1"><source><member>any</member></source><destination><member>any</member></destination></entry>
    </rules></decryption>
    </pre-rulebase>
  </entry></device-group></entry></devices>
  <devices><entry><vsys><entry name="vsys1"><rulebase>
    <security><rules>
      <entry name="local-1"><source><member>any</member></source><destination><member>10.0.2.2</member></destination>
        <service><member>application-default</member></service><action>allow</action></entry>
      <entry name="local-noaction"><source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service></entry>
      <entry name="local-disabled"><source><member>any</member></source><destination><member>any</member></destination>
        <service><member>any</member></service><action>allow</action><disabled>yes</disabled></entry>
      <entry name="local-neg"><source><member>10.5.0.0/16</member></source><destination><member>10.0.3.3</member></destination>
        <negate-source>yes</negate-source>
        <service><member>service-http</member></service><action>allow</action></entry>
      <entry name="local-neg-deny"><source><member>10.5.0.0/16</member></source><destination><member>any</member></destination>
        <negate-destination>yes</negate-destination>
        <service><member>any</member></service><action>drop</action></entry>
    </rules></security>
    <nat><rules><entry name="nat-local"><source><member>any</member></source></entry></rules></nat>
  </rulebase></entry></vsys></entry></devices>
</config>"""


def test_panos_xml_security_only_and_ordering():
    st = _stats()
    rules = parse_paloalto_xml(_PAN_PANORAMA, st)
    names = [r["device_name"] for r in rules]
    assert "nat-1" not in names and "decrypt-1" not in names and "nat-local" not in names
    order = {}
    for r in rules:
        order.setdefault(r["device_name"], r["rule_order"])
    assert order["pre-1"] < order["local-1"] < order["local-neg"] < order["post-1"]
    assert st["rules_skipped_no_action"] == 1
    assert st["rules_disabled"] == 1
    assert st["rules_skipped_negated_deny"] == 1
    assert "local-noaction" not in names
    assert "local-disabled" in names
    assert all(r["enabled"] is (r["device_name"] != "local-disabled") for r in rules)


def test_panos_xml_service_resolution():
    rules = parse_paloalto_xml(_PAN_PANORAMA)
    pre = [r for r in rules if r["device_name"] == "pre-1"]
    assert {(r["protocol"], r["dst_port"]) for r in pre} == {("tcp", "502"), ("tcp", "80,443,1000-2000")}
    app = [r for r in rules if r["device_name"] == "local-1"][0]
    assert app["dst_port"] == "any" and "application-default" in app["raw_line"]
    neg = [r for r in rules if r["device_name"] == "local-neg"][0]
    assert neg["src"] == "any"
    assert "[negated src: 10.5.0.0/16]" in neg["raw_line"]
    assert neg["dst_port"] == "80,8080"


def test_panos_xml_unknown_service_counted():
    xml = """<config><rulebase><security><rules>
      <entry name="r"><service><member>svc-missing</member></service><action>allow</action></entry>
    </rules></security></rulebase></config>"""
    st = _stats()
    rules = parse_paloalto_xml(xml, st)
    assert rules[0]["dst_port"] == "unknown:svc-missing"
    assert st["unknown_port_names"] == 1


# ─────────────────────────────────────────────────────── PAN-OS set ──

def test_panos_set_disabled_negate_services():
    text = textwrap.dedent("""\
        set service svc-ot protocol tcp port 502,102
        set rulebase security rules A source 10.0.0.0/8
        set rulebase security rules A service svc-ot
        set rulebase security rules A action allow
        set rulebase security rules B source any
        set rulebase security rules B action allow
        set rulebase security rules B disabled yes
        set rulebase security rules C destination 10.0.0.0/8
        set rulebase security rules C negate-destination yes
        set rulebase security rules C action allow
        set rulebase security rules D source any
        set rulebase security rules "E F" negate-source yes
        set rulebase security rules "E F" action deny
        """)
    st = _stats()
    rules = parse_paloalto_set(text, st)
    by = {r["device_name"]: r for r in rules}
    assert set(by) == {"A", "B", "C"}
    assert by["B"]["enabled"] is False and by["A"]["enabled"] is True
    assert by["A"]["dst_port"] == "102,502"
    assert by["C"]["dst"] == "any" and "[negated dst: 10.0.0.0/8]" in by["C"]["raw_line"]
    assert st["rules_disabled"] == 1
    assert st["rules_skipped_no_action"] == 1
    assert st["rules_skipped_negated_deny"] == 1
    assert by["A"]["rule_order"] < by["C"]["rule_order"]


# ────────────────────────────────────────────────────────── ingest ──

def test_ingest_stats_and_rule_order(db):
    text = textwrap.dedent("""\
        object-group network ENG
         host 10.0.1.5
         host 10.0.1.6
        ip access-list extended OT
         10 permit tcp object-group ENG host 10.0.1.10 eq 502
         20 permit tcp any any eq www inactive
         30 deny ip any any
        ipv6 access-list V6
         permit ipv6 any any
        """)
    stats = ingest_firewall_config(text, db, vendor_hint="cisco")
    for k in SKIP_STAT_KEYS:
        assert k in stats
    assert stats["rules_created"] == 5          # F-07: the v6 ACE is stored
    assert stats["rules_ipv6"] == 1
    assert stats["rules_skipped_ipv6"] == 0
    assert stats["rules_disabled"] == 1
    rows = db.query(FirewallRule).order_by(FirewallRule.id).all()
    assert [r.rule_order for r in rows] == [1, 1, 2, 3, 4]
    assert [r.enabled for r in rows] == [True, True, False, True, True]
    assert (rows[4].src, rows[4].dst) == ("::/0", "::/0")
    assert rows[0].dst_port == "502"
    assert rows[2].dst_port == "80"
    assert rows[3].dst_port == "any"
