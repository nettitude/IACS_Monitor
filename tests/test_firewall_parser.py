"""
Tests for app/parsers/firewall_parser.py.

Covers:
  parse_cisco_acl()     — basic permit/deny, with/without port, any/any rule
  parse_pfsense_xml()   — basic permit rule
  parse_paloalto_xml()  — basic PAN-OS XML rule
  parse_paloalto_set()  — basic PAN-OS set-command rule
  edge cases            — empty input, malformed input (no crash)
"""
import pytest

from app.parsers.firewall_parser import (
    parse_cisco_acl,
    parse_paloalto_set,
    parse_paloalto_xml,
    parse_pfsense_xml,
)


# ─────────────────────────────────────────── Cisco ACL ───────────────────────


def test_cisco_basic_permit():
    text = "permit tcp 10.0.1.0 0.0.0.255 host 10.0.1.10 eq 502"
    rules = parse_cisco_acl(text)
    assert len(rules) == 1
    r = rules[0]
    assert r["action"] == "permit"
    assert r["protocol"] == "tcp"
    assert r["dst"] == "10.0.1.10"
    assert r["dst_port"] == "502"  # canonical (was "eq 502")


def test_cisco_basic_deny():
    text = "deny tcp any host 10.0.0.1 eq 23"
    rules = parse_cisco_acl(text)
    assert len(rules) == 1
    assert rules[0]["action"] == "deny"
    assert rules[0]["dst_port"] == "23"  # canonical (was "eq 23")


def test_cisco_with_port():
    text = "permit tcp any any eq 443"
    rules = parse_cisco_acl(text)
    assert len(rules) == 1
    assert rules[0]["dst_port"] == "443"  # canonical (was "eq 443")
    assert rules[0]["src"] == "any"
    assert rules[0]["dst"] == "any"


def test_cisco_without_port():
    text = "permit ip any any"
    rules = parse_cisco_acl(text)
    assert len(rules) == 1
    r = rules[0]
    assert r["dst_port"] == "any"  # canonical all-ports (was None)
    assert r["protocol"] == "any"  # "ip" normalizes to "any"


def test_cisco_any_any_rule():
    text = "deny ip any any"
    rules = parse_cisco_acl(text)
    assert len(rules) == 1
    r = rules[0]
    assert r["action"] == "deny"
    assert r["src"] == "any"
    assert r["dst"] == "any"


def test_cisco_named_acl():
    text = (
        "ip access-list extended MODBUS-PERMIT\n"
        " permit tcp 10.0.1.0 0.0.0.255 host 10.0.1.10 eq 502\n"
        " deny ip any any\n"
    )
    rules = parse_cisco_acl(text)
    assert len(rules) == 2
    assert rules[0]["device_name"] == "MODBUS-PERMIT"
    assert rules[0]["action"] == "permit"
    assert rules[1]["action"] == "deny"


def test_cisco_empty_input():
    assert parse_cisco_acl("") == []


def test_cisco_malformed_no_crash():
    text = "this is not a valid acl line at all !!!"
    result = parse_cisco_acl(text)
    # Should not raise — may return [] or ignore the line
    assert isinstance(result, list)


# ─────────────────────────────────────────── pfSense XML ─────────────────────


_PFSENSE_BASIC = """<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source><address>10.0.1.0/24</address></source>
      <destination><address>10.0.1.10</address><port>502</port></destination>
      <descr>Allow Modbus</descr>
    </rule>
  </filter>
</pfsense>"""


def test_pfsense_basic_permit():
    rules = parse_pfsense_xml(_PFSENSE_BASIC)
    assert len(rules) == 1
    r = rules[0]
    assert r["action"] == "permit"
    assert r["protocol"] == "tcp"
    assert r["src"] == "10.0.1.0/24"
    assert r["dst"] == "10.0.1.10"
    assert r["dst_port"] == "502"


_PFSENSE_DENY = """<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><any/></destination>
    </rule>
  </filter>
</pfsense>"""


def test_pfsense_deny_rule():
    rules = parse_pfsense_xml(_PFSENSE_DENY)
    assert len(rules) == 1
    assert rules[0]["action"] == "deny"
    assert rules[0]["src"] == "any"
    assert rules[0]["dst"] == "any"


def test_pfsense_empty_filter():
    xml = """<?xml version="1.0"?><pfsense><filter></filter></pfsense>"""
    assert parse_pfsense_xml(xml) == []


# ─────────────────────────────────────────── PAN-OS XML ──────────────────────


_PANOS_XML = """<?xml version="1.0"?>
<config>
  <devices>
    <entry>
      <vsys>
        <entry>
          <rulebase>
            <security>
              <rules>
                <entry name="Allow-Modbus">
                  <source><member>10.0.1.0/24</member></source>
                  <destination><member>10.0.1.10</member></destination>
                  <service><member>tcp-502</member></service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""


def test_paloalto_xml_basic_rule():
    rules = parse_paloalto_xml(_PANOS_XML)
    assert len(rules) >= 1
    r = rules[0]
    assert r["action"] == "permit"
    assert r["src"] == "10.0.1.0/24"
    assert r["dst"] == "10.0.1.10"
    assert r["protocol"] == "tcp"
    assert r["dst_port"] == "502"


def test_paloalto_xml_empty():
    xml = """<?xml version="1.0"?><config></config>"""
    assert parse_paloalto_xml(xml) == []


def test_paloalto_xml_deny_rule():
    xml = """<?xml version="1.0"?>
<config>
  <rulebase>
    <security>
      <rules>
        <entry name="Block-All">
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <service><member>any</member></service>
          <action>deny</action>
        </entry>
      </rules>
    </security>
  </rulebase>
</config>"""
    rules = parse_paloalto_xml(xml)
    assert len(rules) == 1
    assert rules[0]["action"] == "deny"


# ─────────────────────────────────────────── PAN-OS set format ───────────────


_PANOS_SET = """\
set rulebase security rules Allow-Modbus source 10.0.1.0/24
set rulebase security rules Allow-Modbus destination 10.0.1.10
set rulebase security rules Allow-Modbus service tcp-502
set rulebase security rules Allow-Modbus action allow
"""


def test_paloalto_set_basic_rule():
    rules = parse_paloalto_set(_PANOS_SET)
    assert len(rules) >= 1
    r = rules[0]
    assert r["device_name"] == "Allow-Modbus"
    assert r["action"] == "permit"
    assert r["src"] == "10.0.1.0/24"
    assert r["dst"] == "10.0.1.10"
    assert r["protocol"] == "tcp"
    assert r["dst_port"] == "502"


def test_paloalto_set_empty():
    assert parse_paloalto_set("") == []


def test_paloalto_set_malformed_no_crash():
    text = "not a valid set command line\nalso garbage\n"
    result = parse_paloalto_set(text)
    assert isinstance(result, list)
