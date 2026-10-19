"""Audit findings A-02 (group expansion blow-up), A-07 (FortiOS `action
ipsec`), A-08 (pfSense `match` rules) - firewall config parsers."""
import time

import pytest

from app.parsers import firewall_parser as fp
from app.parsers.firewall_parser import (
    parse_cisco_acl, parse_paloalto_set, parse_paloalto_xml, parse_pfsense_xml,
)
from app.parsers.forti_config_parser import (
    _build_addr_registry, _build_svc_registry, _extract_policies, _extract_zones,
    flatten_global_vdom, parse_forti_block,
)
from app.parsers.rule_match import Unresolved, parse_address, parse_ports

LEVELS = 30
LEAVES = {"10.0.0.1", "10.0.0.2"}


def _timed(fn):
    t0 = time.perf_counter()
    out = fn()
    dt = time.perf_counter() - t0
    assert dt < 1.0, f"took {dt:.2f}s"
    return out


# ------------------------------------------------------------- configs --

def _cisco_diamond(levels=LEVELS):
    lines = ["object-group network L0a", " host 10.0.0.1",
             "object-group network L0b", " host 10.0.0.2",
             "object-group service S0a tcp", " port-object eq 502",
             "object-group service S0b tcp", " port-object eq 102"]
    for k in range(1, levels + 1):
        for x in "ab":
            lines += [f"object-group network L{k}{x}",
                      f" group-object L{k-1}a", f" group-object L{k-1}b",
                      f"object-group service S{k}{x} tcp",
                      f" group-object S{k-1}a", f" group-object S{k-1}b"]
    lines += ["ip access-list extended OT",
              f" 10 permit tcp object-group L{levels}a object-group L{levels}b "
              f"object-group S{levels}a"]
    return "\n".join(lines) + "\n"


def _pf_diamond(levels=LEVELS, rule_type="pass", extra=""):
    al = ["<alias><name>L0a</name><type>host</type><address>10.0.0.1</address></alias>",
          "<alias><name>L0b</name><type>host</type><address>10.0.0.2</address></alias>",
          "<alias><name>P0a</name><type>port</type><address>502</address></alias>",
          "<alias><name>P0b</name><type>port</type><address>102</address></alias>"]
    for k in range(1, levels + 1):
        for x in "ab":
            al.append(f"<alias><name>L{k}{x}</name><type>host</type>"
                      f"<address>L{k-1}a L{k-1}b</address></alias>")
            al.append(f"<alias><name>P{k}{x}</name><type>port</type>"
                      f"<address>P{k-1}a P{k-1}b</address></alias>")
    return (f"<pfsense><aliases>{''.join(al)}</aliases><filter>"
            f"<rule><type>{rule_type}</type><interface>lan</interface>{extra}"
            f"<protocol>tcp</protocol><source><address>L{levels}a</address></source>"
            f"<destination><address>L{levels}b</address><port>P{levels}a</port>"
            f"</destination><descr>r</descr></rule></filter></pfsense>")


def _pan_diamond_xml(levels=LEVELS):
    addrs = ('<entry name="L0a"><ip-netmask>10.0.0.1</ip-netmask></entry>'
             '<entry name="L0b"><ip-netmask>10.0.0.2</ip-netmask></entry>')
    svcs = ('<entry name="S0a"><protocol><tcp><port>502</port></tcp></protocol></entry>'
            '<entry name="S0b"><protocol><tcp><port>102</port></tcp></protocol></entry>')
    groups, sgroups = [], []
    for k in range(1, levels + 1):
        for x in "ab":
            groups.append(f'<entry name="L{k}{x}"><static><member>L{k-1}a</member>'
                          f'<member>L{k-1}b</member></static></entry>')
            sgroups.append(f'<entry name="S{k}{x}"><members><member>S{k-1}a</member>'
                           f'<member>S{k-1}b</member></members></entry>')
    return ("<config><devices><entry name='localhost.localdomain'><vsys>"
            "<entry name='vsys1'>"
            f"<address>{addrs}</address><address-group>{''.join(groups)}</address-group>"
            f"<service>{svcs}</service><service-group>{''.join(sgroups)}</service-group>"
            "<rulebase><security><rules><entry name='r1'>"
            f"<from><member>a</member></from><to><member>b</member></to>"
            f"<source><member>L{levels}a</member></source>"
            f"<destination><member>L{levels}b</member></destination>"
            f"<service><member>S{levels}a</member></service>"
            "<action>allow</action></entry></rules></security></rulebase>"
            "</entry></vsys></entry></devices></config>")


def _pan_diamond_set(levels=LEVELS):
    lines = ["set address L0a ip-netmask 10.0.0.1",
             "set address L0b ip-netmask 10.0.0.2"]
    for k in range(1, levels + 1):
        for x in "ab":
            lines.append(f"set address-group L{k}{x} static [ L{k-1}a L{k-1}b ]")
    lines += [f'set rulebase security rules r1 source L{levels}a',
              f'set rulebase security rules r1 destination L{levels}b',
              'set rulebase security rules r1 service any',
              'set rulebase security rules r1 action allow']
    return "\n".join(lines) + "\n"


def _forti(policy: str, levels=LEVELS, extra_objs=""):
    o = ['config firewall address',
         '    edit "L0a"', '        set subnet 10.0.0.1 255.255.255.255', '    next',
         '    edit "L0b"', '        set subnet 10.0.0.2 255.255.255.255', '    next',
         'end',
         'config firewall service custom',
         '    edit "S0a"', '        set tcp-portrange 502', '    next',
         '    edit "S0b"', '        set tcp-portrange 102', '    next',
         'end', 'config firewall addrgrp']
    for k in range(1, levels + 1):
        for x in "ab":
            o += [f'    edit "L{k}{x}"', f'        set member "L{k-1}a" "L{k-1}b"', '    next']
    o += ['end', 'config firewall service group']
    for k in range(1, levels + 1):
        for x in "ab":
            o += [f'    edit "S{k}{x}"', f'        set member "S{k-1}a" "S{k-1}b"', '    next']
    o += ['end']
    text = "\n".join(o) + "\n" + extra_objs + policy
    stats = {}
    parsed = flatten_global_vdom(parse_forti_block(text))
    zones = _extract_zones(parsed)
    ao, ag = _build_addr_registry(parsed)
    so, sg = _build_svc_registry(parsed)
    rules, _ = _extract_policies(parsed, zones, ao, ag, so, sg, stats=stats)
    return rules, stats


def _forti_policy(action="accept", src=f"L{LEVELS}a", dst=f"L{LEVELS}b",
                  svc=f"S{LEVELS}a"):
    return f"""config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "{src}"
        set dstaddr "{dst}"
        set action {action}
        set service "{svc}"
    next
end
"""


# ---------------------------------------------------------------- A-02 --

def test_cisco_diamond_30_levels_fast_and_correct():
    stats = fp._new_stats()
    rules = _timed(lambda: parse_cisco_acl(_cisco_diamond(), stats))
    assert {r["src"] for r in rules} == LEAVES
    assert {r["dst"] for r in rules} == LEAVES
    assert {r["dst_port"] for r in rules} == {"102,502"}
    assert len(rules) == 4
    assert stats["groups_over_limit"] == 0 and stats["rules_over_limit"] == 0


def test_pfsense_diamond_30_levels_fast_and_correct():
    stats = fp._new_stats()
    rules = _timed(lambda: parse_pfsense_xml(_pf_diamond(), stats))
    assert {r["src"] for r in rules} == LEAVES
    assert {r["dst"] for r in rules} == LEAVES
    assert {r["dst_port"] for r in rules} == {"102,502"}
    assert len(rules) == 4


def test_panos_xml_diamond_30_levels_fast_and_correct():
    stats = fp._new_stats()
    rules = _timed(lambda: parse_paloalto_xml(_pan_diamond_xml(), stats))
    assert {r["src"] for r in rules} == LEAVES
    assert {r["dst"] for r in rules} == LEAVES
    assert {r["dst_port"] for r in rules} == {"502", "102"}
    assert len(rules) == 8


def test_panos_set_diamond_30_levels_fast_and_correct():
    stats = fp._new_stats()
    rules = _timed(lambda: parse_paloalto_set(_pan_diamond_set(), stats))
    assert {r["src"] for r in rules} == LEAVES
    assert {r["dst"] for r in rules} == LEAVES
    assert len(rules) == 4


def test_forti_diamond_30_levels_fast_and_correct():
    rules, stats = _timed(lambda: _forti(_forti_policy()))
    assert {r["src"] for r in rules} == {"10.0.0.1/32", "10.0.0.2/32"}
    assert {r["dst"] for r in rules} == {"10.0.0.1/32", "10.0.0.2/32"}
    assert {r["dst_port"] for r in rules} == {"502", "102"}
    assert len(rules) == 8
    assert stats["groups_over_limit"] == 0 and stats["rules_over_limit"] == 0


def test_cisco_deep_chain_no_recursion_error():
    n = 3000
    lines = ["object-group network G0", " host 10.0.0.1"]
    for k in range(1, n + 1):
        lines += [f"object-group network G{k}", f" group-object G{k-1}"]
    lines += ["ip access-list extended OT", f" 10 permit ip object-group G{n} any"]
    stats = fp._new_stats()
    rules = _timed(lambda: parse_cisco_acl("\n".join(lines) + "\n", stats))
    assert [r["src"] for r in rules] == [f"too-large:G{n - fp.MAX_GROUP_DEPTH}"]
    assert stats["groups_over_limit"] >= 1


def test_cycle_does_not_poison_memo():
    """A group resolved inside a cycle must not cache a partial result."""
    text = "\n".join([
        "object-group network A", " host 10.0.0.1", " group-object B",
        "object-group network B", " host 10.0.0.2", " group-object A",
        "ip access-list extended OT",
        " 10 permit ip object-group A any",
        " 20 permit ip object-group B any", ""])
    rules = parse_cisco_acl(text)
    for order in (1, 2):
        assert {r["src"] for r in rules if r["rule_order"] == order} == LEAVES


def _hosts(n, base="10.1"):
    return [f"{base}.{i // 250}.{i % 250 + 1}" for i in range(n)]


def test_cisco_oversized_cartesian_rule_capped_and_counted():
    src, dst = _hosts(300, "10.1"), _hosts(300, "10.2")
    lines = (["object-group network SRC"] + [f" host {h}" for h in src]
             + ["object-group network DST"] + [f" host {h}" for h in dst]
             + ["ip access-list extended OT",
                " 10 deny tcp object-group SRC object-group DST eq 502"])
    stats = fp._new_stats()
    rules = _timed(lambda: parse_cisco_acl("\n".join(lines) + "\n", stats))
    assert stats["rules_over_limit"] == 1
    assert len(rules) == 300
    assert {r["src"] for r in rules} == {"too-large:SRC"}
    assert all(r["action"] == "deny" for r in rules)       # never widened
    assert isinstance(parse_address("too-large:SRC"), Unresolved)


def test_forti_oversized_cartesian_rule_capped_and_counted():
    src, dst = _hosts(300, "10.1"), _hosts(300, "10.2")
    objs = ["config firewall address"]
    for h in src + dst:
        objs += [f'    edit "h{h}"', f'        set subnet {h} 255.255.255.255', '    next']
    objs += ["end", "config firewall addrgrp",
             '    edit "BIGSRC"', '        set member ' + " ".join(f'"h{h}"' for h in src), '    next',
             '    edit "BIGDST"', '        set member ' + " ".join(f'"h{h}"' for h in dst), '    next',
             "end", ""]
    rules, stats = _forti(_forti_policy(src="BIGSRC", dst="BIGDST", svc="S0a"),
                          levels=1, extra_objs="\n".join(objs))
    assert stats["rules_over_limit"] == 1
    assert len(rules) == 300
    assert {r["src"] for r in rules} == {"too-large:BIGSRC"}


def test_group_member_cap_yields_unresolved_token(monkeypatch):
    monkeypatch.setattr(fp, "MAX_GROUP_MEMBERS", 5)
    lines = (["object-group network BIG"] + [f" host {h}" for h in _hosts(6)]
             + ["object-group service PORTS tcp"]
             + ["ip access-list extended OT", " 10 permit ip object-group BIG any"])
    stats = fp._new_stats()
    rules = parse_cisco_acl("\n".join(lines) + "\n", stats)
    assert [r["src"] for r in rules] == ["too-large:BIG"]
    assert stats["groups_over_limit"] == 1
    # downstream: never "any"
    assert isinstance(parse_ports("too-large:BIG"), Unresolved)


def test_panos_service_cap_token_is_unresolved_port(monkeypatch):
    monkeypatch.setattr(fp, "MAX_GROUP_MEMBERS", 1)
    stats = fp._new_stats()
    rules = parse_paloalto_xml(_pan_diamond_xml(3), stats)
    assert {r["dst_port"] for r in rules} == {"too-large:S3a"}
    assert isinstance(parse_ports("too-large:S3a"), Unresolved)


# ---------------------------------------------------------------- A-07 --

def test_forti_action_ipsec_is_permit_with_note():
    rules, stats = _forti(_forti_policy(action="ipsec", src="L0a", dst="L0b", svc="S0a"),
                          levels=1)
    assert rules and all(r["action"] == "permit" for r in rules)
    assert any("ipsec" in n for n in rules[0]["notes"])


def test_forti_accept_and_deny_unchanged():
    rules, _ = _forti(_forti_policy(action="accept", src="L0a", dst="L0b", svc="S0a"), 1)
    assert {r["action"] for r in rules} == {"permit"}
    rules, _ = _forti(_forti_policy(action="deny", src="L0a", dst="L0b", svc="S0a"), 1)
    assert {r["action"] for r in rules} == {"deny"}


def test_forti_unknown_action_skipped_and_counted():
    rules, stats = _forti(_forti_policy(action="learn", src="L0a", dst="L0b", svc="S0a"), 1)
    assert rules == []
    assert stats["rules_skipped_unknown_action"] == 1


# ---------------------------------------------------------------- A-08 --

def test_pfsense_match_rule_skipped():
    stats = fp._new_stats()
    rules = parse_pfsense_xml(_pf_diamond(1, rule_type="match"), stats)
    assert rules == []
    assert stats["rules_skipped_match"] == 1


def test_pfsense_unknown_type_skipped():
    stats = fp._new_stats()
    assert parse_pfsense_xml(_pf_diamond(1, rule_type="weird"), stats) == []
    assert stats["rules_skipped_unknown_action"] == 1


@pytest.mark.parametrize("t,action", [("pass", "permit"), ("block", "deny"),
                                      ("reject", "deny")])
def test_pfsense_type_mapping(t, action):
    rules = parse_pfsense_xml(_pf_diamond(1, rule_type=t))
    assert rules and {r["action"] for r in rules} == {action}
    if t == "reject":
        assert "reject" in rules[0]["raw_line"]


def test_pfsense_floating_quick_noted():
    rules = parse_pfsense_xml(_pf_diamond(
        1, extra="<floating>yes</floating><direction>in</direction>"))
    assert "floating non-quick" in rules[0]["raw_line"]
    rules = parse_pfsense_xml(_pf_diamond(
        1, extra="<floating>yes</floating><quick>yes</quick>"))
    assert "floating quick" in rules[0]["raw_line"]
