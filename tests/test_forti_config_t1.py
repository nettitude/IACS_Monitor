"""
Tier-1 remediation tests for app/parsers/forti_config_parser.py
(T1-20 disabled, T1-21 negation, T1-23 rule_order, T1-24 service ports).
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import FirewallRule
from app.parsers.forti_config_parser import (
    _build_addr_registry,
    _build_svc_registry,
    _extract_policies,
    _extract_zones,
    _resolve_service,
    flatten_global_vdom,
    ingest_fortigate_config,
    parse_forti_block,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


_OBJECTS = """\
config firewall address
    edit "PLC-1"
        set subnet 10.0.1.10 255.255.255.255
    next
    edit "ENG-NET"
        set subnet 10.0.2.0 255.255.255.0
    next
end
config firewall service custom
    edit "OT-MULTI"
        set tcp-portrange 502 102 20000
    next
    edit "DSTSRC"
        set tcp-portrange 502:1024-65535
    next
    edit "BOTH"
        set tcp-portrange 8000-8010 80
        set udp-portrange 161 162
    next
    edit "SCTP-SVC"
        set sctp-portrange 2905
    next
    edit "ICMP-SVC"
        set protocol ICMP
    next
    edit "GRE-SVC"
        set protocol IP
        set protocol-number 47
    next
end
config firewall service group
    edit "OT-GROUP"
        set member "OT-MULTI" "HTTPS" "PING"
    next
end
"""


def _policies(policy_block: str, stats=None):
    parsed = flatten_global_vdom(parse_forti_block(_OBJECTS + policy_block))
    zones = _extract_zones(parsed)
    ao, ag = _build_addr_registry(parsed)
    so, sg = _build_svc_registry(parsed)
    rules, _ = _extract_policies(parsed, zones, ao, ag, so, sg, stats=stats)
    return rules


def _svc(name):
    parsed = parse_forti_block(_OBJECTS)
    so, sg = _build_svc_registry(parsed)
    return _resolve_service(name, so, sg)


# ────────────────────────────────────────────── T1-24 service ports ──

@pytest.mark.parametrize("name,expected", [
    ("OT-MULTI", [("tcp", "102,502,20000")]),
    ("DSTSRC", [("tcp", "502")]),
    ("BOTH", [("tcp", "80,8000-8010"), ("udp", "161-162")]),
    ("SCTP-SVC", [("sctp", "2905")]),
    ("ICMP-SVC", [("icmp", "any")]),
    ("GRE-SVC", [("gre", "any")]),
    ("OT-GROUP", [("tcp", "102,502,20000"), ("tcp", "443"), ("icmp", "any")]),
    ("ALL", [("any", "any")]),
    ("ALL_TCP", [("tcp", "any")]),
    ("ALL_UDP", [("udp", "any")]),
    ("ALL_ICMP", [("icmp", "any")]),
    ("PING", [("icmp", "any")]),
    ("HTTP", [("tcp", "80")]),
    ("HTTPS", [("tcp", "443")]),
    ("SSH", [("tcp", "22")]),
    ("TELNET", [("tcp", "23")]),
    ("RDP", [("tcp", "3389")]),
    ("SMB", [("tcp", "445")]),
    ("DNS", [("tcp", "53"), ("udp", "53")]),
    ("NTP", [("tcp", "123"), ("udp", "123")]),
    ("SNMP", [("tcp", "161-162"), ("udp", "161-162")]),
])
def test_service_resolution_canonical(name, expected):
    assert _svc(name) == expected


def test_no_python_list_repr_in_ports():
    rules = _policies(textwrap.dedent("""\
        config firewall policy
            edit 1
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "ENG-NET"
                set dstaddr "PLC-1"
                set action accept
                set service "OT-MULTI" "BOTH"
            next
        end
        """))
    for r in rules:
        assert "[" not in r["dst_port"] and "'" not in r["dst_port"] and ":" not in r["dst_port"]
    assert {(r["protocol"], r["dst_port"]) for r in rules} == {
        ("tcp", "102,502,20000"), ("tcp", "80,8000-8010"), ("udp", "161-162")}


# ────────────────────────────────── T1-20 disabled / T1-21 negation ──

_POLICIES = textwrap.dedent("""\
    config firewall policy
        edit 1
            set name "disabled-permit"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "PLC-1"
            set action accept
            set service "ALL"
            set status disable
        next
        edit 2
            set name "neg-src-permit"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "ENG-NET"
            set srcaddr-negate enable
            set dstaddr "PLC-1"
            set action accept
            set service "OT-MULTI"
        next
        edit 3
            set name "neg-dst-deny"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "ENG-NET"
            set dstaddr-negate enable
            set action deny
            set service "ALL"
        next
        edit 4
            set name "neg-svc-permit"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "ENG-NET"
            set dstaddr "PLC-1"
            set service "HTTPS"
            set service-negate enable
            set action accept
        next
        edit 5
            set name "neg-svc-deny"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "ENG-NET"
            set dstaddr "PLC-1"
            set service "HTTPS"
            set service-negate enable
            set action deny
        next
    end
    """)


def test_disabled_and_negated_policies():
    stats = {}
    rules = _policies(_POLICIES, stats)
    names = {r["policy_name"] for r in rules}
    # The disabled policy is kept, flagged enabled=False (reported by
    # review_disabled_rules and excluded from every analysis).
    assert names == {"disabled-permit", "neg-src-permit", "neg-svc-permit"}
    assert all(r["enabled"] is (r["policy_name"] != "disabled-permit") for r in rules)
    assert stats["rules_disabled"] == 1
    assert stats["rules_skipped_negated_deny"] == 2

    neg_src = [r for r in rules if r["policy_name"] == "neg-src-permit"]
    assert all(r["src"] == "any" for r in neg_src)
    assert all(r["dst"] == "10.0.1.10/32" for r in neg_src)
    assert any("negated src: ENG-NET" in n for n in neg_src[0]["notes"])

    neg_svc = [r for r in rules if r["policy_name"] == "neg-svc-permit"]
    assert [(r["protocol"], r["dst_port"]) for r in neg_svc] == [("any", "any")]
    assert any("negated service: HTTPS" in n for n in neg_svc[0]["notes"])


def test_ingest_negation_note_in_raw_line_and_stats(db):
    stats = ingest_fortigate_config(_OBJECTS + _POLICIES, db, firewall_name="FW-T1")
    assert stats["rules_disabled"] == 1
    dis = db.query(FirewallRule).filter(FirewallRule.policy_name == "disabled-permit").all()
    assert dis and all(r.enabled is False for r in dis)
    assert stats["rules_skipped_negated_deny"] == 2
    rows = db.query(FirewallRule).filter(FirewallRule.policy_name == "neg-src-permit").all()
    assert rows and all("[negated src: ENG-NET]" in r.raw_line for r in rows)
    assert all(r.src == "any" for r in rows)


# ──────────────────────────────────────────────────── T1-23 ordering ──

def test_rule_order_is_config_position_not_policy_id(db):
    # Policy 9 was `move`d above policy 2: config order is 9, 2, 5.
    cfg = _OBJECTS + textwrap.dedent("""\
        config firewall policy
            edit 9
                set name "moved-up"
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "all"
                set dstaddr "PLC-1"
                set action deny
                set service "OT-GROUP"
            next
            edit 2
                set name "second"
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "HTTPS"
            next
            edit 5
                set name "third"
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "all"
                set dstaddr "all"
                set action deny
                set service "ALL"
            next
        end
        """)
    ingest_fortigate_config(cfg, db, firewall_name="FW-ORDER")
    rows = db.query(FirewallRule).filter(FirewallRule.firewall_id.isnot(None)).all()
    by_pid = {}
    for r in rows:
        by_pid.setdefault(r.policy_id, set()).add(r.rule_order)
    assert by_pid == {"9": {1}, "2": {2}, "5": {3}}
    # expanded rows of policy 9 (3 services) share one rule_order
    assert len([r for r in rows if r.policy_id == "9"]) == 3


def test_long_service_port_list_split_rows():
    ports = " ".join(str(p) for p in range(10000, 10400, 2))
    cfg = textwrap.dedent(f"""\
        config firewall service custom
            edit "HUGE"
                set tcp-portrange {ports}
            next
        end
        config firewall policy
            edit 1
                set srcintf "a"
                set dstintf "b"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "HUGE"
            next
        end
        """)
    parsed = parse_forti_block(cfg)
    so, sg = _build_svc_registry(parsed)
    rules, _ = _extract_policies(parsed, {}, {}, {}, so, sg)
    assert len(rules) > 1
    assert all(len(r["dst_port"]) <= 255 for r in rules)
    assert {r["rule_order"] for r in rules} == {1}
