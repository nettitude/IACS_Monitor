"""N-24 (VDOM part): the same policy id in two VDOMs keeps BOTH.

Policy identity is (firewall, vdom, policy_id) in storage, re-ingest, shadow
analysis, topology diff, reachability, findings dedup keys and rule-hit
attribution.  A config without a `config vdom` wrapper stores vdom NULL.
"""
import textwrap
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (Base, FirewallRule, Finding, Host, NatRule, NetworkSession)
from app.parsers.alert_engine import _group_rule_key, _rule_group_key, review_shadow_rules
from app.parsers.forti_config_parser import (flatten_global_vdom, ingest_fortigate_config,
                                             parse_forti_block, split_vdoms)
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_hits import record_rule_hits
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.topology_diff import _device_key, compute_diff


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


def ingest(db, cfg, name="FGT-MV", lo=3, hi=4, **kw):
    return ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name,
                                   purdue_zone_from=lo, purdue_zone_to=hi, **kw)


GLOBAL = """
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
        edit "port1"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "port2"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
        edit "port3"
            set vdom "ot"
            set ip 10.13.0.1 255.255.255.0
        next
        edit "port4"
            set vdom "ot"
            set ip 10.14.0.1 255.255.255.0
        next
    end
    end
"""

ROOT = """
    config vdom
    edit root
    config firewall address
        edit "same-name"
            set subnet 10.4.0.0 255.255.255.0
        next
    end
    config firewall policy
        edit 1
            set name "root-deny"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "same-name"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
            set logtraffic disable
        next
        edit 2
            set name "root-permit-ssh"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "SSH"
        next
    end
    next
"""

OT = """
    edit ot
    config firewall address
        edit "same-name"
            set subnet 10.14.0.0 255.255.255.0
        next
    end
    config firewall policy
        edit 1
            set name "ot-permit"
            set srcintf "port4"
            set dstintf "port3"
            set srcaddr "same-name"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
            set logtraffic disable
        next
    end
    next
    end
"""

MV = GLOBAL + ROOT + OT


def rules(db, **kw):
    q = db.query(FirewallRule)
    for k, v in kw.items():
        q = q.filter(getattr(FirewallRule, k) == v)
    return q.order_by(FirewallRule.id).all()


# --------------------------------------------------------------- parsing ---
def test_split_vdoms_views_and_flat_passthrough():
    raw = parse_forti_block(textwrap.dedent(MV))
    views = dict(split_vdoms(raw))
    assert set(views) == {"root", "ot"}                       # declaration-only blocks skipped
    assert set(views["root"]["firewall policy"]) == {"1", "2"}
    assert set(views["ot"]["firewall policy"]) == {"1"}
    assert "port3" in views["root"]["system interface"]      # global sections overlaid
    assert views["root"]["firewall address"]["same-name"]["subnet"] != \
        views["ot"]["firewall address"]["same-name"]["subnet"]
    flat = parse_forti_block("config firewall policy\nedit 1\nset action accept\nnext\nend\n")
    assert split_vdoms(flat) == [(None, flat)]
    # the legacy merged view still collapses (global settings only use it)
    assert set(flatten_global_vdom(raw)["firewall policy"]) == {"1", "2"}


# ------------------------------------------------------------- storage -----
def test_same_policy_id_in_two_vdoms_keeps_both(db):
    st = ingest(db, MV)
    assert st["vdoms"] == ["root", "ot"]
    ones = rules(db, policy_id="1")
    assert sorted((r.vdom, r.action, r.src) for r in ones) == [
        ("ot", "permit", "10.14.0.0/24"), ("root", "deny", "10.4.0.0/24")]
    assert st["rules_created"] == 3
    # rule_order is per VDOM (each VDOM is its own first-match list)
    assert {(r.vdom, r.policy_id): r.rule_order for r in rules(db)} == {
        ("root", "1"): 1, ("root", "2"): 2, ("ot", "1"): 1}
    assert all(f"[vdom {r.vdom}]" in r.raw_line for r in rules(db))


def test_nat_rows_carry_vdom(db):
    cfg = MV.replace("    edit ot\n    config firewall address", """    edit ot
    config firewall vip
        edit "web"
            set extip 10.13.0.50
            set mappedip "10.14.0.5"
            set extintf "port3"
        next
    end
    config firewall address""")
    ingest(db, cfg)
    assert [(n.vdom, n.name) for n in db.query(NatRule)] == [("ot", "web")]


def test_flat_config_stores_null_vdom(db):
    ingest(db, ROOT.replace("config vdom\n    edit root\n", "").rsplit("next", 1)[0])
    assert {r.vdom for r in rules(db)} == {None}


# --------------------------------------------------------------- re-ingest -
def test_reingest_replaces_per_vdom(db):
    ingest(db, MV)
    # per-VDOM export (no `config global`) holding only the `ot` VDOM, changed
    changed = textwrap.dedent("""
        config vdom
        edit ot
        config firewall policy
            edit 1
                set srcintf "port4"
                set dstintf "port3"
                set srcaddr "all"
                set dstaddr "all"
                set action deny
                set service "ALL"
            next
            edit 7
                set srcintf "port4"
                set dstintf "port3"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
            next
        end
        next
        end
    """)
    ingest(db, changed)
    got = sorted((r.vdom, r.policy_id, r.action) for r in rules(db))
    assert got == [("ot", "1", "deny"), ("ot", "7", "permit"),
                   ("root", "1", "deny"), ("root", "2", "permit")]   # root untouched


def test_full_backup_reingest_drops_removed_vdom(db):
    ingest(db, MV)
    ingest(db, GLOBAL + ROOT + "    end\n")          # `ot` VDOM gone from the full backup
    assert {r.vdom for r in rules(db)} == {"root"}
    assert len(rules(db)) == 2


def test_flat_reingest_replaces_vdom_rows(db):
    ingest(db, MV)
    flat = ROOT.replace("config vdom\n    edit root\n", "").rsplit("next", 1)[0]
    ingest(db, flat)
    assert {r.vdom for r in rules(db)} == {None} and len(rules(db)) == 2


# ----------------------------------------------------------- shadow --------
def test_shadow_analysis_is_per_vdom(db):
    ingest(db, MV)
    # root-deny (any service) would shadow a later permit in ITS vdom only
    shadows = find_shadowed_rules(db)["shadows"]
    pairs = {(s["shadowing_rule"].get("vdom"), s["shadowed_rule"].get("vdom")) for s in shadows}
    # no cross-VDOM shadow: root policy 1 (deny 10.4.0.0/24 any) vs ot policy 1
    assert ("root", "ot") not in pairs and ("ot", "root") not in pairs
    for s in shadows:
        assert s["shadowing_rule"].get("vdom") == s["shadowed_rule"].get("vdom")


def test_shadow_within_one_vdom_still_found(db):
    cfg = MV.replace('set service "SSH"', 'set service "SSH"\n set status enable').replace(
        'set srcaddr "same-name"\n            set dstaddr "all"\n            set action deny',
        'set srcaddr "all"\n            set dstaddr "all"\n            set action deny', 1)
    ingest(db, cfg)
    shadows = find_shadowed_rules(db)["shadows"]
    assert any(s["shadowing_rule"]["policy_id"] == "1" and s["shadowing_rule"].get("vdom") == "root"
               and s["shadowed_rule"]["policy_id"] == "2" for s in shadows)
    assert all(s["shadowing_rule"].get("vdom") == s["shadowed_rule"].get("vdom") for s in shadows)


# ---------------------------------------------------- findings dedup keys --
def test_config_findings_keyed_per_vdom(db):
    # policy 1 has logging disabled in BOTH VDOMs -> two findings, not one
    cfg = MV.replace('set action deny', 'set action accept', 1)
    ingest(db, cfg, generate_findings=True)
    refs = [f.source_ref for f in db.query(Finding).filter(
        Finding.check_name == "config_logging_disabled")]
    assert len(refs) == len(set(refs)) == 2
    assert any("root/1" in r for r in refs) and any("ot/1" in r for r in refs)
    n = db.query(Finding).count()
    ingest(db, cfg, generate_findings=True)                 # re-ingest: no duplicates
    assert db.query(Finding).count() == n


def test_logical_rule_key_includes_vdom(db):
    ingest(db, MV)
    a, b = rules(db, policy_id="1")
    ka, kb = _group_rule_key(_rule_group_key(a)), _group_rule_key(_rule_group_key(b))
    assert ka != kb and {"@vd:root", "@vd:ot"} <= {k[k.index("@vd"):].split("@fd")[0] for k in (ka, kb)}
    # a rule with no VDOM keeps the pre-N-24 key
    a.vdom = None
    assert "@vd" not in _group_rule_key(_rule_group_key(a))


def test_shadow_findings_distinct_per_vdom(db):
    ingest(db, MV)
    db.commit()
    review_shadow_rules(db)       # must not raise; identities are vdom-aware


# ------------------------------------------------------- topology diff -----
def test_topology_diff_groups_are_per_vdom(db):
    ingest(db, MV)
    a, b = rules(db, policy_id="1")
    assert _device_key(a) != _device_key(b)
    # a session only the `ot` VDOM's policy 1 explains
    for ip, lvl in (("10.14.0.9", 3), ("10.13.0.9", 4)):
        db.add(Host(ip=ip, purdue_level=lvl))
    db.flush()
    h = {x.ip: x for x in db.query(Host)}
    db.add(NetworkSession(src_host_id=h["10.14.0.9"].id, dst_host_id=h["10.13.0.9"].id,
                          dst_port=80, protocol="tcp", transport="tcp"))
    db.commit()
    diff = compute_diff(db)
    ot1 = next(r for r in rules(db, policy_id="1") if r.vdom == "ot")
    root1 = next(r for r in rules(db, policy_id="1") if r.vdom == "root")
    root2 = rules(db, policy_id="2", vdom="root")[0]
    assert diff["sessions_considered"] == 1 and not diff["unexpected_traffic"]
    db.refresh(ot1)
    db.refresh(root1)
    # credited to the ot VDOM's policy 1 only; root's rules stay unused
    assert ot1.last_matched is not None and root1.last_matched is None
    assert [u["rule_id"] for u in diff["unused_rules"]] == [root2.id]


# ------------------------------------------------------------ reachability -
def test_reachability_evaluates_each_vdom_separately(db):
    # root: 1 deny everything from 10.4.0.0/24 ; ot: 1 permit.  The ids and the
    # per-VDOM order used to interleave (both rule_order 1) so root's deny hid ot's permit.
    cfg = MV.replace('set srcaddr "same-name"\n            set dstaddr "all"\n            set action deny',
                     'set srcaddr "all"\n            set dstaddr "all"\n            set action deny', 1)
    ingest(db, cfg)
    db.add(Host(ip="10.4.0.5", purdue_level=4))
    db.add(Host(ip="10.3.0.5", purdue_level=3))
    db.commit()
    # the ot VDOM's policy permits any->any too (its srcaddr is a /24 though):
    ot = rules(db, vdom="ot")[0]
    ot.src = "any"
    db.commit()
    cell = compute_reachability(db, src_level=4, dst_level=3)["matrix"]["4→3"]
    ep = cell["paths"][0]["hops"][0]["enforcement_points"][0]
    assert {v["vdom"]: v["decision"] for v in ep["vdoms"]} == {"root": "deny", "ot": "permit"}
    assert cell["overall"] == "permitted"                    # most permissive VDOM
    assert compute_path(db, "10.4.0.5", "10.3.0.5")["overall"] == "permitted"


def test_reachability_single_vdom_denied_stays_denied(db):
    ingest(db, GLOBAL + ROOT.replace('"same-name"', '"all"') + "    end\n")
    db.add(Host(ip="10.4.0.5", purdue_level=4))
    db.add(Host(ip="10.3.0.5", purdue_level=3))
    db.commit()
    assert compute_path(db, "10.4.0.5", "10.3.0.5", dst_port=443, protocol="tcp")["overall"] == "denied"


# ---------------------------------------------------------- rule hits ------
def _ev(pid, vd=None, device="FGT-MV"):
    raw = {"vd": vd} if vd else {}
    return SimpleNamespace(log_type="traffic", action="accept", policy_id=pid, policy_name=None,
                           device_name=device, raw_fields=raw, vendor="fortinet",
                           src_ip="10.14.0.9", dst_ip="10.13.0.9", dst_port=80,
                           protocol="tcp", transport="tcp", event_time=None, received_at=None,
                           log_vendor="fortinet", subtype="forward")


def test_rule_hits_use_vd_field_or_report_ambiguous(db):
    ingest(db, MV)
    db.commit()
    from app.parsers import rule_hits as rh
    idx = rh._RuleIndex(db, {"fortinet"})
    stats = {"first_match_evaluations": 0}
    with_vd = rh._candidates(idx, _ev("1", vd="ot"), "fortinet", stats)
    assert {r.vdom for r in with_vd} == {"ot"}
    assert rh._candidates(idx, _ev("1"), "fortinet", stats) is None       # ambiguous: two VDOMs
    # an unambiguous id (only in root) needs no vd
    assert {r.vdom for r in rh._candidates(idx, _ev("2"), "fortinet", stats)} == {"root"}
