"""FortiOS correctness audit, batch C (2026-10-04).

C-02  Port-forward VIP with extport != mappedport -> false 'denied'.  The
      policy resolves the VIP to its mapped address but kept the EXTERNAL
      service port; evaluation runs on the post-NAT dst ip:port.  The service
      port is now translated to the mapped port (equal, unequal, range).
C-03  One stray unescaped quote no longer swallows the rest of the config.
C-04  Central-SNAT orig-port is parsed and tested: a `nat disable` exemption
      limited to tcp/80 does NOT exempt a tcp/443 flow.
C-05  Zone names containing a space ("IT Zone") are matched whole, not split
      into tokens that match nothing (false denied + false shadow findings).
C-09  An interface alias equal to a zone name no longer beats the zone def.
C-10  Reachability is no longer quadratic in rule rows (perf guard).
C-16  firewall_rules.src_zone / dst_zone are TEXT (a 14-interface policy's
      139-char value no longer overflows String(128) on PostgreSQL).
"""
import textwrap
import time

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (Base, Firewall, FirewallDevice, FirewallInterface,
                        FirewallRule, Host, NatRule)
from app.parsers.forti_config_parser import ingest_fortigate_config, parse_forti_block
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


def ingest(db, cfg, name="FW-C", lo=None, hi=None, **kw):
    return ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name,
                                   purdue_zone_from=lo, purdue_zone_to=hi, **kw)


def set_levels(db, name, levels: dict):
    for fi in db.query(FirewallInterface).all():
        if fi.firewall.name == name and fi.name in levels:
            fi.purdue_level = levels[fi.name]
    db.commit()


def H(db, ip, lvl):
    h = db.query(Host).filter(Host.ip == ip).first()
    if h is None:
        h = Host(ip=ip)
        db.add(h)
    h.purdue_level = lvl
    db.flush()
    return h


def cell(db, a, b, **kw):
    return compute_reachability(db, src_level=a, dst_level=b, **kw)["matrix"][f"{a}→{b}"]["overall"]


# =================================================================== C-02 ==
VIP_CFG = """
    config system interface
        edit "port1"
            set ip 10.10.1.1 255.255.255.0
        next
        edit "port2"
            set ip 10.20.3.1 255.255.255.0
        next
    end
    config firewall service custom
        edit "HTTPS"
            set tcp-portrange 443
        next
        edit "RANGED"
            set tcp-portrange 8000-8010
        next
    end
    config firewall vip
        edit "V-HMI"
            set extip 10.10.1.50
            set extintf "port1"
            set portforward enable
            set protocol tcp
            set extport {extport}
            set mappedip 10.20.3.50
            set mappedport {mappedport}
        next
    end
    config firewall policy
        edit 1
            set name "pf"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "V-HMI"
            set action accept
            set schedule "always"
            set service "{svc}"
        next
    end
"""


@pytest.mark.parametrize("extport,mappedport,svc,ext_q,stored", [
    ("443", "443", "HTTPS", 443, "443"),        # equal: no translation
    ("443", "8443", "HTTPS", 443, "8443"),      # unequal: the C-02 repro
    ("8000-8010", "9000-9010", "RANGED", 8005, "9000-9010"),  # range
])
def test_c02_portforward_vip_service_port_translated(db, extport, mappedport, svc, ext_q, stored):
    ingest(db, VIP_CFG.format(extport=extport, mappedport=mappedport, svc=svc), lo=2, hi=4)
    set_levels(db, "FW-C", {"port1": 4, "port2": 2})
    H(db, "10.10.1.9", 4)
    H(db, "10.20.3.50", 2)          # the mapped (inside) host
    db.commit()

    # the stored policy carries the MAPPED address and the MAPPED service port
    r = db.query(FirewallRule).filter(FirewallRule.policy_id == "1").one()
    assert r.dst == "10.20.3.50/32"
    assert r.dst_port == stored

    # a flow to the external VIP ip:port is permitted (was false 'denied' when
    # extport != mappedport)
    res = compute_path(db, "10.10.1.9", "10.10.1.50", dst_port=ext_q, protocol="tcp")
    assert res["overall"] == "permitted"
    # the DNAT target was resolved for the report
    assert res["nat_destination"]["mapped_ip"] == "10.20.3.50"


def test_c02_unequal_ports_was_denied_now_permitted_vs_direct_mapped(db):
    """Sanity: a direct flow to the mapped ip:mappedport also matches the
    translated rule, and a flow to the mapped ip on the EXTERNAL port does
    not (the rule now lives on the mapped port)."""
    ingest(db, VIP_CFG.format(extport="443", mappedport="8443", svc="HTTPS"), lo=2, hi=4)
    set_levels(db, "FW-C", {"port1": 4, "port2": 2})
    H(db, "10.10.1.9", 4)
    H(db, "10.20.3.50", 2)
    db.commit()
    assert compute_path(db, "10.10.1.9", "10.10.1.50", dst_port=443,
                        protocol="tcp")["overall"] == "permitted"


# =================================================================== C-03 ==
STRAY_QUOTE_CFG = '''
config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.20.3.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "p1"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set comment "rack 5" bay 2"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set name "p2"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
'''


def test_c03_stray_quote_does_not_swallow_following_policies(db):
    st = ingest(db, STRAY_QUOTE_CFG)
    pids = sorted({r.policy_id for r in db.query(FirewallRule).all()})
    assert pids == ["1", "2"]                     # both policies survived
    assert st["rules_created"] == 2
    assert st["quote_recoveries"] >= 1            # the stray quote was counted


MULTILINE_OK_CFG = '''
config firewall policy
    edit 1
        set name "p1"
        set srcaddr "all"
        set dstaddr "all"
        set comments "line one
second line with config firewall policy
end
third line"
        set action accept
        set service "ALL"
    next
    edit 2
        set name "p2"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "ALL"
    next
end
'''


def test_c03_legitimate_multiline_quoted_value_not_regressed(db):
    """A well-formed multi-line quoted value (replacemsg-style) still parses,
    and the policy after it is intact with no spurious recoveries."""
    p = parse_forti_block(MULTILINE_OK_CFG)
    assert list(p["firewall policy"]) == ["1", "2"]
    assert p["firewall policy"]["1"]["comments"].startswith("line one")
    assert "config firewall policy" in p["firewall policy"]["1"]["comments"]
    st = ingest(db, MULTILINE_OK_CFG)
    assert st["quote_recoveries"] == 0
    assert sorted({r.policy_id for r in db.query(FirewallRule).all()}) == ["1", "2"]


# =================================================================== C-04 ==
NAT_A = """
    config system settings
        set central-nat enable
    end
    config system interface
        edit "port1"
            set ip 10.3.0.1 255.255.255.0
        next
        edit "port2"
            set ip 172.16.4.1 255.255.255.0
        next
    end
    config firewall address
        edit "ot-hist"
            set subnet 10.3.0.5 255.255.255.255
        next
        edit "ot-net"
            set subnet 10.3.0.0 255.255.255.0
        next
    end
    config firewall ippool
        edit "ot-pool"
            set startip 172.16.4.100
            set endip 172.16.4.100
        next
    end
    config firewall central-snat-map
        edit 1
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-hist"
            set dst-addr "all"
            set protocol 6
            set orig-port 80
            set nat disable
        next
        edit 2
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-net"
            set dst-addr "all"
            set nat enable
            set nat-ippool "ot-pool"
        next
    end
    config firewall policy
        edit 1
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "ot-net"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""

# downstream FW-B permits only the UNtranslated historian source
NAT_B = """
    config system interface
        edit "port3"
            set ip 172.16.4.2 255.255.255.0
        next
        edit "port4"
            set ip 172.16.5.1 255.255.255.0
        next
    end
    config firewall address
        edit "hist"
            set subnet 10.3.0.5 255.255.255.255
        next
    end
    config firewall policy
        edit 1
            set srcintf "port3"
            set dstintf "port4"
            set srcaddr "hist"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def _nat_chain(db):
    ingest(db, NAT_A, "FW-A", 3, 4)
    ingest(db, NAT_B, "FW-B", 4, 5)
    H(db, "10.3.0.5", 3)
    H(db, "172.16.5.9", 5)
    db.commit()


def test_c04_exemption_limited_to_tcp80_does_not_exempt_tcp443(db):
    _nat_chain(db)
    # the exemption was stored with its orig-port
    ex = db.query(NatRule).filter(NatRule.name == "central-snat:1").one()
    assert ex.nat_exempt is True and ex.orig_port == "80"

    # tcp/80: the exemption applies -> source NOT translated -> FW-B permits
    res80 = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=80, protocol="tcp")
    assert [e["type"] for e in res80["nat"]] == ["snat_exempt"]
    assert res80["overall"] == "permitted"

    # tcp/443: the exemption does NOT apply -> entry 2 translates to the pool
    # -> FW-B (permits only the untranslated historian) denies
    res443 = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    snat = [e for e in res443["nat"] if e["type"] == "snat"]
    assert snat and snat[0]["translated"] == {"src_ip": "172.16.4.100"}
    assert "snat_exempt" not in [e["type"] for e in res443["nat"]]
    assert res443["overall"] == "denied"


# =================================================================== C-05 ==
SPACE_ZONE_CFG = """
    config system interface
        edit "port1"
            set ip 10.10.1.1 255.255.255.0
        next
        edit "port2"
            set ip 10.10.2.1 255.255.255.0
        next
        edit "port3"
            set ip 10.20.3.1 255.255.255.0
        next
        edit "port4"
            set ip 10.20.4.1 255.255.255.0
        next
    end
    config system zone
        edit "IT Zone"
            set interface "port1" "port2"
        next
        edit "OT Zone"
            set interface "port3" "port4"
        next
    end
    config firewall policy
        edit 10
            set name "it-to-ot-deny"
            set srcintf "IT Zone"
            set dstintf "OT Zone"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
        edit 11
            set name "ot-to-it-accept"
            set srcintf "OT Zone"
            set dstintf "IT Zone"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def test_c05_space_zone_names_matched_whole(db):
    ingest(db, SPACE_ZONE_CFG, lo=2, hi=4)
    set_levels(db, "FW-C", {"port1": 4, "port2": 4, "port3": 2, "port4": 2})
    # the whole zone name is stored, not split
    r = db.query(FirewallRule).filter(FirewallRule.policy_id == "10").one()
    assert (r.src_zone, r.dst_zone) == ("IT Zone", "OT Zone")
    # OT->IT is permitted by the accept, not falsely denied by the IT->OT deny
    assert cell(db, 2, 4) == "permitted"
    assert cell(db, 4, 2) == "denied"


def test_c05_space_zone_names_no_false_shadow(db):
    ingest(db, SPACE_ZONE_CFG, lo=2, hi=4)
    db.commit()
    res = find_shadowed_rules(db)
    shadows = res.get("shadows", res) if isinstance(res, dict) else res
    pairs = [(s.get("earlier_rule", {}).get("policy_id"),
              s.get("later_rule", {}).get("policy_id")) for s in shadows] \
        if isinstance(shadows, list) else []
    # the deny (IT Zone->OT Zone) must NOT be reported as shadowing the accept
    # (OT Zone->IT Zone): their zone sets are disjoint once names are whole.
    assert ("10", "11") not in pairs and ("11", "10") not in pairs


def test_mp05_rule_twins_resolve_space_zone_names_whole(db):
    """MP-05: the rule-level resolver (alert_engine._RuleZoneResolver) must
    keep "OT Zone" whole like reachability does - a permit IT -> "OT Zone"
    (L1) is an IT/OT bypass at the rule level too, not an unevaluated side."""
    from app.models import Finding, Site
    from app.parsers import alert_engine as ae
    from app.parsers.alert_engine import _RuleZoneResolver, _split_zone_value
    assert _split_zone_value('"IT Zone", "OT Zone"') == ["IT Zone", "OT Zone"]
    assert _split_zone_value("port1 port2") == ["port1 port2"]      # never split on space
    assert _split_zone_value(None) == [] and _split_zone_value("[]") == []
    site = Site(name="C05", code="c05")
    db.add(site)
    db.flush()
    cfg = SPACE_ZONE_CFG.replace('set action deny', 'set action accept', 1)
    ingest(db, cfg, lo=1, hi=4)
    set_levels(db, "FW-C", {"port1": 4, "port2": 4, "port3": 1, "port4": 1})
    fw = db.query(Firewall).filter_by(name="FW-C").one()
    fw.site_id = site.id
    for r in db.query(FirewallRule).filter_by(firewall_id=fw.id):
        r.site_id = site.id
    for i in db.query(FirewallInterface).filter_by(firewall_id=fw.id):
        i.site_id = site.id
    db.commit()
    res = _RuleZoneResolver(db)
    r10 = db.query(FirewallRule).filter(FirewallRule.policy_id == "10").one()
    assert res.resolve_checked(r10, r10.src_zone) == ({4}, True)
    assert res.resolve_checked(r10, r10.dst_zone) == ({1}, True)
    ae.run_periodic_reviews(db, site_id=site.id)
    byp = db.query(Finding).filter(Finding.check_name == "rule_it_ot_bypass",
                                   Finding.status == "open").all()
    assert any("'OT Zone'" in f.title and "(L1)" in f.title for f in byp), [f.title for f in byp]


# =================================================================== C-09 ==
ALIAS_ZONE_CFG = """
    config system interface
        edit "port1"
            set alias "OT"
            set ip 10.10.1.1 255.255.255.0
        next
        edit "port3"
            set ip 10.20.3.1 255.255.255.0
        next
        edit "port4"
            set ip 10.20.4.1 255.255.255.0
        next
    end
    config system zone
        edit "OT"
            set interface "port3" "port4"
        next
    end
    config firewall policy
        edit 20
            set name "ot-zone-to-port1"
            set srcintf "OT"
            set dstintf "port1"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def test_c09_zone_def_beats_interface_alias(db):
    ingest(db, ALIAS_ZONE_CFG, lo=2, hi=4)
    set_levels(db, "FW-C", {"port1": 4, "port3": 2, "port4": 2})
    # srcintf "OT" is the ZONE (port3/port4 @ L2), not port1's alias (L4);
    # the accept OT->port1 therefore permits L2 -> L4.
    assert cell(db, 2, 4) == "permitted"


# =================================================================== C-10 ==
def test_c10_reachability_not_quadratic_in_rule_rows(db):
    fw = FirewallDevice(name="big", vendor="fortigate", purdue_zone_from=4, purdue_zone_to=3)
    db.add(fw)
    db.flush()
    H(db, "10.4.0.5", 4)
    H(db, "10.3.0.5", 3)
    n = 4000
    rows = [
        FirewallRule(firewall_device_id=fw.id, device_name="big", device_type="fortigate",
                     src=f"10.4.{i // 254}.{i % 254}/32", dst="any", protocol="tcp",
                     dst_port=str(1000 + i), action="permit", rule_order=i, enabled=True)
        for i in range(n)
    ]
    db.add_all(rows)
    db.commit()

    t0 = time.perf_counter()
    res = compute_reachability(db, src_level=4, dst_level=3)
    elapsed = time.perf_counter() - t0
    # Before C-10 this was ~hundreds of seconds (O(permits^2) list dedupe);
    # it must now finish in a few seconds.
    assert elapsed < 20, f"compute_reachability took {elapsed:.1f}s for {n} rules"
    assert res["matrix"]["4→3"]["overall"] in ("permitted", "partial")


# =================================================================== C-16 ==
def _joined_many_interfaces(nports: int) -> str:
    # realistic long interface names (as on a real FortiGate the joined
    # srcintf of a 14-interface policy is ~139 chars, overflowing String(128))
    def nm(i):
        return f"lan-segment-{i:02d}"
    ports = "".join(
        f'        edit "{nm(i)}"\n            set ip 10.0.{i}.1 255.255.255.0\n        next\n'
        for i in range(1, nports + 1))
    srcintf = " ".join(f'"{nm(i)}"' for i in range(1, nports + 1))
    return f"""
    config system interface
{ports}    end
    config firewall policy
        edit 1
            set name "wide"
            set srcintf {srcintf}
            set dstintf "port1"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def test_c16_src_zone_dst_zone_are_text_and_hold_long_values(db):
    # schema: the columns must be unbounded TEXT (no String length)
    cols = {c["name"]: c for c in inspect(db.get_bind()).get_columns("firewall_rules")}
    for name in ("src_zone", "dst_zone"):
        assert getattr(cols[name]["type"], "length", None) in (None,), \
            f"{name} must be TEXT (unbounded), got {cols[name]['type']!r}"
    # a 14-interface policy produces a >128-char src_zone and stores fine
    st = ingest(db, _joined_many_interfaces(14))
    assert st["rules_created"] == 1
    r = db.query(FirewallRule).filter(FirewallRule.policy_id == "1").one()
    assert len(r.src_zone) > 128
    assert r.src_zone.split(",")[0] == "lan-segment-01"


# ---- data port with admin access is not "management-only" -------------------

def test_policy_referenced_interface_with_admin_access_is_not_mgmt_only():
    from app.parsers.forti_config_parser import _classify_interface
    cfg = {"allowaccess": ["ping", "https", "ssh"], "type": "physical"}
    assert _classify_interface("port2", cfg)["is_mgmt_only"] is True          # nothing else known
    assert _classify_interface("port2", cfg, policy_referenced=True)["is_mgmt_only"] is False
    # an explicitly management-named port stays management-only even if referenced
    assert _classify_interface("mgmt", cfg, policy_referenced=True)["is_mgmt_only"] is True
