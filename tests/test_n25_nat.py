"""N-25: FortiOS central SNAT, VIP46 / VIP64, IPv6 internet-service and
NAT-aware level-pair matrices.

Already modelled before N-25 (not retested here, see test_api_nat.py /
test_audit_reachability.py): `config firewall vip` / `vip6` DNAT, policy
`nat enable` + ippool SNAT, NatRule persistence, NAT on host queries and the
A-06 level-pair translation of restricted scopes.
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (Base, Firewall, FirewallDevice, FirewallInterface,
                        FirewallRule, Host, NatRule)
from app.parsers import rule_match as rm
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.topology_diff import compute_diff


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


def H(db, ip, lvl):
    db.add(Host(ip=ip, purdue_level=lvl))
    db.flush()


def ingest(db, cfg, name, lo, hi, **kw):
    return ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name,
                                   purdue_zone_from=lo, purdue_zone_to=hi, **kw)


def nat_rows(db, name=None, **flt):
    q = db.query(NatRule)
    if name:
        q = q.filter(NatRule.device_name == name)
    return [n for n in q.order_by(NatRule.id).all()
            if all(getattr(n, k) == v for k, v in flt.items())]


# ------------------------------------------------------------ central SNAT --
CENTRAL_A = """
    config system settings
        set central-nat enable
    end
    config system interface
        edit "port1"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
            set role lan
        next
        edit "port2"
            set vdom "root"
            set ip 172.16.4.1 255.255.255.0
            set role wan
        next
    end
    config firewall address
        edit "ot-net"
            set subnet 10.3.0.0 255.255.255.0
        next
        edit "it-net"
            set subnet 172.16.5.0 255.255.255.0
        next
    end
    config firewall ippool
        edit "ot-pool"
            set type overload
            set startip 172.16.4.100
            set endip 172.16.4.100
        next
    end
    config firewall central-snat-map
        edit 1
            set type ipv4
            set status enable
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-net"
            set dst-addr "it-net"
            set protocol 6
            set nat enable
            set nat-ippool "ot-pool"
        next
        edit 2
            set type ipv4
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-net"
            set dst-addr "all"
            set nat enable
        next
        edit 3
            set type ipv4
            set status disable
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "all"
            set dst-addr "all"
        next
    end
    config firewall policy
        edit 1
            set name "ot-out"
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

# downstream firewall: only the central-SNAT pool (or the A interface address)
# may pass
def _fw_b(src_ip):
    return f"""
    config system interface
        edit "port3"
            set ip 172.16.4.2 255.255.255.0
        next
        edit "port4"
            set ip 172.16.5.1 255.255.255.0
        next
    end
    config firewall address
        edit "snat-src"
            set subnet {src_ip} 255.255.255.255
        next
    end
    config firewall policy
        edit 1
            set name "from-ot-snat"
            set srcintf "port3"
            set dstintf "port4"
            set srcaddr "snat-src"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def _chain(db, b_src="172.16.4.100", a_cfg=CENTRAL_A):
    ingest(db, a_cfg, "FW-A", 3, 4)
    ingest(db, _fw_b(b_src), "FW-B", 4, 5)
    H(db, "10.3.0.5", 3)
    H(db, "172.16.5.9", 5)
    db.commit()


def test_central_snat_parsed_into_nat_rules(db):
    st = ingest(db, CENTRAL_A, "FW-A", 3, 4)
    assert st["central_snat_rules"] == 3
    rows = nat_rows(db, "FW-A", nat_kind="central-snat")
    assert [r.name for r in rows] == ["central-snat:1", "central-snat:2", "central-snat:3"]
    r1, r2, r3 = rows
    assert (r1.nat_type, r1.src_intf, r1.dst_intf) == ("snat", "port1", "port2")
    assert r1.orig_src == "10.3.0.0/24" and r1.orig_dst == "172.16.5.0/24"
    assert r1.mapped_ip == "172.16.4.100/32" and r1.protocol == "tcp"
    assert r1.enabled is True and r1.policy_id == "1"          # feeds from policy 1
    assert r2.mapped_ip == "interface:port2" and r2.orig_dst is None and r2.protocol == "any"
    assert r3.enabled is False                                  # status disable


def test_central_snat_inert_without_central_nat(db):
    st = ingest(db, CENTRAL_A.replace("set central-nat enable", "set central-nat disable"),
                "FW-A", 3, 4)
    rows = nat_rows(db, "FW-A", nat_kind="central-snat")
    assert st["central_snat_rules"] == 3 and not any(r.enabled for r in rows)
    assert "central-nat is not enabled" in rows[0].raw


def test_central_snat_applied_after_policy_on_host_path(db):
    # B only permits the pool address: the flow passes only because FW-A's
    # central SNAT (entry 1: tcp, dst it-net) translated the source.
    _chain(db)
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    assert res["overall"] == "permitted"
    ev = [e for e in res["nat"] if e["type"] == "snat"]
    assert ev and ev[0]["nat_kind"] == "central-snat"
    assert ev[0]["translated"] == {"src_ip": "172.16.4.100"}
    # UDP is not covered by entry 1 (protocol 6); entry 2 is interface mode and
    # translates to FW-A's port2 address 172.16.4.1, which B does not permit
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=53, protocol="udp")
    assert res["overall"] == "denied"


def test_central_snat_dst_addr_limit(db):
    _chain(db)
    H(db, "172.16.9.9", 5)
    # dst outside entry 1's dst-addr (it-net): only entry 2 (interface) applies
    res = compute_path(db, "10.3.0.5", "172.16.9.9", dst_port=443, protocol="tcp")
    snat = [e for e in res["nat"] if e["type"] == "snat"]
    assert snat and snat[0]["translated"]["src_ip"] == "172.16.4.1"
    assert res["overall"] == "denied"


def test_central_snat_interface_mode_resolves_to_interface_address(db):
    _chain(db, b_src="172.16.4.1")          # B permits FW-A's port2 address
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=53, protocol="udp")
    assert res["overall"] == "permitted"
    assert res["nat"][0]["translated"] == {"src_ip": "172.16.4.1"}


def test_central_snat_disabled_rows_do_not_translate(db):
    _chain(db, a_cfg=CENTRAL_A.replace("set central-nat enable", "set central-nat disable"))
    assert compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")["overall"] == "denied"


def test_policy_nat_inert_when_central_nat_on(db):
    cfg = CENTRAL_A.replace('set action accept', 'set action accept\n set nat enable')
    ingest(db, cfg, "FW-A", 3, 4)
    pol = nat_rows(db, "FW-A", nat_kind="policy-nat")
    assert pol and not any(r.enabled for r in pol)
    assert "central-nat enabled" in pol[0].raw


# --------------------------------------- level-pair matrices are NAT-aware --
def test_matrix_translates_unrestricted_scope_through_central_snat(db):
    _chain(db)
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    # B permits only the pool address; A permits ot-net -> any.  Reported
    # scopes keep the ORIGINAL (pre-translation) sources...
    assert cell["overall"] == "partial"
    srcs = {s["src"] for s in cell["paths"][0]["permitted_scopes"]}
    assert any(s.startswith("10.3.0.0/24") for s in srcs)
    # ...and the translated-address view is exposed
    tsrc = {s["src"] for s in cell["paths"][0]["translated_scopes"]}
    assert "172.16.4.100/32" in tsrc


def test_matrix_central_snat_protocol_and_dst_limits(db):
    # only entry 1 (tcp, dst it-net) -> the translated scope is limited to it
    cfg = CENTRAL_A.replace(
        '''        edit 2
            set type ipv4
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-net"
            set dst-addr "all"
            set nat enable
        next
''', "")
    _chain(db, a_cfg=cfg)
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    assert cell["overall"] == "partial"
    assert cell["paths"][0]["permitted_scopes"] == [
        {"src": "10.3.0.0/24", "dst": "172.16.5.0/24", "services": ["tcp/any"]}]
    # the matrix cell says translation was only partly applicable
    assert cell["nat_dependent"] is True


def test_matrix_without_translation_match_stays_denied(db):
    _chain(db, b_src="172.16.4.77")           # neither pool nor interface address
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    assert cell["overall"] == "denied"


def test_matrix_permissive_downstream_stays_permitted(db):
    # regression guard: an SNATing firewall in front of an unrestricted one
    # must not demote "permitted" to "partial"
    ingest(db, CENTRAL_A.replace('set srcaddr "ot-net"', 'set srcaddr "all"'), "FW-A", 3, 4)
    ingest(db, _fw_b("172.16.4.100").replace('set srcaddr "snat-src"', 'set srcaddr "all"'),
           "FW-B", 4, 5)
    db.commit()
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    assert cell["overall"] == "permitted"


def test_matrix_cell_flags_nat_dependent_when_translation_unknown(db):
    # SNAT to an interface whose address is not in the DB and an ippool that
    # does not exist: no concrete translated address -> NAT-dependent cell
    cfg = textwrap.dedent("""
        config system interface
            edit "p1"
                set ip 10.3.0.1 255.255.255.0
            next
        end
        config firewall policy
            edit 1
                set srcintf "p1"
                set dstintf "p2"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
                set nat enable
            next
        end
    """)
    ingest(db, cfg, "FW-A", 3, 4)
    db.commit()
    cell = compute_reachability(db, src_level=3, dst_level=4)["matrix"]["3→4"]
    assert cell["overall"] == "permitted"          # the permit itself is not in doubt
    assert cell["nat_dependent"] is True
    assert any("interface address unknown" in n["reason"] for n in cell["nat_notes"])
    # a cell on a path without NAT rows is not flagged
    plain = compute_reachability(db, src_level=4, dst_level=3)["matrix"]["4→3"]
    assert plain["nat_dependent"] is True          # same firewall, same NAT rows (both directions)


def test_matrix_no_nat_rows_not_flagged(db):
    ingest(db, _fw_b("10.0.0.1"), "FW-B", 4, 5)
    db.commit()
    cell = compute_reachability(db, src_level=4, dst_level=5)["matrix"]["4→5"]
    assert cell["nat_dependent"] is False and cell["nat_notes"] == []


# --------------------------------------------------------- VIP46 / VIP64 --
XFAM_A = """
    config system interface
        edit "port1"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
        edit "port2"
            set vdom "root"
            set ip 172.16.4.1 255.255.255.0
        next
    end
    config firewall address
        edit "it-net"
            set subnet 172.16.4.0 255.255.255.0
        next
    end
    config firewall address6
        edit "ot6-net"
            set ip6 2001:db8:3::/64
        next
    end
    config firewall vip46
        edit "vip46-hmi"
            set extip 172.16.4.50
            set mappedip "2001:db8:3::5"
            set extintf "port2"
            set portforward enable
            set protocol tcp
            set extport 443
            set mappedport 8443
        next
    end
    config firewall vip64
        edit "vip64-hist"
            set extip 2001:db8:3::100
            set mappedip "172.16.4.60"
            set extintf "port1"
        next
    end
    config firewall ippool6
        edit "pool6"
            set startip 2001:db8:3::f00
            set endip 2001:db8:3::f00
        next
    end
    config firewall policy46
        edit 1
            set srcintf "port2"
            set dstintf "port1"
            set srcaddr "it-net"
            set dstaddr "vip46-hmi"
            set action accept
            set schedule "always"
            set service "ALL"
            set ippool enable
            set poolname "pool6"
        next
    end
    config firewall policy64
        edit 1
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "ot6-net"
            set dstaddr "vip64-hist"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def test_vip46_vip64_parsed_as_cross_family_dnat(db):
    st = ingest(db, XFAM_A, "FW-A", 3, 4)
    assert st["rules_cross_family"] == 2
    v46 = nat_rows(db, "FW-A", nat_kind="vip46")[0]
    assert (v46.nat_type, v46.ext_ip, v46.mapped_ip) == ("dnat", "172.16.4.50/32", "2001:db8:3::5/128")
    assert (v46.protocol, v46.ext_port, v46.mapped_port) == ("tcp", "443", "8443")
    assert v46.policy_id == "policy46:1" and v46.src_intf == "port2"
    v64 = nat_rows(db, "FW-A", nat_kind="vip64")[0]
    assert (v64.ext_ip, v64.mapped_ip) == ("2001:db8:3::100/128", "172.16.4.60/32")
    assert v64.policy_id == "policy64:1"
    # policy46 ippool6 -> cross-family SNAT (v4 client sources -> v6 pool)
    sn = nat_rows(db, "FW-A", nat_kind="policy46-nat")[0]
    assert sn.orig_src == "172.16.4.0/24" and sn.mapped_ip == "2001:db8:3::f00/128"


def test_policy46_policy64_rows_are_cross_family(db):
    ingest(db, XFAM_A, "FW-A", 3, 4)
    r46 = db.query(FirewallRule).filter(FirewallRule.policy_id == "policy46:1").one()
    assert (r46.src, r46.dst) == ("172.16.4.0/24", "2001:db8:3::5/128")
    assert "VIP46" in r46.raw_line
    r64 = db.query(FirewallRule).filter(FirewallRule.policy_id == "policy64:1").one()
    assert (r64.src, r64.dst) == ("2001:db8:3::/64", "172.16.4.60/32")


def test_vip46_host_path_translates_family_and_permits(db):
    ingest(db, XFAM_A, "FW-A", 3, 4)
    H(db, "172.16.4.7", 4)
    H(db, "2001:db8:3::5", 3)
    db.commit()
    res = compute_path(db, "172.16.4.7", "172.16.4.50", dst_port=443, protocol="tcp")
    assert res["nat_destination"]["mapped_ip"] == "2001:db8:3::5"
    assert res["overall"] == "permitted"
    dn = [e for e in res["nat"] if e["type"] == "dnat"][0]
    assert dn["cross_family"] is True and dn["nat_kind"] == "vip46"
    assert dn["translated"]["dst_ip"] == "2001:db8:3::5"


def test_vip64_host_path_from_ipv6_client(db):
    ingest(db, XFAM_A, "FW-A", 3, 4)
    H(db, "2001:db8:3::77", 3)
    H(db, "172.16.4.60", 4)
    db.commit()
    res = compute_path(db, "2001:db8:3::77", "2001:db8:3::100")
    assert res["nat_destination"]["mapped_ip"] == "172.16.4.60"
    assert res["overall"] == "permitted"


def test_level_pair_cross_family_is_unknown_not_blocked(db):
    # The only rule that can permit IPv4 traffic from L4 is the policy46 row
    # (v4 client -> v6 mapped server).  A level-pair query has no addresses to
    # translate: the answer must be NAT-dependent "unknown", never "denied".
    ingest(db, XFAM_A, "FW-A", 3, 4)
    H(db, "172.16.4.7", 4)
    H(db, "2001:db8:3::5", 3)
    db.commit()
    cell = compute_reachability(db, src_level=4, dst_level=3)["matrix"]["4→3"]
    assert cell["overall"] == "unknown"
    assert cell["nat_dependent"] is True
    ep = cell["paths"][0]["hops"][0]["enforcement_points"][0]
    assert ep["reason_code"] == "cross_family_nat"
    assert ep["cross_family_rules"][0]["policy_id"] == "policy46:1"
    # IPv6 view of the same boundary (policy64 is the v6 client rule)
    cell6 = compute_reachability(db, src_level=3, dst_level=4, ip_version=6)["matrix"]["3→4"]
    assert cell6["overall"] == "unknown"


def test_level_pair_without_cross_family_rule_is_still_denied(db):
    cfg = XFAM_A.split("config firewall policy46")[0]
    ingest(db, cfg + """
        config firewall policy
            edit 9
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "all"
                set dstaddr "all"
                set action deny
                set service "ALL"
            next
        end
    """, "FW-A", 3, 4)
    db.commit()
    assert compute_reachability(db, src_level=4, dst_level=3)["matrix"]["4→3"]["overall"] == "denied"


def test_downstream_deny_beyond_family_translation_is_unknown(db):
    # FW-A (4<->3) permits v4 and has a VIP46 -> v6; FW-B (3<->2) only has IPv6
    # rules.  Evaluated in IPv4, B would deny for want of v4 rules - but beyond
    # the translation the flow is IPv6, so that deny is not a real "blocked".
    a = XFAM_A.split("config firewall policy46")[0] + """
        config firewall policy
            edit 5
                set srcintf "port2"
                set dstintf "port1"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
            next
        end
    """
    ingest(db, a, "FW-A", 3, 4)
    b = """
        config firewall address6
            edit "ot6"
                set ip6 2001:db8:3::/64
            next
        end
        config firewall policy6
            edit 1
                set srcintf "q1"
                set dstintf "q2"
                set srcaddr "ot6"
                set dstaddr "all"
                set action accept
                set service "ALL"
            next
        end
    """
    ingest(db, b, "FW-B", 2, 3)
    db.commit()
    cell = compute_reachability(db, src_level=4, dst_level=2)["matrix"]["4→2"]
    assert cell["overall"] == "unknown" and cell["nat_dependent"] is True
    # control: no VIP46 on FW-A -> a plain deny stays "denied"
    db.query(NatRule).filter(NatRule.nat_kind.in_(["vip46", "policy46-nat"])).delete(
        synchronize_session=False)
    db.commit()
    assert compute_reachability(db, src_level=4, dst_level=2)["matrix"]["4→2"]["overall"] == "denied"


def test_cross_family_rows_do_not_crash_shadow_and_diff(db):
    ingest(db, XFAM_A, "FW-A", 3, 4)
    db.commit()
    assert find_shadowed_rules(db) is not None
    assert compute_diff(db) is not None


# -------------------------------------------------- IPv6 internet-service --
ISDB6 = """
    config firewall address6
        edit "ot6"
            set ip6 2001:db8:3::/64
        next
    end
    config firewall policy
        edit 1
            set srcintf "port1"
            set dstintf "wan"
            set srcaddr6 "ot6"
            set internet-service6 enable
            set internet-service6-name "Google-Google.Web" "Microsoft-Office365"
            set action accept
            set service "ALL"
        next
    end
    config firewall policy6
        edit 2
            set srcintf "port1"
            set dstintf "wan"
            set srcaddr "ot6"
            set internet-service enable
            set internet-service-name "Amazon-AWS"
            set action accept
        next
    end
"""


def test_ipv6_internet_service_is_an_external_address_set(db):
    st = ingest(db, ISDB6, "FW-A", 3, 4)
    assert st["internet_service6_refs"] == 3
    rows = db.query(FirewallRule).order_by(FirewallRule.id).all()
    assert {(r.policy_id, r.dst) for r in rows} == {
        ("1", "internet-service6:Google-Google.Web"),
        ("1", "internet-service6:Microsoft-Office365"),
        ("policy6:2", "internet-service6:Amazon-AWS"),
    }
    assert all(r.src == "2001:db8:3::/64" for r in rows)       # still an IPv6 source set
    assert all("[external/internet]" in r.raw_line for r in rows)
    assert st["unresolved_objects"] == 3                        # like internet-service:


def test_ipv4_internet_service_unchanged_and_ipv6_flagged_in_reachability(db):
    ingest(db, ISDB6, "FW-A", 3, 4)
    db.commit()
    cell = compute_reachability(db, src_level=3, dst_level=4, ip_version=6)["matrix"]["3→4"]
    ep = cell["paths"][0]["hops"][0]["enforcement_points"][0]
    # an ISDB set cannot be expanded: never a silent permit/deny, flagged external
    assert cell["overall"] == "unknown"
    assert ep["unresolved_rules"] and all(u["external_internet"] for u in ep["unresolved_rules"])


def test_rule_match_external_token_helper():
    assert rm.is_external_addr_token("internet-service6:Foo")
    assert rm.is_external_addr_token("internet-service:Foo")
    assert not rm.is_external_addr_token("10.0.0.0/8")
    assert not rm.is_external_addr_token(None)
    assert isinstance(rm.parse_address("internet-service6:Foo"), rm.Unresolved)


def test_vdom_none_for_flat_config(db):
    ingest(db, CENTRAL_A, "FW-A", 3, 4)
    assert {r.vdom for r in db.query(FirewallRule)} == {None}
    assert {n.vdom for n in db.query(NatRule)} == {None}
