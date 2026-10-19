"""FortiOS correctness audit, group 1:

B-07  `config system zone` / SD-WAN zones resolved (zone -> member interfaces,
      intrazone allow|deny, per VDOM) for reachability, rule_shadow and
      topology_diff.
B-13  central-snat-map first-match in configured order incl. `nat disable`
      exemption entries.
B-15  (a) re-ingest prunes removed interfaces / zones, (b) no truncation of
      NAT lists, (c) invalid service port ranges are unresolved (never
      any/any), (d) tokenizer: escaped quotes and multi-line quoted values.
B-24  only valid unicast single-host address objects become Hosts.
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (Base, FirewallInterface, FirewallRule, FirewallZone,
                        FirewallZoneDef, Host, NatRule, NetworkSession, PcapCapture)
from app.parsers.forti_config_parser import (
    _address_object_host_ip, _forti_portrange_tokens, _resolve_service,
    ingest_fortigate_config, parse_forti_block,
)
from app.parsers.reachability import _Context, compute_path, compute_reachability
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


def ingest(db, cfg, name="FW-Z", lo=None, hi=None, **kw):
    return ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name,
                                   purdue_zone_from=lo, purdue_zone_to=hi, **kw)


def set_levels(db, name, levels: dict):
    for fi in db.query(FirewallInterface).all():
        if fi.firewall.name == name and fi.name in levels:
            fi.purdue_level = levels[fi.name]
    db.commit()


def cell(db, a, b, **kw):
    return compute_reachability(db, src_level=a, dst_level=b, **kw)["matrix"][f"{a}→{b}"]


def H(db, ip, lvl=None):
    h = db.query(Host).filter(Host.ip == ip).first()
    if h is None:
        h = Host(ip=ip)
        db.add(h)
    h.purdue_level = lvl
    db.flush()
    return h


# =================================================================== B-07 ==
IFACES = """
    config system interface
        edit "port1"
            set vdom "root"
            set ip 10.10.1.1 255.255.255.0
            set role lan
        next
        edit "port2"
            set vdom "root"
            set ip 10.10.2.1 255.255.255.0
            set role lan
        next
        edit "port3"
            set vdom "root"
            set ip 10.20.3.1 255.255.255.0
            set role lan
        next
        edit "port4"
            set vdom "root"
            set ip 10.20.4.1 255.255.255.0
            set role lan
        next
    end
"""

ZONES = """
    config system zone
        edit "ITZ"
            set interface "port1" "port2"
        next
        edit "OTZ"
            set intrazone {otz_intra}
            set interface "port3" "port4"
        next
    end
"""

POLICIES_ZONE = """
    config firewall policy
        edit 10
            set name "it-to-ot-deny"
            set srcintf "{it}"
            set dstintf "{ot}"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
        edit 11
            set name "ot-to-it"
            set srcintf "{ot}"
            set dstintf "{it}"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def _zone_cfg(it="ITZ", ot="OTZ", otz_intra="deny", with_zones=True):
    return (IFACES + (ZONES.format(otz_intra=otz_intra) if with_zones else "")
            + POLICIES_ZONE.format(it=it, ot=ot))


LV_TWO_SIDES = {"port1": 4, "port2": 4, "port3": 2, "port4": 2}


def test_zone_parsed_into_zone_defs_and_firewall_zone_rows(db):
    st = ingest(db, _zone_cfg(), lo=2, hi=4)
    assert st["zones_defined"] == 2
    zd = {z.name: z for z in db.query(FirewallZoneDef).all()}
    assert zd["ITZ"].members == ["port1", "port2"] and zd["ITZ"].kind == "zone"
    assert zd["ITZ"].intrazone == "deny"           # FortiOS default
    assert zd["OTZ"].members == ["port3", "port4"] and zd["ITZ"].vdom is None
    fz = {z.interface_name: z.zone_name for z in db.query(FirewallZone).all()}
    assert fz == {"port1": "ITZ", "port2": "ITZ", "port3": "OTZ", "port4": "OTZ"}
    r = db.query(FirewallRule).filter(FirewallRule.policy_id == "10").one()
    assert (r.src_zone, r.dst_zone) == ("ITZ", "OTZ")


@pytest.mark.parametrize("use_zones", [True, False])
def test_zone_repro_ot_to_it_permitted_not_denied(db, use_zones):
    """B-07 repro: deny ITZ->OTZ then accept OTZ->ITZ.  OT->IT is permitted
    exactly as with plain interface names (it used to be "denied": the
    unresolved zone made the deny apply in both directions)."""
    cfg = _zone_cfg() if use_zones else _zone_cfg(it="port1", ot="port3", with_zones=False)
    ingest(db, cfg, lo=2, hi=4)
    set_levels(db, "FW-Z", LV_TWO_SIDES)
    H(db, "10.20.3.5", 2)
    H(db, "10.10.1.5", 4)
    db.commit()
    assert compute_path(db, "10.20.3.5", "10.10.1.5", dst_port=443, protocol="tcp")["overall"] \
        == "permitted"
    assert compute_path(db, "10.10.1.5", "10.20.3.5", dst_port=443, protocol="tcp")["overall"] \
        == "denied"
    assert cell(db, 2, 4)["overall"] == "permitted"
    assert cell(db, 4, 2)["overall"] == "denied"


def test_zone_reanalysis_without_reparse_uses_stored_membership(db):
    ingest(db, _zone_cfg(), lo=2, hi=4)
    set_levels(db, "FW-Z", LV_TWO_SIDES)
    ctx = _Context(db)
    fw_id = db.query(FirewallZoneDef).first().firewall_id
    assert ctx.zone_def(fw_id, None, "itz")["members"] == ["port1", "port2"]
    assert compute_reachability(db, src_level=2, dst_level=4)["matrix"]["2→4"]["overall"] \
        == "permitted"


# Intrazone: OTZ members on two different Purdue levels (port3 L2, port4 L1)
LV_MULTI = {"port1": 4, "port2": 4, "port3": 2, "port4": 1}


def test_intrazone_deny_blocks_traffic_between_zone_members(db):
    ingest(db, _zone_cfg(otz_intra="deny"))          # multi-leg box (interface levels)
    set_levels(db, "FW-Z", LV_MULTI)
    cell = compute_reachability(db, src_level=2, dst_level=1)["matrix"]["2→1"]
    assert cell["overall"] == "denied"
    # the ITZ -> OTZ deny does not govern OTZ-internal traffic, the OTZ -> ITZ
    # accept still permits L2 -> L4
    assert compute_reachability(db, src_level=2, dst_level=4)["matrix"]["2→4"]["overall"] \
        == "permitted"


def test_intrazone_allow_permits_traffic_between_zone_members(db):
    ingest(db, _zone_cfg(otz_intra="allow"))
    set_levels(db, "FW-Z", LV_MULTI)
    assert db.query(FirewallZoneDef).filter_by(name="OTZ").one().intrazone == "allow"
    cell = compute_reachability(db, src_level=2, dst_level=1)["matrix"]["2→1"]
    assert cell["overall"] == "permitted"
    H(db, "10.20.3.5", 2)
    H(db, "10.20.4.5", 1)
    db.commit()
    res = compute_path(db, "10.20.3.5", "10.20.4.5", dst_port=502, protocol="tcp")
    assert res["overall"] == "permitted"
    ep = res["hops"][0]["enforcement_points"][0]
    assert ep["reason_code"] == "intrazone_allow"
    # IT -> OT is still denied by the zone policy
    assert compute_reachability(db, src_level=4, dst_level=1)["matrix"]["4→1"]["overall"] \
        == "denied"


def test_intrazone_allow_explicit_zone_policy_wins(db):
    cfg = _zone_cfg(otz_intra="allow").replace("    config firewall policy\n", """    config firewall policy
        edit 5
            set name "otz-internal-deny"
            set srcintf "OTZ"
            set dstintf "OTZ"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
""", 1)
    ingest(db, cfg)
    set_levels(db, "FW-Z", LV_MULTI)
    assert compute_reachability(db, src_level=2, dst_level=1)["matrix"]["2→1"]["overall"] \
        == "denied"


VDOM_CFG = """
    config vdom
        edit "IT"
        next
        edit "OT"
        next
    end
    config global
        config system interface
            edit "port1"
                set vdom "IT"
                set ip 10.10.1.1 255.255.255.0
            next
            edit "port2"
                set vdom "IT"
                set ip 10.10.2.1 255.255.255.0
            next
            edit "port3"
                set vdom "OT"
                set ip 10.20.3.1 255.255.255.0
            next
            edit "port4"
                set vdom "OT"
                set ip 10.20.4.1 255.255.255.0
            next
        end
    end
    config vdom
        edit "IT"
            config system zone
                edit "Z"
                    set interface "port1" "port2"
                next
            end
        next
        edit "OT"
            config system zone
                edit "Z"
                    set interface "port3"
                next
                edit "ZUP"
                    set interface "port4"
                next
            end
            config firewall policy
                edit 1
                    set name "z-to-zup-deny"
                    set srcintf "Z"
                    set dstintf "ZUP"
                    set srcaddr "all"
                    set dstaddr "all"
                    set action deny
                    set schedule "always"
                    set service "ALL"
                next
                edit 2
                    set name "zup-to-z"
                    set srcintf "ZUP"
                    set dstintf "Z"
                    set srcaddr "all"
                    set dstaddr "all"
                    set action accept
                    set schedule "always"
                    set service "ALL"
                next
            end
        next
    end
"""


def test_zone_in_vdom_resolved_per_vdom(db):
    ingest(db, VDOM_CFG, lo=2, hi=3)
    zd = {(z.vdom, z.name): z.members for z in db.query(FirewallZoneDef).all()}
    # same zone name in two VDOMs never merges
    assert zd == {("IT", "Z"): ["port1", "port2"], ("OT", "Z"): ["port3"],
                  ("OT", "ZUP"): ["port4"]}
    assert {fi.name: fi.vdom for fi in db.query(FirewallInterface).all()} == {
        "port1": "IT", "port2": "IT", "port3": "OT", "port4": "OT"}
    set_levels(db, "FW-Z", {"port3": 2, "port4": 3, "port1": 3, "port2": 3})
    # OT VDOM: ZUP (port4, L3) -> Z (port3, L2) accepted; Z -> ZUP denied.
    # IT's "Z" (port1/port2, L3) must not leak into OT's "Z".
    assert cell(db, 3, 2)["overall"] == "permitted"
    assert cell(db, 2, 3)["overall"] == "denied"


SDWAN_CFG = """
    config system interface
        edit "wan1"
            set ip 192.0.2.2 255.255.255.0
        next
        edit "wan2"
            set ip 198.51.100.2 255.255.255.0
        next
        edit "port3"
            set ip 10.20.3.1 255.255.255.0
        next
    end
    config system sdwan
        set status enable
        config zone
            edit "virtual-wan-link"
            next
            edit "WANZ"
            next
        end
        config members
            edit 1
                set interface "wan1"
                set zone "WANZ"
            next
            edit 2
                set interface "wan2"
                set zone "WANZ"
            next
        end
    end
    config firewall policy
        edit 1
            set name "wan-in-deny"
            set srcintf "WANZ"
            set dstintf "port3"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
        edit 2
            set name "ot-out"
            set srcintf "port3"
            set dstintf "WANZ"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""


def test_sdwan_zone_members_expanded(db):
    ingest(db, SDWAN_CFG, lo=3, hi=5)
    zd = {z.name: z for z in db.query(FirewallZoneDef).all()}
    assert zd["WANZ"].kind == "sdwan" and zd["WANZ"].members == ["wan1", "wan2"]
    assert zd["WANZ"].members_resolved is True
    set_levels(db, "FW-Z", {"wan1": 5, "wan2": 5, "port3": 3})
    assert cell(db, 3, 5)["overall"] == "permitted"
    assert cell(db, 5, 3)["overall"] == "denied"


def test_sdwan_zone_unparseable_members_is_unknown_not_denied(db):
    cfg = SDWAN_CFG.replace('''            edit 2
                set interface "wan2"
                set zone "WANZ"''', '''            edit 2
                set zone "WANZ"''')
    ingest(db, cfg, lo=3, hi=5)
    zd = db.query(FirewallZoneDef).filter_by(name="WANZ").one()
    assert zd.members_resolved is False
    set_levels(db, "FW-Z", {"wan1": 5, "wan2": 5, "port3": 3})
    # the WANZ deny may or may not govern 3->5 (membership unknown): the
    # later accept cannot be reported as a clean permit, and never "denied"
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    assert cell["overall"] == "unknown"


def test_empty_zone_policy_matches_nothing(db):
    cfg = _zone_cfg().replace('''        edit "OTZ"''', '''        edit "EMPTYZ"
        next
        edit "OTZ"''').replace('set srcintf "ITZ"\n            set dstintf "OTZ"',
                               'set srcintf "EMPTYZ"\n            set dstintf "OTZ"')
    ingest(db, cfg, lo=2, hi=4)
    set_levels(db, "FW-Z", LV_TWO_SIDES)
    assert db.query(FirewallZoneDef).filter_by(name="EMPTYZ").one().members == []
    assert db.query(FirewallRule).filter_by(policy_id="10").one().src_zone == "EMPTYZ"
    # the deny names an empty zone: it governs nothing - IT->OT hits the
    # implicit deny, OT->IT the accept
    assert cell(db, 2, 4)["overall"] == "permitted"
    H(db, "10.10.1.5", 4)
    H(db, "10.20.3.5", 2)
    db.commit()
    res = compute_path(db, "10.10.1.5", "10.20.3.5", dst_port=443, protocol="tcp")
    assert res["overall"] == "denied"
    assert res["hops"][0]["enforcement_points"][0]["reason_code"] == "implicit_deny"


def test_rule_shadow_expands_zone_membership(db):
    cfg = IFACES + ZONES.format(otz_intra="deny") + """
    config firewall policy
        edit 1
            set name "permit-ot-all"
            set srcintf "OTZ"
            set dstintf "ITZ"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
        edit 2
            set name "deny-ot-from-any-ot-member"
            set srcintf "OTZ"
            set dstintf "ITZ"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "HTTP"
        next
    end
"""
    ingest(db, cfg)
    res = find_shadowed_rules(db)
    assert any(s["shadow_type"] == "full_shadow" for s in res["shadows"])
    # an empty zone shadows nothing
    db2_cfg = cfg.replace('''        edit "OTZ"''', '''        edit "NOZ"
        next
        edit "OTZ"''').replace('''            set name "permit-ot-all"
            set srcintf "OTZ"''', '''            set name "permit-ot-all"
            set srcintf "NOZ"''')
    ingest(db, db2_cfg)
    res = find_shadowed_rules(db)
    assert not [s for s in res["shadows"] if s["shadow_type"] == "full_shadow"]


def test_topology_diff_fallback_respects_zone_interfaces(db):
    """No Purdue path (hosts unclassified): the per-device first-match
    fallback used to let the ITZ->OTZ deny match an OT->IT session."""
    ingest(db, _zone_cfg())
    a, b = H(db, "10.20.3.5"), H(db, "10.10.1.5")
    db.add(NetworkSession(src_host_id=a.id, dst_host_id=b.id, dst_port=443, transport="tcp"))
    db.add(NetworkSession(src_host_id=b.id, dst_host_id=a.id, dst_port=443, transport="tcp"))
    db.commit()
    res = compute_diff(db)
    unexpected = {(u["src_ip"], u["dst_ip"]): u for u in res["unexpected_traffic"]}
    assert ("10.20.3.5", "10.10.1.5") not in unexpected        # OT->IT accepted
    u = unexpected[("10.10.1.5", "10.20.3.5")]                  # IT->OT denied
    assert u["reason_code"] == "explicit_deny"


# =================================================================== B-13 ==
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
        edit "ot-net"
            set subnet 10.3.0.0 255.255.255.0
        next
        edit "ot-hist"
            set subnet 10.3.0.5 255.255.255.255
        next
    end
    config firewall ippool
        edit "ot-pool"
            set startip 172.16.4.100
            set endip 172.16.4.100
        next
    end
    config firewall central-snat-map
{entries}
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

EXEMPT = """        edit {eid}
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-hist"
            set dst-addr "all"
            set nat disable
        next
"""
XLATE = """        edit {eid}
            set srcintf "port1"
            set dstintf "port2"
            set orig-addr "ot-net"
            set dst-addr "all"
            set nat enable
            set nat-ippool "ot-pool"
        next
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


def _nat_chain(db, entries):
    ingest(db, NAT_A.format(entries=entries), "FW-A", 3, 4)
    ingest(db, NAT_B, "FW-B", 4, 5)
    H(db, "10.3.0.5", 3)
    H(db, "172.16.5.9", 5)
    db.commit()


def test_exemption_entry_first_means_no_translation(db):
    _nat_chain(db, EXEMPT.format(eid=1) + XLATE.format(eid=2))
    rows = db.query(NatRule).filter(NatRule.nat_kind == "central-snat").order_by(NatRule.id).all()
    assert [(r.name, r.sequence, r.nat_exempt, r.enabled) for r in rows] == [
        ("central-snat:1", 1, True, True), ("central-snat:2", 2, False, True)]
    assert rows[0].mapped_ip is None
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    assert res["overall"] == "permitted"
    assert [e["type"] for e in res["nat"]] == ["snat_exempt"]
    # level pair: the exempted source still reaches L5 (never "denied")
    cell = compute_reachability(db, src_level=3, dst_level=5)["matrix"]["3→5"]
    assert cell["overall"] in ("permitted", "partial")


def test_translating_entry_first_translates(db):
    _nat_chain(db, XLATE.format(eid=1) + EXEMPT.format(eid=2))
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    snat = [e for e in res["nat"] if e["type"] == "snat"]
    assert snat and snat[0]["translated"] == {"src_ip": "172.16.4.100"}
    assert res["overall"] == "denied"      # B does not permit the pool address


def test_central_snat_order_is_config_position_not_entry_id(db):
    # `move 7 before 3`: config order is 7 (exemption) then 3 (translation)
    _nat_chain(db, EXEMPT.format(eid=7) + XLATE.format(eid=3))
    rows = {r.name: r.sequence for r in db.query(NatRule).filter(
        NatRule.nat_kind == "central-snat").all()}
    assert rows == {"central-snat:7": 1, "central-snat:3": 2}
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    assert res["overall"] == "permitted"


def test_nat_rows_loaded_in_sequence_order(db):
    _nat_chain(db, EXEMPT.format(eid=1) + XLATE.format(eid=2))
    # swap the stored ids' meaning: give the translating row the lower sequence
    for r in db.query(NatRule).filter(NatRule.nat_kind == "central-snat").all():
        r.sequence = 1 if not r.nat_exempt else 2
    db.commit()
    res = compute_path(db, "10.3.0.5", "172.16.5.9", dst_port=443, protocol="tcp")
    assert res["overall"] == "denied"


# =================================================================== B-15 ==
def test_reingest_removes_deleted_interfaces_and_zones(db):
    cfg = """
    config system interface
        edit "port1"
            set ip 10.1.3.1 255.255.255.0
        next
        edit "port2"
            set ip 10.1.5.1 255.255.255.0
        next
        edit "port3"
            set ip 10.1.4.1 255.255.255.0
        next
    end
    config system zone
        edit "UPZ"
            set interface "port2"
        next
    end
    config firewall policy
        edit 1
            set srcintf "port1"
            set dstintf "port3"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
    """
    ingest(db, cfg)
    set_levels(db, "FW-Z", {"port1": 3, "port2": 5, "port3": 4})
    p1 = db.query(FirewallInterface).filter_by(name="port1").one()
    p2 = db.query(FirewallInterface).filter_by(name="port2").one()
    p1.connects_to_interface_id = p2.id
    db.add(PcapCapture(firewall_id=p2.firewall_id, interface_id=p2.id,
                       suggested_interface_id=p2.id, filename="cap.pcap"))
    db.commit()
    assert set(_Context(db).boundary_map) == {(3, 4), (3, 5), (4, 5)}

    without_p2 = cfg.replace('''        edit "port2"
            set ip 10.1.5.1 255.255.255.0
        next
''', "").replace('''        edit "UPZ"
            set interface "port2"
        next
''', "")
    st = ingest(db, without_p2)
    assert st["interfaces_removed"] == 1
    assert {fi.name for fi in db.query(FirewallInterface).all()} == {"port1", "port3"}
    assert {z.interface_name for z in db.query(FirewallZone).all()} == {"port1", "port3"}
    assert db.query(FirewallZoneDef).count() == 0
    p1 = db.query(FirewallInterface).filter_by(name="port1").one()
    assert p1.connects_to_interface_id is None and p1.purdue_level == 3   # kept
    cap = db.query(PcapCapture).one()
    assert cap.interface_id is None and cap.suggested_interface_id is None
    assert cap.capture_interface_raw == "port2"
    # port2's level / subnet no longer feed reachability
    ctx = _Context(db)
    assert set(ctx.boundary_map) == {(3, 4)}
    assert all(n != "port2" for lst in ctx._leveled_ifaces.values() for n, _ in lst)


def test_reingest_vdom_only_config_prunes_only_its_vdom(db):
    ingest(db, VDOM_CFG)
    # a per-VDOM config (no `config global`) for OT without port4
    ot_only = """
    config vdom
        edit "OT"
            config system interface
                edit "port3"
                    set vdom "OT"
                    set ip 10.20.3.1 255.255.255.0
                next
            end
        next
    end
    """
    ingest(db, ot_only)
    assert {fi.name for fi in db.query(FirewallInterface).all()} == {"port1", "port2", "port3"}


def _members(n, base="10.200"):
    return " ".join(f'"h{i}"' for i in range(n)), "\n".join(
        f'        edit "h{i}"\n            set subnet {base}.{i // 250}.{i % 250 + 1} '
        f'255.255.255.255\n        next' for i in range(n))


def test_nat_lists_never_truncated(db):
    n_src, n_dst = 300, 30
    src_members, src_objs = _members(n_src, "10.3")
    dst_members, dst_objs = _members(n_dst, "172.16")
    dst_members = dst_members.replace('"h', '"d')
    dst_objs = dst_objs.replace('"h', '"d')
    cfg = f"""
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
{src_objs}
{dst_objs}
end
config firewall addrgrp
    edit "srcs"
        set member {src_members}
    next
    edit "dsts"
        set member {dst_members}
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set orig-addr "srcs"
        set dst-addr "dsts"
        set nat enable
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    ingest_fortigate_config(cfg, db, firewall_name="FW-N")
    rows = db.query(NatRule).filter(NatRule.nat_kind == "central-snat").all()
    assert len(rows) == n_src                                   # no 256-row cap
    dsts = rows[0].orig_dst.split(",")
    assert len(dsts) == n_dst and len(rows[0].orig_dst) > 255
    assert dsts[-1] == "172.16.0.30/32"                         # last member intact
    assert all(d.endswith("/32") for d in dsts)                 # no mid-token cut


def test_invalid_service_port_ranges_are_unresolved_not_any(db):
    assert _forti_portrange_tokens("70000-80000 abc 90-80 80:abc 502:1024-65535 0-65535") == (
        [(502, 502), (0, 65535)], ["70000-80000", "abc", "90-80", "80:abc"])
    svc = {"BAD": {"protocol": "TCP/UDP/SCTP", "tcp-portrange": "70000-80000"},
           "ABC": {"protocol": "TCP/UDP/SCTP", "tcp-portrange": "abc"},
           "MIX": {"protocol": "TCP/UDP/SCTP", "tcp-portrange": ["502", "99999"]},
           "NONE": {"protocol": "TCP/UDP/SCTP"}}
    stats: dict = {}
    for name in ("BAD", "ABC", "NONE"):
        res = _resolve_service(name, svc, {}, stats=stats)
        assert ("any", "any") not in res
        assert all(p.startswith("unresolved:") for _proto, p in res), res
    assert _resolve_service("MIX", svc, {}) == [("tcp", "502"), ("tcp", "unresolved:invalid-port:MIX")]
    assert stats["services_invalid_ports"] == 3

    cfg = """
    config system interface
        edit "port1"
            set ip 10.1.3.1 255.255.255.0
        next
        edit "port2"
            set ip 10.1.4.1 255.255.255.0
        next
    end
    config firewall service custom
        edit "BAD"
            set tcp-portrange 70000-80000
        next
    end
    config firewall policy
        edit 1
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "BAD"
        next
    end
    """
    ingest(db, cfg, lo=3, hi=4)
    r = db.query(FirewallRule).one()
    assert r.dst_port.startswith("unresolved:") and r.dst_port != "any"
    set_levels(db, "FW-Z", {"port1": 3, "port2": 4})
    H(db, "10.1.3.5", 3)
    H(db, "10.1.4.5", 4)
    db.commit()
    # never a (false) permit for an arbitrary port: unknown
    res = compute_path(db, "10.1.3.5", "10.1.4.5", dst_port=443, protocol="tcp")
    assert res["overall"] == "unknown"


TOKENIZER_CFG = r'''#config-version=FG100F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
#conf_file_ver=12345
config system replacemsg http "url-block"
    set buffer "<HTML><BODY>
<h1>Blocked</h1>
end
next
config firewall policy
    edit 99
        set action accept
</BODY></HTML>"
end
config firewall address
    edit "plc \"main\""
        set subnet 10.20.3.10 255.255.255.255
        set comment "contains \"quotes\" and a backslash \\ end"
    next
end
config firewall policy
    edit 1
        set name "pol \"one\""
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "plc \"main\""
        set action accept
        set schedule "always"
        set service "ALL"
        set comments "multi
line comment with
config firewall policy
end
inside"
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
    edit 3
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


def test_tokenizer_escaped_quotes_and_multiline_values():
    p = parse_forti_block(TOKENIZER_CFG)
    assert list(p["firewall policy"]) == ["1", "2", "3"]          # 99 is buffer text
    pol1 = p["firewall policy"]["1"]
    assert pol1["name"] == 'pol "one"' and pol1["dstaddr"] == 'plc "main"'
    assert pol1["comments"].startswith("multi\nline") and "config firewall policy" in pol1["comments"]
    addr = p["firewall address"]['plc "main"']
    assert addr["comment"] == 'contains "quotes" and a backslash \\ end'
    buf = p["system replacemsg http url-block"]["buffer"]
    assert buf.startswith("<HTML>") and buf.endswith("</HTML>") and "\nend\n" in buf


def test_tokenizer_all_policies_ingested(db):
    st = ingest(db, TOKENIZER_CFG)
    pids = sorted({r.policy_id for r in db.query(FirewallRule).all()})
    assert pids == ["1", "2", "3"]
    r1 = db.query(FirewallRule).filter_by(policy_id="1").one()
    assert r1.dst == "10.20.3.10/32"                          # escaped-quote name resolved
    assert st["unresolved_objects"] == 0


def test_tokenizer_unterminated_quote_does_not_swallow_config():
    p = parse_forti_block('config firewall policy\n edit 1\n  set comments "oops\n  set action deny\n'
                          ' next\n edit 2\n  set action accept\n next\nend\n')
    assert p["firewall policy"]["1"]["action"] == "deny"
    assert p["firewall policy"]["2"]["action"] == "accept"


# =================================================================== B-24 ==
def test_only_valid_unicast_host_objects_become_hosts(db):
    cfg = """
    config firewall address
        edit "ok-host"
            set subnet 10.20.3.10 255.255.255.255
        next
        edit "ok-bare"
            set subnet 10.20.3.11/32
        next
        edit "ok-range1"
            set type iprange
            set start-ip 10.20.3.12
            set end-ip 10.20.3.12
        next
        edit "bad-name"
            set subnet foo/32
        next
        edit "bad-octet"
            set subnet 999.1.1.1 255.255.255.255
        next
        edit "unspec"
            set subnet 0.0.0.0 255.255.255.255
        next
        edit "mcast"
            set subnet 224.0.0.5 255.255.255.255
        next
        edit "bcast"
            set subnet 255.255.255.255 255.255.255.255
        next
        edit "loop"
            set subnet 127.0.0.1 255.255.255.255
        next
        edit "net"
            set subnet 10.20.3.0 255.255.255.0
        next
        edit "range"
            set type iprange
            set start-ip 10.20.3.20
            set end-ip 10.20.3.30
        next
        edit "all"
        next
    end
    config firewall address6
        edit "v6-host"
            set ip6 2001:db8::10/128
        next
        edit "v6-net"
            set ip6 2001:db8::/64
        next
        edit "v6-mcast"
            set ip6 ff02::1/128
        next
    end
    """
    st = ingest(db, cfg)
    ips = sorted(h.ip for h in db.query(Host).all())
    assert ips == sorted(["10.20.3.10", "10.20.3.11", "10.20.3.12", "2001:db8::10"])
    assert st["hosts_created"] == 4


@pytest.mark.parametrize("cfg", [None, "x", {"subnet": ["1.2.3.4", "255.255.255.256"]},
                                 {"type": "iprange", "start-ip": "1.1.1.1"},
                                 {"ip6": "zz::1/128"}, {"subnet": {"nested": 1}}])
def test_host_ip_helper_never_raises(cfg):
    assert _address_object_host_ip(cfg) is None
