"""
Tier-1 regression tests for app/parsers/reachability.py (T1-30 .. T1-33)
and the shared port/address helpers in app/parsers/rule_match.py.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    Base, Firewall, FirewallDevice, FirewallInterface, FirewallRule, FirewallZone, Host,
)
from app.parsers import rule_match as rm
from app.parsers.reachability import compute_path, compute_reachability


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _fw(db, name, zf, zt, firewall_id=None):
    d = FirewallDevice(name=name, vendor="fortigate", purdue_zone_from=zf,
                       purdue_zone_to=zt, firewall_id=firewall_id)
    db.add(d)
    db.flush()
    return d


_order = {"n": 0}


def _rule(db, fw, action, src="any", dst="any", protocol="any", dst_port=None,
          rule_order=None, src_zone=None, dst_zone=None, firewall_id=None):
    _order["n"] += 1
    r = FirewallRule(
        firewall_device_id=fw.id if fw is not None else None,
        firewall_id=firewall_id if firewall_id is not None else getattr(fw, "firewall_id", None),
        device_name=fw.name if fw is not None else "x",
        device_type="fortigate", src=src, dst=dst, protocol=protocol,
        dst_port=dst_port, action=action,
        rule_order=rule_order if rule_order is not None else _order["n"],
        src_zone=src_zone, dst_zone=dst_zone,
    )
    db.add(r)
    db.flush()
    return r


def _cell(db, s, d, **kw):
    return compute_reachability(db, src_level=s, dst_level=d, **kw)["matrix"][f"{s}→{d}"]


def _eps(cell):
    return [ep for p in cell["paths"] for h in p["hops"] for ep in h["enforcement_points"]]


# ------------------------------------------------------------------ T1-30

def test_two_firewalls_permit_plus_no_match_is_denied(db):
    fw43 = _fw(db, "fw43", 4, 3)
    fw32 = _fw(db, "fw32", 3, 2)
    _rule(db, fw43, "permit")
    _rule(db, fw32, "permit", protocol="tcp", dst_port="22")
    db.commit()
    cell = _cell(db, 4, 2, src_ip="10.4.0.5", dst_ip="10.2.0.5", dst_port=502, protocol="tcp")
    assert cell["overall"] == "denied"
    fw32_eval = [e for e in _eps(cell) if e["firewall_device"]["name"] == "fw32"][0]
    assert fw32_eval["decision"] == "deny"
    assert fw32_eval["reason_code"] == "implicit_deny"
    assert fw32_eval["implicit_deny"] is True


def test_two_firewalls_level_query_permit_plus_only_deny_is_denied(db):
    fw43 = _fw(db, "fw43", 4, 3)
    fw32 = _fw(db, "fw32", 3, 2)
    _rule(db, fw43, "permit")
    _rule(db, fw32, "deny", protocol="tcp", dst_port="23")
    db.commit()
    assert _cell(db, 4, 2)["overall"] == "denied"


def test_single_firewall_no_match_is_denied(db):
    fw = _fw(db, "fw1", 3, 2)
    _rule(db, fw, "permit", protocol="tcp", dst_port="443")
    db.commit()
    cell = _cell(db, 3, 2, dst_port=80, protocol="tcp")
    assert cell["overall"] == "denied"
    ep = _eps(cell)[0]
    assert ep["reason_code"] == "implicit_deny"


def test_zero_rules_is_no_policy(db):
    _fw(db, "fw1", 3, 2)
    db.commit()
    cell = _cell(db, 3, 2)
    assert cell["overall"] == "no_policy"
    assert _eps(cell)[0]["reason_code"] == "no_rules_loaded"


def test_permit_plus_unloaded_device_on_same_boundary_is_an_alternative(db):
    # MP-01: an undeclared second box on the same boundary is an alternative
    # path, so fwA's permit stands; the unloaded box is still reported.
    a = _fw(db, "fwA", 3, 2)
    _fw(db, "fwB", 3, 2)
    _rule(db, a, "permit")
    db.commit()
    cell = _cell(db, 3, 2)
    assert cell["overall"] == "permitted"
    hop = cell["paths"][0]["hops"][0]
    assert hop["arrangement"] == "parallel"
    assert {e["firewall_device"]["name"]: e["reason_code"] for e in hop["enforcement_points"]} == \
        {"fwA": "matched_rule", "fwB": "no_rules_loaded"}


# ------------------------------------------------------------------ T1-31

def test_deny_telnet_then_permit_any(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "deny", protocol="tcp", dst_port="23")
    _rule(db, fw, "permit")
    db.commit()
    cell = _cell(db, 4, 3)
    assert cell["overall"] == "permitted"
    assert cell["denied_services"] == ["tcp/23"]
    assert _cell(db, 4, 3, dst_port=23, protocol="tcp")["overall"] == "denied"
    assert _cell(db, 4, 3, dst_port=22, protocol="tcp")["overall"] == "permitted"
    assert _cell(db, 4, 3, dst_port=23, protocol="udp")["overall"] == "permitted"


def test_lone_permit_443_is_partial(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port="443")
    db.commit()
    cell = _cell(db, 4, 3)
    assert cell["overall"] == "partial"
    assert cell["permitted_services"] == ["tcp/443"]
    ep = _eps(cell)[0]
    assert ep["decision"] == "partial"
    assert ep["permitted_services"] == ["tcp/443"]
    assert ep["implicit_deny"] is True
    assert _cell(db, 4, 3, dst_port=443, protocol="tcp")["overall"] == "permitted"
    assert _cell(db, 4, 3, dst_port=443, protocol="udp")["overall"] == "denied"
    assert _cell(db, 4, 3, dst_port=80, protocol="tcp")["overall"] == "denied"


def test_specific_permit_then_explicit_deny_all_is_partial(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port="502")
    _rule(db, fw, "deny")
    db.commit()
    cell = _cell(db, 4, 3)
    assert cell["overall"] == "partial"
    assert cell["permitted_services"] == ["tcp/502"]


def test_permit_shadowed_by_earlier_specific_deny_not_listed(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "deny", protocol="tcp", dst_port="443")
    _rule(db, fw, "permit", protocol="tcp", dst_port="443")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "denied"


def test_partial_intersection_across_hops(db):
    a = _fw(db, "fw43", 4, 3)
    b = _fw(db, "fw32", 3, 2)
    _rule(db, a, "permit", protocol="tcp", dst_port="443,502")
    _rule(db, b, "permit", protocol="tcp", dst_port="502")
    db.commit()
    cell = _cell(db, 4, 2)
    assert cell["overall"] == "partial"
    assert cell["permitted_services"] == ["tcp/502"]


def test_canonical_port_list_matching(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port="80,443,1000-2000")
    db.commit()
    for port, expected in [(80, "permitted"), (443, "permitted"), (1000, "permitted"),
                           (1500, "permitted"), (2000, "permitted"), (2001, "denied"),
                           (22, "denied"), (444, "denied")]:
        assert _cell(db, 4, 3, dst_port=port, protocol="tcp")["overall"] == expected, port
    assert _cell(db, 4, 3)["permitted_services"] == ["tcp/80,443,1000-2000"]


@pytest.mark.parametrize("legacy,port,expected", [
    ("eq 22", 22, "permitted"),
    ("eq 22", 23, "denied"),
    ("range 1 1024", 1024, "permitted"),
    ("gt 1023", 1024, "permitted"),
    ("gt 1023", 80, "denied"),
    ("['502', '102']", 102, "permitted"),
    ("502:1024-65535", 502, "permitted"),
    ("502:1024-65535", 2000, "denied"),
])
def test_legacy_port_forms(db, legacy, port, expected):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port=legacy)
    db.commit()
    assert _cell(db, 4, 3, dst_port=port, protocol="tcp")["overall"] == expected


@pytest.mark.parametrize("raw", ["unknown:SVC_X", "alias:WEB_PORTS"])
def test_unresolved_service_never_any(db, raw):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port=raw)
    db.commit()
    cell = _cell(db, 4, 3, dst_port=443, protocol="tcp")
    # A-04: an unresolved-service permit may match the port -> unknown, never
    # a fail-closed "denied" (and never "permitted").
    assert cell["overall"] == "unknown"
    ep = _eps(cell)[0]
    assert ep["unresolved_rules"] and ep["unresolved_rules"][0]["unresolved"] == "service"
    # Without a port the unresolved permit is partial, never "permitted"
    nop = _cell(db, 4, 3)
    assert nop["overall"] == "partial"
    assert any(raw in s for s in nop["permitted_services"])


def test_port_query_without_protocol_is_partial_for_tcp_rule(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port="502")
    db.commit()
    cell = _cell(db, 4, 3, dst_port=502)
    assert cell["overall"] == "partial"
    assert cell["permitted_services"] == ["tcp/502"]


# ------------------------------------------------------------------ T1-32

def _zoned_fw(db):
    fwm = Firewall(name="fg1", device_name="fg1", vendor="fortigate")
    db.add(fwm)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=fwm.id, name="port1", zone_label="IT",
                          network_cidr="10.4.0.0/24", purdue_level=4),
        FirewallInterface(firewall_id=fwm.id, name="port2", zone_label="OT",
                          network_cidr="10.3.0.0/24", purdue_level=3),
    ])
    dev = _fw(db, "fg1", 4, 3, firewall_id=fwm.id)
    return fwm, dev


def test_direction_zone_label(db):
    _, dev = _zoned_fw(db)
    _rule(db, dev, "permit", src_zone="IT", dst_zone="OT")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    back = _cell(db, 3, 4)
    assert back["overall"] == "denied"
    ep = _eps(back)[0]
    assert ep["reason_code"] == "implicit_deny"
    assert ep["rules_skipped_direction"] == 1


def test_direction_interface_name_and_zone_membership(db):
    _, dev = _zoned_fw(db)
    db.add(FirewallZone(device_name="fg1", interface_name="port2", zone_name="OT_ZONE"))
    _rule(db, dev, "permit", src_zone="port1", dst_zone="OT_ZONE")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 3, 4)["overall"] == "denied"


def test_direction_zone_list_covers_both(db):
    _, dev = _zoned_fw(db)
    _rule(db, dev, "permit", src_zone="IT, OT", dst_zone="OT IT")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 3, 4)["overall"] == "permitted"


def test_direction_from_address_cidr(db):
    _, dev = _zoned_fw(db)
    _rule(db, dev, "permit", src="10.4.0.0/24", dst="10.3.0.0/24")
    db.commit()
    fwd = _cell(db, 4, 3)
    assert fwd["overall"] == "partial"  # host-restricted permit
    assert _cell(db, 3, 4)["overall"] == "denied"
    assert _cell(db, 4, 3, src_ip="10.4.0.9", dst_ip="10.3.0.9")["overall"] == "permitted"


def test_any_any_rule_still_bidirectional(db):
    _, dev = _zoned_fw(db)
    _rule(db, dev, "permit", src_zone="any", dst_zone="any")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 3, 4)["overall"] == "permitted"


def test_unmapped_zone_still_bidirectional(db):
    fw = _fw(db, "legacy", 4, 3)
    _rule(db, fw, "permit", src_zone="trust", dst_zone="untrust")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 3, 4)["overall"] == "permitted"


def test_firewall_model_only_device_is_enforcement_point(db):
    fwm = Firewall(name="fg-new", vendor="fortigate",
                   purdue_level_ingress=4, purdue_level_egress=3)
    db.add(fwm)
    db.flush()
    db.add(FirewallRule(firewall_id=fwm.id, device_name="fg-new", device_type="fortigate",
                        src="any", dst="any", protocol="any", action="deny", rule_order=1))
    db.commit()
    cell = _cell(db, 4, 3)
    assert cell["overall"] == "denied"
    assert _eps(cell)[0]["firewall_device"]["source"] == "firewall"


def test_device_linked_to_firewall_levels(db):
    fwm = Firewall(name="fg2", vendor="fortigate", purdue_level_ingress=4, purdue_level_egress=3)
    db.add(fwm)
    db.flush()
    dev = _fw(db, "fg2", None, None, firewall_id=fwm.id)
    _rule(db, dev, "deny")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "denied"


# ------------------------------------------------------------------ T1-33

def test_ipv6_rule_does_not_block_ipv4_evaluation(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "deny", src="2001:db8::/32", dst="any")
    _rule(db, fw, "permit")
    db.commit()
    cell = _cell(db, 4, 3, src_ip="10.4.0.1", dst_ip="10.3.0.1")
    assert cell["overall"] == "permitted"


def test_ipv6_permit_does_not_permit_ipv4(db):
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", src="::/0", dst="::/0")
    db.commit()
    assert _cell(db, 4, 3, src_ip="10.4.0.1", dst_ip="10.3.0.1")["overall"] == "denied"


# ------------------------------------------------------------------ compute_path

def test_compute_path_partial_and_implicit_deny(db):
    db.add_all([Host(ip="10.4.0.1", purdue_level=4, sources=["t"]),
                Host(ip="10.3.0.1", purdue_level=3, sources=["t"])])
    fw = _fw(db, "fw1", 4, 3)
    _rule(db, fw, "permit", protocol="tcp", dst_port="443")
    db.commit()
    res = compute_path(db, src_ip="10.4.0.1", dst_ip="10.3.0.1")
    assert res["overall"] == "partial"
    assert res["permitted_services"] == ["tcp/443"]
    res = compute_path(db, src_ip="10.4.0.1", dst_ip="10.3.0.1", dst_port=80, protocol="tcp")
    assert res["overall"] == "denied"
    assert res["hops"][0]["enforcement_points"][0]["reason_code"] == "implicit_deny"


# ------------------------------------------------------------------ rule_match unit

@pytest.mark.parametrize("raw,expected", [
    ("any", rm.ANY), (None, rm.ANY), ("22", ((22, 22),)), ("80,443", ((80, 80), (443, 443))),
    ("1-1024", ((1, 1024),)), ("80,443,1000-2000", ((80, 80), (443, 443), (1000, 2000))),
    ("eq 22", ((22, 22),)), ("range 1 1024", ((1, 1024),)), ("gt 1023", ((1024, 65535),)),
    ("['502', '102']", ((102, 102), (502, 502))), ("502:1024-65535", ((502, 502),)),
    ("0-65535", rm.ANY),
])
def test_parse_ports(raw, expected):
    assert rm.parse_ports(raw) == expected


@pytest.mark.parametrize("raw", ["unknown:NAME", "alias:NAME", "unresolved:X", "www"])
def test_parse_ports_unresolved(raw):
    assert isinstance(rm.parse_ports(raw), rm.Unresolved)


def test_range_ops():
    assert rm.ranges_subtract(((1, 100),), ((10, 20),)) == ((1, 9), (21, 100))
    assert rm.ports_contain(((1, 1024),), ((22, 22), (80, 80))) is True
    assert rm.ports_contain(((80, 80),), rm.ANY) is False
    assert rm.addr_contains(rm.parse_address("10.0.0.0/8"),
                            rm.parse_address("2001:db8::/32")) is False


# ------------------------------------------------------------------ multi-leg firewall

def _multi_leg_site(db, with_device=True):
    """One FortiGate, three legs: port1=L1 (OT), port2=L3 (DMZ), port3=L4 (IT);
    no explicit ingress/egress anywhere."""
    fwm = Firewall(name="site-fg", device_name="site-fg", vendor="fortigate")
    db.add(fwm)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=fwm.id, name="port1", network_cidr="10.1.0.0/24", purdue_level=1),
        FirewallInterface(firewall_id=fwm.id, name="port2", network_cidr="10.3.0.0/24", purdue_level=3),
        FirewallInterface(firewall_id=fwm.id, name="port3", network_cidr="10.4.0.0/24", purdue_level=4),
        FirewallZone(device_name="site-fg", interface_name="port1", zone_name="OT_ZONE"),
        FirewallZone(device_name="site-fg", interface_name="port2", zone_name="DMZ_ZONE"),
        FirewallZone(device_name="site-fg", interface_name="port3", zone_name="IT_ZONE"),
    ])
    dev = _fw(db, "site-fg", None, None, firewall_id=fwm.id) if with_device else None
    for order, (sz, dz, proto, port, action) in enumerate([
        ("IT_ZONE", "OT_ZONE", "any", None, "deny"),
        ("DMZ_ZONE", "OT_ZONE", "tcp", "22", "permit"),
        ("OT_ZONE", "DMZ_ZONE", "tcp", "443", "permit"),
    ], start=1):
        db.add(FirewallRule(
            firewall_id=fwm.id, firewall_device_id=dev.id if dev else None,
            device_name="site-fg", device_type="fortigate", src="any", dst="any",
            protocol=proto, dst_port=port, action=action, rule_order=order,
            src_zone=sz, dst_zone=dz,
        ))
    db.commit()
    return fwm


@pytest.mark.parametrize("with_device", [True, False])
def test_multi_leg_firewall(db, with_device):
    _multi_leg_site(db, with_device)
    c41 = _cell(db, 4, 1)
    assert c41["overall"] == "denied"
    assert len(c41["paths"]) == 1 and len(c41["paths"][0]["hops"]) == 1  # crossed once
    assert _eps(c41)[0]["reason_code"] == "matched_rule"
    assert _eps(c41)[0]["firewall_device"]["multi_leg"] is True

    c31 = _cell(db, 3, 1)
    assert c31["overall"] == "partial" and c31["permitted_services"] == ["tcp/22"]
    c13 = _cell(db, 1, 3)
    assert c13["overall"] == "partial" and c13["permitted_services"] == ["tcp/443"]
    c14 = _cell(db, 1, 4)
    assert c14["overall"] == "denied"
    assert _eps(c14)[0]["reason_code"] == "implicit_deny"
    # 4→3 and 3→4 have no applicable rule → implicit deny, never via itself twice
    for s, d in [(4, 3), (3, 4), (1, 4), (4, 1)]:
        for p in _cell(db, s, d)["paths"]:
            assert len(p["hops"]) == 1


def test_multi_leg_labelled_interfaces_widen_explicit_boundary(db):
    """P-01 (NAT tabletop): the explicit upload boundary (4/3) no longer
    clamps a firewall whose interfaces the operator labelled at more levels
    (L1 / L3 / L4): one enforcement point per labelled level pair, so the
    L1 leg is modelled and IT -> OT hits the IT_ZONE -> OT_ZONE deny."""
    fwm = _multi_leg_site(db)
    fwm.purdue_level_ingress, fwm.purdue_level_egress = 4, 3
    db.commit()
    res = compute_reachability(db)
    assert sorted(e["boundary"] for e in res["enforcement_points"]) == ["1↔3", "1↔4", "3↔4"]
    assert res["matrix"]["4→1"]["overall"] == "denied"
    assert res["matrix"]["3→1"]["overall"] in ("permitted", "partial")


def test_explicit_boundary_wins_over_its_own_levels(db):
    """Labels at the boundary's own two levels change nothing."""
    fwm = _multi_leg_site(db)
    fwm.purdue_level_ingress, fwm.purdue_level_egress = 4, 3
    db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fwm.id,
                                       FirewallInterface.name == "port1").one().purdue_level = None
    db.commit()
    res = compute_reachability(db)
    assert [e["boundary"] for e in res["enforcement_points"]] == ["3↔4"]


def test_two_leg_interface_firewall_behaves_like_boundary(db):
    _, dev = _zoned_fw(db)          # explicit 4/3
    _rule(db, dev, "permit", src_zone="IT", dst_zone="OT")
    fwm2 = Firewall(name="fg-2leg", device_name="fg-2leg", vendor="fortigate")
    db.add(fwm2)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=fwm2.id, name="a", zone_label="OT", purdue_level=3),
        FirewallInterface(firewall_id=fwm2.id, name="b", zone_label="CELL", purdue_level=2),
    ])
    db.add(FirewallRule(firewall_id=fwm2.id, device_name="fg-2leg", device_type="fortigate",
                        src="any", dst="any", protocol="any", action="permit",
                        rule_order=1, src_zone="OT", dst_zone="CELL"))
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 3, 4)["overall"] == "denied"
    assert _cell(db, 3, 2)["overall"] == "permitted"
    assert _cell(db, 2, 3)["overall"] == "denied"
    assert _cell(db, 4, 2)["overall"] == "permitted"   # two boxes, two hops
    assert len(_cell(db, 4, 2)["paths"][0]["hops"]) == 2
