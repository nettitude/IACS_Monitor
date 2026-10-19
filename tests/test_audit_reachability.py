"""Regression tests for audit findings A-04, A-05, A-06 (reachability
"false sense of safety": denied / no traffic where traffic is permitted or
unknown)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (Base, Firewall, FirewallDevice, FirewallInterface,
                        FirewallRule, Host, NatRule)
from app.parsers import rule_match as rm
from app.parsers.reachability import compute_path, compute_reachability


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


_n = [0]


def R(db, fw, action, src="any", dst="any", protocol="any", dst_port=None, fid=None):
    _n[0] += 1
    r = FirewallRule(firewall_device_id=fw.id, firewall_id=fid or fw.firewall_id,
                     device_name="x", device_type="fortigate", src=src, dst=dst,
                     protocol=protocol, dst_port=dst_port, action=action, rule_order=_n[0])
    db.add(r)
    db.flush()
    return r


def H(db, ip, lvl):
    db.add(Host(ip=ip, purdue_level=lvl))
    db.flush()


def fw43(db):
    fw = FirewallDevice(name="f", vendor="fortigate", purdue_zone_from=4, purdue_zone_to=3)
    db.add(fw)
    db.flush()
    H(db, "10.4.0.5", 4)
    H(db, "10.3.0.5", 3)
    return fw


def path(db, **kw):
    return compute_path(db, "10.4.0.5", "10.3.0.5", **kw)["overall"]


def cell(db, s, d, **kw):
    return compute_reachability(db, src_level=s, dst_level=d, **kw)["matrix"][f"{s}→{d}"]["overall"]


# --------------------------------------------------------------------- A-04
@pytest.mark.parametrize("svc", ["alias:MODBUS", "unknown:MODBUS", "too-large:BIG_GRP"])
def test_a04_unresolved_service_permit_port_query_is_unknown(db, svc):
    fw = fw43(db)
    R(db, fw, "permit", protocol="tcp", dst_port=svc)
    db.commit()
    assert path(db, dst_port=502, protocol="tcp") == "unknown"
    assert cell(db, 4, 3, dst_port=502, protocol="tcp") == "unknown"


def test_a04_too_large_token_is_unresolved():
    assert isinstance(rm.parse_ports("too-large:GRP"), rm.Unresolved)
    assert isinstance(rm.parse_address("too-large:GRP"), rm.Unresolved)


def test_a04_unresolved_service_deny_before_permit_any_is_unknown(db):
    fw = fw43(db)
    R(db, fw, "deny", protocol="tcp", dst_port="alias:BAD")
    R(db, fw, "permit")
    db.commit()
    assert path(db, dst_port=502, protocol="tcp") == "unknown"
    assert path(db) == "unknown"
    assert cell(db, 4, 3, dst_port=502, protocol="tcp") == "unknown"
    assert cell(db, 4, 3) == "unknown"


def test_a04_unresolved_deny_before_specific_permit_is_unknown(db):
    fw = fw43(db)
    R(db, fw, "deny", protocol="tcp", dst_port="alias:BAD")
    R(db, fw, "permit", protocol="tcp", dst_port="502")
    db.commit()
    assert cell(db, 4, 3) == "unknown"


def test_a04_unresolved_address_and_service_no_port_is_unknown(db):
    fw = fw43(db)
    R(db, fw, "permit", src="addrgrp_X", protocol="tcp", dst_port="alias:S")
    db.commit()
    assert path(db) == "unknown"
    assert cell(db, 4, 3) == "unknown"


def test_a04_ordinary_verdicts_unchanged(db):
    fw = fw43(db)
    R(db, fw, "deny", protocol="tcp", dst_port="23")
    R(db, fw, "permit", protocol="tcp", dst_port="502")
    db.commit()
    assert path(db, dst_port=502, protocol="tcp") == "permitted"
    assert path(db, dst_port=23, protocol="tcp") == "denied"
    assert path(db, dst_port=80, protocol="tcp") == "denied"
    assert cell(db, 4, 3) == "partial"


def test_a04_resolved_deny_still_beats_later_unresolved(db):
    fw = fw43(db)
    R(db, fw, "deny")
    R(db, fw, "permit", protocol="tcp", dst_port="alias:X")
    db.commit()
    assert path(db, dst_port=502, protocol="tcp") == "denied"


def test_a04_unresolved_permit_without_port_stays_partial(db):
    fw = fw43(db)
    R(db, fw, "permit", protocol="tcp", dst_port="alias:X")
    db.commit()
    assert cell(db, 4, 3) == "partial"


# --------------------------------------------------------------------- A-05
def _pan(db, vendor="panos", dst="10.4.0.100/32"):
    f = Firewall(name="pa", vendor=vendor)
    db.add(f)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=f.id, name="outside", network_cidr="10.4.0.0/24", purdue_level=4),
        FirewallInterface(firewall_id=f.id, name="inside", network_cidr="10.1.0.0/24", purdue_level=1)])
    fw = FirewallDevice(name="pa", vendor=vendor, firewall_id=f.id)
    db.add(fw)
    db.flush()
    f.purdue_level_ingress, f.purdue_level_egress = 4, 1
    R(db, fw, "allow", dst=dst, protocol="tcp", dst_port="502", fid=f.id)
    db.add(NatRule(firewall_id=f.id, firewall_device_id=fw.id, nat_type="dnat",
                   ext_ip="10.4.0.100", mapped_ip="10.1.0.10", protocol="tcp",
                   ext_port="502", mapped_port="502", enabled=True))
    H(db, "10.4.0.5", 4)
    H(db, "10.1.0.10", 1)
    db.commit()
    return fw


@pytest.mark.parametrize("vendor", ["panos", "cisco_ios"])
def test_a05_prenat_port_forward_into_l1(db, vendor):
    _pan(db, vendor)
    r = compute_path(db, "10.4.0.5", "10.4.0.100", dst_port=502, protocol="tcp")
    assert r["overall"] == "permitted"
    ep = r["hops"][0]["enforcement_points"][0]
    assert ep["rules_skipped_direction"] == 0
    assert cell(db, 4, 1) == "partial"
    assert cell(db, 4, 1, dst_port=502, protocol="tcp") == "partial"
    # reverse direction (L1 -> L4) is not opened by the port forward
    assert cell(db, 1, 4) == "denied"


def test_a05_postnat_vendor_unchanged(db):
    # FortiOS matches post-NAT: a rule naming the VIP stays an outside-side rule
    _pan(db, "fortigate")
    assert cell(db, 4, 1) == "denied"


# --------------------------------------------------------------------- A-06
def _snat_chain(db, b_src="10.3.0.1/32"):
    fa, fb = Firewall(name="A", vendor="fortigate"), Firewall(name="B", vendor="fortigate")
    db.add_all([fa, fb])
    db.flush()
    a = FirewallDevice(name="A", vendor="fortigate", purdue_zone_from=4, purdue_zone_to=3, firewall_id=fa.id)
    b = FirewallDevice(name="B", vendor="fortigate", purdue_zone_from=3, purdue_zone_to=2, firewall_id=fb.id)
    db.add_all([a, b])
    db.flush()
    R(db, a, "accept", src="10.4.0.0/24", dst="10.2.0.0/24", fid=fa.id)
    R(db, b, "accept", src=b_src, dst="10.2.0.0/24", fid=fb.id)
    db.add(NatRule(firewall_id=fa.id, firewall_device_id=a.id, nat_type="snat",
                   orig_src="10.4.0.0/24", mapped_ip="10.3.0.1", enabled=True))
    H(db, "10.4.0.5", 4)
    H(db, "10.2.0.5", 2)
    db.commit()


def test_a06_matrix_follows_snat(db):
    _snat_chain(db)
    assert compute_path(db, "10.4.0.5", "10.2.0.5")["overall"] == "permitted"
    m = compute_reachability(db, src_level=4, dst_level=2)["matrix"]["4→2"]
    assert m["overall"] == "partial"
    scopes = m["paths"][0]["permitted_scopes"]
    assert scopes and scopes[0]["src"].startswith("10.4.0.0")  # original source reported


def test_a06_matrix_snat_still_denied_when_downstream_blocks(db):
    _snat_chain(db, b_src="10.3.0.99/32")
    assert compute_path(db, "10.4.0.5", "10.2.0.5")["overall"] == "denied"
    assert cell(db, 4, 2) == "denied"


def test_a06_matrix_follows_dnat(db):
    # fw A (4<->3) permits to VIP 10.3.0.100 which it DNATs to 10.2.0.5;
    # fw B (3<->2) permits only to the real 10.2.0.5.
    fa, fb = Firewall(name="A", vendor="panos"), Firewall(name="B", vendor="fortigate")
    db.add_all([fa, fb])
    db.flush()
    a = FirewallDevice(name="A", vendor="panos", purdue_zone_from=4, purdue_zone_to=3, firewall_id=fa.id)
    b = FirewallDevice(name="B", vendor="fortigate", purdue_zone_from=3, purdue_zone_to=2, firewall_id=fb.id)
    db.add_all([a, b])
    db.flush()
    R(db, a, "accept", dst="10.3.0.100/32", fid=fa.id)
    R(db, b, "accept", dst="10.2.0.5/32", fid=fb.id)
    db.add(NatRule(firewall_id=fa.id, firewall_device_id=a.id, nat_type="dnat",
                   ext_ip="10.3.0.100", mapped_ip="10.2.0.5", enabled=True))
    H(db, "10.4.0.5", 4)
    H(db, "10.2.0.5", 2)
    db.commit()
    assert compute_path(db, "10.4.0.5", "10.3.0.100")["overall"] == "permitted"
    assert cell(db, 4, 2) == "partial"


def test_a06_no_nat_matrix_unchanged(db):
    fa, fb = Firewall(name="A", vendor="fortigate"), Firewall(name="B", vendor="fortigate")
    db.add_all([fa, fb])
    db.flush()
    a = FirewallDevice(name="A", vendor="fortigate", purdue_zone_from=4, purdue_zone_to=3, firewall_id=fa.id)
    b = FirewallDevice(name="B", vendor="fortigate", purdue_zone_from=3, purdue_zone_to=2, firewall_id=fb.id)
    db.add_all([a, b])
    db.flush()
    R(db, a, "accept", src="10.4.0.0/24", fid=fa.id)
    R(db, b, "accept", src="10.3.0.1/32", fid=fb.id)
    db.commit()
    assert cell(db, 4, 2) == "denied"
    R(db, b, "accept", fid=fb.id)
    db.commit()
    assert cell(db, 4, 2) == "partial"
