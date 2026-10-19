"""
Audit 2026-10-01 regression tests: A-24 (topology_diff fallback scoping and
last_matched stamping), A-25 (unfirewalled adjacency in reachability path
finding), A-31 (union-coverage shadow analysis, same-order rows, index).
"""
import ipaddress
import random
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    Base, Firewall, FirewallDevice, FirewallInterface, FirewallRule, Host, NetworkSession,
)
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.topology_diff import compute_diff


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


_n = {"order": 0, "sport": 41000}
SEEN = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def _dev(db, name, zf=None, zt=None, firewall_id=None):
    d = FirewallDevice(name=name, vendor="fortigate", purdue_zone_from=zf, purdue_zone_to=zt,
                       firewall_id=firewall_id)
    db.add(d)
    db.flush()
    return d


def _rule(db, dev, action="permit", src="any", dst="any", protocol="any", dst_port=None,
          rule_order=None, firewall_id=None):
    _n["order"] += 1
    r = FirewallRule(firewall_device_id=dev.id if dev else None, firewall_id=firewall_id,
                     device_name=dev.name if dev else "fw", device_type="fortigate",
                     src=src, dst=dst, protocol=protocol, dst_port=dst_port, action=action,
                     rule_order=rule_order if rule_order is not None else _n["order"])
    db.add(r)
    db.flush()
    return r


def _host(db, ip, level=None):
    h = Host(ip=ip, purdue_level=level)
    db.add(h)
    db.flush()
    return h


def _sess(db, src, dst, dst_port=502, transport="tcp"):
    _n["sport"] += 1
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, src_port=_n["sport"],
                       dst_port=dst_port, transport=transport, protocol="modbus",
                       last_seen=SEEN)
    db.add(s)
    db.flush()
    return s


# ============================================================ A-24 (a) fallback

def test_unrelated_any_permit_does_not_explain_session(db):
    fw = _dev(db, "unrelated")                     # no boundary, no interfaces
    _rule(db, fw, "permit")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    r = compute_diff(db)
    assert len(r["unexpected_traffic"]) == 1
    e = r["unexpected_traffic"][0]
    assert e["reason_code"] == "no_enforcement_point_known"
    assert e["policy_mismatch"] is False
    assert r["sessions_no_enforcement_point"] == 1


def test_unrelated_any_deny_is_not_a_policy_mismatch(db):
    fw = _dev(db, "unrelated")
    _rule(db, fw, "deny")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    e = compute_diff(db)["unexpected_traffic"][0]
    assert e["reason_code"] == "no_enforcement_point_known"


def test_firewall_with_interface_on_session_subnet_explains(db):
    f = Firewall(name="edge", vendor="fortigate")
    db.add(f)
    db.flush()
    db.add(FirewallInterface(firewall_id=f.id, name="lan", network_cidr="10.2.0.0/24"))
    fw = _dev(db, "edge", firewall_id=f.id)
    _rule(db, fw, "permit")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    assert compute_diff(db)["unexpected_traffic"] == []


def test_interface_carrier_with_no_match_is_no_matching_permit(db):
    f = Firewall(name="edge", vendor="fortigate")
    db.add(f)
    db.flush()
    db.add(FirewallInterface(firewall_id=f.id, name="lan", network_cidr="10.2.0.0/24"))
    fw = _dev(db, "edge", firewall_id=f.id)
    _rule(db, fw, "permit", protocol="udp")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    e = compute_diff(db)["unexpected_traffic"][0]
    assert e["reason_code"] == "no_matching_permit"


def test_specific_rule_on_any_firewall_still_explains(db):
    fw = _dev(db, "fw")
    _rule(db, fw, "permit", src="10.2.0.5/32", protocol="tcp", dst_port="502")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    assert compute_diff(db)["unexpected_traffic"] == []


# ============================================================ A-24 (b) last_matched

def test_last_matched_only_on_chosen_path(db):
    direct = _dev(db, "fw42", 4, 2)
    a = _dev(db, "fw43", 4, 3)
    b = _dev(db, "fw32", 3, 2)
    r_direct = _rule(db, direct, "permit")
    r_a = _rule(db, a, "permit")
    r_b = _rule(db, b, "permit")
    _sess(db, _host(db, "10.4.0.5", 4), _host(db, "10.2.0.5", 2))
    db.commit()
    r = compute_diff(db)
    assert r["unexpected_traffic"] == []
    db.refresh(r_direct), db.refresh(r_a), db.refresh(r_b)
    assert r_direct.last_matched is not None
    assert r_a.last_matched is None and r_b.last_matched is None


def test_last_matched_partial_stamps_first_match_only(db):
    fw = _dev(db, "fw21", 2, 1)
    first = _rule(db, fw, "permit", protocol="tcp", dst_port="502")
    second = _rule(db, fw, "permit", protocol="tcp", dst_port="503")
    _sess(db, _host(db, "10.2.0.5", 2), _host(db, "10.1.0.9", 1), dst_port=None)
    db.commit()
    r = compute_diff(db)
    assert r["unexpected_traffic"] == []
    db.refresh(first), db.refresh(second)
    assert first.last_matched is not None
    assert second.last_matched is None


# ============================================================ A-25 flat segments

def test_flat_l2_behind_l3_firewall_permits(db):
    fw = _dev(db, "f", 4, 3)
    _rule(db, fw, "permit")
    _host(db, "10.4.0.5", 4), _host(db, "10.2.0.5", 2)
    db.commit()
    p = compute_path(db, "10.4.0.5", "10.2.0.5")
    assert p["overall"] == "permitted"
    assert [h["boundary"] for h in p["hops"]] == ["3↔4"]
    assert p["inferred_adjacency"][0]["a"] == 2 and p["inferred_adjacency"][0]["b"] == 3
    c = compute_reachability(db, src_level=4, dst_level=2)["matrix"]["4→2"]
    assert c["overall"] == "permitted"
    # reverse direction enters the firewall on its L3 side
    p2 = compute_path(db, "10.2.0.5", "10.4.0.5")
    assert p2["overall"] == "permitted"
    assert (p2["hops"][0]["from_level"], p2["hops"][0]["to_level"]) == (3, 4)


def test_flat_guess_never_reports_denied(db):
    fw = _dev(db, "f", 4, 3)
    _rule(db, fw, "deny")
    _host(db, "10.4.0.5", 4), _host(db, "10.2.0.5", 2)
    db.commit()
    assert compute_path(db, "10.4.0.5", "10.2.0.5")["overall"] == "unknown"
    # the modelled crossing itself is still denied
    assert compute_reachability(db, src_level=4, dst_level=3)["matrix"]["4→3"]["overall"] \
        == "denied"


def test_flat_with_subnet_evidence_keeps_firewall_deny(db):
    f = Firewall(name="f", vendor="fortigate", purdue_level_ingress=4, purdue_level_egress=3)
    db.add(f)
    db.flush()
    db.add_all([FirewallInterface(firewall_id=f.id, name="out", network_cidr="10.4.0.0/24",
                                  purdue_level=4),
                FirewallInterface(firewall_id=f.id, name="in", network_cidr="10.3.0.0/16",
                                  purdue_level=3)])
    fw = _dev(db, "f", firewall_id=f.id)
    _rule(db, fw, "deny", firewall_id=f.id)
    _host(db, "10.4.0.5", 4), _host(db, "10.3.2.5", 2)   # L2 host on the L3 segment
    db.commit()
    p = compute_path(db, "10.4.0.5", "10.3.2.5")
    assert p["inferred_adjacency"][0]["basis"] == "subnet"
    assert p["overall"] == "denied"


def test_flat_edges_never_bypass_a_firewall(db):
    fw = _dev(db, "f", 4, 3)
    _rule(db, fw, "deny")
    _host(db, "10.2.0.5", 2), _host(db, "10.1.0.5", 1)
    db.commit()
    m = compute_reachability(db)["matrix"]
    assert m["4→3"]["overall"] == "denied"
    assert all(len(p["hops"]) == 1 for p in m["4→3"]["paths"])
    # two flat levels with no firewall between them: still no enforcement point
    assert m["2→1"]["overall"] == "no_policy"


def test_no_firewalls_no_flat_inference(db):
    _host(db, "10.2.0.5", 2), _host(db, "10.1.0.5", 1)
    db.commit()
    assert compute_path(db, "10.2.0.5", "10.1.0.5")["overall"] == "no_policy"


# ============================================================ A-31 shadows

def _shadow_dev(db):
    return _dev(db, "fw-s")


def test_union_of_two_permits_fully_shadows_deny(db):
    d = _shadow_dev(db)
    p1 = _rule(db, d, "permit", src="10.0.0.0/25", protocol="tcp", dst_port="80")
    p2 = _rule(db, d, "permit", src="10.0.0.128/25", protocol="tcp", dst_port="80")
    deny = _rule(db, d, "deny", src="10.0.0.0/24", protocol="tcp", dst_port="80")
    db.commit()
    res = find_shadowed_rules(db)
    on_deny = [s for s in res["shadows"] if s["shadowed_rule"]["rule_id"] == deny.id]
    assert len(on_deny) == 1
    s = on_deny[0]
    assert s["shadow_type"] == "full_shadow" and s["union_coverage"] is True
    assert s["severity"] == "high"
    assert {r["rule_id"] for r in s["shadowing_rules"]} == {p1.id, p2.id}


def test_union_over_ports(db):
    d = _shadow_dev(db)
    _rule(db, d, "deny", protocol="tcp", dst_port="1-100")
    _rule(db, d, "deny", protocol="tcp", dst_port="101-200")
    later = _rule(db, d, "deny", protocol="tcp", dst_port="50-150")
    db.commit()
    on = [s for s in find_shadowed_rules(db)["shadows"]
          if s["shadowed_rule"]["rule_id"] == later.id]
    assert len(on) == 1 and on[0]["shadow_type"] == "duplicate" and on[0]["union_coverage"]


def test_union_with_gap_is_not_full_shadow(db):
    d = _shadow_dev(db)
    _rule(db, d, "permit", src="10.0.0.0/26", protocol="tcp", dst_port="80")
    _rule(db, d, "permit", src="10.0.0.128/25", protocol="tcp", dst_port="80")
    deny = _rule(db, d, "deny", src="10.0.0.0/24", protocol="tcp", dst_port="80")
    db.commit()
    res = find_shadowed_rules(db)
    assert not [s for s in res["shadows"] if s["shadowed_rule"]["rule_id"] == deny.id]
    # each narrower permit is an intended carve-out (T3-38)
    assert len([x for x in res["exceptions"] if x["shadowed_rule"]["rule_id"] == deny.id]) == 2


def test_rows_sharing_rule_order_not_compared(db):
    d = _shadow_dev(db)
    _rule(db, d, "permit", src="any", protocol="tcp", dst_port="80", rule_order=7)
    _rule(db, d, "permit", src="10.0.0.0/24", protocol="tcp", dst_port="80", rule_order=7)
    db.commit()
    assert find_shadowed_rules(db)["shadows"] == []


def test_union_respects_protocol(db):
    d = _shadow_dev(db)
    _rule(db, d, "permit", src="10.0.0.0/25")            # any protocol
    _rule(db, d, "permit", src="10.0.0.128/25", protocol="udp")
    deny = _rule(db, d, "deny", src="10.0.0.0/24", protocol="tcp")
    db.commit()
    on = [s for s in find_shadowed_rules(db)["shadows"]
          if s["shadowed_rule"]["rule_id"] == deny.id]
    assert not any(s.get("union_coverage") for s in on)


def test_shadow_5k_rules_one_device_under_30s(db):
    d = _shadow_dev(db)
    rnd = random.Random(2)

    def addr():
        if rnd.random() < 0.03:
            return "any"
        p = rnd.choice([16, 24, 24, 24, 28, 32, 32])
        a = f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}"
        return str(ipaddress.ip_network(f"{a}/{p}", strict=False))

    db.add_all([FirewallRule(
        firewall_device_id=d.id, device_name=d.name, device_type="fortigate",
        src=addr(), dst=addr(), protocol=rnd.choice(["tcp", "udp", "any", "tcp"]),
        dst_port=rnd.choice([None, str(rnd.randint(1, 2000)),
                             f"{rnd.randint(1, 1000)}-{rnd.randint(1001, 3000)}"]),
        action=rnd.choice(["accept", "deny"]), rule_order=k + 1) for k in range(5000)])
    db.commit()
    t = time.time()
    res = find_shadowed_rules(db)
    assert time.time() - t < 30
    assert res["rules_analysed"] == 5000


def test_same_segment_flow_is_not_judged_by_a_firewall_policy(db):
    """Two hosts in one firewall-connected subnet talk through the switch: the
    firewall's deny-all must not turn that into 'traffic got through despite
    an explicit deny' (tabletop: Teleport -> jumpbox ssh inside the DMZ)."""
    f = Firewall(name="dmz-fw", vendor="fortigate")
    db.add(f)
    db.flush()
    db.add(FirewallInterface(firewall_id=f.id, name="dmz", network_cidr="10.40.1.0/24"))
    fw = _dev(db, "dmz-fw", firewall_id=f.id)
    _rule(db, fw, "deny")
    _sess(db, _host(db, "10.40.1.10", 3.5), _host(db, "10.40.1.20", 3.5), dst_port=22)
    # a flow that leaves the segment is still judged
    _sess(db, _host(db, "10.40.1.11", 3.5), _host(db, "10.20.1.5"), dst_port=22)
    db.commit()
    r = compute_diff(db)
    assert [(e["src_ip"], e["reason_code"]) for e in r["unexpected_traffic"]] == [
        ("10.40.1.11", "explicit_deny")]
