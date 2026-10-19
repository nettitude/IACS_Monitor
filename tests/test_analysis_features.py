"""
Analysis features from docs/code-review-remediation.md:
  F-07 IPv6 matching, F-05 NAT modelling, N-05 host-scope intersection /
  address sets / legacy direction, N-10 /topology edge classification,
  N-11 clearing interface labels, N-13 Purdue level range checks,
  F-16 suggestion refresh + evidence + dotted MACs, F-10 last_matched.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app.db import get_db
from app.models import (
    Base, Firewall, FirewallDevice, FirewallInterface, FirewallRule, FirewallZone, Host,
    NatRule, NetworkSession, SwitchInterface,
)
from app.parsers import rule_match as rm
from app.parsers.device_classification import classify_hosts_by_lldp_role
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.switch_parser import parse_cdp_neighbors
from app.parsers.topology_diff import compute_diff
from app.parsers.topology_manager import (
    classify_level_edge, run_purdue_suggestions, set_interface_labels, set_upstream_firewall,
    valid_purdue_level,
)

NOW = datetime.now(timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


_n = {"order": 0, "sport": 40000}


def _fwdev(db, name, zf, zt, vendor="fortigate", firewall=None):
    d = FirewallDevice(name=name, vendor=vendor, purdue_zone_from=zf, purdue_zone_to=zt,
                       firewall_id=firewall.id if firewall else None)
    db.add(d)
    db.flush()
    return d


def _firewall(db, name, vendor="fortigate"):
    f = Firewall(name=name, device_name=name, vendor=vendor)
    db.add(f)
    db.flush()
    return f


def _rule(db, dev, action="permit", src="any", dst="any", protocol="any", dst_port=None,
          src_zone=None, dst_zone=None, policy_id=None, **kw):
    _n["order"] += 1
    r = FirewallRule(firewall_device_id=dev.id, firewall_id=dev.firewall_id, device_name=dev.name,
                     device_type=dev.vendor or "fortigate", src=src, dst=dst, protocol=protocol,
                     dst_port=dst_port, action=action, rule_order=_n["order"],
                     src_zone=src_zone, dst_zone=dst_zone,
                     policy_id=policy_id or str(_n["order"]), **kw)
    db.add(r)
    db.flush()
    return r


def _host(db, ip, level=None, **kw):
    h = Host(ip=ip, purdue_level=level, sources=["test"], **kw)
    db.add(h)
    db.flush()
    return h


def _sess(db, src, dst, dst_port, transport="tcp", last_seen=None):
    _n["sport"] += 1
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, src_port=_n["sport"],
                       dst_port=dst_port, transport=transport, protocol="unknown",
                       last_seen=last_seen or NOW)
    db.add(s)
    db.flush()
    return s


def _cell(db, s, d, **kw):
    return compute_reachability(db, src_level=s, dst_level=d, **kw)["matrix"][f"{s}→{d}"]


# ============================================================ F-07 IPv6

def test_rule_match_families_are_disjoint_and_any_matches_both():
    v4all, v6all, anyx = (rm.parse_address(x) for x in ("0.0.0.0/0", "::/0", "any"))
    assert rm.ip_in_addr("2001:db8::1", v6all) and not rm.ip_in_addr("10.0.0.1", v6all)
    assert rm.ip_in_addr("10.0.0.1", v4all) and not rm.ip_in_addr("2001:db8::1", v4all)
    assert rm.ip_in_addr("10.0.0.1", anyx) and rm.ip_in_addr("2001:db8::1", anyx)
    assert rm.addr_contains(anyx, v6all) and not rm.addr_contains(v4all, v6all)
    r6 = rm.parse_address("range:2001:db8::10-2001:db8::2f")
    assert rm.ip_in_addr("2001:db8::1f", r6) and not rm.ip_in_addr("2001:db8::30", r6)
    assert rm.addr_overlaps(rm.parse_address("2001:db8::/32"), rm.parse_address("10.0.0.0/8")) is False


def test_ipv6_host_path(db):
    _host(db, "2001:db8:4::5", 4)
    _host(db, "2001:db8:3::5", 3)
    dev = _fwdev(db, "fw43", 4, 3)
    _rule(db, dev, src="10.4.0.0/16", dst="10.3.0.0/16")          # v4 only
    _rule(db, dev, src="2001:db8:4::/48", dst="2001:db8:3::/48", protocol="tcp", dst_port="443")
    db.commit()
    ok = compute_path(db, src_ip="2001:db8:4::5", dst_ip="2001:db8:3::5", dst_port=443, protocol="tcp")
    assert ok["overall"] == "permitted", ok
    # non-canonical spelling of the same address resolves the host too
    ok2 = compute_path(db, src_ip="2001:DB8:4:0::5", dst_ip="2001:db8:3::5", dst_port=443, protocol="tcp")
    assert ok2["src_level"] == 4 and ok2["overall"] == "permitted"
    no = compute_path(db, src_ip="2001:db8:4::5", dst_ip="2001:db8:3::5", dst_port=22, protocol="tcp")
    assert no["overall"] == "denied"  # the v4 permit-all never matches v6


def test_level_matrix_per_family(db):
    dev = _fwdev(db, "fw43", 4, 3)
    _rule(db, dev, src="::/0", dst="any")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "denied"
    assert _cell(db, 4, 3, ip_version=6)["overall"] == "permitted"
    db.query(FirewallRule).delete()
    _rule(db, dev, src="any", dst="any")
    db.commit()
    assert _cell(db, 4, 3)["overall"] == "permitted"
    assert _cell(db, 4, 3, ip_version=6)["overall"] == "permitted"


def test_ipv6_sessions_in_diff(db):
    a, b = _host(db, "2001:db8:4::5", 4), _host(db, "2001:db8:3::5", 3)
    c, d = _host(db, "10.4.0.5", 4), _host(db, "10.3.0.5", 3)
    dev = _fwdev(db, "fw43", 4, 3)
    r6 = _rule(db, dev, src="2001:db8:4::/48", dst="2001:db8:3::/48")
    _sess(db, a, b, 443)
    _sess(db, c, d, 443)
    db.commit()
    res = compute_diff(db)
    unexpected = {(u["src_ip"], u["dst_ip"]) for u in res["unexpected_traffic"]}
    assert unexpected == {("10.4.0.5", "10.3.0.5")}
    assert r6.id not in {u["rule_id"] for u in res["unused_rules"]}


def test_ipv6_shadow_within_family_only(db):
    for i, (src, port) in enumerate((("2001:db8::/32", None), ("2001:db8::5/128", "80"),
                                     ("10.0.0.5/32", "80")), 1):
        db.add(FirewallRule(device_name="fw1", device_type="fortigate", src=src, dst="any",
                            protocol="tcp" if port else "any", dst_port=port, action="permit",
                            rule_order=i, policy_id=str(i)))
    db.commit()
    shadows = find_shadowed_rules(db, device_name="fw1")["shadows"]
    assert [s["shadowed_rule"]["src"] for s in shadows] == ["2001:db8::5/128"]


# ============================================================ N-05

def test_address_lists_parse_as_sets():
    spec = rm.parse_address("10.0.0.1,10.0.0.2")
    assert isinstance(spec, rm.AddrSet)
    assert rm.ip_in_addr("10.0.0.2", spec) and not rm.ip_in_addr("10.0.0.3", spec)
    assert rm.addr_equal(rm.parse_address("10.0.0.1 10.0.0.2"), spec)
    assert rm.addr_equal(rm.parse_address("['10.0.0.2', '10.0.0.1']"), spec)
    assert rm.addr_equal(rm.parse_address("10.0.1.0 0.0.0.255"), rm.parse_address("10.0.1.0/24"))
    assert isinstance(rm.parse_address("10.0.0.1,OBJ_NAME"), rm.Unresolved)
    assert rm.parse_address("10.0.0.1, any") == rm.ANY


def test_multi_address_rule_matches_host_query(db):
    _host(db, "10.4.0.2", 4)
    _host(db, "10.3.0.9", 3)
    dev = _fwdev(db, "fw43", 4, 3)
    _rule(db, dev, src="10.4.0.1,10.4.0.2", dst="10.3.0.9")
    db.commit()
    res = compute_path(db, src_ip="10.4.0.2", dst_ip="10.3.0.9")
    assert res["overall"] == "permitted"
    assert not [e for h in res["hops"] for e in h["enforcement_points"] if e["unresolved_rules"]]


def test_host_scopes_intersect_across_hops(db):
    fw43, fw32 = _fwdev(db, "fw43", 4, 3), _fwdev(db, "fw32", 3, 2)
    _rule(db, fw43, src="10.4.0.1/32")
    _rule(db, fw32, src="10.4.0.2/32")
    db.commit()
    assert _cell(db, 4, 2)["overall"] == "denied"   # no host passes both
    db.query(FirewallRule).delete()
    _rule(db, fw43, src="10.4.0.0/24", protocol="tcp", dst_port="443,502")
    _rule(db, fw32, src="10.4.0.1,10.9.9.9", protocol="tcp", dst_port="502")
    db.commit()
    cell = _cell(db, 4, 2)
    assert cell["overall"] == "partial"
    assert cell["permitted_services"] == ["tcp/502"]
    assert cell["paths"][0]["permitted_scopes"] == [
        {"src": "10.4.0.1/32", "dst": "any", "services": ["tcp/502"]}]


def test_legacy_device_direction_from_firewall_zones(db):
    dev = _fwdev(db, "fwL", 4, 3)  # no linked Firewall
    db.add_all([FirewallZone(device_name="fwL", interface_name="port1", zone_name="corp",
                             ip_cidr="10.4.0.1/24"),
                FirewallZone(device_name="fwL", interface_name="port2", zone_name="ot",
                             ip_cidr="10.3.0.1/24")])
    _host(db, "10.4.0.5", 4)
    _host(db, "10.3.0.5", 3)
    _rule(db, dev, src_zone="ot", dst_zone="corp")
    db.commit()
    assert _cell(db, 3, 4)["overall"] == "permitted"
    down = _cell(db, 4, 3)
    assert down["overall"] == "denied"
    ep = down["paths"][0]["hops"][0]["enforcement_points"][0]
    assert ep["rules_skipped_direction"] == 1


def test_legacy_device_direction_from_rule_address_hosts(db):
    dev = _fwdev(db, "fwL", 4, 3)
    _host(db, "10.3.0.5", 3)
    _host(db, "10.4.0.5", 4)
    _rule(db, dev, src="10.3.0.0/24", dst="10.4.0.0/24")
    db.commit()
    assert compute_path(db, src_ip="10.3.0.5", dst_ip="10.4.0.5")["overall"] == "permitted"
    assert compute_path(db, src_ip="10.4.0.5", dst_ip="10.3.0.5")["overall"] == "denied"


# ============================================================ F-05 NAT

def _vip_site(db, vendor):
    fw = _firewall(db, "edge", vendor=vendor)
    dev = _fwdev(db, "edge", 5, 3, vendor=vendor, firewall=fw)
    client = _host(db, "198.51.100.7", 5)
    server = _host(db, "10.3.0.10", 3)
    db.add(NatRule(firewall_id=fw.id, firewall_device_id=dev.id, nat_type="dnat", name="web-vip",
                   protocol="tcp", ext_ip="203.0.113.10/32", ext_port="443",
                   mapped_ip="10.3.0.10/32", mapped_port="8443", device_type=vendor))
    db.flush()
    return fw, dev, client, server


def test_fortios_vip_policy_matches_mapped_address(db):
    _fw_, dev, client, server = _vip_site(db, "fortigate")
    _rule(db, dev, src="any", dst="10.3.0.10/32", protocol="tcp", dst_port="8443")
    db.commit()
    res = compute_path(db, src_ip="198.51.100.7", dst_ip="203.0.113.10", dst_port=443, protocol="tcp")
    assert res["overall"] == "permitted", res
    assert res["dst_level"] == 3
    assert res["nat_destination"]["mapped_ip"] == "10.3.0.10"
    (nat,) = res["nat"]
    assert nat["type"] == "dnat"
    assert nat["original"] == {"dst_ip": "203.0.113.10", "dst_port": 443}
    assert nat["translated"] == {"dst_ip": "10.3.0.10", "dst_port": 8443}
    assert nat["policy_evaluated_on"] == "post_nat"
    assert res["hops"][0]["nat"] == res["nat"]


def test_panos_policy_matches_pre_nat_address(db):
    _fw_, dev, client, server = _vip_site(db, "panos")
    _rule(db, dev, src="any", dst="10.3.0.10/32", protocol="tcp", dst_port="8443")
    db.commit()
    q = dict(src_ip="198.51.100.7", dst_ip="203.0.113.10", dst_port=443, protocol="tcp")
    assert compute_path(db, **q)["overall"] == "denied"   # post-NAT rule does not match on PAN-OS
    db.query(FirewallRule).delete()
    _rule(db, dev, src="any", dst="203.0.113.10/32", protocol="tcp", dst_port="443")
    db.commit()
    res = compute_path(db, **q)
    assert res["overall"] == "permitted"
    assert res["nat"][0]["policy_evaluated_on"] == "pre_nat"


def test_snat_changes_source_for_downstream_hops(db):
    fw32 = _fwdev(db, "fw32", 3, 2)
    fw43 = _fwdev(db, "fw43", 4, 3)
    _host(db, "10.2.0.5", 2)
    _host(db, "10.4.0.9", 4)
    _rule(db, fw32, src="10.2.0.0/24")
    _rule(db, fw43, src="10.3.0.254/32")
    db.add(NatRule(firewall_device_id=fw32.id, nat_type="snat", orig_src="10.2.0.0/24",
                   mapped_ip="10.3.0.254/32"))
    db.commit()
    res = compute_path(db, src_ip="10.2.0.5", dst_ip="10.4.0.9")
    assert res["overall"] == "permitted", res
    assert res["nat"] == [dict(res["nat"][0], type="snat", original={"src_ip": "10.2.0.5"},
                               translated={"src_ip": "10.3.0.254"})]


@pytest.mark.parametrize("vendor,rule_dst,rule_port", [("fortigate", "10.3.0.10/32", "8443"),
                                                       ("panos", "203.0.113.10/32", "443")])
def test_diff_explains_translated_sessions(db, vendor, rule_dst, rule_port):
    _fw_, dev, client, server = _vip_site(db, vendor)
    vip = _host(db, "203.0.113.10")        # the VIP itself has no level
    r = _rule(db, dev, src="any", dst=rule_dst, protocol="tcp", dst_port=rule_port)
    _sess(db, client, server, 8443)        # captured inside: mapped address
    _sess(db, client, vip, 443)            # captured outside: VIP address
    db.commit()
    res = compute_diff(db)
    assert res["unexpected_traffic"] == [], res["unexpected_traffic"]
    assert r.id not in {u["rule_id"] for u in res["unused_rules"]}


# ============================================================ F-10

def test_diff_sets_last_matched_and_filters_unused(db, monkeypatch):
    monkeypatch.delenv("IACS_UNUSED_RULE_DAYS", raising=False)
    a, b = _host(db, "10.4.0.5", 4), _host(db, "10.3.0.5", 3)
    dev = _fwdev(db, "fw43", 4, 3)
    used = _rule(db, dev, protocol="tcp", dst_port="502")
    logged = _rule(db, dev, protocol="tcp", dst_port="22", last_matched=NOW - timedelta(days=10))
    stale = _rule(db, dev, protocol="tcp", dst_port="23", last_matched=NOW - timedelta(days=200))
    never = _rule(db, dev, protocol="tcp", dst_port="80")
    seen = NOW - timedelta(days=1)
    _sess(db, a, b, 502, last_seen=seen)
    db.commit()
    res = compute_diff(db)
    db.expire_all()
    got = db.get(FirewallRule, used.id).last_matched
    assert abs((got - seen).total_seconds()) < 1
    unused = {u["rule_id"]: u for u in res["unused_rules"]}
    assert set(unused) == {stale.id, never.id}
    assert unused[never.id]["last_matched"] is None
    assert unused[stale.id]["last_matched"].startswith(str((NOW - timedelta(days=200)).date()))
    assert res["unused_rule_days"] == 90
    # existing (newer, from logs) value is kept: max(), not overwrite
    newer = NOW
    db.get(FirewallRule, used.id).last_matched = newer
    db.commit()
    compute_diff(db)
    db.expire_all()
    assert abs((db.get(FirewallRule, used.id).last_matched - newer).total_seconds()) < 1
    monkeypatch.setenv("IACS_UNUSED_RULE_DAYS", "5")
    assert logged.id in {u["rule_id"] for u in compute_diff(db)["unused_rules"]}


# ============================================================ F-16

def _iface(db, fw, name, **kw):
    i = FirewallInterface(firewall_id=fw.id, name=name, **kw)
    db.add(i)
    db.flush()
    return i


def test_suggestions_refresh_and_need_evidence(db):
    fw = _firewall(db, "FW-A")
    stale = _iface(db, fw, "port9", network_cidr="192.168.50.0/24",
                   suggested_purdue_level=3, purdue_suggestion_source="role_heuristic")
    manual = _iface(db, fw, "port8", network_cidr="10.9.0.0/24", purdue_level=1)
    hosts_if = _iface(db, fw, "port2", network_cidr="10.2.0.0/24")
    alias_if = _iface(db, fw, "port3", alias="SCADA LAN")
    zone_if = _iface(db, fw, "port5")
    db.add(FirewallZone(device_name="FW-A", interface_name="port5", zone_name="CORP_ZONE"))
    for i, lv in enumerate((2, 2, 1)):
        _host(db, f"10.2.0.{10 + i}", lv)
    stats = run_purdue_suggestions(db)
    db.flush()
    assert (stale.suggested_purdue_level, stale.purdue_suggestion_source) == (None, None)
    assert stats["suggestions_cleared"] == 1
    assert manual.purdue_level == 1 and manual.suggested_purdue_level is None
    assert (hosts_if.suggested_purdue_level, hosts_if.purdue_suggestion_source) == (2, "connected_hosts")
    assert (alias_if.suggested_purdue_level, alias_if.purdue_suggestion_source) == (2, "name_keyword")
    assert (zone_if.suggested_purdue_level, zone_if.purdue_suggestion_source) == (4, "zone_name")
    # evidence disappears -> suggestion is cleared on the next run
    db.query(Host).delete()
    run_purdue_suggestions(db)
    assert hosts_if.suggested_purdue_level is None


def test_cisco_dotted_mac_neighbour_matches_host(db):
    h = Host(mac="00:11:22:33:44:55", sources=["t"])
    db.add(h)
    db.add(SwitchInterface(device_name="sw1", port_name="Gi1/0/1",
                           neighbor_device="0011.2233.4455", neighbor_protocol="lldp",
                           neighbor_platform="Siemens SIMATIC S7-1500"))
    db.commit()
    assert classify_hosts_by_lldp_role(db)["hosts_matched"] == 1


def test_cdp_mac_device_id_is_normalised():
    text = ("-------------------------\nDevice ID: 0011.2233.4455\nPlatform: cisco WS-C2960,\n"
            "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): Gi0/1\n")
    assert parse_cdp_neighbors(text)[0]["neighbor_device"] == "00:11:22:33:44:55"


# ============================================================ N-13 / N-10 helpers

def test_valid_purdue_level_is_central():
    assert [x for x in range(-1, 8) if valid_purdue_level(x)] == [0, 1, 2, 3, 4, 5]
    assert not valid_purdue_level(True) and not valid_purdue_level("3")


def test_set_upstream_accepts_level_5(db):
    fw = _firewall(db, "FW-A")
    set_upstream_firewall(db, fw.id, None, purdue_level_ingress=5, purdue_level_egress=4)
    with pytest.raises(ValueError, match="0–5"):
        set_upstream_firewall(db, fw.id, None, purdue_level_ingress=6)


def test_classify_level_edge():
    b = {(3, 4)}
    assert classify_level_edge(3, 3, b) == {"violation": "same", "crosses_firewall": False}
    # F-08: L3.5 (industrial DMZ) is a level of its own, so L4<->L3 skips it
    # (was "adjacent"); L4<->L3.5 and L3.5<->L3 are adjacent.
    assert classify_level_edge(4, 3, b) == {"violation": "skips_level", "crosses_firewall": True}
    assert classify_level_edge(4, 3.5, {(3.5, 4)}) == {"violation": "adjacent", "crosses_firewall": True}
    assert classify_level_edge(3.5, 3, b) == {"violation": "adjacent", "crosses_firewall": False}
    assert classify_level_edge(1, 3, b) == {"violation": "skips_level", "crosses_firewall": False}
    assert classify_level_edge(None, 3, b) == {"violation": "unclassified", "crosses_firewall": None}


def test_set_interface_labels_clear(db):
    fw = _firewall(db, "FW-A")
    i = _iface(db, fw, "port1", side="inside", purdue_level=2, zone_label="Cell")
    set_interface_labels(db, i.id, clear=["side", "purdue_level"])
    assert (i.side, i.purdue_level, i.zone_label) == (None, None, "Cell")
    with pytest.raises(ValueError):
        set_interface_labels(db, i.id, side="inside", clear=["side"])
    with pytest.raises(ValueError):
        set_interface_labels(db, i.id, clear=["name"])


# ============================================================ routes

@pytest.fixture
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'af.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        c.Session = Session
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def test_topology_edges_have_violation_and_nodes_hostname(api):
    with api.Session() as s:
        hosts = [Host(ip="10.4.0.1", purdue_level=4, hostname="erp", sources=["t"]),
                 Host(ip="10.3.0.1", purdue_level=3, sources=["t"]),
                 Host(ip="10.1.0.1", purdue_level=1, sources=["t"]),
                 Host(ip="10.9.0.1", sources=["t"])]
        s.add_all(hosts)
        s.add(FirewallDevice(name="fw43", purdue_zone_from=4, purdue_zone_to=3))
        s.flush()
        h4, h3, h1, hx = hosts
        for i, (a, b) in enumerate(((h4, h3), (h4, h1), (h3, h3), (hx, h3))):
            s.add(NetworkSession(src_host_id=a.id, dst_host_id=b.id, src_port=1000 + i,
                                 dst_port=502, transport="tcp", protocol="modbus"))
        s.commit()
    body = api.get("/topology").json()
    assert {n["ip"]: n["hostname"] for n in body["nodes"]}["10.4.0.1"] == "erp"
    got = [(e["violation"], e["crosses_firewall"]) for e in sorted(body["edges"], key=lambda e: e["id"])]
    # F-08: L4->L3 skips the L3.5 DMZ level (was "adjacent")
    assert got == [("skips_level", True), ("skips_level", True), ("same", False), ("unclassified", None)]


def test_set_interface_side_can_clear(api):
    with api.Session() as s:
        fw = Firewall(name="FW-A", vendor="fortigate")
        s.add(fw)
        s.flush()
        i = FirewallInterface(firewall_id=fw.id, name="port1", side="inside", purdue_level=2)
        s.add(i)
        s.commit()
        iid = i.id
    r = api.post("/topology/set-interface-side", json={"interface_id": iid, "zone_label": "Cell"})
    assert r.json()["interface"]["side"] == "inside"          # null = unchanged
    r = api.post("/topology/set-interface-side",
                 json={"interface_id": iid, "clear": ["side", "purdue_level"]})
    assert r.status_code == 200
    assert (r.json()["interface"]["side"], r.json()["interface"]["purdue_level"]) == (None, None)
    assert api.post("/topology/set-interface-side",
                    json={"interface_id": iid, "purdue_level": 5}).status_code == 200
    assert api.post("/topology/set-interface-side",
                    json={"interface_id": iid, "purdue_level": 6}).status_code == 422
    assert api.post("/topology/set-interface-side",
                    json={"interface_id": iid, "side": "inside", "clear": ["side"]}).status_code == 422
    assert api.post("/topology/set-interface-side",
                    json={"interface_id": 99999, "clear": ["side"]}).status_code == 404


@pytest.mark.parametrize("params", [{"purdue_zone_from": 6}, {"purdue_zone_to": -1}])
def test_ingest_firewall_rejects_out_of_range_levels(api, params):
    r = api.post("/ingest/firewall", params=params,
                 files={"file": ("acl.txt", b"access-list 101 permit ip any any\n")})
    assert r.status_code == 422
    assert "Purdue level 0–5" in r.json()["detail"]


def test_nat_destination_reported_on_early_returns(monkeypatch):
    """compute_path must keep nat_destination even when it returns before
    evaluating any firewall (no_policy / intra_level / unknown)."""
    import app.parsers.reachability as r
    sentinel = {"nat_rule_id": 1, "name": "vip", "ext_ip": "203.0.113.5",
                "mapped_ip": "10.0.1.10", "mapped_port": None, "mapped_level": 1}

    def fake_inner(db, src_ip, dst_ip, dst_level, dst_port, protocol, _nat_out=None):
        _nat_out["nat_destination"] = sentinel
        return r._path_result(src_ip, None, None, dst_ip, None, 1, "no_policy")

    monkeypatch.setattr(r, "_compute_path_inner", fake_inner)
    res = r.compute_path(None, "10.0.4.5", "203.0.113.5")
    assert res["overall"] == "no_policy" and res["nat_destination"] == sentinel
