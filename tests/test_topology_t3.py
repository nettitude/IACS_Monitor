"""
Tier-3 regression tests for the topology / analysis modules (T3-34 .. T3-41):
topology_diff, rule_match ranges, device_classification, rule_shadow,
cross_fw_findings, topology_manager, reachability caching.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    Base, Finding, Firewall, FirewallDevice, FirewallInterface, FirewallRule, Host,
    NetworkSession, SwitchVlan,
)
from app.parsers import rule_match as rm
from app.parsers.cross_fw_findings import (
    _check_any_any_permit, _check_asymmetric_permits, _check_missing_deny_all,
)
from app.parsers.device_classification import _server_side, classify_hosts
from app.parsers.reachability import compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.topology_diff import compute_diff, parse_address_spec
from app.parsers.topology_manager import get_topology_state, set_upstream_firewall, upstream_chain


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


_n = {"order": 0, "sport": 40000}


def _dev(db, name, zf=None, zt=None):
    d = FirewallDevice(name=name, vendor="fortigate", purdue_zone_from=zf, purdue_zone_to=zt)
    db.add(d)
    db.flush()
    return d


def _rule(db, dev=None, action="permit", src="any", dst="any", protocol="any", dst_port=None,
          src_zone=None, dst_zone=None, device_name=None, firewall_id=None, rule_order=None,
          policy_id=None, device_type="fortigate"):
    _n["order"] += 1
    r = FirewallRule(
        firewall_device_id=dev.id if dev else None, firewall_id=firewall_id,
        device_name=device_name or (dev.name if dev else "fw"), device_type=device_type,
        src=src, dst=dst, protocol=protocol, dst_port=dst_port, action=action,
        rule_order=rule_order if rule_order is not None else _n["order"],
        src_zone=src_zone, dst_zone=dst_zone, policy_id=policy_id,
    )
    db.add(r)
    db.flush()
    return r


def _host(db, ip, level=None, **kw):
    h = Host(ip=ip, purdue_level=level, **kw)
    db.add(h)
    db.flush()
    return h


def _sess(db, src, dst, dst_port=502, src_port=None, protocol="modbus", transport="tcp"):
    _n["sport"] += 1
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id,
                       src_port=src_port if src_port is not None else _n["sport"],
                       dst_port=dst_port, transport=transport, protocol=protocol)
    db.add(s)
    db.flush()
    return s


# =========================================================== T3-34 diff paths

def test_multihop_session_needs_every_hop_to_permit(db):
    fw21 = _dev(db, "fw21", 2, 1)
    fw32 = _dev(db, "fw32", 3, 2)
    _rule(db, fw21, "deny")                       # 1<->2 denies everything
    _rule(db, fw32, "permit")                     # 2<->3 permits everything
    plc, hist = _host(db, "10.1.0.5", 1), _host(db, "10.3.0.5", 3)
    _sess(db, plc, hist)
    db.commit()
    r = compute_diff(db)
    assert len(r["unexpected_traffic"]) == 1
    e = r["unexpected_traffic"][0]
    assert e["path_evaluated"] is True
    assert e["reason_code"] == "explicit_deny"
    assert e["policy_mismatch"] is True
    assert r["purdue_boundary_scoping"] is True


def test_multihop_session_explained_when_all_hops_permit(db):
    fw21 = _dev(db, "fw21", 2, 1)
    fw32 = _dev(db, "fw32", 3, 2)
    p1 = _rule(db, fw21, "permit", protocol="tcp", dst_port="502")
    p2 = _rule(db, fw32, "permit")
    _sess(db, _host(db, "10.1.0.5", 1), _host(db, "10.3.0.5", 3))
    db.commit()
    r = compute_diff(db)
    assert r["unexpected_traffic"] == []
    assert {u["rule_id"] for u in r["unused_rules"]}.isdisjoint({p1.id, p2.id})


def test_multihop_implicit_deny_on_one_hop(db):
    fw21 = _dev(db, "fw21", 2, 1)
    fw32 = _dev(db, "fw32", 3, 2)
    _rule(db, fw21, "permit", protocol="tcp", dst_port="22")   # 502 not permitted
    _rule(db, fw32, "permit")
    _sess(db, _host(db, "10.1.0.5", 1), _host(db, "10.3.0.5", 3))
    db.commit()
    e = compute_diff(db)["unexpected_traffic"][0]
    assert e["reason_code"] == "implicit_deny"
    assert e["policy_mismatch"] is False


def test_earlier_deny_beats_later_permit_scoped(db):
    fw = _dev(db, "fw21", 2, 1)
    deny = _rule(db, fw, "deny", src="10.2.0.5/32", protocol="tcp", dst_port="502")
    permit = _rule(db, fw, "permit")
    _sess(db, _host(db, "10.2.0.5", 2), _host(db, "10.1.0.9", 1))
    db.commit()
    r = compute_diff(db)
    e = r["unexpected_traffic"][0]
    assert e["reason_code"] == "explicit_deny"
    assert e["blocking_rule"]["rule_id"] == deny.id
    assert permit.id in {u["rule_id"] for u in r["unused_rules"]}


def test_earlier_deny_beats_later_permit_global_fallback(db):
    fw = _dev(db, "fwx")                        # no Purdue boundary
    deny = _rule(db, fw, "deny", src="10.2.0.5", protocol="tcp", dst_port="502")
    _rule(db, fw, "permit")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    e = compute_diff(db)["unexpected_traffic"][0]
    assert e["path_evaluated"] is False
    assert e["reason_code"] == "explicit_deny"
    assert e["blocking_rule"]["rule_id"] == deny.id


def test_global_fallback_any_device_first_match_permit_explains(db):
    a, b = _dev(db, "fwa"), _dev(db, "fwb")
    _rule(db, a, "deny")
    _rule(db, b, "permit", dst="10.1.0.0/24", protocol="tcp", dst_port="502")
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    # A-24: fwb's permit names the destination -> it plausibly carries the
    # flow; fwa's any/any deny does not (an unrelated box), so no mismatch.
    assert compute_diff(db)["unexpected_traffic"] == []


def test_disabled_rules_still_excluded_from_diff(db):
    fw = _dev(db, "fwx")
    r = _rule(db, fw, "permit")
    r.enabled = False
    _sess(db, _host(db, "10.2.0.5"), _host(db, "10.1.0.9"))
    db.commit()
    res = compute_diff(db)
    assert len(res["unexpected_traffic"]) == 1
    assert res["unused_rules"] == []


# ======================================================= T3-41 diff truncation

def test_diff_reports_truncation_and_is_ordered(db):
    fw = _dev(db, "fwx")
    _rule(db, fw, "permit", dst_port="22", protocol="tcp")
    a, b = _host(db, "10.2.0.5"), _host(db, "10.1.0.9")
    s1 = _sess(db, a, b)
    _sess(db, a, b)
    db.commit()
    r = compute_diff(db, session_limit=1)
    assert r["sessions_total"] == 2
    assert r["sessions_truncated"] is True
    assert r["session_limit"] == 1
    assert [e["session_id"] for e in r["unexpected_traffic"]] == [s1.id]
    r2 = compute_diff(db)
    assert r2["sessions_truncated"] is False and r2["sessions_considered"] == 2


# =============================================================== T3-35 ranges

def test_range_is_exact_not_under_covering_supernet():
    spec = parse_address_spec("range:10.0.0.10-10.0.0.200")
    assert rm.ip_in_addr("10.0.0.150", spec) is True     # was outside 10.0.0.0/26
    assert rm.ip_in_addr("10.0.0.9", spec) is False
    assert rm.ip_in_addr("10.0.0.201", spec) is False
    assert sum(n.num_addresses for n in spec.networks) == 191
    assert parse_address_spec("range:10.0.0.0-10.0.0.255") == parse_address_spec("10.0.0.0/24")
    net = parse_address_spec("10.0.0.64/26")
    assert rm.addr_contains(spec, net) is True
    assert rm.addr_contains(net, spec) is False
    assert rm.addr_overlaps(spec, parse_address_spec("10.0.0.0/29")) is False


def test_range_rule_matches_in_diff(db):
    fw = _dev(db, "fwx")
    _rule(db, fw, "permit", src="range:10.0.0.10-10.0.0.200")
    _sess(db, _host(db, "10.0.0.150"), _host(db, "10.9.0.1"))
    _sess(db, _host(db, "10.0.0.201"), _host(db, "10.9.0.2"))
    db.commit()
    r = compute_diff(db)
    assert [e["src_ip"] for e in r["unexpected_traffic"]] == ["10.0.0.201"]


def test_range_in_shadow_analysis(db):
    _rule(db, None, "permit", src="range:10.0.0.10-10.0.0.200", device_name="fw1")
    _rule(db, None, "deny", src="10.0.0.128/26", device_name="fw1")   # .128-.191 inside range
    shadows = find_shadowed_rules(db, device_name="fw1")["shadows"]
    assert [s["shadow_type"] for s in shadows] == ["full_shadow"]


def test_range_in_reachability(db):
    fw = _dev(db, "fw21", 2, 1)
    _rule(db, fw, "permit", src="range:10.2.0.10-10.2.0.200")
    db.commit()
    ok = compute_reachability(db, src_ip="10.2.0.150", dst_ip="10.1.0.1", src_level=2, dst_level=1)
    no = compute_reachability(db, src_ip="10.2.0.250", dst_ip="10.1.0.1", src_level=2, dst_level=1)
    assert ok["matrix"]["2→1"]["overall"] == "permitted"
    assert no["matrix"]["2→1"]["overall"] == "denied"


# ======================================================== T3-36 classification

def test_server_side_rules():
    assert _server_side(50000, 502, "modbus") == "dst"
    assert _server_side(502, 50000, "modbus") == "src"           # reply-first capture
    assert _server_side(44818, 445, "smb2_3") is None            # ephemeral 44818
    assert _server_side(44818, 445, "ethernet_ip") is None       # mislabelled by port
    assert _server_side(50000, 44818, "ethernet_ip") == "dst"
    assert _server_side(44818, 50000, "ethernet_ip") == "src"
    assert _server_side(20000, 50000, "modbus") is None          # non-canonical high port
    assert _server_side(502, 102, "s7comm") == "dst"             # canonical wins


def test_client_on_hmi_vlan_gets_vlan_level(db):
    db.add(SwitchVlan(device_name="sw", vlan_id=20, vlan_name="SCADA_HMI"))
    hmi = _host(db, "10.2.0.5", vlan="20")
    plc = _host(db, "10.1.0.5")
    _sess(db, hmi, plc, dst_port=502)
    db.commit()
    classify_hosts(db)
    db.refresh(hmi), db.refresh(plc)
    assert plc.device_type == "modbus_device" and plc.purdue_level == 1
    assert plc.classification_source == "protocol_inferred"
    assert hmi.purdue_level == 2
    assert hmi.classification_source == "vlan_inferred"


def test_client_without_vlan_gets_low_rank_hint_only(db):
    ews = _host(db, "10.3.0.5")
    _sess(db, ews, _host(db, "10.1.0.5"), dst_port=502)
    db.commit()
    classify_hosts(db)
    db.refresh(ews)
    assert ews.device_type == "ics_protocol_client_unclassified"
    assert ews.classification_source == "protocol_client_hint"
    assert ews.purdue_level is None


def test_legacy_client_marker_is_demoted_and_reclassified(db):
    db.add(SwitchVlan(device_name="sw", vlan_id=20, vlan_name="SCADA_HMI"))
    hmi = _host(db, "10.2.0.5", vlan="20", device_type="ics_protocol_client_unclassified",
                classification_source="protocol_inferred")
    db.commit()
    classify_hosts(db)
    db.refresh(hmi)
    assert hmi.purdue_level == 2 and hmi.classification_source == "vlan_inferred"


def test_smb_from_ephemeral_44818_does_not_make_ews_a_plc(db):
    ews, fs = _host(db, "10.3.0.5"), _host(db, "10.3.0.9")
    _sess(db, ews, fs, src_port=44818, dst_port=445, protocol="ethernet_ip")
    db.commit()
    classify_hosts(db)
    db.refresh(ews), db.refresh(fs)
    assert ews.device_type is None and ews.purdue_level is None
    assert fs.device_type is None


# =============================================== T3-37 firewall VLAN propagation

def test_firewall_vlan_propagates_to_null_source_vlan_and_hosts_use_it(db):
    fw = Firewall(name="fg", vendor="fortigate", is_multi_fw=False, topology_confirmed=False)
    db.add(fw)
    db.flush()
    db.add(FirewallInterface(firewall_id=fw.id, name="port3.30", vlan_id="30", purdue_level=2,
                             is_ha=False, is_mgmt_only=False))
    sv = SwitchVlan(device_name="sw", vlan_id=30, vlan_name="VLAN0030")   # no keyword, NULL src
    manual = SwitchVlan(device_name="sw2", vlan_id=30, vlan_name="X", purdue_level=3,
                        purdue_level_source="manual")
    db.add_all([sv, manual])
    h = _host(db, "10.2.0.7", vlan="30")
    db.commit()
    classify_hosts(db)
    db.refresh(sv), db.refresh(manual), db.refresh(h)
    assert sv.purdue_level == 2 and sv.purdue_level_source == "firewall_propagated"
    assert manual.purdue_level == 3 and manual.purdue_level_source == "manual"
    assert h.purdue_level == 3    # manual SwitchVlan level outranks propagated
    assert h.classification_source == "vlan_inferred"


def test_classify_by_vlan_reads_switchvlan_level_over_name(db):
    db.add(SwitchVlan(device_name="sw", vlan_id=40, vlan_name="CONTROL",
                      purdue_level=3, purdue_level_source="manual"))
    h = _host(db, "10.3.0.8", vlan="40")
    db.commit()
    classify_hosts(db)
    db.refresh(h)
    assert h.purdue_level == 3      # name keyword "control" would say 1


# =================================================================== T3-38 shadow

def test_zone_sets_and_any_cover_specific_zone(db):
    _rule(db, None, "permit", src_zone="port1,port2", dst_zone="any", device_name="fw1")
    _rule(db, None, "deny", src_zone="port1", dst_zone="wan1", device_name="fw1")
    s = find_shadowed_rules(db, device_name="fw1")["shadows"]
    assert len(s) == 1 and s[0]["shadow_type"] == "full_shadow"
    assert s[0]["severity"] == "high"          # deny ineffective


def test_disjoint_zone_sets_do_not_shadow(db):
    _rule(db, None, "permit", src_zone="port1,port2", device_name="fw1")
    _rule(db, None, "deny", src_zone="port3", device_name="fw1")
    assert find_shadowed_rules(db, device_name="fw1")["shadows"] == []


def test_exception_pattern_not_a_shadow(db):
    _rule(db, None, "permit", src="10.0.0.5/32", device_name="fw1")
    _rule(db, None, "deny", src="10.0.0.0/24", device_name="fw1")
    r = find_shadowed_rules(db, device_name="fw1", generate_findings=True)
    assert r["shadows"] == []
    assert [e["shadow_type"] for e in r["exceptions"]] == ["exception"]
    assert r["findings_created"] == 0


def test_shadow_severity_by_type(db):
    _rule(db, None, "deny", device_name="fwa")
    _rule(db, None, "permit", src="10.0.0.0/8", device_name="fwa")       # dead permit
    _rule(db, None, "permit", src="10.0.0.0/8", device_name="fwb")
    _rule(db, None, "permit", src="10.0.0.0/8", device_name="fwb")       # duplicate
    sev = {s["shadowed_rule"]["device_name"]: (s["shadow_type"], s["severity"])
           for s in find_shadowed_rules(db)["shadows"]}
    assert sev["fwa"] == ("full_shadow", "medium")
    assert sev["fwb"] == ("duplicate", "low")


def test_generated_findings_carry_type_severity(db):
    _rule(db, None, "permit", device_name="fw1")
    _rule(db, None, "deny", src="10.0.0.1/32", device_name="fw1")
    find_shadowed_rules(db, device_name="fw1", generate_findings=True)
    f = db.query(Finding).filter_by(check_name="shadow_rule").one()
    assert f.severity == "high"


# ============================================================= T3-39 cross-FW

def _xfw(db, name, vendor="generic"):
    fw = Firewall(name=name, vendor=vendor, is_multi_fw=True, topology_confirmed=False)
    db.add(fw)
    db.flush()
    return fw


def _xif(db, fw, name, zone_label=None, side=None):
    i = FirewallInterface(firewall_id=fw.id, name=name, zone_label=zone_label, side=side,
                          is_ha=False, is_mgmt_only=False)
    db.add(i)
    db.flush()
    return i


def test_any_any_requires_any_service_and_link_zone(db):
    a, b = _xfw(db, "A"), _xfw(db, "B")
    i = _xif(db, a, "port2")
    r1 = _rule(db, None, "permit", protocol="udp", dst_port="53", src_zone="internal",
               dst_zone="wan2", firewall_id=a.id)
    r2 = _rule(db, None, "permit", src_zone="internal", dst_zone="wan2", firewall_id=a.id)
    r3 = _rule(db, None, "permit", src="0.0.0.0/0", dst="any", src_zone="port2",
               firewall_id=a.id, policy_id="7")
    out = [f for f in _check_any_any_permit(db, a, b, i, [r1, r2, r3]) if f]
    assert [f.rule_id for f in out] == [r3.id]


def test_asymmetry_normalises_addresses_and_scopes_to_link(db):
    a, b = _xfw(db, "A"), _xfw(db, "B")
    ia, ib = _xif(db, a, "port2"), _xif(db, b, "wan1")
    ra = _rule(db, None, "permit", src="10.1.0.0/24", dst="10.2.0.0/24", protocol="tcp",
               dst_port="502", src_zone="port2", firewall_id=a.id)
    other = _rule(db, None, "permit", src="10.9.0.0/24", dst="10.8.0.0/24", protocol="tcp",
                  dst_port="80", src_zone="port7", dst_zone="port8", firewall_id=a.id)
    rb = _rule(db, None, "permit", src="10.1.0.0 0.0.0.255", dst="10.2.0.0 0.0.0.255",
               protocol="tcp", dst_port="eq 502", dst_zone="wan1", firewall_id=b.id)
    assert [f for f in _check_asymmetric_permits(db, a, b, ia, ib, [ra, other], [rb]) if f] == []
    # without the peer rule: only the on-link rule is flagged
    out = [f for f in _check_asymmetric_permits(db, a, b, ia, ib, [ra, other], []) if f]
    assert [f.rule_id for f in out] == [ra.id]


def test_deny_naming_interface_recognised_with_zone_label(db):
    a, b = _xfw(db, "A"), _xfw(db, "B")
    i = _xif(db, a, "port2", zone_label="Control LAN")
    d = _rule(db, None, "deny", src_zone="port2", firewall_id=a.id)
    assert _check_missing_deny_all(db, a, b, i, [d]) == []


@pytest.mark.parametrize("vendor", ["panos_xml", "palo_alto", "cisco_ios", "cisco_asa",
                                    "pfsense", "fortigate"])
def test_implicit_deny_vendors_info_only(db, vendor):
    a, b = _xfw(db, "A", vendor), _xfw(db, "B")
    i = _xif(db, a, "port2")
    r = _rule(db, None, "permit", src="10.0.0.0/8", firewall_id=a.id, device_type=vendor)
    out = _check_missing_deny_all(db, a, b, i, [r])
    assert len(out) == 1 and out[0].severity == "info"


def test_unknown_vendor_missing_deny_high(db):
    a, b = _xfw(db, "A", "generic"), _xfw(db, "B")
    i = _xif(db, a, "port2")
    r = _rule(db, None, "permit", src="10.0.0.0/8", firewall_id=a.id, device_type="generic")
    assert _check_missing_deny_all(db, a, b, i, [r])[0].severity == "high"


# ============================================================ T3-40 upstream

def test_upstream_two_cycle_rejected(db):
    a, b = _xfw(db, "A"), _xfw(db, "B")
    set_upstream_firewall(db, a.id, b.id)
    with pytest.raises(ValueError, match="cycle.*B#.*A#.*B#"):
        set_upstream_firewall(db, b.id, a.id)
    assert b.upstream_firewall_id is None


def test_upstream_three_cycle_rejected_and_chain_ok(db):
    a, b, c = _xfw(db, "A"), _xfw(db, "B"), _xfw(db, "C")
    set_upstream_firewall(db, a.id, b.id)
    set_upstream_firewall(db, b.id, c.id)
    with pytest.raises(ValueError, match="cycle"):
        set_upstream_firewall(db, c.id, a.id)
    assert upstream_chain(db, a.id) == ([a.id, b.id, c.id], False)
    set_upstream_firewall(db, a.id, c.id)      # re-pointing without a loop is fine


def test_upstream_walk_terminates_on_corrupt_cycle(db):
    a, b = _xfw(db, "A"), _xfw(db, "B")
    a.upstream_firewall_id, b.upstream_firewall_id = b.id, a.id   # bypass validation
    db.flush()
    chain, cyclic = upstream_chain(db, a.id)
    assert cyclic and chain == [a.id, b.id, a.id]
    state = get_topology_state(db)
    assert all(f["upstream_cycle"] for f in state["firewalls"])
    c = _xfw(db, "C")
    with pytest.raises(ValueError, match="cycle"):
        set_upstream_firewall(db, c.id, a.id)


# ===================================================== T3-41 reachability cache

def test_reachability_parses_each_rule_once(db, monkeypatch):
    for zf, zt in [(4, 3), (3, 2), (2, 1)]:
        fw = _dev(db, f"fw{zf}{zt}", zf, zt)
        for p in ("22", "80", "502"):
            _rule(db, fw, "permit", protocol="tcp", dst_port=p)
    db.commit()
    calls = {"n": 0}
    real = rm.parse_ports

    def counting(x):
        calls["n"] += 1
        return real(x)

    monkeypatch.setattr(rm, "parse_ports", counting)
    compute_reachability(db)
    assert calls["n"] == 9       # 9 rules, many level pairs / paths


# ------------------------------------------------------------------ D-10 --
def test_scada_master_that_also_serves_dnp3_is_not_an_rtu(db):
    """A master polls several outstations and accepts DNP3 from one of them
    (unsolicited); it is supervisory (L2, local_scada), not rtu_or_ied."""
    master = _host(db, "10.3.0.10")
    rtus = [_host(db, f"10.0.0.{k}") for k in (1, 2, 3)]
    for r in rtus:
        _sess(db, master, r, dst_port=20000, protocol="dnp3")
    _sess(db, rtus[0], master, dst_port=20000, protocol="dnp3")      # unsolicited
    db.commit()
    classify_hosts(db)
    db.refresh(master)
    assert master.device_type == "local_scada" and master.purdue_level == 2
    for r in rtus:
        db.refresh(r)
        assert r.device_type == "rtu_or_ied" and r.purdue_level == 1


def test_hmi_polling_two_plcs_is_supervisory_and_control_vlan_does_not_demote_it(db):
    db.add(SwitchVlan(device_name="sw", vlan_id=30, vlan_name="CONTROL_NET"))
    hmi = _host(db, "10.2.0.5", vlan="30")
    single = _host(db, "10.2.0.6", vlan="30")        # polls one PLC only
    p1, p2 = _host(db, "10.1.0.1"), _host(db, "10.1.0.2")
    _sess(db, hmi, p1), _sess(db, hmi, p2), _sess(db, single, p1)
    db.commit()
    classify_hosts(db)
    for h in (hmi, single, p1):
        db.refresh(h)
    assert hmi.device_type == "local_scada" and hmi.purdue_level == 2
    # one poll only: still a client hint, but the "CONTROL" VLAN (L1) must
    # not put a polling host below L2
    assert single.device_type == "ics_protocol_client_unclassified" and single.purdue_level == 2
    assert p1.device_type == "modbus_device" and p1.purdue_level == 1
