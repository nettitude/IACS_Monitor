"""
Tests for the Phase 6 FirewallRule-based twin checks in
app/parsers/alert_engine.py (T1-12 .. T1-16):

  review_rule_cleartext_protocols, review_rule_cleartext_creds,
  review_rule_ot_it_dependency, review_rule_mgmt_wrong_zone,
  review_rule_it_ot_bypass, review_rule_conduit_drift
  + helpers _parse_rule_ports, _RuleZoneResolver, _rule_traffic_confirmed.

Topology used by most tests (firewall "FGT1"):
  port1  L3 (alias "corp")      FirewallZone IT_ZONE = {port1}
  port2  L1                     FirewallZone OT_ZONE = {port2, port3}
  port3  L2
  port4  L4 (zone_label "Enterprise")
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import (
    ApprovedCommsEntry, Baseline, Finding, Firewall, FirewallInterface,
    FirewallRule, FirewallZone, Host, NetworkSession,
)
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import (
    _parse_rule_ports, _rule_zone_purdue, _rule_traffic_confirmed,
    escalation_count,
    review_rule_cleartext_creds, review_rule_conduit_drift,
    review_rule_cleartext_protocols, review_rule_it_ot_bypass,
    review_rule_mgmt_wrong_zone, review_rule_ot_it_dependency,
    run_periodic_reviews,
)

ANY = [(0, 65535)]


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def fw(db):
    fw = Firewall(name="FGT1", device_name="FGT1", vendor="fortigate")
    db.add(fw)
    db.flush()
    for name, lvl, alias, label in [
        ("port1", 3, "corp", None),
        ("port2", 1, None, None),
        ("port3", 2, None, None),
        ("port4", 4, None, "Enterprise"),
    ]:
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl,
                                 alias=alias, zone_label=label))
    for zone, iface in [("IT_ZONE", "port1"), ("OT_ZONE", "port2"), ("OT_ZONE", "port3")]:
        db.add(FirewallZone(device_name="FGT1", interface_name=iface, zone_name=zone))
    db.flush()
    return fw


def _rule(db, fw=None, src_zone="IT_ZONE", dst_zone="OT_ZONE", dst_port="23",
          protocol="tcp", action="permit", device_name="FGT1", policy_id="10",
          conduit=None):
    r = FirewallRule(
        firewall_id=fw.id if fw is not None else None,
        device_name=device_name, device_type="fortigate", policy_id=policy_id,
        src_zone=src_zone, dst_zone=dst_zone, src="all", dst="all",
        protocol=protocol, dst_port=dst_port, action=action, conduit=conduit,
    )
    db.add(r)
    db.flush()
    return r


def _session(db, src_level, dst_level, dst_port, transport="tcp"):
    src = Host(ip=f"10.{src_level}.0.{dst_port % 250 + 1}", purdue_level=src_level)
    dst = Host(ip=f"10.{dst_level}.1.{dst_port % 250 + 1}", purdue_level=dst_level)
    db.add_all([src, dst])
    db.flush()
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=dst_port,
                       transport=transport)
    db.add(s)
    db.flush()
    return s


def _baseline(db, entries):
    b = Baseline(name="b1", is_active=True)
    db.add(b)
    db.flush()
    for port, proto, conduit in entries:
        db.add(ApprovedCommsEntry(baseline_id=b.id, src="10.0.0.0/8", dst="10.0.0.0/8",
                                  dst_port=port, protocol=proto, conduit=conduit))
    db.flush()
    return b


def _only(findings, check_name=None):
    assert len(findings) == 1, findings
    f = findings[0]
    if check_name:
        assert f.check_name == check_name
    return f


# ─── port parser ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    (None, ANY), ("", ANY), ("any", ANY), ("ALL", ANY), ("  Any ", ANY),
    ("22", [(22, 22)]),
    ("1-1024", [(1, 1024)]),
    ("80,443", [(80, 80), (443, 443)]),
    ("80 443", [(80, 80), (443, 443)]),
    ("80,1000-2000", [(80, 80), (1000, 2000)]),
    ("eq 22", [(22, 22)]),
    ("eq telnet", [(23, 23)]),
    ("range 1 1024", [(1, 1024)]),
    ("gt 1023", [(1024, 65535)]),
    ("lt 1024", [(0, 1023)]),
    ("neq 53", [(0, 52), (54, 65535)]),
    ("www", [(80, 80)]), ("ftp-data", [(20, 20)]), ("netbios-ssn", [(139, 139)]),
    ("domain", [(53, 53)]), ("snmptrap", [(162, 162)]), ("sqlnet", [(1521, 1521)]),
    ("isakmp", [(500, 500)]), ("bgp", [(179, 179)]), ("lpd", [(515, 515)]),
    ("HTTP", [(80, 80)]), ("HTTPS", [(443, 443)]), ("TELNET", [(23, 23)]),
    ("FTP", [(21, 21)]), ("SSH", [(22, 22)]), ("SNMP", [(161, 161)]),
    ("RDP", [(3389, 3389)]), ("DNS", [(53, 53)]), ("SMB", [(445, 445)]),
    ("SAMBA", [(139, 139)]), ("modbus", [(502, 502)]), ("vnc", [(5900, 5900)]),
    ("['502', '102']", [(502, 502), (102, 102)]),
    ("502:1024-65535", [(502, 502)]),
    ("80-80", [(80, 80)]),
    ("eq www range 1000 1010", [(80, 80), (1000, 1010)]),
    ("garbage", None), ("70000", None), ("eq", None), ("1024-1", None),
    ("PING", None),
])
def test_parse_rule_ports(raw, expected):
    assert _parse_rule_ports(raw) == expected


def test_parse_rule_ports_partial_keeps_parsed_tokens():
    assert _parse_rule_ports("80,CUSTOM_SVC") == [(80, 80)]


# ─── zone resolver ────────────────────────────────────────────────────────────

class TestZoneResolver:
    def test_fortigate_zone_name_via_firewallzone(self, db, fw):
        r = _rule(db, fw)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "OT_ZONE") == {1, 2}
        assert res.resolve(r, "IT_ZONE") == {3}

    def test_interface_list_name_alias_label(self, db, fw):
        r = _rule(db, fw)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "port1,port2") == {1, 3}
        # MP-05 (C-05 parity): a side is a comma-joined list and a name may
        # contain spaces, so "port1 port3" is ONE (unknown) name, never two
        assert res.resolve(r, "port1, port3") == {2, 3}
        assert res.resolve_checked(r, "port1 port3") == (set(), False)
        assert res.resolve(r, "corp") == {3}
        assert res.resolve(r, "Enterprise") == {4}

    def test_any_is_all_levels_on_firewall(self, db, fw):
        other = Firewall(name="FGT2", vendor="fortigate")
        db.add(other)
        db.flush()
        db.add(FirewallInterface(firewall_id=other.id, name="x", purdue_level=0))
        db.flush()
        r = _rule(db, fw)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "any") == {1, 2, 3, 4}
        assert res.resolve(r, "") == {1, 2, 3, 4}

    def test_firewall_id_none_uses_device_name(self, db, fw):
        r = _rule(db, None, device_name="FGT1")
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "OT_ZONE") == {1, 2}
        assert res.resolve(r, "port1") == {3}

    def test_firewall_id_none_unknown_device_unambiguous_names(self, db, fw):
        r = _rule(db, None, device_name=None)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "port2") == {1}
        assert res.resolve(r, "OT_ZONE") == {1, 2}  # zone defined by one device only
        assert res.resolve(r, "any") == {1, 2, 3, 4}

    def test_ambiguous_interface_name_without_firewall_unresolved(self, db, fw):
        other = Firewall(name="FGT2", vendor="fortigate")
        db.add(other)
        db.flush()
        db.add(FirewallInterface(firewall_id=other.id, name="port2", purdue_level=4))
        db.flush()
        r = _rule(db, None, device_name=None)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "port2") == set()

    def test_unresolved_and_null(self, db, fw):
        r = _rule(db, fw)
        res = _rule_zone_purdue(db)
        assert res.resolve(r, "NOPE_ZONE") == set()
        assert res.resolve(r, None) == set()
        assert res.resolve(r, "NOPE,port2") == {1}
        assert res.sides_unresolved == 2
        assert res.tokens_unresolved == 2


# ─── traffic confirmation ─────────────────────────────────────────────────────

class TestTrafficConfirmed:
    def test_requires_levels_transport_and_port(self, db):
        _session(db, 3, 1, 23, "tcp")
        assert _rule_traffic_confirmed(db, {3}, {1}, ports=[23], transport="tcp")
        assert not _rule_traffic_confirmed(db, {3}, {1}, ports=[23], transport="udp")
        assert not _rule_traffic_confirmed(db, {4}, {1}, ports=[23])
        assert not _rule_traffic_confirmed(db, {3}, {2}, ports=[23])
        assert not _rule_traffic_confirmed(db, {3}, {1}, ports=[21])
        assert not _rule_traffic_confirmed(db, set(), {1}, ports=[23])
        assert _rule_traffic_confirmed(db, {3}, {1}, port_ranges=[(1, 100)])
        assert _rule_traffic_confirmed(db, {3}, {1}, port_ranges=ANY)


# ─── per-check behaviour ──────────────────────────────────────────────────────
#
# CASES: check fn, check_name, a firing (src_zone, dst_zone, dst_port),
# base severity, escalated severity, confirming session (src_lvl, dst_lvl,
# port), and an unrelated session that must NOT escalate.

CASES = [
    pytest.param(review_rule_cleartext_protocols, "rule_cleartext_protocol",
                 ("IT_ZONE", "OT_ZONE", "23"), "medium", "critical",
                 (3, 1, 23), (4, 4, 23), id="insecure"),
    pytest.param(review_rule_cleartext_creds, "rule_cleartext_creds",
                 ("IT_ZONE", "OT_ZONE", "23"), "high", "critical",
                 (3, 2, 23), (3, 4, 23), id="cleartext"),
    pytest.param(review_rule_ot_it_dependency, "rule_ot_it_dependency",
                 ("OT_ZONE", "IT_ZONE", "53"), "low", "medium",
                 (2, 3, 53), (4, 3, 53), id="ot_it_dep"),
    pytest.param(review_rule_mgmt_wrong_zone, "rule_mgmt_wrong_zone",
                 ("IT_ZONE", "OT_ZONE", "22"), "medium", "high",
                 (3, 1, 22), (4, 1, 22), id="mgmt"),
    pytest.param(review_rule_it_ot_bypass, "rule_it_ot_bypass",
                 ("IT_ZONE", "OT_ZONE", "502"), "high", "critical",
                 (3, 1, 502), (3, 2, 502), id="bypass"),
]


@pytest.mark.parametrize("fn,check,zones,base,escalated,good,bad", CASES)
class TestRuleTwins:
    def test_fires_on_permit_with_zone_names(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones)
        f = _only(fn(db), check)
        assert f.severity == base
        assert f.detail["confirmed_by_traffic"] is False
        assert f.detail["src_purdue_levels"] and f.detail["dst_purdue_levels"]

    def test_no_fire_on_deny(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones, action="deny")
        assert fn(db) == []

    def test_interface_list_zones(self, db, fw, fn, check, zones, base, escalated, good, bad):
        iface = {"IT_ZONE": "port1,port4", "OT_ZONE": "port2,port3"}
        _rule(db, fw, iface[zones[0]], iface[zones[1]], zones[2])
        _only(fn(db), check)

    def test_firewall_id_none(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, None, *zones, device_name="FGT1")
        _only(fn(db), check)

    @pytest.mark.parametrize("port", ["any", "1-1024", None])
    def test_wide_port_specs_caught(self, db, fw, fn, check, zones, base, escalated, good, bad, port):
        _rule(db, fw, zones[0], zones[1], port)
        f = _only(fn(db), check)
        if check != "rule_it_ot_bypass":
            assert len(f.detail["matched_ports"]) >= 1

    def test_escalates_same_finding_on_matching_traffic(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones)
        f1 = _only(fn(db), check)
        db.commit()
        fid = f1.id
        _session(db, *good)
        assert fn(db) == []  # escalation is not a new finding
        db.commit()
        assert db.query(Finding).filter(Finding.check_name == check).count() == 1
        f = db.get(Finding, fid)
        assert f.severity == escalated
        assert f.detail["confirmed_by_traffic"] is True
        assert "matching traffic observed" in f.title
        assert "exploit" not in (f.detail["description"] + f.title).lower()
        assert escalation_count(db) == 1

    def test_no_escalation_for_unrelated_levels(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones)
        _session(db, *bad)
        _session(db, good[0], good[1], 9999)  # right levels, wrong port
        f = _only(fn(db), check)
        assert f.severity == base
        assert f.detail["confirmed_by_traffic"] is False

    def test_rerun_does_not_duplicate(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones)
        assert len(fn(db)) == 1
        db.commit()
        assert fn(db) == []
        assert db.query(Finding).filter(Finding.check_name == check).count() == 1

    def test_closed_finding_refires(self, db, fw, fn, check, zones, base, escalated, good, bad):
        _rule(db, fw, *zones)
        f1 = _only(fn(db), check)
        f1.status = "closed"
        db.commit()
        f2 = _only(fn(db), check)
        db.commit()
        assert f2.id != f1.id and f2.source_ref == f1.source_ref
        assert db.query(Finding).filter(Finding.check_name == check).count() == 2


@pytest.mark.parametrize("fn", [
    review_rule_cleartext_protocols, review_rule_cleartext_creds,
    review_rule_ot_it_dependency, review_rule_mgmt_wrong_zone,
    review_rule_conduit_drift,
])
def test_icmp_rules_skipped_by_port_checks(db, fw, fn):
    _baseline(db, [(502, "tcp", None)])
    _rule(db, fw, "IT_ZONE", "OT_ZONE", "any", protocol="icmp")
    _rule(db, fw, "OT_ZONE", "IT_ZONE", "any", protocol="icmp", policy_id="11")
    _rule(db, fw, "IT_ZONE", "OT_ZONE", "0", protocol=None, policy_id="12")
    assert fn(db) == []


class TestSpecificChecks:
    def test_eq_telnet_parsed(self, db, fw):
        _rule(db, fw, dst_port="eq telnet")
        f = _only(review_rule_cleartext_protocols(db))
        assert f.detail["matched_ports"] == [23]

    def test_one_finding_per_rule_lists_all_ports(self, db, fw):
        _rule(db, fw, dst_port="1-1024")
        f = _only(review_rule_cleartext_protocols(db))
        # DR-04: a TCP rule never "permits" the UDP services TFTP / SNMP
        assert f.detail["matched_ports"] == [20, 21, 23, 25, 80, 110, 143]

    def test_insecure_same_zone_skipped_but_any_any_flagged(self, db, fw):
        _rule(db, fw, "OT_ZONE", "OT_ZONE", "23")
        assert review_rule_cleartext_protocols(db) == []
        _rule(db, fw, "any", "any", "23", policy_id="20")
        _only(review_rule_cleartext_protocols(db))

    def test_cleartext_not_fired_for_it_destination(self, db, fw):
        _rule(db, fw, "OT_ZONE", "IT_ZONE", "23")
        assert review_rule_cleartext_creds(db) == []

    def test_unresolved_zone_skips_level_checks(self, db, fw):
        _rule(db, fw, "MYSTERY", "OT_ZONE", "22")
        assert review_rule_mgmt_wrong_zone(db) == []
        assert review_rule_it_ot_bypass(db) == []

    def test_bypass_needs_deep_ot(self, db, fw):
        _rule(db, fw, "IT_ZONE", "port3", "502")  # L3 -> L2 only
        assert review_rule_it_ot_bypass(db) == []

    def test_transport_mismatch_does_not_confirm(self, db, fw):
        _rule(db, fw, dst_port="23", protocol="tcp")
        _session(db, 3, 1, 23, transport="udp")
        f = _only(review_rule_cleartext_protocols(db))
        assert f.detail["confirmed_by_traffic"] is False

    def test_unresolved_src_never_confirms(self, db, fw):
        _rule(db, fw, "MYSTERY", "OT_ZONE", "23")
        _session(db, 3, 1, 23)
        f = _only(review_rule_cleartext_protocols(db))
        assert f.severity == "medium"


# ─── conduit drift ────────────────────────────────────────────────────────────

class TestConduitDrift:
    def test_no_baseline_no_findings(self, db, fw):
        _rule(db, fw, dst_port="23")
        assert review_rule_conduit_drift(db) == []

    def test_unapproved_port_fires_approved_does_not(self, db, fw):
        _baseline(db, [(502, "tcp", None)])
        _rule(db, fw, dst_port="502")
        _rule(db, fw, dst_port="23", policy_id="11")
        f = _only(review_rule_conduit_drift(db), "rule_conduit_drift")
        assert f.detail["dst_port"] == "23"
        assert f.detail["uncovered_ports"] == "23"

    def test_any_rule_and_range_rule_caught(self, db, fw):
        _baseline(db, [(502, "tcp", None)])
        _rule(db, fw, dst_port="any")
        _rule(db, fw, dst_port="500-510", policy_id="11")
        found = {f.detail["dst_port"]: f for f in review_rule_conduit_drift(db)}
        assert set(found) == {"any", "500-510"}
        assert found["500-510"].detail["uncovered_ports"] == "500-501,503-510"

    def test_any_port_approved_entry_covers_everything(self, db, fw):
        _baseline(db, [(None, "any", None)])
        _rule(db, fw, dst_port="any")
        _rule(db, fw, dst_port="23", policy_id="11")
        assert review_rule_conduit_drift(db) == []

    def test_any_port_entry_scoped_by_conduit_and_transport(self, db, fw):
        _baseline(db, [(None, "any", "cond-A"), (None, "udp", None)])
        _rule(db, fw, dst_port="23", conduit="cond-A")                 # covered
        _rule(db, fw, dst_port="23", conduit="cond-B", policy_id="11")  # udp only -> drift
        f = _only(review_rule_conduit_drift(db))
        assert f.detail["policy_id"] == "11"

    def test_dedup_key_includes_baseline(self, db, fw):
        b1 = _baseline(db, [(502, "tcp", None)])
        _rule(db, fw, dst_port="23")
        f1 = _only(review_rule_conduit_drift(db))
        b1.is_active = False
        b2 = Baseline(name="b2", is_active=True)
        db.add(b2)
        db.flush()
        db.add(ApprovedCommsEntry(baseline_id=b2.id, src="x", dst="y", dst_port=502))
        db.flush()
        f2 = _only(review_rule_conduit_drift(db))
        assert f1.source_ref != f2.source_ref
        assert f2.detail["baseline_id"] == b2.id

    def test_escalates_on_traffic_at_rule_levels_only(self, db, fw):
        _baseline(db, [(502, "tcp", None)])
        _rule(db, fw, dst_port="23")
        _session(db, 4, 4, 23)  # unrelated levels
        f = _only(review_rule_conduit_drift(db))
        assert f.severity == "medium"
        db.commit()
        _session(db, 3, 2, 23)
        assert review_rule_conduit_drift(db) == []
        db.commit()
        assert db.get(Finding, f.id).severity == "high"

    def test_rerun_and_closed_refire(self, db, fw):
        _baseline(db, [(502, "tcp", None)])
        _rule(db, fw, dst_port="23")
        f1 = _only(review_rule_conduit_drift(db))
        db.commit()
        assert review_rule_conduit_drift(db) == []
        # Acknowledged = owned by a person: the persisting drift updates it,
        # no duplicate is opened.
        f1.status = "acknowledged"
        db.commit()
        assert review_rule_conduit_drift(db) == []
        # Closed: a recurrence opens a fresh finding.
        f1.status = "closed"
        db.commit()
        f2 = _only(review_rule_conduit_drift(db))
        assert f2.id != f1.id


# ─── run_periodic_reviews integration ─────────────────────────────────────────

def test_run_periodic_reviews_builds_resolver_once_and_counts_new_only(db, fw, monkeypatch):
    _rule(db, fw, "IT_ZONE", "OT_ZONE", "23")
    calls = []
    real = ae._rule_zone_purdue
    monkeypatch.setattr(ae, "_rule_zone_purdue", lambda d: calls.append(1) or real(d))

    stats = run_periodic_reviews(db)
    assert len(calls) == 1
    assert stats["review_rule_cleartext_protocols"] == 1
    assert stats["review_rule_it_ot_bypass"] == 1
    assert stats["review_rule_mgmt_wrong_zone"] == 1   # telnet is a mgmt port too
    assert stats["review_rule_cleartext_creds"] == 1
    assert stats["review_rule_ot_it_dependency"] == 0

    # Second run: traffic now confirms -> escalations, not new findings.
    _session(db, 3, 1, 23)
    db.commit()
    stats2 = run_periodic_reviews(db)
    assert all(stats2[k] == 0 for k in stats2 if k.startswith("review_rule_"))
    sev = {f.check_name: f.severity for f in db.query(Finding).filter(
        Finding.check_name.like("rule_%"))}
    assert sev["rule_cleartext_protocol"] == "critical"
    assert sev["rule_it_ot_bypass"] == "critical"
    assert sev["rule_mgmt_wrong_zone"] == "high"
