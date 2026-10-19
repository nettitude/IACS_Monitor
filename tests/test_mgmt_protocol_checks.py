"""
Cleartext / management protocol split (owner, 2026-10-12): "rewrite the
insecure protocol rule to be Cleartext and make a different rule for
management protocol. Cleartext management protocol will be in both findings".

  rule_cleartext_protocol / cleartext_protocol   (was rule_insecure_protocol /
                                                  insecure_protocol; 3.5)
  rule_mgmt_protocol / mgmt_protocol             (new; 5.1, 5.2)

Telnet and SNMP v1/v2c are in both port lists, so they raise both findings.

Topology (firewall "FGT1"): port1 L3 = IT_ZONE, port2 L1 = OT_ZONE.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.explain import entry
from app.models import (
    CHECK_TYPE_REFERENCE, Finding, Firewall, FirewallInterface, FirewallRule,
    FirewallZone, Host, NetworkSession,
)
from app.parsers import alert_engine as ae
from app.parsers.access_path_findings import AUTO_POLICY_CHECKS
from app.parsers.alert_engine import (
    review_cleartext_protocols, review_mgmt_protocols,
    review_rule_cleartext_protocols, review_rule_mgmt_protocols,
    run_periodic_reviews,
)


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
    for name, lvl in [("port1", 3), ("port2", 1)]:
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl))
    for zone, iface in [("IT_ZONE", "port1"), ("OT_ZONE", "port2")]:
        db.add(FirewallZone(device_name="FGT1", interface_name=iface, zone_name=zone))
    db.flush()
    return fw


def _rule(db, fw, dst_port, src_zone="IT_ZONE", dst_zone="OT_ZONE", policy_id="10",
          protocol="tcp"):
    r = FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                     policy_id=policy_id, src_zone=src_zone, dst_zone=dst_zone,
                     src="all", dst="all", protocol=protocol, dst_port=dst_port,
                     action="permit")
    db.add(r)
    db.flush()
    return r


def _session(db, src_level, dst_level, dst_port, protocol="tcp-app"):
    src = Host(ip=f"10.{src_level}.0.{dst_port % 250 + 1}", purdue_level=src_level)
    dst = Host(ip=f"10.{dst_level}.1.{dst_port % 250 + 1}", purdue_level=dst_level)
    db.add_all([src, dst])
    db.flush()
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=dst_port,
                       transport="tcp", protocol=protocol)
    db.add(s)
    db.flush()
    return s


def _by_check(findings):
    out = {}
    for f in findings:
        out.setdefault(f.check_name, []).append(f)
    return out


# ─── catalogue ────────────────────────────────────────────────────────────────

def test_catalogue_names_and_mapping():
    assert "rule_insecure_protocol" not in CHECK_TYPE_REFERENCE
    assert "insecure_protocol" not in CHECK_TYPE_REFERENCE
    assert CHECK_TYPE_REFERENCE["rule_cleartext_protocol"][:3] == ("SR 7.7, SR 4.1", "3.5", "medium")
    assert CHECK_TYPE_REFERENCE["cleartext_protocol"][:3] == ("SR 7.7, SR 4.1", "3.5", "medium")
    for check in ("rule_mgmt_protocol", "mgmt_protocol"):
        assert CHECK_TYPE_REFERENCE[check] == (
            "SR 1.3, SR 5.1 RE1, SR 4.1", "5.1, 5.2", "medium", "periodic_review")
        assert entry(check)["why"]   # "Why this was flagged" text exists


def test_registered_as_twin_auto_resolved_and_acknowledged_by_access_review():
    assert "review_rule_mgmt_protocols" in {f.__name__ for f in ae._RULE_TWIN_CHECKS}
    assert ae._TWIN_CHECK_NAME["review_rule_mgmt_protocols"] == "rule_mgmt_protocol"
    assert ae._AUTO_RESOLVE_CHECKS["review_rule_mgmt_protocols"] == ("rule_mgmt_protocol",)
    assert ae._AUTO_RESOLVE_CHECKS["review_mgmt_protocols"] == ("mgmt_protocol",)
    assert ae._AUTO_RESOLVE_CHECKS["review_cleartext_protocols"] == ("cleartext_protocol", "smbv1_legacy")
    assert "rule_mgmt_protocol" in AUTO_POLICY_CHECKS


def test_cleartext_management_ports_are_in_both_lists():
    assert ae._CLEARTEXT_MGMT_PORTS == {23, 161, 162}
    assert 22 in ae._MGMT_PROTO_PORTS and 22 not in ae._CLEARTEXT_PROTO_PORTS
    assert 21 in ae._CLEARTEXT_PROTO_PORTS and 21 not in ae._MGMT_PROTO_PORTS
    # general web traffic is not a management protocol for this check
    assert not {80, 443, 8080} & set(ae._MGMT_PROTO_PORTS)


# ─── firewall rule twins ──────────────────────────────────────────────────────

@pytest.mark.parametrize("port,cleartext,mgmt", [
    ("23", "medium", "high"),      # Telnet: cleartext management -> both findings
    ("161", "medium", "high"),     # SNMP v1/v2c: both
    ("22", None, "medium"),        # SSH: management only
    ("3389", None, "medium"),      # RDP: management only
    ("21", "medium", None),        # FTP: cleartext only
    ("80", "medium", None),        # HTTP: cleartext only
    ("443", None, None),           # HTTPS: neither
])
def test_rule_twins_split(db, fw, port, cleartext, mgmt):
    _rule(db, fw, port, protocol="udp" if port == "161" else "tcp")
    ct = review_rule_cleartext_protocols(db)
    mp = review_rule_mgmt_protocols(db)
    assert [f.severity for f in ct] == ([cleartext] if cleartext else [])
    assert [f.severity for f in mp] == ([mgmt] if mgmt else [])
    if ct:
        assert ct[0].title.startswith("Cleartext protocol across zones")
    if mp:
        assert mp[0].title.startswith("Management protocol across zones")
        assert mp[0].detail["cleartext_mgmt_ports"] == ([int(port)] if mgmt == "high" else [])


def test_rule_mgmt_one_finding_per_rule_listing_every_port(db, fw):
    _rule(db, fw, "22,23,3389,5900-5901")
    (f,) = review_rule_mgmt_protocols(db)
    assert f.detail["matched_ports"] == [22, 23, 3389, 5900, 5901]
    assert f.severity == "high"                       # Telnet in the mix
    assert "SSH, Telnet, RDP, VNC permitted" in f.title   # VNC named once
    assert "Telnet is cleartext" in f.detail["description"]


def test_rule_mgmt_intra_zone_is_not_judged(db, fw):
    _rule(db, fw, "22", src_zone="OT_ZONE", dst_zone="OT_ZONE")
    assert review_rule_mgmt_protocols(db) == []


def test_rule_mgmt_escalates_to_critical_on_observed_traffic(db, fw):
    _rule(db, fw, "22")
    (f,) = review_rule_mgmt_protocols(db)
    assert f.severity == "medium"
    db.commit()
    _session(db, 3, 1, 22)
    assert review_rule_mgmt_protocols(db) == []       # escalated in place
    db.commit()
    f = db.query(Finding).filter(Finding.check_name == "rule_mgmt_protocol").one()
    assert f.severity == "critical" and f.detail["confirmed_by_traffic"] is True


# ─── PCAP sessions ────────────────────────────────────────────────────────────

def test_pcap_telnet_raises_both_findings(db):
    _session(db, 3, 1, 23, protocol="telnet")
    ct = _by_check(review_cleartext_protocols(db))
    mp = review_mgmt_protocols(db)
    assert len(ct["cleartext_protocol"]) == 1
    assert ct["cleartext_protocol"][0].title.startswith("Cleartext protocol Telnet crossing zones")
    (f,) = mp
    assert f.check_name == "mgmt_protocol" and f.severity == "high" and f.detail["cleartext"] is True


def test_pcap_ssh_is_management_only_and_same_level_skipped(db):
    _session(db, 3, 1, 22, protocol="ssh")
    _session(db, 1, 1, 3389, protocol="rdp")
    assert review_cleartext_protocols(db) == []
    (f,) = review_mgmt_protocols(db)
    assert f.detail["dst_port"] == 22 and f.severity == "medium"


# ─── periodic run: both twins, related_checks, auto-resolve ───────────────────

def test_periodic_run_raises_both_and_auto_resolves(db, fw):
    r = _rule(db, fw, "23")
    stats = run_periodic_reviews(db)
    db.commit()
    assert stats["review_rule_cleartext_protocols"] == 1
    assert stats["review_rule_mgmt_protocols"] == 1
    fs = {f.check_name: f for f in db.query(Finding).filter(Finding.status == "open")}
    assert "rule_mgmt_protocol" in fs["rule_cleartext_protocol"].detail["related_checks"]
    assert "rule_cleartext_protocol" in fs["rule_mgmt_protocol"].detail["related_checks"]

    # the policy no longer permits Telnet: both close on the next complete run
    r.dst_port = "502"
    db.commit()
    run_periodic_reviews(db)
    db.commit()
    st = {f.check_name: f.status for f in db.query(Finding).filter(
        Finding.check_name.in_(("rule_cleartext_protocol", "rule_mgmt_protocol")))}
    assert st == {"rule_cleartext_protocol": "closed", "rule_mgmt_protocol": "closed"}
