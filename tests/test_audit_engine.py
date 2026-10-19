"""Regression tests for audit findings A-09, A-10, A-11 (alert_engine)."""
import logging

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import configure_sqlite_engine
from app.models import (
    ApprovedCommsEntry, Base, Baseline, Finding, Firewall, FirewallInterface,
    FirewallRule, FortiAnalyzerEvent, Host, NetworkSession,
)
import app.parsers.alert_engine as ae


@pytest.fixture
def db():
    logging.disable(logging.CRITICAL)
    eng = configure_sqlite_engine(create_engine("sqlite://"))
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()
    eng.dispose()
    logging.disable(logging.NOTSET)


def _fw(db, name="fw1", ifaces=(("itnet", 4), ("plcnet", 1))):
    fw = Firewall(name=name)
    db.add(fw)
    db.flush()
    for n, lvl in ifaces:
        db.add(FirewallInterface(firewall_id=fw.id, name=n, purdue_level=lvl))
    db.flush()
    return fw


def _rule(db, fw, pid="10", src="itnet", dst="plcnet", proto="tcp", port="502", **kw):
    r = FirewallRule(device_type="fortigate", device_name=fw.name if fw else kw.pop("device_name", None),
                     firewall_id=fw.id if fw else None, policy_id=pid, action="accept",
                     enabled=True, src_zone=src, dst_zone=dst, src="all", dst="all",
                     protocol=proto, dst_port=port, **kw)
    db.add(r)
    db.flush()
    return r


def _findings(db, check):
    return db.query(Finding).filter(Finding.check_name == check).order_by(Finding.id).all()


# ---------------------------------------------------------------- A-09

def test_a09_cleared_interface_level_keeps_bypass_open(db):
    fw = _fw(db)
    _rule(db, fw)
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_it_ot_bypass")] == ["open"]
    db.query(FirewallInterface).filter_by(name="itnet").update({"purdue_level": None})
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_it_ot_bypass")] == ["open"]


def test_a09_ambiguous_interface_name_keeps_bypass_open(db):
    # Rule without firewall_id: resolved site-wide while the name is unique.
    fw = _fw(db)
    r = _rule(db, fw)
    r.firewall_id = None
    r.device_name = None
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_it_ot_bypass")] == ["open"]
    _fw(db, "fw2", ifaces=(("itnet", 2),))  # second firewall: "itnet" now ambiguous
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_it_ot_bypass")] == ["open"]


def test_a09_junk_rule_does_not_block_other_auto_resolve(db):
    fw = _fw(db)
    good = _rule(db, fw, pid="10")
    _rule(db, fw, pid="99", src="nosuchzone")  # permanently unresolvable
    db.commit()
    ae.run_periodic_reviews(db)
    assert len(_findings(db, "rule_it_ot_bypass")) == 1
    good.dst_zone = "itnet"  # fully evaluated, no longer a bypass
    db.commit()
    ae.run_periodic_reviews(db)
    f = _findings(db, "rule_it_ot_bypass")[0]
    assert f.status == "closed" and "Auto-resolved" in (f.notes or "")


def test_a09_deleted_rule_still_auto_resolves(db):
    fw = _fw(db)
    r = _rule(db, fw)
    db.commit()
    ae.run_periodic_reviews(db)
    db.delete(r)
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_it_ot_bypass")] == ["closed"]


def test_a09_unparseable_ports_keep_mgmt_finding_open(db):
    fw = _fw(db)
    r = _rule(db, fw, port="22")
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_mgmt_wrong_zone")] == ["open"]
    r.dst_port = "%%garbage%%"
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_mgmt_wrong_zone")] == ["open"]
    r.dst_port = "502"  # parseable, no longer a mgmt port -> closes
    db.commit()
    ae.run_periodic_reviews(db)
    assert [f.status for f in _findings(db, "rule_mgmt_wrong_zone")] == ["closed"]


def test_a09_auto_resolve_skips_only_unevaluated_identity(db):
    def mk(key):
        f = Finding(check_name="rule_it_ot_bypass", category="periodic_review", status="open",
                    severity="high", title="t", source_ref="ref-" + key,
                    detail={"rule_key": key, "firewall_id": 1, "device_name": "fw1"})
        db.add(f)
        return f
    keep, close = mk("10"), mk("11")
    db.flush()
    n = ae._auto_resolve(db, "x", ("rule_it_ot_bypass",), set(), {("10", 1, "fw1")})
    assert n == 1 and keep.status == "open" and close.status == "closed"


# ---------------------------------------------------------------- A-10

class _E:
    def __init__(self, protocol, port=None, end=None, conduit=None):
        self.protocol, self.dst_port, self.dst_port_end, self.conduit = protocol, port, end, conduit


def test_a10_icmp_entry_never_covers_tcp():
    assert ae._approved_coverage([_E("icmp")], "tcp", None) == (False, [])
    assert ae._approved_coverage([_E("gre")], "udp", None) == (False, [])
    assert ae._approved_coverage([_E("any")], "tcp", None) == (True, [])
    assert ae._approved_coverage([_E(None, 502)], "tcp", None) == (False, [(502, 502)])


def test_a10_transport_any_rule_needs_tcp_and_udp():
    assert ae._approved_coverage([_E("tcp", 502)], None, None) == (False, [])
    assert ae._approved_coverage([_E("tcp", 502), _E("udp", 502)], None, None) == (False, [(502, 502)])
    assert ae._approved_coverage([_E("tcp"), _E("udp")], None, None) == (True, [])


def _baseline(db, *entries):
    b = Baseline(name="b", is_active=True)
    db.add(b)
    db.flush()
    for proto, port in entries:
        db.add(ApprovedCommsEntry(baseline_id=b.id, src="any", dst="any", protocol=proto, dst_port=port))
    db.flush()
    return b


def test_a10_icmp_entry_does_not_suppress_drift(db):
    fw = _fw(db)
    _rule(db, fw, port="502")
    _baseline(db, ("icmp", None))
    db.commit()
    out = ae.review_rule_conduit_drift(db)
    assert len(out) == 1 and out[0].detail["uncovered_by_transport"] == {"tcp": "502"}


def test_a10_any_transport_rule_reports_uncovered_udp(db):
    fw = _fw(db)
    _rule(db, fw, proto="any", port="502")
    _baseline(db, ("tcp", 502))
    db.commit()
    out = ae.review_rule_conduit_drift(db)
    assert len(out) == 1
    assert out[0].detail["uncovered_by_transport"] == {"udp": "502"}
    assert "udp/502" in out[0].title


def test_a10_negative_matching_entries_cover(db):
    fw = _fw(db)
    _rule(db, fw, proto="any", port="502")
    _rule(db, fw, pid="11", proto="tcp", port="22")
    _baseline(db, ("tcp", 502), ("udp", 502), ("any", 22))
    db.commit()
    assert ae.review_rule_conduit_drift(db) == []


# ---------------------------------------------------------------- A-11

def _ev(db, src, dst, action="accept"):
    e = FortiAnalyzerEvent(source_type="api_push", log_type="traffic", action=action,
                           src_ip=src, dst_ip=dst, dst_port=3389)
    db.add(e)
    db.flush()
    return ae.evaluate_event(e, db)


@pytest.fixture
def hosts(db):
    db.add_all([Host(ip="10.40.0.5", purdue_level=4), Host(ip="10.50.0.5", purdue_level=5),
                Host(ip="10.20.0.5", purdue_level=2), Host(ip="10.35.0.5", purdue_level=3.5),
                Host(ip="10.30.0.5", purdue_level=3), Host(ip="10.10.0.5", purdue_level=1)])
    db.flush()


def _bypass(out):
    return [f for f in out if f.check_name == "it_ot_bypass"]


def test_a11_realtime_l4_to_l2_high(db, hosts):
    out = _bypass(_ev(db, "10.40.0.5", "10.20.0.5"))
    assert len(out) == 1 and out[0].severity == "high"
    out = _bypass(_ev(db, "10.20.0.5", "10.50.0.5"))  # reverse direction, L5
    assert len(out) == 1 and out[0].severity == "high"


def test_a11_realtime_old_cases_unchanged(db, hosts):
    out = _bypass(_ev(db, "10.40.0.5", "10.10.0.5"))
    assert len(out) == 1 and out[0].severity == "critical"
    key = ae._dedup_key("it_ot_bypass", {
        "src_ip": "10.40.0.5", "dst_ip": "10.10.0.5", "dst_port": 3389, "policy_id": None,
        "src_level": 4, "dst_level": 1, "detection": "purdue_level"})
    assert out[0].source_ref == key
    assert len(_bypass(_ev(db, "10.35.0.5", "10.10.0.5"))) == 1   # DMZ -> L1 still bypass


def test_a11_realtime_negatives(db, hosts):
    assert _bypass(_ev(db, "10.35.0.5", "10.20.0.5")) == []   # DMZ -> L2: mgmt/remote checks
    assert _bypass(_ev(db, "10.30.0.5", "10.20.0.5")) == []   # L3 -> L2 adjacent
    assert _bypass(_ev(db, "10.40.0.5", "10.30.0.5")) == []   # L4 -> L3
    assert _bypass(_ev(db, "10.40.0.5", "10.20.0.5", action="deny")) == []


def test_a11_rule_twin_l4_to_l2(db):
    fw = _fw(db, ifaces=(("itnet", 4), ("scada", 2), ("dmz", 3.5)))
    _rule(db, fw, dst="scada")
    _rule(db, fw, pid="11", src="dmz", dst="scada", port="502")
    db.commit()
    out = ae.review_rule_it_ot_bypass(db)
    assert len(out) == 1
    f = out[0]
    assert f.detail["policy_id"] == "10" and f.severity == "medium"
    assert f.detail["bypass_kind"] == "l2" and f.detail["dst_ot_levels"] == [2]


def test_a11_rule_twin_deep_ot_unchanged(db):
    fw = _fw(db)
    _rule(db, fw)
    db.commit()
    out = ae.review_rule_it_ot_bypass(db)
    assert len(out) == 1 and out[0].severity == "high"
    assert out[0].detail["bypass_kind"] == "deep_ot"
    assert out[0].title.startswith("IT/OT boundary bypass: direct IT 'itnet' (L4) → deep-OT 'plcnet' (L1)")


def test_a11_session_l4_to_l2(db, hosts):
    src = db.query(Host).filter_by(ip="10.40.0.5").one()
    dst = db.query(Host).filter_by(ip="10.20.0.5").one()
    dmz = db.query(Host).filter_by(ip="10.35.0.5").one()
    db.add(NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=443, transport="tcp"))
    db.add(NetworkSession(src_host_id=dmz.id, dst_host_id=dst.id, dst_port=22, transport="tcp"))
    db.flush()
    out = ae.review_ns_it_ot_bypass(db)
    assert len(out) == 1 and out[0].severity == "high" and out[0].detail["dst_port"] == 443
