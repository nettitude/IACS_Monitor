"""
Disabled firewall rules: stored with enabled=False, flagged by
review_disabled_rules (check "disabled_rule", checklist 3.8 / SR 7.7), and
excluded from every other analysis.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app.db import Base, get_db
from app.models import CHECK_TYPE_REFERENCE, FirewallInterface, FirewallRule, Finding
from app.parsers.alert_engine import (
    review_disabled_rules,
    review_rule_it_ot_bypass,
    run_periodic_reviews,
)
from app.parsers.firewall_parser import ingest_firewall_config
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.reachability import compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.topology_diff import compute_diff

SAMPLE = (Path(__file__).resolve().parent.parent / "sample_data" / "sample_fortigate_config.txt").read_text()

# Two disabled policies injected at the TOP of the policy list:
#  5  legacy IT(port3) -> OT(port1) accept ALL, logging off   -> medium
#  6  old OT -> OT-PLCs deny TELNET (address group expands)    -> low
_DISABLED = """config firewall policy
    edit 5
        set name "Legacy-IT-to-OT-Any"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic disable
        set status disable
    next
    edit 6
        set name "Old-Block-Telnet"
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "OT-PLCs"
        set service "TELNET"
        set action deny
        set status disable
    next
"""
CONFIG = SAMPLE.replace("config firewall policy\n", _DISABLED, 1)
assert CONFIG != SAMPLE


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def _ingest(db, text=CONFIG, generate_findings=False):
    stats = ingest_fortigate_config(text, db, firewall_name="FW-OT",
                                    generate_findings=generate_findings)
    # Operator-assigned Purdue levels: port1 OT L1, port2 DMZ L3, port3 IT L4.
    for iface in db.query(FirewallInterface):
        iface.purdue_level = {"port1": 1, "port2": 3, "port3": 4}.get(iface.name)
    db.commit()
    return stats


def _disabled_findings(db, status="open"):
    return (db.query(Finding)
            .filter(Finding.check_name == "disabled_rule", Finding.status == status)
            .order_by(Finding.id).all())


# ------------------------------------------------------------- storage --

def test_check_registered_as_3_8_sr_7_7():
    sr, checklist, sev, cat = CHECK_TYPE_REFERENCE["disabled_rule"]
    assert (sr, checklist, sev, cat) == ("SR 7.7", "3.8", "low", "periodic_review")


def test_fortios_disabled_policies_stored_flagged(db):
    stats = _ingest(db)
    assert stats["rules_disabled"] == 2
    dis = db.query(FirewallRule).filter(FirewallRule.enabled.is_(False)).all()
    assert {r.policy_id for r in dis} == {"5", "6"}
    # The address group expands policy 6 to several rows; all flagged.
    assert sum(1 for r in dis if r.policy_id == "6") >= 2
    assert db.query(FirewallRule).filter(FirewallRule.enabled.is_(True),
                                         FirewallRule.policy_id.in_(["5", "6"])).count() == 0


# ------------------------------------------------------------- finding --

def test_one_finding_per_logical_rule_with_severity(db):
    _ingest(db)
    review_disabled_rules(db)
    db.commit()
    fs = _disabled_findings(db)
    assert len(fs) == 2                      # not one per expanded row
    by_pid = {f.detail["policy_id"]: f for f in fs}
    legacy, telnet = by_pid["5"], by_pid["6"]
    assert legacy.severity == "medium"
    assert any("IT→OT" in r for r in legacy.detail["severity_reasons"])
    assert any("any-source" in r for r in legacy.detail["severity_reasons"])
    assert telnet.severity == "low"          # a deny: inert either way
    assert telnet.detail["rule"]["expanded_rows"] >= 2
    for f in fs:
        assert f.isa62443_sr == "SR 7.7" and f.checklist_id == "3.8"
        assert f.category == "periodic_review"
        assert "Legacy-IT-to-OT-Any" in legacy.title


def test_rerun_and_reingest_do_not_duplicate(db):
    _ingest(db)
    review_disabled_rules(db); db.commit()
    first_ids = {f.id for f in _disabled_findings(db)}
    review_disabled_rules(db); db.commit()
    assert {f.id for f in _disabled_findings(db)} == first_ids
    # Re-ingest recreates FirewallRule rows with NEW ids; the finding identity
    # (policy id / raw line) must survive that.
    _ingest(db)
    review_disabled_rules(db); db.commit()
    assert {f.id for f in _disabled_findings(db)} == first_ids


def test_closed_finding_recurs_if_rule_still_present(db):
    _ingest(db)
    review_disabled_rules(db); db.commit()
    f = _disabled_findings(db)[0]
    f.status = "closed"
    db.commit()
    review_disabled_rules(db); db.commit()
    assert len(_disabled_findings(db)) == 2
    assert len(_disabled_findings(db, status="closed")) == 1


def test_no_finding_once_rule_removed_from_config(db):
    _ingest(db, SAMPLE)
    assert review_disabled_rules(db) == []


def test_registered_in_periodic_reviews(db):
    _ingest(db)
    stats = run_periodic_reviews(db)
    assert "review_disabled_rules" in stats
    assert len(_disabled_findings(db)) == 2


def test_cisco_inactive_grouped_by_rule_identity(db):
    text = (
        "object-group network ENG\n host 10.0.1.5\n host 10.0.1.6\n"
        "ip access-list extended OT\n"
        " 10 permit tcp object-group ENG host 10.0.1.10 eq 502 inactive\n"
        " 20 deny ip any any\n"
    )
    ingest_firewall_config(text, db, vendor_hint="cisco")
    assert db.query(FirewallRule).filter(FirewallRule.enabled.is_(False)).count() == 2
    fs = review_disabled_rules(db)
    db.commit()
    assert len(fs) == 1 and fs[0].severity == "low"
    assert fs[0].detail["rule"]["expanded_rows"] == 2
    assert "inactive" in fs[0].title
    # Re-ingest: still one open finding.
    db.query(FirewallRule).delete()
    ingest_firewall_config(text, db, vendor_hint="cisco")
    assert review_disabled_rules(db) == []


# ----------------------------------------------------------- exclusion --

def test_disabled_rules_excluded_from_rule_twins(db):
    _ingest(db)
    review_rule_it_ot_bypass(db); db.commit()
    pids = {f.detail.get("policy_id") for f in
            db.query(Finding).filter(Finding.check_name == "rule_it_ot_bypass")}
    assert "5" not in pids


def test_disabled_rules_excluded_from_fortios_config_checks(db):
    _ingest(db, generate_findings=True)
    logging = db.query(Finding).filter(Finding.check_name == "config_logging_disabled").all()
    pids = {str((f.detail or {}).get("policy_id")) for f in logging}
    assert "98" in pids          # the enabled no-logging policy is still flagged
    assert "5" not in pids       # the disabled one is not


def test_disabled_rules_excluded_from_reachability(db):
    _ingest(db)
    cell = compute_reachability(db)["matrix"]["4→1"]
    # Disabled permit-any IT->OT sits first in config order; the enabled
    # explicit deny (policy 99) must still decide the verdict.
    assert cell["overall"] == "denied"


def test_disabled_rules_excluded_from_shadow_analysis(db):
    _ingest(db)
    res = find_shadowed_rules(db)
    ids = {r.id for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(False))}
    blob = repr(res)
    for rid in ids:
        assert f"'rule_id': {rid}," not in blob and f"'id': {rid}," not in blob
    pids = set()
    for s in res.get("shadows", []):
        for side in ("shadowing", "shadowed", "rule_a", "rule_b"):
            v = s.get(side)
            if isinstance(v, dict):
                pids.add(str(v.get("policy_id")))
    assert "5" not in pids and "6" not in pids


def test_disabled_rules_excluded_from_unused_rules(db):
    _ingest(db)
    disabled_ids = {r.id for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(False))}
    assert disabled_ids
    unused = compute_diff(db).get("unused_rules", [])
    assert unused                                   # enabled permits are still reported
    assert not ({u["rule_id"] for u in unused} & disabled_ids)


# ----------------------------------------------------------------- API --

@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'api.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with Session() as s:
        _ingest(s)
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def test_api_lists_disabled_rules(client):
    rows = client.get("/firewall-rules", params={"enabled": "false"}).json()
    assert rows and all(r["enabled"] is False for r in rows)
    assert {r["policy_id"] for r in rows} == {"5", "6"}
    active = client.get("/firewall-rules", params={"enabled": "true"}).json()
    assert active and all(r["enabled"] is True for r in active)
    devs = client.get("/firewall-devices").json()
    dev = devs[0] if isinstance(devs, list) else devs
    assert dev["disabled_rule_count"] >= 3 and dev["rule_count"] > 0
