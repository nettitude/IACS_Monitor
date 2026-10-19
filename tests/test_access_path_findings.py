"""
Access-path review phase 4: findings from classifications
(app/parsers/access_path_findings.py, docs/access-path-review.md
"Reporting & findings").

Built on the PLANT1-FGT tabletop scenario (tests/test_access_paths.py):
  #3 broad-mgmt     L4 -> L3 any      (rule_cleartext_protocol + rule_mgmt_protocol)
  #5 remote-hmi-vip L4 -> L2 8443     (rule_it_ot_bypass + rule_mgmt_wrong_zone + rule_mgmt_protocol)
  #6 DIRECT bypass  L4 -> L2 502      (rule_it_ot_bypass)
  #9 plc-to-field   L1 -> L0 502      (no automatic finding)
"""
import re

import pytest

from app.models import CHECK_TYPE_REFERENCE, AccessPathTag, Finding, Firewall, FirewallRule
from app.parsers import alert_engine as ae
from app.parsers.access_path_findings import (
    CHECK_PERMISSIVE, sync_findings_for_tags, sync_site_findings,
)
from app.parsers.access_paths import classify_access_paths, enumerate_access_paths
from tests.test_access_paths import (  # noqa: F401  (db fixture re-used)
    PLANT1_CFG, PLANT1_LEVELS, _ingest, _site, db,
)
from tests.test_access_paths_overlay import (
    FIELD, HISTORIAN, HMI_VIP, OT_L3, _host, _plant, _sess,
)

ZERO = {"raised": 0, "confirmed": 0, "acknowledged": 0, "reopened": 0, "closed": 0}


def _key(db, sid, pid):
    rows = [p for p in enumerate_access_paths(db, sid)["paths"]
            if p["direction"] != "composed" and [c["policy_id"] for c in p["chain"]] == [pid]]
    assert len(rows) == 1, rows
    return rows[0]["tag_key"]


def _classify(db, sid, key, cls, note=None, by=None):
    item = {"tag_key": key, "classification": cls}
    if note is not None:
        item["note"] = note
    if by is not None:
        item["classified_by"] = by
    classify_access_paths(db, sid, [item])
    db.commit()
    return sync_findings_for_tags(db, sid, [key])


def _auto(db, sid, check, pid):
    rows = [f for f in db.query(Finding).filter(Finding.site_id == sid,
                                                Finding.check_name == check)
            if (f.detail or {}).get("policy_id") == pid and not (f.detail or {}).get("manual")]
    assert len(rows) == 1, [(f.id, f.status) for f in rows]
    return rows[0]


def _manual(db, sid, check, key, status=None):
    rows = [f for f in db.query(Finding).filter(Finding.site_id == sid,
                                                Finding.check_name == check)
            if (f.detail or {}).get("access_path_tag") == key]
    if status is not None:
        rows = [f for f in rows if f.status == status]
    return rows


@pytest.fixture
def plant(db):
    sid, hosts = _plant(db)
    ae.run_periodic_reviews(db, site_id=sid)
    return sid, hosts


# ================================================================ permissive
def test_permissive_raises_finding_and_is_idempotent(db, plant):
    sid, _ = plant
    key = _key(db, sid, "3")
    res = _classify(db, sid, key, "permissive", note="too broad", by="alice")
    assert res == {**ZERO, "raised": 1}
    [f] = _manual(db, sid, CHECK_PERMISSIVE, key)
    assert f.status == "open" and f.severity == "medium"
    assert f.title == "Permissive policy: PLANT1-FGT #3 broad-mgmt (L4 → L3, any)"
    assert f.category == "periodic_review" and f.site_id == sid
    d = f.detail
    assert d["access_path_tag"] == key and d["note"] == "too broad"
    assert d["classified_by"] == "alice"
    assert d["path"]["src"]["level"] == 4 and d["path"]["dst"]["level"] == 3
    assert d["service"] == ["any"]
    assert [c["policy_id"] for c in d["chain"]] == ["3"]
    assert {"permit_any", "cleartext_protocol", "mgmt_protocol"} <= set(d["flags"])
    assert d["traffic"]["status"] == "no_capture"
    assert f.isa62443_sr == CHECK_TYPE_REFERENCE[CHECK_PERMISSIVE][0]
    before = (f.occurrence_count, f.last_seen, f.notes, dict(f.detail))
    # idempotent: a repeat changes nothing
    assert sync_findings_for_tags(db, sid, [key]) == ZERO
    db.refresh(f)
    assert (f.occurrence_count, f.last_seen, f.notes, dict(f.detail)) == before
    assert len(_manual(db, sid, CHECK_PERMISSIVE, key)) == 1


def test_permissive_high_when_seen_and_flagged(db, plant):
    sid, h = plant
    _sess(db, h[HISTORIAN], h[OT_L3], 40100, 23)       # telnet L4 -> L3 via #3
    db.commit()
    key = _key(db, sid, "3")
    _classify(db, sid, key, "permissive")
    [f] = _manual(db, sid, CHECK_PERMISSIVE, key)
    assert f.detail["traffic"]["status"] == "seen"
    assert f.severity == "high"


# ================================================================ bypass
def test_bypass_without_auto_finding_raises_manual(db, plant):
    sid, _ = plant
    key = _key(db, sid, "9")                       # L1 -> L0, no automatic finding
    res = _classify(db, sid, key, "it_ot_bypass", note="field access", by="dave")
    assert res == {**ZERO, "raised": 1}
    [f] = _manual(db, sid, "rule_it_ot_bypass", key)
    assert f.detail["manual"] is True and f.status == "open"
    assert f.severity == "high"                     # deep-OT destination (L0)
    assert f.isa62443_sr == CHECK_TYPE_REFERENCE["rule_it_ot_bypass"][0]
    assert sync_findings_for_tags(db, sid, [key]) == ZERO


def test_bypass_manual_escalates_when_seen(db, plant):
    sid, h = plant
    l1 = _host(db, sid, "10.50.0.7", 1)
    _sess(db, l1, h[FIELD], 40200, 502)
    db.commit()
    key = _key(db, sid, "9")
    _classify(db, sid, key, "it_ot_bypass")
    [f] = _manual(db, sid, "rule_it_ot_bypass", key)
    assert f.severity == "critical"


def test_bypass_confirms_existing_auto_finding(db, plant):
    sid, _ = plant
    auto = _auto(db, sid, "rule_it_ot_bypass", "6")
    key = _key(db, sid, "6")
    res = _classify(db, sid, key, "it_ot_bypass", note="remove policy 6", by="erin")
    assert res == {**ZERO, "confirmed": 1}
    db.refresh(auto)
    assert auto.detail["manual_confirmed"] is True
    assert auto.detail["reviewer_note"] == "remove policy 6"
    assert auto.detail["classified_by"] == "erin"
    assert auto.status == "open"
    assert _manual(db, sid, "rule_it_ot_bypass", key) == []
    assert sync_findings_for_tags(db, sid, [key]) == ZERO


def test_bypass_confirm_keeps_acknowledged(db, plant):
    sid, _ = plant
    auto = _auto(db, sid, "rule_it_ot_bypass", "6")
    auto.status, auto.acknowledged_by = "acknowledged", "bob"
    db.commit()
    res = _classify(db, sid, _key(db, sid, "6"), "it_ot_bypass", note="n")
    assert res["confirmed"] == 1
    db.refresh(auto)
    assert auto.status == "acknowledged" and auto.acknowledged_by == "bob"
    assert auto.detail["manual_confirmed"] is True


def test_manual_bypass_superseded_when_auto_check_flags_policy(db):
    sid, _ = _plant(db)                                  # no review run yet
    key = _key(db, sid, "6")
    assert _classify(db, sid, key, "it_ot_bypass")["raised"] == 1
    ae.run_periodic_reviews(db, site_id=sid)             # auto finding appears
    auto = _auto(db, sid, "rule_it_ot_bypass", "6")
    assert auto.detail.get("manual_confirmed") is True
    assert _manual(db, sid, "rule_it_ot_bypass", key, status="open") == []
    [closed] = _manual(db, sid, "rule_it_ot_bypass", key)
    assert closed.status == "closed" and "superseded" in closed.notes


# ================================================================ accept
def test_exception_acknowledges_only_that_policys_findings(db, plant):
    sid, _ = plant
    key = _key(db, sid, "5")
    res = _classify(db, sid, key, "exception", note="vendor VPN", by="carol")
    assert res == {**ZERO, "acknowledged": 3}
    for check in ("rule_it_ot_bypass", "rule_mgmt_wrong_zone", "rule_mgmt_protocol"):
        f = _auto(db, sid, check, "5")
        assert f.status == "acknowledged" and f.acknowledged_by == "carol"
        assert f.notes == "Accepted exception in Access Review: vendor VPN"
        assert f.detail["acknowledged_via_tag"] == key
    # other policies untouched
    assert _auto(db, sid, "rule_it_ot_bypass", "6").status == "open"
    assert _auto(db, sid, "rule_cleartext_protocol", "3").status == "open"
    assert sync_findings_for_tags(db, sid, [key]) == ZERO


def test_reviewed_ok_default_actor_and_wording(db, plant):
    sid, _ = plant
    _classify(db, sid, _key(db, sid, "3"), "reviewed_ok", note="mgmt jump net")
    f = _auto(db, sid, "rule_cleartext_protocol", "3")
    assert f.status == "acknowledged" and f.acknowledged_by == "access-review"
    assert f.notes == "Accepted reviewed OK in Access Review: mgmt jump net"


def test_exception_matches_config_finding_by_policy(db, plant):
    sid, _ = plant
    fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
    for pid in ("3", "9"):
        db.add(Finding(category="config_review", check_name="config_permit_any_any_any",
                       severity="critical", status="open", title=f"Policy {pid} any",
                       detail={"policy_id": pid}, site_id=sid,
                       source_ref=f"config:{fw.id}:config_permit_any_any_any:{pid}"))
    db.commit()
    _classify(db, sid, _key(db, sid, "3"), "exception", note="x")
    by_ref = {f.source_ref: f.status for f in db.query(Finding).filter(
        Finding.check_name == "config_permit_any_any_any")}
    assert by_ref[f"config:{fw.id}:config_permit_any_any_any:3"] == "acknowledged"
    assert by_ref[f"config:{fw.id}:config_permit_any_any_any:9"] == "open"


def test_unclassify_reopens_only_findings_acknowledged_by_tag(db, plant):
    sid, _ = plant
    human = _auto(db, sid, "rule_it_ot_bypass", "6")
    human.status, human.acknowledged_by, human.notes = "acknowledged", "bob", "risk accepted"
    db.commit()
    k5 = _key(db, sid, "5")
    _classify(db, sid, k5, "exception", note="vendor VPN")
    res = _classify(db, sid, k5, "unclassified")
    assert res == {**ZERO, "reopened": 3}
    for check in ("rule_it_ot_bypass", "rule_mgmt_wrong_zone", "rule_mgmt_protocol"):
        f = _auto(db, sid, check, "5")
        assert f.status == "open" and f.acknowledged_by is None
        assert "acknowledged_via_tag" not in f.detail
    db.refresh(human)
    assert human.status == "acknowledged" and human.acknowledged_by == "bob"
    assert sync_findings_for_tags(db, sid, [k5]) == ZERO


def test_transition_chain_permissive_bypass_accept_unclassified(db, plant):
    sid, _ = plant
    key = _key(db, sid, "3")
    assert _classify(db, sid, key, "permissive")["raised"] == 1
    # permissive -> it_ot_bypass: permissive closed, manual bypass raised
    assert _classify(db, sid, key, "it_ot_bypass") == {**ZERO, "raised": 1, "closed": 1}
    assert _manual(db, sid, CHECK_PERMISSIVE, key)[0].status == "closed"
    assert len(_manual(db, sid, "rule_it_ot_bypass", key, status="open")) == 1
    # -> reviewed_ok: manual closed, the policy's auto findings (cleartext +
    # management protocol) acknowledged
    assert _classify(db, sid, key, "reviewed_ok") == {**ZERO, "acknowledged": 2, "closed": 1}
    assert _manual(db, sid, "rule_it_ot_bypass", key, status="open") == []
    # -> unclassified: acknowledgement withdrawn
    assert _classify(db, sid, key, "unclassified") == {**ZERO, "reopened": 2}
    assert _auto(db, sid, "rule_cleartext_protocol", "3").status == "open"


def test_acceptance_handed_over_to_other_tag_of_same_policy(db, plant):
    """Two tags cover policy #2 (its own row and the composed conduit #1+#2):
    withdrawing one acceptance hands the acknowledgement to the other."""
    sid, _ = plant
    fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
    f2 = Finding(category="periodic_review", check_name="rule_cleartext_protocol",
                 severity="medium", status="open", title="policy 2", site_id=sid,
                 source_ref="test-p2", detail={"policy_id": "2", "vdom": None,
                                               "firewall_id": fw.id})
    db.add(f2)
    db.commit()
    k2 = _key(db, sid, "2")
    kc = next(p["tag_key"] for p in enumerate_access_paths(db, sid)["paths"]
              if p["direction"] == "composed")
    classify_access_paths(db, sid, [{"tag_key": k2, "classification": "exception"},
                                    {"tag_key": kc, "classification": "reviewed_ok"}])
    db.commit()
    assert sync_findings_for_tags(db, sid, [k2, kc])["acknowledged"] == 1
    db.refresh(f2)
    first = f2.detail["acknowledged_via_tag"]
    gone = k2 if first == k2 else kc
    stays = kc if gone == k2 else k2
    assert _classify(db, sid, gone, "unclassified") == ZERO
    db.refresh(f2)
    assert f2.status == "acknowledged" and f2.detail["acknowledged_via_tag"] == stays
    assert _classify(db, sid, stays, "permissive")["reopened"] == 1
    db.refresh(f2)
    assert f2.status == "open"


# ================================================================ periodic
def test_periodic_review_does_not_undo_exception_or_manual(db, plant):
    sid, h = plant
    k5, k9, k3 = _key(db, sid, "5"), _key(db, sid, "9"), _key(db, sid, "3")
    _classify(db, sid, k5, "exception", note="vendor VPN")
    _classify(db, sid, k9, "it_ot_bypass")
    _classify(db, sid, k3, "permissive")
    # traffic now confirms #5 (severity escalation must not re-open it)
    _sess(db, h[HISTORIAN], h[HMI_VIP], 40300, 8443)
    db.commit()
    for _ in range(2):
        ae.run_periodic_reviews(db, site_id=sid)
    active = [f for f in db.query(Finding).filter(Finding.site_id == sid,
                                                  Finding.check_name == "rule_it_ot_bypass",
                                                  Finding.status.in_(("open", "acknowledged")))
              if (f.detail or {}).get("policy_id") == "5"]
    assert len(active) == 1 and active[0].status == "acknowledged"
    assert active[0].detail["acknowledged_via_tag"] == k5
    assert len(_manual(db, sid, "rule_it_ot_bypass", k9, status="open")) == 1
    assert len(_manual(db, sid, CHECK_PERMISSIVE, k3, status="open")) == 1
    assert "_review_access_path_classifications" in ae._AUTO_RESOLVE_CHECKS


def test_periodic_review_applies_tags_to_new_auto_findings(db):
    sid, _ = _plant(db)
    key = _key(db, sid, "5")
    _classify(db, sid, key, "exception", note="ok")      # nothing to acknowledge yet
    ae.run_periodic_reviews(db, site_id=sid)
    assert _auto(db, sid, "rule_it_ot_bypass", "5").status == "acknowledged"
    assert _auto(db, sid, "rule_mgmt_wrong_zone", "5").status == "acknowledged"


def test_unscoped_periodic_run_syncs_each_site(db):
    sid, _ = _plant(db)
    key = _key(db, sid, "3")
    classify_access_paths(db, sid, [{"tag_key": key, "classification": "permissive"}])
    db.commit()
    ae.run_periodic_reviews(db)
    [f] = _manual(db, sid, CHECK_PERMISSIVE, key)
    assert f.site_id == sid and f.status == "open"


# ================================================================ orphaned
def test_orphaned_tag_closes_manual_finding(db, plant):
    sid, _ = plant
    key = _key(db, sid, "3")
    _classify(db, sid, key, "permissive")
    cfg = re.sub(r"    edit 3\n.*?    next\n", "", PLANT1_CFG, count=1, flags=re.S)
    assert '"broad-mgmt"' not in cfg
    _ingest(db, cfg, "PLANT1-FGT", sid, PLANT1_LEVELS)
    assert not db.query(FirewallRule).filter(FirewallRule.policy_name == "broad-mgmt").count()
    res = sync_findings_for_tags(db, sid, [key])
    assert res == {**ZERO, "closed": 1}
    [f] = _manual(db, sid, CHECK_PERMISSIVE, key)
    assert f.status == "closed" and "no longer in the firewall configuration" in f.notes
    assert sync_findings_for_tags(db, sid, [key]) == ZERO


def test_orphaned_tag_not_judged_when_enumeration_truncated(db, plant, monkeypatch):
    sid, _ = plant
    key = _key(db, sid, "3")
    _classify(db, sid, key, "permissive")
    monkeypatch.setenv("IACS_MAX_ACCESS_PATH_ROWS", "1")
    res = sync_site_findings(db, sid)
    assert res["_incomplete"] is True
    assert _manual(db, sid, CHECK_PERMISSIVE, key)[0].status == "open"


# ================================================================ sites
def test_site_isolation(db):
    a, _ = _plant(db, name="Plant A")
    b, _ = _plant(db, name="Plant B")
    ae.run_periodic_reviews(db, site_id=a)
    ae.run_periodic_reviews(db, site_id=b)
    ka, kb = _key(db, a, "5"), _key(db, b, "5")
    assert ka == kb                                    # identical configs, identical keys
    _classify(db, a, ka, "exception", note="A only")
    _classify(db, a, _key(db, a, "3"), "permissive")
    assert _auto(db, a, "rule_it_ot_bypass", "5").status == "acknowledged"
    assert _auto(db, b, "rule_it_ot_bypass", "5").status == "open"
    assert _auto(db, b, "rule_mgmt_wrong_zone", "5").status == "open"
    assert db.query(Finding).filter(Finding.check_name == CHECK_PERMISSIVE,
                                    Finding.site_id == b).count() == 0
    # a sync for site B with A's keys (no tags in B) changes nothing
    assert sync_findings_for_tags(db, b, [ka]) == ZERO
    assert db.query(AccessPathTag).filter(AccessPathTag.site_id == b).count() == 0


# ================================================================ registry
def test_permissive_check_registration_and_sr_mapping():
    sr, cl, sev, cat = CHECK_TYPE_REFERENCE[CHECK_PERMISSIVE]
    refs = lambda s: {x.strip() for x in s.split(",")}
    expected = (refs(CHECK_TYPE_REFERENCE["config_permit_any_any_any"][0])
                | refs(CHECK_TYPE_REFERENCE["rule_cleartext_protocol"][0]))
    assert refs(sr) == expected
    assert refs(cl) == {CHECK_TYPE_REFERENCE["config_permit_any_any_any"][1],
                        CHECK_TYPE_REFERENCE["rule_cleartext_protocol"][1]}
    assert sev == "medium" and cat == "periodic_review"
    assert CHECK_PERMISSIVE in ae._AUTO_RESOLVE_CHECKS["_review_access_path_classifications"]
    import generate_report as gr
    assert gr.check_catalogue()[CHECK_PERMISSIVE]["sr"] == sr
    assert gr.section_of(cl) == "3"
    assert CHECK_PERMISSIVE in gr._CHECK_INPUTS


def test_sync_survives_errors(db, plant, monkeypatch):
    sid, _ = plant
    key = _key(db, sid, "3")
    classify_access_paths(db, sid, [{"tag_key": key, "classification": "permissive"}])
    db.commit()

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr("app.parsers.access_paths._enumerate", boom)
    res = sync_findings_for_tags(db, sid, [key])
    assert res["error"] and res["raised"] == 0
    assert db.query(AccessPathTag).filter(AccessPathTag.tag_key == key).one().classification \
        == "permissive"
