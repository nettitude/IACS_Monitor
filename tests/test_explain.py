"""Finding explanations (app/explain.py, GET /findings/{id}/explanation)."""
from types import SimpleNamespace

import generate_report as gr
from app.checklist_rows import ROWS
from app.explain import C, explain
from app.models import CHECK_TYPE_REFERENCE


def _f(**kw):
    base = dict(id=1, check_name="config_no_admin_lockout", title="Admin account lockout not configured",
                severity="high", category="config_review", isa62443_sr="SR 1.11, SR 1.12",
                checklist_id="5.5", detail={"device_name": "FG-1"})
    base.update(kw)
    return SimpleNamespace(**base)


def test_every_check_has_why_and_fix():
    names = set(gr.check_catalogue())
    assert names <= set(C), sorted(names - set(C))
    for n in names:
        assert len(C[n]["why"]) > 40 and len(C[n]["fix"]) > 15, n


def test_every_checklist_row_is_in_the_workbook_table():
    rows = {c.strip() for v in CHECK_TYPE_REFERENCE.values() for c in str(v[1]).split(",") if c.strip()}
    # rows the app maps but the workbook does not have (explanations fall back
    # to the finding's checklist_title for them)
    assert rows - set(ROWS) == {"1.6", "7.7", "7.8", "8.10"}
    assert ROWS["2.1"]["title"].startswith("No direct IT to Level 1/2 path")


def test_config_finding_without_description():
    x = explain(_f())
    assert x["what"]["text"].startswith("Admin account lockout not configured")
    assert ("Device", "FG-1") in [tuple(p) for p in x["what"]["facts"]]
    assert "brute-forced" in x["why"]
    assert x["requirement"]["rows"][0]["title"].startswith("Account lockout")
    assert x["severity"]["reason"].startswith("Default severity")
    assert "configuration without the condition is uploaded" in x["close"]
    assert "admin-lockout-threshold" in x["verify"]


def test_path_finding_with_nat_and_recorded_reason():
    d = {"description": "The policies A #1 + B #2 ...", "path_label": "L4 x → L1 y", "allowed_by": "A #1 + B #2",
         "chain": [{"firewall_name": "A", "policy_id": "1", "policy_name": "p1"},
                   {"firewall_name": "B", "policy_id": "2", "policy_name": "p2"}],
         "path": {"src": {"level": 4, "scope": "10.10.0.0/16"}, "dst": {"level": 1, "scope": "10.30.2.11/32"}},
         "nat": [{"type": "dnat", "name": "VIP-1", "firewall": "A", "external": "10.10.0.51:44818",
                  "mapped": "10.30.2.11:44818"}],
         "traffic": {"status": "seen", "sessions": 6},
         "severity_reason": "High: the path reaches L0/L1; raised one step because seen."}
    x = explain(_f(check_name="chain_it_ot_bypass", category="periodic_review", severity="critical",
                   checklist_id="2.1, 2.2", isa62443_sr="SR 5.1 RE2, SR 5.2", detail=d))
    p = x["what"]["path"]
    assert [h["firewall"] for h in p["hops"]] == ["A", "B"] and p["nat"][0]["name"] == "VIP-1"
    assert "Path" not in [k for k, _ in x["what"]["facts"]]          # shown as the hop list
    assert x["severity"]["reason"].startswith("High: the path reaches")
    assert [r["id"] for r in x["requirement"]["rows"]] == ["2.1", "2.2"]
    assert "DMZ host" in x["resolve"]


def test_derived_severity_reason():
    x = explain(_f(check_name="rule_it_ot_bypass", category="periodic_review", severity="critical",
                   title="IT/OT boundary bypass ... [matching traffic observed]", detail={}))
    assert "seen in the capture" in x["severity"]["reason"] and "high" in x["severity"]["reason"]
    x = explain(_f(check_name="unknown_check", detail={}))
    assert x["why"] and x["resolve"]


from tests.test_access_paths import db  # noqa: E402,F401


def test_lower_reoccurrence_keeps_the_reason_of_the_higher_severity(db):
    from app.parsers import alert_engine as ae
    from tests.test_access_paths import _site
    sid = _site(db, "EX")
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, sid):
        f = ae._make_finding(db, "dead_end_permit", "t", "x", {"severity_reason": "Medium: attempts"},
                             severity="medium", dedup_evidence={"rule_key": "k"})
        db.flush()
        ae._make_finding(db, "dead_end_permit", "t", "x", {"severity_reason": "Low: none"},
                         severity="low", dedup_evidence={"rule_key": "k"})
        db.flush()
    assert f.severity == "medium" and f.detail["severity_reason"] == "Medium: attempts"


def test_row_mismatch_with_the_workbook_is_shown():
    x = explain(_f(check_name="config_no_scheduled_backup", checklist_id="7.5",
                   detail={"checklist_title": "Configuration backup scheduled and stored offsite"}))
    r = x["requirement"]["rows"][0]
    assert r["title"].startswith("Configuration backup") and r["mismatch"]
    assert r["workbook_title"].startswith("DoS protections") and "ref_62443" not in r
    assert x["verify"] is None                     # the workbook's verify text is for another check
    ok = explain(_f())["requirement"]["rows"][0]
    assert not ok["mismatch"] and ok["ref_62443"]
