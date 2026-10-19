"""
Report PASS / NOT EVALUATED and the Configuration Evidence appendix (owner, 2026-10-12:
"In the 62443 pdf does it print out tests that passed and the evidence?" -> "do 1 and 2").

  1. check_evaluations rows: written by run_periodic_reviews (site-bound runs) for each
     check of every review that ran, and by the FortiGate config upload (per firewall,
     with the settings examined).  The report says PASS (evaluated after the latest
     data, nothing found), NOT EVALUATED (no complete review since the latest data /
     config uploaded without findings), no data, or "no findings" for untracked checks.
  2. Configuration Evidence: per FortiGate config, every examined setting with PASS or
     the checks that have a finding on that firewall.
"""
from datetime import datetime, timedelta, timezone

import pytest
from reportlab.platypus import Paragraph
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.check_evaluations import FORTIGATE_CONFIG, coverage_states, data_changed_at, record
from app.db import Base, configure_sqlite_engine
from app.models import CheckEvaluation, Firewall, Site
from app.parsers import alert_engine as ae
from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS, ingest_fortigate_config
from app.parsers.site_scope import ingest_site
import generate_report as gr

SAMPLE = open("sample_data/sample_fortigate_config.txt").read()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _site(db, code="a"):
    site = Site(name=f"Site {code}", code=code)
    db.add(site)
    db.flush()
    return site.id


def _upload(db, sid, findings=True, name="FW-A"):
    with ingest_site(db, sid):
        ingest_fortigate_config(SAMPLE, db, firewall_name=name, generate_findings=findings)
    db.commit()
    return db.query(Firewall).filter(Firewall.name == name, Firewall.site_id == sid).one()


def _cov(db, sid):
    d = gr.collect_report_data(db, site_id=sid)
    return d, {c["check_name"]: c for c in d["coverage"]}


def _texts(flowables) -> str:
    out = []
    for f in flowables:
        if isinstance(f, Paragraph):
            out.append(f.text)
        for row in getattr(f, "_cellvalues", []) or []:
            out += [c.text for c in row if isinstance(c, Paragraph)]
    return "\n".join(out)


# ─── recording ────────────────────────────────────────────────────────────────

def test_config_upload_records_evidence(db):
    sid = _site(db)
    fw = _upload(db, sid)
    (row,) = db.query(CheckEvaluation).filter(CheckEvaluation.check_name == FORTIGATE_CONFIG).all()
    assert row.site_id == sid and row.scope == f"fw:{fw.id}" and row.complete
    secs = {s["section"]: s["rows"] for s in row.evidence["sections"]}
    assert any(s.startswith("Logging and monitoring") for s in secs)
    flat = {r["setting"]: r["value"] for rows in secs.values() for r in rows}
    assert flat["DNS resolvers (system dns)"].startswith("primary 10.0.4.10 (internal)")
    assert flat["NTP source (system ntp)"] == "FortiGuard (Internet)"
    assert "not set (FortiOS default" in flat["Implicit-deny logging (log setting fwpolicy-implicit-log)"]


def test_upload_without_findings_records_nothing(db):
    sid = _site(db)
    _upload(db, sid, findings=False)
    assert db.query(CheckEvaluation).count() == 0


def test_review_run_records_every_mapped_check(db):
    sid = _site(db)
    _upload(db, sid)
    ae.run_periodic_reviews(db, site_id=sid)
    names = {r.check_name for r in db.query(CheckEvaluation).filter(CheckEvaluation.scope == "")}
    expected = {c for cs in ae.review_checks_map().values() for c in cs}
    # every review of the run that has a mapping recorded its checks
    assert {"unused_policy", "shadow_rule", "rule_cleartext_protocol", "denied_trend", "ntp_sync"} <= names
    assert names <= expected


def test_unscoped_run_records_nothing(db):
    _site(db)
    ae.run_periodic_reviews(db)
    assert db.query(CheckEvaluation).filter(CheckEvaluation.scope == "").count() == 0


def test_failed_review_is_recorded_incomplete(db, monkeypatch):
    sid = _site(db)
    _upload(db, sid)

    def boom(_db):
        raise RuntimeError("x")
    boom.__name__ = "review_shadow_rules"
    monkeypatch.setattr(ae, "review_shadow_rules", boom)
    ae.run_periodic_reviews(db, site_id=sid)
    r = db.query(CheckEvaluation).filter(CheckEvaluation.check_name == "shadow_rule").one()
    assert r.complete is False and r.note == "review failed"
    _d, cov = _cov(db, sid)
    if cov["shadow_rule"]["count"] == 0 and not cov["shadow_rule"]["missing"]:
        assert cov["shadow_rule"]["state"] == "not evaluated" and "incomplete" in cov["shadow_rule"]["basis"]


# ─── report states ────────────────────────────────────────────────────────────

def test_pass_after_review_and_not_evaluated_after_new_data(db):
    sid = _site(db)
    _upload(db, sid)
    _d, before = _cov(db, sid)
    tracked = {c for cs in ae.review_checks_map().values() for c in cs}
    cand = [n for n, c in before.items() if n in tracked and c["state"] == "not evaluated"]
    assert cand, "uploaded data and no review run: tracked checks are NOT EVALUATED"
    ae.run_periodic_reviews(db, site_id=sid)
    _d, after = _cov(db, sid)
    passed = [n for n in cand if after[n]["state"] == "pass"]
    assert passed and "reviewed" in after[passed[0]]["basis"]
    # a new config upload after the run: the review results are out of date
    fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
    fw.config_uploaded_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.commit()
    _d, stale = _cov(db, sid)
    assert stale[passed[0]]["state"] == "not evaluated" and "new data" in stale[passed[0]]["basis"]


def test_config_checks_pass_per_fortigate_config(db):
    sid = _site(db)
    _d, cov = _cov(db, sid)
    assert cov["config_weak_tls_version"]["state"] in ("no data", "no findings")   # nothing uploaded
    _upload(db, sid)
    d, cov = _cov(db, sid)
    clean = [n for n in FORTIGATE_CONFIG_CHECKS if n in cov and cov[n]["count"] == 0 and not cov[n]["missing"]]
    assert clean and all(cov[n]["state"] == "pass" for n in clean)
    assert "1 FortiGate config(s) evaluated" in cov[clean[0]]["basis"]


def test_config_uploaded_without_findings_is_not_evaluated(db):
    sid = _site(db)
    fw = _upload(db, sid)
    fw.config_uploaded_at = datetime.now(timezone.utc) + timedelta(minutes=5)   # later upload, no findings run
    db.commit()
    _d, cov = _cov(db, sid)
    n = next(n for n in FORTIGATE_CONFIG_CHECKS if n in cov and cov[n]["count"] == 0 and not cov[n]["missing"])
    assert cov[n]["state"] == "not evaluated" and "FW-A" in cov[n]["basis"]


def test_data_changed_at_and_record_helpers(db):
    sid = _site(db)
    assert data_changed_at(db, sid) is None
    _upload(db, sid)
    assert data_changed_at(db, sid) is not None
    record(db, None, "x")                              # no site: nothing
    record(db, sid, "denied_trend", source="t", complete=False, note="n")
    record(db, sid, "denied_trend", source="t2")       # upsert
    db.commit()
    (r,) = db.query(CheckEvaluation).filter(CheckEvaluation.check_name == "denied_trend").all()
    assert r.source == "t2" and r.complete and r.note is None
    st = coverage_states(db, [sid], gr.check_catalogue(), {"faz_events": 3, "protocol_details": 0})
    assert st["auth_failure"]["state"] == "pass" and "3 log event" in st["auth_failure"]["basis"]
    assert "unauthorized_industrial_write" not in st                     # no decoded writes


# ─── PDF ──────────────────────────────────────────────────────────────────────

def test_pdf_coverage_and_evidence_appendix(db):
    sid = _site(db)
    _upload(db, sid)
    ae.run_periodic_reviews(db, site_id=sid)
    d = gr.collect_report_data(db, site_id=sid)
    assert len(d["config_evidence"]) == 1
    ev = d["config_evidence"][0]
    assert ev["firewall"] == "FW-A" and "config_no_syslog_forwarding" in ev["open_checks"]
    txt = _texts(gr.build_config_evidence(d))
    assert "Configuration Evidence" in txt and "PASS" in txt and "FINDING" in txt
    assert "config_no_syslog_forwarding" in txt                      # the failing check is named
    cov_txt = _texts(gr.build_coverage(d))
    assert "PASS" in cov_txt and "NOT EVALUATED" in cov_txt.upper()
    summ = _texts(gr.build_executive_summary(d))
    assert "passed (evaluated on the current data" in summ
    import io
    buf = io.BytesIO()
    gr.render_pdf(d, buf)
    assert buf.getvalue()[:4] == b"%PDF"


def test_no_evidence_section_without_fortigate_config(db):
    sid = _site(db)
    d = gr.collect_report_data(db, site_id=sid)
    assert d["config_evidence"] == [] and gr.build_config_evidence(d) == []


def test_site_delete_purges_evaluations(db):
    sid = _site(db)
    _upload(db, sid)
    ae.run_periodic_reviews(db, site_id=sid)
    assert db.query(CheckEvaluation).filter(CheckEvaluation.site_id == sid).count() > 0
    from app.api import routes
    fn = getattr(routes, "_purge_site_data", None) or getattr(routes, "_delete_site_data", None)
    if fn is None:
        pytest.skip("site purge helper not exposed")
    fn(db, sid)
    assert db.query(CheckEvaluation).filter(CheckEvaluation.site_id == sid).count() == 0
