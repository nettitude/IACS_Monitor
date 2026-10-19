"""
Checks in the compliance report (owner, 2026-10-14: "the UI needs a list of all the
findings checks and a means to deselect findings not add into the report ... grouped
into selections, such as for deselecting all of the CIS fortinet checks.  Groups of
finding not selected should be listed in the Compliance report").  Decisions: on the
Reports page, saved per site, the CIS group = every FortiGate configuration check,
optional reason.
"""
import contextlib
import io

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Finding, Site
from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
from app.report_checks import GROUPS, check_group


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    """The seeded API (also used by tests/test_cov_routes.py)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'rc.db'}", connect_args={"check_same_thread": False})
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

    s = Session()
    a, b = Site(name="A", code="a"), Site(name="B", code="b")
    s.add_all([a, b])
    s.flush()
    for site in (a, b):
        for check, sev, title in (("config_weak_tls_version", "high", "Weak TLS on admin GUI"),
                                  ("config_no_timezone", "low", "No timezone set"),
                                  ("unknown_device", "medium", "Unknown device 10.0.0.9"),
                                  ("rule_it_ot_bypass", "critical", "IT to OT bypass policy 20")):
            s.add(Finding(site_id=site.id, category="periodic_review", check_name=check, severity=sev,
                          status="open", title=title, detail={}))
    s.commit()
    ids = (a.id, b.id)
    s.close()
    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        try:
            yield c, ids
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _pdf(c, **params):
    r = c.get("/reports/compliance.pdf", params=params)
    assert r.status_code == 200, r.text
    return " ".join(" ".join((p.extract_text() or "").split()) for p in PdfReader(io.BytesIO(r.content)).pages)


def test_groups():
    assert [k for k, _l, _d in GROUPS][0] == "fortigate"
    assert all(check_group(n) == "fortigate" for n in FORTIGATE_CONFIG_CHECKS)
    assert check_group("config_mgmt_not_restricted_to_mgmt_zone") == "fortigate"
    assert check_group("rule_it_ot_bypass") == "rules" and check_group("chain_it_ot_bypass") == "paths"
    assert check_group("zone_doc_1_1") == "zones" and check_group("auth_failure", "real_time") == "syslog"
    assert check_group("session_it_ot_bypass") == "traffic" and check_group("switch_dual_gateway") == "switches"
    assert check_group("unknown_device", "periodic_review") == "network"


def test_selection_lists_every_check(api):
    c, (a, b) = api
    j = c.get("/reports/check-selection", params={"site_id": a}).json()
    names = [x["check_name"] for g in j["groups"] for x in g["checks"]]
    assert len(names) == len(set(names)) == j["checks"] >= 150
    fg = next(g for g in j["groups"] if g["key"] == "fortigate")
    assert fg["label"] == "FortiGate configuration (CIS)" and fg["state"] == "all"
    assert fg["open_findings"] == 2 and fg["total"] >= len(FORTIGATE_CONFIG_CHECKS)
    tls = next(x for x in fg["checks"] if x["check_name"] == "config_weak_tls_version")
    assert tls["included"] and tls["open_findings"] == 1 and tls["sr"] and tls["title"]


def test_exclude_group_with_reason_per_site_and_put_back(api):
    c, (a, b) = api
    fg = [x["check_name"] for g in c.get("/reports/check-selection", params={"site_id": a}).json()["groups"]
          if g["key"] == "fortigate" for x in g["checks"]]
    j = c.put("/reports/check-selection", params={"site_id": a},
              json={"exclude": [{"check_name": n, "reason": "covered by the CIS audit"} for n in fg], "by": "alice"}).json()
    assert j["excluded_added"] == len(fg) and j["excluded"] == len(fg)
    g = next(x for x in j["groups"] if x["key"] == "fortigate")
    assert g["state"] == "none" and g["checks"][0]["reason"] == "covered by the CIS audit"
    assert g["checks"][0]["excluded_by"] == "alice"
    # site B unchanged
    assert c.get("/reports/check-selection", params={"site_id": b}).json()["excluded"] == 0
    # one back in: the group is partial
    j = c.put("/reports/check-selection", params={"site_id": a}, json={"include": ["config_weak_tls_version"]}).json()
    assert j["included_again"] == 1 and next(x for x in j["groups"] if x["key"] == "fortigate")["state"] == "some"
    assert c.put("/reports/check-selection", params={"site_id": a}, json={"exclude": ["no_such_check"]}).status_code == 422


def test_pdf_leaves_excluded_checks_out_and_lists_them(api):
    c, (a, b) = api
    full = _pdf(c, site_id=a)
    assert "Weak TLS on admin GUI" in full and "Checks Excluded from this Report" not in full
    fg = [x["check_name"] for g in c.get("/reports/check-selection", params={"site_id": a}).json()["groups"]
          if g["key"] == "fortigate" for x in g["checks"]]
    c.put("/reports/check-selection", params={"site_id": a},
          json={"exclude": [{"check_name": n, "reason": "covered by the CIS audit"} for n in fg], "by": "alice"})
    c.put("/reports/check-selection", params={"site_id": a}, json={"exclude": [{"check_name": "unknown_device"}]})
    text = _pdf(c, site_id=a)
    assert "Weak TLS on admin GUI" not in text and "No timezone set" not in text
    assert "IT to OT bypass policy 20" in text                       # not excluded
    assert "Checks Excluded from this Report" in text
    assert "FortiGate configuration (CIS)" in text and "covered by the CIS audit" in text
    assert "Network & asset reviews" in text                         # the single excluded check's group
    assert "excluded from this report" in text                       # executive summary note
    # site B and the all_checks override still show everything
    assert "Weak TLS on admin GUI" in _pdf(c, site_id=b)
    assert "Weak TLS on admin GUI" in _pdf(c, site_id=a, all_checks=True)


def test_closed_findings_have_their_own_section(api):
    """Owner 2026-10-14: closed findings are listed in a 'Closed Findings' section when
    'Include closed findings' is ticked - never among the findings in scope."""
    from app.models import Finding
    c, (a, b) = api
    fid = c.get("/findings", params={"site_id": a, "check_name": "config_no_timezone"}).json()[0]["id"]
    assert c.patch(f"/findings/{fid}/status", params={"status": "closed", "notes": "fixed in change 42"}).status_code == 200
    text = _pdf(c, site_id=a)
    assert "Closed Findings" not in text and "No timezone set" not in text
    text = _pdf(c, site_id=a, include_closed=True)
    i = text.index("Closed Findings", text.index("One entry per check"))   # the section, not the summary's mention
    assert "No timezone set" not in text[:i] and "No timezone set" in text[i:]
    assert "fixed in change 42" in text[i:] and "1 closed finding(s) are listed in their own section" in text
    assert "Weak TLS on admin GUI" in text[:i]                         # open findings stay in scope
