"""
Report details per site (owner 2026-10-18): cover, distribution list, revision
history, constraints - stored on the Reports page, printed by the PDF.
"""
import contextlib
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'rd.db'}", connect_args={"check_same_thread": False})
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
    with TestClient(main_mod.app) as c:
        a = c.post("/sites", json={"name": "Plant A", "code": "pa"}).json()["id"]
        b = c.post("/sites", json={"name": "Plant B", "code": "pb"}).json()["id"]
        try:
            yield c, a, b, Session
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


BODY = {"client_name": "Plant A - Operations", "project_name": "Q4 firewall audit", "author": "Pat", "author_email": "pat@example.test",
        "version": "0.2", "classification": "Internal", "constraints": "Captures cover the control network only.",
        "distribution": [{"name": "Sam Lee", "role": "OT Security", "email": "sam@example.test", "side": "client"},
                         {"name": "Pat", "role": "Assessor", "email": "pat@example.test", "side": "assessor"}, {"name": "", "role": "", "email": ""}],
        "revisions": [{"version": "0.1", "date": "2026-10-16", "status": "Assessment in progress"}, {"version": "0.2", "date": "2026-10-18", "status": "Draft"}],
        "by": "pat"}


def test_details_defaults_store_and_site_scope(api):
    c, a, b, Session = api
    d = c.get("/reports/details", params={"site_id": a}).json()
    assert d["stored"] is False and d["version"] == "1.0" and d["classification"].startswith("Confidential") and d["distribution"] == []
    r = c.put("/reports/details", params={"site_id": a}, json=BODY)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["stored"] and d["client_name"] == "Plant A - Operations" and d["updated_by"] == "pat"
    assert len(d["distribution"]) == 2 and d["distribution"][1]["side"] == "assessor"      # the empty row is dropped
    assert [x["version"] for x in d["revisions"]] == ["0.1", "0.2"]
    assert c.get("/reports/details", params={"site_id": a}).json()["project_name"] == "Q4 firewall audit"
    assert c.get("/reports/details", params={"site_id": b}).json()["stored"] is False           # per site
    # a second PUT replaces every field
    r = c.put("/reports/details", params={"site_id": a}, json={"client_name": "Plant A", "distribution": [], "revisions": []})
    assert r.json()["client_name"] == "Plant A" and r.json()["distribution"] == [] and r.json()["version"] == "1.0"


def test_pdf_prints_the_details(api):
    import pypdf
    c, a, b, Session = api
    c.put("/reports/details", params={"site_id": a}, json=BODY)
    r = c.get("/reports/compliance.pdf", params={"site_id": a})
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.content)).pages)
    assert "Plant A - Operations" in text and "Q4 firewall audit" in text and "Internal" in text
    assert "Distribution List" in text and "Sam Lee" in text and "OT Security" in text
    assert "Revision History" in text and "Assessment in progress" in text
    assert "Engagement Particulars" in text and "Captures cover the control network only." in text
    assert "Contents" in text and "Appendix" in text
    # the other site keeps the defaults
    text_b = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(c.get("/reports/compliance.pdf", params={"site_id": b}).content)).pages)
    assert "Plant A - Operations" not in text_b and "Confidential Security Data (CSD)" in text_b


def test_public_layout_is_the_previous_report(api):
    """Owner 2026-10-18: the previous compliance report stays available as layout=public."""
    import pypdf
    c, a, b, Session = api
    c.put("/reports/details", params={"site_id": a}, json=BODY)
    r = c.get("/reports/compliance.pdf", params={"site_id": a, "layout": "public"})
    assert r.status_code == 200
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.content)).pages)
    assert "OT Firewall Security Review" in text and "Executive Summary" in text and "Prepared For:" in text
    assert "Distribution List" not in text and "Engagement Particulars" not in text and "Contents" not in text
    assert c.get("/reports/compliance.pdf", params={"site_id": a, "layout": "fancy"}).status_code == 422
    assert c.get("/reports/compliance.pdf", params={"site_id": a, "layout": "lrqa"}).status_code == 200
    # the LRQA layout is the default and leaves the shared styles in the template look afterwards
    text2 = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(c.get("/reports/compliance.pdf", params={"site_id": a}).content)).pages)
    assert "Distribution List" in text2 and "Executive Summary" in text2


def test_rollup_public_has_cover_and_no_placeholder_contents(api):
    """Audit 2026-10-18: the all-sites roll-up in the public layout must not print a blank cover
    and a TableOfContents placeholder; the LRQA roll-up numbers the per-site sections."""
    import pypdf
    c, a, b, Session = api
    r = c.get("/reports/compliance.pdf", params={"all_sites": "true", "layout": "public"})
    assert r.status_code == 200
    pages = [p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(r.content)).pages]
    assert "OT Firewall Security Review" in pages[0] and not any("Placeholder for table of contents" in p for p in pages)
    r = c.get("/reports/compliance.pdf", params={"all_sites": "true"})
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(r.content)).pages)
    assert "2  Site: Plant A" in text and "2.1  Findings" in text and "3.2  Analysis: Plant B" in text and "4  Appendix" in text
    assert "5  Analysis" not in text


def test_single_site_lrqa_has_no_blank_page_before_findings(api):
    import pypdf
    c, a, b, Session = api
    r = c.get("/reports/compliance.pdf", params={"site_id": a})
    pages = [(p.extract_text() or "").strip() for p in pypdf.PdfReader(io.BytesIO(r.content)).pages]
    blank = [i + 1 for i, t in enumerate(pages) if len(t.splitlines()) <= 4]       # only the footer
    assert blank == [], blank
