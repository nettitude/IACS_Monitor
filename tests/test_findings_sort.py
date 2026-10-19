"""Findings are listed by severity (critical, high, medium, low, info), newest
first within a severity: GET /findings, the CSV export and the PDF report."""
import csv
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
import generate_report as gr
from app.db import Base, get_db
from app.models import CHECK_TYPE_REFERENCE, Finding

ORDER = ["critical", "high", "medium", "low", "info"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'sort.db'}",
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
    with TestClient(main_mod.app) as c:
        c.Session = Session
        now = datetime.now(timezone.utc)
        ref = CHECK_TYPE_REFERENCE["shadow_rule"]
        # created oldest -> newest in a mixed severity order
        sevs = ["low", "critical", "info", "medium", "high", "critical", "low", "high"]
        with Session() as s:
            for i, sev in enumerate(sevs):
                s.add(Finding(category=ref[3], check_name="shadow_rule", severity=sev,
                              status="open", title=f"f{i} {sev}", isa62443_sr=ref[0],
                              checklist_id=ref[1], device_name="FW1",
                              created_at=now - timedelta(minutes=100 - i)))
            s.commit()
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def _rank(sev):
    return ORDER.index(sev)


def test_list_default_is_severity_then_newest(client):
    rows = client.get("/findings").json()
    assert [_rank(r["severity"]) for r in rows] == sorted(_rank(r["severity"]) for r in rows)
    crit = [r["title"] for r in rows if r["severity"] == "critical"]
    assert crit == ["f5 critical", "f1 critical"]          # newest first within a severity


def test_list_paging_keeps_severity_order(client):
    a = client.get("/findings", params={"limit": 3, "offset": 0}).json()
    b = client.get("/findings", params={"limit": 3, "offset": 3}).json()
    sev = [r["severity"] for r in a + b]
    assert sev == ["critical", "critical", "high", "high", "medium", "low"]


def test_list_sort_newest(client):
    rows = client.get("/findings", params={"sort": "newest"}).json()
    assert [r["title"][:2] for r in rows] == ["f7", "f6", "f5", "f4", "f3", "f2", "f1", "f0"]
    assert client.get("/findings", params={"sort": "bogus"}).status_code == 422


def test_export_severity_order(client):
    rows = list(csv.DictReader(io.StringIO(client.get("/findings/export").text)))
    assert [r["severity"] for r in rows] == [
        "critical", "critical", "high", "high", "medium", "low", "low", "info"]


def test_report_severity_order(client):
    with client.Session() as s:
        data = gr.collect_report_data(s)
    assert [f["severity"] for f in data["findings"]] == [
        "critical", "critical", "high", "high", "medium", "low", "low", "info"]
    fl = next(iter(next(iter(data["sections"].values())).values()))
    assert [f["severity"] for f in fl][:2] == ["critical", "critical"]


def test_report_checks_most_severe_first():
    data = {"findings": [1], "max_per_check": 5, "catalogue": {},
            "sections": {"3": {
                "a_low": [dict(severity="low", status="open", created_at=None, title="x",
                               device_name="", detail={}, isa62443_sr="SR 7.7",
                               checklist_id="3.1", fr=["FR7"], sl=1)],
                "z_crit": [dict(severity="critical", status="open", created_at=None, title="y",
                                device_name="", detail={}, isa62443_sr="SR 5.2",
                                checklist_id="3.9", fr=["FR5"], sl=1)]}}}
    story = gr.build_findings(data)

    def _texts(x):                       # every Paragraph text, through KeepTogether and Table cells (2026-10-18 layout)
        out = [str(getattr(x, "text", ""))]
        for y in getattr(x, "_content", []) or []:
            out += _texts(y)
        for row in getattr(x, "_cellvalues", []) or []:
            for cell in row:
                out += _texts(cell)
        return out
    flat = " ".join(t for x in story for t in _texts(x))
    assert flat.index("z_crit") < flat.index("a_low")


# ------------------------------------------------------- false positives (SF) --

def test_false_positive_status_api_export_and_report(client):
    rows = client.get("/findings").json()
    fid = rows[0]["id"]
    # reason is required
    assert client.patch(f"/findings/{fid}/status", params={"status": "false_positive"}).status_code == 422
    r = client.patch(f"/findings/{fid}/status", params={"status": "false_positive", "reason": "design conduit",
                                                       "acknowledged_by": "p.m"})
    assert r.status_code == 200 and r.json()["false_positive_by"] == "p.m"
    row = next(x for x in client.get("/findings").json() if x["id"] == fid)
    assert row["status"] == "false_positive" and row["false_positive_reason"] == "design conduit"
    # listed last, filterable, counted in the summary
    assert client.get("/findings").json()[-1]["id"] == fid
    assert [x["id"] for x in client.get("/findings", params={"status": "false_positive"}).json()] == [fid]
    assert client.get("/findings/summary").json()["by_status"]["false_positive"] == 1
    # CSV: own section at the end with the reason
    rows = list(csv.DictReader(io.StringIO(client.get("/findings/export").text)))
    assert rows[-1]["status"] == "false_positive" and rows[-1]["false_positive_reason"] == "design conduit"
    assert rows[-1]["false_positive_by"] == "p.m" and rows[-1]["false_positive_at"]
    # PDF: its own section, out of the findings in scope
    with client.Session() as s:
        data = gr.collect_report_data(s)
    assert [f["id"] for f in data["false_positives"]] == [fid]
    assert all(f["id"] != fid for f in data["findings"])
    assert data["sev_status"][rows[-1]["severity"]]["false_positive"] == 1
    pypdf = pytest.importorskip("pypdf")
    buf = io.BytesIO()
    gr.render_pdf(data, buf)
    text = " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(buf.getvalue())).pages)
    assert "False Positives" in text and "design conduit" in text
    # leaving the state keeps the audit trail in the notes
    r = client.patch(f"/findings/{fid}/status", params={"status": "open", "acknowledged_by": "p.m"})
    assert r.status_code == 200 and r.json()["false_positive_reason"] is None
    row = next(x for x in client.get("/findings").json() if x["id"] == fid)
    assert "was a false positive: design conduit" in (row["notes"] or "")
