"""
Findings workbook (owner, 2026-10-14): an xlsx export of the findings that is the
base of the import updating status, name and notes, so a clean report can be
produced.  GET /findings/export.xlsx, POST /findings/import.xlsx (dry run first).
"""
import contextlib
import io

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Finding, Site


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'wb.db'}", connect_args={"check_same_thread": False})
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
    ids = {}
    for key, site, check, status, title in (
            ("open", a, "rule_it_ot_bypass", "open", "IT to OT bypass policy 20"),
            ("ack", a, "unknown_device", "acknowledged", "Unknown device 10.0.0.9"),
            ("closed", a, "config_no_timezone", "closed", "No timezone set"),
            ("fp", a, "config_weak_tls_version", "false_positive", "Weak TLS on admin GUI"),
            ("excl", a, "config_default_hostname", "open", "Default hostname"),
            ("other", b, "rule_it_ot_bypass", "open", "Site B finding")):
        f = Finding(site_id=site.id, category="periodic_review", check_name=check, severity="high", status=status,
                    title=title, detail={}, acknowledged_by="bob" if status == "acknowledged" else None,
                    false_positive_reason="test rig" if status == "false_positive" else None, notes="first note")
        s.add(f)
        s.flush()
        ids[key] = f.id
    s.commit()
    sid = (a.id, b.id)
    s.close()
    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        c.put("/reports/check-selection", params={"site_id": a.id}, json={"exclude": ["config_default_hostname"]})
        try:
            yield c, sid, ids
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _export(c, sid, **params):
    r = c.get("/findings/export.xlsx", params={"site_id": sid, **params})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.openxmlformats")
    return load_workbook(io.BytesIO(r.content))


def _rows(wb):
    ws = wb["Findings"]
    head = [str(c.value).replace("(edit)", "").strip() for c in ws[1]]
    return [dict(zip(head, [c.value for c in row])) for row in ws.iter_rows(min_row=2) if row[0].value is not None]


def _save(wb) -> bytes:
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _import(c, sid, data, **params):
    r = c.post("/findings/import.xlsx", params={"site_id": sid, **params}, files={"file": ("f.xlsx", data)})
    assert r.status_code == 200, r.text
    return r.json()


def test_export_contents(api):
    c, (a, b), ids = api
    rows = _rows(_export(c, a))
    by = {r["Finding ID"]: r for r in rows}
    assert set(by) == {ids["open"], ids["ack"], ids["fp"]}                 # closed and excluded left out
    assert by[ids["ack"]]["Status"] == "Acknowledged" and by[ids["ack"]]["Acknowledged by"] == "bob"
    assert by[ids["fp"]]["False-positive reason"] == "test rig"
    assert by[ids["open"]]["Name"] in (None, "") and by[ids["open"]]["New note"] in (None, "")
    rows = _rows(_export(c, a, include_closed=True, include_excluded=True))
    by = {r["Finding ID"]: r for r in rows}
    assert set(by) == {ids["open"], ids["ack"], ids["fp"], ids["closed"], ids["excl"]}
    assert by[ids["excl"]]["Excluded from report"] == "yes" and by[ids["closed"]]["Status"] == "Closed"
    assert "How to use" in _export(c, a).sheetnames


def test_round_trip_updates_status_name_and_notes(api):
    c, (a, b), ids = api
    wb = _export(c, a)
    ws = wb["Findings"]
    head = [str(x.value).replace("(edit)", "").strip() for x in ws[1]]
    col = {h: i + 1 for i, h in enumerate(head)}
    for row in ws.iter_rows(min_row=2):
        fid = row[0].value
        if fid == ids["open"]:
            ws.cell(row=row[0].row, column=col["Status"], value="Acknowledged")
            ws.cell(row=row[0].row, column=col["Name"], value="alice")
            ws.cell(row=row[0].row, column=col["New note"], value="reviewed in Excel")
        elif fid == ids["ack"]:
            ws.cell(row=row[0].row, column=col["Status"], value="Closed")
            ws.cell(row=row[0].row, column=col["New note"], value="fixed in CR-77")
    data = _save(wb)
    # preview writes nothing
    j = _import(c, a, data, dry_run=True)
    assert j["dry_run"] and j["changed"] == 2 and j["unchanged"] == 1 and j["errors"] == []
    assert {x["finding_id"]: x["status"] for x in j["changes"]} == {ids["open"]: "acknowledged", ids["ack"]: "closed"}
    assert c.get(f"/findings", params={"site_id": a}).json() and \
        next(f for f in c.get("/findings", params={"site_id": a, "include_excluded": True}).json() if f["id"] == ids["open"])["status"] == "open"
    # apply
    j = _import(c, a, data, dry_run=False, name="default-name")
    assert not j["dry_run"] and j["changed"] == 2
    fs = {f["id"]: f for f in c.get("/findings", params={"site_id": a, "include_excluded": True}).json()}
    assert fs[ids["open"]]["status"] == "acknowledged" and fs[ids["open"]]["acknowledged_by"] == "alice"
    assert "reviewed in Excel" in fs[ids["open"]]["notes"] and "first note" in fs[ids["open"]]["notes"]   # appended
    assert fs[ids["ack"]]["status"] == "closed" and "fixed in CR-77" in fs[ids["ack"]]["notes"]
    # importing the same file again: nothing changes
    j = _import(c, a, data, dry_run=False)
    assert j["changed"] == 0 and j["unchanged"] == 3


def test_errors_are_reported_per_row(api):
    c, (a, b), ids = api
    wb = _export(c, a)
    ws = wb["Findings"]
    head = [str(x.value).replace("(edit)", "").strip() for x in ws[1]]
    col = {h: i + 1 for i, h in enumerate(head)}
    for row in ws.iter_rows(min_row=2):
        if row[0].value == ids["open"]:
            ws.cell(row=row[0].row, column=col["Status"], value="False positive")     # no reason -> refused
        elif row[0].value == ids["ack"]:
            ws.cell(row=row[0].row, column=col["Status"], value="Wontfix")            # unknown status
    n = ws.max_row + 1
    ws.cell(row=n, column=1, value=ids["other"])                                    # another site's finding
    ws.cell(row=n, column=col["Status"], value="Closed")
    ws.cell(row=n + 1, column=1, value=999999)
    ws.cell(row=n + 1, column=col["Status"], value="Closed")
    j = _import(c, a, _save(wb), dry_run=False)
    errs = {e["finding_id"]: e["error"] for e in j["errors"]}
    assert "reason is required" in errs[ids["open"]] and "unknown status" in errs[ids["ack"]]
    assert "no such finding" in errs[ids["other"]] and "no such finding" in errs[999999]
    assert j["changed"] == 0
    assert c.get("/findings", params={"site_id": b}).json()[0]["status"] == "open"
    r = c.post("/findings/import.xlsx", params={"site_id": a}, files={"file": ("x.xlsx", b"not a workbook")})
    assert r.status_code == 422
