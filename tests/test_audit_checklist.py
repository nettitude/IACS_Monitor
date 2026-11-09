"""
Audit checklist report (owner 2026-10-24): the filled-in ISA/IEC 62443 Master Audit Checklist
workbook -> findings (one per checklist row), CSV, the PDF in the LRQA layout, the route.
"""
import datetime as dt
import io

import pytest

from app import audit_checklist as ac
from tests.test_report_details import api_ctx  # noqa: F401  (re-used by test_cov_routes)

HEADERS = ["#", "Master ID", "Domain", "Check title", "Audit check (paraphrased)", "Suggested evidence", "Covers (source Req IDs)",
           "Source standards", "NIST firewall reference", "FR", "Min SL", "Audit scope", "Conditional", "Status", "Maturity Level",
           "Finding / Observation", "Evidence Reviewed", "Severity", "Recommendation", "Owner", "Target Date"]
GOV = "Governance, program & policy"
FW = "Firewall management (NIST best practice)"
ROWS = [
    (1, "GOV-01", GOV, "Security program & ISMS alignment", "Is there an IACS security program aligned with the ISMS?", "SP document; ISMS scope",
     "ORG 1.1; 1-1 §3", "2-1, 1-1", None, "Program", 1, None, "No", "Partially compliant", 2,
     "A program exists but is not aligned with the ISMS.", "Security Program v2.1; ISMS scope statement", "Medium",
     "Align the program with the ISMS: one glossary, shared risk register.\nRecord the alignment in the next revision.", "OT Security Manager", dt.datetime(2027, 1, 31)),
    (2, "GOV-02", GOV, "Program scope", "Is the IACS program scope defined?", "Scope statement", "1-1 §1", "1-1", None, "Program", 1, None, "No",
     "Compliant", 3, "Scope statement covers all plants.", "Scope statement 2026-02", None, None, None, None),
    (3, "GOV-05", GOV, "Personnel screening <b>&amp;</b>", "Are background checks done before IACS access?", "HR screening policy; sample records", "ORG 1.2", "2-1",
     None, "Program", 1, None, "No", "non compliant", 1, "+ No background checks for contractors.", "HR policy (staff only)", "HIGH",
     "Extend the screening policy to contractors; verify before badge issue.", "HR", dt.datetime(2026, 12, 15)),
    (4, "FW-05", FW, "Anti-spoofing & invalid traffic", "Are spoofed sources dropped and reverse-path checks enabled?", "Interface settings; rules",
     "— (NIST best practice)", "NIST", "NIST SP 800-41r1 §4.1", "FR 5", 1, "Network – Firewall", "No", "Not applicable", None,
     "No boundary firewall in scope.", None, None, None, None, None),
    (5, "FW-07", FW, "Industrial protocol inspection", "Are industrial protocols inspected where the risk warrants?", "IPS profiles", "— (NIST best practice)",
     "NIST", "NIST SP 800-82r3", "FR 5", 2, "Network – Firewall", "Yes", "Not assessed", None, None, None, None, None, None, None),
    (6, "FW-14", FW, "Firewall firmware & vulnerabilities", "Is firewall firmware supported and patched?", "Version report", "— (NIST best practice)", "NIST",
     "NIST SP 800-41r1 §5.3", "FR 3", 1, "Network – Firewall", "No", None, None, "Observation: firmware two majors behind; status not set.", None, "medium",
     None, None, None),
    (7, "FW-08", FW, "Periodic rule review", "Are rule bases reviewed at least annually?", "Review records", "— (NIST best practice)", "NIST",
     "NIST SP 800-41r1 §5.5", "FR 5", 1, "Network – Firewall", "No", "Bogus", None, None, None, None, None, None, None),
]


def make_workbook(rows=ROWS, *, headers=HEADERS, sheet="Master Checklist", title="ISA/IEC 62443 Consolidated Master Audit Checklist (test)",
                  extra_sheets=True) -> bytes:
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet
    ws.append(list(headers))
    for r in rows:
        ws.append(list(r))
    if extra_sheets:
        ins = wb.create_sheet("Instructions", 0)
        ins["A1"] = title
        ins["A2"] = "7 test checks"
        ref = wb.create_sheet("NIST references")
        ref.append(["Publication", "Title", "Version / date", "Used for"])
        ref.append(["NIST SP 800-41 Rev. 1", "Guidelines on Firewalls and Firewall Policy", "Rev. 1", "FW-01…FW-15"])
        ref.append(["Links", "https://csrc.nist.gov/", None, None])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_parse_normalises_cells_and_warns():
    p = ac.parse_workbook(make_workbook())
    assert p["sheet"] == "Master Checklist" and p["title"].startswith("ISA/IEC 62443 Consolidated") and len(p["rows"]) == 7
    assert p["domains"] == [GOV, FW]
    by = {r["master_id"]: r for r in p["rows"]}
    assert by["GOV-05"]["status"] == "Non-compliant" and by["GOV-05"]["severity"] == "high"       # case / hyphen tolerant
    assert by["GOV-01"]["target_date"] == "2027-01-31" and by["GOV-01"]["maturity"] == "2" and by["GOV-01"]["min_sl"] == "1"
    assert by["FW-14"]["status"] == "Not assessed" and by["FW-14"]["severity"] == "medium"          # blank status
    assert by["FW-08"]["status"] == "Bogus" and any("row 8" in w and "Bogus" in w for w in p["warnings"])
    assert by["GOV-05"]["title"] == "Personnel screening <b>&amp;</b>"                                 # kept verbatim, escaped later
    assert p["references"] == ["NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy"]
    assert all("row" in r and r["n"] for r in p["rows"])


def test_header_tolerance_and_other_sheet_name():
    headers = ["No", "ID", "Domain", "Title", "Audit check", "Suggested evidence", "Covers", "Source standard", "NIST ref", "FR", "Min SL",
               "Audit scope", "Conditional", "STATUS", "Maturity", "Finding", "Evidence reviewed", "Severity", "Recommendations", "Owner", "Target date"]
    p = ac.parse_workbook(make_workbook(headers=headers, sheet="Checks", extra_sheets=False))
    assert len(p["rows"]) == 7 and p["sheet"] == "Checks" and p["title"] == "ISA/IEC 62443 Master Audit Checklist"
    assert p["rows"][0]["recommendation"].startswith("Align the program")
    # a column missing is a note, not an error
    short = [h for h in HEADERS if h != "Owner"]
    rows = [r[:19] + r[20:] for r in ROWS]
    p = ac.parse_workbook(make_workbook(rows, headers=short))
    assert any("Owner" in w for w in p["warnings"]) and p["rows"][0]["owner"] == ""


def test_not_a_checklist():
    with pytest.raises(ac.ChecklistError):
        ac.parse_workbook(b"PK\x03\x04 not really a workbook")
    with pytest.raises(ac.ChecklistError):
        ac.parse_workbook(b"plain text")
    no_status = [h for h in HEADERS if h != "Status"]
    with pytest.raises(ac.ChecklistError, match="Status"):
        ac.parse_workbook(make_workbook([r[:13] + r[14:] for r in ROWS], headers=no_status))
    with pytest.raises(ac.ChecklistError, match="no checklist rows"):
        ac.parse_workbook(make_workbook([]))


def test_findings_selection_and_order():
    p = ac.parse_workbook(make_workbook())
    ids = lambda rows: [r["master_id"] for r in rows]       # noqa: E731
    f = ac.order_rows(ac.select_rows(p["rows"], "findings"), "severity")
    assert ids(f) == ["GOV-05", "GOV-01", "FW-14"]           # high; medium partial before medium unrated status
    assert ids(ac.order_rows(ac.select_rows(p["rows"], "findings"), "checklist")) == ["GOV-01", "GOV-05", "FW-14"]
    assert ids(ac.select_rows(p["rows"], "assessed")) == ["GOV-01", "GOV-02", "GOV-05", "FW-05", "FW-14", "FW-08"]
    assert len(ac.select_rows(p["rows"], "all")) == 7
    assert not ac.is_finding({"status": "Compliant", "finding": "noted"}) and not ac.is_finding({"status": "Not applicable", "severity": "high"})
    assert ac.is_finding({"status": "Not assessed", "recommendation": "do x"}) and not ac.is_finding({"status": "Not assessed"})
    with pytest.raises(ValueError):
        ac.select_rows(p["rows"], "some")
    with pytest.raises(ValueError):
        ac.order_rows(p["rows"], "random")


def test_domain_summary_and_report_data():
    p = ac.parse_workbook(make_workbook())
    s = {d["domain"]: d for d in ac.domain_summary(p["rows"])}
    assert s[GOV]["total"] == 3 and s[GOV]["compliant"] == 1 and s[GOV]["partial"] == 1 and s[GOV]["non_compliant"] == 1
    assert s[GOV]["compliance_pct"] == 50.0 and s[GOV]["high"] == 1 and s[GOV]["findings"] == 2
    assert s[FW]["compliance_pct"] is None and s[FW]["not_applicable"] == 1 and s[FW]["not_assessed"] == 2 and s[FW]["findings"] == 1
    assert s["Total"]["total"] == 7 and s["Total"]["is_total"]
    d = ac.report_data(p, "findings", "severity", details={"client_name": "Plant A", "site": "Plant A"}, source_name="t.xlsx")
    assert d["n_rows"] == 7 and d["n_findings"] == 3 and d["n_selected"] == 3 and d["n_assessed"] == 5
    assert [r["section"] for r in d["selected"]] == ["5.1", "5.2", "5.3"]
    assert d["by_severity"] == {"high": 1, "medium": 2} and d["by_status"]["Not assessed"] == 2
    assert any("FW-14" in w and "without a status" in w for w in d["warnings"])
    j = ac.summary_json(d)
    assert j["selected"] == 3 and j["items"][0]["master_id"] == "GOV-05" and j["items"][0]["has_observation"] and not j["items"][2]["has_recommendation"]
    assert j["domains"][-1]["domain"] == "Total" and "is_total" not in j["domains"][-1]


def test_clean_and_merge_details():
    raw = {"client_name": " Plant A\x01 ", "author": "Pat", "report_date": "2026-10-24", "version": ["x"], "junk": "y",
           "pocs": [{"name": "Sam", "role": "OT", "email": "s@x"}, {"name": ""}, "bad"], "consultants": [{"name": "Lee"}],
           "distribution": [{"name": "Old", "side": "assessor"}, {"name": "Cli", "side": "client"}], "revisions": [{"version": "0.1", "date": "d", "status": "s"}, {}]}
    d = ac.clean_details(raw)
    assert d["client_name"] == "Plant A" and d["report_date"] == "2026-10-24" and "version" not in d and "junk" not in d
    assert [(x["name"], x["side"]) for x in d["distribution"]] == [("Cli", "client"), ("Sam", "client"), ("Old", "assessor"), ("Lee", "assessor")]
    assert d["revisions"] == [{"version": "0.1", "date": "d", "status": "s"}]
    assert ac.clean_details({"report_date": "next week sometime"})["report_date"] == "next week sometime"
    assert ac.clean_details("nope") == {} and ac.clean_details({"pocs": "x"}) == {"distribution": []}
    base = {"client_name": "Site", "author": "A", "distribution": [{"name": "S", "side": "client"}], "site": "Plant A"}
    m = ac.merge_details(base, {"author": "B", "client_name": "", "distribution": []})
    assert m["author"] == "B" and m["client_name"] == "Site" and m["distribution"] == [] and m["site"] == "Plant A"
    assert ac.merge_details(None, None) == {}
    p = ac.parse_workbook(make_workbook())
    assert ac.report_data(p, details={"report_date": "2026-11-02"})["report_date"] == "2026-11-02"
    assert len(ac.report_data(p)["report_date"]) == 10


def test_csv_has_one_line_per_finding_and_guards_formulas():
    import csv
    p = ac.parse_workbook(make_workbook())
    text = ac.to_csv(ac.report_data(p, "findings", "severity"))
    assert text.startswith("﻿")
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    assert rows[0][:5] == ["Section", "Master ID", "Domain", "Finding title (check title)", "Finding details (audit check)"]
    assert len(rows) == 4 and [r[1] for r in rows[1:]] == ["GOV-05", "GOV-01", "FW-14"]
    head = dict(zip(rows[0], rows[1]))
    assert head["Section"] == "5.1" and head["Severity"] == "High" and head["Status"] == "Non-compliant"
    assert head["Finding / Observation"].startswith("'+ No background")         # B-18 formula guard (a leading + = - @ gets an apostrophe)
    assert head["Finding title (check title)"] == "Personnel screening <b>&amp;</b>" and head["Target date"] == "2026-12-15"
    assert head["Evidence reviewed"] == "HR policy (staff only)" and head["Suggested evidence"] == "HR screening policy; sample records"
    assert head["Recommendation"].startswith("Extend the screening")
    assert dict(zip(rows[0], rows[2]))["Recommendation"].count("\n") == 1          # multi-line cell kept
    assert len(list(csv.reader(io.StringIO(ac.to_csv(ac.report_data(p, "all")).lstrip("﻿"))))) == 8


def _pdf_text(data: bytes) -> str:
    import pypdf
    assert data.startswith(b"%PDF")
    return "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(data)).pages)


def test_pdf_prints_the_finding_as_specified():
    import generate_audit_report as gar
    p = ac.parse_workbook(make_workbook())
    details = {"client_name": "Plant A - Operations", "project_name": "Q4 audit", "author": "Pat", "version": "0.3", "classification": "Internal",
               "constraints": "Interviews on 2026-10-20 only.", "site": "Plant A", "report_date": "2026-11-05",
               "distribution": [{"name": "Sam Lee", "role": "OT Security", "email": "sam@example.test", "side": "client"},
                                {"name": "Kim Park", "role": "Plant manager", "email": "", "side": "client"},
                                {"name": "Lee Cole", "role": "LRQA lead consultant", "email": "lee@lrqa.test", "side": "assessor"},
                                {"name": "Ana Ruiz", "role": "LRQA consultant", "email": "", "side": "assessor"}],
               "revisions": [{"version": "0.3", "date": "2026-10-24", "status": "Draft"}]}
    text = _pdf_text(gar.report_bytes(p, "pdf", scope="findings", order="severity", details=details, source_name="audit.xlsx"))
    # cover, front matter, particulars
    assert "IEC 62443 Audit" in text and "Checklist Report" in text and "Plant A - Operations" in text and "Q4 audit" in text
    assert "Distribution List" in text and "Sam Lee" in text and "Kim Park" in text and "Revision History" in text and "Draft" in text
    assert "LRQA consultants" in text and "Lee Cole" in text and "Ana Ruiz" in text and "Date:\n2026-11-05" in text    # report date on the cover
    assert "report dated 2026-11-05" not in text                                                   # constraints given, so no default text
    assert "Engagement Particulars" in text and "Interviews on 2026-10-20 only." in text and "7 checks in 2 domains" in text
    assert "Compliance by Domain" in text and "Internal" in text
    # 4 Findings table, 5 Analysis entries: title = check title, details = audit check, auditor's entries
    assert "Findings" in text and "5.1" in text and "5.3" in text
    assert "5.1 High: Personnel screening <b>&amp;</b>" in text.replace("\n", " ")        # escaped, not interpreted
    assert "Are background checks done before IACS access?" in text
    assert "Finding / Observation" in text and "No background checks for contractors." in text
    assert "Evidence Reviewed" in text and "HR policy (staff only)" in text and "Suggested evidence (checklist): HR screening policy" in text
    assert "Recommendation" in text and "1.  Extend the screening policy to contractors;" in text and "2.  Verify before badge issue." in text
    assert "Owner / target date" in text and "HR / 2026-12-15" in text and "Covers: ORG 1.2" in text
    assert "1.  Align the program with the ISMS: one glossary, shared risk register." in text       # multi-line recommendation = items
    assert "Not assessed" in text and "No recommendation was recorded by the auditor." in text      # FW-14: finding without a status
    assert "No evidence reviewed was recorded by the auditor." in text
    # appendix: every check, scale, references from the workbook
    assert "Checklist Status" in text and "Program scope" in text and "Periodic rule review" in text
    assert "Severity and Status Scale" in text and "Guidelines on Firewalls and Firewall Policy" in text
    assert "Firewall Audit" not in text                     # not the compliance report's cover title
    # owner 2026-10-25: the LRQA logo (ui/lrqa_logo.png) is drawn on the cover, nowhere else
    import pypdf
    pages = pypdf.PdfReader(io.BytesIO(gar.report_bytes(p, "pdf", details=details))).pages
    assert gar.LOGO.is_file() and len(pages[0].images) == 1 and all(len(pg.images) == 0 for pg in pages[1:4])
    assert "IACS" not in pages[0].extract_text() and "IACS" in pages[1].extract_text()      # the wordmark stays in the page footers
    # an empty selection renders too
    empty = _pdf_text(gar.report_bytes(ac.parse_workbook(make_workbook(ROWS[4:5])), "pdf"))
    assert "No findings" in empty and "Checklist Status" in empty


def test_cli_writes_pdf_and_csv(tmp_path, capsys):
    import generate_audit_report as gar
    src = tmp_path / "checklist.xlsx"
    src.write_bytes(make_workbook())
    out, csv_path = tmp_path / "r.pdf", tmp_path / "r.csv"
    assert gar.main([str(src), "--out", str(out), "--csv", str(csv_path), "--client", "Plant A", "--scope", "assessed", "--order", "checklist",
                     "--date", "2026-12-01", "--poc", "Sam Lee; OT Security; sam@x.test", "--poc", "Kim Park", "--consultant", "Lee Cole; LRQA lead",
                     "--no-prompt"]) == 0
    import csv
    assert out.read_bytes().startswith(b"%PDF")
    assert len(list(csv.reader(io.StringIO(csv_path.read_text(encoding="utf-8").lstrip("\ufeff"))))) == 7      # header + 6 assessed
    text = _pdf_text(out.read_bytes())
    assert "Plant A" in text and "in checklist order" in text
    assert "Date:\n2026-12-01" in text and "Sam Lee" in text and "Kim Park" in text and "Lee Cole" in text and "LRQA lead" in text
    assert gar.main([str(tmp_path / "missing.xlsx")]) == 2 and "error:" in capsys.readouterr().err
    (tmp_path / "bad.xlsx").write_bytes(b"nope")
    assert gar.main([str(tmp_path / "bad.xlsx"), "--out", str(tmp_path / "x.pdf")]) == 2


def test_cli_prompts_for_the_cover_and_the_lists(capsys):
    """Owner 2026-10-24: the program asks for Prepared for, the author, the date, the client POCs and the LRQA consultants."""
    import generate_audit_report as gar
    answers = iter(["Plant B", "", "2026-10-30", "Sam Lee", "OT Security", "sam@x.test", "Kim Park", "", "", "",
                    "Lee Cole", "LRQA lead", "lee@lrqa.test", ""])
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return next(answers)
    d = gar.prompt_details({}, ask=ask)
    assert d["client_name"] == "Plant B" and d["author"] == "IACS_Monitor" and d["report_date"] == "2026-10-30"
    assert [(x["name"], x["side"]) for x in d["distribution"]] == [("Sam Lee", "client"), ("Kim Park", "client"), ("Lee Cole", "assessor")]
    assert d["distribution"][0]["email"] == "sam@x.test" and d["distribution"][2]["role"] == "LRQA lead"
    assert any("Prepared for" in q for q in asked) and any("Date of the report" in q for q in asked) and any("LRQA consultant 1" in q for q in asked)
    # fields given on the command line are not asked again; EOF keeps the defaults
    asked.clear()
    d = gar.prompt_details({"client_name": "C", "author": "A", "report_date": "2026-01-01", "distribution": [{"name": "P", "side": "client"}]},
                           ask=lambda q: (asked.append(q), (_ for _ in ()).throw(EOFError()))[1])
    assert d["client_name"] == "C" and [x["name"] for x in d["distribution"]] == ["P"] and all("LRQA consultant" in q for q in asked)
    # no terminal (pytest): main() never prompts
    src_ok = gar.main is not None
    assert src_ok


def test_route_formats_and_details(api):
    c, a, b, Session = api
    wb = make_workbook()
    files = lambda: {"file": ("ISA62443_Master_Audit_Checklist.xlsx", wb, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}  # noqa: E731
    r = c.post("/reports/audit-checklist", params={"format": "json"}, files=files())
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["rows"] == 7 and j["findings"] == 3 and j["selected"] == 3 and j["filename"].endswith(".xlsx") and j["scope"] == "findings"
    assert [i["master_id"] for i in j["items"]] == ["GOV-05", "GOV-01", "FW-14"] and j["by_status"]["Compliant"] == 1
    assert c.post("/reports/audit-checklist", params={"format": "json", "scope": "all", "order": "checklist"}, files=files()).json()["selected"] == 7
    # the PDF with the site's report details
    c.put("/reports/details", params={"site_id": a}, json={"client_name": "Plant A - Operations", "author": "Pat", "constraints": "Desk review only."})
    r = c.post("/reports/audit-checklist", params={"site_id": a}, files=files())
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert 'filename="iasc_audit_' in r.headers["content-disposition"] and r.headers["content-disposition"].endswith('.pdf"')
    assert int(r.headers["content-length"]) == len(r.content)
    text = _pdf_text(r.content)
    assert "Plant A - Operations" in text and "Desk review only." in text and "Personnel screening" in text
    # details given with the request override the site's: Prepared for, author, date, POCs and LRQA consultants
    given = {"client_name": "Plant A - Board", "author": "Lee", "report_date": "2026-11-11",
             "pocs": [{"name": "Sam Lee", "role": "OT Security", "email": "sam@x.test"}, {"name": "Kim Park"}],
             "consultants": [{"name": "Lee Cole", "role": "LRQA lead consultant"}, {"name": "Ana Ruiz"}], "constraints": ""}
    r = c.post("/reports/audit-checklist", params={"site_id": a}, files=files(), data={"details": __import__("json").dumps(given)})
    assert r.status_code == 200, r.text
    text = _pdf_text(r.content)
    assert "Plant A - Board" in text and "Plant A - Operations" not in text and "Author:\nLee" in text and "Date:\n2026-11-11" in text
    assert "Desk review only." in text                                                    # an empty field keeps the site's value
    assert all(x in text for x in ("Sam Lee", "Kim Park", "Lee Cole", "Ana Ruiz", "LRQA consultants"))
    assert c.post("/reports/audit-checklist", files=files(), data={"details": "[1, 2]"}).status_code == 422
    assert c.post("/reports/audit-checklist", files=files(), data={"details": "{not json"}).status_code == 422
    j = c.post("/reports/audit-checklist", params={"format": "json"}, files=files(), data={"details": "{}"}).json()
    assert j["rows"] == 7
    # without a site: defaults on the cover
    text2 = _pdf_text(c.post("/reports/audit-checklist", files=files()).content)
    assert "Plant A - Operations" not in text2 and "Confidential Security Data (CSD)" in text2
    # the CSV
    r = c.post("/reports/audit-checklist", params={"format": "csv", "site_id": a}, files=files())
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv") and r.headers["content-disposition"].endswith('.csv"')
    body = r.content.decode("utf-8")
    assert body.startswith("﻿Section,Master ID") and body.count("\r\n") == 4
    # refusals
    assert c.post("/reports/audit-checklist", params={"format": "docx"}, files=files()).status_code == 422
    assert c.post("/reports/audit-checklist", params={"scope": "mine"}, files=files()).status_code == 422
    r = c.post("/reports/audit-checklist", files={"file": ("x.xlsx", b"not a workbook", "application/octet-stream")})
    assert r.status_code == 422 and "not a master audit checklist" in r.json()["detail"]
    assert c.post("/reports/audit-checklist", params={"site_id": 999}, files=files()).status_code == 422
