"""
generate_audit_report.py
========================
The ISA/IEC 62443 audit report built from a filled-in Master Audit Checklist workbook
(owner 2026-10-24).  The workbook (``ISA62443_Master_Audit_Checklist.xlsx``, sheet
*Master Checklist*) is the input; the output is the PDF in the technical-report
layout (cover, contents, distribution list, revision history, engagement particulars,
findings, analysis, appendix - ``generate_report.py`` is reused for the page furniture and
the styles) and, with ``--csv``, the findings as a CSV file.

One report finding per checklist row: the *Check title* is the finding's title, the
*Audit check* its details, the *Domain* its area, the auditor's *Finding / Observation*,
*Evidence Reviewed* and *Recommendation* are printed as written, with Status, Maturity
Level, Severity, Owner and Target Date.

CLI::

    python generate_audit_report.py CHECKLIST.xlsx [--out FILE.pdf] [--csv FILE.csv]
        [--scope findings|assessed|all] [--order severity|checklist]
        [--client NAME] [--project NAME] [--author NAME] [--version V] [--classification TEXT]
        [--constraints TEXT]

The API serves the same report at ``POST /reports/audit-checklist`` (format pdf / csv / json),
where the cover, distribution list and revision history come from the site's *Report details*.
"""
from __future__ import annotations

import argparse
import io
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from reportlab.lib.pagesizes import A4
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import generate_report as gr                                     # noqa: E402  (page templates, styles, helpers)
from app import audit_checklist as ac                            # noqa: E402

esc, _p, _sp, _heads, _grid_table = gr.esc, gr._p, gr._sp, gr._heads, gr._grid_table
H1, H2, H3, BODY, SMALL, CELL, CELL_SMALL, CELL_BOLD, CAPTION = gr.H1, gr.H2, gr.H3, gr.BODY, gr.SMALL, gr.CELL, gr.CELL_SMALL, gr.CELL_BOLD, gr.CAPTION
cm = gr.cm

COVER_TITLE_LINES = ("IEC 62443 Audit", "Checklist Report")
LOGO = ROOT / "ui" / "report_logo.png"          # public branch: no logo ships; the cover draws the IACS Monitor wordmark box (drop a PNG here to brand it)
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", None: "Unrated"}
STATUS_COLOUR = {"Non-compliant": gr.SEV_COLOUR["high"], "Partially compliant": gr.SEV_COLOUR["medium"],
                 "Compliant": gr.OK_GREEN, "Not applicable": gr.DARK_GREY, "Not assessed": gr.DARK_GREY}


def _hex(c) -> str:
    return "#" + c.hexval()[2:]


def _sev_para(sev: Optional[str], style=CELL) -> Paragraph:
    col = gr.SEV_COLOUR.get(sev or "", gr.DARK_GREY)
    return Paragraph(f'<font color="{_hex(col)}">{esc(SEV_LABEL.get(sev, (sev or "").title()))}</font>', style)


def _status_para(st: str, style=CELL) -> Paragraph:
    return Paragraph(f'<font color="{_hex(STATUS_COLOUR.get(st, gr.DARK_GREY))}">{esc(st or "")}</font>', style)


def _cover_fields(data: dict) -> dict:
    d = data.get("details") or {}
    site = data.get("site") or d.get("client_name") or "the organisation"
    return {"client": d.get("client_name") or site, "project": d.get("project_name") or data.get("checklist") or site,
            "author": d.get("author") or "IACS_Monitor", "date": data.get("report_date") or data["generated_at"].strftime("%Y-%m-%d"),
            "classification": d.get("classification") or "Confidential Security Data (CSD)", "version": d.get("version") or "1.0",
            "title_lines": COVER_TITLE_LINES, "logo": str(LOGO) if LOGO.is_file() else None}


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def build_contents(data: dict) -> list:
    toc = TableOfContents()
    toc.levelStyles = [gr.TOC_STYLE]
    toc.dotsMinLevel = 9
    who = (data.get("details") or {}).get("client_name") or data.get("site") or "the organisation"
    story = [_p("Contents", gr._style("Normal", fontName="Helvetica", fontSize=18, leading=22, textColor=gr.TEAL, spaceAfter=12)), toc, _sp(1)]
    story.append(_p(esc(f"The contents of this report belong to {who}. The findings, observations and recommendations in this "
                        "document are the auditor's assessment of the ISA/IEC 62443 Master Audit Checklist at a point in time, "
                        "recorded in the checklist workbook and reproduced here without change. Review every recommendation, "
                        "assess the risk and follow change control before remediation work is carried out."), SMALL))
    story.append(PageBreak())
    return story


def build_distribution(data: dict) -> list:
    """1 Distribution List: the client's points of contact, then the assessor team (owner 2026-10-24)."""
    d = data.get("details") or {}
    dist = d.get("distribution") or []
    client = [r for r in dist if (r.get("side") or "client") != "assessor"]
    lrqa = [r for r in dist if r.get("side") == "assessor"]
    if not lrqa and (d.get("author") or d.get("author_email")):
        lrqa = [{"name": d.get("author") or "", "role": "Author", "email": d.get("author_email") or ""}]
    return [_p("1&nbsp;&nbsp;Distribution List", H1),
            _p(esc(f"{d.get('client_name') or data.get('site') or 'Client'} - points of contact"), H3), gr._people_table(client),
            _p("Assessor team", H3), gr._people_table(lrqa), _sp(0.6)]


def build_revisions(data: dict) -> list:
    d = data.get("details") or {}
    revs = d.get("revisions") or []
    rows = [_heads("Version", "Issue Date", "Status")]
    for r in revs:
        rows.append([Paragraph(esc(r.get("version") or "", 20), CELL), Paragraph(esc(r.get("date") or "", 40), CELL), Paragraph(esc(r.get("status") or "", 80), CELL)])
    if not revs:
        rows.append([Paragraph(esc(d.get("version") or "1.0"), CELL), Paragraph(esc(data.get("report_date") or ""), CELL), Paragraph("Issued", CELL)])
    return [_p("2&nbsp;&nbsp;Revision History", H1), _grid_table(rows, [3 * cm, 5 * cm, 9 * cm], zebra=False), PageBreak()]


def build_particulars(data: dict) -> list:
    """3 Engagement Particulars: background, scope, constraints, finding summary, compliance by domain."""
    d = data.get("details") or {}
    who = d.get("client_name") or data.get("site") or "the organisation"
    scope_txt = {"findings": "the checks rated Non-compliant or Partially compliant (and checks with a recorded finding, "
                             "severity or recommendation that were not rated Compliant or Not applicable)",
                 "assessed": "every assessed check (every status other than Not assessed)",
                 "all": "every check of the checklist"}[data["scope"]]
    story = [_p("3&nbsp;&nbsp;Engagement Particulars", H1), _p("Background", H3),
             _p(esc(f"This report documents the ISA/IEC 62443 audit of {who} against the consolidated Master Audit Checklist "
                    f"({data['checklist']}). The auditor rated each check (Compliant, Partially compliant, Non-compliant, "
                    "Not applicable or Not assessed), recorded the finding or observation, the evidence reviewed, a severity, "
                    "a recommendation, an owner and a target date in the checklist workbook; this report reproduces those "
                    "entries. The checks are paraphrased for audit use - the licensed standards hold the normative wording."), BODY),
             _p("Scope", H3)]
    rows = [_heads("Description", "Component")]
    c = data["by_status"]
    rows.append([Paragraph("Checklist", CELL), Paragraph(esc(data["checklist"], 200) + (f"<br/>{esc(data['source_name'], 120)}" if data.get("source_name") else ""), CELL)])
    rows.append([Paragraph("Checks", CELL), Paragraph(esc(f"{data['n_rows']} checks in {len(data['domains'])} domains"), CELL)])
    rows.append([Paragraph("Assessment status", CELL), Paragraph("<br/>".join(esc(f"{st}: {c.get(st, 0)}") for st in ac.STATUSES), CELL)])
    rows.append([Paragraph("Findings in this report", CELL), Paragraph(esc(f"{data['n_selected']} - {scope_txt}"), CELL)])
    rows.append([Paragraph("Domains", CELL), Paragraph("<br/>".join(esc(x, 120) for x in data["domains"]), CELL)])
    story.append(_grid_table(rows, [4 * cm, 13 * cm], zebra=False))
    story.append(_p("Assessment Window, Observations and Constraints", H3))
    story.append(_p(esc(d.get("constraints") or f"Checklist as received for the report dated {data['report_date']}. "
                        "No constraints were recorded.", 4000), BODY))
    if data.get("warnings"):
        story.append(_p(esc("Workbook notes: " + "; ".join(data["warnings"][:12]), 1500), SMALL))
    story.append(_p("Finding Summary", H3))
    sev = Counter(r.get("severity") if r.get("severity") in ac.SEVERITIES else None for r in data["selected"])
    story.append(_p(esc(f"The checklist records {data['n_findings']} finding(s) in {data['n_rows']} checks; {data['n_selected']} are in "
                        "this report. The following table shows the categorisation by the severity the auditor assigned:"), BODY))
    keys = ["critical", "high", "medium", "low", None]
    if not sev.get("critical"):
        keys.remove("critical")
    cells = [Paragraph(f'<font color="{_hex(gr.SEV_COLOUR.get(k or "", gr.DARK_GREY))}" size="18"><b>{sev.get(k, 0)}</b></font>'
                       f'<br/><font size="8">{esc(SEV_LABEL[k])}</font>',
                       gr._style("Normal", fontName="Helvetica", fontSize=9, leading=14, alignment=1)) for k in keys]
    t = Table([cells], colWidths=[17 * cm / len(cells)] * len(cells))
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, gr.MID_GREY), ("INNERGRID", (0, 0), (-1, -1), 0.5, gr.MID_GREY),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(t)
    story.append(_sp(0.3))
    story.append(_p("Compliance by Domain", H3))
    story.append(_p("Every check of the checklist by domain (the workbook's Summary sheet): the status counts, the compliance "
                    "percentage of the applicable, assessed checks (Compliant plus half of Partially compliant) and the "
                    "high-severity findings.", BODY))
    rows = [_heads("Domain", "Checks", "Compl.", "Partial", "Non-c.", "N/A", "Not ass.", "Compl. %", "High")]
    extra = []
    for i, s in enumerate(data["summary"], 1):
        st = CELL_BOLD if s["is_total"] else CELL
        pct = "—" if s["compliance_pct"] is None else f"{s['compliance_pct']:g} %"
        rows.append([Paragraph(esc(s["domain"], 80), st)] + [Paragraph(str(s[k]), st) for k in ("total", "compliant", "partial", "non_compliant", "not_applicable", "not_assessed")]
                    + [Paragraph(esc(pct), st), Paragraph(str(s["high"]), st)])
        if s["is_total"]:
            extra.append(("BACKGROUND", (0, i), (-1, i), gr.TOTAL_BG))
    story.append(_grid_table(rows, [5.3 * cm, 1.5 * cm, 1.5 * cm, 1.5 * cm, 1.5 * cm, 1.1 * cm, 1.7 * cm, 1.8 * cm, 1.1 * cm], zebra=False, extra=extra))
    story.append(_p("Compl. = Compliant, Partial = Partially compliant, Non-c. = Non-compliant, N/A = Not applicable, Not ass. = Not assessed, "
                    "High = findings rated High.", CAPTION))
    story.append(PageBreak())
    return story


def build_findings_summary(data: dict, num: str = "4") -> list:
    """4 Findings: one row per selected check - id, title, domain, status, severity, analysis section."""
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Findings", H1), _p(esc((data.get("details") or {}).get("client_name") or data.get("site") or data["checklist"], 120), H3)]
    if not data["selected"]:
        story += [_p("<i>No findings: no check of the checklist is rated Non-compliant or Partially compliant and none carries "
                     "a recorded finding.</i>", BODY), PageBreak()]
        return story
    rows = [_heads("ID", "Title", "Domain", "Status", "Severity", "Section")]
    for r in data["selected"]:
        rows.append([Paragraph(esc(r.get("master_id"), 20), CELL), Paragraph(esc(r.get("title"), 160), CELL),
                     Paragraph(esc(r.get("domain"), 80), CELL_SMALL), _status_para(r.get("status"), CELL_SMALL),
                     _sev_para(r.get("severity"), CELL_SMALL), Paragraph(esc(r.get("section")), CELL)])
    story.append(_grid_table(rows, [1.7 * cm, 5.6 * cm, 4 * cm, 2.2 * cm, 1.7 * cm, 1.8 * cm], zebra=False))
    story.append(_sp(0.2))
    story.append(_p(esc(f"One row per checklist row; section 5 holds the auditor's finding, evidence and recommendation for each."), SMALL))
    story.append(PageBreak())
    return story


def _meta_table(r: dict) -> Table:
    fr = " / ".join(x for x in (r.get("fr"), f"Min SL {r['min_sl']}" if r.get("min_sl") else "") if x)
    scope = ", ".join(x for x in (r.get("audit_scope"), "conditional: applies only when the feature is used" if (r.get("conditional") or "").lower().startswith("y") else "") if x)
    meta = [[Paragraph("Master ID", CELL), Paragraph(esc(r.get("master_id") or "—", 40), CELL)],
            [Paragraph("Domain", CELL), Paragraph(esc(r.get("domain") or "—", 120), CELL)],
            [Paragraph("Status", CELL), _status_para(r.get("status") or "—")],
            [Paragraph("Severity", CELL), _sev_para(r.get("severity"))],
            [Paragraph("Maturity level", CELL), Paragraph(esc(r.get("maturity") or "—", 40), CELL)],
            [Paragraph("Owner / target date", CELL), Paragraph(esc(" / ".join(x for x in (r.get("owner"), r.get("target_date")) if x) or "—", 200), CELL)],
            [Paragraph("Foundational requirement", CELL), Paragraph(esc(fr or "—", 60), CELL)]]
    if scope:
        meta.append([Paragraph("Audit scope", CELL), Paragraph(esc(scope, 160), CELL)])
    t = Table(meta, colWidths=[3.6 * cm, 13.4 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, gr.MID_GREY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _paras(text: str, limit: int = 6000, empty: str = "") -> list:
    """Auditor text as paragraphs (blank-line separated); ``empty`` in italics when nothing was recorded."""
    text = (text or "").strip()
    if not text:
        return [_p(f"<i>{esc(empty)}</i>", BODY)] if empty else []
    parts = [x.strip() for x in text[:limit].replace("\r", "").split("\n") if x.strip()]
    return [_p(esc(x, limit), BODY) for x in parts] or [_p(esc(text, limit), BODY)]


def build_findings(data: dict, num: str = "5") -> list:
    """5 Analysis: one entry per selected checklist row, each on its own page."""
    who = (data.get("details") or {}).get("client_name") or data.get("site") or data["checklist"]
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Analysis: {esc(who, 120)}", H1),
             _p("One entry per checklist row" + (", most severe first" if data["order"] == "severity" else ", in checklist order")
                + ": the check as the auditor assessed it, the finding or observation, the evidence reviewed, the "
                "recommendation and the owner and target date, followed by the source requirements the check "
                "consolidates and the standards and NIST publications it comes from.", BODY)]
    if not data["selected"]:
        story += [_p("<i>No findings in scope.</i>", BODY), PageBreak()]
        return story
    for i, r in enumerate(data["selected"]):
        sev = r.get("severity")
        col = gr.SEV_COLOUR.get(sev or "", gr.NAVY)
        head = _p(f'{esc(r["section"])} <font color="{_hex(col)}">{esc(SEV_LABEL.get(sev, (sev or "").title()))}</font>: {esc(r.get("title") or r.get("master_id"), 200)}', H2)
        details = [_p("Audit Check", H3)] + _paras(r.get("audit_check"), 3000, "No audit check text in the workbook.")
        observation = [_p("Finding / Observation", H3)] + _paras(r.get("finding"), empty="No finding or observation was recorded by the auditor.")
        evidence = [_p("Evidence Reviewed", H3)] + _paras(r.get("evidence"), empty="No evidence reviewed was recorded by the auditor.")
        if r.get("suggested_evidence"):
            evidence.append(_p(esc(f"Suggested evidence (checklist): {r['suggested_evidence']}", 600), SMALL))
        rec_text = (r.get("recommendation") or "").strip()
        recs = [_p("Recommendation", H3)]
        if rec_text:
            lines = [x.strip() for x in rec_text.replace("\r", "").split("\n") if x.strip()]
            items = lines if len(lines) > 1 else gr._sentences(rec_text)
            recs += [_p(f"{n}.&nbsp;&nbsp;{esc(sx, 1500)}", BODY) for n, sx in enumerate(items, 1)]
        else:
            recs.append(_p("<i>No recommendation was recorded by the auditor.</i>", BODY))
        reading = []
        if r.get("covers"):
            reading.append("Covers: " + r["covers"])
        if r.get("source_standards"):
            reading.append("Source standards: " + r["source_standards"])
        if r.get("nist_ref"):
            reading.append(r["nist_ref"])
        further = ([_p("Further Reading", H3)] + [_p("•&nbsp;&nbsp;" + esc(x, 600), BODY) for x in reading]) if reading else []
        if i > 0:
            story.append(PageBreak())
        story.append(KeepTogether([head, _meta_table(r)] + details))
        story += observation + evidence + recs + further
    story.append(PageBreak())
    return story


def build_appendix(data: dict, num: str = "6") -> list:
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Appendix", H1), _p("Checklist Status", H2),
             _p("Every check of the Master Audit Checklist with the auditor's status, maturity level and severity, by domain.", BODY)]
    rows = [_heads("#", "ID", "Check title", "Status", "Maturity", "Severity")]
    extra = []
    last = object()
    for r in data["rows"]:
        if r.get("domain") != last:
            last = r.get("domain")
            rows.append([Paragraph(esc(last or "(no domain)", 120), CELL_BOLD), "", "", "", "", ""])
            extra += [("SPAN", (0, len(rows) - 1), (-1, len(rows) - 1)), ("BACKGROUND", (0, len(rows) - 1), (-1, len(rows) - 1), gr.LIGHT_GREY)]
        rows.append([Paragraph(esc(r.get("n"), 6), CELL_SMALL), Paragraph(esc(r.get("master_id"), 20), CELL_SMALL),
                     Paragraph(esc(r.get("title"), 160), CELL_SMALL), _status_para(r.get("status"), CELL_SMALL),
                     Paragraph(esc(r.get("maturity") or "—", 20), CELL_SMALL), _sev_para(r.get("severity"), CELL_SMALL) if r.get("severity") else Paragraph("—", CELL_SMALL)])
    story.append(_grid_table(rows, [0.9 * cm, 1.8 * cm, 8 * cm, 2.6 * cm, 1.7 * cm, 2 * cm], zebra=False, extra=extra))
    story.append(_sp(0.4))
    story.append(_p("Severity and Status Scale", H2))
    rows = [_heads("Value", "Meaning")]
    for sv, txt in (("high", "The requirement is not met and the gap exposes the IACS; remediate first."),
                    ("medium", "The requirement is partly met or the gap needs a further step to be exploited."),
                    ("low", "Deviation from the requirement or best practice with limited exposure.")):
        rows.append([_sev_para(sv), Paragraph(txt, CELL)])
    for st, txt in (("Compliant", "Every source requirement the check consolidates is met."),
                    ("Partially compliant", "Some source requirements are met; the gaps are named by Req ID in the finding."),
                    ("Non-compliant", "The requirement is not met."), ("Not applicable", "The feature or scope the check covers is not used."),
                    ("Not assessed", "The check was not examined in this audit.")):
        rows.append([_status_para(st), Paragraph(txt, CELL)])
    story.append(_grid_table(rows, [4 * cm, 13 * cm], zebra=False))
    story.append(_sp(0.4))
    refs = ["ISA/IEC 62443-2-1:2024 Security program requirements for IACS asset owners",
            "ISA/IEC 62443-1-1:2007 Terminology, concepts and models",
            "ISA/IEC 62443-3-2:2020 Security risk assessment for system design",
            "ISA/IEC 62443-3-3:2013 System security requirements and security levels",
            "ISA/IEC 62443-4-1:2018 Secure product development lifecycle requirements",
            "ISA TR 62443-2-2:2025 IACS security protection ratings", "ISA TR 62443-2-3:2015 Patch management in the IACS environment"]
    refs += [x for x in (data.get("references") or []) if x]
    story.append(_p("Standards and References", H2))
    story += [_p("•&nbsp;&nbsp;" + esc(x, 300), BODY) for x in refs]
    return story


def build_story(data: dict) -> list:
    story = []
    story += gr.build_cover(data)
    story += build_contents(data)
    story += build_distribution(data)
    story += build_revisions(data)
    story += build_particulars(data)
    story += build_findings_summary(data)
    story += build_findings(data)
    story += build_appendix(data)
    return story


def render_pdf(data: dict, out) -> None:
    """Render to ``out`` (a path or a binary file-like object) in the technical-report layout."""
    cov = _cover_fields(data)
    with gr._RENDER_LOCK:                                # the shared styles are module state (audit 2026-10-18)
        gr._set_layout("lrqa")
        try:
            doc = gr._ReportDoc(out, pagesize=A4, leftMargin=gr.MARGIN, rightMargin=gr.MARGIN, topMargin=gr.MARGIN,
                                bottomMargin=gr.MARGIN, title="IEC 62443 Audit Checklist Report", author=cov["author"],
                                subject="ISA/IEC 62443 Master Audit Checklist")
            doc._iasc_site = data.get("site")
            doc._iasc_cover = cov
            gr._build_templates(doc, "lrqa")        # the template page furniture (the compliance report is public-only here)
            doc.multiBuild(build_story(data))
        finally:
            gr._set_layout("lrqa")


def report_bytes(parsed: dict, fmt: str = "pdf", **opts) -> bytes:
    """Parsed workbook -> PDF or CSV bytes (used by POST /reports/audit-checklist)."""
    data = ac.report_data(parsed, **opts)
    if fmt == "csv":
        return ac.to_csv(data).encode("utf-8")
    buf = io.BytesIO()
    render_pdf(data, buf)
    return buf.getvalue()


def _person(text: str) -> Optional[dict]:
    """'Name; Role; Email' (role and email optional) -> row."""
    parts = [x.strip() for x in (text or "").split(";")] + ["", ""]
    return {"name": parts[0], "role": parts[1], "email": parts[2]} if parts[0] else None


def _ask(prompt: str, default: str = "", *, ask=input) -> str:
    try:
        v = ask(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    except EOFError:
        return default
    return v or default


def _ask_people(label: str, *, ask=input) -> list:
    """Name / role / email rows until an empty name."""
    out = []
    while len(out) < ac.MAX_PEOPLE:
        name = _ask(f"{label} {len(out) + 1} name (blank to finish)", ask=ask)
        if not name:
            break
        out.append({"name": name, "role": _ask(f"{label} {len(out) + 1} role", ask=ask), "email": _ask(f"{label} {len(out) + 1} email", ask=ask)})
    return out


def prompt_details(details: dict, *, ask=input, out=sys.stderr) -> dict:
    """Owner 2026-10-24: the program asks for what the cover and the distribution list need -
    Prepared for, the author, the date of the report, the client's points of contact and the
    assessor team (any number of each) - unless they were already given on the command line."""
    d = dict(details)
    print("Report details (Enter keeps the default; the lists end with an empty name).", file=out)
    if not d.get("client_name"):
        d["client_name"] = _ask("Prepared for (client)", ask=ask)
    if not d.get("author"):
        d["author"] = _ask("Author", "IACS_Monitor", ask=ask)
    if not d.get("report_date"):
        d["report_date"] = _ask("Date of the report (YYYY-MM-DD)", datetime.now().astimezone().strftime("%Y-%m-%d"), ask=ask)
    dist = list(d.get("distribution") or [])
    if not any(r.get("side") == "client" for r in dist):
        dist += [{**r, "side": "client"} for r in _ask_people("Client POC", ask=ask)]
    if not any(r.get("side") == "assessor" for r in dist):
        dist += [{**r, "side": "assessor"} for r in _ask_people("Assessor", ask=ask)]
    d["distribution"] = dist
    return ac.clean_details(d)


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ISA/IEC 62443 audit report (PDF + CSV) from a filled-in Master Audit Checklist workbook.")
    ap.add_argument("checklist", help="the Master Audit Checklist workbook (.xlsx)")
    ap.add_argument("--out", default="isa62443_audit_report.pdf", help="output PDF path (default isa62443_audit_report.pdf)")
    ap.add_argument("--csv", help="also write the findings as CSV to this path")
    ap.add_argument("--no-pdf", action="store_true", help="write only the CSV")
    ap.add_argument("--scope", choices=ac.SCOPES, default="findings",
                    help="findings (default): Non-compliant / Partially compliant and recorded findings; assessed: every "
                         "status but Not assessed; all: every check")
    ap.add_argument("--order", choices=ac.ORDERS, default="severity", help="analysis order (default: severity, then checklist order)")
    ap.add_argument("--client", help="Prepared For on the cover (asked for when missing)")
    ap.add_argument("--date", help="date of the report on the cover, YYYY-MM-DD (asked for when missing; default today)")
    ap.add_argument("--poc", action="append", default=[], metavar="'NAME; ROLE; EMAIL'",
                    help="a client point of contact for the Distribution List (repeat for several; asked for when none is given)")
    ap.add_argument("--consultant", action="append", default=[], metavar="'NAME; ROLE; EMAIL'",
                    help="a member of the assessor team for the Distribution List (repeat for several; asked for when none is given)")
    ap.add_argument("--no-prompt", action="store_true", help="never ask on the terminal; use the flags and defaults only")
    ap.add_argument("--project", help="Project on the cover")
    ap.add_argument("--author", help="Author on the cover (asked for when missing; default IACS_Monitor)")
    ap.add_argument("--author-email")
    ap.add_argument("--version", help="report version (default 1.0)")
    ap.add_argument("--classification", help="footer classification (default Confidential Security Data (CSD))")
    ap.add_argument("--constraints", help="assessment window / constraints paragraph")
    a = ap.parse_args(list(argv) if argv is not None else None)
    try:
        parsed = ac.parse_workbook(Path(a.checklist).read_bytes())
    except (OSError, ac.ChecklistError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    details = {k: v for k, v in (("client_name", a.client), ("project_name", a.project), ("author", a.author), ("author_email", a.author_email),
                                 ("version", a.version), ("classification", a.classification), ("constraints", a.constraints),
                                 ("report_date", a.date)) if v}
    people = [{**r, "side": "client"} for r in map(_person, a.poc) if r] + [{**r, "side": "assessor"} for r in map(_person, a.consultant) if r]
    if people:
        details["distribution"] = people
    if not a.no_prompt and sys.stdin.isatty():
        details = prompt_details(details)
    else:
        details = ac.clean_details(details)
    data = ac.report_data(parsed, a.scope, a.order, details=details, source_name=Path(a.checklist).name, generated_at=datetime.now().astimezone())
    for w in data["warnings"]:
        print(f"note: {w}", file=sys.stderr)
    if a.csv:
        Path(a.csv).write_text(ac.to_csv(data), encoding="utf-8", newline="")
        print(f"wrote {a.csv} ({data['n_selected']} findings)")
    if not a.no_pdf:
        render_pdf(data, a.out)
        print(f"wrote {a.out} ({data['n_selected']} of {data['n_rows']} checks in the analysis, scope {a.scope})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
