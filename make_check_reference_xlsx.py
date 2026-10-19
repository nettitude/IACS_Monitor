#!/usr/bin/env python3
"""Generate docs/IACS_Monitor_62443_check_reference.xlsx from the catalogue (owner 2026-10-15:
"create a new download xls of the findings checks, details, etc").

Sheets: Checks (one row per check with everything the application knows about it), By section,
By data source, By FR, By severity, Reference key.  Run from the repo root:

    .venv/bin/python make_check_reference_xlsx.py [--out path.xlsx]
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import sys
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import security_levels as sl                   # noqa: E402
from app.checklist_rows import ROWS                     # noqa: E402
from app import writeup as wu
from app.explain import C as EXPLAIN                    # noqa: E402
from app.models import CHECK_TYPE_REFERENCE as REF      # noqa: E402
from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS   # noqa: E402
from app.report_checks import GROUPS, check_group        # noqa: E402

FONT = "Arial"
WHEN = {"config_review": "At each FortiGate config upload (cross-firewall checks: topology run-checks)",
        "periodic_review": "Periodic review: POST /reviews/run, the schedule, after uploads",
        "real_time": "As each log event is ingested"}
GROUP_LABEL = {g[0]: g[1] for g in GROUPS}


def _doc_rows() -> dict:
    """Title / data source / code location per check from docs/62443-check-reference.md."""
    out = {}
    p = ROOT / "docs" / "62443-check-reference.md"
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 9:
            continue
        src = cells[7]
        out[cells[0].strip("`")] = {"title": cells[1], "source": src.split(" — ")[0].strip(),
                                    "source_detail": src.split(" — ", 1)[1].strip() if " — " in src else "",
                                    "code": cells[8].strip("`"), "note": cells[9] if len(cells) > 9 else ""}
    return out


def build(out_path: Path) -> int:
    docs = _doc_rows()
    header = ["Check code (check_name)", "What the check looks for", "Concern", "Why it is an issue", "How to resolve",
              "FortiOS example (template)", "Standard / best-practice references", "How it closes", "Workbook row(s)", "Workbook section", "Workbook item", "62443 reference of the row",
              "NIST reference of the row", "IEC 62443-3-3 SR", "Foundational requirement(s)", "Security level (SL)",
              "Default severity", "Category", "When it runs", "Report group", "Data source", "Data source detail",
              "Code location", "Note"]
    rows = []
    for name in sorted(REF, key=lambda n: (str(REF[n][1] or "zz"), n)):
        sr, row, sev, cat = REF[name]
        d = docs.get(name, {})
        e = EXPLAIN.get(name, {})
        first_row = str(row or "").split(",")[0].strip()
        wb_row = ROWS.get(first_row, {})
        desc = sl.describe(sr)
        rows.append([
            name, d.get("title", ""), wu.concern(name, e.get("why", "")), e.get("why", ""), e.get("fix", ""),
            wu.FORTI.get(name, ""), "; ".join(wu.references(name, sr)), e.get("close", ""),
            row or "(not in the checklist)", wb_row.get("section", ""), wb_row.get("title", ""),
            wb_row.get("ref_62443", ""), wb_row.get("nist", ""), sr,
            ", ".join(desc.get("fr") or []), desc.get("sl") if desc.get("sl") is not None else "",
            sev, cat, WHEN.get(cat, cat), GROUP_LABEL.get(check_group(name, cat), check_group(name, cat)),
            d.get("source", "FortiGate config" if name in FORTIGATE_CONFIG_CHECKS else ""),
            d.get("source_detail", ""), d.get("code", ""), d.get("note", ""),
        ])

    wb = Workbook()
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    head_font = Font(name=FONT, bold=True, color="FFFFFF", size=10)
    head_fill = PatternFill("solid", fgColor="1F4E78")
    body_font = Font(name=FONT, size=10)

    def sheet(title, hdr, data, widths):
        ws = wb.create_sheet(title) if wb.sheetnames != ["Sheet"] else wb.active
        ws.title = title
        ws.append(hdr)
        for c in ws[1]:
            c.font, c.fill, c.border = head_font, head_fill, border
            c.alignment = Alignment(vertical="center", wrap_text=True)
        for r in data:
            ws.append(r)
        for rr in ws.iter_rows(min_row=2, max_row=ws.max_row):
            for c in rr:
                c.font, c.border = body_font, border
                c.alignment = Alignment(vertical="top", wrap_text=True)
        for i, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(i)].width = w
        ws.freeze_panes = "B2"
        ws.auto_filter.ref = ws.dimensions
        ws.row_dimensions[1].height = 30
        return ws

    sheet("Checks", header, rows, [34, 44, 60, 50, 36, 12, 28, 44, 24, 18, 22, 14, 10, 12, 16, 34, 26, 26, 50, 40, 30])

    # summaries (counts computed at generation time)
    def summary(title, key_fn, label):
        cnt = collections.Counter(key_fn(r) for r in rows)
        sev_cnt = collections.defaultdict(collections.Counter)
        for r in rows:
            sev_cnt[key_fn(r)][r[13]] += 1
        sevs = ["critical", "high", "medium", "low", "info"]
        data = [[k, v] + [sev_cnt[k][s] for s in sevs] for k, v in sorted(cnt.items(), key=lambda kv: (str(kv[0])))]
        data.append(["Total", len(rows)] + [sum(sev_cnt[k][s] for k in cnt) for s in sevs])
        ws = sheet(title, [label, "Checks"] + [s.capitalize() for s in sevs], data, [46, 10, 10, 10, 10, 10, 10])
        for c in ws[ws.max_row]:
            c.font = Font(name=FONT, bold=True, size=10)
        return ws

    summary("By section", lambda r: r[6] or "(not in the checklist)", "OT firewall review workbook section")
    summary("By data source", lambda r: r[17] or "(unspecified)", "Data source")
    summary("By report group", lambda r: r[16], "Report group (Checks in the report)")
    summary("By severity", lambda r: r[13], "Default severity")
    fr_rows = collections.Counter()
    for r in rows:
        for fr in (r[11].split(", ") if r[11] else ["(none)"]):
            fr_rows[fr] += 1
    fr_names = {"FR1": "Identification and authentication control", "FR2": "Use control", "FR3": "System integrity",
                "FR4": "Data confidentiality", "FR5": "Restricted data flow", "FR6": "Timely response to events",
                "FR7": "Resource availability"}
    sheet("By FR", ["Foundational requirement", "Name", "Checks (a check may map to several FRs)"],
          [[k, fr_names.get(k, ""), v] for k, v in sorted(fr_rows.items())], [24, 40, 16])

    key = [
        ["Generated", dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "make_check_reference_xlsx.py from app.models.CHECK_TYPE_REFERENCE, app.explain, app.checklist_rows, app.security_levels, docs/62443-check-reference.md"],
        ["Checks", len(rows), "Every finding type the application can raise (check_name on a finding)"],
        ["Workbook row(s)", "", "Row of the OT Firewall Review 62443 workbook the check answers; '(not in the checklist)' = SR only"],
        ["IEC 62443-3-3 SR", "", "System requirement(s) and requirement enhancements; '2-1 ...' = 62443-2-1 element, 'ZCR' = 62443-3-2"],
        ["Foundational requirement / SL", "", "Derived from the SR string by app/security_levels.py; SL = the lowest capability level at which the requirement applies"],
        ["Default severity", "", "The severity the check records unless the evidence raises or lowers it (see the explanation)"],
        ["Category / When it runs", "", "config_review = at FortiGate upload; periodic_review = review runs; real_time = per log event"],
        ["Report group", "", "The group under Reports & Diagnostics > Checks in the report"],
        ["Data source", "", "What the check reads (firewall config, PCAP sessions, syslog, switch output, inventory ...)"],
        ["Why / How to resolve / How it closes", "", "The 'Why this was flagged' texts shown with each finding (app/explain.py)"],
        ["Counts on the summary sheets", "", "Computed when the workbook was generated - regenerate after adding checks"],
    ]
    sheet("Reference key", ["Item", "Value", "Meaning"], key, [34, 18, 110])
    wb.save(out_path)
    return len(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "IACS_Monitor_62443_check_reference.xlsx"))
    a = ap.parse_args()
    n = build(Path(a.out))
    print(f"{a.out}: {n} checks")
