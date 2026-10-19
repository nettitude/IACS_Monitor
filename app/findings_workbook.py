"""
Findings workbook: an xlsx export of the findings that is also the import that
updates them (owner 2026-10-14: "an xlsx export of the findings which will be the
base of an import feature to update the finding notes, status and Name. The
Import of the compliance xls will update the findings so a clean report can be
outputted").

Sheet "Findings": one row per finding, keyed on the Finding ID.  Editable
columns: Status (open / acknowledged / closed / false positive), Name (who makes
the change - recorded as acknowledged_by / false_positive_by), New note (appended
to the finding's notes with a stamp, like the Findings page), False-positive
reason.  Everything else is read-only context.  The import applies exactly the
Findings page rules (``apply_status_change`` in app.api.routes): a false positive
needs a reason, acknowledging needs a name, re-opening a finding whose
recurrence is open is refused, notes are appended never overwritten.  A dry run
reports what would change without writing.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

SHEET = "Findings"
STATUS_LABELS = {"open": "Open", "acknowledged": "Acknowledged", "closed": "Closed", "false_positive": "False positive"}
STATUS_VALUES = {v.lower(): k for k, v in STATUS_LABELS.items()} | {k: k for k in STATUS_LABELS} | {"fp": "false_positive"}

# (header, key, editable)
COLUMNS = [
    ("Finding ID", "id", False), ("Site", "site", False), ("Check", "check_name", False), ("Severity", "severity", False),
    ("Status", "status", True), ("Name", "name", True), ("New note", "new_note", True),
    ("False-positive reason", "false_positive_reason", True),
    ("Title", "title", False), ("Device", "device_name", False), ("62443-3-3 SR", "isa62443_sr", False),
    ("Checklist row", "checklist_id", False), ("Category", "category", False), ("Created", "created_at", False),
    ("Last seen", "last_seen", False), ("Occurrences", "occurrence_count", False),
    ("Acknowledged by", "acknowledged_by", False), ("Acknowledged at", "acknowledged_at", False),
    ("Closed at", "closed_at", False), ("Notes (history)", "notes", False),
    ("Excluded from report", "excluded_from_report", False),
]
_EDIT = {h for h, _k, e in COLUMNS if e}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dt(v) -> str:
    return v.strftime("%Y-%m-%d %H:%M") if isinstance(v, datetime) else ("" if v is None else str(v))


def export_xlsx(db: DBSession, site_id: int, include_closed: bool = False, include_excluded: bool = False) -> bytes:
    """The site's findings as a workbook (open + acknowledged + false positives;
    closed with ``include_closed``; findings of checks left out of the report with
    ``include_excluded``)."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    from app.models import Finding, Site
    from app.report_checks import excluded_by_site, hide_excluded
    site = db.get(Site, site_id)
    excluded = excluded_by_site(db).get(site_id, set())
    q = db.query(Finding).filter(Finding.site_id == site_id)
    if not include_closed:
        q = q.filter(Finding.status != "closed")
    q = hide_excluded(db, q, site_id, include_excluded)
    rows = sorted(q.all(), key=lambda f: (_SEV_RANK.get((f.severity or "").lower(), 5), f.status != "open", -(f.id or 0)))

    wb = Workbook()
    ws = wb.active
    ws.title = SHEET
    head_font, edit_fill = Font(bold=True), PatternFill("solid", fgColor="FFF2CC")
    for col, (h, _k, editable) in enumerate(COLUMNS, start=1):
        c = ws.cell(row=1, column=col, value=h + (" (edit)" if editable else ""))
        c.font = head_font
        if editable:
            c.fill = edit_fill
    for r, f in enumerate(rows, start=2):
        vals = {
            "id": f.id, "site": site.name if site else site_id, "check_name": f.check_name, "severity": f.severity,
            "status": STATUS_LABELS.get(f.status, f.status), "name": "", "new_note": "",
            "false_positive_reason": f.false_positive_reason or "", "title": f.title, "device_name": f.device_name or "",
            "isa62443_sr": f.isa62443_sr or "", "checklist_id": f.checklist_id or "", "category": f.category,
            "created_at": _dt(f.created_at), "last_seen": _dt(f.last_seen), "occurrence_count": f.occurrence_count,
            "acknowledged_by": f.acknowledged_by or "", "acknowledged_at": _dt(f.acknowledged_at),
            "closed_at": _dt(f.closed_at), "notes": f.notes or "",
            "excluded_from_report": "yes" if f.check_name in excluded else "",
        }
        for col, (_h, k, editable) in enumerate(COLUMNS, start=1):
            c = ws.cell(row=r, column=col, value=vals[k])
            if editable:
                c.fill = edit_fill
            if k in ("notes", "title", "new_note", "false_positive_reason"):
                c.alignment = Alignment(wrap_text=True, vertical="top")
    status_col = [h for h, _k, _e in COLUMNS].index("Status") + 1
    dv = DataValidation(type="list", formula1='"' + ",".join(STATUS_LABELS.values()) + '"', allow_blank=False)
    ws.add_data_validation(dv)
    if rows:
        dv.add(f"{get_column_letter(status_col)}2:{get_column_letter(status_col)}{len(rows) + 1}")
    widths = {"Finding ID": 11, "Site": 14, "Check": 30, "Severity": 10, "Status": 15, "Name": 16, "New note": 40,
              "False-positive reason": 30, "Title": 60, "Device": 18, "62443-3-3 SR": 18, "Notes (history)": 50}
    for col, (h, _k, _e) in enumerate(COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(col)].width = widths.get(h, 14)
    ws.freeze_panes = "B2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(len(rows) + 1, 2)}"

    info = wb.create_sheet("How to use")
    for i, line in enumerate((
        "IACS_Monitor findings workbook - export of site '" + (site.name if site else str(site_id)) + "' on "
        + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "Edit only the shaded columns on the Findings sheet: Status, Name, New note, False-positive reason.",
        "Status: Open, Acknowledged, Closed or False positive. Acknowledging needs a Name; a false positive needs a reason.",
        "New note is appended to the finding's notes with a date stamp and the Name (the history is never overwritten).",
        "Rows are matched on the Finding ID - do not change it; rows with an empty Finding ID are ignored.",
        "Import the file on Reports & Diagnostics (Findings workbook): preview first, then apply.",
        f"site_id={site_id}",
    ), start=1):
        info.cell(row=i, column=1, value=line)
    info.column_dimensions["A"].width = 120
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def parse_xlsx(data: bytes) -> list:
    """Rows of the Findings sheet as dicts keyed by COLUMNS key (header names
    matched case-insensitively, '(edit)' ignored); ``row`` = the sheet row number."""
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = wb[SHEET] if SHEET in wb.sheetnames else wb[wb.sheetnames[0]]
    it = ws.iter_rows(values_only=True)
    try:
        header = next(it)
    except StopIteration:
        raise ValueError("the workbook is empty")
    key_of = {}
    norm = {h.lower(): k for h, k, _e in COLUMNS}
    for i, h in enumerate(header):
        hn = str(h or "").replace("(edit)", "").strip().lower()
        if hn in norm:
            key_of[i] = norm[hn]
    if "id" not in key_of.values():
        raise ValueError("no 'Finding ID' column: export the workbook from IACS_Monitor first")
    out = []
    for n, row in enumerate(it, start=2):
        d = {key_of[i]: v for i, v in enumerate(row) if i in key_of}
        if d.get("id") in (None, ""):
            continue
        d["row"] = n
        out.append(d)
    return out


def apply_rows(db: DBSession, site_id: int, rows: list, dry_run: bool = True, default_name: Optional[str] = None) -> dict:
    """Apply the editable columns.  Every row that differs from the finding goes
    through the Findings page's status rules; ``dry_run`` rolls back."""
    from fastapi import HTTPException
    from app.api.routes import apply_finding_status
    from app.models import Finding
    stats = {"rows": len(rows), "changed": 0, "unchanged": 0, "errors": [], "changes": [], "dry_run": dry_run}
    for d in rows:
        try:
            fid = int(str(d["id"]).strip())
        except (TypeError, ValueError):
            stats["errors"].append({"row": d.get("row"), "finding_id": d.get("id"), "error": "Finding ID is not a number"})
            continue
        f = db.get(Finding, fid)
        if f is None or f.site_id != site_id:
            stats["errors"].append({"row": d.get("row"), "finding_id": fid, "error": "no such finding in this site"})
            continue
        status_in = str(d.get("status") or "").strip().lower()
        status = STATUS_VALUES.get(status_in, status_in) if status_in else f.status
        if status not in STATUS_LABELS:
            stats["errors"].append({"row": d.get("row"), "finding_id": fid, "error": f"unknown status {d.get('status')!r}"})
            continue
        name = str(d.get("name") or "").strip() or default_name
        note = str(d.get("new_note") or "").strip()
        reason = str(d.get("false_positive_reason") or "").strip()
        reason_changed = reason and reason != (f.false_positive_reason or "")
        # a note already in the finding's history was applied by an earlier import of
        # this workbook: importing the same file twice changes nothing
        note_new = bool(note) and note not in (f.notes or "")
        if status == f.status and not note_new and not reason_changed:
            stats["unchanged"] += 1
            continue
        try:
            apply_finding_status(db, f, status, notes=note if note_new else None, acknowledged_by=name,
                                 reason=reason or None)
        except HTTPException as exc:
            stats["errors"].append({"row": d.get("row"), "finding_id": fid, "error": str(exc.detail)})
            continue
        stats["changed"] += 1
        stats["changes"].append({"row": d.get("row"), "finding_id": fid, "title": f.title, "status": f.status,
                                 "note": note or None, "name": name})
    if dry_run:
        db.rollback()
    else:
        db.commit()
    return stats
