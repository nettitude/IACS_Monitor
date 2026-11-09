"""
app/audit_checklist.py
======================
The ISA/IEC 62443 Master Audit Checklist workbook (``Checklist/ISA62443_Master_Audit_Checklist.xlsx``:
149 consolidated checks, one row each, with the yellow auditor columns Status, Maturity Level,
Finding / Observation, Evidence Reviewed, Severity, Recommendation, Owner, Target Date) as the
input of an audit report (owner 2026-10-24: "a program that takes the master audit checklist as
an import and creates a report ... a CSV export besides a PDF").

This module reads the workbook, picks the rows that are findings, summarises the checklist per
domain and writes the CSV; ``generate_audit_report.py`` (repo root) renders the PDF in the
LRQA compliance report's layout, and ``POST /reports/audit-checklist`` serves both.

Report finding = one checklist row:
  * title            = *Check title*
  * details          = *Audit check (paraphrased)*
  * domain           = *Domain*
  * observation      = *Finding / Observation* (auditor)
  * evidence         = *Evidence Reviewed* (auditor), with *Suggested evidence* as the prompt
  * recommendation   = *Recommendation* (auditor)
  * status, maturity, severity, owner, target date, FR, Min SL, scope, covers, standards, NIST ref

Nothing here touches the database.  Every cell value is a plain string (control characters
dropped, length capped) before it reaches the CSV or the PDF.
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter, OrderedDict
from datetime import date, datetime
from typing import Any, Optional

MAX_ROWS = 2000                 # checklist rows read (the master checklist has 149)
MAX_CELL = 4000                 # characters kept per cell
SHEET_NAME = "Master Checklist"

STATUSES = ("Compliant", "Partially compliant", "Non-compliant", "Not applicable", "Not assessed")
SEVERITIES = ("critical", "high", "medium", "low")        # the workbook offers High / Medium / Low
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
STATUS_RANK = {"Non-compliant": 0, "Partially compliant": 1, "Not assessed": 2, "Compliant": 3, "Not applicable": 4}
SCOPES = ("findings", "assessed", "all")
ORDERS = ("severity", "checklist")

# header text (lower-cased, spaces collapsed) -> field.  A header matches when it starts with the key.
_HEADER_KEYS = (
    ("#", "n"), ("no", "n"),
    ("master id", "master_id"), ("id", "master_id"),
    ("domain", "domain"),
    ("check title", "title"), ("title", "title"),
    ("audit check", "audit_check"), ("check", "audit_check"),
    ("suggested evidence", "suggested_evidence"),
    ("covers", "covers"),
    ("source standard", "source_standards"),
    ("nist", "nist_ref"),
    ("fr", "fr"),
    ("min sl", "min_sl"),
    ("audit scope", "audit_scope"),
    ("conditional", "conditional"),
    ("status", "status"),
    ("maturity", "maturity"),
    ("finding", "finding"),
    ("evidence reviewed", "evidence"),
    ("severity", "severity"),
    ("recommendation", "recommendation"),
    ("owner", "owner"),
    ("target date", "target_date"),
)
FIELDS = ("n", "master_id", "domain", "title", "audit_check", "suggested_evidence", "covers", "source_standards",
          "nist_ref", "fr", "min_sl", "audit_scope", "conditional", "status", "maturity", "finding", "evidence",
          "severity", "recommendation", "owner", "target_date")
REQUIRED = ("title", "audit_check", "status")

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ChecklistError(ValueError):
    """The upload is not a master audit checklist workbook."""


def _text(v: Any, limit: int = MAX_CELL) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        s = v.date().isoformat() if (v.hour, v.minute, v.second) == (0, 0, 0) else v.isoformat(sep=" ", timespec="minutes")
    elif isinstance(v, date):
        s = v.isoformat()
    elif isinstance(v, float) and v.is_integer():
        s = str(int(v))
    else:
        s = str(v)
    s = _CTRL_RE.sub(" ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _norm_header(v: Any) -> str:
    return re.sub(r"\s+", " ", _text(v, 200).lower()).strip()


def _map_headers(cells: list) -> dict[int, str]:
    """Column index -> field for a header row; the first matching column wins per field."""
    found: dict[int, str] = {}
    taken: set[str] = set()
    for idx, raw in enumerate(cells):
        h = _norm_header(raw)
        if not h:
            continue
        for key, field in _HEADER_KEYS:
            if field in taken:
                continue
            if h == key or (len(key) > 2 and h.startswith(key)):
                found[idx] = field
                taken.add(field)
                break
    return found


def _norm_status(v: str) -> tuple[str, bool]:
    """(status, known): case / space tolerant match against the five workbook values."""
    s = re.sub(r"\s+", " ", v.lower().replace("_", " ").replace("-", " ")).strip()
    for st in STATUSES:
        if s == st.lower().replace("-", " "):
            return st, True
    if not s:
        return "Not assessed", True
    aliases = {"partial": "Partially compliant", "partially": "Partially compliant", "non compliant": "Non-compliant",
               "noncompliant": "Non-compliant", "n/a": "Not applicable", "na": "Not applicable",
               "not applicable": "Not applicable", "yes": "Compliant", "no": "Non-compliant", "pass": "Compliant",
               "fail": "Non-compliant", "open": "Non-compliant"}
    if s in aliases:
        return aliases[s], True
    return v[:40], False


def _norm_severity(v: str) -> Optional[str]:
    s = v.strip().lower()
    if not s:
        return None
    for sv in SEVERITIES:
        if s.startswith(sv[:3]):
            return sv
    return s[:20]


def parse_workbook(data: bytes) -> dict:
    """Read the master audit checklist from xlsx bytes.

    Returns ``{"title", "sheet", "rows": [row dicts], "domains": [...], "warnings": [...],
    "references": [...]}``.  Raises ChecklistError when no sheet has the required headers.
    Formulas are read as their cached values (``data_only``)."""
    try:
        import openpyxl
    except ImportError as exc:                                  # pragma: no cover - openpyxl is a runtime dependency
        raise ChecklistError(f"openpyxl is not installed: {exc}")
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:                                    # noqa: BLE001 - zip / xml errors of a non-workbook
        raise ChecklistError(f"not an xlsx workbook ({exc.__class__.__name__})")
    try:
        sheets = ([wb[SHEET_NAME]] if SHEET_NAME in wb.sheetnames else []) + [ws for ws in wb.worksheets if ws.title != SHEET_NAME]
        header_at, mapping, sheet = None, None, None
        for ws in sheets:
            for i, cells in enumerate(ws.iter_rows(min_row=1, max_row=8, values_only=True), 1):
                m = _map_headers(list(cells))
                if all(f in m.values() for f in REQUIRED):
                    header_at, mapping, sheet = i, m, ws
                    break
            if sheet is not None:
                break
        if sheet is None:
            raise ChecklistError(f"no sheet with the columns {', '.join(_FIELD_LABEL[f] for f in REQUIRED)} "
                                 f"(expected the '{SHEET_NAME}' sheet of the master audit checklist)")
        warnings: list[str] = []
        missing = [f for f in FIELDS if f not in mapping.values()]
        if missing:
            warnings.append("columns not found (left empty): " + ", ".join(_FIELD_LABEL[f] for f in missing))
        rows: list[dict] = []
        for r_no, cells in enumerate(sheet.iter_rows(min_row=header_at + 1, values_only=True), header_at + 1):
            cells = list(cells)
            raw = {f: "" for f in FIELDS}
            for idx, field in mapping.items():
                if idx < len(cells):
                    raw[field] = _text(cells[idx])
            if not (raw["master_id"] or raw["title"] or raw["audit_check"]):
                continue                                        # blank line
            if len(rows) >= MAX_ROWS:
                warnings.append(f"only the first {MAX_ROWS} rows were read")
                break
            row = dict(raw)
            row["row"] = r_no
            row["status"], known = _norm_status(raw["status"])
            if not known:
                warnings.append(f"row {r_no} ({raw['master_id'] or raw['title']}): unknown status {raw['status']!r}")
            row["severity"] = _norm_severity(raw["severity"])
            if row["severity"] is not None and row["severity"] not in SEVERITIES:
                warnings.append(f"row {r_no} ({raw['master_id'] or raw['title']}): unknown severity {raw['severity']!r}")
            row["maturity"] = raw["maturity"]
            try:
                row["min_sl"] = str(int(float(raw["min_sl"]))) if raw["min_sl"] else ""
            except ValueError:
                pass
            if not row["n"]:
                row["n"] = str(len(rows) + 1)
            rows.append(row)
        if not rows:
            raise ChecklistError(f"the '{sheet.title}' sheet has no checklist rows")
        title = ""
        if "Instructions" in wb.sheetnames:
            for cells in wb["Instructions"].iter_rows(min_row=1, max_row=1, values_only=True):
                title = _text(cells[0] if cells else "", 200)
        references = []
        if "NIST references" in wb.sheetnames:
            for i, cells in enumerate(wb["NIST references"].iter_rows(min_row=2, values_only=True)):
                cells = [_text(c, 300) for c in cells]
                if cells and cells[0] and cells[0].lower() != "links" and i < 20:
                    references.append(" - ".join(x for x in cells[:2] if x))
        domains = list(OrderedDict((r["domain"] or "(no domain)", None) for r in rows))
        return {"title": title or "ISA/IEC 62443 Master Audit Checklist", "sheet": sheet.title, "rows": rows,
                "domains": domains, "warnings": warnings, "references": references}
    finally:
        wb.close()


_FIELD_LABEL = {
    "n": "#", "master_id": "Master ID", "domain": "Domain", "title": "Check title", "audit_check": "Audit check",
    "suggested_evidence": "Suggested evidence", "covers": "Covers (source Req IDs)", "source_standards": "Source standards",
    "nist_ref": "NIST firewall reference", "fr": "FR", "min_sl": "Min SL", "audit_scope": "Audit scope",
    "conditional": "Conditional", "status": "Status", "maturity": "Maturity level", "finding": "Finding / Observation",
    "evidence": "Evidence reviewed", "severity": "Severity", "recommendation": "Recommendation", "owner": "Owner",
    "target_date": "Target date",
}


def is_finding(row: dict) -> bool:
    """A row the auditor rated Non-compliant / Partially compliant, or wrote a finding, severity or
    recommendation on without rating it Compliant / Not applicable."""
    st = row.get("status")
    if st in ("Non-compliant", "Partially compliant"):
        return True
    if st in ("Compliant", "Not applicable"):
        return False
    return bool(row.get("finding") or row.get("severity") or row.get("recommendation"))


def select_rows(rows: list, scope: str = "findings") -> list:
    """``findings`` (default): the rows that are findings; ``assessed``: every row with a status
    other than Not assessed; ``all``: every row."""
    if scope not in SCOPES:
        raise ValueError(f"unknown scope {scope!r}; use one of {', '.join(SCOPES)}")
    if scope == "all":
        return list(rows)
    if scope == "assessed":
        return [r for r in rows if r.get("status") != "Not assessed" or is_finding(r)]
    return [r for r in rows if is_finding(r)]


def _sort_key(order: str):
    if order == "checklist":
        return lambda r: (_num(r.get("n")), r.get("row", 0))
    return lambda r: (SEV_RANK.get(r.get("severity"), 4), STATUS_RANK.get(r.get("status"), 5), _num(r.get("n")), r.get("row", 0))


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 1e9


def order_rows(rows: list, order: str = "severity") -> list:
    if order not in ORDERS:
        raise ValueError(f"unknown order {order!r}; use one of {', '.join(ORDERS)}")
    return sorted(rows, key=_sort_key(order))


def domain_summary(rows: list) -> list:
    """The workbook's Summary sheet recomputed: one dict per domain (+ a total line) with the status
    counts, the compliance percentage of the applicable, assessed checks ((C + 0.5 P) / (C + P + N))
    and the number of high-severity findings."""
    out = []
    by_dom: "OrderedDict[str, list]" = OrderedDict()
    for r in rows:
        by_dom.setdefault(r.get("domain") or "(no domain)", []).append(r)
    for dom, rs in list(by_dom.items()) + [("Total", rows)]:
        c = Counter(r.get("status") for r in rs)
        comp, part, non = c.get("Compliant", 0), c.get("Partially compliant", 0), c.get("Non-compliant", 0)
        den = comp + part + non
        out.append({"domain": dom, "total": len(rs), "compliant": comp, "partial": part, "non_compliant": non,
                    "not_applicable": c.get("Not applicable", 0), "not_assessed": c.get("Not assessed", 0),
                    "compliance_pct": round(100.0 * (comp + 0.5 * part) / den, 1) if den else None,
                    "high": sum(1 for r in rs if r.get("severity") in ("critical", "high") and is_finding(r)),
                    "findings": sum(1 for r in rs if is_finding(r)), "is_total": dom == "Total"})
    return out


DETAIL_FIELDS = ("client_name", "project_name", "author", "author_email", "version", "classification", "constraints", "report_date")
PERSON_KEYS = ("name", "role", "email")
MAX_PEOPLE = 50


def clean_text(v: Any, limit: int = 200) -> str:
    """Scalars only, control characters removed, trimmed (the Report details rule)."""
    if v is None or isinstance(v, (dict, list, tuple, bool)):
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v)).strip()[:limit]


def clean_people(items: Any, side: str) -> list:
    """[{name, role, email}] rows for the distribution list, ``side`` client / assessor; at most MAX_PEOPLE."""
    out = []
    for it in (items or []) if isinstance(items, (list, tuple)) else []:
        if not isinstance(it, dict):
            continue
        row = {k: clean_text(it.get(k)) for k in PERSON_KEYS}
        if any(row.values()):
            row["side"] = side
            out.append(row)
        if len(out) >= MAX_PEOPLE:
            break
    return out


def clean_details(raw: Any) -> dict:
    """The report details given with a report request (console card, CLI, API ``details`` JSON):
    only the known scalar fields (empty ones dropped) and the two people lists - ``distribution``
    rows keep their ``side`` (client / assessor), ``pocs`` / ``consultants`` are shorthands for the
    two sides.  Returns {} for anything that is not a mapping."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for k in DETAIL_FIELDS:
        v = clean_text(raw.get(k), 4000 if k == "constraints" else 200)
        if v:
            out[k] = v
    if "report_date" in out and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", out["report_date"]):
        out["report_date"] = out["report_date"][:40]
    people = []
    if isinstance(raw.get("distribution"), list):
        people += clean_people([x for x in raw["distribution"] if isinstance(x, dict) and x.get("side") != "assessor"], "client")
        people += clean_people([x for x in raw["distribution"] if isinstance(x, dict) and x.get("side") == "assessor"], "assessor")
    people += clean_people(raw.get("pocs"), "client") + clean_people(raw.get("consultants"), "assessor")
    if any(k in raw for k in ("distribution", "pocs", "consultants")):
        out["distribution"] = [x for x in people if x["side"] == "client"][:MAX_PEOPLE] + [x for x in people if x["side"] == "assessor"][:MAX_PEOPLE]
    if isinstance(raw.get("revisions"), list):
        out["revisions"] = [{k: clean_text(r.get(k)) for k in ("version", "date", "status")} for r in raw["revisions"][:MAX_PEOPLE] if isinstance(r, dict)]
        out["revisions"] = [r for r in out["revisions"] if any(r.values())]
    return out


def merge_details(base: Optional[dict], given: Optional[dict]) -> dict:
    """The site's stored Report details overridden by what the request gave (a given list replaces the stored one)."""
    out = dict(base or {})
    for k, v in (given or {}).items():
        if v not in (None, ""):
            out[k] = v
    return out


def report_data(parsed: dict, scope: str = "findings", order: str = "severity", *, details: Optional[dict] = None,
                source_name: Optional[str] = None, generated_at: Optional[datetime] = None) -> dict:
    """Everything the PDF, the CSV and the JSON preview need: the selected rows numbered as
    analysis entries (``section`` = "5.n"), the counts and the per-domain summary."""
    rows = parsed["rows"]
    selected = order_rows(select_rows(rows, scope), order)
    for i, r in enumerate(selected, 1):
        r["section"] = f"5.{i}"
    sev = Counter(r.get("severity") if r.get("severity") in SEVERITIES else None for r in selected)
    warnings = list(parsed.get("warnings") or [])
    unrated = [r for r in selected if r.get("status") == "Not assessed"]
    if unrated:
        warnings.append(f"{len(unrated)} check(s) carry a finding, severity or recommendation without a status and are reported as "
                        "Not assessed: " + ", ".join(r.get("master_id") or f"row {r.get('row')}" for r in unrated[:12])
                        + (" …" if len(unrated) > 12 else ""))
    generated_at = generated_at or datetime.now().astimezone()
    d = dict(details or {})
    report_date = clean_text(d.get("report_date"), 40) or generated_at.strftime("%Y-%m-%d")
    return {
        "checklist": parsed["title"], "sheet": parsed["sheet"], "source_name": source_name or "", "scope": scope, "order": order,
        "generated_at": generated_at, "report_date": report_date, "details": d, "site": d.get("site"),
        "rows": rows, "selected": selected, "domains": parsed["domains"], "summary": domain_summary(rows),
        "by_status": dict(Counter(r.get("status") for r in rows)),
        "by_severity": {k or "unrated": v for k, v in sev.items()},
        "n_rows": len(rows), "n_selected": len(selected), "n_findings": sum(1 for r in rows if is_finding(r)),
        "n_assessed": sum(1 for r in rows if r.get("status") != "Not assessed"),
        "warnings": warnings, "references": list(parsed.get("references") or []),
    }


CSV_COLUMNS = (
    ("section", "Section"), ("master_id", "Master ID"), ("domain", "Domain"), ("title", "Finding title (check title)"),
    ("audit_check", "Finding details (audit check)"), ("status", "Status"), ("maturity", "Maturity level"),
    ("severity", "Severity"), ("finding", "Finding / Observation"), ("evidence", "Evidence reviewed"),
    ("suggested_evidence", "Suggested evidence"), ("recommendation", "Recommendation"), ("owner", "Owner"),
    ("target_date", "Target date"), ("fr", "FR"), ("min_sl", "Min SL"), ("audit_scope", "Audit scope"),
    ("conditional", "Conditional"), ("covers", "Covers (source Req IDs)"), ("source_standards", "Source standards"),
    ("nist_ref", "NIST firewall reference"),
)


def _csv_safe(v: Any) -> Any:
    """B-18: a cell starting with = + - @ (or a tab / CR) would run as a formula in a spreadsheet."""
    if isinstance(v, str) and v and v[0] in "=+-@\t\r":
        return "'" + v
    return v


def to_csv(data: dict) -> str:
    """One line per selected finding, in report order (UTF-8 with BOM so Excel opens it as UTF-8)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow([label for _k, label in CSV_COLUMNS])
    for r in data["selected"]:
        w.writerow([_csv_safe(_cell(r, k)) for k, _label in CSV_COLUMNS])
    return "﻿" + buf.getvalue()


def _cell(r: dict, k: str) -> str:
    v = r.get(k)
    if k == "severity":
        return (v or "").title() if v else ""
    return "" if v is None else str(v)


def summary_json(data: dict, limit: int = 500) -> dict:
    """The JSON preview of ``POST /reports/audit-checklist?format=json``."""
    return {
        "checklist": data["checklist"], "sheet": data["sheet"], "source_name": data["source_name"], "scope": data["scope"],
        "order": data["order"], "rows": data["n_rows"], "assessed": data["n_assessed"], "findings": data["n_findings"],
        "selected": data["n_selected"], "by_status": data["by_status"], "by_severity": data["by_severity"],
        "domains": [{k: v for k, v in d.items() if k != "is_total"} for d in data["summary"]],
        "items": [{"section": r.get("section"), "master_id": r.get("master_id"), "title": r.get("title"), "domain": r.get("domain"),
                   "status": r.get("status"), "severity": r.get("severity"), "maturity": r.get("maturity"),
                   "has_observation": bool(r.get("finding")), "has_evidence": bool(r.get("evidence")),
                   "has_recommendation": bool(r.get("recommendation"))} for r in data["selected"][:limit]],
        "truncated": max(0, data["n_selected"] - limit), "warnings": data["warnings"],
    }
