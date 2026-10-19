"""
Access-path review phase 4: the "Permitted Communication Paths & Permissive
Policies" section of the compliance PDF (generate_report.py), driven by the
Access Review selection (access_path_tag.report_include).

PLANT1-FGT tabletop scenario (tests/test_access_paths.py); the PDF text is
extracted with pypdf.
"""
import io
import re

import pytest
from pypdf import PdfReader

import generate_report as gr
from app.parsers import alert_engine as ae
from app.parsers.access_paths import classify_access_paths, enumerate_access_paths
from tests.test_access_paths import (  # noqa: F401  (db fixture re-used)
    PLANT1_CFG, PLANT1_LEVELS, _ingest, _site, db,
)
from tests.test_access_paths_overlay import FIELD, HISTORIAN, PLC, _plant, _sess

TITLE = "Permitted Communication Paths & Permissive Policies"
FOOTNOTE = gr.ACCESS_PATH_FOOTNOTE


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _pdf_text(db, **opts) -> str:
    pdf = gr.generate_report_bytes(db, **opts)
    reader = PdfReader(io.BytesIO(pdf))
    return _norm(" ".join(page.extract_text() or "" for page in reader.pages))


def _section(text: str, nth: int = 0) -> str:
    starts = [m.start() for m in re.finditer(re.escape(TITLE), text)]
    assert len(starts) > nth, "section title missing"
    start = starts[nth]
    end = text.find("Check Coverage", start)
    return text[start:end if end != -1 else None]


def _paths(db, sid):
    return enumerate_access_paths(db, sid)


def _by_pid(paths, pid):
    rows = [p for p in paths if p["direction"] != "composed"
            and [c["policy_id"] for c in p["chain"]] == [pid]]
    assert len(rows) == 1
    return rows[0]["tag_key"]


def _tag(db, sid, items):
    classify_access_paths(db, sid, items)
    db.commit()


@pytest.fixture
def tagged(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[PLC], 40000, 502)          # #6 seen (1 session)
    _sess(db, h[HISTORIAN], h[FIELD], 41000, 502)        # unexplained L4 -> L0
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    out = _paths(db, sid)
    p = out["paths"]
    flow = out["unmatched_observed"][0]["tag_key"]
    _tag(db, sid, [
        {"tag_key": _by_pid(p, "6"), "classification": "it_ot_bypass",
         "note": "Raise change to remove policy 6", "classified_by": "alice"},
        {"tag_key": _by_pid(p, "3"), "classification": "permissive", "note": "too broad"},
        {"tag_key": _by_pid(p, "5"), "classification": "exception", "report_include": True,
         "note": "vendor portal"},
        {"tag_key": _by_pid(p, "8"), "report_include": False},
        {"tag_key": _by_pid(p, "9"), "report_include": False},
        {"tag_key": flow, "note": "who is this"},
    ])
    return sid


def test_section_groups_lines_and_wording(db, tagged):
    sec = _section(_pdf_text(db, site_id=tagged, site="Plant 1"))
    # group headers in order
    order = ["IT/OT boundary bypass (1)", "Permissive (1)", "Accepted exception / Reviewed OK (1)",
             "Unclassified, for review (", "Unexplained flows (1)"]
    pos = [sec.find(h) for h in order]
    assert all(x != -1 for x in pos), list(zip(order, pos))
    assert pos == sorted(pos)
    # summary table
    for col in ("Classification", "Lines", "Seen in capture", "Not seen in capture", "No capture"):
        assert col in sec
    # included lines (narrow cells may wrap a long name: compare without spaces)
    flat = sec.replace(" ", "")
    assert "DIRECT-it-to-plc-BYPASS" in flat and "broad-mgmt" in flat and "remote-hmi-vip" in flat
    assert "Raise change to remove policy 6" in sec and "vendor portal" in sec
    assert "No rule allows this" in sec and "who is this" in sec
    assert "dmz-poll-plc" in flat                      # unclassified, flagged -> default included
    assert "10.40.0.10" in sec                        # composed row shows its pivot
    # excluded lines absent
    assert "hmi-to-plc" not in flat and "plc-to-field" not in flat
    # traffic wording
    assert "Seen in capture (1 session)" in sec
    assert re.search(r"Notseenincapture\(window\d{4}-\d\d-\d\d\d\d:\d\d–\d{4}-\d\d-\d\d"
                     r"\d\d:\d\d\)", flat)
    assert "No capture loaded" not in sec
    # SR references from the check mapping
    assert "SR 5.1 RE2" in sec and "SR 7.7" in sec
    # footnote present; "unused" never used outside it
    assert _norm(FOOTNOTE) in sec
    assert "unused" not in sec.replace(_norm(FOOTNOTE), "").lower()
    # intro names the config upload and the capture window
    assert "PLANT1-FGT, uploaded" in sec and "capture window" in sec


def test_section_no_capture_wording(db):
    sid, _ = _plant(db)
    p = _paths(db, sid)["paths"]
    _tag(db, sid, [{"tag_key": _by_pid(p, "3"), "classification": "permissive"}])
    sec = _section(_pdf_text(db, site_id=sid))
    assert "No capture loaded" in sec
    assert "no packet capture is loaded" in sec
    assert "Not seen in capture (" not in sec
    assert "unused" not in sec.replace(_norm(FOOTNOTE), "").lower()


def test_section_nothing_selected(db):
    sid, _ = _plant(db)
    out = _paths(db, sid)
    items = [{"tag_key": r["tag_key"], "report_include": False} for r in out["paths"]]
    _tag(db, sid, items)
    sec = _section(_pdf_text(db, site_id=sid))
    assert "No lines were selected for this report in Access Review." in sec
    assert "IT/OT boundary bypass (" not in sec


def test_section_lists_orphaned_classifications(db, tagged):
    cfg = re.sub(r"    edit 3\n.*?    next\n", "", PLANT1_CFG, count=1, flags=re.S)
    _ingest(db, cfg, "PLANT1-FGT", tagged, PLANT1_LEVELS)
    sec = _section(_pdf_text(db, site_id=tagged))
    assert "Classifications whose path is no longer in the configuration" in sec
    assert "too broad" in sec and "policy 3" in sec
    assert "broad-mgmt" not in sec.replace(" ", "")


def test_rollup_has_one_section_per_site(db, tagged):
    other, _ = _plant(db, name="Plant 2")
    text = _pdf_text(db, all_sites=True)
    assert text.count(TITLE) == 2
    first, second = _section(text, 0), _section(text, 1)
    assert "Raise change to remove policy 6" in first
    assert "Raise change to remove policy 6" not in second     # sites isolated


def test_collect_data_shapes(db, tagged):
    d = gr.collect_report_data(db, site_id=tagged, site="Plant 1")
    [sec] = d["access_paths"]
    assert sec["site_id"] == tagged and sec["error"] is None
    labels = {r["label"]: r for r in sec["summary"]}
    assert labels["IT/OT boundary bypass"]["seen"] == 1
    assert labels["Permissive"]["not_seen"] == 1
    assert all(ln["traffic"] for g in sec["groups"].values() for ln in g)
    assert gr.access_path_traffic_text({"status": "partial"}) == "Seen on one leg"
    assert gr.access_path_traffic_text({"status": "no_capture"}) == "No capture loaded"
    assert gr.access_path_traffic_text({"status": "seen", "sessions": 3}) == \
        "Seen in capture (3 sessions)"


def test_section_failure_does_not_break_report(db, tagged, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("enumeration failed")
    monkeypatch.setattr("app.parsers.access_paths._enumerate", boom)
    sec = _section(_pdf_text(db, site_id=tagged))
    assert "could not be computed" in sec



# ------------------------------------------------- report-line count / API --
@pytest.fixture
def client(db, monkeypatch):
    """TestClient on the test's in-memory session (GET /access-paths and
    POST /access-paths/classify)."""
    import app.main as main_mod
    from fastapi.testclient import TestClient
    from app.db import get_db, get_write_db

    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    monkeypatch.setattr("app.parsers.access_path_findings.sync_findings_for_tags",
                        lambda db, site_id, keys: {"implemented": False})

    def _get_db():
        yield db

    ov = main_mod.app.dependency_overrides
    ov[get_db] = ov[get_write_db] = _get_db
    try:
        yield TestClient(main_mod.app)
    finally:
        ov.pop(get_db, None)
        ov.pop(get_write_db, None)


def _intro_count(sec_text: str) -> int:
    m = re.search(r"This section lists the (\d+) lines?", sec_text)
    assert m, "intro line count missing"
    return int(m.group(1))


def test_api_report_count_equals_lines_printed(db, tagged, client):
    """counts.report_include (the console's "Generate report (N lines)") =
    every line the report prints: paths + composed + unexplained flows."""
    j = client.get("/access-paths", params={"site_id": tagged}).json()
    c = j["counts"]
    bk = c["report_include_by_kind"]
    assert set(bk) == {"path", "composed", "unexplained"}
    assert bk["unexplained"] == 1 and bk["composed"] >= 1      # an included unexplained flow
    assert c["report_include"] == sum(bk.values())
    [sec] = gr.collect_report_data(db, site_id=tagged)["access_paths"]
    printed = [ln for g in sec["groups"].values() for ln in g]
    assert len(printed) == sec["included"] == c["report_include"]
    assert {k: sum(1 for ln in printed if ln["kind"] == k) for k in bk} == bk
    text = _section(_pdf_text(db, site_id=tagged))
    assert _intro_count(text) == c["report_include"]
    assert re.search(rf"Total {c['report_include']} ", text)
    # filters narrow the rows, never the report count
    f = client.get("/access-paths", params={"site_id": tagged, "classification": "permissive",
                                            "include_unmatched": "false"}).json()["counts"]
    assert f["total"] == 1 and f["report_include"] == c["report_include"]
    # the classify response carries the updated count; excluding the flow drops it by one
    flow = j["unmatched_observed"][0]["tag_key"]
    r = client.post("/access-paths/classify", json={"site_id": tagged, "items": [
        {"tag_key": flow, "report_include": False}]})
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["report_include"] == c["report_include"] - 1
    assert r.json()["counts"]["report_include_by_kind"]["unexplained"] == 0
    again = client.get("/access-paths", params={"site_id": tagged}).json()["counts"]
    assert again["report_include"] == c["report_include"] - 1
    assert _intro_count(_section(_pdf_text(db, site_id=tagged))) == c["report_include"] - 1


_SUMMARY_ROW = r" (\d+) (\d+) (\d+) (\d+)"


def test_summary_rows_mirror_group_headers(db, tagged):
    """One summary row per printed group (same order, label, count); an
    unexplained flow counts only under Unexplained flows, whatever its
    classification (shown in its note)."""
    flow = _paths(db, tagged)["unmatched_observed"][0]["tag_key"]
    _tag(db, tagged, [{"tag_key": flow, "classification": "permissive"}])
    [sec] = gr.collect_report_data(db, site_id=tagged)["access_paths"]
    want = [(lbl, len(sec["groups"][k])) for k, lbl, always, _d in gr._AP_GROUPS
            if always or sec["groups"][k]]
    assert [(r["label"], r["lines"]) for r in sec["summary"]] == want
    assert dict(want)["Permissive"] == 1 and dict(want)["Unexplained flows"] == 1
    text = _section(_pdf_text(db, site_id=tagged))
    table = text[text.index("No capture", text.index("Classification Lines")):]
    table = table[:table.index("Total ")]
    pos = []
    for label, n in want:
        m = re.search(re.escape(label) + _SUMMARY_ROW, table)
        assert m and int(m.group(1)) == n, (label, n, table)
        pos.append(m.start())
        assert f"{label} ({n})" in text                          # the group header
    assert pos == sorted(pos)
    total = sum(n for _l, n in want)
    assert re.search(rf"Total {total} ", text) and _intro_count(text) == total
    unexp = text[text.index("Unexplained flows (1)"):]
    assert "Permissive: who is this" in unexp


def _section_raw(db, site_id) -> str:
    pdf = gr.generate_report_bytes(db, site_id=site_id)
    raw = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)
    starts = [m.start() for m in re.finditer(re.escape(TITLE), raw)]
    start = starts[-1]
    end = raw.find("Check Coverage", start)
    return raw[start:end if end != -1 else None]


def test_section_tables_never_split_words(db, tagged):
    raw = _section_raw(db, tagged)
    # undo only the line breaks the report puts at its allowed break points
    joined = _norm(re.sub(r"([_\-–/])\n", r"\1", raw))
    for tok in ("Path", "Service", "Allowed by", "Flags", "Traffic", "Reviewer note",
                "ISA/IEC 62443", "cleartext_protocol", "industrial_proto_out_of_zone",
                "DIRECT-it-to-plc-BYPASS", "conduit_through_dmz", "historian-to-dmz",
                "10.30.0.100/32", "SR 5.1 RE2", "Not seen in capture"):
        assert tok in joined, tok
    # each header row is printed whole (one table per printed group)
    heads = "Path Service Allowed by Flags Traffic Reviewer note ISA/IEC 62443"
    assert _norm(raw).count(heads) == 5
    for bad in ("Servic e", "BYPAS S", "DIR ECT", "protoc ol", "proto _out", "ISA/IEC 6 2443"):
        assert bad not in _norm(raw), bad
    # every word of every printed cell (flags, policies, paths, services,
    # SR references) survives whole once the allowed breaks are undone
    [sec] = gr.collect_report_data(db, site_id=tagged)["access_paths"]
    words = set()
    for ln in (x for g in sec["groups"].values() for x in g):
        for v in [ln["path"], ln["service"], ln["sr"], *ln["flags"], *ln["allowed_by"]]:
            words.update(v.split())
    assert words
    jw = set(joined.split())
    missing = [w for w in words if w not in jw and w.rstrip(",") not in jw and w + "," not in jw]
    assert not missing, missing
    # intro + footnote unchanged
    norm = _norm(raw)
    assert _norm(FOOTNOTE) in norm and "PLANT1-FGT, uploaded" in norm


def test_ap_cell_breaks_only_after_separators():
    w = 2.0 * gr.cm
    out = gr._ap_cell("industrial_proto_out_of_zone", gr.AP_CELL_SMALL, w)
    parts = out.split("<br/>")
    assert len(parts) > 1 and "".join(parts) == "industrial_proto_out_of_zone"
    assert all(p.endswith("_") for p in parts[:-1])
    out = gr._ap_cell("PLANT1-FGT #6 DIRECT-it-to-plc-BYPASS", gr.AP_CELL_SMALL, w)
    assert "".join(out.split("<br/>")) == "PLANT1-FGT #6 DIRECT-it-to-plc-BYPASS"
    assert all(p.endswith("-") for p in out.split("<br/>")[:-1])
    assert gr._ap_cell("a <b> & c", gr.AP_CELL_SMALL, w) == "a &lt;b&gt; &amp; c"
