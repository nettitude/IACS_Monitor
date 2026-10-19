"""ISA/IEC 62443 FR / security level on checks and findings (app/security_levels.py):
the catalogue, GET /findings ?target_sl= / ?fr=, the summary, the CSV export
and the PDF report's target level."""
import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
import generate_report as gr
from app import security_levels as L
from app.db import Base, get_db
from app.models import CHECK_TYPE_REFERENCE, Finding


# ---------------------------------------------------------------- parsing --

@pytest.mark.parametrize("text,frs,sl", [
    ("SR 5.1 RE2", ["FR5"], 3),
    ("SR 5.1 RE2, SR 5.2", ["FR5"], 1),
    ("SR 1.13 RE1", ["FR1"], 2),
    ("SR 2.1, SR 3.5", ["FR2", "FR3"], 1),
    ("SR 7.8", ["FR7"], 2),
    ("SR 6.2, SR 7.1", ["FR6", "FR7"], 1),
    ("SR 5.2 RE3", ["FR5"], 3),
    ("SR 2.12", ["FR2"], 3),
    ("SR 5.1 RE 2", ["FR5"], 3),
    ("SR 5.1(RE2)", ["FR5"], 3),
    ("SR 2.9, 2.10", ["FR2"], 1),                      # bare number continues the SR list
    ("SR 7.1, 7.2 / 7.4 — HA failover", ["FR7"], 1),
    ("SR 7.6, 2-1 NET 1.4", ["FR7"], 1),               # 62443-2-1 part ignored
    ("SR 5.2, ZCR 3", ["FR5"], 1),
    ("2-1 SPE 2", [], None),                           # no 62443-3-3 SR
    ("SR 8.1", [], None),                              # not a 3-3 SR
    ("", [], None),
    (None, [], None),
])
def test_parse(text, frs, sl):
    assert L.frs(text) == frs
    assert L.security_level(text) == sl


def test_sl_by_requirement():
    assert L.sl_by_requirement("SR 5.1 RE2, SR 5.2") == {"SR 5.1 RE2": 3, "SR 5.2": 1}


def test_matches_target_and_fr():
    assert L.matches("SR 5.1 RE2", target_sl=3)
    assert not L.matches("SR 5.1 RE2", target_sl=2)
    assert L.matches("2-1 SPE 2", target_sl=1)          # programme item: every level
    assert not L.matches("2-1 SPE 2", fr="FR5")
    assert L.matches("SR 2.1, SR 3.5", fr="FR3")
    assert not L.matches("SR 2.1, SR 3.5", fr="FR5")


@pytest.mark.parametrize("raw,want", [("2", 2), ("SL3", 3), ("sl-t 4", 4), ("SL-T1", 1), ("", None), (None, None)])
def test_normalize_sl(raw, want):
    assert L.normalize_sl(raw) == want


@pytest.mark.parametrize("raw", ["5", "SL9", "x", "-1"])
def test_normalize_sl_rejects(raw):
    with pytest.raises(ValueError):
        L.normalize_sl(raw)


@pytest.mark.parametrize("raw,want", [("FR5", "FR5"), ("fr1", "FR1"), ("7", "FR7"), ("RDF", "FR5"), ("", None)])
def test_normalize_fr(raw, want):
    assert L.normalize_fr(raw) == want


def test_normalize_fr_rejects():
    with pytest.raises(ValueError):
        L.normalize_fr("FR8")


def test_every_registered_sr_parses():
    """Every catalogue SR string either yields a 3-3 level or is a 2-1-only
    programme item - no typo silently drops a requirement."""
    for name, info in gr.check_catalogue().items():
        if info["sl"] is None:
            assert "SR" not in (info["sr"] or "").upper(), (name, info["sr"])
        else:
            assert info["fr"], name
            assert all(v is not None for v in info["sl_by_sr"].values()), (name, info["sl_by_sr"])


def test_catalogue_carries_fr_and_sl():
    cat = gr.check_catalogue()
    assert cat["session_ot_internet_egress"]["sl"] == 3
    assert cat["session_ot_internet_egress"]["fr"] == ["FR5"]
    assert cat["config_vpn_source_unrestricted"]["sl"] == 2
    assert cat["unauth_ot_write"]["fr"] == ["FR2", "FR3"]
    assert cat["zone_doc_1_6"]["sl"] is None and cat["zone_doc_1_6"]["fr"] == []


# -------------------------------------------------------------------- API --

@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'sl.db'}",
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
        with Session() as s:
            def F(check, sr=None, status="open"):
                ref = CHECK_TYPE_REFERENCE.get(check)
                return Finding(category=ref[3] if ref else "config_review", check_name=check,
                               severity="high", status=status, title=f"{check} t",
                               isa62443_sr=sr if sr is not None else ref[0],
                               checklist_id=ref[1] if ref else "9.9", device_name="FW1")
            s.add_all([
                F("session_ot_internet_egress"),            # SR 5.1 RE2 -> SL3, FR5
                F("config_vpn_source_unrestricted"),        # SR 1.13 RE1 -> SL2, FR1
                F("unauth_ot_write"),                       # SR 2.1, SR 3.5 -> SL1, FR2+FR3
                F("zone_doc_1_6"),                          # 2-1 only
                F("config_custom", sr=""),                  # no SR at all
                F("config_custom2", sr="SR 6.2"),           # SL2, FR6 (inline SR)
            ])
            s.commit()
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def _checks(rows):
    return sorted(r["check_name"] for r in rows)


def test_rows_carry_fr_and_level(client):
    rows = {r["check_name"]: r for r in client.get("/findings").json()}
    assert rows["session_ot_internet_egress"]["security_level"] == 3
    assert rows["session_ot_internet_egress"]["fr"] == ["FR5"]
    assert rows["unauth_ot_write"]["fr"] == ["FR2", "FR3"]
    assert rows["zone_doc_1_6"]["security_level"] is None
    assert rows["config_custom2"]["security_level"] == 2


def test_target_sl_filter(client):
    r = client.get("/findings", params={"target_sl": 1})
    assert r.status_code == 200
    assert _checks(r.json()) == ["config_custom", "unauth_ot_write", "zone_doc_1_6"]
    assert r.headers["X-Total-Count"] == "3"
    sl2 = _checks(client.get("/findings", params={"target_sl": "SL2"}).json())
    assert "config_vpn_source_unrestricted" in sl2 and "config_custom2" in sl2
    assert "session_ot_internet_egress" not in sl2
    assert len(client.get("/findings", params={"target_sl": 3}).json()) == 6


def test_fr_filter(client):
    assert _checks(client.get("/findings", params={"fr": "FR3"}).json()) == ["unauth_ot_write"]
    assert _checks(client.get("/findings", params={"fr": "5"}).json()) == ["session_ot_internet_egress"]
    both = client.get("/findings", params={"fr": "FR5", "target_sl": 2}).json()
    assert both == []


def test_bad_params_422(client):
    assert client.get("/findings", params={"target_sl": 5}).status_code == 422
    assert client.get("/findings", params={"fr": "FR9"}).status_code == 422
    assert client.get("/findings/summary", params={"target_sl": "x"}).status_code == 422


def test_summary_by_level_and_filter(client):
    s = client.get("/findings/summary").json()
    assert s["by_security_level"] == {"SL1": 1, "SL2": 2, "SL3": 1, "none": 2}
    assert s["by_fr"]["FR2"] == 1 and s["by_fr"]["FR3"] == 1
    s1 = client.get("/findings/summary", params={"target_sl": 1}).json()
    assert s1["total_open"] == 3 and s1["target_sl"] == 1
    assert sum(x["open"] for x in s1["by_site"]) == 3


def test_category_reference_has_levels(client):
    rows = {r["check_name"]: r for r in client.get("/findings/category-reference").json()}
    assert rows["session_ot_internet_egress"]["security_level"] == 3
    assert rows["cross_fw_any_any_permit"]["security_level"] == 2
    assert rows["cross_fw_any_any_permit"]["fr"] == ["FR5"]


def test_export_columns_and_filter(client):
    r = client.get("/findings/export", params={"target_sl": 2})
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {"fr", "security_level"} <= set(rows[0])
    by = {x["check_name"]: x for x in rows}
    assert "session_ot_internet_egress" not in by
    assert by["unauth_ot_write"]["fr"] == "FR2 FR3"
    assert by["config_vpn_source_unrestricted"]["security_level"] == "SL2"
    assert by["zone_doc_1_6"]["security_level"] == ""


# ----------------------------------------------------------------- report --

def test_report_target_level(client):
    with client.Session() as s:
        full = gr.collect_report_data(s)
        sl1 = gr.collect_report_data(s, target_sl=1)
    assert len(full["findings"]) == 6
    assert sorted(f["check_name"] for f in sl1["findings"]) == [
        "config_custom", "unauth_ot_write", "zone_doc_1_6"]
    assert "session_ot_internet_egress" in sl1["above_target"]
    assert all(c["sl"] is None or c["sl"] <= 1 for c in sl1["coverage"])
    assert len(sl1["coverage"]) < len(full["coverage"])
    total = sum(sum(v.values()) for v in sl1["sev_status"].values())
    assert total == 3
    buf = io.BytesIO()
    gr.render_pdf(sl1, buf)
    assert buf.getvalue()[:4] == b"%PDF"


def test_report_pdf_text(client):
    pypdf = pytest.importorskip("pypdf")
    with client.Session() as s:
        data = gr.collect_report_data(s, target_sl=2)
    buf = io.BytesIO()
    gr.render_pdf(data, buf)
    text = " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(buf.getvalue())).pages)
    assert "SL-T 2" in text
    # owner 2026-10-17: the FR x SL matrix is no longer printed; the check selection notes checks above the target
    assert "Foundational Requirement and Security Level" not in text
    assert "above SL-T" in text


def test_report_route_target_sl(client):
    r = client.get("/reports/compliance.pdf", params={"target_sl": 2})
    assert r.status_code == 200 and r.content[:4] == b"%PDF"
    assert client.get("/reports/compliance.pdf", params={"target_sl": 7}).status_code == 422


def test_cli_target_sl_arg():
    with pytest.raises(SystemExit):
        gr.main(["--target-sl", "5", "--db", "sqlite://"])


@pytest.mark.parametrize("raw,want", [("0", 0), ("SL0", 0), ("SL0 - No Requirements", 0),
                                      ("SL2 - Simple Intentional Means", 2)])
def test_normalize_sl_accepts_sl0_and_labels(raw, want):
    """Owner 2026-10-14: the report's SL-T list matches the other SL lists (SL0-SL4, labelled)."""
    assert L.normalize_sl(raw) == want
