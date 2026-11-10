"""
Multi-site phase 4 (docs/multi-site-design.md): read-only roll-up
(GET /sites/rollup), per-site PDF isolation, all-sites PDF sections,
unmapped-line retention sanity.
"""
import io
from datetime import datetime, timedelta, timezone

import pypdf
import pytest
from sqlalchemy import event

from app.models import (
    Attestation, Baseline, Finding, Firewall, FirewallDevice, Host, PcapCapture,
    Site, UnmappedLogEvent, utcnow,
)
from tests.test_sites_phase3 import _api, _ok, up, asa, pending

pytestmark = pytest.mark.no_auto_site


def _finding(site_id, sev, title, status="open", n=0):
    return Finding(site_id=site_id, category="config_review", check_name="it_ot_bypass",
                   severity=sev, status=status, title=title, isa62443_sr="SR 5.2",
                   checklist_id="5.2", detail={"n": n}, device_name=f"dev-{site_id}",
                   source_ref=f"s{site_id}:{title}:{n}")


@pytest.fixture
def client(tmp_path):
    from app.parsers import alert_engine
    alert_engine._last_review_info.clear()
    alert_engine._last_review_info_by_site.clear()     # process-wide state of earlier tests
    with _api(tmp_path / "p4.db") as c:
        _ok(c.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit
        c.site_a = _ok(c.post("/sites", json={"name": "Alpha Plant", "code": "alpha"}), 201)["id"]
        c.site_b = _ok(c.post("/sites", json={"name": "Bravo Works", "code": "bravo"}), 201)["id"]
        now = datetime.now(timezone.utc)
        with c.Session() as s:
            a, b = c.site_a, c.site_b
            s.add_all([Firewall(site_id=a, name="FW-ALPHA-ONLY", config_uploaded_at=now - timedelta(days=10)), Firewall(site_id=b, name="FW-BRAVO-1", config_uploaded_at=now - timedelta(days=3)),
                       Firewall(site_id=b, name="FW-BRAVO-2", config_uploaded_at=now - timedelta(days=4)),
                       FirewallDevice(site_id=a, name="DEV-ALPHA-ONLY", vendor="fortigate"),
                       FirewallDevice(site_id=b, name="DEV-BRAVO-ONLY", vendor="fortigate"),
                       Host(site_id=a, ip="10.1.0.1"), Host(site_id=b, ip="10.2.0.1"),
                       Host(site_id=b, ip="10.2.0.2"), Host(site_id=b, ip="10.2.0.3")])
            s.add_all([_finding(a, "critical", "ALPHA-CRIT-SECRET", n=1),
                       _finding(a, "high", "alpha high", n=2),
                       _finding(a, "high", "alpha closed", status="closed", n=3),
                       _finding(b, "medium", "BRAVO-MED-SECRET", n=4),
                       _finding(b, "low", "bravo low", n=5), _finding(b, "low", "bravo low 2", n=6)])
            ba = Baseline(site_id=a, name="ALPHA-BASE", is_active=True)
            bb = Baseline(site_id=b, name="BRAVO-BASE", is_active=False)
            s.add_all([ba, bb])
            s.flush()
            for cl in ("1.1", "1.2", "1.3", "1.4", "1.5", "1.6"):
                s.add(Attestation(site_id=a, checklist_id=cl, attested_by="x", attested_at=now - timedelta(days=5),
                                  baseline_id=ba.id, is_current=True))
            s.add(Attestation(site_id=b, checklist_id="1.1", attested_by="y", attested_at=now - timedelta(days=500),
                              baseline_id=None, is_current=True))
            s.add(PcapCapture(site_id=a, uploaded_at=now - timedelta(hours=2)))
            s.commit()
        yield c


def _site(d, code):
    return next(x for x in d["sites"] if x["code"] == code)


# ------------------------------------------------------------- roll-up ------

def test_rollup_correctness(client):
    d = _ok(client.get("/sites/rollup"))
    assert [x["code"] for x in d["sites"]] == ["default", "alpha", "bravo"]
    a, b, dflt = _site(d, "alpha"), _site(d, "bravo"), _site(d, "default")
    assert (a["firewalls"], a["firewall_devices"], a["hosts"]) == (1, 1, 1)
    assert (b["firewalls"], b["firewall_devices"], b["hosts"]) == (2, 1, 3)
    assert a["open_by_severity"] == {"critical": 1, "high": 1}      # closed one not counted
    assert (a["open_critical"], a["open_high"], a["open_findings"]) == (1, 1, 2)
    assert b["open_by_severity"] == {"medium": 1, "low": 2}
    assert (b["open_critical"], b["open_high"], b["open_findings"]) == (0, 0, 3)
    assert dflt["open_findings"] == 0 and dflt["open_by_severity"] == {}
    assert a["baseline_active"] == "ALPHA-BASE" and b["baseline_active"] is None
    assert a["attestation"]["state"] == "current" and a["attestation"]["current"] == 6
    assert b["attestation"]["state"] == "overdue"
    assert (b["attestation"]["current"], b["attestation"]["stale"], b["attestation"]["missing"]) == (0, 1, 5)
    now = datetime.now(timezone.utc)
    ua, ub = (datetime.fromisoformat(x["last_upload_at"]) for x in (a, b))
    assert timedelta(hours=1) < now - ua < timedelta(hours=3)        # newest of config / PCAP
    assert timedelta(days=2.9) < now - ub < timedelta(days=3.1)
    assert dflt["last_upload_at"] is None
    assert a["last_review_at"] is None                          # no review ran in this process for it
    t = d["totals"]
    assert (t["sites"], t["firewalls"], t["hosts"], t["open_findings"]) == (3, 3, 4, 5)
    assert t["open_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 2}
    assert t["open_critical"] == 1 and t["open_high"] == 1 and t["attestation_overdue_sites"] == 2
    assert d["unmapped_pending"] == 0


def test_rollup_unmapped_global_and_review_time(client):
    _ok(up(client, "/ingest/syslog", "u.log", asa("nobody", 1)))
    assert pending(client) == 1
    _ok(client.post("/reviews/run", params={"site_id": client.site_a}))
    d = _ok(client.get("/sites/rollup"))
    assert d["unmapped_pending"] == 1
    assert _site(d, "alpha")["last_review_at"] and _site(d, "bravo")["last_review_at"] is None


def test_rollup_is_read_only_and_not_n_plus_one(client):
    engine = client.Session.kw["bind"]
    stmts, writes = [], []

    @event.listens_for(engine, "before_cursor_execute")
    def _spy(conn, cur, statement, params, ctx, many):
        stmts.append(statement)
        if statement.lstrip().split(None, 1)[0].upper() in ("INSERT", "UPDATE", "DELETE"):
            writes.append(statement)
    try:
        _ok(client.get("/sites/rollup"))
        few = len(stmts)
        with client.Session() as s:
            for i in range(5):
                s.add(Site(name=f"Extra {i}", code=f"extra{i}"))
            s.commit()
        stmts.clear()
        writes.clear()
        _ok(client.get("/sites/rollup"))
    finally:
        event.remove(engine, "before_cursor_execute", _spy)
    assert writes == []
    assert len(stmts) <= few + 1, (few, len(stmts))        # query count independent of site count


def test_rollup_route_not_shadowed_by_site_id(client):
    assert client.get("/sites/rollup").status_code == 200
    assert client.get("/sites/9999").status_code == 404


# --------------------------------------------------------------- PDF --------

def _text(pdf: bytes) -> str:
    return "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)


def test_per_site_pdf_isolation(client):
    ra = client.get("/reports/compliance.pdf", params={"site_id": client.site_a})
    rb = client.get("/reports/compliance.pdf", params={"site": "bravo"})
    assert ra.status_code == rb.status_code == 200
    ta, tb = _text(ra.content), _text(rb.content)
    assert "Alpha Plant" in ta and "alpha" in ta and "ALPHA-CRIT-SECRET" in ta and "DEV-ALPHA-ONLY" in ta
    assert "Bravo Works" in tb and "BRAVO-MED-SECRET" in tb and "DEV-BRAVO-ONLY" in tb
    for leaked in ("Bravo", "BRAVO"):
        assert leaked not in ta, leaked
    for leaked in ("Alpha", "ALPHA"):
        assert leaked not in tb, leaked
    assert "Site Code:" in ta and "alpha" in ta  # the site code on the public cover


def test_per_site_report_data_isolation(client):
    import generate_report as gr
    with client.Session() as s:
        da = gr.collect_report_data(s, site="Alpha Plant", site_id=client.site_a)
        db_ = gr.collect_report_data(s, site="Bravo Works", site_id=client.site_b)
    assert da["site_code"] == "alpha" and db_["site_code"] == "bravo"
    assert {f["title"] for f in da["findings"]} == {"ALPHA-CRIT-SECRET", "alpha high"}
    assert {f["title"] for f in db_["findings"]} == {"BRAVO-MED-SECRET", "bravo low", "bravo low 2"}
    assert [d["name"] for d in da["firewall_devices"]] == ["DEV-ALPHA-ONLY"]
    assert [d["name"] for d in db_["firewall_devices"]] == ["DEV-BRAVO-ONLY"]
    assert da["baseline"]["name"] == "ALPHA-BASE" and db_["baseline"] is None


def test_all_sites_pdf_has_section_per_site(client):
    r = client.get("/reports/compliance.pdf", params={"all_sites": "true"})
    assert r.status_code == 200
    t = _text(r.content)
    assert "Sites in this report" in t
    for name in ("Default", "Alpha Plant", "Bravo Works"):
        assert f"Site: {name}" in t, name
    assert "ALPHA-CRIT-SECRET" in t and "BRAVO-MED-SECRET" in t
    assert client.get("/reports/compliance.pdf",
                      params={"all_sites": "true", "site_id": client.site_a}).status_code == 422
    # several sites and no site named: still refused (no silent merge)
    assert client.get("/reports/compliance.pdf").status_code == 422


# ----------------------------------------------------------- retention ------

def test_retention_purge_sanity(client, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")  # B-21: discard/purge are gated
    _ok(up(client, "/ingest/syslog", "r.log", "\n".join([asa("old-dev", 1), asa("new-dev", 2), asa("gone", 3)])))
    _ok(client.post("/site-devices/unmapped/discard", json={"device_key": "gone"}))
    with client.Session() as s:
        s.query(UnmappedLogEvent).filter_by(device_key="old-dev").update(
            {UnmappedLogEvent.received_at: utcnow() - timedelta(days=45)})
        s.commit()
    out = _ok(client.post("/site-devices/unmapped/purge", params={"days": 30}))
    assert (out["replayed_or_discarded"], out["expired_pending"], out["pending_lines"]) == (1, 1, 1)
    assert pending(client, "new-dev") == 1                      # fresh line survives
    monkeypatch.setenv("IACS_UNMAPPED_RETENTION_DAYS", "not-a-number")
    from app.site_devices import retention_days
    assert retention_days() == 30
    # purge touches no findings / events
    with client.Session() as s:
        assert s.query(Finding).count() == 6
