"""
generate_report.py (F-02): the compliance PDF is built from the database.

Uses a temp-file SQLite DB built from Base.metadata and seeded directly with
ORM rows; never touches the project DB.
"""
import io
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

import generate_report as gr
from app.db import Base, make_engine
from app.models import (
    ApprovedCommsEntry, Attestation, Baseline, CHECK_TYPE_REFERENCE, Finding,
    FirewallDevice, FirewallRule, FortiAnalyzerEvent, Host, NatRule,
)

ROOT = Path(__file__).resolve().parent.parent
XSS_TITLE = 'Rule <b>bold</b> & <img src=x onerror="alert(1)"> <para> &amp; </font>'

try:
    import pypdf
except ImportError:  # pragma: no cover
    pypdf = None


def seed_db(Session):
    now = datetime.now(timezone.utc)
    with Session() as s:
        b = Baseline(name="AUDIT-2026", is_active=True)
        s.add(b)
        s.flush()
        s.add(ApprovedCommsEntry(baseline_id=b.id, src="10.0.0.0/24", dst="10.0.1.0/24",
                                 dst_port=502, protocol="tcp"))
        dev = FirewallDevice(name="FW-<OT>&1", vendor="fortigate", purdue_zone_from=3,
                             purdue_zone_to=2)
        dev2 = FirewallDevice(name="FW-EMPTY", vendor="cisco_ios")
        s.add_all([dev, dev2])
        s.flush()
        rules = [FirewallRule(device_type="fortigate", firewall_device_id=dev.id, src="any",
                              dst="10.0.1.0/24", action="permit", enabled=True, policy_id=str(i))
                 for i in range(3)]
        rules.append(FirewallRule(device_type="fortigate", firewall_device_id=dev.id, src="any",
                                  dst="any", action="permit", enabled=False, policy_id="9"))
        s.add_all(rules)
        s.add(NatRule(firewall_device_id=dev.id, nat_type="dnat", ext_ip="1.2.3.4", mapped_ip="10.0.1.5"))
        s.add(FortiAnalyzerEvent(source_type="api_push", device_name="FW1"))
        s.add(Host(ip="10.0.1.5"))
        s.flush()

        def F(check, sev, status="open", title=None, detail=None, cl=None, sr=None, device="FW1"):
            ref = CHECK_TYPE_REFERENCE.get(check)
            return Finding(category=(ref[3] if ref else "config_review"), check_name=check,
                           severity=sev, status=status, title=title or f"{check} finding",
                           isa62443_sr=sr or (ref[0] if ref else "SR 1.1"),
                           checklist_id=cl or (ref[1] if ref else "9.9"),
                           detail=detail or {"src": "10.0.0.1", "dst": "10.0.1.5"},
                           device_name=device)
        s.add_all([
            F("it_ot_bypass", "critical"),
            F("it_ot_bypass", "critical", title=XSS_TITLE,
              detail={"note": "<script>&</script>", "nested": {"a": [1, "<x>"]}}),
            F("shadow_rule", "medium", device="dev<&>"),
            F("disabled_rule", "low", status="acknowledged"),
            F("ntp_sync", "medium", status="closed"),
            F("config_custom_thing", "high", title="Inline config check <ok>"),
            F("zone_doc_1_2", "high"),
            F("rule_cleartext_protocol", "medium", title="x" * 5000, detail={"k": "y" * 9000}),
        ])
        s.add(Attestation(checklist_id="1.1", attested_by="alice <a@x>", attested_at=now - timedelta(days=10),
                          notes="Doc at \\\\share\\zones & <diagram>", baseline_id=b.id, is_current=True,
                          proof_filename="zones<1>.pdf"))
        s.add(Attestation(checklist_id="1.3", attested_by="bob", attested_at=now - timedelta(days=500),
                          baseline_id=b.id, is_current=True))
        s.commit()


@pytest.fixture
def Session(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'report.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False)
    seed_db(S)
    yield S
    eng.dispose()


def pdf_text(data: bytes) -> str:
    r = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join(p.extract_text() or "" for p in r.pages)


def test_collect_data_counts_and_coverage(Session):
    with Session() as db:
        d = gr.collect_report_data(db, site="Plant 1")
    names = {f["check_name"] for f in d["findings"]}
    assert "ntp_sync" not in names                      # closed excluded by default
    assert {"it_ot_bypass", "disabled_rule", "config_custom_thing"} <= names
    assert d["sev_status"]["critical"]["open"] == 2
    assert d["sev_status"]["medium"]["closed"] == 1
    # catalogue always covers every CHECK_TYPE_REFERENCE entry
    assert set(CHECK_TYPE_REFERENCE) <= set(d["catalogue"])
    assert len(d["coverage"]) == len(d["catalogue"])
    cov = {c["check_name"]: c for c in d["coverage"]}
    assert cov["it_ot_bypass"]["count"] == 2 and cov["it_ot_bypass"]["state"] == "findings"
    assert cov["ghost_vlan"]["state"] == "no data"      # no switch VLANs seeded
    # rules exist but the reviews never ran: NOT EVALUATED (owner 2026-10-12), not a silent pass
    assert cov["unused_policy"]["state"] == "not evaluated"
    assert "review not run" in cov["unused_policy"]["basis"]
    # FAZ events exist: real-time checks are evaluated on each event as it arrives
    assert cov["remote_access_bypass"]["state"] == "pass" and "log event" in cov["remote_access_bypass"]["basis"]
    assert d["observed_other"] == ["config_custom_thing"]
    att = {a["checklist_id"]: a for a in d["attestations"]}
    assert att["1.1"]["status"] == "current"
    assert att["1.3"]["status"] == "stale"
    assert att["1.2"]["status"] == "missing" and att["1.2"]["open_findings"] == 1
    fw = {x["name"]: x for x in d["firewall_devices"]}
    assert fw["FW-<OT>&1"]["active_rules"] == 3
    assert fw["FW-<OT>&1"]["disabled_rules"] == 1
    assert fw["FW-<OT>&1"]["nat_rules"] == 1
    assert fw["FW-EMPTY"]["active_rules"] == 0
    assert d["baseline"]["name"] == "AUDIT-2026" and d["baseline"]["comms_entries"] == 1


def test_include_closed_and_unknown_baseline(Session):
    with Session() as db:
        d = gr.collect_report_data(db, include_closed=True)
        # owner 2026-10-14: closed findings get their own section, never the findings in scope
        assert "ntp_sync" in {f["check_name"] for f in d["closed_findings"]}
        assert "ntp_sync" not in {f["check_name"] for f in d["findings"]}
        assert d["closed_total"] == len(d["closed_findings"]) >= 1
        assert "ntp_sync" not in {f["check_name"] for f in gr.collect_report_data(db)["closed_findings"]}
        with pytest.raises(LookupError):
            gr.collect_report_data(db, baseline="nope")


def test_pdf_renders_with_markup_in_data(Session):
    with Session() as db:
        pdf = gr.generate_report_bytes(db, site='Site <A> & "B"')
    assert pdf.startswith(b"%PDF")
    if pypdf is None:
        pytest.skip("pypdf not installed")
    text = pdf_text(pdf)
    assert "Executive Summary" in text and "Check Coverage" in text
    assert "it_ot_bypass" in text and "config_custom_thing" in text
    assert "Site <A> & \"B\"" in text                     # escaped, not parsed as markup
    assert "FW-<OT>&1" in text
    assert "<b>bold</b>" in text                          # literal, not bold markup
    assert "alice <a@x>" in text
    assert "STALE" in text and "MISSING" in text and "CURRENT" in text
    # every implemented check appears in the coverage / mapping tables
    flat = text.replace("\n", "")
    for name in CHECK_TYPE_REFERENCE:
        assert name in flat, name


def test_story_builds_for_empty_db(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng)() as db:
        d = gr.collect_report_data(db)
        assert d["findings"] == [] and d["baseline"] is None
        assert all(c["state"] != "findings" for c in d["coverage"])
        assert gr.build_story(d)
        buf = io.BytesIO()
        gr.render_pdf(d, buf)
    assert buf.getvalue().startswith(b"%PDF")
    eng.dispose()


def test_escape_helper():
    assert gr.esc("<a & b>") == "&lt;a &amp; b&gt;"
    assert gr.esc("x" * 50, 10).endswith("…") and len(gr.esc("x" * 50, 10)) == 10
    assert gr.esc(None) == ""
    assert "\x01" not in gr.esc("a\x01b")


def test_cli_reads_db_readonly(Session, tmp_path):
    dbfile = tmp_path / "report.db"
    before = dbfile.stat().st_mtime_ns
    out = tmp_path / "out.pdf"
    r = subprocess.run([sys.executable, str(ROOT / "generate_report.py"), "--db", f"sqlite:///{dbfile}",
                        "--out", str(out), "--site", "CLI Site", "--include-closed"],
                       capture_output=True, text=True, cwd=tmp_path, timeout=120)
    assert r.returncode == 0, r.stderr
    assert out.read_bytes().startswith(b"%PDF")
    assert dbfile.stat().st_mtime_ns == before
    # unknown baseline -> exit 2; missing DB file -> error, file NOT created
    r = subprocess.run([sys.executable, str(ROOT / "generate_report.py"), "--db", f"sqlite:///{dbfile}",
                        "--out", str(out), "--baseline", "nope"], capture_output=True, text=True,
                       cwd=tmp_path, timeout=120)
    assert r.returncode == 2
    missing = tmp_path / "missing.db"
    r = subprocess.run([sys.executable, str(ROOT / "generate_report.py"), "--db", f"sqlite:///{missing}",
                        "--out", str(out)], capture_output=True, text=True, cwd=tmp_path, timeout=120)
    assert r.returncode != 0 and not missing.exists()


def test_paired_firewall_attestation_rows_in_report(Session):
    """The vendor-diversity attestation of each paired firewall appears in
    the attestation table (status current / missing) and the PDF builds."""
    from app.models import Attestation, Firewall, FirewallGroup, Site
    with Session() as db:
        site = db.query(Site).order_by(Site.id).first()
        if site is None:
            site = Site(name="Report site", code="report-site")
            db.add(site)
            db.flush()
        a = Firewall(site_id=site.id, name="PAIR-OUT", vendor="fortigate")
        b = Firewall(site_id=site.id, name="PAIR-IN", vendor="paloalto")
        db.add_all([a, b])
        db.flush()
        g1 = FirewallGroup(site_id=site.id, kind="paired", name="DMZ pair")
        g2 = FirewallGroup(site_id=site.id, kind="paired", name="Other pair")
        db.add_all([g1, g2])
        db.flush()
        a.paired_group_id = b.paired_group_id = g1.id
        db.add(Attestation(site_id=site.id, checklist_id=f"PF-{g1.id}", attested_by="ops",
                           attested_at=datetime.now(timezone.utc), is_current=True))
        db.commit()
        d = gr.collect_report_data(db, site_id=site.id)
        rows = {r["checklist_id"]: r for r in d["attestations"]}
        assert rows[f"PF-{g1.id}"]["status"] == "current"
        assert "PAIR-OUT + PAIR-IN" in rows[f"PF-{g1.id}"]["description"]
        assert "fortigate, paloalto" in rows[f"PF-{g1.id}"]["description"]
        assert rows[f"PF-{g2.id}"]["status"] == "missing"
        buf = io.BytesIO()
        gr.render_pdf(d, buf)
        assert pdf_text(buf.getvalue()).count("PF-") >= 2


def test_shadowed_and_redundant_rules_section(Session):
    """Owner 2026-10-14: the PDF lists the shadow_rule findings as rule pairs in their
    own section (type, severity, actions-differ mark), per firewall."""
    if pypdf is None:
        pytest.skip("pypdf not installed")
    from app.models import Finding
    rule = lambda pid, action, src, dst: {"rule_id": int(pid), "policy_id": pid, "vdom": None, "policy_name": f"pol-{pid}",
                                          "action": action, "src": src, "dst": dst, "protocol": "tcp", "dst_port": "502",
                                          "device_name": "FW-SHADOW", "rule_order": int(pid)}
    with Session() as db:
        db.add_all([
            Finding(category="periodic_review", check_name="shadow_rule", severity="low", status="open",
                    title="Rule 20 is a duplicate of rule 10", isa62443_sr="SR 7.7", checklist_id="3.9", device_name="FW-SHADOW",
                    detail={"shadow_type": "duplicate", "severity": "low", "action_conflict": False,
                            "shadowing_rule": rule("10", "permit", "10.0.4.0/24", "10.0.1.10"),
                            "shadowed_rule": rule("20", "permit", "10.0.4.0/24", "10.0.1.10")}),
            Finding(category="periodic_review", check_name="shadow_rule", severity="high", status="acknowledged",
                    title="Rule 40 is fully shadowed by rule 30", isa62443_sr="SR 7.7", checklist_id="3.9", device_name="FW-SHADOW",
                    detail={"shadow_type": "full_shadow", "severity": "high", "action_conflict": True,
                            "shadowing_rule": rule("30", "permit", "any", "10.0.1.0/24"),
                            "shadowed_rule": rule("40", "deny", "10.0.4.5", "10.0.1.0/24")}),
        ])
        db.commit()
        pdf = gr.generate_report_bytes(db)
    text = " ".join(pdf_text(pdf).split())
    i = text.index("Shadowed and Redundant Rules")
    sec = text[i:text.index("Check Coverage", i)]
    assert "FW-SHADOW: 2 pair(s)" in sec and "1 fully shadowed" in sec and "1 duplicate (redundant)" in sec
    assert "#10 pol-10" in sec and "#20 pol-20" in sec and "#30 pol-30" in sec and "#40 pol-40" in sec
    assert "Fully shadowed" in sec and "Duplicate (redundant)" in sec and "actions differ" in sec
    assert "DENY" in sec and "acknowledged" in sec
