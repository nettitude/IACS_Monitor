"""Regression tests: audit batch 2 (C) - follow-ups to B-09, B-14, B-16."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db as db_mod
from app.api import routes
from app.models import ApprovedHost, Base, Baseline, Finding, Host, Site
from app.parsers import alert_engine
from app.parsers.host_identity import mark_stale_hosts
from app.parsers.pcap_parser import GROUP_MARKER_MAC, ingest_pcap, is_group_marker_host
from app.parsers.site_scope import analysis_site

from tests.test_audit_batch2_b import _pcap, _udp


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Site(name="Plant", code="plant"))
    s.commit()
    yield s
    s.close()


def _sid(db):
    return db.query(Site).filter_by(code="plant").one().id


def _broadcast_site(db, tmp_path):
    sid = _sid(db)
    ingest_pcap(_pcap(tmp_path, [_udp("10.0.0.255", "ff:ff:ff:ff:ff:ff")]), db, site_id=sid)
    bl = Baseline(site_id=sid, name="bl", is_active=True)
    db.add(bl); db.flush()
    db.add(ApprovedHost(baseline_id=bl.id, ip="10.9.9.9", role="hmi"))  # unrelated approved host
    db.commit()
    marker = db.query(Host).filter(Host.mac == GROUP_MARKER_MAC).one()
    assert is_group_marker_host(marker)
    return sid, marker


# ------------------------------------------------- 1. marker is not a device

def test_unknown_devices_skips_group_marker(db, tmp_path):
    sid, marker = _broadcast_site(db, tmp_path)
    with analysis_site(db, sid):
        alert_engine.review_unknown_devices(db)
    db.flush()
    fs = db.query(Finding).filter_by(check_name="unknown_device").all()
    assert [f.detail["ip"] for f in fs] == ["10.0.0.1"]          # sender only
    assert not any(f.detail.get("mac") == GROUP_MARKER_MAC for f in fs)


def test_rollup_and_site_counts_exclude_marker(db, tmp_path):
    sid, _ = _broadcast_site(db, tmp_path)
    assert db.query(Host).filter(Host.site_id == sid).count() == 2   # sender + marker rows
    out = routes._sites_rollup(db)
    site = next(s for s in out["sites"] if s["id"] == sid)
    assert site["hosts"] == 1 and out["totals"]["hosts"] == 1
    assert routes._site_counts(db, [sid])[sid]["hosts"] == 1


def test_ingest_stats_and_stale_exclude_marker(db, tmp_path):
    sid = _sid(db)
    stats = ingest_pcap(_pcap(tmp_path, [_udp("10.0.0.255", "ff:ff:ff:ff:ff:ff")]), db, site_id=sid)
    assert stats["hosts_total"] == 1
    out = mark_stale_hosts(db, older_than_days=0,
                           now=datetime.now(timezone.utc) + timedelta(days=3650), site_id=sid)
    assert out["marked_stale"] == 1
    marker = db.query(Host).filter(Host.mac == GROUP_MARKER_MAC).one()
    assert marker.stale is False


def test_hosts_and_assets_lists_exclude_marker(tmp_path):
    from tests.test_cov_routes import _api
    with _api(tmp_path / "c1.db") as c:
        with c.Session() as s:
            s.add(Site(name="Default", code="default")); s.commit()
            sid = s.query(Site).one().id
            ingest_pcap(_pcap(tmp_path, [_udp("10.0.0.255", "ff:ff:ff:ff:ff:ff")]), s, site_id=sid)
            s.commit()
            assert s.query(Host).count() == 2
        for path in ("/hosts", "/assets"):
            r = c.get(path)
            assert r.status_code == 200, r.text
            body = r.json()
            rows = body if isinstance(body, list) else body.get("items", body.get("hosts", []))
            assert [h["ip"] for h in rows] == ["10.0.0.1"], (path, rows)


# ------------------------------------- 2. escalation re-open clears the ack

def test_escalation_reopen_clears_ack_fields(db):
    sid = _sid(db)
    ev = {"ip": "10.0.0.5", "mac": None}
    now = datetime.now(timezone.utc)
    f = Finding(site_id=sid, category="periodic_review", check_name="unknown_device",
                severity="low", status="acknowledged", title="old",
                source_ref=alert_engine._dedup_key("unknown_device", ev),
                acknowledged_by="alice", acknowledged_at=now, closed_at=now)
    db.add(f); db.commit()
    with analysis_site(db, sid):
        # equal severity: acknowledged finding is active for dedup, untouched
        assert alert_engine._make_finding(db, "unknown_device", "t", "d", ev, severity="low") is None
        assert f.status == "acknowledged" and f.acknowledged_by == "alice"
        # escalation: re-opened in place, stale acknowledgement dropped
        assert alert_engine._make_finding(db, "unknown_device", "t2", "d", ev, severity="critical") is None
    assert (f.status, f.severity) == ("open", "critical")
    assert (f.acknowledged_by, f.acknowledged_at, f.closed_at) == (None, None, None)
    assert "Re-opened" in f.notes
    assert db.query(Finding).count() == 1


# ------------------------------------------ 3. background jobs use writers

class _Spy:
    def __init__(self, factory):
        self.factory, self.calls = factory, 0

    def __call__(self):
        self.calls += 1
        return self.factory()


def test_background_jobs_use_write_session(db, monkeypatch):
    import app.main as main_mod
    import app.site_devices as site_devices
    spy = _Spy(sessionmaker(bind=db.get_bind()))
    monkeypatch.setattr(db_mod, "WriteSessionLocal", spy)
    monkeypatch.setattr(db_mod, "SessionLocal",
                        lambda: pytest.fail("background job used the plain SessionLocal"))
    ran = []
    monkeypatch.setattr(alert_engine, "run_periodic_reviews",
                        lambda s, site_id=None: ran.append(site_id) or {})
    monkeypatch.setattr(site_devices, "purge_unmapped", lambda s: ran.append("purge") or {})
    main_mod._run_scheduled_reviews()
    main_mod._run_unmapped_retention()
    assert spy.calls == 2 and ran == [_sid(db), "purge"]
