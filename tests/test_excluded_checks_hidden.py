"""
Findings of checks left out of the compliance report are hidden throughout the
application (owner, 2026-10-14: "When the checks in the reports change, under the
Reports & Diagnostics, change the findings through the applications should reflect
this change" -> hidden everywhere, reviews keep evaluating).

GET /findings, /findings/summary, /findings/export, /findings/export/summary,
/findings/linked, /findings/link-counts and the site counts (/sites, /sites/rollup)
leave them out unless ``include_excluded=true``; listed rows carry
``excluded_from_report``.  Per site: another site's identical check is unaffected.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Finding, Host, Site


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'hx.db'}", connect_args={"check_same_thread": False})
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

    s = Session()
    a, b = Site(name="A", code="a"), Site(name="B", code="b")
    s.add_all([a, b])
    s.flush()
    hosts = {}
    for site in (a, b):
        h = Host(site_id=site.id, ip="10.0.0.9", mac=f"aa:bb:cc:dd:ee:0{site.id}")
        s.add(h)
        s.flush()
        hosts[site.id] = h.id
        for check, sev, title in (("config_weak_tls_version", "high", "Weak TLS on admin GUI"),
                                  ("unknown_device", "medium", "Unknown device 10.0.0.9"),
                                  ("rule_it_ot_bypass", "critical", "IT to OT bypass policy 20")):
            s.add(Finding(site_id=site.id, category="periodic_review", check_name=check, severity=sev,
                          status="open", title=title, detail={"ip": "10.0.0.9"}))
    s.commit()
    ids = (a.id, b.id)
    s.close()
    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        try:
            yield c, ids, hosts
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _exclude(c, sid, *names):
    r = c.put("/reports/check-selection", params={"site_id": sid}, json={"exclude": list(names), "by": "t"})
    assert r.status_code == 200, r.text


def test_list_summary_and_exports_hide_excluded(api):
    c, (a, b), hosts = api
    _exclude(c, a, "config_weak_tls_version", "unknown_device")
    titles = [f["title"] for f in c.get("/findings", params={"site_id": a}).json()]
    assert titles == ["IT to OT bypass policy 20"]
    rows = c.get("/findings", params={"site_id": a, "include_excluded": True}).json()
    assert {f["title"]: f["excluded_from_report"] for f in rows} == {
        "IT to OT bypass policy 20": False, "Weak TLS on admin GUI": True, "Unknown device 10.0.0.9": True}
    assert c.get("/findings", params={"site_id": a}).headers["X-Total-Count"] == "1"
    # site B keeps its three; the all-sites list hides only A's
    assert len(c.get("/findings", params={"site_id": b}).json()) == 3
    assert len(c.get("/findings").json()) == 4
    s = c.get("/findings/summary", params={"site_id": a}).json()
    assert s["total_open"] == 1 and s["by_severity"] == {"critical": 1}
    assert c.get("/findings/summary", params={"site_id": a, "include_excluded": True}).json()["total_open"] == 3
    assert c.get("/findings/summary").json()["total_open"] == 4
    csv = c.get("/findings/export", params={"site_id": a}).content.decode("utf-8-sig")
    assert "Weak TLS" not in csv and "IT to OT bypass" in csv
    assert "Weak TLS" in c.get("/findings/export", params={"site_id": a, "include_excluded": True}).content.decode("utf-8-sig")
    pivot = c.get("/findings/export/summary", params={"site_id": a}).content.decode("utf-8-sig")
    assert pivot.count(",1") >= 1


def test_linked_counts_and_site_counts_hide_excluded(api):
    c, (a, b), hosts = api
    _exclude(c, a, "unknown_device")
    j = c.get("/findings/linked", params={"site_id": a, "host_id": hosts[a]}).json()
    assert sorted(f["check_name"] for f in j["findings"]) == ["config_weak_tls_version", "rule_it_ot_bypass"]
    j = c.get("/findings/linked", params={"site_id": a, "host_id": hosts[a], "include_excluded": True}).json()
    assert len(j["findings"]) == 3 and any(f["excluded_from_report"] for f in j["findings"])
    assert c.get("/findings/link-counts", params={"site_id": a}).json()["hosts"][str(hosts[a])]["count"] == 2
    assert c.get("/findings/link-counts", params={"site_id": b}).json()["hosts"][str(hosts[b])]["count"] == 3
    sites = {s["id"]: s for s in c.get("/sites").json()}
    assert sites[a]["counts"]["open_findings"] == 2 and sites[b]["counts"]["open_findings"] == 3
    roll = {s["id"]: s for s in c.get("/sites/rollup").json()["sites"]}
    assert roll[a]["open_findings"] == 2 and roll[a]["open_by_severity"].get("medium", 0) == 0
    # putting the check back shows the finding again (it was evaluated all along)
    c.put("/reports/check-selection", params={"site_id": a}, json={"include": ["unknown_device"]})
    assert c.get("/findings/summary", params={"site_id": a}).json()["total_open"] == 3
