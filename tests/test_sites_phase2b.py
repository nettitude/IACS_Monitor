"""
Multi-site phase 2 part B (docs/multi-site-design.md): per-site analysis.

Two sites are built with IDENTICAL data (same host IPs/MACs, same firewall
and device names, same baseline name, same deny-all rule, same observed
session).  Plant B differs in a few places:

* an extra IT->OT permit (10.3.0.0/24 -> 10.1.0.0/24 tcp/502) plus a
  narrower permit it shadows;
* host 10.3.0.77 sits at Purdue level 1 in B (level 3 in A);
* B's active baseline does not approve the observed Modbus flow;
* B has a second firewall (multi-FW) - A has one.

Every analysis must only see its own site.
"""
import threading
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.parsers.alert_engine as ae
from app.db import Base, configure_sqlite_engine
from app.models import (
    ApprovedCommsEntry, Baseline, Finding, Firewall, FirewallDevice, FirewallInterface,
    FirewallRule, FortiAnalyzerEvent, Host, NetworkSession, Site,
)
from app.parsers.device_classification import classify_hosts
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.rule_shadow import find_shadowed_rules
from app.parsers.site_scope import CrossSiteError, analysis_site, current_site
from app.parsers.topology_diff import compute_diff
from app.parsers.topology_manager import (
    confirm_link, get_topology_state, set_upstream_firewall, upstream_chain,
)
from app.parsers.traffic_findings import check_unauthorized_industrial_writes


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def Session():
    eng = configure_sqlite_engine(create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool))
    Base.metadata.create_all(eng)
    yield sessionmaker(bind=eng)
    eng.dispose()


def _build_site(db, name, plant_b: bool) -> int:
    site = Site(name=name, code=name.lower().replace(" ", "-"))
    db.add(site)
    db.flush()
    sid = site.id

    def host(ip, mac, level):
        h = Host(ip=ip, mac=mac, purdue_level=level, sources=["test"], site_id=sid)
        db.add(h)
        return h

    it = host("10.3.0.10", "00:11:22:33:44:10", 3)
    plc = host("10.1.0.20", "00:11:22:33:44:20", 1)
    host("10.3.0.77", "00:11:22:33:44:77", 1 if plant_b else 3)
    db.flush()
    db.add(NetworkSession(src_host_id=it.id, dst_host_id=plc.id, dst_port=502,
                          transport="tcp", protocol="modbus", packet_count=10,
                          first_seen=_now(), last_seen=_now()))

    fw = Firewall(name="edge-fw", vendor="fortigate", site_id=sid)
    db.add(fw)
    db.flush()
    db.add(FirewallInterface(firewall_id=fw.id, name="port1", network_cidr="10.3.0.0/24",
                             ip_cidr="10.3.0.1/24"))
    if plant_b:
        fw2 = Firewall(name="core-fw", vendor="fortigate", site_id=sid)
        db.add(fw2)
        db.flush()
        db.add(FirewallInterface(firewall_id=fw2.id, name="port9", network_cidr="10.3.0.0/24",
                                 ip_cidr="10.3.0.2/24"))

    dev = FirewallDevice(name="fw1", vendor="fortigate", purdue_zone_from=3,
                         purdue_zone_to=1, site_id=sid)
    db.add(dev)
    db.flush()

    def rule(order, action, src="any", dst="any", proto="any", port=None, pid=None):
        db.add(FirewallRule(firewall_device_id=dev.id, device_name="fw1",
                            device_type="fortigate", policy_id=pid or str(order),
                            rule_order=order, src=src, dst=dst, protocol=proto,
                            dst_port=port, action=action, site_id=sid))

    if plant_b:
        rule(1, "permit", "10.3.0.0/24", "10.1.0.0/24", "tcp", "502")
        rule(2, "permit", "10.3.0.10/32", "10.1.0.20/32", "tcp", "502")
    rule(10, "deny")

    bl = Baseline(name="2026-audit", is_active=True, created_at=_now(), site_id=sid)
    db.add(bl)
    db.flush()
    if plant_b:
        db.add(ApprovedCommsEntry(baseline_id=bl.id, src="10.9.9.9", dst="10.9.9.8",
                                  dst_port=80, protocol="tcp"))
    else:
        db.add(ApprovedCommsEntry(baseline_id=bl.id, src="10.3.0.10", dst="10.1.0.20",
                                  dst_port=502, protocol="tcp"))
    db.commit()
    return sid


@pytest.fixture
def sites(Session):
    db = Session()
    a = _build_site(db, "Plant A", plant_b=False)
    b = _build_site(db, "Plant B", plant_b=True)
    yield db, a, b
    db.close()


def _checks(db, sid, status="open"):
    q = db.query(Finding).filter(Finding.site_id == sid)
    if status:
        q = q.filter(Finding.status == status)
    return {f.check_name for f in q}


# ----------------------------------------------------------------- scope --

def test_scope_filters_roots_and_children(sites):
    db, a, b = sites
    assert db.query(Host).count() == 6
    with analysis_site(db, a):
        assert current_site(db) == a
        assert db.query(Host).count() == 3
        assert db.query(NetworkSession).count() == 1
        assert db.query(FirewallInterface).count() == 1
        assert db.query(FirewallRule).count() == 1
        assert db.query(ApprovedCommsEntry).one().dst == "10.1.0.20"
    assert current_site(db) is None


# --------------------------------------------------------------- reviews --

def test_reviews_create_findings_only_in_reviewed_site(sites):
    db, a, b = sites
    ae.run_periodic_reviews(db, site_id=a)
    assert db.query(Finding).filter(Finding.site_id == b).count() == 0
    a_checks = _checks(db, a)
    assert "shadow_rule" not in a_checks
    assert "conduit_matrix_drift" not in a_checks   # A's baseline approves the flow

    ae.run_periodic_reviews(db, site_id=b)
    b_checks = _checks(db, b)
    assert "shadow_rule" in b_checks
    assert "conduit_matrix_drift" in b_checks       # B's baseline does not
    # A's findings untouched by B's run
    assert _checks(db, a) == a_checks
    # every finding of each run carries its site
    for f in db.query(Finding):
        assert f.site_id in (a, b)


def test_same_condition_in_both_sites_gets_one_finding_per_site(sites):
    db, a, b = sites
    ae.run_periodic_reviews(db, site_id=a)
    ae.run_periodic_reviews(db, site_id=b)
    refs_a = {f.source_ref for f in db.query(Finding).filter(Finding.site_id == a)}
    refs_b = {f.source_ref for f in db.query(Finding).filter(Finding.site_id == b)}
    common = refs_a & refs_b
    # identical data (deny-all rule, identical hosts) produces identical
    # source_refs - each site has its own open finding for them
    assert common
    # re-running B does not re-detect / bump A's copy
    before = {f.id: f.occurrence_count for f in db.query(Finding).filter(Finding.site_id == a)}
    ae.run_periodic_reviews(db, site_id=b)
    after = {f.id: f.occurrence_count for f in db.query(Finding).filter(Finding.site_id == a)}
    assert before == after


def test_auto_resolve_only_touches_reviewed_site(sites):
    db, a, b = sites
    stale = []
    for sid in (a, b):
        f = Finding(category="periodic_review", check_name="shadow_rule", severity="low",
                    status="open", title="stale", detail={}, source_ref="stale-ref",
                    site_id=sid)
        db.add(f)
        stale.append(f)
    db.commit()
    ae.run_periodic_reviews(db, site_id=b)
    db.refresh(stale[0]), db.refresh(stale[1])
    assert stale[0].status == "open"          # site A untouched
    assert stale[1].status == "closed"        # site B auto-resolved
    assert ae.auto_resolved_counts(db, site_id=b).get("review_shadow_rules") == 1
    ae.run_periodic_reviews(db, site_id=a)
    db.refresh(stale[0])
    assert stale[0].status == "closed"
    # B's real shadow finding survived A's run
    assert "shadow_rule" in _checks(db, b)


def test_review_lock_is_per_site(sites):
    db, a, b = sites
    lock = ae._acquire_review_lock(a)
    assert lock is not None
    try:
        assert ae.run_periodic_reviews(db, site_id=a) == {ae.REVIEW_SKIPPED_STAT: 0}
        assert ae._review_run_skipped(db)
        # an unscoped run conflicts with any site run
        assert ae.run_periodic_reviews(db) == {ae.REVIEW_SKIPPED_STAT: 0}
        stats = ae.run_periodic_reviews(db, site_id=b)
        assert ae.REVIEW_SKIPPED_STAT not in stats and not ae._review_run_skipped(db)
    finally:
        lock.release()
    assert ae.REVIEW_SKIPPED_STAT not in ae.run_periodic_reviews(db, site_id=a)


def test_two_sites_review_concurrently(Session):
    db = Session()
    a = _build_site(db, "Plant A", plant_b=False)
    b = _build_site(db, "Plant B", plant_b=True)
    db.close()
    started, release = threading.Event(), threading.Event()
    real = ae.review_denied_trends
    results = {}

    def slow(db_, **kw):
        if current_site(db_) == a:
            started.set()
            release.wait(10)
        return real(db_, **kw)

    def run(sid):
        s = Session()
        try:
            results[sid] = ae.run_periodic_reviews(s, site_id=sid)
        finally:
            s.close()

    orig = ae.review_denied_trends
    ae.review_denied_trends = slow
    try:
        t = threading.Thread(target=run, args=(a,))
        t.start()
        assert started.wait(10)
        run(b)                               # B runs while A is mid-run
        s = Session()
        assert ae.run_periodic_reviews(s, site_id=a) == {ae.REVIEW_SKIPPED_STAT: 0}
        s.close()
        release.set()
        t.join(30)
    finally:
        ae.review_denied_trends = orig
        release.set()
    assert ae.REVIEW_SKIPPED_STAT not in results[a]
    assert ae.REVIEW_SKIPPED_STAT not in results[b]


def test_failed_bookkeeping_per_site(sites, monkeypatch):
    db, a, b = sites

    def review_ip_conflicts(db_, **kw):
        if current_site(db_) == a:
            raise RuntimeError("x")
        return []
    monkeypatch.setattr(ae, "review_ip_conflicts", review_ip_conflicts)
    ae.run_periodic_reviews(db, site_id=a)
    ae.run_periodic_reviews(db, site_id=b)
    assert ae.failed_reviews(db, site_id=a) == ["review_ip_conflicts"]
    assert ae.failed_reviews(db, site_id=b) == []
    assert ae.last_review_info(site_id=a)["failed_reviews"] == ["review_ip_conflicts"]
    assert ae.last_review_info()["site_id"] == b


def test_single_review_function_takes_site_id(sites):
    db, a, b = sites
    assert ae.review_shadow_rules(db, site_id=a) == []
    found = ae.review_shadow_rules(db, site_id=b)
    assert found and all(f.site_id == b for f in found)
    assert ae.review_conduit_matrix_drift(db, site_id=a) == []
    assert ae.review_conduit_matrix_drift(db, site_id=b)


# -------------------------------------------------------------- real-time --

def _event(db, sid, src, dst, port=502):
    ev = FortiAnalyzerEvent(source_type="syslog", log_type="traffic", action="accept", src_ip=src, dst_ip=dst,
                            dst_port=port, device_name="edge-fw", received_at=_now(),
                            raw_fields={}, site_id=sid)
    db.add(ev)
    db.flush()
    return ev


def test_realtime_event_uses_only_its_sites_hosts(sites):
    db, a, b = sites
    # 10.3.0.10 (L3) -> 10.3.0.77: L3 in A (same level), L1 in B (IT->OT)
    ev_a = _event(db, a, "10.3.0.10", "10.3.0.77")
    assert not [f for f in ae.evaluate_event(ev_a, db) if f.check_name == "it_ot_bypass"]
    ev_b = _event(db, b, "10.3.0.10", "10.3.0.77")
    found = [f for f in ae.evaluate_event(ev_b, db) if f.check_name == "it_ot_bypass"]
    assert found and found[0].site_id == b
    # the check functions are scoped by the event's site too
    assert ae.check_it_ot_bypass(ev_a, db) is None
    db.flush()
    assert not db.query(Finding).filter(Finding.site_id == a,
                                        Finding.check_name == "it_ot_bypass").count()
    # findings created by the site-A event (if any) are site A's
    assert all(f.site_id == a for f in db.query(Finding).filter(Finding.forti_event_id == ev_a.id))


def test_realtime_finding_dedup_per_site(sites):
    db, a, b = sites
    ev_b = _event(db, b, "10.3.0.10", "10.3.0.77")
    assert ae.check_it_ot_bypass(ev_b, db) is not None
    # move A's host to L1 too: the same condition in A opens A's own finding
    with analysis_site(db, a):
        db.query(Host).filter(Host.ip == "10.3.0.77").one().purdue_level = 1
    ev_a = _event(db, a, "10.3.0.10", "10.3.0.77")
    f_a = ae.check_it_ot_bypass(ev_a, db)
    assert f_a is not None and f_a.site_id == a


def test_traffic_findings_scoped(sites):
    db, a, b = sites
    out = check_unauthorized_industrial_writes(db, commit=False, site_id=a)
    assert isinstance(out, dict)
    db.flush()
    assert all(f.site_id == a for f in db.query(Finding))


# ----------------------------------------- reachability / shadow / diff --

def test_compute_path_differs_per_site(sites):
    db, a, b = sites
    pa = compute_path(db, "10.3.0.10", "10.1.0.20", dst_port=502, protocol="tcp", site_id=a)
    pb = compute_path(db, "10.3.0.10", "10.1.0.20", dst_port=502, protocol="tcp", site_id=b)
    assert pa["overall"] == "denied"
    assert pb["overall"] == "permitted"


def test_compute_reachability_differs_per_site(sites):
    db, a, b = sites
    ra = compute_reachability(db, site_id=a)
    rb = compute_reachability(db, site_id=b)
    assert ra["matrix"] != rb["matrix"]
    assert len(ra["enforcement_points"]) == 1 and len(rb["enforcement_points"]) == 1


def test_find_shadowed_rules_per_site(sites):
    db, a, b = sites
    assert find_shadowed_rules(db, site_id=a)["shadows"] == []
    res = find_shadowed_rules(db, site_id=b, generate_findings=True)
    assert res["shadows"]
    db.flush()
    assert {f.site_id for f in db.query(Finding).filter(Finding.check_name == "shadow_rule")} == {b}


def test_topology_diff_last_matched_only_site_rules(sites):
    db, a, b = sites
    da = compute_diff(db, site_id=a)
    db.commit()
    assert all(r.last_matched is None for r in db.query(FirewallRule))
    assert da["sessions_total"] == 1
    db_ = compute_diff(db, site_id=b)
    db.commit()
    matched = db.query(FirewallRule).filter(FirewallRule.last_matched.isnot(None)).all()
    assert matched and {r.site_id for r in matched} == {b}
    assert db_["sessions_total"] == 1


# ------------------------------------------------------------- topology --

def test_topology_state_per_site(sites):
    db, a, b = sites
    sa_ = get_topology_state(db, site_id=a)
    sb_ = get_topology_state(db, site_id=b)
    assert sa_["firewall_count"] == 1 and sa_["is_multi_fw"] is False
    assert sb_["firewall_count"] == 2 and sb_["is_multi_fw"] is True
    assert sa_["pending_proposals"] == []
    for p in sb_["pending_proposals"]:
        ids = {fw["id"] for fw in sb_["firewalls"]}
        assert p["fw_a_id"] in ids and p["fw_b_id"] in ids


def test_links_never_cross_sites(sites):
    db, a, b = sites
    fw_a = db.query(Firewall).filter(Firewall.site_id == a).one()
    fw_b = db.query(Firewall).filter(Firewall.site_id == b, Firewall.name == "core-fw").one()
    with pytest.raises(CrossSiteError):
        set_upstream_firewall(db, fw_a.id, fw_b.id)
    # scoped: the other site's firewall does not exist
    with pytest.raises(ValueError, match="not found"):
        set_upstream_firewall(db, fw_a.id, fw_b.id, site_id=a)
    ia = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_a.id).one()
    ib = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_b.id).one()
    with pytest.raises(CrossSiteError):
        confirm_link(db, ia.id, ib.id)
    # unscoped proposals never pair firewalls of different sites
    from app.parsers.topology_manager import detect_subnet_overlaps
    fw_site = {f.id: f.site_id for f in db.query(Firewall)}
    for p in detect_subnet_overlaps(db):
        assert fw_site[p["fw_a_id"]] == fw_site[p["fw_b_id"]]
    # within one site linking works
    edge_b = db.query(Firewall).filter(Firewall.site_id == b, Firewall.name == "edge-fw").one()
    set_upstream_firewall(db, fw_b.id, edge_b.id, site_id=b)
    assert upstream_chain(db, fw_b.id, site_id=b)[0] == [fw_b.id, edge_b.id]


def test_classification_does_not_touch_other_site(sites):
    db, a, b = sites
    before = {(h.id, h.purdue_level, h.device_type) for h in db.query(Host).filter(Host.site_id == b)}
    classify_hosts(db, site_id=a)
    db.commit()
    after = {(h.id, h.purdue_level, h.device_type) for h in db.query(Host).filter(Host.site_id == b)}
    assert before == after
