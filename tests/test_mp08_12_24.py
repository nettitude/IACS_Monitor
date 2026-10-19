"""MP-08 (truncation order + marker), MP-12 (boundary vs interface labels),
MP-24 (rules not judged surfaced)."""
import os

import pytest

from app.models import Finding, FirewallDevice, FirewallInterface, FirewallRule
from app.parsers import alert_engine as ae
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.alert_engine import rules_not_judged
from app.parsers.reachability import _Context, compute_path, compute_reachability
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import firewall_level_boundaries
from tests.test_access_paths import _ADDR_SVC, _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host

IT, OPS, HMI = "10.4.0.10", "10.3.0.10", "10.2.0.10"


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


# ------------------------------------------------------------------ MP-12 --
def _dis_site(db, zf, zt, levels, name="Disagree"):
    sid = _site(db, name)
    cfg = _two_leg_cfg("p_lo", "p_hi", "10.2.0.1", "10.4.0.1",
                       _policy(1, "hi-to-lo-any", "p_hi", "p_lo", "ALL", "all", "all"))
    fw = _ingest(db, cfg, "FW-DIS", sid, levels)
    dev = db.query(FirewallDevice).filter_by(site_id=sid, name="FW-DIS").one()
    dev.purdue_zone_from, dev.purdue_zone_to = zf, zt
    _host(db, sid, IT, 4)
    _host(db, sid, OPS, 3)
    _host(db, sid, HMI, 2)
    db.commit()
    return sid, fw


def test_boundary_level_between_labelled_legs_is_not_a_leg(db):
    # device says 4 -> 3, interfaces say 4 / 2: there is no L3 leg
    sid, fw = _dis_site(db, 4, 3, {"p_hi": 4, "p_lo": 2})
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
        r = compute_path(db, IT, OPS, dst_port=502, protocol="tcp")
        bounds = firewall_level_boundaries(db)
    assert set(ctx.boundary_map) == {(2, 4)}
    assert bounds == {(2, 4)}                          # topology page agrees with the engine
    assert reach["matrix"]["3→2"]["overall"] == "no_policy"
    assert r["overall"] != "denied"                   # no phantom L3 leg to deny on
    [c] = reach["label_conflicts"]
    assert c["firewall"] == "FW-DIS" and c["boundary"] == [3, 4]
    assert c["interface_levels"] == [2, 4] and c["ignored_levels"] == [3] and c["assumed_levels"] == []
    assert "L3 lies between labelled legs and is ignored" in c["detail"]
    assert r["label_conflicts"] == reach["label_conflicts"]
    with analysis_site(db, sid):
        ap = enumerate_access_paths(db, sid)
    assert ap["label_conflicts"] == reach["label_conflicts"]


def test_boundary_dmz_between_labelled_legs_does_not_enable_dmz_bypass(db):
    # device says 4 -> 3.5, interfaces say 4 / 3: no DMZ leg exists
    sid, fw = _dis_site(db, 4, 3.5, {"p_hi": 4, "p_lo": 3})
    with analysis_site(db, sid):
        ctx = _Context(db)
        ap = enumerate_access_paths(db, sid)
    assert set(ctx.boundary_map) == {(3, 4)}
    assert not any("dmz_bypass" in p["flags"] for p in ap["paths"])
    [c] = ap["label_conflicts"]
    assert c["ignored_levels"] == [3.5]


def test_boundary_level_beyond_labelled_legs_is_the_unlabelled_far_leg(db):
    # C8: declared 4 -> 1, only the OT legs labelled (2 / 1): the IT side stays
    sid = _site(db, "C8")
    cfg = _ADDR_SVC + """
    config system interface
        edit "p_it"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "p_l2"
            set vdom "root"
            set ip 10.2.0.1 255.255.255.0
        next
        edit "p_l1"
            set vdom "root"
            set ip 10.1.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "any", "any", "any", "ALL") + """
    end
    """
    fw = _ingest(db, cfg, "FW-41", sid, {"p_l2": 2, "p_l1": 1})
    dev = db.query(FirewallDevice).filter_by(site_id=sid, name="FW-41").one()
    dev.purdue_zone_from, dev.purdue_zone_to = 4, 1
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
    assert set(ctx.boundary_map) == {(1, 2), (1, 4), (2, 4)}
    [c] = ctx.label_conflicts
    assert c["assumed_levels"] == [4] and c["ignored_levels"] == []
    assert "L4 assumed to be an unlabelled leg" in c["detail"]


def test_consistent_boundary_and_labels_raise_no_conflict(db):
    sid, fw = _dis_site(db, 4, 2, {"p_hi": 4, "p_lo": 2}, name="Agree")
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
    assert ctx.label_conflicts == [] and reach["label_conflicts"] == []
    assert set(ctx.boundary_map) == {(2, 4)}


# ------------------------------------------------------------------ MP-08 --
def _wide_site(db):
    """FW-TOP 4/3 with 12 downhill permits and FW-OT 3/2 with 12 upward
    permits: enough rows to exceed a budget of 10."""
    sid = _site(db, "Wide plant")
    down = "".join(_policy(100 + i, f"it-l3-{i}", "p_it", "p_l3", "MODBUS", "it_host", f"10.3.0.{i}")
                   for i in range(1, 13))
    up = "".join(_policy(200 + i, f"l2-l3-{i}", "p_l2", "p_l3", "MODBUS", f"10.2.0.{i}", "ot_host")
                 for i in range(1, 13))
    addrs = "".join(f'''
        edit "10.3.0.{i}"
            set subnet 10.3.0.{i} 255.255.255.255
        next
        edit "10.2.0.{i}"
            set subnet 10.2.0.{i} 255.255.255.255
        next''' for i in range(1, 13))
    top = _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1", down).replace(
        "config firewall address", "config firewall address" + addrs, 1)
    ot = _two_leg_cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2", up).replace(
        "config firewall address", "config firewall address" + addrs, 1)
    _ingest(db, top, "FW-TOP", sid, {"p_it": 4, "p_l3": 3})
    _ingest(db, ot, "FW-OT", sid, {"p_l3": 3, "p_l2": 2})
    _host(db, sid, IT, 4)
    db.commit()
    return sid


def test_truncation_keeps_downhill_rows_and_is_recorded(db, monkeypatch):
    sid = _wide_site(db)
    with analysis_site(db, sid):
        full = enumerate_access_paths(db, sid)
    assert not full["truncated"] and len(full["paths"]) >= 24
    monkeypatch.setenv("IACS_MAX_ACCESS_PATH_ROWS", "10")
    with analysis_site(db, sid):
        part = enumerate_access_paths(db, sid)
    assert part["truncated"] and len(part["paths"]) == 10
    # every surviving row is a downhill (IT -> OT) row: those are enumerated first
    assert all(p["direction"] == "down" for p in part["paths"])
    assert {p["src"]["level"] for p in part["paths"]} == {4}
    # the review run records it: info finding, last_review_info truncated marker
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, "access_path_enumeration_truncated")
    assert f.severity == "info" and "truncated at 10 rows" in f.title
    assert f.detail["budget"] == 10 and f.detail["rows_listed"] == 10
    info = ae.last_review_info(site_id=sid)
    assert "access-path enumeration" in info["truncated"]["review_chain_it_ot_bypass"]
    assert "access-path enumeration" in info["truncated"]["review_access_path_truncation"]
    # the budget lifted: the finding auto-resolves on the next complete run
    monkeypatch.delenv("IACS_MAX_ACCESS_PATH_ROWS")
    ae.run_periodic_reviews(db, site_id=sid)
    assert _open(db, "access_path_enumeration_truncated") == []
    assert ae.last_review_info(site_id=sid)["truncated"] == {}


def test_matrix_cells_are_enumerated_downhill_first(db):
    sid = _wide_site(db)
    with analysis_site(db, sid):
        reach = compute_reachability(db)
    keys = list(reach["matrix"])
    first_up = next(i for i, k in enumerate(keys)
                    if reach["matrix"][k]["src_level"] < reach["matrix"][k]["dst_level"])
    assert all(reach["matrix"][k]["src_level"] > reach["matrix"][k]["dst_level"] for k in keys[:first_up])
    assert keys[0] == "5→0"


# ------------------------------------------------------------------ MP-24 --
def test_rules_not_judged_lists_policies_with_an_unresolvable_side(db):
    sid = _site(db, "Not judged")
    cfg = _ADDR_SVC + """
    config system interface
        edit "wan1"
            set vdom "root"
            set ip 203.0.113.2 255.255.255.0
        next
        edit "port1"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "port2"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "wan-in", "wan1", "port2", "ALL", "all", "all") \
        + _policy(2, "it-l3", "port1", "port2", "MODBUS", "it_host", "ot_host") \
        + _policy(3, "ghost", "nosuch", "port2", "ALL", "all", "all") + """
    end
    """
    fw = _ingest(db, cfg, "FW-NJ", sid, {"port1": 4, "port2": 3})      # wan1 unlabelled
    db.commit()
    out = rules_not_judged(db, site_id=sid)
    assert out["total_rules"] == 3 and out["not_judged"] == 2
    [e] = out["firewalls"]
    assert e["firewall"] == "FW-NJ" and e["rules_total"] == 3 and e["not_judged"] == 2
    by_pid = {p["policy_id"]: p for p in e["policies"]}
    assert "interface without a Purdue level" in by_pid["1"]["reasons"][0]
    assert "no interface or zone of that name" in by_pid["3"]["reasons"][0]
    assert e["reasons"] == {"src_zone: unlabelled interface": 1, "src_zone: unknown name": 1}
    # labelling wan1 judges policy 1
    i = db.query(FirewallInterface).filter_by(firewall_id=fw.id, name="wan1").one()
    i.purdue_level = 5
    db.commit()
    out = rules_not_judged(db, site_id=sid)
    assert out["not_judged"] == 1 and out["firewalls"][0]["policies"][0]["policy_id"] == "3"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import app.main as main_mod
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.db import Base as DBase, get_db, get_write_db, make_engine

    engine = make_engine(f"sqlite:///{tmp_path / 'nj.db'}")
    DBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    ov = main_mod.app.dependency_overrides
    ov[get_db] = ov[get_write_db] = _get_db
    try:
        c = TestClient(main_mod.app)
        c.Session = Session
        yield c
    finally:
        ov.pop(get_db, None)
        ov.pop(get_write_db, None)


def test_rules_not_judged_api_and_report(api):
    from generate_report import collect_report_data
    r = api.post("/sites", json={"name": "NJ", "code": "nj"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    cfg = _ADDR_SVC + """
    config system interface
        edit "wan1"
            set vdom "root"
            set ip 203.0.113.2 255.255.255.0
        next
        edit "port2"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "wan-in", "wan1", "port2", "ALL", "all", "all") + """
    end
    """
    r = api.post("/ingest/fortigate-config", params={"site": "nj", "firewall_name": "FW-NJ"},
                 files={"file": ("fw.conf", cfg.encode())})
    assert r.status_code == 200, r.text
    r = api.get("/reviews/rules-not-judged", params={"site_id": sid})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["not_judged"] == 1 and body["firewalls"][0]["firewall"] == "FW-NJ"
    # the report carries it under coverage
    with api.Session() as db:
        data = collect_report_data(db, site_id=sid)
    assert data["rules_not_judged"]["not_judged"] == 1
