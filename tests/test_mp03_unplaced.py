"""MP-03: a firewall with rules but no enforcement point is surfaced
(``unplaced_firewalls``), no "nearest" flat edge is invented into empty
levels, a verdict that rests on an inferred unfirewalled hop is never
better than "unknown", and the inferred hop is printed in the path."""
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.reachability import _Context, compute_path, compute_reachability
from app.parsers.site_scope import analysis_site
from tests.test_access_paths import _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host

IT, SCADA, HMI = "10.4.0.10", "10.3.0.10", "10.2.0.10"


def _site_with_unlabelled_mid(db, label_mid=False):
    """FW-TOP (L4/L3, permits it_host -> any) above FW-MID (L3/L2, permits
    only tcp/443).  FW-MID is ingested without interface levels unless
    ``label_mid``."""
    sid = _site(db, "Unlabelled mid")
    _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                             _policy(1, "it-any", "p_it", "p_l3", "ALL", "it_host", "all")),
            "FW-TOP", sid, {"p_it": 4, "p_l3": 3})
    _ingest(db, _two_leg_cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2",
                             _policy(1, "l3-l2-https", "p_l3", "p_l2", "SSHX", "all", "all")),
            "FW-MID", sid, {"p_l3": 3, "p_l2": 2} if label_mid else {})
    _host(db, sid, IT, 4)
    _host(db, sid, SCADA, 3)
    _host(db, sid, HMI, 2)
    db.commit()
    return sid


def test_unplaced_firewall_is_listed_everywhere(db):
    sid = _site_with_unlabelled_mid(db)
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
        path = compute_path(db, IT, HMI, dst_port=502, protocol="tcp")
        ap = enumerate_access_paths(db, sid)
    [u] = ctx.unplaced_firewalls
    assert u["firewall"] == "FW-MID" and u["rule_count"] == 1
    assert u["reason"].startswith("no interface Purdue levels")
    assert u["unlabelled_interfaces"] == ["p_l2", "p_l3"]
    assert [x["firewall"] for x in reach["unplaced_firewalls"]] == ["FW-MID"]
    assert [x["firewall"] for x in path["unplaced_firewalls"]] == ["FW-MID"]
    assert [x["firewall"] for x in ap["unplaced_firewalls"]] == ["FW-MID"]
    # a level pair with no path mentions it in its reason
    assert "FW-MID carries rules but is not placed" in reach["matrix"]["3→2"]["reason"]


def test_verdict_over_an_inferred_hop_is_unknown_not_permitted(db):
    sid = _site_with_unlabelled_mid(db)
    with analysis_site(db, sid):
        reach = compute_reachability(db)
        r = compute_path(db, IT, HMI, dst_port=502, protocol="tcp")
    # the flow FW-MID would deny is no longer "permitted"
    assert r["overall"] == "unknown"
    assert r["inferred_adjacency"] == [{"a": 2, "b": 3, "basis": "nearest", "ambiguous": False}]
    assert "inferred unfirewalled hop L2~L3 while FW-MID carries rules" in r["inferred_hop_note"]
    assert r["path"] == "Level 4 (10.4.0.10) → [3↔4] → ~ Level 2 (10.2.0.10) (inferred, no firewall)"
    c = reach["matrix"]["4→2"]
    assert c["overall"] == "unknown"
    [p] = c["paths"]
    assert p["path"] == "4 → [3↔4] → ~ 2 (inferred, no firewall)" and p["inferred_hop_note"]
    # the real firewall hop keeps its own verdict
    assert c["paths"][0]["hops"][0]["boundary_decision"] == "partial"   # it_host -> any only


def test_labelling_the_firewall_restores_the_real_verdict(db):
    sid = _site_with_unlabelled_mid(db, label_mid=True)
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
        r = compute_path(db, IT, HMI, dst_port=502, protocol="tcp")
    assert ctx.unplaced_firewalls == [] and reach["unplaced_firewalls"] == []
    assert r["overall"] == "denied" and r["inferred_adjacency"] == []
    assert r["path"] == "Level 4 (10.4.0.10) → [3↔4] → [2↔3] → Level 2 (10.2.0.10)"
    assert ctx.flat_edges == []


def test_no_flat_edge_into_a_level_without_evidence(db):
    sid = _site(db, "Lone firewall")
    _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                             _policy(1, "it-any", "p_it", "p_l3", "ALL", "it_host", "all")),
            "FW-TOP", sid, {"p_it": 4, "p_l3": 3})
    _host(db, sid, IT, 4)
    _host(db, sid, SCADA, 3)
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
    # levels 0, 1, 2, 3.5 and 5 have no hosts, no boundary, no label: no edge
    assert ctx.flat_edges == []
    assert reach["matrix"]["4→0"]["overall"] == "no_policy"
    assert reach["matrix"]["4→3.5"]["overall"] == "no_policy"
    assert reach["unplaced_firewalls"] == []
    # a host at L2 is evidence: one "nearest" edge L2~L3 appears; with no
    # firewall missing from the model the firewall hop decides (A-25) and
    # the inferred hop is printed, not hidden
    _host(db, sid, HMI, 2)
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        reach = compute_reachability(db)
    assert [(f["a"], f["b"], f["basis"]) for f in ctx.flat_edges] == [(2, 3, "nearest")]
    c = reach["matrix"]["4→2"]
    assert c["overall"] == "partial"
    assert c["paths"][0]["path"] == "4 → [3↔4] → ~ 2 (inferred, no firewall)"
    assert c["paths"][0]["inferred_hop_note"] is None


def test_subnet_evidence_flat_hop_stays_decisive_without_unplaced_firewalls(db):
    # an L2 host inside FW-TOP's L3 interface subnet shares that segment:
    # the L2~L3 hop has evidence and no firewall is missing, so the verdict
    # through FW-TOP stands (A-25)
    sid = _site(db, "Shared segment")
    _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                             _policy(1, "it-any", "p_it", "p_l3", "ALL", "it_host", "all")),
            "FW-TOP", sid, {"p_it": 4, "p_l3": 3})
    _host(db, sid, IT, 4)
    _host(db, sid, "10.3.0.77", 2)
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        r = compute_path(db, IT, "10.3.0.77", dst_port=502, protocol="tcp")
    assert [(f["a"], f["b"], f["basis"]) for f in ctx.flat_edges] == [(2, 3, "subnet")]
    assert r["overall"] == "permitted" and r["inferred_hop_note"] is None
    assert "(inferred, no firewall)" in r["path"]


def test_subnet_evidence_flat_hop_is_unknown_when_a_firewall_is_unplaced(db):
    sid = _site_with_unlabelled_mid(db)
    _host(db, sid, "10.3.0.77", 2)      # L2 host on FW-TOP's L3 subnet
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        r = compute_path(db, IT, "10.3.0.77", dst_port=502, protocol="tcp")
    assert [(f["a"], f["b"], f["basis"]) for f in ctx.flat_edges] == [(2, 3, "subnet")]
    assert r["overall"] == "unknown"
    assert "FW-MID carries rules but is not placed" in r["inferred_hop_note"]
