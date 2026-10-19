"""MP-01: several firewalls on one Purdue boundary are ALTERNATIVES (any one
permitting is enough) unless they are declared in series - a paired group, a
confirmed upstream chain, or a confirmed inside<->outside link - in which
case every box in the series must permit."""
from datetime import datetime, timezone

from app.models import FirewallInterface, NetworkSession
from app.parsers import alert_engine as ae
from app.parsers import firewall_groups as fg
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.reachability import compute_reachability
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import set_upstream_firewall
from tests.test_access_paths import _ADDR_SVC, _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host
from tests.test_firewall_groups import _open

IT = "10.4.0.10"
SRV_A = "10.3.0.10"      # behind FW-A (10.3.0.0/24)
SRV_B = "10.6.0.10"      # behind FW-B (10.6.0.0/24)

_EXTRA_ADDR = """
        edit "srv_a"
            set subnet 10.3.0.10 255.255.255.255
        next
        edit "srv_b"
            set subnet 10.6.0.10 255.255.255.255
        next
"""


def _cfg(lo_if, hi_if, lo_ip, hi_ip, policies):
    return _two_leg_cfg(lo_if, hi_if, lo_ip, hi_ip, policies).replace(
        "config firewall address", "config firewall address" + _EXTRA_ADDR, 1)


def _parallel_site(db, a_dst="srv_a", b_dst="srv_b", b_first=False):
    """FW-A (L4 10.4.0.1 / L3 10.3.0.1) and FW-B (L4 10.4.0.2 / L3 10.6.0.1)
    each permit it_host -> its own server on APPX; nothing declares them in
    series."""
    sid = _site(db, "Parallel plant" + ("-b" if b_first else ""))
    cfg_a = _cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                 _policy(100, "A-it-l3", "p_it", "p_l3", "APPX", "it_host", a_dst))
    cfg_b = _cfg("p_l3b", "p_it", "10.6.0.1", "10.4.0.2",
                 _policy(100, "B-it-l3", "p_it", "p_l3b", "APPX", "it_host", b_dst))
    if b_first:
        fb = _ingest(db, cfg_b, "FW-B", sid, {"p_it": 4, "p_l3b": 3})
        fa = _ingest(db, cfg_a, "FW-A", sid, {"p_it": 4, "p_l3": 3})
    else:
        fa = _ingest(db, cfg_a, "FW-A", sid, {"p_it": 4, "p_l3": 3})
        fb = _ingest(db, cfg_b, "FW-B", sid, {"p_it": 4, "p_l3b": 3})
    _host(db, sid, IT, 4)
    _host(db, sid, SRV_A, 3)
    _host(db, sid, SRV_B, 3)
    db.commit()
    return sid, fa, fb


def _ep(db, sid, **kw):
    with analysis_site(db, sid):
        out = compute_reachability(db, **kw)
    [ep] = [e for e in out["enforcement_points"] if (e["zone_lo"], e["zone_hi"]) == (3, 4)]
    return out, ep


def _cell(out, s, d):
    return out["matrix"][f"{s}→{d}"]


def _l4_l3_rows(db, sid):
    with analysis_site(db, sid):
        out = enumerate_access_paths(db, sid)
    return [p for p in out["paths"] if p["direction"] == "down"
            and p["src"]["level"] == 4 and p["dst"]["level"] == 3], out


# --------------------------------------------------------- alternatives --
def test_undeclared_same_boundary_firewalls_are_alternatives(db):
    sid, fa, fb = _parallel_site(db)
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "parallel"
    assert sorted(a["devices"] for a in ep["alternatives"]) == [["FW-A"], ["FW-B"]]
    assert all(a["basis"] == [] for a in ep["alternatives"])
    # generic 4->3: each box permits something, so the pair is partial, not denied
    assert _cell(out, 4, 3)["overall"] == "partial"
    # host queries: each server is reachable through its own firewall alone
    for dst, fw in ((SRV_A, "FW-A"), (SRV_B, "FW-B")):
        o, _ = _ep(db, sid, src_ip=IT, dst_ip=dst, dst_port=9999, protocol="tcp")
        c = _cell(o, 4, 3)
        assert c["overall"] == "permitted", (dst, c["overall"])
        [hop] = c["paths"][0]["hops"]
        assert hop["arrangement"] == "parallel"
        # the box that provably holds neither address is dropped
        assert hop["placement"] and hop["placement"]["basis"] == "interface networks"
        assert hop["placement"]["dropped"] == [("FW-B" if fw == "FW-A" else "FW-A")]
        on_path = [e["firewall_device"]["name"] for e in hop["enforcement_points"] if not e.get("not_on_path")]
        assert on_path == [fw]
        assert all(e.get("not_on_path") == "interface networks" for e in hop["enforcement_points"]
                   if e["firewall_device"]["name"] != fw)


def test_parallel_firewalls_yield_one_access_path_row_each(db):
    sid, fa, fb = _parallel_site(db)
    rows, _ = _l4_l3_rows(db, sid)
    assert sorted((tuple(c["firewall_name"] for c in r["chain"]), r["dst"]["scope"]) for r in rows) == \
        [(("FW-A",), "10.3.0.10/32"), (("FW-B",), "10.6.0.10/32")]
    ae.run_periodic_reviews(db, site_id=sid)
    # a permit each box has is not "dead-ended" by the other box
    assert not _open(db, sid, "dead_end_permit")


# ---------------------------------------------------------------- series --
def test_paired_group_restores_series_semantics(db):
    sid, fa, fb = _parallel_site(db)
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fa.id, fb.id], name="IT/OT pair")
    db.commit()
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "series"
    [alt] = ep["alternatives"]
    assert alt["devices"] == ["FW-A", "FW-B"] and any("paired group" in b for b in alt["basis"])
    # FW-A permits it_host->srv_a but FW-B does not: in series it is denied
    o, _ = _ep(db, sid, src_ip=IT, dst_ip=SRV_A, dst_port=9999, protocol="tcp")
    c = _cell(o, 4, 3)
    assert c["overall"] == "denied"
    [hop] = c["paths"][0]["hops"]
    assert hop["arrangement"] == "series" and hop["placement"] is None
    rows, _ = _l4_l3_rows(db, sid)
    assert rows == []


def test_confirmed_upstream_chain_restores_series_semantics(db):
    sid, fa, fb = _parallel_site(db, b_dst="srv_a")
    # both permit it_host -> srv_a; as alternatives that is two rows
    rows, _ = _l4_l3_rows(db, sid)
    assert len(rows) == 2
    set_upstream_firewall(db, fa.id, fb.id, topology_confirmed=True)
    db.commit()
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "series"
    assert any("upstream" in b for b in ep["alternatives"][0]["basis"])
    o, _ = _ep(db, sid, src_ip=IT, dst_ip=SRV_A, dst_port=9999, protocol="tcp")
    assert _cell(o, 4, 3)["overall"] == "permitted"
    rows, _ = _l4_l3_rows(db, sid)
    [r] = rows
    assert {c["firewall_name"] for c in r["chain"]} == {"FW-A", "FW-B"}


def test_confirmed_inside_outside_link_restores_series_semantics(db):
    sid, fa, fb = _parallel_site(db)
    a = db.query(FirewallInterface).filter_by(firewall_id=fa.id, name="p_it").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=fb.id, name="p_l3b").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    a.side, b.side = "outside", "inside"
    db.commit()
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "series"
    assert any("link" in b for b in ep["alternatives"][0]["basis"])
    # a link that is not inside<->outside (two outsides) is NOT a series relation
    b.side = "outside"
    db.commit()
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "parallel"


def test_series_set_and_a_third_box_are_mixed(db):
    sid, fa, fb = _parallel_site(db)
    cfg_c = _cfg("p_l3c", "p_it", "10.7.0.1", "10.4.0.3",
                 _policy(100, "C-it-l3", "p_it", "p_l3c", "APPX", "it_host", "all"))
    _ingest(db, cfg_c, "FW-C", sid, {"p_it": 4, "p_l3c": 3})
    _host(db, sid, "10.7.0.10", 3)
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fa.id, fb.id])
    db.commit()
    out, ep = _ep(db, sid)
    assert ep["arrangement"] == "mixed"
    assert sorted(a["devices"] for a in ep["alternatives"]) == [["FW-A", "FW-B"], ["FW-C"]]
    # srv_a sits behind the pair: the pair decides (FW-B lacks the permit -> denied),
    # FW-C - which holds neither address - is dropped by placement
    o, _ = _ep(db, sid, src_ip=IT, dst_ip=SRV_A, dst_port=9999, protocol="tcp")
    c = _cell(o, 4, 3)
    assert c["overall"] == "denied"
    assert c["paths"][0]["hops"][0]["placement"]["dropped"] == ["FW-C"]
    # a server behind FW-C is reached through FW-C alone
    o, _ = _ep(db, sid, src_ip=IT, dst_ip="10.7.0.10", dst_port=9999, protocol="tcp")
    c = _cell(o, 4, 3)
    assert c["overall"] == "permitted"
    assert c["paths"][0]["hops"][0]["placement"]["dropped"] == ["FW-A + FW-B"]


# ---------------------------------------------------------------- overlay --
def test_observed_flow_is_credited_to_the_firewall_that_holds_the_server(db):
    # both permit it_host -> srv_a; FW-B is ingested first so its row comes
    # first - the flow must still land on FW-A, whose L3 network holds srv_a
    sid, fa, fb = _parallel_site(db, b_dst="srv_a", b_first=True)
    it = _host(db, sid, IT, 4)
    srv = _host(db, sid, SRV_A, 3)
    now = datetime.now(timezone.utc)
    db.add(NetworkSession(src_host_id=it.id, dst_host_id=srv.id, src_port=40000, dst_port=9999,
                          transport="tcp", protocol="unknown", first_seen=now, last_seen=now,
                          packet_count=10))
    db.commit()
    rows, out = _l4_l3_rows(db, sid)
    seen = {r["chain"][0]["firewall_name"]: r["traffic"]["status"] for r in rows}
    assert seen == {"FW-A": "seen", "FW-B": "not_seen"}
    assert out["unmatched_observed"] == []


# ------------------------------------------------------------------ MP-02 --
def _three_leg_site(db):
    """A 3-leg FW-C (L4 / L3.5 / L3) beside a 2-box chain FW-A (L4 / L3.5)
    -> FW-B (L3.5 / L3).  FW-C permits only L4 -> L3.5; FW-A and FW-B
    permit anything.  Physically 4 -> 3 is reachable through A then B (or
    through C's L4 leg and then B)."""
    sid = _site(db, "Three-leg plant")
    fa = _ingest(db, _two_leg_cfg("p_dmz", "p_it", "10.35.0.2", "10.4.0.2",
                                  _policy(1, "a-any", "any", "any", "ALL")),
                 "FW-A", sid, {"p_it": 4, "p_dmz": 3.5})
    fb = _ingest(db, _two_leg_cfg("p_l3", "p_dmz", "10.3.0.2", "10.35.0.3",
                                  _policy(1, "b-any", "any", "any", "ALL")),
                 "FW-B", sid, {"p_dmz": 3.5, "p_l3": 3})
    cfg_c = _ADDR_SVC + """
    config system interface
        edit "p_it"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "p_dmz"
            set vdom "root"
            set ip 10.35.0.1 255.255.255.0
        next
        edit "p_l3"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "c-it-dmz", "p_it", "p_dmz", "ALL") + """
    end
    """
    fc = _ingest(db, cfg_c, "FW-C", sid, {"p_it": 4, "p_dmz": 3.5, "p_l3": 3})
    db.commit()
    return sid, fa, fb, fc


def test_reused_box_is_left_out_of_the_later_hop_not_the_whole_path(db):
    sid, fa, fb, fc = _three_leg_site(db)
    with analysis_site(db, sid):
        out = compute_reachability(db)
    c43 = _cell(out, 4, 3)
    assert c43["overall"] == "permitted"
    # the direct FW-C hop denies; the A -> B route is present and permits,
    # with FW-C left out of its second hop (already crossed on the first)
    by_hops = {tuple(h["boundary"] for h in p["hops"]): p for p in c43["paths"]}
    direct = by_hops[("3↔4",)]
    assert [e["firewall_device"]["name"] for e in direct["hops"][0]["enforcement_points"]] == ["FW-C"]
    assert direct["hops"][0]["boundary_decision"] == "denied"
    two = by_hops[("3.5↔4", "3↔3.5")]
    first, second = two["hops"]
    assert {e["firewall_device"]["name"] for e in first["enforcement_points"]} == {"FW-A", "FW-C"}
    assert [e["firewall_device"]["name"] for e in second["enforcement_points"]] == ["FW-B"]
    assert second["already_crossed"] == ["FW-C"] and first["already_crossed"] == []
    assert second["boundary_decision"] == "permitted"
    # L3.5 -> L3 is decided by FW-B and FW-C as alternatives: permitted
    assert _cell(out, 3.5, 3)["overall"] == "permitted"


def test_three_leg_access_path_rows_follow_real_routes(db):
    sid, fa, fb, fc = _three_leg_site(db)
    rows, _ = _l4_l3_rows(db, sid)
    chains = sorted(tuple(c["firewall_name"] for c in r["chain"]) for r in rows)
    assert chains == [("FW-A", "FW-B"), ("FW-C", "FW-B")]
    # no chain ever crosses one box twice
    with analysis_site(db, sid):
        allrows = enumerate_access_paths(db, sid)["paths"]
    for r in allrows:
        names = [c["firewall_name"] for c in r["chain"]]
        assert len(names) == len(set(names)), names


def test_a_hop_with_no_box_left_is_a_dead_end(db):
    # one 3-leg box alone: 4 -> 3.5 -> 3 would cross it twice, so only the
    # direct 4 -> 3 hop remains
    sid = _site(db, "Lone three-leg")
    cfg_c = _ADDR_SVC + """
    config system interface
        edit "p_it"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "p_dmz"
            set vdom "root"
            set ip 10.35.0.1 255.255.255.0
        next
        edit "p_l3"
            set vdom "root"
            set ip 10.3.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "c-any", "any", "any", "ALL") + """
    end
    """
    _ingest(db, cfg_c, "FW-C", sid, {"p_it": 4, "p_dmz": 3.5, "p_l3": 3})
    db.commit()
    with analysis_site(db, sid):
        out = compute_reachability(db)
    c = _cell(out, 4, 3)
    assert c["overall"] == "permitted"
    assert [tuple(h["boundary"] for h in p["hops"]) for p in c["paths"]] == [("3↔4",)]
