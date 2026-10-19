"""Group 4 of the multi-firewall audit: rows and findings.

* MP-06  a network-scoped source is placed by the labelled interface network
         that holds it: no impossible "L3 10.4.0.0/24 -> L1" rows, one
         chain finding per real path.
* MP-07  prefix / dead-end rows are marked ``reach``, lose level-judged
         flags and are left out of the report by default.
* MP-10  specific denies in front of a permit-any are subtracted across hops
         (matrix, host path and access-path rows agree).
* MP-19  dead_end_permit names the blocking firewall for network scopes.
"""
from app.models import Finding
from app.parsers import alert_engine as ae
from app.parsers.access_paths import count_rows, enumerate_access_paths, report_lines
from app.parsers.chain_findings import _representative
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import set_upstream_firewall
from tests.test_access_paths import _ADDR_SVC, _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host

IT, PLC = "10.4.0.10", "10.1.0.30"
_EXTRA = """
        edit "it_net"
            set subnet 10.4.0.0 255.255.255.0
        next
        edit "l3_srv"
            set subnet 10.3.0.10 255.255.255.255
        next
"""


def _cfg(lo, hi, lo_ip, hi_ip, pols):
    return _two_leg_cfg(lo, hi, lo_ip, hi_ip, pols).replace(
        "config firewall address", "config firewall address" + _EXTRA, 1)


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


def _four_chain(db, src="it_net"):
    """FW-A 4/3.5 -> FW-B 3.5/3 -> FW-C 3/2 -> FW-D 2/1, every policy
    ``src -> plc`` MODBUS (the audit's MP-06 shape)."""
    sid = _site(db, "Four chain " + src)
    fa = _ingest(db, _cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                          _policy(100, "A", "p_it", "p_dmz", "MODBUS", src, "plc")),
                 "FW-A", sid, {"p_it": 4, "p_dmz": 3.5})
    fb = _ingest(db, _cfg("p_l3", "p_dmz", "10.3.0.1", "10.35.0.2",
                          _policy(200, "B", "p_dmz", "p_l3", "MODBUS", src, "plc")),
                 "FW-B", sid, {"p_dmz": 3.5, "p_l3": 3})
    fc = _ingest(db, _cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2",
                          _policy(300, "C", "p_l3", "p_l2", "MODBUS", src, "plc")),
                 "FW-C", sid, {"p_l3": 3, "p_l2": 2})
    fd = _ingest(db, _cfg("p_l1", "p_l2", "10.1.0.1", "10.2.0.2",
                          _policy(400, "D", "p_l2", "p_l1", "MODBUS", src, "plc")),
                 "FW-D", sid, {"p_l2": 2, "p_l1": 1})
    for down, up in ((fb, fa), (fc, fb), (fd, fc)):
        set_upstream_firewall(db, down.id, up.id, topology_confirmed=True)
    _host(db, sid, IT, 4)
    _host(db, sid, PLC, 1)
    db.commit()
    return sid


# ------------------------------------------------------------ MP-06 + 07 --
def test_network_source_is_placed_by_its_interface_network(db):
    sid = _four_chain(db)
    with analysis_site(db, sid):
        res = enumerate_access_paths(db, sid)
    rows = res["paths"]
    # one real path (4 -> 1) plus its three prefixes; never an L3.5 / L3 / L2
    # row sourced from the L4 network
    assert {(r["src"]["level"], r["dst"]["level"]) for r in rows} == {(4, 1), (4, 2), (4, 3), (4, 3.5)}
    assert all(r["src"]["scope"] == "10.4.0.0/24" for r in rows)
    by_dst = {r["dst"]["level"]: r for r in rows}
    assert by_dst[1]["reach"] == "reaches" and "it_ot_bypass" in by_dst[1]["flags"]
    for lv in (2, 3, 3.5):
        assert by_dst[lv]["reach"] == "prefix"
        assert by_dst[lv]["flags"] == [] and by_dst[lv]["report_include"] is False
    assert "dmz_bypass" in by_dst[3]["flags_at_reached_level"]
    assert res["counts"]["by_reach"] == {"reaches": 1, "prefix": 3, "dead_end": 0}
    assert res["counts"]["by_flag"].get("dmz_bypass", 0) == 0
    assert res["counts"]["report_include"] == 1
    ae.run_periodic_reviews(db, site_id=sid)
    byp = _open(db, "chain_it_ot_bypass")
    assert len(byp) == 1 and "L4 p_it 10.4.0.0/24 → L1" in byp[0].title
    assert _open(db, "dmz_bypass") == []


def test_report_lines_skip_prefix_rows(db):
    sid = _four_chain(db)
    from app.parsers.access_paths import _enumerate
    with analysis_site(db, sid):
        res = _enumerate(db, overlay=False, unmatched_cap=0)
    kinds = [(item["src"]["level"], item["dst"]["level"], kind) for item, kind in report_lines(res)]
    assert kinds == [(4, 1, "path")]
    assert count_rows(res["paths"])["by_reach"]["prefix"] == 3


# ------------------------------------------------------------------ MP-10 --
def _deny_then_any(db):
    """FW-A (4/3) permits tcp 443 + 502; FW-B (3/2) denies tcp/502 then
    permits any."""
    sid = _site(db, "Deny then any")
    svc = '''
        edit "WEB-MODBUS"
            set tcp-portrange 443 502
        next
'''
    fa = _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                                  _policy(1, "a", "p_it", "p_l3", "WEB-MODBUS", "all", "all"))
                 .replace("config firewall service custom", "config firewall service custom" + svc, 1),
                 "FW-A", sid, {"p_it": 4, "p_l3": 3})
    deny = _policy(1, "deny502", "p_l3", "p_l2", "MODBUS", "all", "all").replace(
        "set action accept", "set action deny")
    fb = _ingest(db, _two_leg_cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2",
                                  deny + _policy(2, "any", "p_l3", "p_l2", "ALL", "all", "all")),
                 "FW-B", sid, {"p_l3": 3, "p_l2": 2})
    set_upstream_firewall(db, fb.id, fa.id, topology_confirmed=True)
    _host(db, sid, IT, 4)
    _host(db, sid, "10.2.0.20", 2)
    db.commit()
    return sid


def test_specific_deny_is_subtracted_across_hops(db):
    sid = _deny_then_any(db)
    with analysis_site(db, sid):
        reach = compute_reachability(db)
        p502 = compute_path(db, IT, "10.2.0.20", dst_port=502, protocol="tcp")
        p443 = compute_path(db, IT, "10.2.0.20", dst_port=443, protocol="tcp")
        res = enumerate_access_paths(db, sid)
    c = reach["matrix"]["4→2"]
    assert c["overall"] == "partial"
    assert c["permitted_services"] == ["tcp/443"] and c["denied_services"] == ["tcp/502"]
    # matrix and host path agree
    assert p502["overall"] == "denied" and p443["overall"] == "permitted"
    # the access-path row for the chain lists 443 only: no Modbus bypass
    [row] = [r for r in res["paths"] if r["src"]["level"] == 4 and r["dst"]["level"] == 2]
    assert row["service"] == ["tcp/443"]
    assert "industrial_proto_out_of_zone" not in row["flags"]
    # FW-B alone (3 -> 2): permit-any with the deny kept as text
    [hop] = c["paths"][0]["hops"][1:]
    assert hop["enforcement_points"][0]["denied_services"] == ["tcp/502"]


def test_union_keeps_only_denies_common_to_every_alternative(db):
    from app.parsers.reachability import _SVC_ANY, _Verdict, _union_verdicts
    deny = (frozenset({"tcp"}), ((502, 502),))
    a = _Verdict("permitted", [_SVC_ANY], ["tcp/502"], [deny])
    b = _Verdict("permitted", [_SVC_ANY], ["tcp/502"], [deny])
    u = _union_verdicts([a, b])
    assert u.decision == "permitted" and u.denied_services == ["tcp/502"] and u.denies == [deny]
    c = _Verdict("partial", [(_SVC_ANY[0], _SVC_ANY[1], frozenset({"tcp"}), ((502, 502),))])
    u = _union_verdicts([a, c])        # the partial alternative permits 502
    assert u.decision == "permitted" and u.denied_services == [] and u.denies == []


# ------------------------------------------------------------------ MP-19 --
def test_dead_end_names_the_blocker_for_a_network_source(db):
    sid = _site(db, "Dead end net")
    fa = _ingest(db, _cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                          _policy(100, "A-it-ot", "p_it", "p_dmz", "MODBUS", "it_net", "ot_host")),
                 "FW-A", sid, {"p_it": 4, "p_dmz": 3.5})
    fb = _ingest(db, _cfg("p_l2", "p_dmz", "10.2.0.1", "10.35.0.2",
                          _policy(200, "B-other", "p_dmz", "p_l2", "SSHX", "l3_srv", "ot_host")),
                 "FW-B", sid, {"p_dmz": 3.5, "p_l2": 2})
    set_upstream_firewall(db, fb.id, fa.id, topology_confirmed=True)
    _host(db, sid, "10.2.0.20", 2)
    db.commit()
    with analysis_site(db, sid):
        # a host inside the scope (the config's address object) stands for it
        assert _representative(db, "10.4.0.0/24", 4) == "10.4.0.10"
        assert _representative(db, "10.9.0.0/24", 4) == "10.9.0.1"      # no host: first usable
        assert _representative(db, "10.2.0.20/32") == "10.2.0.20"
        assert _representative(db, "any") is None
    _host(db, sid, "10.4.0.77", 4)
    db.commit()
    with analysis_site(db, sid):
        assert _representative(db, "10.4.0.0/24", 4) == "10.4.0.77"     # a classified host wins
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, "dead_end_permit")
    assert "FW-B drops it (implicit deny)" in f.title
    assert "(traced 10.4.0.77 → 10.2.0.20)" in f.title
    assert f.detail["blocked_at"]["firewall"] == "FW-B"
    assert f.detail["blocked_at"]["traced_src"] == "10.4.0.77"
