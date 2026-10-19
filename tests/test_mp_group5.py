"""Group 5 and leftovers of the multi-firewall audit: MP-11, MP-13, MP-16,
MP-17, MP-18, MP-21, MP-22, MP-23, MP-25."""
from app.models import Finding, FirewallGroup, FirewallInterface, FirewallRule
from app.parsers import alert_engine as ae
from app.parsers import firewall_groups as fg
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.chain_findings import bypass_severity
from app.parsers.reachability import _SVC_ANY, _Verdict, _union_verdicts, compute_path
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import (detect_subnet_overlaps, run_purdue_suggestions,
                                          set_upstream_firewall)
from tests.test_access_paths import _ADDR_SVC, _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host
from tests.test_mp06_07_10_19 import _cfg, _four_chain


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


# ------------------------------------------------------------------ MP-11 --
def test_bypass_severity_follows_source_and_destination_band():
    assert bypass_severity(5, 1) == ("critical", "internet", bypass_severity(5, 1)[2])
    assert bypass_severity(4, 1)[0] == "high" and bypass_severity(4, 2)[0] == "medium"
    assert bypass_severity(3.5, 1)[0] == "medium" and bypass_severity(3.5, 2)[0] == "low"
    assert bypass_severity(3, 1)[0] == "medium" and bypass_severity(3, 2)[0] == "low"
    assert "internet" in bypass_severity(5, 0)[2] and "site operations" in bypass_severity(3, 1)[2]


def test_chain_finding_names_source_band_and_change_point(db):
    sid = _four_chain(db)
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, "chain_it_ot_bypass")
    assert f.severity == "high" and f.detail["source_band"] == "enterprise"
    assert "enterprise network (L4)" in f.detail["description"]
    # MP-22: every hop carries its own src / dst / service and the narrowest hop
    chain = f.detail["chain"]
    assert all(c.get("src") and c.get("dst") and c.get("service") for c in chain)
    assert any(c.get("narrowest") for c in chain)
    assert f.detail["change_point"]


# ------------------------------------------------------------------ MP-13 --
def test_peer_link_suggests_the_peers_own_level_for_a_chain(db):
    sid = _site(db, "Chain suggestion")
    outer = _ingest(db, _two_leg_cfg("inner", "wan", "10.3.0.1", "10.4.0.1",
                                     _policy(1, "a", "wan", "inner", "ALL", "all", "all")),
                    "OUTER", sid, {"wan": 4, "inner": 3})
    inner = _ingest(db, _two_leg_cfg("scada", "uplink", "10.2.0.1", "10.3.0.2",
                                     _policy(1, "b", "uplink", "scada", "ALL", "all", "all")),
                    "INNER", sid, {})
    a = db.query(FirewallInterface).filter_by(firewall_id=outer.id, name="inner").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=inner.id, name="uplink").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    db.commit()
    with analysis_site(db, sid):
        run_purdue_suggestions(db)
    db.commit()
    assert (b.suggested_purdue_level, b.purdue_suggestion_source) == (3, "peer_link")


# ------------------------------------------------------------------ MP-18 --
def test_parallel_cell_firewalls_are_not_suggested_as_a_series_pair(db):
    sid = _site(db, "Cells")
    fa = _ingest(db, _two_leg_cfg("p_cell", "p_up", "10.21.0.1", "10.3.0.11",
                                  _policy(1, "a", "p_up", "p_cell", "MODBUS", "all", "all")),
                 "FW-C1", sid, {"p_up": 3, "p_cell": 2})
    fb = _ingest(db, _two_leg_cfg("p_cell", "p_up", "10.22.0.1", "10.3.0.12",
                                  _policy(1, "b", "p_up", "p_cell", "MODBUS", "all", "all")),
                 "FW-C2", sid, {"p_up": 3, "p_cell": 2})
    with analysis_site(db, sid):
        props = detect_subnet_overlaps(db)
    [p] = [x for x in props if {x["fw_a_name"], x["fw_b_name"]} == {"FW-C1", "FW-C2"}]
    assert p["arrangement"] == "parallel" and "parallel firewalls" in p["arrangement_note"]
    a = db.query(FirewallInterface).filter_by(firewall_id=fa.id, name="p_up").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=fb.id, name="p_up").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    db.commit()
    with analysis_site(db, sid):
        assert fg.suggest_paired(db) == []            # same-level ends: parallel
        # an inside-to-outside link (different levels) is a series candidate
        b.purdue_level = 2
        a.purdue_level = 3
        db.flush()
        # (levels now differ on the link ends, but the boxes no longer share a
        #  level pair - still not a pair)
        assert fg.suggest_paired(db) == []


# ------------------------------------------------------------------ MP-16 --
def test_same_level_crossing_through_one_firewall_is_evaluated(db):
    sid = _site(db, "Three-leg same level")
    cfg = _ADDR_SVC + """
    config system interface
        edit "port1"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "port2"
            set vdom "root"
            set ip 10.3.1.1 255.255.255.0
        next
        edit "port3"
            set vdom "root"
            set ip 10.3.2.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(2, "scada-to-hist", "port2", "port3", "SSHX", "all", "all") \
        + _policy(3, "deny-l3-l3", "port2", "port3", "ALL", "all", "all").replace(
            "set action accept", "set action deny") + """
    end
    """
    _ingest(db, cfg, "FW-3LEG", sid, {"port1": 4, "port2": 3, "port3": 3})
    _host(db, sid, "10.3.1.10", 3)
    _host(db, sid, "10.3.2.10", 3)
    db.commit()
    with analysis_site(db, sid):
        ok = compute_path(db, "10.3.1.10", "10.3.2.10", dst_port=22, protocol="tcp")
        no = compute_path(db, "10.3.1.10", "10.3.2.10", dst_port=502, protocol="tcp")
        back = compute_path(db, "10.3.2.10", "10.3.1.10", dst_port=22, protocol="tcp")
    assert ok["overall"] == "permitted" and no["overall"] == "denied"
    assert ok["same_level_crossing"]["ingress"] == "port2" and ok["same_level_crossing"]["egress"] == "port3"
    assert ok["path"] == "Level 3 (10.3.1.10) → [3↔3 FW-3LEG port2→port3] → Level 3 (10.3.2.10)"
    assert ok["hops"][0]["enforcement_points"][0]["matching_rule"]["policy_id"] == "2"
    # the reverse direction has no policy at all on that leg pair: nothing
    # to evaluate ("no_policy" - the leg crossing exists but no rule names it)
    assert back["overall"] in ("denied", "no_policy") and back["same_level_crossing"]["ingress"] == "port3"


def test_same_level_without_a_firewall_leg_is_still_intra_level(db):
    sid = _site(db, "Flat L3")
    _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                             _policy(1, "a", "p_it", "p_l3", "ALL", "all", "all")),
            "FW", sid, {"p_it": 4, "p_l3": 3})
    _host(db, sid, "10.3.0.10", 3)
    _host(db, sid, "10.3.0.11", 3)
    db.commit()
    with analysis_site(db, sid):
        r = compute_path(db, "10.3.0.10", "10.3.0.11", dst_port=22, protocol="tcp")
    assert r["overall"] == "intra_level" and "not evaluated" in r["path"]


# ------------------------------------------------------------------ MP-17 --
def test_host_path_reports_alternatives_and_prefers_placement(db):
    sid = _site(db, "Direct vs DMZ")
    _ingest(db, _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                             _policy(1, "any", "p_it", "p_l3", "ALL", "all", "all")),
            "FW-X", sid, {"p_it": 4, "p_l3": 3})
    _ingest(db, _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.2",
                             _policy(1, "https", "p_it", "p_dmz", "SSHX", "all", "all")),
            "FW-Y1", sid, {"p_it": 4, "p_dmz": 3.5})
    _ingest(db, _two_leg_cfg("p_l3", "p_dmz", "10.3.0.2", "10.35.0.2",
                             _policy(1, "https", "p_dmz", "p_l3", "SSHX", "all", "all")),
            "FW-Y2", sid, {"p_dmz": 3.5, "p_l3": 3})
    _host(db, sid, "10.4.0.10", 4)
    _host(db, sid, "10.3.0.10", 3)
    db.commit()
    with analysis_site(db, sid):
        r = compute_path(db, "10.4.0.10", "10.3.0.10", dst_port=22, protocol="tcp")
    assert r["overall"] == "permitted" and r["paths_evaluated"] == 2
    assert "most permissive of 2 level paths" in r["path_note"]
    alts = {a["path"]: a for a in r["alternatives"]}
    assert alts["4 → [3↔4] → 3"]["chosen"] is True and alts["4 → [3↔4] → 3"]["decision"] == "permitted"
    assert alts["4 → [3.5↔4] → [3↔3.5] → 3"]["decision"] == "permitted"
    assert alts["4 → [3.5↔4] → [3↔3.5] → 3"]["firewalls"] == ["FW-Y1", "FW-Y2"]


# ------------------------------------------------------------------ MP-21 --
def test_three_leg_composition_and_network_pivot_note(db):
    """vendor (L5) -> gateway (L3.5) -> jump host (L3) -> PLC (L1), joined
    through two single-host pivots; plus a leg pair meeting on a /24."""
    sid = _site(db, "Three legs")
    extra = '''
        edit "gw"
            set subnet 10.35.0.10 255.255.255.255
        next
        edit "jump"
            set subnet 10.3.0.10 255.255.255.255
        next
        edit "dmz_net"
            set subnet 10.35.0.0 255.255.255.0
        next
'''
    def c(lo, hi, lo_ip, hi_ip, pols):
        return _two_leg_cfg(lo, hi, lo_ip, hi_ip, pols).replace(
            "config firewall address", "config firewall address" + extra, 1)
    _ingest(db, c("p_dmz", "p_inet", "10.35.0.1", "203.0.113.1",
                  _policy(1, "vendor-gw", "p_inet", "p_dmz", "SSHX", "all", "gw")
                  + _policy(2, "vendor-net", "p_inet", "p_dmz", "SSHX", "all", "dmz_net")),
            "FW-EDGE", sid, {"p_inet": 5, "p_dmz": 3.5})
    _ingest(db, c("p_l3", "p_dmz", "10.3.0.1", "10.35.0.2",
                  _policy(1, "gw-jump", "p_dmz", "p_l3", "SSHX", "gw", "jump")
                  + _policy(2, "net-jump", "p_dmz", "p_l3", "SSHX", "dmz_net", "jump")),
            "FW-DMZ", sid, {"p_dmz": 3.5, "p_l3": 3})
    _ingest(db, c("p_l1", "p_l3", "10.1.0.1", "10.3.0.2",
                  _policy(1, "jump-plc", "p_l3", "p_l1", "MODBUS", "jump", "plc")),
            "FW-OT", sid, {"p_l3": 3, "p_l1": 1})
    _host(db, sid, "10.35.0.10", 3.5)
    _host(db, sid, "10.3.0.10", 3)
    _host(db, sid, "10.1.0.30", 1)
    db.commit()
    with analysis_site(db, sid):
        res = enumerate_access_paths(db, sid)
    composed = [p for p in res["paths"] if p["direction"] == "composed"]
    three = [p for p in composed if len(p["legs"]) == 3]
    assert three, [(p["src"]["level"], p["dst"]["level"], len(p["legs"])) for p in composed]
    [row] = [p for p in three if p["src"]["level"] == 5 and p["dst"]["level"] == 1
             and p["legs"][0]["policy_ids"] == ["1"] and p["legs"][1]["policy_ids"] == ["1"]]
    assert [pv["ip"] for pv in row["pivots"]] == ["10.35.0.10", "10.3.0.10"]
    assert [c["firewall_name"] for c in row["chain"]] == ["FW-EDGE", "FW-DMZ", "FW-OT"]
    # the /24 pair (vendor-net -> dmz_net, dmz_net -> jump) overlaps on a network: noted
    notes = res["composition_notes"]
    assert any(n["leg1"].startswith("FW-EDGE #2") and n["leg2"].startswith("FW-DMZ #2") for n in notes)
    assert all("declare a hop" in n["reason"] for n in notes)


# ------------------------------------------------------------------ MP-23 --
def test_vpn_sourced_policy_is_judged_once(db):
    sid = _site(db, "VPN once")
    cfg = _ADDR_SVC + """
    config system interface
        edit "ssl.root"
            set vdom "root"
            set type tunnel
        next
        edit "port2"
            set vdom "root"
            set ip 10.2.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "vpn-to-ot", "ssl.root", "port2", "SSHX", "all", "all") + """
    end
    """
    _ingest(db, cfg, "FW-VPN", sid, {"port2": 2})
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    twins = [f for f in _open(db, "rule_it_ot_bypass") + _open(db, "rule_mgmt_wrong_zone")
             if f.device_name == "FW-VPN"]
    assert twins == [], [f.title for f in twins]
    vpn = _open(db, "vpn_direct_to_ot") + _open(db, "config_vpn_direct_to_ot")
    assert vpn, "the VPN check still judges the policy"


# ------------------------------------------------------------------ MP-25 --
def test_union_of_partial_and_unknown_is_marked_uncertain():
    partial = _Verdict("partial", [(_SVC_ANY[0], _SVC_ANY[1], frozenset({"tcp"}), ((443, 443),))])
    u = _union_verdicts([partial, _Verdict("unknown")])
    assert u.decision == "partial" and u.uncertain is True
    assert _union_verdicts([partial, _Verdict("denied")]).uncertain is False


def test_tunnel_that_stops_being_remote_access_loses_auto_l5():
    from app.parsers.forti_config_parser import VPN_TUNNEL_AUTO_SOURCE, _vpn_tunnel_level

    class Row:
        purdue_level = 5
        purdue_suggestion_source = VPN_TUNNEL_AUTO_SOURCE
        side = "outside"
        remote_access = "ipsec_dialup"
    r = Row()
    _vpn_tunnel_level(r, "to-branch", "tunnel", dialup=frozenset())      # no longer dial-up
    assert r.purdue_level is None and r.purdue_suggestion_source is None and r.remote_access is None
    r2 = Row()
    r2.purdue_suggestion_source = None                                   # operator label
    _vpn_tunnel_level(r2, "to-branch", "tunnel", dialup=frozenset())
    assert r2.purdue_level == 5


def test_labels_on_the_ha_secondary_only_are_explained(db):
    from app.parsers.reachability import _Context
    sid = _site(db, "HA labels")
    cfg = _two_leg_cfg("p_l1", "p_l3", "10.1.0.1", "10.3.0.2",
                       _policy(20, "l3-l1", "p_l3", "p_l1", "MODBUS", "it_host", "plc"))
    fa = _ingest(db, cfg, "FW-A", sid, {})
    fb = _ingest(db, cfg, "FW-B", sid, {"p_l3": 3, "p_l1": 1})
    with analysis_site(db, sid):
        fg.declare_ha(db, sid, [fa.id, fb.id])
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
    [u] = [x for x in ctx.unplaced_firewalls if x["firewall"] == "FW-A"]
    assert "interface levels are on the HA secondary (FW-B) only" in u["reason"]
