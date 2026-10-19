"""MP-09 / MP-14 / MP-15: one side-resolution story for reachability and
the rule twins.

* MP-09  a rule side naming an interface that EXISTS but carries no level is
         "another leg" on a multi-leg box (never this crossing, and listed as
         skipped), uncertain on a partially labelled explicit boundary, and
         incomplete for the rule twins.
* MP-14  the twin resolver follows reachability's lookup order (zone
         definition > exact interface name > alias / zone_label) with the
         exact-name and label maps kept apart.
* MP-15  a firewall with an upload boundary and no interface labels feeds
         that boundary to the rule twins (one severity step lower, flagged).
"""
from app.models import Finding, FirewallDevice, FirewallInterface, FirewallRule, Site
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import _RuleZoneResolver
from app.parsers.reachability import _SIDE_UNKNOWN, _Context, compute_path, compute_reachability
from app.parsers.site_scope import analysis_site
from tests.test_access_paths import _ADDR_SVC, _ingest, _policy, _site, db  # noqa: F401
from tests.test_access_paths_overlay import _host

IT, OPS, PLC = "10.4.0.10", "10.3.0.10", "10.1.0.30"


def _cfg(ifaces: dict, policies: str, zones: str = "") -> str:
    body = "".join(f'''
        edit "{n}"
            set vdom "root"
            set ip {ip}
        next''' for n, ip in ifaces.items())
    return _ADDR_SVC + f"""
    config system interface{body}
    end
    {zones}
    config firewall policy
    {policies}
    end
    """


def _rules(db, fw):
    return {r.policy_id: r for r in db.query(FirewallRule).filter_by(firewall_id=fw.id)}


def _ep(ctx, lo, hi):
    [ep] = ctx.boundary_map[(lo, hi)]
    return ep


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


# ------------------------------------------------------------------ MP-09 --
def test_unlabelled_interface_is_another_leg_on_a_multi_leg_box(db):
    sid = _site(db, "Three-leg with wan")
    cfg = _cfg({"wan1": "203.0.113.2 255.255.255.0", "port1": "10.4.0.1 255.255.255.0",
                "port2": "10.3.0.1 255.255.255.0"},
               _policy(1, "wan-to-ops", "wan1", "port2", "ALL", "all", "all")
               + _policy(2, "it-to-ops-modbus", "port1", "port2", "MODBUS", "it_host", "ot_host")
               + _policy(3, "mixed", "wan1, port1", "port2", "SSHX", "all", "all"))
    fw = _ingest(db, cfg, "FW-3", sid, {"port1": 4, "port2": 3})      # wan1 unlabelled
    _host(db, sid, IT, 4)
    _host(db, sid, OPS, 3)
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        ep = _ep(ctx, 3, 4)
        r = _rules(db, fw)
        # wan1 alone: no labelled leg -> matches nothing on this crossing
        assert ctx.side_levels(ep, r["1"], "src") == frozenset()
        assert ctx.rule_applies(ep, r["1"], 4, 3) is False
        assert ctx.direction_unverified(ep, r["1"]) is False
        # "wan1, port1": the labelled leg it also names decides
        assert ctx.side_levels(ep, r["3"], "src") == {4}
        assert ctx.rule_applies(ep, r["3"], 4, 3) is True
        reach = compute_reachability(db)
    c = reach["matrix"]["4→3"]
    assert c["overall"] == "partial"           # policies 2 and 3, never the wan1 permit-all
    [ev] = c["paths"][0]["hops"][0]["enforcement_points"]
    assert sorted(ev["permitted_services"]) == ["tcp/22", "tcp/502"]
    [sk] = ev["rules_skipped_unlabelled"]
    assert sk["policy_id"] == "1" and sk["unlabelled"] == ["wan1"]
    [epi] = reach["enforcement_points"]
    assert epi["unlabelled_interfaces"] == ["wan1"]


def test_unlabelled_interface_on_a_partly_labelled_boundary_is_uncertain(db):
    sid = _site(db, "Explicit boundary, one label")
    cfg = _cfg({"port1": "10.4.0.1 255.255.255.0", "port2": "10.3.0.1 255.255.255.0"},
               _policy(1, "it-to-ops", "port1", "port2", "ALL", "all", "all"))
    fw = _ingest(db, cfg, "FW-E", sid, {"port2": 3})     # port1 known, no level
    fw.purdue_level_ingress, fw.purdue_level_egress = 4, 3
    _host(db, sid, IT, 4)
    _host(db, sid, OPS, 3)
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        ep = _ep(ctx, 3, 4)
        r = _rules(db, fw)
        assert ctx.side_levels(ep, r["1"], "src") is _SIDE_UNKNOWN
        assert ctx.rule_applies(ep, r["1"], 4, 3) == "uncertain"
        reach = compute_reachability(db)
    c = reach["matrix"]["4→3"]
    assert c["overall"] == "unknown"
    [ev] = c["paths"][0]["hops"][0]["enforcement_points"]
    [u] = ev["unresolved_rules"]
    assert "names interface(s) without a Purdue level (port1)" in u["note"]
    # the twins: the side is incomplete, the rule is marked not evaluated
    res = _RuleZoneResolver(db)
    assert res.resolve_checked(r["1"], "port1") == (set(), False)
    assert res.is_known_unlabelled(fw.id, "port1") and not res.is_known_unlabelled(fw.id, "port2")
    assert res.names_unlabelled([r["1"]])


def test_fully_unlabelled_boundary_keeps_both_ways_and_unverified(db):
    # D-11 is unchanged: no labelled interface at all -> both ways, flagged
    sid = _site(db, "Explicit boundary, no labels")
    cfg = _cfg({"port1": "10.4.0.1 255.255.255.0", "port2": "10.3.0.1 255.255.255.0"},
               _policy(1, "it-to-ops", "port1", "port2", "ALL", "all", "all"))
    fw = _ingest(db, cfg, "FW-U", sid, {})
    fw.purdue_level_ingress, fw.purdue_level_egress = 4, 3
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        ep = _ep(ctx, 3, 4)
        r = _rules(db, fw)
        assert ctx.side_levels(ep, r["1"], "src") is None
        assert ctx.rule_applies(ep, r["1"], 4, 3) is True and ctx.rule_applies(ep, r["1"], 3, 4) is True
        assert ctx.direction_unverified(ep, r["1"]) is True


# ------------------------------------------------------------------ MP-14 --
def test_twin_resolver_prefers_zone_definition_over_alias_and_keeps_maps_apart(db):
    sid = _site(db, "Alias vs zone")
    zones = '''
    config system zone
        edit "OT"
            set interface "port3"
        next
    end
    '''
    cfg = _cfg({"port1": "10.4.0.1 255.255.255.0", "port2": "10.3.0.1 255.255.255.0",
                "port3": "10.1.0.1 255.255.255.0", "dmz": "10.35.0.1 255.255.255.0",
                "port9": "10.9.0.1 255.255.255.0"},
               _policy(1, "it-to-OT", "port1", "OT", "ALL", "all", "all")
               + _policy(2, "it-to-dmz", "port1", "dmz", "ALL", "all", "all"), zones)
    fw = _ingest(db, cfg, "FW-Z", sid, {"port1": 4, "port2": 3, "port3": 1, "dmz": 3.5, "port9": 3})
    p2 = db.query(FirewallInterface).filter_by(firewall_id=fw.id, name="port2").one()
    p2.alias = "OT"                       # alias equal to the zone name
    p9 = db.query(FirewallInterface).filter_by(firewall_id=fw.id, name="port9").one()
    p9.zone_label = "DMZ"                 # label equal to another interface's NAME
    db.commit()
    with analysis_site(db, sid):
        ctx = _Context(db)
        ep13 = _ep(ctx, 1, 4)
        r = _rules(db, fw)
        res = _RuleZoneResolver(db)
        # zone OT = {port3 (L1)} wins over port2's alias "OT" (L3) - both resolvers
        assert ctx.side_levels(ep13, r["1"], "dst") == {1}
        assert res.resolve_checked(r["1"], "OT") == ({1}, True)
        # "dmz" is an interface NAME (L3.5); port9's label "DMZ" (L3) must not overwrite it
        ep354 = _ep(ctx, 3.5, 4)
        assert ctx.side_levels(ep354, r["2"], "dst") == {3.5}
        assert res.resolve_checked(r["2"], "dmz") == ({3.5}, True)
        # a label shared by two interfaces resolves to both levels
        p2.zone_label = "shared"
        p9.zone_label = "shared"
        db.flush()
        res = _RuleZoneResolver(db)
        assert res.resolve_checked(r["2"], "shared") == ({3}, True)
        p9.purdue_level = 2
        db.flush()
        res = _RuleZoneResolver(db)
        assert res.resolve_checked(r["2"], "shared") == ({2, 3}, True)
    # the IT -> OT (L1) permit is an IT/OT bypass at the rule level too
    ae.run_periodic_reviews(db, site_id=sid)
    assert any("'OT' (L1)" in f.title for f in _open(db, "rule_it_ot_bypass"))


# ------------------------------------------------------------------ MP-15 --
def _boundary_site(db, with_sides=False):
    sid = _site(db, "Boundary only")
    cfg = _cfg({"port1": "10.4.0.1 255.255.255.0", "port2": "10.2.0.1 255.255.255.0"},
               _policy(1, "it-to-hmi-any", "port1", "port2", "ALL", "all", "all"))
    fw = _ingest(db, cfg, "FW-42", sid, {})
    dev = db.query(FirewallDevice).filter_by(site_id=sid, name="FW-42").one()
    dev.purdue_zone_from, dev.purdue_zone_to = 4, 2            # the upload boundary
    if with_sides:
        for i in db.query(FirewallInterface).filter_by(firewall_id=fw.id):
            i.side = "outside" if i.name == "port1" else "inside"
    db.commit()
    return sid, fw


def test_upload_boundary_feeds_the_rule_twins_one_step_lower(db):
    sid, fw = _boundary_site(db)
    r = _rules(db, fw)["1"]
    res = _RuleZoneResolver(db)
    assert res.boundary_by_fw[fw.id] == (2, 4)
    # no interface side recorded: either end
    assert res.resolve_checked(r, "port1") == ({2, 4}, True)
    assert res.from_boundary([r])
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = [f for f in _open(db, "rule_it_ot_bypass") if f.device_name == "FW-42"]
    assert f.severity == "low"                       # medium, stepped down
    assert "[levels from upload boundary, direction unverified]" in f.title
    assert f.detail["level_source"] == "boundary"
    assert "'port1' (L4) → OT 'port2' (L2)" in f.title


def test_interface_side_picks_the_end_of_the_boundary(db):
    sid, fw = _boundary_site(db, with_sides=True)
    r = _rules(db, fw)["1"]
    res = _RuleZoneResolver(db)
    assert res.resolve_checked(r, "port1") == ({4}, True)      # outside -> high side
    assert res.resolve_checked(r, "port2") == ({2}, True)      # inside -> low side
    assert res.resolve_checked(r, "any") == ({2, 4}, True)


def test_boundary_is_ignored_once_an_interface_is_labelled(db):
    sid, fw = _boundary_site(db)
    i = db.query(FirewallInterface).filter_by(firewall_id=fw.id, name="port2").one()
    i.purdue_level = 2
    db.commit()
    r = _rules(db, fw)["1"]
    res = _RuleZoneResolver(db)
    assert res.resolve_checked(r, "port2") == ({2}, True)
    assert res.resolve_checked(r, "port1") == (set(), False)   # known, unlabelled: incomplete
    assert not res.from_boundary([r]) and res.names_unlabelled([r])
    # labels present: the finding (if any) is never stepped down
    ae.run_periodic_reviews(db, site_id=sid)
    assert not any(f.detail.get("level_source") == "boundary" for f in _open(db, "rule_it_ot_bypass"))
