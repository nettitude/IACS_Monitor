"""HA clusters, paired firewalls (+ vendor-diversity attestation) and
dead-end permits."""
import pytest

from app.models import Attestation, Finding, Firewall, FirewallGroup, FirewallInterface
from app.parsers import alert_engine as ae
from app.parsers import firewall_groups as fg
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.cross_fw_findings import run_cross_fw_checks
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import detect_subnet_overlaps, set_upstream_firewall
from tests.test_access_paths import _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host

PLC = "10.1.0.30"


def _open(db, sid, check):
    return db.query(Finding).filter(Finding.site_id == sid, Finding.check_name == check,
                                    Finding.status == "open").all()


def _ha_site(db, extra_policy_on_b=""):
    """FW-IT (L4/L3) upstream of an HA cluster FW-A / FW-B (L3/L1) whose two
    member configs are identical (same interfaces, same policy)."""
    sid = _site(db, "HA plant")
    up = _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                      _policy(10, "it-l3", "p_it", "p_l3", "MODBUS", "it_host", "plc"))
    pol = _policy(20, "l3-l1", "p_l3", "p_l1", "MODBUS", "it_host", "plc")
    a = _two_leg_cfg("p_l1", "p_l3", "10.1.0.1", "10.3.0.2", pol)
    b = _two_leg_cfg("p_l1", "p_l3", "10.1.0.1", "10.3.0.2", pol + extra_policy_on_b)
    fw_it = _ingest(db, up, "FW-IT", sid, {"p_it": 4, "p_l3": 3})
    fa = _ingest(db, a, "FW-A", sid, {"p_l3": 3, "p_l1": 1})
    fb = _ingest(db, b, "FW-B", sid, {"p_l3": 3, "p_l1": 1})
    set_upstream_firewall(db, fa.id, fw_it.id, site_id=sid)
    set_upstream_firewall(db, fb.id, fw_it.id, site_id=sid)
    _host(db, sid, PLC, 1)
    db.commit()
    return sid, fw_it, fa, fb


def _l4_l1_chains(db, sid):
    return [p for p in enumerate_access_paths(db, sid)["paths"]
            if p["direction"] == "down" and p["src"]["level"] == 4 and p["dst"]["level"] == 1]


# -------------------------------------------------------------------- HA --
def test_ha_cluster_is_one_enforcement_point(db):
    sid, fw_it, fa, fb = _ha_site(db)
    before = _l4_l1_chains(db, sid)
    # MP-01: two undeclared boxes on the L3/L1 boundary are alternatives, so
    # the flow has one chain through each (never both in one chain)
    assert before and all(len({c["firewall_name"] for c in p["chain"]}) == 2 for p in before)
    assert {frozenset(c["firewall_name"] for c in p["chain"]) for p in before} == \
        {frozenset({"FW-IT", "FW-A"}), frozenset({"FW-IT", "FW-B"})}
    with analysis_site(db, sid):
        g = fg.declare_ha(db, sid, [fa.id, fb.id])
    db.commit()
    after = _l4_l1_chains(db, sid)
    assert after and all({c["firewall_name"] for c in p["chain"]} == {"FW-IT", "FW-A"} for p in after)
    with analysis_site(db, sid):
        assert fg.ha_secondary_ids(db) == {fb.id}
        assert g.primary_firewall_id == fa.id
        # the members' identical interfaces are never proposed as a link
        assert not [p for p in detect_subnet_overlaps(db)
                    if {p["fw_a_id"], p["fw_b_id"]} == {fa.id, fb.id}]


def test_ha_drift_finding_and_clean_cluster(db):
    extra = _policy(99, "temp-any", "p_l3", "p_l1", "ALL")
    sid, fw_it, fa, fb = _ha_site(db, extra_policy_on_b=extra)
    with analysis_site(db, sid):
        fg.declare_ha(db, sid, [fa.id, fb.id], name="OT core")
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, sid, "ha_config_drift")
    assert f.severity == "high"                       # a permit differs
    assert "FW-B" in f.title and "1 policy(ies) only on FW-B" in f.title
    assert f.detail["extra_on_member"][0]["policy_id"] == "99"
    # the member's own rule findings are not raised (one configuration)
    assert not [x for x in _open(db, sid, "rule_cleartext_protocol") if x.device_name == "FW-B"]


def test_ha_identical_members_no_drift_and_duplicates_folded(db):
    sid, fw_it, fa, fb = _ha_site(db)
    # config findings for both members (generate_findings at ingest)
    db.add_all([Finding(site_id=sid, category="config_review", check_name="config_no_timezone",
                        severity="low", title=f"tz {n}", detail={}, source_ref=f"config:{i}:config_no_timezone",
                        status="open")
                for i, n in ((fa.id, "A"), (fb.id, "B"))])
    db.commit()
    with analysis_site(db, sid):
        fg.declare_ha(db, sid, [fa.id, fb.id])
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert _open(db, sid, "ha_config_drift") == []
    tz = db.query(Finding).filter(Finding.check_name == "config_no_timezone").all()
    by = {f.source_ref.split(":")[1]: f for f in tz}
    assert by[str(fa.id)].status == "open"
    assert by[str(fb.id)].status == "closed" and "Folded into HA cluster" in by[str(fb.id)].notes


def test_ha_validation_and_suggestion(db):
    sid, fw_it, fa, fb = _ha_site(db)
    fa.ha_mode, fa.ha_cfg_group = "a-p", "OT-CORE/7"
    fb.ha_mode, fb.ha_cfg_group = "a-p", "OT-CORE/7"
    db.commit()
    with analysis_site(db, sid):
        [s] = fg.suggest_ha(db)
        assert {x["id"] for x in s["firewalls"]} == {fa.id, fb.id}
        with pytest.raises(fg.GroupError):
            fg.declare_ha(db, sid, [fa.id])
        with pytest.raises(fg.GroupError) as e:
            fg.declare_ha(db, sid, [fa.id, 999999])
        assert e.value.status == 404
        fg.declare_ha(db, sid, [fa.id, fb.id], primary_id=fb.id)
        with pytest.raises(fg.GroupError) as e:
            fg.declare_ha(db, sid, [fa.id, fw_it.id])
        assert e.value.status == 409
        assert fg.suggest_ha(db) == []
        assert fg.ha_secondary_ids(db) == {fa.id}


# ---------------------------------------------------------------- paired --
def _paired_site(db):
    """Two firewalls in series on the L4/L3 boundary, linked by a transit net;
    FW-OUT has one permit FW-IN lacks."""
    sid = _site(db, "Paired plant")
    out = _two_leg_cfg("p_tr", "p_it", "172.16.0.1", "10.4.0.1",
                       _policy(10, "it-l3", "p_it", "p_tr", "MODBUS", "it_host", "ot_host")
                       + _policy(11, "TEMP-any", "p_it", "p_tr", "ALL", "it_host", "all"))
    inn = _two_leg_cfg("p_l3", "p_tr", "10.3.0.1", "172.16.0.2",
                       _policy(10, "it-l3", "p_tr", "p_l3", "MODBUS", "it_host", "ot_host"))
    fo = _ingest(db, out, "FW-OUT", sid, {"p_it": 4, "p_tr": 3})
    fi = _ingest(db, inn, "FW-IN", sid, {"p_tr": 4, "p_l3": 3})
    a = db.query(FirewallInterface).filter_by(firewall_id=fo.id, name="p_tr").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=fi.id, name="p_tr").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    db.commit()
    return sid, fo, fi


def test_paired_suggestion_declaration_and_asymmetry_scope(db):
    sid, fo, fi = _paired_site(db)
    with analysis_site(db, sid):
        [s] = fg.suggest_paired(db)
        assert {x["name"] for x in s["firewalls"]} == {"FW-OUT", "FW-IN"} and s["levels"] == [3, 4]
        g = fg.declare_paired(db, sid, [fo.id, fi.id], name="IT/OT pair")
        db.commit()
        assert fg.suggest_paired(db) == []
        out = run_cross_fw_checks(db)
    db.commit()
    assert out["asymmetric_skipped_links"] == 0
    asym = _open(db, sid, "cross_fw_asymmetric_permit")
    assert any("FW-OUT" in f.title and "FW-IN" in f.title for f in asym)
    assert g.kind == "paired"


def test_confirmed_groups_decide_over_the_heuristic(db):
    sid, fo, fi = _paired_site(db)
    other = Firewall(site_id=sid, name="FW-X", vendor="paloalto")
    db.add(other)
    db.commit()
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, other.id])
        db.commit()
        # FW-OUT and FW-IN have identical levels, but FW-OUT's confirmed pair
        # is FW-X: the linked FW-IN is not compared any more
        assert fg.confirmed_pair(db, fo, fi) is False
        assert fg.confirmed_pair(db, fo, other) is True


def test_vendor_diversity_is_a_manual_attestation(db):
    from datetime import datetime, timezone
    sid, fo, fi = _paired_site(db)
    with analysis_site(db, sid):
        g = fg.declare_paired(db, sid, [fo.id, fi.id], name="DMZ pair")
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, sid, "paired_firewall_vendor_diversity")
    assert f.detail["attestation_checklist_id"] == f"PF-{g.id}"
    assert f.detail["recorded_vendors"] == ["fortigate"] and f.detail["manual_check"] is True
    # the operator confirms -> resolved on the next run
    db.add(Attestation(site_id=sid, checklist_id=f"PF-{g.id}", attested_by="ops lead",
                       attested_at=datetime.now(timezone.utc), notes="FortiGate outer, Palo Alto inner",
                       is_current=True))
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert _open(db, sid, "paired_firewall_vendor_diversity") == []
    with analysis_site(db, sid):
        gd = fg.group_dict(db, db.get(FirewallGroup, g.id))
    assert gd["vendor_diversity_attested"]["attested_by"] == "ops lead"


def test_ha_cluster_counts_once_in_a_pair(db):
    sid, fw_it, fa, fb = _ha_site(db)
    with analysis_site(db, sid):
        fg.declare_ha(db, sid, [fa.id, fb.id])
        with pytest.raises(fg.GroupError):
            fg.declare_paired(db, sid, [fa.id, fb.id])      # one logical firewall
        # MP-04: FW-IT (L4/L3) and the cluster (L3/L1) are a chain, not a
        # pair on one level pair - refused with both placements named
        with pytest.raises(fg.GroupError, match="FW-IT L3↔L4, FW-A L1↔L3"):
            fg.declare_paired(db, sid, [fw_it.id, fa.id])
        # relabelled onto the cluster's level pair the HA cluster joins whole
        for i in db.query(FirewallInterface).filter_by(firewall_id=fw_it.id):
            i.purdue_level = {"p_it": 3, "p_l3": 1}.get(i.name, i.purdue_level)
        db.flush()
        g = fg.declare_paired(db, sid, [fw_it.id, fa.id])
        assert {f.id for f in db.query(Firewall).filter_by(paired_group_id=g.id)} == {fw_it.id, fa.id, fb.id}


# --------------------------------------------------------------- dead ends --
def _three_fw(db, third_permits: bool):
    sid = _site(db, "Dead-end plant")
    c1 = _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1",
                      _policy(10, "it-l3", "p_it", "p_l3", "MODBUS", "it_host", "plc"))
    c2 = _two_leg_cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2",
                      _policy(20, "LEGACY-l3-l2", "p_l3", "p_l2", "MODBUS", "it_host", "plc"))
    c3 = _two_leg_cfg("p_l1", "p_l2", "10.1.0.1", "10.2.0.2",
                      _policy(30, "l2-l1", "p_l2", "p_l1", "MODBUS", "it_host", "plc")
                      if third_permits else _policy(31, "hmi-l1", "p_l2", "p_l1", "MODBUS", "ot_host", "plc"))
    f1 = _ingest(db, c1, "FW1", sid, {"p_it": 4, "p_l3": 3})
    f2 = _ingest(db, c2, "FW2", sid, {"p_l3": 3, "p_l2": 2})
    f3 = _ingest(db, c3, "FW3", sid, {"p_l2": 2, "p_l1": 1})
    set_upstream_firewall(db, f2.id, f1.id, site_id=sid)
    set_upstream_firewall(db, f3.id, f2.id, site_id=sid)
    _host(db, sid, "10.4.0.10", 4)
    _host(db, sid, PLC, 1)
    db.commit()
    return sid


def test_dead_end_permit_is_raised_and_not_called_a_bypass(db):
    sid = _three_fw(db, third_permits=False)
    ae.run_periodic_reviews(db, site_id=sid)
    [d] = _open(db, sid, "dead_end_permit")
    assert d.detail["reached_level"] == 2 and d.detail["destination_level"] == 1
    assert d.detail["blocked_at"]["firewall"] == "FW3" and d.detail["blocked_at"]["implicit_deny"]
    assert "LEGACY" in d.detail["name_markers"]
    assert d.severity == "low"                         # no capture attempts
    # the L4 -> L2 row reaches nothing at L2: not an IT/OT bypass finding
    assert not [f for f in _open(db, sid, "chain_it_ot_bypass") if PLC in f.title]


def test_prefix_of_a_longer_chain_is_neither(db):
    sid = _three_fw(db, third_permits=True)
    ae.run_periodic_reviews(db, site_id=sid)
    assert _open(db, sid, "dead_end_permit") == []
    chain = _open(db, sid, "chain_it_ot_bypass")
    # one finding for the full L4 -> L1 chain; its L4 -> L2 prefix is not raised
    assert [f.detail["path"]["dst"]["level"] for f in chain if f.detail["path"]["src"]["level"] == 4] == [1]


# -------------------------------------------------------------------- API --
from tests.test_access_path_tags import api  # noqa: E402,F401

_HA_CFG = """
config system global
    set hostname "{host}"
end
config system ha
    set group-name "OT-CORE"
    set group-id 7
    set mode a-p
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.3.0.2 255.255.255.0
    next
    edit "port2"
        set vdom "root"
        set ip 10.1.0.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "l3-l1"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""


def test_ha_peer_upload_groups_and_attestation_api(api):
    c = api
    site = c.post("/sites", json={"name": "Api plant", "code": "api"}).json()["id"]

    def up(name, peer=None):
        params = {"site": "api", "firewall_name": name, "generate_findings": "true"}
        if peer:
            params["ha_peer"] = peer
        r = c.post("/ingest/fortigate-config", params=params,
                   files={"file": (f"{name}.conf", _HA_CFG.format(host=name).encode(), "text/plain")})
        assert r.status_code == 200, r.text
        return r.json()

    a = up("FG-A")
    assert a["stats"]["ha_cluster"]["config_ha"] == {"mode": "a-p", "group": "OT-CORE/7"}
    sugg = c.get(f"/topology/firewall-groups?site_id={site}").json()["suggestions"]
    assert sugg == []                                   # only one HA config so far
    b = up("FG-B", peer="FG-A")
    gid = b["stats"]["ha_cluster"]["group_id"]
    groups = c.get(f"/topology/firewall-groups?site_id={site}").json()["groups"]
    [g] = [x for x in groups if x["id"] == gid]
    assert g["kind"] == "ha" and {m["name"] for m in g["members"]} == {"FG-A", "FG-B"}
    fa = next(m["id"] for m in g["members"] if m["name"] == "FG-A")
    assert g["primary_firewall_id"] == fa
    # the member's duplicate config findings were folded into the primary's
    s = c.Session()
    fb = next(m["id"] for m in g["members"] if m["name"] == "FG-B")
    assert not s.query(Finding).filter(Finding.source_ref.like(f"config:{fb}:%"),
                                       Finding.status == "open").count()
    # bad peer -> reported, upload still fine
    bad = up("FG-C", peer="nope")
    assert "not an uploaded firewall" in bad["stats"]["ha_cluster"]["error"]
    # paired firewall over the API + PF attestation
    s.close()
    s = c.Session()                      # fresh snapshot: FG-C was uploaded since
    fc = s.query(Firewall).filter_by(name="FG-C").one().id
    r = c.post(f"/topology/paired-firewalls?site_id={site}", json={"firewall_ids": [fa, fc], "name": "pair"})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert r.json()["attestation_checklist_id"] == f"PF-{pid}"
    r = c.post("/attestation", data={"checklist_id": f"PF-{pid}", "attested_by": "ops",
                                     "attested_at": "2026-10-01", "site": "api"})
    assert r.status_code == 201, r.text
    assert c.post("/attestation", data={"checklist_id": "PF-99999", "attested_by": "ops",
                                        "attested_at": "2026-10-01", "site": "api"}).status_code == 400
    g2 = [x for x in c.get(f"/topology/firewall-groups?site_id={site}").json()["groups"] if x["id"] == pid][0]
    assert g2["vendor_diversity_attested"]["attested_by"] == "ops"
    # errors and delete
    assert c.post(f"/topology/ha-pairs?site_id={site}", json={"firewall_ids": [fa]}).status_code == 422
    assert c.post(f"/topology/ha-pairs?site_id={site}", json={"firewall_ids": [fa, fc]}).status_code == 409
    assert c.delete(f"/topology/firewall-groups/{gid}?site_id={site}").status_code == 200
    assert c.delete(f"/topology/firewall-groups/{gid}?site_id={site}").status_code == 404


def test_one_diversity_finding_per_paired_group(db):
    """Each paired group has its own finding (dedup key per group)."""
    sid, fo, fi = _paired_site(db)
    x1 = Firewall(site_id=sid, name="FW-X1", vendor="fortigate")
    x2 = Firewall(site_id=sid, name="FW-X2", vendor="paloalto")
    db.add_all([x1, x2])
    db.commit()
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id])
        fg.declare_paired(db, sid, [x1.id, x2.id])
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert len(_open(db, sid, "paired_firewall_vendor_diversity")) == 2
