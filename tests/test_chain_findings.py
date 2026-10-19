"""D-05: chain-aware rule reviews - findings for IT -> OT paths permitted
by a chain of policies across several firewalls, which no single-policy
rule twin can see."""
from app.models import Finding
from app.parsers import alert_engine as ae
from app.parsers import chain_findings as cf
from app.parsers.site_scope import analysis_site
from app.parsers.topology_manager import set_upstream_firewall
from tests.test_access_paths import _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_path_tags import api  # noqa: F401


def _chain_site(db, service="ALL", levels2=None):
    sid = _site(db, "Chain plant")
    cfg1 = _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                        _policy(100, "it-dmz", "p_it", "p_dmz", service))
    cfg2 = _two_leg_cfg("p_l1", "p_dmz", "10.1.0.1", "10.35.0.2",
                        _policy(200, "dmz-l1", "p_dmz", "p_l1", service))
    fw1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_dmz": 3.5})
    fw2 = _ingest(db, cfg2, "FW2", sid, levels2 if levels2 is not None else {"p_dmz": 3.5, "p_l1": 1})
    set_upstream_firewall(db, fw2.id, fw1.id, site_id=sid)
    db.commit()
    return sid, fw1, fw2


def _findings(db, sid, check):
    return db.query(Finding).filter(Finding.site_id == sid, Finding.check_name == check,
                                    Finding.status == "open").all()


def test_chain_bypass_is_raised_where_the_rule_twin_is_blind(db):
    """L4 -> L3 -> L2 -> L1 through three firewalls, each crossing adjacent
    levels only: no single policy is a bypass, the chain is."""
    sid = _site(db, "Serial plant")
    cfg1 = _two_leg_cfg("p_l3", "p_it", "10.3.0.1", "10.4.0.1", _policy(100, "it-l3", "p_it", "p_l3", "ALL"))
    cfg2 = _two_leg_cfg("p_l2", "p_l3", "10.2.0.1", "10.3.0.2", _policy(200, "l3-l2", "p_l3", "p_l2", "ALL"))
    cfg3 = _two_leg_cfg("p_l1", "p_l2", "10.1.0.1", "10.2.0.2", _policy(300, "l2-l1", "p_l2", "p_l1", "ALL"))
    fw1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_l3": 3})
    fw2 = _ingest(db, cfg2, "FW2", sid, {"p_l3": 3, "p_l2": 2})
    fw3 = _ingest(db, cfg3, "FW3", sid, {"p_l2": 2, "p_l1": 1})
    set_upstream_firewall(db, fw2.id, fw1.id, site_id=sid)
    set_upstream_firewall(db, fw3.id, fw2.id, site_id=sid)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    # the per-policy twin sees only adjacent-level crossings: nothing
    assert _findings(db, sid, "rule_it_ot_bypass") == []
    chain = _findings(db, sid, "chain_it_ot_bypass")
    # every bypassing sub-chain is its own remediation item: L4 -> L1 (3 fws),
    # L3 -> L1 (2 fws, stays even if the L4 policy goes), L4 -> L2 (2 fws)
    assert sorted(f.title.split(":")[1].split("(")[0].strip() for f in chain) == sorted([
        "L4 p_it any → L1 p_l1 any", "L3 p_l3 any → L1 p_l1 any", "L4 p_it any → L2 p_l2 any"])
    f = next(f for f in chain if "across 3 firewalls" in f.title)
    assert f.severity == "high"                       # L4 -> L1, not seen in capture
    assert next(x for x in chain if "L2 p_l2" in x.title).severity == "medium"
    assert "FW1 #100" in f.detail["allowed_by"] and "FW3 #300" in f.detail["allowed_by"]
    assert [c["policy_id"] for c in f.detail["chain"]] == ["100", "200", "300"]
    assert f.detail["access_path_tag"].startswith("p:") and f.detail["chain_review"] is True
    assert f.detail["path"]["src"]["level"] == 4 and f.detail["path"]["dst"]["level"] == 1
    # ALL service also overlaps management ports -> the mgmt chain twin fires too
    mg = _findings(db, sid, "chain_mgmt_wrong_zone")
    assert any("across 3 firewalls" in m.title for m in mg)
    m = next(m for m in mg if "across 3 firewalls" in m.title)
    assert m.severity == "medium" and "SSH" in m.title and "RDP" in m.title
    n_chain, n_mgmt = len(chain), len(mg)
    # idempotent: a second run re-detects, no duplicates
    ae.run_periodic_reviews(db, site_id=sid)
    assert len(_findings(db, sid, "chain_it_ot_bypass")) == n_chain
    assert len(_findings(db, sid, "chain_mgmt_wrong_zone")) == n_mgmt


def test_chain_findings_auto_resolve_when_the_chain_is_cleared(db):
    sid, fw1, fw2 = _chain_site(db)
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _findings(db, sid, "chain_it_ot_bypass")
    # the reviewer accepts the path: finding resolves instead of re-raising
    from app.models import AccessPathTag
    db.add(AccessPathTag(site_id=sid, tag_key=f.detail["access_path_tag"], kind="path",
                         classification="exception", note="vendor maintenance window"))
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert _findings(db, sid, "chain_it_ot_bypass") == []
    assert db.query(Finding).filter(Finding.id == f.id).one().status != "open"


def test_unverified_direction_rows_are_not_raised(db):
    """D-11 x D-05: with FW2's interfaces unlabelled the chain's direction
    rests on no evidence; no chain finding is raised from such rows."""
    sid, fw1, fw2 = _chain_site(db, levels2={})
    fw2.purdue_level_ingress, fw2.purdue_level_egress = 3.5, 1
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert _findings(db, sid, "chain_it_ot_bypass") == []
    assert _findings(db, sid, "chain_mgmt_wrong_zone") == []


def test_single_firewall_rows_are_left_to_the_rule_twin(db):
    sid = _site(db, "Single")
    cfg = _two_leg_cfg("p_l1", "p_it", "10.1.0.1", "10.4.0.1",
                       _policy(10, "it-l1", "p_it", "p_l1", "ALL"))
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_l1": 1})
    ae.run_periodic_reviews(db, site_id=sid)
    assert _findings(db, sid, "chain_it_ot_bypass") == []
    assert len(_findings(db, sid, "rule_it_ot_bypass")) >= 1


def test_mgmt_ports_parsing():
    assert cf._ports({"service": ["tcp/22", "udp/161"]}) == {22, 161}
    assert cf._ports({"service": ["tcp/1000-2000"]}) == set()
    assert cf._ports({"service": ["tcp/440-450,3389"]}) == {443, 3389}
    assert cf._ports({"service": ["any"]}) == set(cf._MGMT_PORTS)
    assert cf._ports({"service": ["icmp"]}) == set()


def test_upward_skip_through_every_boundary_is_flagged_and_raised(db):
    """G-02: L1 -> L3 through two firewalls (each crossing adjacent levels)
    is an upward skip, mirroring the downward bypass."""
    sid = _site(db, "Upward plant")
    cfg1 = _two_leg_cfg("p_l1", "p_l2", "10.1.0.1", "10.2.0.1",
                        _policy(10, "plc-up", "p_l1", "p_l2", "MODBUS", "plc", "it_host"))
    cfg2 = _two_leg_cfg("p_l2", "p_l3", "10.2.0.2", "10.3.0.1",
                        _policy(20, "plc-up2", "p_l2", "p_l3", "MODBUS", "plc", "it_host"))
    f1 = _ingest(db, cfg1, "FW-A", sid, {"p_l2": 2, "p_l1": 1})
    f2 = _ingest(db, cfg2, "FW-B", sid, {"p_l3": 3, "p_l2": 2})
    set_upstream_firewall(db, f1.id, f2.id, site_id=sid)
    db.commit()
    from app.parsers.access_paths import enumerate_access_paths
    rows = [p for p in enumerate_access_paths(db, sid)["paths"]
            if p["direction"] == "up" and p["src"]["level"] == 1 and p["dst"]["level"] == 3]
    assert rows and all("ot_upward_skip" in p["flags"] for p in rows)
    # adjacent uphill rows are not skips
    adj = [p for p in enumerate_access_paths(db, sid)["paths"]
           if p["direction"] == "up" and p["src"]["level"] == 1 and p["dst"]["level"] == 2]
    assert adj and not any("ot_upward_skip" in p["flags"] for p in adj)
    ae.run_periodic_reviews(db, site_id=sid)
    up = _findings(db, sid, "chain_ot_upward_skip")
    assert len(up) == 1 and up[0].severity == "medium" and "across 2 firewalls" in up[0].title


def test_upward_skip_needs_an_ot_source_and_one_finding_per_chain(db):
    """G-02 follow-up: a DMZ host going straight to the internet is not an
    OT upward skip; an OT host whose one policy chain reaches L3 and L4
    (destination any) gets ONE finding, on the furthest row."""
    sid = _site(db, "Egress plant")
    cfg1 = _two_leg_cfg("p_l1", "p_l3", "10.1.0.1", "10.3.0.1",
                        _policy(10, "plc-out", "p_l1", "p_l3", "HTTPS", "plc", "all"))
    cfg2 = _two_leg_cfg("p_l3", "p_it", "10.3.0.2", "10.4.0.1",
                        _policy(20, "plc-out2", "p_l3", "p_it", "HTTPS", "plc", "all")
                        + _policy(21, "site-out", "p_l3", "p_it", "HTTPS", "all", "all"))
    f1 = _ingest(db, cfg1, "FW-A", sid, {"p_l3": 3, "p_l1": 1})
    f2 = _ingest(db, cfg2, "FW-B", sid, {"p_it": 4, "p_l3": 3})
    set_upstream_firewall(db, f1.id, f2.id, site_id=sid)
    db.commit()
    from app.parsers.access_paths import enumerate_access_paths
    paths = enumerate_access_paths(db, sid)["paths"]
    site_out = [p for p in paths if p["direction"] == "up" and p["src"]["level"] == 3]
    assert site_out and not any("ot_upward_skip" in p["flags"] for p in site_out)
    ae.run_periodic_reviews(db, site_id=sid)
    up = _findings(db, sid, "chain_ot_upward_skip")
    assert len(up) == 1 and up[0].detail["path"]["dst"]["level"] == 4
    assert "also let it reach L3" in up[0].detail["description"]


def test_chain_mgmt_from_a_declared_management_zone_is_not_raised(db):
    """Declared management networks: a chain whose source zone is declared a
    management zone on the first firewall (or whose source is inside a
    management network) is the sanctioned management path."""
    from app.parsers import mgmt_networks as mgn
    sid, fw1, fw2 = _chain_site(db)
    ae.run_periodic_reviews(db, site_id=sid)
    assert _findings(db, sid, "chain_mgmt_wrong_zone")
    with analysis_site(db, sid):
        row, _ = mgn.declare(db, sid, kind="name", name="p_it", firewall_id=fw1.id)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid, only=mgn.MGMT_REVIEWS)
    assert _findings(db, sid, "chain_mgmt_wrong_zone") == []
    # the bypass itself is still a bypass (management declarations do not touch it)
    assert _findings(db, sid, "chain_it_ot_bypass")
