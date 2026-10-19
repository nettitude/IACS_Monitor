"""MP-04: a declared paired (series) group is validated and consulted.

* ``declare_paired`` refuses members already placed on different level pairs
  (the inner member would silently drop off the path).
* ``paired_group_warnings`` (reachability / access paths / API) names
  groups whose members sit on different level pairs, are not placed, or
  have no confirmed link between them.
* ``cross_fw_asymmetric_permit`` compares paired members even without a
  confirmed link - over the transit interfaces when the members share an IP
  network, otherwise over their whole rulesets.
"""
import pytest

from app.models import Finding, FirewallInterface
from app.parsers import firewall_groups as fg
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.cross_fw_findings import run_cross_fw_checks
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.site_scope import analysis_site
from tests.test_access_paths import _ingest, _policy, _site, _two_leg_cfg, db  # noqa: F401
from tests.test_access_paths_overlay import _host

IT, OPS = "10.4.0.10", "10.3.0.10"


def _pair_site(db, in_levels, transit_in="172.16.0.2", name="Pair plant"):
    """FW-OUT (10.4.0.1 / transit 172.16.0.1) then FW-IN (transit / 10.3.0.1).
    FW-OUT permits it_host -> ot_host MODBUS and a TEMP any; FW-IN permits
    only the MODBUS flow."""
    sid = _site(db, name)
    fo = _ingest(db, _two_leg_cfg("p_tr", "p_it", "172.16.0.1", "10.4.0.1",
                                  _policy(10, "it-l3", "p_it", "p_tr", "MODBUS", "it_host", "ot_host")
                                  + _policy(11, "TEMP-any", "p_it", "p_tr", "ALL", "it_host", "all")),
                 "FW-OUT", sid, {"p_it": 4, "p_tr": 3})
    fi = _ingest(db, _two_leg_cfg("p_l3", "p_tr", "10.3.0.1", transit_in,
                                  _policy(10, "it-l3", "p_tr", "p_l3", "MODBUS", "it_host", "ot_host")),
                 "FW-IN", sid, in_levels)
    _host(db, sid, IT, 4)
    _host(db, sid, OPS, 3)
    db.commit()
    return sid, fo, fi


def _open(db, sid, check):
    return db.query(Finding).filter(Finding.site_id == sid, Finding.check_name == check,
                                    Finding.status == "open").all()


# -------------------------------------------------------------- declare --
def test_declare_paired_refuses_members_on_different_level_pairs(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 3.5, "p_l3": 3})     # transit mislabelled "DMZ"
    with analysis_site(db, sid):
        with pytest.raises(fg.GroupError) as exc:
            fg.declare_paired(db, sid, [fo.id, fi.id])
    assert "FW-OUT L3↔L4, FW-IN L3↔L3.5" in str(exc.value)
    assert "far side" in str(exc.value)
    assert fo.paired_group_id is None and fi.paired_group_id is None


def test_declare_paired_accepts_matching_or_not_yet_placed_members(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3})
    with analysis_site(db, sid):
        g = fg.declare_paired(db, sid, [fo.id, fi.id])
    assert g.kind == "paired"
    # a member with no labels yet is not judged
    sid2, fo2, fi2 = _pair_site(db, {}, name="Pair plant 2")
    with analysis_site(db, sid2):
        g2 = fg.declare_paired(db, sid2, [fo2.id, fi2.id])
    assert g2.id != g.id


# ------------------------------------------------------------- warnings --
def test_mismatched_labels_after_declaration_are_warned_everywhere(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3})
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id], name="IT/OT pair")
    db.commit()
    # the operator later relabels FW-IN's transit leg as a DMZ
    tr = db.query(FirewallInterface).filter_by(firewall_id=fi.id, name="p_tr").one()
    tr.purdue_level = 3.5
    db.commit()
    with analysis_site(db, sid):
        reach = compute_reachability(db)
        path = compute_path(db, IT, OPS, dst_port=22, protocol="tcp")
        ap = enumerate_access_paths(db, sid)
    kinds = {w["kind"] for w in reach["paired_group_warnings"]}
    assert "level_mismatch" in kinds and "unlinked" in kinds
    [mm] = [w for w in reach["paired_group_warnings"] if w["kind"] == "level_mismatch"]
    assert mm["group"] == "IT/OT pair" and mm["members"] == ["FW-OUT", "FW-IN"]
    assert "FW-OUT L3↔L4, FW-IN L3↔L3.5" in mm["detail"]
    assert path["paired_group_warnings"] == reach["paired_group_warnings"]
    assert ap["paired_group_warnings"] == reach["paired_group_warnings"]


def test_linked_and_matching_pair_has_no_warning(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3})
    a = db.query(FirewallInterface).filter_by(firewall_id=fo.id, name="p_tr").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=fi.id, name="p_tr").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id])
    db.commit()
    with analysis_site(db, sid):
        reach = compute_reachability(db)
    assert reach["paired_group_warnings"] == []
    # unplaced member: labels removed from FW-IN
    for i in db.query(FirewallInterface).filter_by(firewall_id=fi.id):
        i.purdue_level = None
    db.commit()
    with analysis_site(db, sid):
        reach = compute_reachability(db)
    assert [w["kind"] for w in reach["paired_group_warnings"]] == ["unplaced_member"]
    assert "FW-IN carries fewer than two interface levels" in reach["paired_group_warnings"][0]["detail"]


# ------------------------------------------------------------- cross-fw --
def test_asymmetric_permit_is_raised_for_an_unlinked_pair_over_the_shared_transit(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3})
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id])
        db.commit()
        out = run_cross_fw_checks(db)
    db.commit()
    assert out["paired_unlinked"] == 1 and out["links_analysed"] == 1
    [f] = _open(db, sid, "cross_fw_asymmetric_permit")
    assert "FW-OUT" in f.title and "FW-IN" in f.title and f.detail["rule_a_policy"] == "11"
    assert f.detail["iface_a"] == "p_tr" and f.detail["iface_b"] == "p_tr"


def test_asymmetric_permit_is_raised_for_an_unlinked_pair_without_a_shared_network(db):
    # the transit networks do not overlap (different /30s): whole rulesets
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3}, transit_in="172.16.9.2")
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id])
        db.commit()
        out = run_cross_fw_checks(db)
    db.commit()
    assert out["paired_unlinked"] == 1
    [f] = _open(db, sid, "cross_fw_asymmetric_permit")
    assert f.detail["rule_a_policy"] == "11"
    assert f.detail["iface_a"] == "FW-OUT (paired group, link not confirmed)"


def test_confirmed_link_is_not_compared_twice(db):
    sid, fo, fi = _pair_site(db, {"p_tr": 4, "p_l3": 3})
    a = db.query(FirewallInterface).filter_by(firewall_id=fo.id, name="p_tr").one()
    b = db.query(FirewallInterface).filter_by(firewall_id=fi.id, name="p_tr").one()
    a.connects_to_interface_id, b.connects_to_interface_id = b.id, a.id
    with analysis_site(db, sid):
        fg.declare_paired(db, sid, [fo.id, fi.id])
        db.commit()
        out = run_cross_fw_checks(db)
    db.commit()
    assert out["paired_unlinked"] == 0 and out["links_analysed"] == 1
    assert len(_open(db, sid, "cross_fw_asymmetric_permit")) == 1
