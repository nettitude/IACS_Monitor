"""
Tests for app/parsers/topology_manager.py

Coverage:
  - detect_subnet_overlaps / propose_topology
  - confirm_link (happy path + error cases)
  - set_upstream_firewall (happy path + error cases)
  - run_purdue_suggestions (all three sources + priority ordering)
  - get_topology_state (shape + new fields)
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Firewall, FirewallInterface
from app.parsers.topology_manager import (
    confirm_link,
    detect_subnet_overlaps,
    get_topology_state,
    propose_topology,
    run_purdue_suggestions,
    set_upstream_firewall,
)


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _fw(db, name, vendor="fortigate", is_multi_fw=True):
    fw = Firewall(name=name, vendor=vendor, is_multi_fw=is_multi_fw, topology_confirmed=False)
    db.add(fw)
    db.flush()
    return fw


def _iface(db, fw, name, ip_cidr=None, network_cidr=None, side=None,
           purdue_level=None, is_ha=False, is_mgmt_only=False, role=None):
    iface = FirewallInterface(
        firewall_id=fw.id,
        name=name,
        ip_cidr=ip_cidr,
        network_cidr=network_cidr,
        side=side,
        purdue_level=purdue_level,
        is_ha=is_ha,
        is_mgmt_only=is_mgmt_only,
        role=role,
    )
    db.add(iface)
    db.flush()
    return iface


# ─── detect_subnet_overlaps ───────────────────────────────────────────────────

def test_detect_exact_match_high_confidence(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "dmz", network_cidr="10.10.10.0/24")
    _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 1
    assert proposals[0]["confidence"] == "high"


def test_detect_subnet_of_medium_confidence(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "transit", network_cidr="10.0.0.0/8")
    _iface(db, fw2, "wan1",   network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 1
    assert proposals[0]["confidence"] == "medium"


def test_detect_same_slash16_is_not_a_proposal(db):
    """D-07: a shared /16 is no evidence of a link (60 noise proposals on
    the multi-firewall tabletop, whose transit nets all sit in 172.16/16)."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "a", network_cidr="192.168.1.0/24")
    _iface(db, fw2, "b", network_cidr="192.168.2.0/24")
    assert detect_subnet_overlaps(db) == []


def test_detect_no_overlap_excluded(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "a", network_cidr="10.0.0.0/8")
    _iface(db, fw2, "b", network_cidr="172.16.0.0/12")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 0


def test_detect_excludes_ha_interfaces(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "ha1", network_cidr="10.10.10.0/24", is_ha=True)
    _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 0


def test_detect_excludes_mgmt_only_interfaces(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "mgmt", network_cidr="10.10.10.0/24", is_mgmt_only=True)
    _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 0


def test_detect_excludes_already_linked(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz", network_cidr="10.10.10.0/24")
    i2 = _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 0


def test_detect_sorted_high_before_medium(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    fw3 = _fw(db, "FW-C")
    _iface(db, fw1, "a", network_cidr="192.168.0.0/16")  # medium confidence with fw2
    _iface(db, fw2, "b", network_cidr="192.168.2.0/24")
    _iface(db, fw1, "c", network_cidr="10.10.10.0/24")   # high confidence with fw3
    _iface(db, fw3, "d", network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert proposals[0]["confidence"] == "high"
    assert proposals[-1]["confidence"] == "medium"


def test_detect_deduplicates_ab_vs_ba(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "a", network_cidr="10.10.10.0/24")
    _iface(db, fw2, "b", network_cidr="10.10.10.0/24")
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 1  # not 2


def test_propose_topology_is_alias(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "a", network_cidr="10.10.10.0/24")
    _iface(db, fw2, "b", network_cidr="10.10.10.0/24")
    assert detect_subnet_overlaps(db) == propose_topology(db)


# ─── confirm_link ─────────────────────────────────────────────────────────────

def test_confirm_link_sets_both_directions(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz", network_cidr="10.10.10.0/24")
    i2 = _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    a, b = confirm_link(db, i1.id, i2.id)
    assert a.connects_to_interface_id == i2.id
    assert b.connects_to_interface_id == i1.id


def test_confirm_link_removes_from_proposals(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz", network_cidr="10.10.10.0/24")
    i2 = _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    confirm_link(db, i1.id, i2.id)
    db.flush()
    proposals = detect_subnet_overlaps(db)
    assert len(proposals) == 0


def test_confirm_link_raises_on_missing_iface(db):
    fw1 = _fw(db, "FW-A")
    i1 = _iface(db, fw1, "dmz")
    with pytest.raises(ValueError, match="not found"):
        confirm_link(db, i1.id, 9999)


def test_confirm_link_raises_same_firewall(db):
    fw1 = _fw(db, "FW-A")
    i1 = _iface(db, fw1, "dmz")
    i2 = _iface(db, fw1, "internal")
    with pytest.raises(ValueError, match="same firewall"):
        confirm_link(db, i1.id, i2.id)


# ─── set_upstream_firewall ────────────────────────────────────────────────────

def test_set_upstream_writes_fields(db):
    fw1 = _fw(db, "FW-Perimeter")
    fw2 = _fw(db, "FW-Core")
    result = set_upstream_firewall(
        db, fw2.id,
        upstream_firewall_id=fw1.id,
        purdue_level_ingress=4,
        purdue_level_egress=3,
        topology_confirmed=True,
    )
    assert result.upstream_firewall_id == fw1.id
    assert result.purdue_level_ingress == 4
    assert result.purdue_level_egress == 3
    assert result.topology_confirmed is True


def test_set_upstream_null_clears_chain(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    set_upstream_firewall(db, fw2.id, upstream_firewall_id=fw1.id)
    db.flush()
    result = set_upstream_firewall(db, fw2.id, upstream_firewall_id=None)
    assert result.upstream_firewall_id is None


def test_set_upstream_raises_on_missing_fw(db):
    with pytest.raises(ValueError, match="not found"):
        set_upstream_firewall(db, 9999, upstream_firewall_id=None)


def test_set_upstream_raises_on_self_reference(db):
    fw1 = _fw(db, "FW-A")
    with pytest.raises(ValueError, match="different firewall"):
        set_upstream_firewall(db, fw1.id, upstream_firewall_id=fw1.id)


def test_set_upstream_raises_on_missing_upstream(db):
    fw1 = _fw(db, "FW-A")
    with pytest.raises(ValueError, match="not found"):
        set_upstream_firewall(db, fw1.id, upstream_firewall_id=9999)


def test_set_upstream_partial_fields_not_cleared(db):
    fw1 = _fw(db, "FW-A")
    fw1.purdue_level_ingress = 4
    fw1.purdue_level_egress = 3
    db.flush()
    # Only update topology_confirmed — ingress/egress should be untouched
    result = set_upstream_firewall(db, fw1.id, upstream_firewall_id=None, topology_confirmed=True)
    assert result.purdue_level_ingress == 4
    assert result.purdue_level_egress == 3


# ─── run_purdue_suggestions ───────────────────────────────────────────────────

def test_purdue_suggestion_fw_chain_outside(db):
    fw = _fw(db, "FW-A")
    fw.purdue_level_ingress = 4
    db.flush()
    iface = _iface(db, fw, "wan1", side="outside", ip_cidr="203.0.113.1/30")
    stats = run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level == 4
    assert iface.purdue_suggestion_source == "fw_chain"
    assert stats["by_source"]["fw_chain"] == 1


def test_purdue_suggestion_fw_chain_inside(db):
    fw = _fw(db, "FW-A")
    fw.purdue_level_egress = 3
    db.flush()
    iface = _iface(db, fw, "lan", side="inside", ip_cidr="10.0.1.1/24")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level == 3
    assert iface.purdue_suggestion_source == "fw_chain"


def test_purdue_suggestion_peer_link(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz",  side="outside", purdue_level=4)
    i2 = _iface(db, fw2, "wan1", side="inside")
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(i2)
    # MP-13: one wire, one level - the peer's own level (4)
    assert i2.suggested_purdue_level == 4
    assert i2.purdue_suggestion_source == "peer_link"
    # a declared paired (series) group: inside peer of outside-4 -> 4-1=3
    from app.models import FirewallGroup
    g = FirewallGroup(kind="paired", name="pair")
    db.add(g)
    db.flush()
    fw1.paired_group_id = fw2.paired_group_id = g.id
    db.flush()
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(i2)
    assert i2.suggested_purdue_level == 3


def test_purdue_suggestion_peer_link_reverse(db):
    """When i2 has the operator level and i1 does not."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    i1 = _iface(db, fw1, "dmz",  side="outside")
    i2 = _iface(db, fw2, "wan1", side="inside", purdue_level=3)
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(i1)
    # MP-13: the peer's own level (3); +1 only for a declared paired group
    assert i1.suggested_purdue_level == 3
    assert i1.purdue_suggestion_source == "peer_link"


def test_purdue_suggestion_role_heuristic_wan(db):
    fw = _fw(db, "FW-A")
    iface = _iface(db, fw, "wan1", role="wan")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level == 4
    assert iface.purdue_suggestion_source == "role_heuristic"


def test_purdue_suggestion_role_heuristic_lan(db):
    fw = _fw(db, "FW-A")
    iface = _iface(db, fw, "lan1", role="lan")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level == 3
    assert iface.purdue_suggestion_source == "role_heuristic"


def test_purdue_suggestion_private_ip_alone_is_not_evidence(db):
    # F-16: RFC 1918 addressing alone used to yield "L3" for every subnet;
    # without real evidence the interface now stays unsuggested.
    fw = _fw(db, "FW-A")
    iface = _iface(db, fw, "internal", ip_cidr="192.168.1.1/24", network_cidr="192.168.1.0/24")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level is None
    assert iface.purdue_suggestion_source is None


def test_purdue_suggestion_public_ip_alone_is_not_evidence(db):
    fw = _fw(db, "FW-A")
    iface = _iface(db, fw, "wan1", ip_cidr="203.0.113.1/30", network_cidr="203.0.113.0/30")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.suggested_purdue_level is None


def test_purdue_suggestion_does_not_overwrite_operator_level(db):
    fw = _fw(db, "FW-A")
    fw.purdue_level_ingress = 4
    db.flush()
    # Operator has explicitly set purdue_level=2 — engine must NOT touch it
    iface = _iface(db, fw, "wan1", side="outside", purdue_level=2)
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    assert iface.purdue_level == 2                  # operator value preserved
    assert iface.suggested_purdue_level is None     # no suggestion written


def test_purdue_suggestion_fw_chain_beats_role_heuristic(db):
    """fw_chain (source 2) should win over role_heuristic (source 3) for
    same interface, but only if fw_chain runs first."""
    fw = _fw(db, "FW-A")
    fw.purdue_level_ingress = 2   # unusual value — distinguishes from heuristic
    db.flush()
    # Role says wan→4, fw_chain says ingress=2 for outside interface
    iface = _iface(db, fw, "wan1", side="outside", role="wan")
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(iface)
    # fw_chain runs before role_heuristic so fw_chain (ingress=2) wins
    assert iface.suggested_purdue_level == 2
    assert iface.purdue_suggestion_source == "fw_chain"


def test_purdue_suggestion_summary_counts(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    fw1.purdue_level_ingress = 4
    fw1.purdue_level_egress  = 3
    db.flush()
    _iface(db, fw1, "outside", side="outside")
    _iface(db, fw1, "inside",  side="inside")
    _iface(db, fw2, "wan1",    role="wan")
    stats = run_purdue_suggestions(db)
    assert stats["interfaces_updated"] == 3
    assert stats["by_source"]["fw_chain"] == 2
    assert stats["by_source"]["role_heuristic"] == 1


def test_purdue_suggestion_peer_level_clamped_at_bounds(db):
    """Level must never go below 0 or above 4."""
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    # outside peer at level 0 — inside suggestion should be max(0-1, 0)=0
    i1 = _iface(db, fw1, "dmz",  side="outside", purdue_level=0)
    i2 = _iface(db, fw2, "wan1", side="inside")
    i1.connects_to_interface_id = i2.id
    i2.connects_to_interface_id = i1.id
    db.flush()
    run_purdue_suggestions(db)
    db.flush()
    db.refresh(i2)
    assert i2.suggested_purdue_level == 0   # clamped, not -1


# ─── get_topology_state ───────────────────────────────────────────────────────

def test_topology_state_shape_single_fw(db):
    fw = _fw(db, "FW-A", is_multi_fw=False)
    _iface(db, fw, "wan1", ip_cidr="203.0.113.1/30")
    state = get_topology_state(db)
    assert state["is_multi_fw"] is False
    assert state["firewall_count"] == 1
    assert state["pending_proposals"] == []
    fw_state = state["firewalls"][0]
    assert fw_state["id"] == fw.id
    assert fw_state["purdue_level_ingress"] is None
    assert fw_state["purdue_level_egress"] is None
    assert fw_state["upstream_firewall_id"] is None


def test_topology_state_includes_suggestion_fields(db):
    fw = _fw(db, "FW-A")
    fw.purdue_level_ingress = 4
    db.flush()
    iface = _iface(db, fw, "wan1", side="outside")
    run_purdue_suggestions(db)
    db.commit()
    state = get_topology_state(db)
    iface_state = state["firewalls"][0]["interfaces"][0]
    assert iface_state["suggested_purdue_level"] == 4
    assert iface_state["purdue_suggestion_source"] == "fw_chain"


def test_topology_state_multi_fw_has_proposals(db):
    fw1 = _fw(db, "FW-A")
    fw2 = _fw(db, "FW-B")
    _iface(db, fw1, "dmz",  network_cidr="10.10.10.0/24")
    _iface(db, fw2, "wan1", network_cidr="10.10.10.0/24")
    state = get_topology_state(db)
    assert state["is_multi_fw"] is True
    assert len(state["pending_proposals"]) == 1


def test_topology_state_purdue_levels_in_fw(db):
    fw = _fw(db, "FW-A")
    set_upstream_firewall(db, fw.id, upstream_firewall_id=None,
                          purdue_level_ingress=4, purdue_level_egress=3)
    db.flush()
    state = get_topology_state(db)
    fw_state = state["firewalls"][0]
    assert fw_state["purdue_level_ingress"] == 4
    assert fw_state["purdue_level_egress"] == 3
