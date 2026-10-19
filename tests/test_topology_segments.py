"""D-07: link proposals without the /16 heuristic; shared segments."""
import ipaddress

import pytest

from app.models import Firewall, FirewallInterface
from app.parsers import topology_manager as tm
from tests.test_access_paths import _site, db  # noqa: F401
from tests.test_access_path_tags import api  # noqa: F401


def _fw(db, name, sid):
    fw = Firewall(name=name, vendor="fortigate", site_id=sid)
    db.add(fw)
    db.flush()
    return fw


def _if(db, fw, name, cidr, host):
    i = FirewallInterface(firewall_id=fw.id, name=name, network_cidr=cidr, ip_cidr=host,
                          is_ha=False, is_mgmt_only=False)
    db.add(i)
    db.flush()
    return i


def test_shared_slash16_is_not_a_link():
    n = ipaddress.ip_network
    assert tm._overlap_confidence(n("172.16.1.0/30"), n("172.16.2.0/30")) == "none"
    assert tm._overlap_confidence(n("172.16.1.0/30"), n("172.16.1.0/30")) == "high"
    assert tm._overlap_confidence(n("10.0.0.0/8"), n("10.1.0.0/16")) == "medium"


def test_three_firewalls_on_one_network_become_a_segment_proposal(db):
    sid = _site(db, "Seg plant")
    fws = [_fw(db, f"FG-{k}", sid) for k in "ABC"]
    ifs = [_if(db, fw, "dmz", "10.40.1.0/24", f"10.40.1.{k}/24") for k, fw in enumerate(fws, 1)]
    _if(db, fws[0], "wan", "203.0.113.0/29", "203.0.113.1/29")
    _if(db, fws[1], "it", "10.10.0.0/24", "10.10.0.1/24")
    db.commit()
    state = tm.get_topology_state(db, site_id=sid)
    assert state["pending_proposals"] == []            # no pairwise tangle for the shared net
    [seg] = state["segment_proposals"]
    assert seg["network"] == "10.40.1.0/24" and seg["confidence"] == "high"
    assert [m["fw_name"] for m in seg["members"]] == ["FG-A", "FG-B", "FG-C"]
    assert "_ifaces" not in seg
    # confirm: label on all, proposal gone, members listed, cross-fw pairs 3
    out = tm.confirm_segment(db, [i.id for i in ifs], site_id=sid)
    db.commit()
    assert out["segment"] == "seg-10.40.1.0/24" and len(out["members"]) == 3
    state = tm.get_topology_state(db, site_id=sid)
    assert state["segment_proposals"] == []
    assert all(i["segment"] == "seg-10.40.1.0/24" for fw in state["firewalls"]
               for i in fw["interfaces"] if i["name"] == "dmz")


def test_two_firewalls_stay_a_pairwise_proposal(db):
    sid = _site(db, "Pair plant")
    a, b = _fw(db, "A", sid), _fw(db, "B", sid)
    _if(db, a, "x", "172.16.1.0/30", "172.16.1.1/30")
    _if(db, b, "y", "172.16.1.0/30", "172.16.1.2/30")
    db.commit()
    state = tm.get_topology_state(db, site_id=sid)
    assert len(state["pending_proposals"]) == 1 and state["segment_proposals"] == []


def test_confirm_segment_validation(db):
    sid = _site(db, "V plant")
    a, b = _fw(db, "A", sid), _fw(db, "B", sid)
    ia = _if(db, a, "x", "10.0.0.0/24", "10.0.0.1/24")
    ia2 = _if(db, a, "y", "10.0.0.0/24", "10.0.0.5/24")
    ib = _if(db, b, "z", "10.0.0.0/24", "10.0.0.2/24")
    other = _site(db, "Other")
    c = _fw(db, "C", other)
    ic = _if(db, c, "w", "10.0.0.0/24", "10.0.0.3/24")
    db.commit()
    with pytest.raises(ValueError):
        tm.confirm_segment(db, [ia.id], site_id=sid)
    with pytest.raises(ValueError):
        tm.confirm_segment(db, [ia.id, ia2.id], site_id=sid)     # one firewall
    with pytest.raises(ValueError):
        tm.confirm_segment(db, [ia.id, 999999], site_id=sid)
    from app.parsers.site_scope import CrossSiteError
    with pytest.raises(CrossSiteError):
        tm.confirm_segment(db, [ia.id, ic.id])
    # a prior point-to-point link between members is superseded
    ia.connects_to_interface_id, ib.connects_to_interface_id = ib.id, ia.id
    db.flush()
    tm.confirm_segment(db, [ia.id, ib.id], name="DMZ switch", site_id=sid)
    db.commit()
    assert ia.connects_to_interface_id is None and ib.connects_to_interface_id is None
    assert ia.segment == ib.segment == "DMZ switch"


def test_confirm_segment_endpoint(api):
    client = api
    db = client.Session()
    sid = _site(db, "API plant")
    fws = [_fw(db, f"F{k}", sid) for k in range(3)]
    ids = [_if(db, fw, "dmz", "10.40.1.0/24", f"10.40.1.{k + 1}/24").id for k, fw in enumerate(fws)]
    db.commit()
    r = client.post(f"/topology/confirm-segment?site_id={sid}", json={"iface_ids": ids})
    assert r.status_code == 200, r.text
    assert r.json()["segment"] == "seg-10.40.1.0/24" and "cross_fw_checks" in r.json()
    r = client.post(f"/topology/confirm-segment?site_id={sid}", json={"iface_ids": [ids[0]]})
    assert r.status_code == 400
    assert client.get(f"/topology/state?site_id={sid}").json()["segment_proposals"] == []
