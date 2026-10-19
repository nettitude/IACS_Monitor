"""FortiOS group 1 follow-up: zone definitions (B-07) and NAT first-match
order (B-13) used by every consumer, not only reachability.

* alert_engine periodic reviews resolve zone-named policy sides through
  FirewallZoneDef (shared helper app.parsers.fortios_zones): a zone-named
  IT->OT permit raises the same findings as the interface-named one.
* topology_manager.get_topology_state resolves zones to member levels.
* cross_fw_findings matches zone-named rules against link interfaces.
* GET /nat-rules lists rows in (sequence, id) order with sequence /
  nat_exempt.
"""
import textwrap

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app.db import get_db, make_engine
from app.models import (Base, Finding, FirewallInterface, FirewallRule, FirewallZone,
                        FirewallZoneDef, NatRule)
from app.parsers import fortios_zones as fz
from app.parsers import rule_match as rm
from app.parsers.alert_engine import _rule_zone_purdue, run_periodic_reviews
from app.parsers.cross_fw_findings import _rule_touches_iface
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.topology_manager import get_topology_state


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


IFACES = """
    config system interface
        edit "port1"
            set ip 10.10.1.1 255.255.255.0
        next
        edit "port2"
            set ip 10.10.2.1 255.255.255.0
        next
        edit "port3"
            set ip 10.20.3.1 255.255.255.0
        next
        edit "port4"
            set ip 10.20.4.1 255.255.255.0
        next
    end
"""
ZONES = """
    config system zone
        edit "ITZ"
            set interface "port1" "port2"
        next
        edit "OTZ"
            set interface "port3" "port4"
        next
        edit "EMPTYZ"
        next
    end
"""
POLICY = """
    config firewall policy
        edit 10
            set name "it-to-ot"
            set srcintf {src}
            set dstintf {dst}
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "ALL"
        next
    end
"""
LEVELS = {"port1": 4, "port2": 4, "port3": 2, "port4": 2}


def ingest(db, src, dst, zones=True, name="FW-Z"):
    cfg = IFACES + (ZONES if zones else "") + POLICY.format(src=src, dst=dst)
    st = ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name,
                                 purdue_zone_from=2, purdue_zone_to=4)
    for fi in db.query(FirewallInterface).all():
        if fi.name in LEVELS:
            fi.purdue_level = LEVELS[fi.name]
    db.commit()
    return st


def findings(db):
    return {(f.check_name, f.severity) for f in db.query(Finding).all()
            if f.status != "closed"}


# ============================================================ alert_engine ==
def _periodic(db):
    stats = run_periodic_reviews(db)
    db.commit()
    return stats


def test_zone_named_it_to_ot_permit_same_findings_as_interface_named():
    out = []
    for zoned in (True, False):
        e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                          poolclass=StaticPool)
        Base.metadata.create_all(e)
        s = sessionmaker(bind=e)()
        if zoned:
            ingest(s, '"ITZ"', '"OTZ"')
            # zone defs alone (no legacy FirewallZone rows) must be enough
            s.query(FirewallZone).delete()
            s.commit()
        else:
            ingest(s, '"port1" "port2"', '"port3" "port4"', zones=False)
        _periodic(s)
        out.append(findings(s))
        s.close()
    zone_f, iface_f = out
    assert zone_f == iface_f
    # the IT->OT permit is actually reported (not an empty comparison)
    rule_checks = {c for c, _ in iface_f if c.startswith("rule_")}
    assert rule_checks, iface_f


def test_resolver_uses_zone_defs_per_vdom_and_conservative_semantics(db):
    ingest(db, '"ITZ"', '"OTZ"')
    db.query(FirewallZone).delete()
    db.commit()
    rule = db.query(FirewallRule).filter_by(policy_id="10").one()
    res = _rule_zone_purdue(db)
    assert res.resolve_checked(rule, "ITZ") == ({4}, True)
    assert res.resolve_checked(rule, "OTZ") == ({2}, True)
    # empty zone: matches nothing, fully evaluated
    assert res.resolve_checked(rule, "EMPTYZ") == (set(), True)
    # unknown membership: incomplete (never "matches nothing")
    zd = db.query(FirewallZoneDef).filter_by(name="OTZ").one()
    zd.members_resolved = False
    db.commit()
    res = _rule_zone_purdue(db)
    levels, complete = res.resolve_checked(rule, "OTZ")
    assert complete is False and levels == set()
    # a zone of another VDOM does not resolve for this rule
    zd.members_resolved = True
    zd.vdom = "other"
    db.commit()
    res = _rule_zone_purdue(db)
    assert res.resolve_checked(rule, "OTZ")[1] is False


def test_empty_zone_permit_raises_no_rule_findings(db):
    ingest(db, '"EMPTYZ"', '"OTZ"')
    _periodic(db)
    assert not {c for c, _ in findings(db) if c.startswith("rule_")}


# ======================================================== topology_manager ==
def test_topology_state_resolves_zones(db):
    ingest(db, '"ITZ"', '"OTZ"')
    st = get_topology_state(db)
    fw = st["firewalls"][0]
    zones = {z["name"]: z for z in fw["zones"]}
    assert zones["ITZ"]["purdue_levels"] == [4] and zones["ITZ"]["level_status"] == "resolved"
    assert zones["OTZ"]["purdue_levels"] == [2] and zones["OTZ"]["members"] == ["port3", "port4"]
    assert zones["EMPTYZ"]["level_status"] == "empty" and zones["EMPTYZ"]["purdue_levels"] == []
    assert len(zones["OTZ"]["member_interface_ids"]) == 2
    ifz = {i["name"]: i["zones"] for i in fw["interfaces"]}
    assert ifz["port1"] == ["ITZ"] and ifz["port4"] == ["OTZ"]
    # a member without a level -> the zone's direction is unknown
    p3 = db.query(FirewallInterface).filter_by(name="port3").one()
    p3.purdue_level = None
    db.commit()
    zones = {z["name"]: z for z in get_topology_state(db)["firewalls"][0]["zones"]}
    assert zones["OTZ"]["level_status"] == "unknown"
    # unparseable membership -> unknown
    zd = db.query(FirewallZoneDef).filter_by(name="ITZ").one()
    zd.members_resolved = False
    db.commit()
    zones = {z["name"]: z for z in get_topology_state(db)["firewalls"][0]["zones"]}
    assert zones["ITZ"]["level_status"] == "unknown"


# ======================================================= cross_fw_findings ==
def test_cross_fw_rule_touches_link_iface_through_zone(db):
    ingest(db, '"ITZ"', '"OTZ"')
    rule = db.query(FirewallRule).filter_by(policy_id="10").one()
    idx = fz.ZoneDefIndex(db)
    assert _rule_touches_iface(rule, {"port3"}, idx) is True
    assert _rule_touches_iface(rule, {"port9"}, idx) is False
    # without zone defs the zone name never matched the interface
    assert _rule_touches_iface(rule, {"port3"}) is False
    # unknown membership is conservative: may touch
    zd = db.query(FirewallZoneDef).filter_by(name="OTZ").one()
    zd.members_resolved = False
    db.commit()
    assert _rule_touches_iface(rule, {"port9"}, fz.ZoneDefIndex(db)) is True


def test_shared_helper_is_single_implementation():
    assert rm.expand_zone_tokens is fz.expand_zone_tokens
    assert rm.load_zone_defs is fz.load_zone_defs
    zmap = {"z": {"members": [], "resolved": True}, "u": {"members": ["p1"], "resolved": False}}
    assert fz.zone_lookup(zmap, "Z") == ([], True)
    assert fz.zone_lookup(zmap, "u") == ([], False)
    assert fz.zone_lookup(zmap, "port1") is None


# ================================================================ /nat-rules ==
NAT_CFG = """
config system interface
    edit "port1"
        set ip 10.3.0.1 255.255.255.0
    next
    edit "port2"
        set ip 172.16.4.1 255.255.255.0
    next
end
config firewall address
    edit "ot-net"
        set subnet 10.3.0.0 255.255.255.0
    next
    edit "ot-hist"
        set subnet 10.3.0.5 255.255.255.255
    next
end
config firewall ippool
    edit "ot-pool"
        set startip 172.16.4.100
        set endip 172.16.4.100
    next
end
config firewall central-snat-map
    edit 7
        set srcintf "port1"
        set dstintf "port2"
        set orig-addr "ot-hist"
        set dst-addr "all"
        set nat disable
    next
    edit 3
        set srcintf "port1"
        set dstintf "port2"
        set orig-addr "ot-net"
        set dst-addr "all"
        set nat enable
        set nat-ippool "ot-pool"
    next
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    eng = make_engine(f"sqlite:///{tmp_path / 'followup.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = S()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        yield c, S
    main_mod.app.dependency_overrides.pop(get_db, None)
    eng.dispose()


def test_nat_rules_listed_in_sequence_order_with_exempt_flag(api):
    client, S = api
    r = client.post("/ingest/fortigate-config", params={"firewall_name": "FW-N"},
                    files={"file": ("n.conf", NAT_CFG.encode(), "text/plain")})
    assert r.status_code == 200, r.text
    rows = [x for x in client.get("/nat-rules").json() if x["nat_kind"] == "central-snat"]
    assert [(x["name"], x["sequence"], x["nat_exempt"]) for x in rows] == [
        ("central-snat:7", 1, True), ("central-snat:3", 2, False)]
    # order follows sequence, not id: reverse the stored sequences
    s = S()
    for n in s.query(NatRule).filter(NatRule.nat_kind == "central-snat").all():
        n.sequence = 2 if n.nat_exempt else 1
    s.add(NatRule(firewall_id=n.firewall_id, nat_type="snat", nat_kind="central-snat",
                  name="central-snat:nul", sequence=None, enabled=True))
    s.commit()
    s.close()
    rows = [x for x in client.get("/nat-rules", params={"nat_type": "snat"}).json()
            if x["nat_kind"] == "central-snat"]
    assert [x["name"] for x in rows] == ["central-snat:3", "central-snat:7", "central-snat:nul"]
