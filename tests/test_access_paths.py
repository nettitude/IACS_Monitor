"""
Regression tests for the PHASE 1 access-path enumeration engine
(app/parsers/access_paths.py) and its GET /access-paths endpoint.

Config-only: every path is derived from firewall access rules through the
existing reachability engine (no PCAP).  Fixture pattern mirrors
tests/test_fortios_group1.py (in-memory sqlite + ingest_fortigate_config),
with configs wrapped in ingest_site() so each firewall lands in a chosen site
and interface Purdue levels set after ingest.
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Firewall, FirewallInterface, Site
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.topology_manager import set_upstream_firewall
from app.sites import ingest_site


@pytest.fixture
def db():
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                      poolclass=StaticPool)
    Base.metadata.create_all(e)
    s = sessionmaker(bind=e)()
    yield s
    s.close()


def _site(db, name):
    site = Site(name=name, code=name.lower().replace(" ", "-"))
    db.add(site)
    db.flush()
    return site.id


def _ingest(db, cfg, name, sid, levels):
    """Ingest one FortiGate config into ``sid`` and set interface levels."""
    with ingest_site(db, sid):
        ingest_fortigate_config(textwrap.dedent(cfg), db, firewall_name=name)
    db.flush()
    fw = db.query(Firewall).filter(Firewall.name == name, Firewall.site_id == sid).one()
    for fi in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id):
        if fi.name in levels:
            fi.purdue_level = levels[fi.name]
    db.commit()
    return fw


# ---------------------------------------------------------------------------
# Config templates
# ---------------------------------------------------------------------------

_ADDR_SVC = """
    config firewall address
        edit "it_host"
            set subnet 10.4.0.10 255.255.255.255
        next
        edit "ot_host"
            set subnet 10.2.0.20 255.255.255.255
        next
        edit "plc"
            set subnet 10.1.0.30 255.255.255.255
        next
    end
    config firewall service custom
        edit "MODBUS"
            set tcp-portrange 502
        next
        edit "SSHX"
            set tcp-portrange 22
        next
        edit "APPX"
            set tcp-portrange 9999
        next
    end
"""


def _two_leg_cfg(lo_if, hi_if, lo_ip, hi_ip, policies):
    return _ADDR_SVC + f"""
    config system interface
        edit "{hi_if}"
            set vdom "root"
            set ip {hi_ip} 255.255.255.0
        next
        edit "{lo_if}"
            set vdom "root"
            set ip {lo_ip} 255.255.255.0
        next
    end
    config firewall policy
    {policies}
    end
    """


def _policy(pid, name, srcintf, dstintf, service, src="all", dst="all"):
    return f"""
        edit {pid}
            set name "{name}"
            set srcintf "{srcintf}"
            set dstintf "{dstintf}"
            set srcaddr "{src}"
            set dstaddr "{dst}"
            set action accept
            set schedule "always"
            set service "{service}"
        next
    """


def _flags_of(paths):
    return {f for p in paths for f in p["flags"]}


# ============================================================ downhill bypass
def test_it_ot_bypass_down(db):
    sid = _site(db, "A")
    cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                       _policy(10, "it-to-ot", "p_it", "p_ot", "ALL"))
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_ot": 2})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    downs = [p for p in out["paths"] if p["direction"] == "down"
             and p["src"]["level"] == 4 and p["dst"]["level"] == 2]
    assert downs, "expected an L4->L2 downhill row"
    row = downs[0]
    assert "it_ot_bypass" in row["flags"]
    # phase 2 overlay: no sessions / rule hits were ever loaded -> no_capture
    assert row["traffic"]["status"] == "no_capture"
    assert row["chain"] and row["chain"][0]["policy_id"] == "10"
    assert row["initiation"]["initiates"] == "higher_to_lower"


# =========================================================== OT egress upward
def test_ot_egress_external_up(db):
    sid = _site(db, "A")
    cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                       _policy(20, "ot-to-it", "p_ot", "p_it", "APPX",
                               src="ot_host", dst="it_host"))
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_ot": 2})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    ups = [p for p in out["paths"] if p["direction"] == "up"
           and p["src"]["level"] == 2 and p["dst"]["level"] == 4]
    assert ups, "expected an L2->L4 uphill row"
    assert "ot_egress_external" in ups[0]["flags"]
    assert ups[0]["initiation"]["initiates"] == "lower_to_higher"


# ============================================================ upward tier-skip
def test_ot_upward_skip(db):
    sid = _site(db, "A")
    # L1 <-> L3 firewall: an uphill crossing that skips L2 (and the DMZ).
    cfg = _two_leg_cfg("p_l1", "p_l3", "10.1.0.1", "10.3.0.1",
                       _policy(30, "l1-to-l3", "p_l1", "p_l3", "APPX",
                               src="plc", dst="it_host"))
    _ingest(db, cfg, "FW", sid, {"p_l3": 3, "p_l1": 1})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    ups = [p for p in out["paths"] if p["direction"] == "up"
           and p["src"]["level"] == 1 and p["dst"]["level"] == 3]
    assert ups, "expected an L1->L3 uphill row"
    assert "ot_upward_skip" in ups[0]["flags"]
    # L3 is not IT (>=4): this is not an external egress.
    assert "ot_egress_external" not in ups[0]["flags"]


# =================================================================== permit any
def test_permit_any(db):
    sid = _site(db, "A")
    # Adjacent L3<->L4 permit-any-any-any: permit_any fires, bypass does not.
    cfg = _two_leg_cfg("p_l3", "p_l4", "10.3.0.1", "10.4.0.1",
                       _policy(40, "any-any", "p_l4", "p_l3", "ALL"))
    _ingest(db, cfg, "FW", sid, {"p_l4": 4, "p_l3": 3})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    row = next(p for p in out["paths"]
               if p["src"]["level"] == 4 and p["dst"]["level"] == 3)
    assert "permit_any" in row["flags"]
    assert "it_ot_bypass" not in row["flags"]


# ============================================================ insecure protocol
def test_mgmt_protocol_ssh_across_zones(db):
    sid = _site(db, "A")
    cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                       _policy(50, "ssh-it-ot", "p_it", "p_ot", "SSHX",
                               src="it_host", dst="ot_host"))
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_ot": 2})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    row = next(p for p in out["paths"]
               if p["src"]["level"] == 4 and p["dst"]["level"] == 2)
    # SSH is a management protocol, not cleartext (owner 2026-10-12: separate)
    assert "mgmt_protocol" in row["flags"] and "cleartext_protocol" not in row["flags"]
    assert "insecure_protocol" not in row["flags"]
    assert row["service"] == ["tcp/22"]
    # Specific host + specific service: not a permit_any row.
    assert "permit_any" not in row["flags"]


# ================================================= industrial proto out of zone
def test_industrial_proto_out_of_zone(db):
    sid = _site(db, "A")
    cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                       _policy(60, "modbus-it-ot", "p_it", "p_ot", "MODBUS",
                               src="it_host", dst="ot_host"))
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_ot": 2})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    row = next(p for p in out["paths"]
               if p["src"]["level"] == 4 and p["dst"]["level"] == 2)
    assert "industrial_proto_out_of_zone" in row["flags"]
    assert row["service"] == ["tcp/502"]


# ============================================= legitimate single tier not flagged
def test_legitimate_l2_l1_modbus_not_flagged(db):
    sid = _site(db, "A")
    cfg = _two_leg_cfg("p_l1", "p_l2", "10.1.0.1", "10.2.0.1",
                       _policy(70, "modbus-l2-l1", "p_l2", "p_l1", "MODBUS",
                               src="ot_host", dst="plc"))
    _ingest(db, cfg, "FW", sid, {"p_l2": 2, "p_l1": 1})
    out = enumerate_access_paths(db, sid, boundary_only=True)
    row = next(p for p in out["paths"]
               if p["src"]["level"] == 2 and p["dst"]["level"] == 1)
    assert row["flags"] == [], f"legit L2->L1 Modbus must carry no flags, got {row['flags']}"


# ============================================================= direction filter
def _three_leg(db, sid):
    cfg = _ADDR_SVC + """
    config system interface
        edit "p_it"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "p_l2"
            set vdom "root"
            set ip 10.2.0.1 255.255.255.0
        next
        edit "p_l1"
            set vdom "root"
            set ip 10.1.0.1 255.255.255.0
        next
    end
    config firewall policy
    """ + _policy(1, "it-l2", "p_it", "p_l2", "APPX") \
        + _policy(2, "it-l1", "p_it", "p_l1", "APPX") \
        + _policy(3, "l2-l1", "p_l2", "p_l1", "APPX") \
        + _policy(4, "l2-it", "p_l2", "p_it", "APPX") \
        + _policy(5, "l1-it", "p_l1", "p_it", "APPX") \
        + _policy(6, "l1-l2", "p_l1", "p_l2", "APPX") + "\n    end\n"
    _ingest(db, cfg, "FW", sid, {"p_it": 4, "p_l2": 2, "p_l1": 1})


def test_direction_filter(db):
    sid = _site(db, "A")
    _three_leg(db, sid)
    allp = enumerate_access_paths(db, sid, direction="all")["paths"]
    down = enumerate_access_paths(db, sid, direction="down")["paths"]
    up = enumerate_access_paths(db, sid, direction="up")["paths"]
    assert {p["direction"] for p in down} == {"down"}
    assert {p["direction"] for p in up} == {"up"}
    assert len(allp) == len(down) + len(up)
    assert down and up


# ============================================================== boundary_only
def test_boundary_only_toggle(db):
    sid = _site(db, "A")
    # Multi-leg firewall (L2 + L4) carrying an INTRA-zone L4<->L4 permit
    # (zone ITZ = two L4 interfaces) and nothing crossing the boundary.
    cfg = _ADDR_SVC + """
    config system interface
        edit "p_it_a"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
        next
        edit "p_it_b"
            set vdom "root"
            set ip 10.4.1.1 255.255.255.0
        next
        edit "p_ot"
            set vdom "root"
            set ip 10.2.0.1 255.255.255.0
        next
    end
    config system zone
        edit "ITZ"
            set interface "p_it_a" "p_it_b"
        next
    end
    config firewall policy
    """ + _policy(80, "intra-it", "ITZ", "ITZ", "APPX") + "\n    end\n"
    _ingest(db, cfg, "FW", sid, {"p_it_a": 4, "p_it_b": 4, "p_ot": 2})

    on = enumerate_access_paths(db, sid, boundary_only=True)["paths"]
    off = enumerate_access_paths(db, sid, boundary_only=False)["paths"]
    # No cross-level policy exists, so boundary_only=True yields nothing new.
    assert all(p["direction"] != "same" for p in on)
    same_rows = [p for p in off if p["direction"] == "same"]
    assert same_rows, "boundary_only=False must surface the intra-zone permit"
    assert same_rows[0]["src"]["level"] == 4 and same_rows[0]["dst"]["level"] == 4
    assert len(off) > len(on)


# ========================================================= multi-firewall chain
def test_multi_firewall_chain_single_row(db):
    sid = _site(db, "A")
    # FW1: L4 <-> L3.5 (DMZ).  FW2: L3.5 <-> L2.
    cfg1 = _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                        _policy(100, "it-dmz", "p_it", "p_dmz", "ALL"))
    cfg2 = _two_leg_cfg("p_ot", "p_dmz", "10.2.0.1", "10.35.0.2",
                        _policy(200, "dmz-ot", "p_dmz", "p_ot", "ALL"))
    fw1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_dmz": 3.5})
    fw2 = _ingest(db, cfg2, "FW2", sid, {"p_dmz": 3.5, "p_ot": 2})
    # Confirm the topology chain (reachability chains via levels; this records
    # the operator's upstream link too).
    set_upstream_firewall(db, fw2.id, fw1.id, site_id=sid)
    db.commit()

    out = enumerate_access_paths(db, sid, boundary_only=True)
    joined = [p for p in out["paths"]
              if p["src"]["level"] == 4 and p["dst"]["level"] == 2]
    assert joined, "expected an end-to-end L4->L2 row through the DMZ"
    row = joined[0]
    # One row, chain lists BOTH firewall hops.
    assert len(row["chain"]) == 2
    pids = {h["policy_id"] for h in row["chain"]}
    assert pids == {"100", "200"}
    names = {h["firewall_name"] for h in row["chain"]}
    assert names == {"FW1", "FW2"}
    # L4 -> L2 routed straight through both firewalls: the DMZ never terminates
    # the session (same src/dst end to end), so it IS an it_ot_bypass.  Only a
    # composed row (pivot on a DMZ host) is exempt - see the composed tests.
    assert "it_ot_bypass" in row["flags"]


# =============================================================== row truncation
def test_row_budget_truncation(db, monkeypatch):
    sid = _site(db, "A")
    _three_leg(db, sid)  # produces several cross-boundary rows
    full = enumerate_access_paths(db, sid)
    assert full["counts"]["total"] > 1 and not full["truncated"]
    monkeypatch.setenv("IACS_MAX_ACCESS_PATH_ROWS", "1")
    capped = enumerate_access_paths(db, sid)
    assert capped["truncated"] is True
    assert len(capped["paths"]) == 1


# ============================================================== site isolation
def test_two_sites_isolated(db):
    sid_a = _site(db, "Plant A")
    sid_b = _site(db, "Plant B")
    # Identical topology/policies; only the firewall name differs per site so
    # isolation can be asserted by name.
    cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                       _policy(10, "it-to-ot", "p_it", "p_ot", "ALL"))
    _ingest(db, cfg, "FW-A", sid_a, {"p_it": 4, "p_ot": 2})
    _ingest(db, cfg, "FW-B", sid_b, {"p_it": 4, "p_ot": 2})

    out_a = enumerate_access_paths(db, sid_a, boundary_only=True)
    out_b = enumerate_access_paths(db, sid_b, boundary_only=True)
    assert out_a["paths"] and out_b["paths"]
    names_a = {h["firewall_name"] for p in out_a["paths"] for h in p["chain"]}
    names_b = {h["firewall_name"] for p in out_b["paths"] for h in p["chain"]}
    assert names_a == {"FW-A"}, f"site A rows leaked another site: {names_a}"
    assert names_b == {"FW-B"}, f"site B rows leaked another site: {names_b}"
    # Each site enumerated independently: same row count, no doubling.
    assert out_a["counts"]["total"] == out_b["counts"]["total"]


# ================================================= composed conduit (phase gap)
def test_composed_never_through_any_scope(db):
    """Both legs use all/all scopes: joining them would combine everything,
    so no composed conduit row may be emitted (phase 2 joins only through a
    specific host)."""
    sid = _site(db, "A")
    cfg1 = _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                        _policy(100, "it-dmz", "p_it", "p_dmz", "ALL"))
    cfg2 = _two_leg_cfg("p_ot", "p_dmz", "10.2.0.1", "10.35.0.2",
                        _policy(200, "dmz-ot", "p_dmz", "p_ot", "ALL"))
    _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_dmz": 3.5})
    _ingest(db, cfg2, "FW2", sid, {"p_dmz": 3.5, "p_ot": 2})
    out = enumerate_access_paths(db, sid)
    assert all(p["direction"] != "composed" for p in out["paths"])


# ================================================================= endpoint ==
def test_access_paths_endpoint(tmp_path, monkeypatch):
    import app.main as main_mod
    from fastapi.testclient import TestClient
    from app.db import Base as DBase, get_db, make_engine

    engine = make_engine(f"sqlite:///{tmp_path / 'ap.db'}")
    DBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    try:
        setup = Session()
        sid = _site(setup, "Plant A")
        cfg = _two_leg_cfg("p_ot", "p_it", "10.2.0.1", "10.4.0.1",
                           _policy(10, "it-to-ot", "p_it", "p_ot", "ALL"))
        _ingest(setup, cfg, "FW", sid, {"p_it": 4, "p_ot": 2})
        setup.close()

        client = TestClient(main_mod.app)
        # One site exists -> site derived automatically.
        r = client.get("/access-paths")
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) >= {"paths", "truncated", "counts", "site_id"}
        assert body["counts"]["total"] == len(body["paths"])
        assert any("it_ot_bypass" in p["flags"] for p in body["paths"])

        # flagged_only returns only flagged rows.
        r2 = client.get("/access-paths", params={"flagged_only": "true"})
        assert r2.status_code == 200
        assert all(p["flags"] for p in r2.json()["paths"])

        # bad direction -> 422.
        r3 = client.get("/access-paths", params={"direction": "sideways"})
        assert r3.status_code == 422
    finally:
        main_mod.app.dependency_overrides.pop(get_db, None)
        engine.dispose()


# ======================================== PLANT1 attribution regression (coordinator)
# One FortiGate, specific permits before a final IT Zone -> OT Zone DENY ALL.
# Regression for: (1) the deny #7 being attributed as the permitting hop of
# L4->L2 (the engine sets a "partial" ep's matching_rule to the TERMINAL rule);
# (2) rows merged per level-pair cell with policy_name None.
PLANT1_CFG = 'config system interface\n    edit "port1"\n        set vdom "root"\n        set ip 10.10.0.1 255.255.0.0\n    next\n    edit "port2"\n        set vdom "root"\n        set ip 10.20.0.1 255.255.0.0\n    next\n    edit "port3"\n        set vdom "root"\n        set ip 10.30.0.1 255.255.0.0\n    next\n    edit "port4"\n        set vdom "root"\n        set ip 10.40.0.1 255.255.0.0\n    next\n    edit "port5"\n        set vdom "root"\n        set ip 10.50.0.1 255.255.0.0\n    next\n    edit "port6"\n        set vdom "root"\n        set ip 10.60.0.1 255.255.0.0\n    next\nend\nconfig system zone\n    edit "IT Zone"\n        set interface "port1"\n    next\n    edit "OT Zone"\n        set interface "port2" "port3"\n    next\nend\nconfig firewall address\n    edit "historian"\n        set subnet 10.10.5.10 255.255.255.255\n    next\n    edit "dmz-relay"\n        set subnet 10.40.0.10 255.255.255.255\n    next\n    edit "plc"\n        set subnet 10.30.0.100 255.255.255.255\n    next\nend\nconfig firewall vip\n    edit "VIP-HMI"\n        set extip 10.10.0.200\n        set mappedip "10.30.0.50"\n        set extintf "port1"\n        set portforward enable\n        set extport 443\n        set mappedport 8443\n    next\nend\nconfig firewall service custom\n    edit "MODBUS"\n        set tcp-portrange 502\n    next\nend\nconfig firewall policy\n    edit 1\n        set name "historian-to-dmz"\n        set srcintf "port1"\n        set dstintf "port4"\n        set srcaddr "historian"\n        set dstaddr "dmz-relay"\n        set action accept\n        set schedule "always"\n        set service "HTTPS"\n    next\n    edit 2\n        set name "dmz-poll-plc"\n        set srcintf "port4"\n        set dstintf "port3"\n        set srcaddr "dmz-relay"\n        set dstaddr "plc"\n        set action accept\n        set schedule "always"\n        set service "MODBUS"\n    next\n    edit 3\n        set name "broad-mgmt"\n        set srcintf "port1"\n        set dstintf "port2"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set schedule "always"\n        set service "ALL"\n    next\n    edit 4\n        set name "ssh-mgmt-narrow-SHADOWED"\n        set srcintf "port1"\n        set dstintf "port2"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set schedule "always"\n        set service "SSH"\n    next\n    edit 5\n        set name "remote-hmi-vip"\n        set srcintf "port1"\n        set dstintf "port3"\n        set srcaddr "all"\n        set dstaddr "VIP-HMI"\n        set action accept\n        set schedule "always"\n        set service "HTTPS"\n    next\n    edit 6\n        set name "DIRECT-it-to-plc-BYPASS"\n        set srcintf "port1"\n        set dstintf "port3"\n        set srcaddr "historian"\n        set dstaddr "plc"\n        set action accept\n        set schedule "always"\n        set service "MODBUS"\n    next\n    edit 8\n        set name "hmi-to-plc"\n        set srcintf "port3"\n        set dstintf "port5"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set schedule "always"\n        set service "MODBUS"\n    next\n    edit 9\n        set name "plc-to-field"\n        set srcintf "port5"\n        set dstintf "port6"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set schedule "always"\n        set service "MODBUS"\n    next\n    edit 7\n        set name "seg-deny-it-ot"\n        set srcintf "IT Zone"\n        set dstintf "OT Zone"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action deny\n        set schedule "always"\n        set service "ALL"\n    next\nend\n'

PLANT1_LEVELS = {"port1": 4, "port2": 3, "port3": 2, "port4": 3.5, "port5": 1, "port6": 0}
PLANT1_NAMES = {"1": "historian-to-dmz", "2": "dmz-poll-plc", "3": "broad-mgmt",
                "4": "ssh-mgmt-narrow-SHADOWED", "5": "remote-hmi-vip",
                "6": "DIRECT-it-to-plc-BYPASS", "7": "seg-deny-it-ot",
                "8": "hmi-to-plc", "9": "plc-to-field"}


@pytest.fixture
def plant1(db):
    sid = _site(db, "Plant 1")
    _ingest(db, PLANT1_CFG, "PLANT1-FGT", sid, PLANT1_LEVELS)
    return enumerate_access_paths(db, sid)["paths"]


def _rows(paths, s, d):
    """Single-chain rows of a level pair (composed conduits excluded)."""
    return [p for p in paths if p["src"]["level"] == s and p["dst"]["level"] == d
            and p["direction"] != "composed"]


def test_plant1_deny_never_attributed(plant1):
    for p in plant1:
        for hop in p["chain"]:
            assert hop["action"] in ("permit", "accept"), p
            assert hop["policy_id"] != "7", f"deny #7 attributed as permitting hop: {p}"


def test_plant1_l4_l2_one_row_per_permitting_policy(plant1):
    rows = _rows(plant1, 4, 2)
    by_pid = {r["chain"][0]["policy_id"]: r for r in rows}
    assert len(rows) == 2 and set(by_pid) == {"5", "6"}
    vip, bypass = by_pid["5"], by_pid["6"]
    assert vip["service"] == ["tcp/8443"]
    assert bypass["service"] == ["tcp/502"]
    assert "it_ot_bypass" in bypass["flags"]
    assert "industrial_proto_out_of_zone" in bypass["flags"]
    # #6 is host-to-host Modbus: permit_any must not leak in from #5.
    assert "permit_any" not in bypass["flags"]
    assert "permit_any" in vip["flags"]          # #5 has srcaddr all
    assert "industrial_proto_out_of_zone" not in vip["flags"]


def test_plant1_policy_names_from_set_name(plant1):
    for p in plant1:
        for hop in p["chain"]:
            assert hop["policy_name"] == PLANT1_NAMES[hop["policy_id"]], hop
            assert hop["firewall_name"] == "PLANT1-FGT"


def test_plant1_single_policy_pairs_one_row(plant1):
    for (s, d), pid in {(4, 3.5): "1", (3.5, 2): "2", (2, 1): "8", (1, 0): "9",
                        (4, 3): "3"}.items():
        rows = _rows(plant1, s, d)
        assert len(rows) == 1, (s, d, rows)
        assert [h["policy_id"] for h in rows[0]["chain"]] == [pid]


def test_plant1_shadowed_policy_has_no_row(plant1):
    # #4 (SSH) sits behind #3 (any/any/ALL) on the same interfaces: it can
    # never fire, so no row may be attributed to it.
    assert all(h["policy_id"] != "4" for p in plant1 for h in p["chain"])


def test_multi_firewall_chain_partial_hop_names_real_permit(db):
    """Per-hop attribution on a chain whose second hop is specific permits
    followed by an explicit deny: the chain lists the permit, never the deny."""
    sid = _site(db, "A")
    cfg1 = _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1",
                        _policy(100, "it-dmz", "p_it", "p_dmz", "ALL"))
    deny = """
        edit 299
            set name "dmz-ot-deny"
            set srcintf "p_dmz"
            set dstintf "p_ot"
            set srcaddr "all"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
    """
    cfg2 = _two_leg_cfg("p_ot", "p_dmz", "10.2.0.1", "10.35.0.2",
                        _policy(200, "dmz-ot-modbus", "p_dmz", "p_ot", "MODBUS",
                                dst="ot_host") + deny)
    _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_dmz": 3.5})
    _ingest(db, cfg2, "FW2", sid, {"p_dmz": 3.5, "p_ot": 2})
    rows = _rows(enumerate_access_paths(db, sid)["paths"], 4, 2)
    assert len(rows) == 1
    chain = rows[0]["chain"]
    assert [(h["firewall_name"], h["policy_id"], h["policy_name"]) for h in chain] == [
        ("FW1", "100", "it-dmz"), ("FW2", "200", "dmz-ot-modbus")]
    assert rows[0]["service"] == ["tcp/502"]


# ---- chain walk must prune, not take the cartesian product ------------------

def test_walk_stages_prunes_dead_branches(monkeypatch):
    """10 stages x 15 policies is 15**10 raw combinations; only branches whose
    scopes still intersect may be visited (field tabletop: 12-firewall chain
    never finished before this)."""
    import itertools
    import time
    from app.parsers import access_paths as ap

    root = tuple(ap.rm.ANY for _ in range(4))

    def fake_intersect(a, b):
        if a == root:
            return b
        r = a & b
        return r or None

    monkeypatch.setattr(ap, "_intersect_service", fake_intersect)
    # stage i, policy j carries host set {j}: only the 15 "diagonal" chains survive
    stages = [[{"_piece": frozenset({j}), "id": (i, j)} for j in range(15)] for i in range(10)]
    t = time.time()
    out = list(ap._walk_stages(stages))
    assert time.time() - t < 2.0
    assert len(out) == 15
    for combo, piece in out:
        assert len({p["id"][1] for p in combo}) == 1 and len(combo) == 10

    # same order as the filtered cartesian product on a small overlapping case
    small = [[{"_piece": frozenset(s), "id": (i, k)} for k, s in enumerate(({1, 2}, {2, 3}, {3}))] for i in range(3)]
    expect = []
    for c in itertools.product(*small):
        p = c[0]["_piece"]
        for x in c[1:]:
            p = p & x["_piece"]
            if not p:
                break
        if p:
            expect.append([x["id"] for x in c])
    got = [[x["id"] for x in c] for c, _ in ap._walk_stages(small)]
    assert got == expect and got


def test_chain_row_shows_the_intersected_scope(db):
    """G-04: a broad first policy (IT /16) followed by a narrow one (one host)
    yields a row for that host only, not flagged permit_any, with the broad
    text kept as policy_scope."""
    sid = _site(db, "Scope plant")
    cfg1 = _two_leg_cfg("p_tr", "p_it", "172.16.0.1", "10.4.0.1",
                        _policy(10, "IT-ANY-TEMP", "p_it", "p_tr", "ALL", "all", "all"))
    cfg2 = _two_leg_cfg("p_l1", "p_tr", "10.1.0.1", "172.16.0.2",
                        _policy(20, "it-host-plc", "p_tr", "p_l1", "MODBUS", "it_host", "plc"))
    f1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_tr": 3})
    f2 = _ingest(db, cfg2, "FW2", sid, {"p_tr": 3, "p_l1": 1})
    set_upstream_firewall(db, f2.id, f1.id, site_id=sid)
    db.commit()
    rows = [p for p in enumerate_access_paths(db, sid)["paths"]
            if p["src"]["level"] == 4 and p["dst"]["level"] == 1]
    assert rows
    r = rows[0]
    assert r["src"]["scope"] == "10.4.0.10/32" and r["dst"]["scope"] == "10.1.0.30/32"
    assert r["src"]["policy_scope"] == "any"
    assert "permit_any" not in r["flags"]


def test_identical_traffic_keeps_only_the_first_match_row(db):
    """G-04: an ANY policy and a specific policy on the outer firewall both
    lead into the same narrow inner policy - the same traffic twice.  Only
    the earlier outer policy ever matches it: one row, the other combination
    recorded as shadowed."""
    sid = _site(db, "First-match plant")
    cfg1 = _two_leg_cfg("p_tr", "p_it", "172.16.0.1", "10.4.0.1",
                        _policy(5, "it-host-plc", "p_it", "p_tr", "MODBUS", "it_host", "plc")
                        + _policy(10, "IT-ANY-TEMP", "p_it", "p_tr", "ALL", "all", "all"))
    cfg2 = _two_leg_cfg("p_l1", "p_tr", "10.1.0.1", "172.16.0.2",
                        _policy(20, "it-host-plc", "p_tr", "p_l1", "MODBUS", "it_host", "plc"))
    f1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_tr": 3})
    f2 = _ingest(db, cfg2, "FW2", sid, {"p_tr": 3, "p_l1": 1})
    set_upstream_firewall(db, f2.id, f1.id, site_id=sid)
    db.commit()
    rows = [p for p in enumerate_access_paths(db, sid)["paths"]
            if p["src"]["level"] == 4 and p["dst"]["level"] == 1]
    assert len(rows) == 1
    r = rows[0]
    assert [c["policy_id"] for c in r["chain"]] == ["5", "20"]
    assert r["shadowed_by_first_match"] == ["FW1 #10 IT-ANY-TEMP + FW2 #20 it-host-plc"]
    assert "permit_any" not in r["flags"]
