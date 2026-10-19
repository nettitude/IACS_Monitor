"""
F-08: Purdue Level 3.5 (industrial DMZ) as a first-class level.

Covers app/purdue.py (parse / validate / format / ordering / predicates),
the NUMERIC(2,1) storage + CHECK constraints and their migration
(b9c0d1e2f3a4) over existing integer data, every level-accepting API
endpoint (3.5 accepted, 3.7 / 6 / -1 rejected with one 422 message),
reachability with a 3-leg L1/L3.5/L4 firewall and an L4-L3.5-L3 chain,
DMZ classification (VLAN names, zone names, FortiOS dmz role), edge
adjacency, and the alert-engine decisions documented in alert_engine.py.
"""
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app import purdue
from app.db import Base, configure_sqlite_engine, get_db
from app.models import (
    ApprovedHost, Baseline, Firewall, FirewallDevice, FirewallInterface, FirewallRule,
    FirewallZone, Host, NetworkSession, SwitchVlan,
)
from app.parsers.alert_engine import (
    _fmt_levels, review_cleartext_protocols, review_mgmt_access_from_wrong_zone,
    review_rule_it_ot_bypass, review_rule_mgmt_wrong_zone,
)
from app.parsers.device_classification import (
    DEVICE_TYPE_REFERENCE, classify_hosts_by_vlan, classify_vlan_name,
)
from app.parsers.reachability import compute_path, compute_reachability
from app.parsers.topology_manager import (
    classify_level_edge, firewall_level_boundaries, purdue_level_error,
    run_purdue_suggestions, set_interface_labels, set_upstream_firewall, valid_purdue_level,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BAD_LEVELS = [3.7, 6, -1]


@pytest.fixture
def db():
    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


# ============================================================ app/purdue.py

@pytest.mark.parametrize("raw, expected", [
    (0, 0), (5, 5), (3.0, 3), (3.5, 3.5), (Decimal("3.5"), 3.5), (Decimal("4.0"), 4),
    ("3", 3), ("3.0", 3), ("3.5", 3.5), (" L3.5 ", 3.5), ("l4", 4), ("Level 2", 2),
    ("dmz", 3.5), ("IDMZ", 3.5), ("", None), (None, None),
])
def test_normalize_level_accepts(raw, expected):
    got = purdue.normalize_level(raw)
    assert got == expected
    if expected is not None:
        assert type(got) is (float if expected == 3.5 else int)


@pytest.mark.parametrize("raw", [3.7, 6, -1, 2.5, 4.5, True, False, "6", "L6", "x", "3.5.1",
                                 float("nan"), float("inf"), [], {}])
def test_normalize_level_rejects(raw):
    with pytest.raises(ValueError):
        purdue.normalize_level(raw)


def test_valid_levels_and_validation_helpers():
    assert purdue.VALID_LEVELS == (0, 1, 2, 3, 3.5, 4, 5)
    assert [x for x in (-1, 0, 1, 2, 2.5, 3, 3.5, 3.7, 4, 5, 6) if purdue.is_valid_level(x)] \
        == [0, 1, 2, 3, 3.5, 4, 5]
    assert not purdue.is_valid_level("3.5") and not purdue.is_valid_level(True)
    # topology_manager's old names are thin wrappers over app.purdue
    assert valid_purdue_level(3.5) and not valid_purdue_level(3.7)
    msg = purdue_level_error("purdue_level", 6)
    assert msg == purdue.purdue_level_error("purdue_level", 6)
    assert "3.5 (Industrial DMZ)" in msg and "0–5" in msg


def test_names_and_formatting():
    assert purdue.LEVEL_NAMES[3.5] == "Industrial DMZ"
    assert set(purdue.LEVEL_NAMES) == set(purdue.VALID_LEVELS)
    assert [purdue.fmt_level(x) for x in (3, 3.0, 3.5, None, 9)] == ["L3", "L3", "L3.5", "L?", "L?"]
    assert purdue.level_label(3.5) == "L3.5 Industrial DMZ"
    assert purdue.sorted_levels({4, 3.5, 3.0, 9, None}) == [3, 3.5, 4]
    assert list(purdue.iter_levels(reverse=True))[:3] == [5, 4, 3.5]
    assert _fmt_levels({3.5, 1, 3.0}) == "L1,3,3.5"
    rows = purdue.canonical_levels()
    assert [r["label"] for r in rows] == ["L0", "L1", "L2", "L3", "L3.5", "L4", "L5"]
    assert [r["is_dmz"] for r in rows].count(True) == 1


def test_ordering_and_predicates():
    assert purdue.level_distance(3, 3.5) == 1 and purdue.level_distance(3.5, 4) == 1
    assert purdue.level_distance(3, 4) == 2 and purdue.level_distance(0, 5) == 6
    assert purdue.next_level(3) == 3.5 and purdue.prev_level(4) == 3.5
    assert purdue.next_level(5) == 5 and purdue.prev_level(0) == 0
    assert purdue.levels_between(3, 4) == [3.5] and purdue.levels_between(2, 3) == []
    assert [x for x in purdue.VALID_LEVELS if purdue.is_ot(x)] == [0, 1, 2]
    assert [x for x in purdue.VALID_LEVELS if purdue.is_deep_ot(x)] == [0, 1]
    assert [x for x in purdue.VALID_LEVELS if purdue.is_site_ops(x)] == [3]
    assert [x for x in purdue.VALID_LEVELS if purdue.is_dmz(x)] == [3.5]
    assert [x for x in purdue.VALID_LEVELS if purdue.is_it(x)] == [4, 5]
    assert [x for x in purdue.VALID_LEVELS if purdue.is_it_side(x)] == [3, 3.5, 4, 5]
    assert not any(f(None) for f in (purdue.is_ot, purdue.is_dmz, purdue.is_it, purdue.is_it_side))


# ============================================================ storage

def test_column_type_round_trip_and_check_constraints(db):
    h = Host(ip="10.35.0.1", purdue_level=3.5)
    h2 = Host(ip="10.3.0.1", purdue_level=3.0)
    fw = Firewall(name="fw", vendor="fortigate", purdue_level_ingress=4, purdue_level_egress="3.5")
    db.add_all([h, h2, fw])
    db.commit()
    db.expire_all()
    assert (h.purdue_level, h2.purdue_level) == (3.5, 3)
    assert type(h2.purdue_level) is int
    assert (fw.purdue_level_ingress, fw.purdue_level_egress) == (4, 3.5)
    assert db.query(Host).filter(Host.purdue_level == 3.5).one().ip == "10.35.0.1"
    assert db.query(Host).filter(Host.purdue_level > 3).count() == 1
    for model, kw in ((Host, {"ip": "10.9.9.9", "purdue_level": 3.7}),
                      (FirewallDevice, {"name": "d", "purdue_zone_to": 6}),
                      (Firewall, {"name": "f2", "vendor": "x", "purdue_level_egress": -1}),
                      (SwitchVlan, {"vlan_id": 7, "purdue_level": 2.5})):
        db.add(model(**kw))
        with pytest.raises(sa.exc.IntegrityError):
            db.commit()
        db.rollback()


def _cfg(url: str) -> Config:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def test_migration_integer_to_numeric_keeps_data(tmp_path):
    """b9c0d1e2f3a4 on a database with integer levels: data kept (still
    stored as INTEGER on SQLite), out-of-set values NULLed, constraints
    swapped, hosts' partial unique indexes survive the rebuild, 3.5 is then
    accepted and 3.7 rejected; downgrade maps 3.5 -> NULL; re-upgrade works."""
    url = f"sqlite:///{tmp_path / 'dmz.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "a8b9c0d1e2f3")
    eng = sa.create_engine(url)
    with eng.begin() as c:
        c.exec_driver_sql("INSERT INTO hosts (id, ip, purdue_level) VALUES (1, '10.3.0.1', 3), "
                          "(2, '10.0.0.5', 0), (3, '10.0.0.6', NULL)")
        c.exec_driver_sql("INSERT INTO hosts (id, mac) VALUES (4, 'aa:bb:cc:dd:ee:ff')")
        c.exec_driver_sql("INSERT INTO firewalls (id, name, vendor, topology_confirmed, is_multi_fw, "
                          "purdue_level_ingress, purdue_level_egress) VALUES (1, 'f', 'x', 0, 0, 7, 3)")
        c.exec_driver_sql("INSERT INTO firewall_devices (id, name, purdue_zone_from, purdue_zone_to) "
                          "VALUES (1, 'd', 4, 3)")
        c.exec_driver_sql("INSERT INTO firewall_interfaces (id, firewall_id, name, purdue_level, "
                          "suggested_purdue_level, is_ha, is_mgmt_only) VALUES (1, 1, 'port2', 2, 4, 0, 0)")
        c.exec_driver_sql("INSERT INTO switch_vlans (id, device_name, vlan_id, purdue_level) "
                          "VALUES (1, 'sw', 30, 1)")
        idx_before = sorted(c.exec_driver_sql(
            "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='hosts' "
            "AND sql IS NOT NULL").all())
        assert any("WHERE" in sql for _n, sql in idx_before)  # partial indexes exist
    eng.dispose()

    command.upgrade(cfg, "head")
    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    for table, col in (("hosts", "purdue_level"), ("firewalls", "purdue_level_ingress"),
                       ("firewalls", "purdue_level_egress"), ("firewall_devices", "purdue_zone_from"),
                       ("firewall_devices", "purdue_zone_to"), ("firewall_interfaces", "purdue_level"),
                       ("firewall_interfaces", "suggested_purdue_level"), ("switch_vlans", "purdue_level")):
        t = {c["name"]: c["type"] for c in insp.get_columns(table)}[col]
        assert isinstance(t, sa.Numeric) and (t.precision, t.scale) == (2, 1), (table, col, t)
    cks = {ck["name"] for ck in insp.get_check_constraints("hosts")}
    assert {"ck_host_purdue_level_valid", "ck_host_identity"} <= cks
    assert "ck_host_purdue_level_range" not in cks
    assert {ck["name"] for ck in insp.get_check_constraints("firewall_interfaces")} >= {
        "ck_fw_iface_purdue_level", "ck_fw_iface_suggested_purdue"}
    with eng.begin() as c:
        rows = c.exec_driver_sql("SELECT id, purdue_level, typeof(purdue_level) FROM hosts ORDER BY id").all()
        assert rows == [(1, 3, "integer"), (2, 0, "integer"), (3, None, "null"), (4, None, "null")]
        assert c.exec_driver_sql("SELECT purdue_level_ingress, purdue_level_egress FROM firewalls").one() \
            == (None, 3)  # 7 was outside the valid set -> NULL (warning logged)
        assert c.exec_driver_sql("SELECT purdue_zone_from, purdue_zone_to FROM firewall_devices").one() == (4, 3)
        assert c.exec_driver_sql("SELECT purdue_level, suggested_purdue_level FROM firewall_interfaces").one() \
            == (2, 4)
        idx_after = sorted(c.exec_driver_sql(
            "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='hosts' "
            "AND sql IS NOT NULL").all())
        # e1f2a3b4c5d6 (multi-site phase 2) replaces the global host identity
        # indexes by per-site ones (which reconcile already created early).
        _replaced = {"ix_host_ip_only", "ix_host_mac_only"}
        assert idx_after == [i for i in idx_before if i[0] not in _replaced]
        c.exec_driver_sql("UPDATE hosts SET purdue_level = 3.5 WHERE id = 2")
        c.exec_driver_sql("UPDATE firewall_interfaces SET purdue_level = 3.5")
    for stmt in ("UPDATE hosts SET purdue_level = 3.7 WHERE id = 1",
                 "UPDATE firewall_devices SET purdue_zone_to = 6",
                 "UPDATE switch_vlans SET purdue_level = -1"):
        with pytest.raises(sa.exc.IntegrityError):
            with eng.begin() as c:
                c.exec_driver_sql(stmt)
    with sessionmaker(bind=eng)() as s:
        assert s.get(Host, 2).purdue_level == 3.5 and s.get(Host, 1).purdue_level == 3
    eng.dispose()

    command.upgrade(cfg, "head")       # at head: no-op
    command.downgrade(cfg, "a8b9c0d1e2f3")
    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    assert isinstance({c["name"]: c["type"] for c in insp.get_columns("hosts")}["purdue_level"], sa.Integer)
    assert "ck_host_purdue_level_range" in {ck["name"] for ck in insp.get_check_constraints("hosts")}
    with eng.begin() as c:
        assert c.exec_driver_sql("SELECT id, purdue_level FROM hosts ORDER BY id").all() \
            == [(1, 3), (2, None), (3, None), (4, None)]
        assert c.exec_driver_sql("SELECT purdue_level FROM firewall_interfaces").scalar() is None
    eng.dispose()
    command.upgrade(cfg, "head")


# ============================================================ API

@pytest.fixture
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'api.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        c.Session = Session
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def _assert_422(r, field):
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert isinstance(detail, str) and detail.startswith(f"{field} must be a Purdue level 0–5")


def test_purdue_levels_endpoint(api):
    body = api.get("/purdue-levels").json()
    assert [lv["level"] for lv in body["levels"]] == [0, 1, 2, 3, 3.5, 4, 5]
    assert body["levels"][4] == {"level": 3.5, "label": "L3.5", "name": "Industrial DMZ", "is_dmz": True}
    dt = {d["device_type"]: d["purdue_level"] for d in body["device_types"]}
    assert dt["jump_host"] == 3.5 and dt["plc"] == 1
    assert '"level":3,' in api.get("/purdue-levels").text  # never 3.0


def _seed_iface(api):
    with api.Session() as s:
        fw = Firewall(name="FW-A", vendor="fortigate")
        s.add(fw)
        s.flush()
        i = FirewallInterface(firewall_id=fw.id, name="port2", purdue_level=3)
        h = Host(ip="10.3.0.9", purdue_level=3, sources=["t"])
        d = FirewallDevice(name="dev-a", vendor="fortigate")
        s.add_all([i, h, d])
        s.commit()
        return fw.id, i.id, h.id, d.id


def test_set_interface_side_accepts_dmz_and_serialises_exactly(api):
    _fw, iid, _h, _d = _seed_iface(api)
    r = api.post("/topology/set-interface-side", json={"interface_id": iid, "purdue_level": 3.5})
    assert r.status_code == 200 and r.json()["interface"]["purdue_level"] == 3.5
    assert '"purdue_level":3.5' in r.text
    r = api.post("/topology/set-interface-side", json={"interface_id": iid, "purdue_level": "L3"})
    assert r.status_code == 200 and '"purdue_level":3}' in r.text      # 3, not 3.0
    for bad in BAD_LEVELS + ["L9", True]:
        _assert_422(api.post("/topology/set-interface-side",
                             json={"interface_id": iid, "purdue_level": bad}), "purdue_level")


def test_set_upstream_accepts_dmz_and_level_5(api):
    fw_id, *_ = _seed_iface(api)
    r = api.post("/topology/set-upstream",
                 json={"firewall_id": fw_id, "purdue_level_ingress": 4, "purdue_level_egress": 3.5})
    assert r.status_code == 200, r.text
    assert (r.json()["firewall"]["purdue_level_ingress"], r.json()["firewall"]["purdue_level_egress"]) \
        == (4, 3.5)
    with api.Session() as s:
        fw = s.get(Firewall, fw_id)
        assert (fw.purdue_level_ingress, fw.purdue_level_egress) == (4, 3.5)
    # was capped at 0-4 with a 400 before F-08
    assert api.post("/topology/set-upstream",
                    json={"firewall_id": fw_id, "purdue_level_ingress": 5}).status_code == 200
    for bad in BAD_LEVELS:
        _assert_422(api.post("/topology/set-upstream",
                             json={"firewall_id": fw_id, "purdue_level_egress": bad}), "purdue_level_egress")


def test_host_classification_and_filters(api):
    _fw, _i, hid, _d = _seed_iface(api)
    r = api.patch(f"/hosts/{hid}/classification", params={"device_type": "jump_host"})
    assert r.status_code == 200 and r.json()["purdue_level"] == 3.5          # reference default
    r = api.patch(f"/hosts/{hid}/classification", params={"device_type": "custom", "purdue_level": "3.5"})
    assert r.status_code == 200 and r.json()["purdue_level"] == 3.5
    for bad in BAD_LEVELS:
        _assert_422(api.patch(f"/hosts/{hid}/classification",
                              params={"device_type": "custom", "purdue_level": bad}), "purdue_level")
    assert [h["ip"] for h in api.get("/hosts", params={"purdue_level": "dmz"}).json()] == ["10.3.0.9"]
    assert api.get("/hosts", params={"purdue_level": 3}).json() == []
    assert [a["ip"] for a in api.get("/assets", params={"purdue_level": 3.5}).json()] == ["10.3.0.9"]
    assert "10.3.0.9" in api.get("/assets/export", params={"purdue_level": 3.5}).text
    for path in ("/hosts", "/assets", "/assets/export"):
        _assert_422(api.get(path, params={"purdue_level": 3.7}), "purdue_level")


def test_firewall_device_boundary_and_filters(api):
    *_, did = _seed_iface(api)
    r = api.patch(f"/firewall-devices/{did}/boundary",
                  params={"purdue_zone_from": 4, "purdue_zone_to": 3.5})
    assert r.status_code == 200 and (r.json()["purdue_zone_from"], r.json()["purdue_zone_to"]) == (4, 3.5)
    devs = api.get("/firewall-devices", params={"purdue_zone_to": "L3.5"}).json()
    devs = devs.get("devices", devs) if isinstance(devs, dict) else devs
    assert [d["name"] for d in devs] == ["dev-a"]
    for bad in BAD_LEVELS:
        _assert_422(api.patch(f"/firewall-devices/{did}/boundary", params={"purdue_zone_to": bad}),
                    "purdue_zone_to")
        _assert_422(api.get("/firewall-devices", params={"purdue_zone_from": bad}), "purdue_zone_from")
    topo = api.get("/topology").json()
    b = topo["firewall_boundaries"][0]
    assert (b["zone_lo"], b["zone_hi"]) == (3.5, 4)


def test_ingest_firewall_accepts_dmz_boundary(api):
    r = api.post("/ingest/firewall", params={"firewall_device_name": "edge",
                                             "purdue_zone_from": 4, "purdue_zone_to": 3.5},
                 files={"file": ("acl.txt", b"access-list 101 permit ip any any\n")})
    assert r.status_code == 200, r.text
    with api.Session() as s:
        d = s.query(FirewallDevice).filter_by(name="edge").one()
        assert (d.purdue_zone_from, d.purdue_zone_to) == (4, 3.5)
    for bad in BAD_LEVELS:
        _assert_422(api.post("/ingest/firewall", params={"purdue_zone_to": bad},
                             files={"file": ("acl.txt", b"access-list 101 permit ip any any\n")}),
                    "purdue_zone_to")
        _assert_422(api.post("/ingest/fortigate-config", params={"purdue_zone_from": bad},
                             files={"file": ("fg.txt", b"config system global\nend\n")}),
                    "purdue_zone_from")


def test_reachability_params(api):
    # FI-01: no implicit site - an operation on a fresh install asks for one
    assert api.get("/reachability", params={"src_level": 3.5, "dst_level": 1}).status_code == 409
    assert api.post("/sites", json={"name": "Plant", "code": "plant"}).status_code == 201
    r = api.get("/reachability", params={"src_level": 3.5, "dst_level": 1})
    assert r.status_code == 200 and list(r.json()["matrix"]) == ["3.5→1"]
    assert r.json()["matrix"]["3.5→1"]["src_level"] == 3.5
    for bad in BAD_LEVELS:
        _assert_422(api.get("/reachability", params={"src_level": bad}), "src_level")
        _assert_422(api.get("/reachability/path", params={"src": "10.0.0.1", "dst_level": bad}),
                    "dst_level")


# ============================================================ reachability

def _three_leg_dmz_firewall(db):
    """One FortiGate, legs port1 = L1 (OT), port2 = L3.5 (DMZ), port3 = L4 (IT)."""
    fw = Firewall(name="site-fg", device_name="site-fg", vendor="fortigate")
    db.add(fw)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=fw.id, name="port1", network_cidr="10.1.0.0/24", purdue_level=1),
        FirewallInterface(firewall_id=fw.id, name="port2", network_cidr="10.35.0.0/24", purdue_level=3.5),
        FirewallInterface(firewall_id=fw.id, name="port3", network_cidr="10.4.0.0/24", purdue_level=4),
        FirewallZone(device_name="site-fg", interface_name="port1", zone_name="OT_ZONE"),
        FirewallZone(device_name="site-fg", interface_name="port2", zone_name="DMZ_ZONE"),
        FirewallZone(device_name="site-fg", interface_name="port3", zone_name="IT_ZONE"),
        Host(ip="10.4.0.5", purdue_level=4), Host(ip="10.35.0.5", purdue_level=3.5),
        Host(ip="10.1.0.5", purdue_level=1),
    ])
    for order, (sz, dz, proto, port, action) in enumerate([
        ("IT_ZONE", "OT_ZONE", "any", None, "deny"),
        ("IT_ZONE", "DMZ_ZONE", "tcp", "3389", "permit"),
        ("DMZ_ZONE", "OT_ZONE", "tcp", "22", "permit"),
    ], start=1):
        db.add(FirewallRule(firewall_id=fw.id, device_name="site-fg", device_type="fortigate",
                            src="any", dst="any", protocol=proto, dst_port=port, action=action,
                            rule_order=order, src_zone=sz, dst_zone=dz))
    db.commit()
    return fw


def test_reachability_three_leg_firewall_with_dmz_leg(db):
    _three_leg_dmz_firewall(db)
    res = compute_reachability(db)
    m = res["matrix"]
    assert {"4→3.5", "3.5→1", "1→3.5", "3.5→4", "3→3.5"} <= set(m)
    assert sorted(ep["boundary"] for ep in res["enforcement_points"]) == ["1↔3.5", "1↔4", "3.5↔4"]
    assert res["levels_with_hosts"] == [1, 3.5, 4]
    assert m["4→3.5"]["overall"] == "partial" and m["4→3.5"]["permitted_services"] == ["tcp/3389"]
    assert m["3.5→1"]["overall"] == "partial" and m["3.5→1"]["permitted_services"] == ["tcp/22"]
    c41 = m["4→1"]
    assert c41["overall"] == "denied"
    assert all(len(p["hops"]) == 1 for p in c41["paths"])   # one box, crossed once
    assert m["3→3.5"]["overall"] == "no_policy"               # no L3 leg on this firewall
    # host path from the DMZ jump host into OT
    p = compute_path(db, src_ip="10.35.0.5", dst_ip="10.1.0.5", dst_port=22, protocol="tcp")
    assert (p["src_level"], p["dst_level"], p["overall"]) == (3.5, 1, "permitted")


def test_reachability_two_firewall_chain_through_dmz(db):
    a = FirewallDevice(name="fw-it-dmz", vendor="fortigate", purdue_zone_from=4, purdue_zone_to=3.5)
    b = FirewallDevice(name="fw-dmz-ops", vendor="fortigate", purdue_zone_from=3.5, purdue_zone_to=3)
    db.add_all([a, b])
    db.flush()
    for d, proto, port in ((a, "any", None), (b, "tcp", "443")):
        db.add(FirewallRule(firewall_device_id=d.id, device_name=d.name, device_type="fortigate",
                            src="any", dst="any", protocol=proto, dst_port=port, action="permit",
                            rule_order=1))
    db.commit()
    m = compute_reachability(db)["matrix"]
    c = m["4→3"]
    assert c["overall"] == "partial" and c["permitted_services"] == ["tcp/443"]
    assert [[(h["from_level"], h["to_level"], h["boundary"]) for h in p["hops"]] for p in c["paths"]] \
        == [[(4, 3.5, "3.5↔4"), (3.5, 3, "3↔3.5")]]
    assert m["4→3.5"]["overall"] == "permitted"
    assert m["3.5→3"]["overall"] == "partial"
    # MP-03: L2 has no hosts, no firewall and no label -> nothing is inferred
    # into it (was a baseless "partial" cell before).
    assert m["4→2"]["overall"] == "no_policy"
    # A-25: once L2 has a host it is inferred flat with L3 (nearest) and the
    # chain's policy decides.
    from app.models import Host
    db.add(Host(ip="10.2.0.9", purdue_level=2, sources=["test"]))
    db.commit()
    m = compute_reachability(db)["matrix"]
    assert m["4→2"]["overall"] == "partial"
    assert m["4→2"]["paths"][0]["inferred_adjacency"][0]["basis"] == "nearest"
    assert m["4→2"]["paths"][0]["path"].endswith("→ ~ 2 (inferred, no firewall)")
    assert firewall_level_boundaries(db) == {(3.5, 4), (3, 3.5)}


# ============================================================ adjacency

def test_level_edge_adjacency_treats_dmz_as_own_level():
    b = {(3.5, 4), (3, 3.5)}
    assert classify_level_edge(3, 3.5, b) == {"violation": "adjacent", "crosses_firewall": True}
    assert classify_level_edge(4, 3.5, b) == {"violation": "adjacent", "crosses_firewall": True}
    assert classify_level_edge(4, 3, b) == {"violation": "skips_level", "crosses_firewall": True}
    assert classify_level_edge(3.5, 3.5, b)["violation"] == "same"
    assert classify_level_edge(3.5, 2, set()) == {"violation": "skips_level", "crosses_firewall": False}
    assert classify_level_edge(2, 3, set())["violation"] == "adjacent"


# ============================================================ classification

def test_dmz_vlan_names_and_device_types():
    assert classify_vlan_name("DMZ") == 3.5
    assert classify_vlan_name("OT-IDMZ-30") == 3.5
    assert classify_vlan_name("dmz_historian") == 3.5       # zone name wins over contents
    assert classify_vlan_name("CORP_IT") == 4                 # unchanged
    assert classify_vlan_name("ADMZONE") is None              # token match only
    assert DEVICE_TYPE_REFERENCE["jump_host"][0] == 3.5


def test_hosts_on_dmz_vlan_classified_3_5(db):
    db.add_all([SwitchVlan(device_name="sw", vlan_id=35, vlan_name="IDMZ"),
                Host(ip="10.35.0.7", vlan="35")])
    db.flush()
    classify_hosts_by_vlan(db)
    h = db.query(Host).one()
    assert (h.purdue_level, h.classification_source) == (3.5, "vlan_inferred")


def test_purdue_suggestions_for_dmz_role_and_zone(db):
    fw = Firewall(name="fg", device_name="fg", vendor="fortigate")
    db.add(fw)
    db.flush()
    by_role = FirewallInterface(firewall_id=fw.id, name="port7", role="dmz")
    by_zone = FirewallInterface(firewall_id=fw.id, name="port8")
    lan = FirewallInterface(firewall_id=fw.id, name="port9", role="lan")
    db.add_all([by_role, by_zone, lan,
                FirewallZone(device_name="fg", interface_name="port8", zone_name="DMZ_ZONE")])
    db.flush()
    run_purdue_suggestions(db)
    assert (by_role.suggested_purdue_level, by_role.purdue_suggestion_source) == (3.5, "role_heuristic")
    assert (by_zone.suggested_purdue_level, by_zone.purdue_suggestion_source) == (3.5, "zone_name")
    assert lan.suggested_purdue_level == 3                    # unchanged


def test_peer_link_suggestions_around_dmz(db):
    fw1, fw2 = Firewall(name="a", vendor="fortigate"), Firewall(name="b", vendor="fortigate")
    db.add_all([fw1, fw2])
    db.flush()
    dmz = FirewallInterface(firewall_id=fw1.id, name="dmz", purdue_level=3.5)
    out = FirewallInterface(firewall_id=fw2.id, name="wan", side="outside")
    l3 = FirewallInterface(firewall_id=fw1.id, name="p3", purdue_level=3)
    up = FirewallInterface(firewall_id=fw2.id, name="up", side="outside")
    db.add_all([dmz, out, l3, up])
    db.flush()
    out.connects_to_interface_id, dmz.connects_to_interface_id = dmz.id, out.id
    up.connects_to_interface_id, l3.connects_to_interface_id = l3.id, up.id
    db.flush()
    run_purdue_suggestions(db)
    # MP-13: a confirmed link is one wire - both ends carry the peer's level
    assert out.suggested_purdue_level == 3.5
    assert up.suggested_purdue_level == 3
    # a declared paired (series) group uses the far-side convention (+-1)
    g = __import__("app.models", fromlist=["FirewallGroup"]).FirewallGroup(kind="paired", name="pair")
    db.add(g)
    db.flush()
    fw1.paired_group_id = fw2.paired_group_id = g.id
    db.flush()
    run_purdue_suggestions(db)
    assert out.suggested_purdue_level == 4      # outside of a DMZ leg
    assert up.suggested_purdue_level == 4       # whole levels: +1, the DMZ is never invented


def test_set_interface_labels_and_upstream_store_dmz(db):
    fw = Firewall(name="fg", vendor="fortigate")
    db.add(fw)
    db.flush()
    i = FirewallInterface(firewall_id=fw.id, name="p")
    db.add(i)
    db.flush()
    set_interface_labels(db, i.id, purdue_level=3.5)
    set_upstream_firewall(db, fw.id, None, purdue_level_ingress=4, purdue_level_egress=3.5)
    db.commit()
    db.expire_all()
    assert (i.purdue_level, fw.purdue_level_egress) == (3.5, 3.5)
    with pytest.raises(ValueError, match="3.5 \\(Industrial DMZ\\)"):
        set_interface_labels(db, i.id, purdue_level=3.7)


# ============================================================ alert engine

def _now():
    return datetime.now(timezone.utc)


def _mgmt_session(db, src_ip, src_level, dst_ip="10.2.0.10", port=22):
    src = db.query(Host).filter_by(ip=src_ip).first() or Host(ip=src_ip, purdue_level=src_level)
    dst = db.query(Host).filter_by(ip=dst_ip).first() or Host(ip=dst_ip, purdue_level=2)
    db.add_all([src, dst])
    db.flush()
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, src_port=40000, dst_port=port,
                       transport="tcp", protocol="ssh", packet_count=5)
    db.add(s)
    db.flush()
    return s


def test_mgmt_from_dmz_is_one_step_lower_than_from_enterprise(db):
    b = Baseline(name="b", is_active=True, created_at=_now())
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip="10.9.9.9", role="jump_host"))
    _mgmt_session(db, "10.35.0.5", 3.5)
    _mgmt_session(db, "10.4.0.5", 4)
    _mgmt_session(db, "10.9.9.9", 3.5)          # the approved jump host: no finding
    db.flush()
    found = {f.detail["src_ip"]: f for f in review_mgmt_access_from_wrong_zone(db)}
    assert set(found) == {"10.35.0.5", "10.4.0.5"}
    dmz, ent = found["10.35.0.5"], found["10.4.0.5"]
    assert (dmz.severity, ent.severity) == ("low", "medium")
    assert dmz.detail["dmz_source"] is True and ent.detail["dmz_source"] is False
    assert "DMZ" in dmz.title and "DMZ" not in ent.title
    assert "jump_host" in dmz.detail["description"] and "(L3.5)" in dmz.detail["description"]
    assert dmz.detail["src_purdue_level"] == 3.5


@pytest.fixture
def dmz_fw(db):
    fw = Firewall(name="FGT1", device_name="FGT1", vendor="fortigate")
    db.add(fw)
    db.flush()
    for name, lvl in (("port1", 1), ("port2", 2), ("port5", 3.5), ("port4", 4)):
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl))
    db.flush()
    return fw


def _rule(db, fw, src_zone, dst_zone, dst_port="22", policy_id="10"):
    r = FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                     policy_id=policy_id, src_zone=src_zone, dst_zone=dst_zone, src="all",
                     dst="all", protocol="tcp", dst_port=dst_port, action="permit")
    db.add(r)
    db.flush()
    return r


def test_rule_mgmt_from_dmz_zone_lower_severity(db, dmz_fw):
    _rule(db, dmz_fw, "port5", "port2", policy_id="10")          # DMZ -> L2 SSH
    _rule(db, dmz_fw, "port4", "port2", policy_id="11")          # L4 -> L2 SSH
    by_policy = {f.detail["policy_id"]: f for f in review_rule_mgmt_wrong_zone(db)}
    assert by_policy["10"].severity == "low" and by_policy["10"].detail["dmz_source"] is True
    assert "DMZ" in by_policy["10"].title
    assert by_policy["11"].severity == "medium" and by_policy["11"].detail["dmz_source"] is False


def test_rule_it_ot_bypass_still_fires_from_dmz(db, dmz_fw):
    _rule(db, dmz_fw, "port5", "port1", dst_port="502")          # DMZ -> L1 direct
    found = review_rule_it_ot_bypass(db)
    assert len(found) == 1
    assert found[0].detail["src_it_levels"] == [3.5] and found[0].detail["dst_deep_ot_levels"] == [1]
    assert "L3.5" in found[0].title


def test_insecure_protocol_between_l3_and_dmz_is_a_crossing(db):
    a, b = Host(ip="10.3.0.1", purdue_level=3), Host(ip="10.35.0.1", purdue_level=3.5)
    c = Host(ip="10.3.0.2", purdue_level=3)
    db.add_all([a, b, c])
    db.flush()
    for dst in (b, c):
        db.add(NetworkSession(src_host_id=a.id, dst_host_id=dst.id, src_port=1000 + dst.id,
                              dst_port=23, transport="tcp", protocol="telnet", packet_count=3))
    db.flush()
    found = [f for f in review_cleartext_protocols(db) if f.check_name == "cleartext_protocol"]
    assert [f.detail["dst_ip"] for f in found] == ["10.35.0.1"]   # same-level L3->L3 skipped
    assert "(L3.5)" in found[0].title
