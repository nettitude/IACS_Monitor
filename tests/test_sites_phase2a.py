"""
Multi-site phase 2 part A (docs/multi-site-design.md): site-scoped identity
(per-site unique indexes, migration e1f2a3b4c5d6), ingest get-or-create
inside the upload's site, per-site baselines / attestations, per-site
analysis routes and cross-site reference refusal.

Sites are isolated: the same IP / MAC / firewall name uploaded to two sites
gives two independent row sets, and a re-ingest in one site never touches
the other.
"""
import shutil
from contextlib import contextmanager
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    Attestation, Baseline, Finding, Firewall, FirewallDevice, FirewallInterface, FirewallRule,
    FirewallZone, FortiAnalyzerEvent, Host, MacTableEntry, NetworkSession, Site, SwitchInterface,
    SwitchVlan,
)
from app.parsers.common import get_or_create_host
from app.parsers.host_identity import merge_hosts
from app.sites import ingest_site

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"


@contextmanager
def _api(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("IACS_REVIEW_ENABLED", "false")
        mp.setattr(main_mod, "init_db", lambda: None)
        prev = main_mod.app.dependency_overrides.get(get_db)
        main_mod.app.dependency_overrides[get_db] = _get_db
        try:
            with TestClient(main_mod.app) as c:
                c.Session = Session
                yield c
        finally:
            if prev is None:
                main_mod.app.dependency_overrides.pop(get_db, None)
            else:
                main_mod.app.dependency_overrides[get_db] = prev
            engine.dispose()


def _ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.text[:800])
    return r.json()


def up(c, url, name, params=None, content=None):
    data = content if content is not None else (SAMPLES / name).read_bytes()
    return c.post(url, params=params or {}, files={"file": (name, data, "application/octet-stream")})


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "p2a.db") as c:
        _ok(c.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit (no implicit Default)
        c.a = _ok(c.post("/sites", json={"name": "Plant A", "code": "plant-a"}), 201)["id"]
        c.b = _ok(c.post("/sites", json={"name": "Plant B", "code": "plant-b"}), 201)["id"]
        yield c


@pytest.fixture
def overlapped(client):
    """The SAME FortiGate config, ARP table, PCAP and switch/MAC data in both plants."""
    for site in ("plant-a", "plant-b"):
        _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt",
               {"site": site, "firewall_name": "FW-OT", "generate_findings": "true"}))
        _ok(up(client, "/ingest/firewall", "sample_firewall_cisco.txt",
               {"site": site, "firewall_device_name": "CISCO-EDGE", "purdue_zone_from": 4,
                "purdue_zone_to": 3}))
        _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt", {"site": site}))
        _ok(up(client, "/ingest/switch", "sample_switch_running_config.txt",
               {"site": site, "device_name": "SW-CORE"}))
        _ok(up(client, "/ingest/switch", "sample_switch_vlan_brief.txt",
               {"site": site, "device_name": "SW-CORE"}))
        _ok(up(client, "/ingest/mac-table", "sample_mac_table_cisco.txt",
               {"site": site, "device_name": "SW-CORE"}))
    return client


def _count(c, model, site_id, *crit):
    with c.Session() as s:
        return s.query(model).filter(model.site_id == site_id, *crit).count()


# ------------------------------------------------------------ identity ------

def test_same_ip_mac_firewall_name_in_two_sites_stay_separate(overlapped):
    c = overlapped
    with c.Session() as s:
        for model in (Host, Firewall, FirewallDevice, FirewallRule, FirewallZone,
                      SwitchInterface, SwitchVlan, MacTableEntry):
            na = s.query(model).filter(model.site_id == c.a).count()
            nb = s.query(model).filter(model.site_id == c.b).count()
            assert na and na == nb, (model.__name__, na, nb)
        fws = s.query(Firewall).filter(Firewall.name == "FW-OT").all()
        assert sorted(f.site_id for f in fws) == sorted([c.a, c.b])
        devs = s.query(FirewallDevice).filter(FirewallDevice.name == "CISCO-EDGE").all()
        assert sorted(d.site_id for d in devs) == sorted([c.a, c.b])
        # every IP / MAC of Plant A also exists - as a different row - in Plant B
        a_hosts = {(h.ip, h.mac): h.id for h in s.query(Host).filter(Host.site_id == c.a)}
        b_hosts = {(h.ip, h.mac): h.id for h in s.query(Host).filter(Host.site_id == c.b)}
        assert a_hosts.keys() == b_hosts.keys()
        assert not set(a_hosts.values()) & set(b_hosts.values())
        # rules hang off the firewall of their own site
        for fw in fws:
            assert {r.site_id for r in s.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id)} \
                == {fw.site_id}


def test_pcap_sessions_are_per_site(client):
    for site in ("plant-a", "plant-b"):
        _ok(up(client, "/ingest/pcap", "modbus_sample.pcap", {"site": site}))
    with client.Session() as s:
        per_site = {}
        for sid in (client.a, client.b):
            hosts = {h.id for h in s.query(Host).filter(Host.site_id == sid)}
            sess = s.query(NetworkSession).filter(NetworkSession.src_host_id.in_(hosts)).all()
            assert sess and all(x.dst_host_id in hosts for x in sess)
            per_site[sid] = len(sess)
        assert per_site[client.a] == per_site[client.b]


def test_get_or_create_host_and_merge_never_cross_sites(client):
    with client.Session() as s:
        a = get_or_create_host(s, "10.9.9.9", "aa:bb:cc:00:00:01", "test", site_id=client.a)
        b = get_or_create_host(s, "10.9.9.9", "aa:bb:cc:00:00:01", "test", site_id=client.b)
        assert a.id != b.id and (a.site_id, b.site_id) == (client.a, client.b)
        with ingest_site(s, client.b):      # bound ingest site = the scope
            assert get_or_create_host(s, "10.9.9.9", None, "test").id == b.id
        with pytest.raises(ValueError, match="different sites"):
            merge_hosts(s, a, b)
        s.rollback()


def test_unique_indexes_are_per_site(client):
    with client.Session() as s:
        s.add_all([Host(site_id=client.a, ip="10.1.1.1"), Host(site_id=client.b, ip="10.1.1.1")])
        s.commit()
        s.add(Host(site_id=client.a, ip="10.1.1.1"))
        with pytest.raises(IntegrityError):
            s.commit()
        s.rollback()
        s.add_all([Firewall(site_id=client.a, name="X"), Firewall(site_id=client.b, name="X")])
        s.commit()
        s.add(Firewall(site_id=client.b, name="X"))
        with pytest.raises(IntegrityError):
            s.commit()
        s.rollback()
        for sid in (client.a, client.b):
            s.add(Finding(site_id=sid, category="real_time", severity="low", status="open",
                          title="t", source_ref="same-ref"))
            s.add(FortiAnalyzerEvent(site_id=sid, source_type="syslog", dedup_hash="h" * 40))
        s.commit()


def test_reingest_in_one_site_does_not_touch_the_other(overlapped):
    c = overlapped
    with c.Session() as s:
        b_rules = sorted(r.id for r in s.query(FirewallRule).filter(FirewallRule.site_id == c.b))
        b_fw = s.query(Firewall).filter(Firewall.site_id == c.b, Firewall.name == "FW-OT").one().id
    _ok(up(c, "/ingest/fortigate-config", "sample_fortigate_config.txt",
           {"site": "plant-a", "firewall_name": "FW-OT"}))
    _ok(up(c, "/ingest/firewall", "sample_firewall_cisco.txt",
           {"site": "plant-a", "firewall_device_name": "CISCO-EDGE"}))
    with c.Session() as s:
        assert sorted(r.id for r in s.query(FirewallRule).filter(FirewallRule.site_id == c.b)) == b_rules
        assert s.query(Firewall).filter(Firewall.name == "FW-OT").count() == 2
        assert s.query(Firewall).filter(Firewall.site_id == c.b, Firewall.name == "FW-OT").one().id == b_fw
    # the same log line in two sites is two events (dedup per site)
    line = (b'date=2026-09-30 time=10:00:00 devname="FW-OT" type=traffic subtype=forward '
            b'srcip=10.0.3.50 dstip=10.0.1.10 srcport=50000 dstport=23 proto=6 action=accept '
            b'policyid=99 service=TELNET\n')
    from app.parsers.forti_parser import ingest_syslog_line_ex
    with c.Session() as s:
        with ingest_site(s, c.a):
            e1, st1 = ingest_syslog_line_ex(line.decode(), s)
        with ingest_site(s, c.b):
            e2, st2 = ingest_syslog_line_ex(line.decode(), s)
            e3, st3 = ingest_syslog_line_ex(line.decode(), s)
        assert (st1, st2, st3) == ("created", "created", "duplicate")
        assert e1.id != e2.id == e3.id


def test_infer_vlan_by_subnet_is_per_site(client):
    from app.parsers.mac_table_parser import infer_vlan_by_subnet
    with client.Session() as s:
        s.add(Host(site_id=client.a, ip="10.5.5.1", vlan="10", vlan_source="mac_table"))
        s.add(Host(site_id=client.b, ip="10.5.5.2"))
        s.commit()
        assert infer_vlan_by_subnet(s)["hosts_inferred"] == 0
        assert s.query(Host).filter(Host.site_id == client.b).one().vlan is None


# ------------------------------------------------- baselines / attestation --

def test_one_active_baseline_per_site(client):
    for site, name in (("plant-a", "A1"), ("plant-b", "B1"), ("plant-a", "A2"), ("plant-b", "SHARED"),
                       ("plant-a", "SHARED")):
        _ok(up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv",
               {"site": site, "baseline_name": name}))
    act = lambda sid: sorted(b["name"] for b in _ok(client.get("/baselines", params={"site_id": sid}))
                             if b["is_active"])
    assert act(client.a) == ["SHARED"] and act(client.b) == ["SHARED"]
    # same name in two sites = two baselines
    with client.Session() as s:
        assert s.query(Baseline).filter(Baseline.name == "SHARED").count() == 2
    r = _ok(client.post("/baselines/A1/activate", params={"site": "plant-a"}))
    assert r["activated"] == "A1" and r["site_id"] == client.a
    assert act(client.a) == ["A1"] and act(client.b) == ["SHARED"]   # B untouched
    # A1 is not a Plant B baseline; several sites -> site required
    assert client.post("/baselines/A1/activate", params={"site": "plant-b"}).status_code == 404
    r = client.post("/baselines/A1/activate")
    assert r.status_code == 422 and "site" in r.json()["detail"]
    with client.Session() as s:  # the DB enforces it too
        s.add(Baseline(site_id=client.a, name="A3", is_active=True))
        with pytest.raises(IntegrityError):
            s.commit()


def test_attestations_are_per_site(client):
    for site in ("plant-a", "plant-b"):
        _ok(up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv",
               {"site": site, "baseline_name": "B1"}))

    def attest(site, who):
        return _ok(client.post("/attestation", data={
            "checklist_id": "1.1", "attested_by": who, "attested_at": "2026-09-30",
            "baseline_name": "B1", "site": site}), 201)

    a1 = attest("plant-a", "alice")
    b1 = attest("plant-b", "bob")
    assert a1["baseline_id"] != b1["baseline_id"]
    a2 = attest("plant-a", "alice2")   # demotes a1 only
    cur = lambda sid: _ok(client.get("/attestation/current", params={"site_id": sid}))
    ca, cb = cur(client.a), cur(client.b)
    assert ca["rows"]["1.1"]["id"] == a2["id"] and cb["rows"]["1.1"]["id"] == b1["id"]
    assert ca["baseline"] == "B1" and ca["rows"]["1.2"] is None
    rows = _ok(client.get("/attestation", params={"site_id": client.b, "current_only": "true"}))
    assert [r["id"] for r in rows] == [b1["id"]]
    assert client.get("/attestation/current").status_code == 422   # several sites
    # the Plant B baseline name does not resolve for another site's attestation
    r = client.post("/attestation", data={"checklist_id": "1.2", "attested_by": "x",
                                          "attested_at": "2026-09-30", "baseline_name": "B1",
                                          "site": "default"})
    assert r.status_code == 404


# -------------------------------------------------------------- routes ------

PER_SITE_GETS = ("/diff", "/reachability", "/firewall-rules/shadowed", "/topology", "/topology/state")
PER_SITE_POSTS = ("/classify", "/findings/scan-industrial-writes", "/topology/run-checks",
                  "/topology/suggest-purdue")


def test_per_site_routes_require_site_when_several_exist(overlapped):
    c = overlapped
    for path in PER_SITE_GETS:
        r = c.get(path)
        assert r.status_code == 422 and "site" in r.json()["detail"], path
        assert c.get(path, params={"site_id": 999}).status_code == 422, path
        assert c.get(path, params={"site": "nope"}).status_code == 422, path
        out = _ok(c.get(path, params={"site": "plant-b"}))
        assert out["site_id"] == c.b, path
    for path in PER_SITE_POSTS:
        assert c.post(path).status_code == 422, path
        assert _ok(c.post(path, params={"site_id": c.a}))["site_id"] == c.a, path
    r = c.get("/reachability/path", params={"src": "10.0.1.10", "dst_level": 4})
    assert r.status_code == 422
    assert _ok(c.get("/reachability/path", params={"src": "10.0.1.10", "dst_level": 4,
                                                   "site": "plant-a"}))["site_id"] == c.a
    # site and site_id must agree
    assert c.get("/diff", params={"site": "plant-a", "site_id": c.b}).status_code == 422


def test_topology_views_show_only_the_site(overlapped):
    c = overlapped
    ta = _ok(c.get("/topology", params={"site_id": c.a}))
    tb = _ok(c.get("/topology", params={"site_id": c.b}))
    assert ta["nodes"] and len(ta["nodes"]) == len(tb["nodes"])
    assert not {n["id"] for n in ta["nodes"]} & {n["id"] for n in tb["nodes"]}
    sa_ = _ok(c.get("/topology/state", params={"site": "plant-a"}))
    with c.Session() as s:
        a_fw = {f.id for f in s.query(Firewall).filter(Firewall.site_id == c.a)}
    assert {f["id"] for f in sa_["firewalls"]} == a_fw


def test_single_site_derives_the_site(tmp_path):
    with _api(tmp_path / "one.db") as c:
        c.get("/sites")
        _ok(up(c, "/ingest/fortigate-config", "sample_fortigate_config.txt", {"site": "default"}))
        for path in PER_SITE_GETS:
            assert _ok(c.get(path))["site"] == "Default", path


def test_reviews_run_per_site(overlapped):
    c = overlapped
    one = _ok(c.post("/reviews/run", params={"site": "plant-a"}))
    assert one["site_id"] == c.a and list(one["sites"]) == ["Plant A"]
    allr = _ok(c.post("/reviews/run"))
    assert set(allr["sites"]) == {"Default", "Plant A", "Plant B"}
    assert allr["total_findings"] == sum(v["total_findings"] for v in allr["sites"].values())
    with c.Session() as s:  # findings land in the reviewed site
        zone = s.query(Finding).filter(Finding.check_name == "zone_doc_1_1",
                                       Finding.status == "open").all()
        per_site = [f.site_id for f in zone]
        assert {c.a, c.b} <= set(per_site) and len(per_site) == len(set(per_site))
    assert c.post("/reviews/run", params={"site": "ghost"}).status_code == 422


def test_cross_site_references_rejected(overlapped):
    c = overlapped
    with c.Session() as s:
        fa = s.query(Firewall).filter(Firewall.site_id == c.a, Firewall.name == "FW-OT").one()
        fb = s.query(Firewall).filter(Firewall.site_id == c.b, Firewall.name == "FW-OT").one()
        ia = s.query(FirewallInterface).filter(FirewallInterface.firewall_id == fa.id).first()
        ib = s.query(FirewallInterface).filter(FirewallInterface.firewall_id == fb.id).first()
        fa_id, fb_id, ia_id, ib_id = fa.id, fb.id, ia.id, ib.id
    r = c.post("/topology/set-upstream", json={"firewall_id": fa_id, "upstream_firewall_id": fb_id})
    assert r.status_code == 422 and "site" in r.json()["detail"]
    r = c.post("/topology/confirm-link", json={"iface_a_id": ia_id, "iface_b_id": ib_id})
    assert r.status_code == 422
    # a firewall of another site is invisible to an explicit site
    r = c.post("/topology/set-upstream", params={"site": "plant-b"},
               json={"firewall_id": fa_id, "upstream_firewall_id": None})
    assert r.status_code == 404
    r = c.post("/topology/set-interface-side", params={"site_id": c.b},
               json={"interface_id": ia_id, "side": "inside"})
    assert r.status_code == 404
    # same-site operations still work, the site is derived from the firewall
    r = _ok(c.post("/topology/set-interface-side", json={"interface_id": ia_id, "side": "inside"}))
    assert r["interface"]["side"] == "inside"
    r = _ok(c.post("/topology/set-upstream", json={"firewall_id": fa_id, "upstream_firewall_id": None}))
    assert r["site_id"] == c.a
    with c.Session() as s:
        dev_a = s.query(FirewallDevice).filter(FirewallDevice.site_id == c.a).first().id
    assert c.get("/firewall-rules/shadowed", params={"site": "plant-b",
                                                    "firewall_device_id": dev_a}).status_code == 404


def test_pcap_capture_cannot_be_pinned_to_another_sites_interface(overlapped):
    c = overlapped
    r = _ok(up(c, "/ingest/pcap-fw", "modbus_sample.pcap", {"site": "plant-a"}))
    with c.Session() as s:
        fb = s.query(Firewall).filter(Firewall.site_id == c.b).first()
        ib = s.query(FirewallInterface).filter(FirewallInterface.firewall_id == fb.id).first().id
        fa = s.query(Firewall).filter(Firewall.site_id == c.a).first()
    assert c.post(f"/ingest/pcap/{r['capture_id']}/confirm", json={"interface_id": ib}).status_code == 422
    assert up(c, "/ingest/pcap-fw", "modbus_sample.pcap",
              {"site": "plant-b", "firewall_id": fa.id}).status_code == 422


def test_report_requires_site_or_rollup(overlapped):
    c = overlapped
    assert c.get("/reports/compliance.pdf").status_code == 422
    one = c.get("/reports/compliance.pdf", params={"site": "plant-a"})
    assert one.status_code == 200 and one.content.startswith(b"%PDF")
    roll = c.get("/reports/compliance.pdf", params={"all_sites": "true"})
    assert roll.status_code == 200 and roll.content.startswith(b"%PDF")
    import generate_report
    with c.Session() as s:
        data = generate_report.collect_rollup_data(s)
    assert [d["site"] for d in data["sites"]] == ["Default", "Plant A", "Plant B"]
    assert data["sites"][1]["site_id"] == c.a


# ----------------------------------------------------------- migration ------

PRISTINE_DB = Path("/tmp/claude-0/pristine_original.db")


def _cfg(url):
    from alembic.config import Config
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def _indexes(url, table):
    eng = sa.create_engine(url)
    try:
        return {i["name"]: i for i in sa.inspect(eng).get_indexes(table)}
    finally:
        eng.dispose()


def test_migration_builds_per_site_indexes_and_resolves_conflicts(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "c0d1e2f3a4b5")
    eng = sa.create_engine(url)
    with eng.begin() as c:
        # (reconcile, run against the live models, may have created the new
        # indexes early - simulate a database where it could not)
        for ix in ("ux_baselines_site_active", "ux_firewalls_site_name"):
            c.execute(sa.text(f"DROP INDEX IF EXISTS {ix}"))
        c.execute(sa.text("INSERT INTO sites (id, name, code) VALUES (2, 'B', 'b')"))
        # two active baselines in one site, duplicate firewall names in one site
        c.execute(sa.text("INSERT INTO baselines (name, is_active, site_id) VALUES "
                          "('x', 1, 1), ('y', 1, 1), ('z', 1, 2)"))
        c.execute(sa.text("INSERT INTO firewalls (name, vendor, topology_confirmed, is_multi_fw, site_id) "
                          "VALUES ('fw', 'fortigate', 0, 0, 1), ('fw', 'fortigate', 0, 0, 1), "
                          "('fw', 'fortigate', 0, 0, 2)"))
    eng.dispose()
    command.upgrade(cfg, "head")
    ix = _indexes(url, "hosts")
    assert {"ux_hosts_site_mac_ip", "ux_hosts_site_ip_only", "ux_hosts_site_mac_only"} <= set(ix)
    assert not {"ix_host_ip_only", "ix_host_mac_only"} & set(ix)
    assert "ux_findings_site_source_ref_open" in _indexes(url, "findings")
    assert "ux_baselines_site_active" in _indexes(url, "baselines")
    eng = sa.create_engine(url)
    with eng.connect() as c:
        act = c.execute(sa.text("SELECT site_id, name FROM baselines WHERE is_active = 1 ORDER BY site_id")).all()
        assert act == [(1, "y"), (2, "z")]
        names = sorted(r[0] for r in c.execute(sa.text("SELECT name FROM firewalls WHERE site_id = 1")))
        assert names[0] == "fw" and names[1].startswith("fw (#")
        assert not any(uc["column_names"] == ["name"]
                       for uc in sa.inspect(c).get_unique_constraints("baselines"))
    eng.dispose()
    # same host identity in two sites is now allowed by the schema
    eng = sa.create_engine(url)
    with eng.begin() as c:
        c.execute(sa.text("INSERT INTO hosts (ip, site_id, stale) VALUES ('10.0.0.1', 1, 0), ('10.0.0.1', 2, 0)"))
    eng.dispose()
    command.upgrade(cfg, "head")   # re-runnable
    # downgrade refuses to restore a global unique the data now violates, but completes
    command.downgrade(cfg, "c0d1e2f3a4b5")
    assert "ix_host_ip_only" not in _indexes(url, "hosts")
    command.upgrade(cfg, "head")


@pytest.mark.skipif(not PRISTINE_DB.exists(), reason="pristine legacy DB not available")
def test_pristine_legacy_upgrade_has_per_site_identity(tmp_path):
    db = tmp_path / "legacy.db"
    shutil.copy(PRISTINE_DB, db)
    url = f"sqlite:///{db}"
    cfg = _cfg(url)
    command.stamp(cfg, "0001baseline0")
    command.upgrade(cfg, "head")
    ix = _indexes(url, "hosts")
    assert "ux_hosts_site_mac_ip" in ix and "ix_host_ip_only" not in ix
    eng = sa.create_engine(url)
    with eng.connect() as c:
        insp = sa.inspect(c)
        assert not any(uc["column_names"] == ["mac", "ip"] for uc in insp.get_unique_constraints("hosts"))
        assert not any(uc["column_names"] == ["name"] for uc in insp.get_unique_constraints("firewall_devices"))
    eng.dispose()
