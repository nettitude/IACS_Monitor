"""
Multi-site phase 1 (docs/multi-site-design.md): the Site model, required
``site`` on every non-log upload, site_id on created rows, site_id list
filters, the /sites API with delete gating, and the Default-site backfill.
"""
import csv
import io
from contextlib import contextmanager
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    Attestation, Baseline, Finding, Firewall, FirewallDevice, FirewallInterface,
    FirewallRule, FirewallZone, FortiAnalyzerEvent, Host, MacTableEntry, NatRule,
    NetworkSession, PcapCapture, Site, SwitchInterface, SwitchVlan,
)
from app.sites import SiteNotFound, get_default_site, ingest_site, resolve_site

from _site_util import SITE_REQUIRED_ROUTES

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
        mp.delenv("IACS_ENABLE_DELETE", raising=False)
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


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "sites.db") as c:
        # FI-01: a fresh install has no site; these tests model a database
        # that has the Default site (an upgraded one), created explicitly.
        assert c.get("/sites").json() == []
        assert c.post("/sites", json={"name": "Default", "code": "default"}).status_code == 201
        yield c


def up(c, url, name, params=None, content=None):
    data = content if content is not None else (SAMPLES / name).read_bytes()
    return c.post(url, params=params or {}, files={"file": (name, data, "application/octet-stream")})


def _ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.text[:600])
    return r.json()


def _mk_site(c, name, code=None):
    body = {"name": name}
    if code:
        body["code"] = code
    return _ok(c.post("/sites", json=body), 201)


# ---------------------------------------------------- required site (422) --

_ROUTE_SAMPLE = {
    "/ingest/pcap": "modbus_sample.pcap",
    "/ingest/pcap-fw": "modbus_sample.pcap",
    "/ingest/arp": "sample_arp_cisco.txt",
    "/ingest/firewall": "sample_firewall_cisco.txt",
    "/ingest/fortigate-config": "sample_fortigate_config.txt",
    "/ingest/switch": "sample_switch_running_config.txt",
    "/ingest/mac-table": "sample_mac_table_cisco.txt",
    "/ingest/baseline/comms-matrix": "sample_approved_comms.csv",
    "/ingest/baseline/approved-hosts": "sample_approved_hosts.csv",
    "/ingest/baseline/asset-inventory": "sample_asset_inventory.csv",
    "/ingest/baseline/reviewed-policies": "sample_approved_comms.csv",
}


def test_every_site_required_route_has_a_sample():
    assert set(_ROUTE_SAMPLE) == set(SITE_REQUIRED_ROUTES)


@pytest.mark.no_auto_site
@pytest.mark.parametrize("route", SITE_REQUIRED_ROUTES)
def test_upload_without_site_is_422(client, route):
    r = up(client, route, _ROUTE_SAMPLE[route])
    assert r.status_code == 422, r.text
    assert "'site' is required" in r.json()["detail"]
    r = up(client, route, _ROUTE_SAMPLE[route], {"site": "  "})
    assert r.status_code == 422 and "'site' is required" in r.json()["detail"]
    # nothing was stored
    with client.Session() as s:
        assert s.query(Host).count() == s.query(FirewallRule).count() == 0


@pytest.mark.no_auto_site
@pytest.mark.parametrize("route", SITE_REQUIRED_ROUTES)
def test_upload_with_unknown_site_is_422(client, route):
    _mk_site(client, "Plant A")
    r = up(client, route, _ROUTE_SAMPLE[route], {"site": "Plant Nowhere"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "Unknown site 'Plant Nowhere'" in detail and "Plant A" in detail
    assert up(client, route, _ROUTE_SAMPLE[route], {"site": "9999"}).status_code == 422


@pytest.mark.no_auto_site
def test_attestation_requires_site_form_field(client):
    form = {"checklist_id": "1.1", "attested_by": "a", "attested_at": "2026-09-01"}
    r = client.post("/attestation", data=form)
    assert r.status_code == 422 and "'site' is required" in r.json()["detail"]
    r = client.post("/attestation", data={**form, "site": "nope"})
    assert r.status_code == 422 and "Unknown site" in r.json()["detail"]
    a = _mk_site(client, "Plant A")
    j = _ok(client.post("/attestation", data={**form, "site": "plant-a"}), 201)
    assert j["site_id"] == a["id"]


@pytest.mark.no_auto_site
def test_site_accepts_id_name_or_code_case_insensitive(client):
    a = _mk_site(client, "Plant A", "pa")
    for ref in (str(a["id"]), "Plant A", "plant a", "PA", "pa"):
        j = _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt", {"site": ref}))
        assert (j["site_id"], j["site"]) == (a["id"], "Plant A"), ref


@pytest.mark.no_auto_site
def test_log_routes_do_not_require_site_and_route_per_device(client):
    """Phase 3: log routes never require a site.  Lines of unknown devices
    are held (unmapped_log_events), not stored in Default; ?site= maps them."""
    _mk_site(client, "Plant A")
    j = _ok(up(client, "/ingest/forti-syslog", "sample_forti_events.cef"))
    assert j["stats"]["events_created"] == 0 and j["stats"]["unmapped"] > 0
    _ok(up(client, "/ingest/syslog", "sample_syslog_asa.log",
           {"vendor_hint": "cisco_asa", "site": "default"}))
    with client.Session() as s:
        default_id = s.query(Site.id).filter(Site.code == "default").scalar()
        assert default_id is not None
        sites = {sid for (sid,) in s.query(FortiAnalyzerEvent.site_id).distinct()}
        assert sites == {default_id}


# ------------------------------------------------ rows get the upload's site --

@pytest.fixture
def two_sites(client):
    a = _mk_site(client, "Plant A")
    b = _mk_site(client, "Plant B")
    A, B = {"site": "Plant A"}, {"site": "plant-b"}
    _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt",
           {**A, "firewall_name": "FW-A"}))
    _ok(up(client, "/ingest/switch", "sample_switch_running_config.txt", {**A, "device_name": "SW-A"}))
    _ok(up(client, "/ingest/switch", "sample_switch_vlan_brief.txt", {**A, "device_name": "SW-A"}))
    _ok(up(client, "/ingest/mac-table", "sample_mac_table_cisco.txt", {**A, "device_name": "SW-A"}))
    _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt", A))
    _ok(up(client, "/ingest/firewall", "sample_firewall_cisco.txt",
           {**B, "firewall_device_name": "CISCO-B", "purdue_zone_from": 4, "purdue_zone_to": 3}))
    _ok(up(client, "/ingest/firewall", "sample_firewall_pfsense.xml",
           {**B, "firewall_device_name": "PF-B"}))
    _ok(up(client, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv",
           {**B, "baseline_name": "BL-B"}))
    _ok(up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv",
           {**B, "baseline_name": "BL-B"}))
    with client.Session() as s:
        hosts_before = {h for (h,) in s.query(Host.id)}
    _ok(up(client, "/ingest/pcap-fw", "modbus_sample.pcap", B))
    with client.Session() as s:
        b_pcap_hosts = {h for (h,) in s.query(Host.id)} - hosts_before
    _ok(client.post("/attestation", data={"checklist_id": "1.2", "attested_by": "x",
                                          "attested_at": "2026-09-01", "site": "Plant B"}), 201)
    return {"a": a["id"], "b": b["id"], "b_pcap_hosts": b_pcap_hosts}


def test_rows_get_the_upload_site(client, two_sites):
    a, b = two_sites["a"], two_sites["b"]
    with client.Session() as s:
        def sites(model, *filters):
            return {sid for (sid,) in s.query(model.site_id).filter(*filters).distinct()}

        assert sites(Firewall) == {a}
        assert sites(FirewallDevice, FirewallDevice.name == "FW-A") <= {a}
        assert sites(FirewallDevice, FirewallDevice.name.in_(["CISCO-B", "PF-B"])) == {b}
        assert sites(FirewallRule, FirewallRule.firewall_id.isnot(None)) == {a}
        assert sites(FirewallRule, FirewallRule.firewall_device_id.in_(
            s.query(FirewallDevice.id).filter(FirewallDevice.site_id == b))) == {b}
        assert sites(NatRule) <= {a}
        assert sites(FirewallZone) == {a}
        assert sites(SwitchInterface) == sites(SwitchVlan) == sites(MacTableEntry) == {a}
        assert sites(Baseline) == {b}
        assert sites(Attestation) == {b}
        assert sites(PcapCapture) == {b}
        assert sites(Finding) <= {a, b} and sites(Finding, Finding.rule_id.isnot(None)) <= {a, b}
        # findings about a rule are in that rule's site
        for f_site, r_site in s.query(Finding.site_id, FirewallRule.site_id).join(
                FirewallRule, FirewallRule.id == Finding.rule_id):
            assert f_site == r_site
        # hosts first seen in B's capture are B's
        assert two_sites["b_pcap_hosts"]
        assert sites(Host, Host.id.in_(two_sites["b_pcap_hosts"])) == {b}
        assert a in sites(Host)  # ARP / FortiGate address objects
        # no row anywhere fell back to the Default site
        default_id = s.query(Site.id).filter(Site.code == "default").scalar()
        for model in (Firewall, FirewallDevice, FirewallRule, Host, SwitchInterface,
                      Baseline, Attestation, PcapCapture, Finding):
            assert default_id not in sites(model), model.__name__


# ------------------------------------------------------------ list filters --

def test_site_id_filters_return_only_that_site(client, two_sites):
    a, b = two_sites["a"], two_sites["b"]

    def rows(path, site, key=None, **params):
        j = _ok(client.get(path, params={**params, "site_id": site}))
        return j[key] if key else j

    for path in ("/hosts", "/assets", "/findings", "/firewall-rules", "/firewall-devices",
                 "/switch-interfaces", "/baselines", "/attestation", "/firewall-zones",
                 "/nat-rules"):
        all_rows = _ok(client.get(path))
        ra, rb = rows(path, a), rows(path, b)
        assert all(r["site_id"] == a for r in ra), path
        assert all(r["site_id"] == b for r in rb), path
        assert len(ra) + len(rb) == len(all_rows), path
    assert rows("/firewall-devices", b) and rows("/switch-interfaces", b) == []
    assert {r["site_name"] for r in rows("/hosts", b)} == {"Plant B"}

    fws_b = rows("/topology/firewalls", b, "firewalls")
    assert fws_b == [] and len(rows("/topology/firewalls", a, "firewalls")) == 1
    assert rows("/topology/state", b, "firewalls") == []
    topo_b = rows("/topology", b)
    assert {n["site_id"] for n in topo_b["nodes"]} == {b}
    node_ids = {n["id"] for n in topo_b["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in topo_b["edges"])
    assert {d["name"] for d in topo_b["firewall_boundaries"]} == {"CISCO-B"}
    sess_b = rows("/sessions", b)
    assert sess_b and {x["site_id"] for x in sess_b} == {b}

    summ = _ok(client.get("/findings/summary", params={"site_id": a}))
    assert summ["site_id"] == a
    assert summ["total_open"] == len([f for f in rows("/findings", a, limit=5000)
                                      if f["status"] == "open"])
    # B-24: a site-filtered summary lists only that site in by_site
    assert [x["site_name"] for x in summ["by_site"]] == ["Plant A"]
    assert summ["by_site"][0]["open"] == summ["total_open"]
    summ_all = _ok(client.get("/findings/summary"))
    assert {x["site_name"] for x in summ_all["by_site"]} >= {"Plant A", "Plant B"}

    text = client.get("/findings/export", params={"site_id": b}).content.decode("utf-8-sig")
    assert {r["site_name"] for r in csv.DictReader(io.StringIO(text))} <= {"Plant B"}
    assert client.get("/findings/export/summary", params={"site_id": b}).status_code == 200
    text = client.get("/assets/export", params={"site_id": b}).content.decode("utf-8-sig")
    assert {r["site_name"] for r in csv.DictReader(io.StringIO(text))} == {"Plant B"}

    pdf = client.get("/reports/compliance.pdf", params={"site_id": b})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")

    for path in ("/hosts", "/findings", "/findings/summary", "/topology", "/reports/compliance.pdf"):
        r = client.get(path, params={"site_id": 999})
        assert r.status_code == 422 and "Unknown site_id" in r.json()["detail"], path


def test_report_scoping_counts_only_the_site(client, two_sites):
    import generate_report
    with client.Session() as s:
        data_b = generate_report.collect_report_data(s, site_id=two_sites["b"])
        data_all = generate_report.collect_report_data(s)
        n_b = s.query(Finding).filter(Finding.site_id == two_sites["b"],
                                      Finding.status.in_(["open", "acknowledged"])).count()
    assert len(data_b["findings"]) == n_b <= len(data_all["findings"])
    assert {d["name"] for d in data_b["firewall_devices"]} == {"CISCO-B", "PF-B"}


# ---------------------------------------------------------------- /sites --

def test_sites_crud_and_validation(client):
    sites = _ok(client.get("/sites"))
    assert [(x["name"], x["code"], x["is_default"]) for x in sites] == [("Default", "default", True)]
    a = _mk_site(client, "Plant A")
    assert a["code"] == "plant-a" and a["counts"] == {
        "firewalls": 0, "firewall_devices": 0, "hosts": 0, "open_findings": 0,
        "devices": 0, "unmapped_pending": 0, "conflicts_pending": 0}
    assert _ok(client.get(f"/sites/{a['id']}"))["name"] == "Plant A"
    assert client.get("/sites/9999").status_code == 404

    assert client.post("/sites", json={"name": "plant a"}).status_code == 409       # name, any case
    assert client.post("/sites", json={"name": "X", "code": "PLANT-A"}).status_code == 409
    assert client.post("/sites", json={"name": "plant-a", "code": "zz"}).status_code == 409  # = a code
    assert client.post("/sites", json={"name": "123"}).status_code == 422
    assert client.post("/sites", json={"name": "Y", "code": "bad code!"}).status_code == 422
    assert client.post("/sites", json={"name": ""}).status_code == 422
    assert client.post("/sites", json={}).status_code == 422

    j = _ok(client.patch(f"/sites/{a['id']}", json={"name": "Plant Alpha", "description": "north"}))
    assert (j["name"], j["code"], j["description"]) == ("Plant Alpha", "plant-a", "north")
    assert client.patch(f"/sites/{a['id']}", json={"code": "default"}).status_code == 409
    assert client.patch("/sites/9999", json={"name": "q"}).status_code == 404

    _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt", {"site": "plant-a"}))
    counts = {x["code"]: x["counts"] for x in _ok(client.get("/sites"))}
    assert counts["plant-a"]["hosts"] > 0 and counts["default"]["hosts"] == 0


def test_site_delete_gating(client, monkeypatch):
    a = _mk_site(client, "Plant A")
    b = _mk_site(client, "Plant B")
    _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt",
           {"site": "Plant A", "firewall_name": "FW-A"}))
    _ok(up(client, "/ingest/pcap", "modbus_sample.pcap", {"site": "Plant A"}))
    _ok(up(client, "/ingest/firewall", "sample_firewall_cisco.txt",
           {"site": "Plant B", "firewall_device_name": "CISCO-B"}))

    assert client.delete(f"/sites/{a['id']}").status_code == 403       # IACS_ENABLE_DELETE unset
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    r = client.delete(f"/sites/{a['id']}")
    assert r.status_code == 409 and "force=true" in r.json()["detail"] and "hosts" in r.json()["detail"]
    j = _ok(client.delete(f"/sites/{a['id']}", params={"force": "true"}))
    assert j["data_removed"]["firewalls"] == 1 and j["data_removed"]["hosts"] > 0
    with client.Session() as s:
        assert s.get(Site, a["id"]) is None
        for model in (Host, Firewall, FirewallRule, Finding, FirewallZone, PcapCapture):
            assert s.query(model).filter(model.site_id == a["id"]).count() == 0, model
        assert s.query(FirewallInterface).count() == 0
        assert s.query(NetworkSession).count() == 0
        # Plant B untouched
        assert s.query(FirewallRule).filter(FirewallRule.site_id == b["id"]).count() > 0
    # an empty site deletes without force; the last site never does
    default_id = next(x["id"] for x in _ok(client.get("/sites")) if x["code"] == "default")
    _ok(client.delete(f"/sites/{default_id}"))
    r = client.delete(f"/sites/{b['id']}", params={"force": "true"})
    assert r.status_code == 409 and "last remaining site" in r.json()["detail"]
    assert client.delete("/sites/9999").status_code == 404


# ------------------------------------------------- helpers / flush filling --

def test_resolve_site_and_flush_time_site_filling(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'u.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    with pytest.raises(SiteNotFound):
        resolve_site(s, None)
    default = get_default_site(s)
    assert (default.name, default.code) == ("Default", "default")
    b = Site(name="Plant B", code="pb")
    s.add(b)
    s.commit()
    assert resolve_site(s, "PB").id == resolve_site(s, "plant b").id == resolve_site(s, b.id).id == b.id
    with pytest.raises(SiteNotFound):
        resolve_site(s, "nope")

    # explicit > parent > ingest binding > Default
    fw = Firewall(name="fw", vendor="fortigate", site_id=b.id)
    s.add(fw)
    s.flush()
    rule = FirewallRule(device_type="fortigate", action="permit", firewall_id=fw.id)
    orphan = Host(ip="10.1.1.1")
    s.add_all([rule, orphan])
    s.flush()
    assert rule.site_id == b.id and orphan.site_id == default.id
    f = Finding(category="config_review", title="t", rule_id=rule.id)
    with ingest_site(s, default.id):          # parent wins over the binding
        s.add(f)
        bound = Host(ip="10.1.1.2")
        s.add(bound)
    with ingest_site(s, b.id):
        s.flush()
    assert f.site_id == b.id
    assert bound.site_id == default.id         # site remembered at add() time
    with ingest_site(s, b.id):
        late = Host(ip="10.1.1.3")
        s.add(late)
        s.flush()
    assert late.site_id == b.id
    s.close()
    engine.dispose()


def test_parser_entry_points_take_site_id():
    import inspect
    from app.parsers import (arp_parser, baseline_parser, firewall_parser, forti_config_parser,
                             mac_table_parser, pcap_parser, switch_parser)
    for fn in (arp_parser.ingest_arp_table, baseline_parser.ingest_approved_comms,
               baseline_parser.ingest_approved_hosts, baseline_parser.ingest_asset_inventory,
               baseline_parser.ingest_reviewed_policies, baseline_parser.get_or_create_baseline,
               firewall_parser.ingest_firewall_config, forti_config_parser.ingest_fortigate_config,
               mac_table_parser.ingest_mac_table, pcap_parser.ingest_pcap,
               switch_parser.ingest_switch_config):
        p = inspect.signature(fn).parameters.get("site_id")
        assert p is not None and p.default is None and p.kind is p.KEYWORD_ONLY, fn.__name__


def test_parser_called_directly_with_site_id(tmp_path):
    from app.parsers.arp_parser import ingest_arp_table
    engine = create_engine(f"sqlite:///{tmp_path / 'p.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    b = Site(name="Plant B", code="pb")
    s.add(b)
    s.commit()
    ingest_arp_table((SAMPLES / "sample_arp_cisco.txt").read_text(), s, site_id=b.id)
    s.commit()
    assert {sid for (sid,) in s.query(Host.site_id).distinct()} == {b.id}
    assert "iasc_ingest_site_id" not in s.info   # binding released after the call
    ingest_arp_table("Internet  10.77.0.1  0  aaaa.bbbb.cccc  ARPA  Vlan1\n", s)  # legacy: Default
    s.commit()
    assert s.query(Host).filter(Host.ip == "10.77.0.1").one().site_id == get_default_site(s).id
    s.close()
    engine.dispose()


# ------------------------------------------------------ migration backfill --

def test_migration_backfills_default_site(tmp_path):
    """Rows written before c0d1e2f3a4b5 (site_id NULL - as d4e5f6a7b8c9
    leaves them) end up in the Default site, NOT NULL."""
    from alembic import command
    from test_migrations import _cfg, _schema_diffs
    url = f"sqlite:///{tmp_path / 'm.db'}"
    command.upgrade(_cfg(url), "b9c0d1e2f3a4")
    eng = sa.create_engine(url)
    with eng.begin() as conn:
        conn.execute(sa.text("INSERT INTO hosts (ip) VALUES ('10.0.0.1'), ('10.0.0.2')"))
        conn.execute(sa.text("INSERT INTO findings (category, severity, status, title) "
                             "VALUES ('real_time', 'low', 'open', 'old')"))
        conn.execute(sa.text("INSERT INTO baselines (name) VALUES ('B0')"))
    command.upgrade(_cfg(url), "head")
    assert _schema_diffs(url) == []
    with eng.connect() as conn:
        did = conn.execute(sa.text("SELECT id FROM sites WHERE code='default'")).scalar()
        for t in ("hosts", "findings", "baselines"):
            assert conn.execute(sa.text(f"SELECT DISTINCT site_id FROM {t}")).scalars().all() == [did]
        cols = {c["name"]: c for c in sa.inspect(conn).get_columns("hosts")}
        assert cols["site_id"]["nullable"] is False
    eng.dispose()
