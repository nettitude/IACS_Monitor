"""
Findings next to their objects (owner, 2026-10-14: "how can host or firewall
rule list findings next to them so the finding can be edited easily").

GET /findings/linked returns the findings naming a host (address or MAC - a
multi-homed device's addresses share its MAC), a firewall policy (policy_id with
the firewall, or a firewall_rule_id), an IEC 62443 zone (by name, plus the
findings of its hosts) or a conduit; GET /findings/link-counts gives the badge
counts per object.  Open and acknowledged only, unless include_closed.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.finding_links import LinkIndex, finding_hosts
from app.models import (Finding, Firewall, FirewallRule, Host, IecConduit, IecConduitRule, IecZone,
                        IecZoneMember, Site)


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    """The seeded API (also used by tests/test_cov_routes.py)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'fl.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    s = Session()
    site = Site(name="L", code="l")
    other = Site(name="O", code="o")
    s.add_all([site, other])
    s.flush()
    sid = site.id
    mac = "28:cf:e9:18:b5:ed"
    a = Host(site_id=sid, ip="10.100.159.38", mac=mac)
    b = Host(site_id=sid, ip="192.168.88.52", mac=mac)
    plc = Host(site_id=sid, ip="10.10.1.10", mac="00:11:22:33:44:55")
    fw = Firewall(site_id=sid, name="FW-C", device_name="fgt-c")
    s.add_all([a, b, plc, fw])
    s.flush()
    rule = FirewallRule(site_id=sid, firewall_id=fw.id, device_name="fgt-c", device_type="fortigate",
                        policy_id="20", src="10.40.1.50", dst="10.10.1.10", action="accept")
    s.add(rule)
    s.flush()
    z1 = IecZone(site_id=sid, name="Control")
    z2 = IecZone(site_id=sid, name="Enterprise")
    s.add_all([z1, z2])
    s.flush()
    s.add(IecZoneMember(site_id=sid, zone_id=z1.id, kind="subnet", ref="10.10.1.0/24"))
    cd = IecConduit(site_id=sid, zone_a_id=z1.id, zone_b_id=z2.id, name="IT-OT")
    s.add(cd)
    s.flush()
    s.add(IecConduitRule(site_id=sid, conduit_id=cd.id, firewall_name="FW-C", vdom="", policy_id="20"))

    def F(check, detail, status="open", severity="medium", device_name=None, site=sid):
        f = Finding(site_id=site, category="periodic_review", check_name=check, severity=severity, status=status,
                    title=check, detail=detail, device_name=device_name)
        s.add(f)
        s.flush()
        return f.id
    ids = {
        "unknown": F("unknown_device", {"ip": "10.100.159.38", "mac": mac}, severity="high"),
        "mh": F("multi_homed_host", {"addresses": ["10.100.159.38", "192.168.88.52"]}),
        "write": F("unauthorized_industrial_write", {"src_ip": "10.40.1.50", "dst_ip": "10.10.1.10/32"}, severity="critical"),
        "policy": F("config_logging_disabled", {"policy_id": "20"}, device_name="fgt-c"),
        "rule_row": F("rule_it_ot_bypass", {"firewall_rule_id": rule.id}),
        "zone": F("undocumented_conduit", {"zone_a": "Control", "zone_b": "Enterprise"}),
        "closed": F("unknown_device", {"ip": "192.168.88.52"}, status="closed"),
        "fp": F("unknown_device", {"ip": "192.168.88.52"}, status="false_positive"),
        "other_site": F("unknown_device", {"ip": "192.168.88.52"}, site=other.id),
    }
    s.commit()
    hid = {"a": a.id, "b": b.id, "plc": plc.id}
    meta = {"fw": fw.id, "z1": z1.id, "cd": cd.id}
    s.close()
    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        try:
            yield c, sid, hid, meta, ids
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _ids(r):
    assert r.status_code == 200, r.text
    return {f["id"] for f in r.json()["findings"]}


def test_finding_hosts_reads_every_shape():
    ips, macs = finding_hosts({"ip": "10.0.0.1", "src_ip": "10.0.0.2/32", "addresses": ["10.0.0.3"],
                               "hosts": [{"ip": "10.0.0.4"}, "garbage"], "mac": "AA:BB:CC:DD:EE:FF",
                               "mac_addresses": ["00:11:22:33:44:55"]})
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
    assert macs == {"aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"}


def test_host_by_address_and_shared_mac(api):
    c, sid, hid, meta, ids = api
    # 192.168.88.52 has no finding naming its address except multi_homed_host, but shares the
    # MAC of 10.100.159.38 -> the unknown_device finding is listed on both addresses
    got = _ids(c.get("/findings/linked", params={"site_id": sid, "host_id": hid["b"]}))
    assert got == {ids["unknown"], ids["mh"]}
    j = c.get("/findings/linked", params={"site_id": sid, "host_id": hid["a"]}).json()
    assert j["summary"] == {"count": 2, "open": 2, "max_severity": "high"}
    assert j["findings"][0]["id"] == ids["unknown"]               # most severe first
    assert {"title", "status", "severity", "detail", "isa62443_sr"} <= set(j["findings"][0])


def test_closed_and_false_positive_only_on_request(api):
    c, sid, hid, meta, ids = api
    assert ids["closed"] not in _ids(c.get("/findings/linked", params={"site_id": sid, "ip": "192.168.88.52"}))
    got = _ids(c.get("/findings/linked", params={"site_id": sid, "ip": "192.168.88.52", "include_closed": True}))
    assert {ids["closed"], ids["fp"]} <= got and ids["other_site"] not in got


def test_policy_by_device_name_and_rule_row(api):
    c, sid, hid, meta, ids = api
    got = _ids(c.get("/findings/linked", params={"site_id": sid, "firewall_id": meta["fw"], "policy_id": "20"}))
    assert got == {ids["policy"], ids["rule_row"]}


def test_zone_and_conduit(api):
    c, sid, hid, meta, ids = api
    got = _ids(c.get("/findings/linked", params={"site_id": sid, "zone_id": meta["z1"]}))
    assert got == {ids["zone"], ids["write"]}                     # zone name + its host 10.10.1.10
    got = _ids(c.get("/findings/linked", params={"site_id": sid, "conduit_id": meta["cd"]}))
    assert got == {ids["zone"], ids["policy"], ids["rule_row"]}   # both zones + attached policy 20


def test_link_counts(api):
    c, sid, hid, meta, ids = api
    j = c.get("/findings/link-counts", params={"site_id": sid}).json()
    assert j["hosts"][str(hid["a"])]["count"] == 2 and j["hosts"][str(hid["plc"])]["max_severity"] == "critical"
    assert j["policies"][f"{meta['fw']}|20"]["count"] == 2
    assert j["zones"][str(meta["z1"])]["count"] == 2 and j["conduits"][str(meta["cd"])]["count"] == 3


def test_errors(api):
    c, sid, hid, meta, ids = api
    assert c.get("/findings/linked", params={"site_id": sid}).status_code == 422
    assert c.get("/findings/linked", params={"site_id": sid, "host_id": 999999}).status_code == 404
    assert c.get("/findings/linked", params={"site_id": 999999, "ip": "10.0.0.1"}).status_code == 422
