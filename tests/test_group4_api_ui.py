"""
Audit group 4 leftovers (docs/code-review-remediation.md B-23 / B-24):

  B-24c  /assets, /assets/export: ``location`` = free-text physical location,
         ``site`` / ``site_id`` = the multi-site filter; PATCH ?location=
  B-24d  /findings/summary by_site lists only the filtered site
  B-24e  auto-resolve for the session (review_ns_*) and VLAN reviews and for
         the cross-firewall checks (cross_fw_findings)
  B-23   static UI guards (per-view load guard, apiAll site capture, keyboard
         handlers, no innerHTML); the behaviour is covered by the browser
         smoke scripts (tests/ui_smoke_index.py, tests/ui_smoke_pages.py)
"""
import csv
import io
import re
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import (
    Finding, Firewall, FirewallInterface, FirewallRule, Host, MacTableEntry,
    NetworkSession, SwitchVlan,
)
from app.parsers import alert_engine as ae
from app.parsers.cross_fw_findings import run_cross_fw_checks
from tests.test_sites_phase3 import _api, _ok

pytestmark = pytest.mark.no_auto_site
UI = Path(__file__).resolve().parent.parent / "ui"


# ----------------------------------------------------------------- API (c/d)

@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "g4.db") as c:
        _ok(c.get("/sites"))
        c.site_a = _ok(c.post("/sites", json={"name": "Plant A", "code": "a"}), 201)["id"]
        c.site_b = _ok(c.post("/sites", json={"name": "Plant B", "code": "b"}), 201)["id"]
        with c.Session() as s:
            s.add_all([
                Host(site_id=c.site_a, ip="10.0.0.1", site="North hall"),
                Host(site_id=c.site_a, ip="10.0.0.2", site="South hall"),
                Host(site_id=c.site_b, ip="10.9.0.1", site="North hall"),
            ])
            for sid, n in ((c.site_a, 2), (c.site_b, 1)):
                for i in range(n):
                    s.add(Finding(site_id=sid, category="config_review", check_name="it_ot_bypass",
                                  severity="high", status="open", title=f"f{sid}-{i}",
                                  source_ref=f"g4:{sid}:{i}"))
            s.commit()
        yield c


def _ips(r):
    assert r.status_code == 200, r.text
    return sorted(a["ip"] for a in r.json())


def test_assets_site_is_multisite_filter_location_is_free_text(client):
    a, b = client.site_a, client.site_b
    assert _ips(client.get("/assets")) == ["10.0.0.1", "10.0.0.2", "10.9.0.1"]
    # site / site_id = the multi-site Site (id, name or code)
    assert _ips(client.get("/assets", params={"site_id": b})) == ["10.9.0.1"]
    assert _ips(client.get("/assets", params={"site": "a"})) == ["10.0.0.1", "10.0.0.2"]
    assert _ips(client.get("/assets", params={"site": "Plant B"})) == ["10.9.0.1"]
    assert _ips(client.get("/assets", params={"site": str(a), "site_id": a})) == ["10.0.0.1", "10.0.0.2"]
    # location = free-text physical location, across sites unless filtered
    assert _ips(client.get("/assets", params={"location": "north"})) == ["10.0.0.1", "10.9.0.1"]
    assert _ips(client.get("/assets", params={"location": "north", "site_id": a})) == ["10.0.0.1"]
    # "site" is no longer a text match: a location string is an unknown site
    r = client.get("/assets", params={"site": "North hall"})
    assert r.status_code == 422 and "Unknown site" in r.json()["detail"]
    r = client.get("/assets", params={"site": "a", "site_id": b})
    assert r.status_code == 422 and "disagree" in r.json()["detail"]
    assert client.get("/assets", params={"site_id": 9999}).status_code == 422


def test_assets_export_site_and_location(client):
    def ips(params):
        r = client.get("/assets/export", params=params)
        assert r.status_code == 200, r.text
        return sorted(row["ip"] for row in csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert ips({"site": "b"}) == ["10.9.0.1"]
    assert ips({"site_id": client.site_a, "location": "south"}) == ["10.0.0.2"]
    assert ips({"location": "NORTH"}) == ["10.0.0.1", "10.9.0.1"]
    assert client.get("/assets/export", params={"site": "nope"}).status_code == 422


def test_patch_asset_location(client):
    hid = next(a["id"] for a in client.get("/assets").json() if a["ip"] == "10.0.0.2")
    j = _ok(client.patch(f"/assets/{hid}", params={"location": "Panel room 3"}))
    assert j["site"] == "Panel room 3" and j["site_id"] == client.site_a
    assert j["site_name"] == "Plant A"
    # ?site= is not an inventory field any more (and never moves the host)
    j = _ok(client.patch(f"/assets/{hid}", params={"site": "b", "owner": "ops"}))
    assert (j["site"], j["site_id"], j["owner"]) == ("Panel room 3", client.site_a, "ops")


def test_findings_summary_by_site_filtered(client):
    a, b = client.site_a, client.site_b
    allsum = _ok(client.get("/findings/summary"))
    assert {x["site_id"]: x["open"] for x in allsum["by_site"]}.items() >= {a: 2, b: 1}.items()
    s = _ok(client.get("/findings/summary", params={"site_id": b}))
    assert s["by_site"] == [{"site_id": b, "site_name": "Plant B", "open": 1}]
    assert s["total_open"] == 1
    s = _ok(client.get("/findings/summary", params={"site_id": a}))
    assert [(x["site_id"], x["open"]) for x in s["by_site"]] == [(a, 2)]


# ---------------------------------------------------------- auto-resolve (e)

@pytest.fixture
def db(monkeypatch):
    monkeypatch.delenv("IACS_AUTO_RESOLVE", raising=False)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def _host(db, ip, level=None, **kw):
    h = db.query(Host).filter(Host.ip == ip).first()
    if h is None:
        h = Host(ip=ip, purdue_level=level, **kw)
        db.add(h)
        db.flush()
    return h


def _sess(db, src, dst, port, src_level=None, dst_level=None):
    s, d = _host(db, src, src_level), _host(db, dst, dst_level)
    db.add(NetworkSession(src_host_id=s.id, dst_host_id=d.id, src_port=40000 + port,
                          dst_port=port, transport="tcp", packet_count=3))
    db.flush()


def _status(db, check):
    return sorted(f.status for f in db.query(Finding).filter(Finding.check_name == check))


def test_auto_resolve_table_covers_new_reviews():
    for name in ("review_ns_it_ot_bypass", "review_ns_ot_internet_egress",
                 "review_ns_remote_access_bypass", "review_ns_scanning_anomaly",
                 "review_ns_mgmt_from_non_admin", "review_vlan_zone_mismatch",
                 "review_ghost_vlans", "review_intervlan_routing"):
        assert name in ae._AUTO_RESOLVE_CHECKS
        assert callable(getattr(ae, name))
    for name in ("review_denied_trends", "review_ntp_sync",
                 "review_single_path_critical_devices", "review_no_path_redundancy",
                 "review_firmware_not_documented"):
        assert name not in ae._AUTO_RESOLVE_CHECKS
    # AU full review B5: the zone-documentation checks are re-derived from
    # the current hosts / zones every run, so they auto-resolve like the rest.
    assert ae._AUTO_RESOLVE_CHECKS["review_zone_documentation"] == tuple(f"zone_doc_1_{i}" for i in range(1, 7))
    from app.models import CHECK_TYPE_REFERENCE
    for names in ae._AUTO_RESOLVE_CHECKS.values():
        for cn in names:
            assert CHECK_TYPE_REFERENCE[cn][3] == "periodic_review", cn


def test_session_it_ot_bypass_closes_when_fixed(db):
    _sess(db, "10.4.0.10", "10.1.0.20", 502, src_level=4, dst_level=1)
    _sess(db, "10.2.0.5", "10.1.0.20", 502, src_level=2, dst_level=1)   # not a bypass
    ae.run_periodic_reviews(db)
    assert _status(db, "session_it_ot_bypass") == ["open"]
    # fix: the IT host is re-classified into the control zone (L2 -> L1 is fine)
    db.query(Host).filter(Host.ip == "10.4.0.10").one().purdue_level = 2
    db.commit()
    ae.run_periodic_reviews(db)
    assert _status(db, "session_it_ot_bypass") == ["closed"]
    assert ae.auto_resolved_counts(db).get("review_ns_it_ot_bypass") == 1
    f = db.query(Finding).filter(Finding.check_name == "session_it_ot_bypass").one()
    assert f.notes.startswith("Auto-resolved") and f.closed_at is not None


def test_session_findings_kept_without_session_data(db):
    _sess(db, "10.4.0.10", "10.1.0.20", 502, src_level=4, dst_level=1)
    ae.run_periodic_reviews(db)
    assert _status(db, "session_it_ot_bypass") == ["open"]
    db.query(Finding).update({Finding.session_id: None})
    db.query(NetworkSession).delete()
    db.commit()
    ae.run_periodic_reviews(db)        # empty table = no data, not "fixed"
    assert _status(db, "session_it_ot_bypass") == ["open"]


def test_session_unknown_level_keeps_finding(db):
    _sess(db, "10.4.0.10", "10.1.0.20", 502, src_level=4, dst_level=1)
    ae.run_periodic_reviews(db)
    db.query(Host).filter(Host.ip == "10.1.0.20").one().purdue_level = None
    db.commit()
    ae.run_periodic_reviews(db)        # B-20: cannot be re-evaluated -> kept
    assert _status(db, "session_it_ot_bypass") == ["open"]
    assert ae.last_review_info()["skipped_unknown_level"].get("review_ns_it_ot_bypass") == 1


def test_faz_covered_flow_keeps_session_finding(db):
    _sess(db, "10.4.0.10", "10.1.0.20", 502, src_level=4, dst_level=1)
    ae.run_periodic_reviews(db)
    assert _status(db, "session_it_ot_bypass") == ["open"]
    db.info[ae._SEEN_KEY] = seen = set()
    try:
        cover = ae._FazCoverage(db, "it_ot_bypass", "session_it_ot_bypass")
        cover.flows.add(("10.4.0.10", "10.1.0.20", 502))
        cover._cache[("10.4.0.10", "10.1.0.20", 502, "tcp")] = True
        # C-01: covers() now takes the session's src_port and canonicalises to
        # the (client, server, server_port) identity (ephemeral 50000 -> :502).
        assert cover.covers("10.4.0.10", 50000, "10.1.0.20", 502, "tcp")
    finally:
        db.info.pop(ae._SEEN_KEY, None)
    f = db.query(Finding).filter(Finding.check_name == "session_it_ot_bypass").one()
    assert f.source_ref in seen


def test_ghost_vlan_closes_when_vlan_activated(db):
    sv = SwitchVlan(device_name="SW1", vlan_id=99, vlan_name="OLD", status="inactive")
    db.add_all([sv, MacTableEntry(device_name="SW1", port_name="Gi0/5",
                                  mac="aa:bb:cc:dd:ee:01", vlan="99")])
    db.commit()
    ae.run_periodic_reviews(db)
    assert _status(db, "ghost_vlan") == ["open"]
    sv.status = "active"
    db.commit()
    ae.run_periodic_reviews(db)
    assert _status(db, "ghost_vlan") == ["closed"]


def test_vlan_zone_mismatch_closes_and_acknowledged_kept(db):
    db.add_all([
        SwitchVlan(device_name="SW1", vlan_id=30, vlan_name="CELL", purdue_level=1,
                   purdue_level_source="keyword_inferred"),
        SwitchVlan(device_name="SW1", vlan_id=40, vlan_name="CELL2", purdue_level=1,
                   purdue_level_source="keyword_inferred"),
    ])
    _host(db, "10.1.0.2", 3, vlan="30", classification_source="protocol_inferred")
    _host(db, "10.1.0.3", 3, vlan="40", classification_source="protocol_inferred")
    db.commit()
    ae.run_periodic_reviews(db)
    assert _status(db, "vlan_zone_mismatch") == ["open", "open"]
    ack = next(f for f in db.query(Finding).filter(Finding.check_name == "vlan_zone_mismatch")
               if f.detail["host_ip"] == "10.1.0.3")
    ack.status, ack.acknowledged_by = "acknowledged", "alice"
    for ip in ("10.1.0.2", "10.1.0.3"):
        db.query(Host).filter(Host.ip == ip).one().purdue_level = 1   # fixed
    db.commit()
    ae.run_periodic_reviews(db)
    assert _status(db, "vlan_zone_mismatch") == ["acknowledged", "closed"]


def test_auto_resolve_disabled_by_env(db, monkeypatch):
    sv = SwitchVlan(device_name="SW1", vlan_id=99, vlan_name="OLD", status="inactive")
    db.add_all([sv, MacTableEntry(device_name="SW1", port_name="Gi0/5",
                                  mac="aa:bb:cc:dd:ee:01", vlan="99")])
    db.commit()
    ae.run_periodic_reviews(db)
    sv.status = "active"
    db.commit()
    monkeypatch.setenv("IACS_AUTO_RESOLVE", "false")
    ae.run_periodic_reviews(db)
    assert _status(db, "ghost_vlan") == ["open"]


def _linked_fws(db):
    fa, fb = Firewall(name="FW-A", vendor="other"), Firewall(name="FW-B", vendor="other")
    db.add_all([fa, fb])
    db.flush()
    ia = FirewallInterface(firewall_id=fa.id, name="port9")
    ib = FirewallInterface(firewall_id=fb.id, name="port9")
    db.add_all([ia, ib])
    db.flush()
    ia.connects_to_interface_id, ib.connects_to_interface_id = ib.id, ia.id
    rules = []
    for fw, pid in ((fa, "7"), (fb, "8")):
        r = FirewallRule(firewall_id=fw.id, device_type="other", src="any", dst="any", protocol="any",
                         dst_port="any", action="permit", enabled=True, policy_id=pid,
                         src_zone="port9", dst_zone="port9")
        rules.append(r)
        db.add(FirewallRule(firewall_id=fw.id, device_type="other", src="any", dst="any", protocol="any",
                            dst_port="any", action="deny", enabled=True, policy_id="99",
                            src_zone="port9", dst_zone="port9"))
    db.add_all(rules)
    db.flush()
    return fa, fb, ia, ib, rules


def test_cross_fw_findings_auto_resolve(db):
    fa, fb, ia, ib, rules = _linked_fws(db)
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["auto_resolved"] == 0
    assert _status(db, "cross_fw_any_any_permit") == ["open", "open"]
    # acknowledge FW-B's finding; fix both rules
    fb_f = db.query(Finding).filter(Finding.check_name == "cross_fw_any_any_permit",
                                    Finding.device_name == "FW-B").one()
    fb_f.status, fb_f.acknowledged_by = "acknowledged", "bob"
    for r in rules:
        r.dst = "10.1.0.0/24"
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert _status(db, "cross_fw_any_any_permit") == ["acknowledged", "closed"]
    assert out["auto_resolved"] >= 1
    closed = db.query(Finding).filter(Finding.check_name == "cross_fw_any_any_permit",
                                      Finding.status == "closed").one()
    assert closed.device_name == "FW-A" and "Auto-resolved" in closed.notes
    # the condition comes back -> the closed finding is reopened (same source_ref)
    rules[0].dst = "any"
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    assert _status(db, "cross_fw_any_any_permit") == ["acknowledged", "open"]


def test_cross_fw_unresolvable_rule_keeps_finding(db):
    fa, fb, ia, ib, rules = _linked_fws(db)
    run_cross_fw_checks(db)
    db.commit()
    rules[0].src = "UNRESOLVED_OBJECT"          # cannot tell any-any any more
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    assert _status(db, "cross_fw_any_any_permit") == ["open", "open"]


def test_cross_fw_unlinked_findings_close(db):
    fa, fb, ia, ib, rules = _linked_fws(db)
    run_cross_fw_checks(db)
    db.commit()
    assert _status(db, "cross_fw_any_any_permit") == ["open", "open"]
    ia.connects_to_interface_id = ib.connects_to_interface_id = None
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["links_analysed"] == 0
    assert _status(db, "cross_fw_any_any_permit") == ["closed", "closed"]


# ------------------------------------------------------------ UI static (B-23)

PAGES = ["index.html", "findings.html", "fw_topology.html", "attestation.html"]   # /ui/topology = index.html


@pytest.mark.parametrize("page", PAGES + ["upload.html"])
def test_ui_no_innerhtml(page):
    src = (UI / page).read_text(encoding="utf-8")
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write", src)


@pytest.mark.parametrize("page", PAGES)
def test_ui_view_loaders_use_load_guard(page):
    src = (UI / page).read_text(encoding="utf-8")
    assert "function beginLoad(view)" in src and ".stale()" in src
    assert "ctrl.abort()" in src            # superseded request is aborted


def test_index_every_loader_guarded_and_apiall_captures_site():
    src = (UI / "index.html").read_text(encoding="utf-8")
    loaders = re.findall(r"^async function (load\w+)\(", src, re.M)
    for name in loaders:
        if name in ("loadSites", "loadPurdueLevels"):          # global, not per site
            continue
        body = src.split(f"async function {name}(", 1)[1].split("\nasync function ", 1)[0]
        assert "beginLoad(" in body, f"{name} has no load guard"
    assert "async function apiAll(path, pageSize = 10000, opts = {})" in src
    assert "opts.site !== undefined" in src                  # withSiteFilter honours a captured site
    assert "abortAllLoads()" in src


def test_index_keyboard_operable_rows_and_headers():
    src = (UI / "index.html").read_text(encoding="utf-8")
    assert "function onActivate(fn)" in src
    for marker in ("class: `finding-row", "class: 'host-node'", "class: 'iface-card'"):
        chunk = src.split(marker, 1)[1][:900]
        assert "tabindex: 0" in chunk and "role: 'button'" in chunk and "onkeydown" in chunk, marker
    # the table is built in assetsRenderTableNow (assetsRenderTable wraps it in keepScroll)
    assets = src.split("function assetsRenderTableNow()", 1)[1].split("\nfunction ", 1)[0]
    assert "'aria-sort'" in assets and "th-btn" in assets and "'aria-selected'" in assets
    assert ":focus-visible" in src
    # B-24: the asset location is written via ?location=, never ?site=
    assert "['site', 'Location', 'text', 'location']" in src
