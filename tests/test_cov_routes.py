"""
F-01: HTTP-level coverage for every API route (TestClient, temp-file SQLite,
get_db override, init_db and the scheduler disabled).

ROUTE TABLE - every @router / @app route and the test(s) that exercise it.
test_every_route_is_listed_in_the_table parses the route decorators in
app/api/routes.py and app/main.py and fails when a route is missing here (or
listed here but gone), and when a test named here does not exist.

    METHOD  PATH                                     TESTS
    POST    /ingest/pcap                             test_ingest_pcap, test_ingest_pcap_errors
    POST    /ingest/arp                              test_ingest_arp
    POST    /ingest/firewall                         test_ingest_firewall
    POST    /ingest/fortigate-config                 test_ingest_fortigate_config, test_ingest_fortigate_config_errors
    POST    /ingest/switch                           test_ingest_switch
    POST    /ingest/mac-table                        test_ingest_mac_table
    GET     /switch-interfaces                       test_switch_interfaces
    POST    /classify                                test_classify
    GET     /purdue-levels                           test_purdue_levels
    PATCH   /hosts/{host_id}/classification          test_host_classification
    DELETE  /hosts/{host_id}/classification          test_host_classification
    GET     /hosts/{host_id}/classification-suggestion  test_host_classification_suggestion
    GET     /subnets                                 test_subnet_zones
    POST    /subnets                                 test_subnet_zones
    DELETE  /subnets/{zone_id}                       test_subnet_zones
    GET     /iec-zones                               test_iec_zones_members
    GET     /iec-zones/candidates                    test_iec_zones_members
    POST    /iec-zones                               test_iec_zones_members
    PATCH   /iec-zones/{zone_id}                     test_iec_zone_edits
    DELETE  /iec-zones/{zone_id}                     test_iec_conduits
    POST    /iec-zones/{zone_id}/members             test_iec_zones_members
    DELETE  /iec-zones/members/{member_id}           test_iec_zone_edits
    POST    /iec-zones/import                        test_iec_zones_import
    GET     /iec-zones/export                        test_iec_conduits
    GET     /iec-conduits                            test_iec_conduits
    POST    /iec-conduits                            test_iec_conduits
    PATCH   /iec-conduits/{conduit_id}               test_iec_zone_edits
    PATCH   /firewalls/{firewall_id}/sl-c            test_iec_sl_c
    DELETE  /iec-conduits/{conduit_id}               test_iec_zone_edits
    POST    /iec-conduits/{conduit_id}/rules         test_iec_conduit_rules
    DELETE  /iec-conduits/{conduit_id}/rules/{rule_id}  test_iec_conduit_rules
    GET     /external-comms                          test_external_comms
    POST    /external-comms/review                   test_external_comms
    DELETE  /external-comms/review/{review_id}       test_external_comms
    PATCH   /hosts/{host_id}/role                    test_host_role
    GET     /hosts                                   test_hosts_list
    POST    /hosts/mark-stale                        test_hosts_mark_stale
    GET     /hosts/{host_id}/history                 test_host_history
    GET     /assets                                  test_assets_list
    PATCH   /assets/{host_id}                        test_asset_update
    GET     /assets/export                           test_assets_export
    GET     /sessions                                test_sessions_list
    GET     /sessions/{session_id}/details           test_session_details
    GET     /firewall-rules                          test_firewall_rules
    GET     /firewall-rules/shadowed                 test_firewall_rules_shadowed
    GET     /firewall-zones                          test_firewall_zones
    GET     /nat-rules                               test_nat_rules
    GET     /firewall-devices                        test_firewall_devices
    GET     /topology/subnets                        test_subnet_topology
    GET     /topology/ports                          test_port_topology
    PATCH   /firewall-devices/{device_id}/boundary   test_firewall_device_boundary
    GET     /findings                                test_findings_list
    GET     /findings/linked                         test_findings_linked
    GET     /findings/export.xlsx                    test_findings_workbook
    GET     /findings/{finding_id}/config-snippet    test_firewall_config_text
    GET     /firewalls/{firewall_id}/config          test_firewall_config_text
    GET     /firewalls/{firewall_id}/config/block    test_firewall_config_text
    POST    /findings/import.xlsx                    test_findings_workbook
    GET     /reports/check-selection                 test_report_check_selection
    GET     /reports/details                         test_report_details
    PUT     /reports/details                         test_report_details
    PUT     /reports/check-selection                 test_report_check_selection
    GET     /findings/link-counts                    test_findings_linked
    GET     /findings/summary                        test_findings_summary
    GET     /findings/export                         test_findings_export
    GET     /findings/export/summary                 test_findings_export_summary
    GET     /findings/category-reference             test_findings_category_reference
    PATCH   /findings/{finding_id}/status            test_finding_status
    POST    /findings/scan-industrial-writes         test_scan_industrial_writes
    GET     /reachability                            test_reachability
    GET     /reachability/path                       test_reachability_path
    GET     /access-paths                            test_access_paths
    POST    /access-paths/classify                   test_access_paths_classify
    GET     /access-paths/hops                       test_access_path_hops
    POST    /access-paths/hops                       test_access_path_hops
    DELETE  /access-paths/hops/{hop_id}              test_access_path_hops
    GET     /diff                                    test_diff
    GET     /topology                                test_topology
    POST    /ingest/forti-event                      test_ingest_forti_event
    POST    /ingest/forti-syslog                     test_ingest_forti_syslog
    POST    /ingest/syslog                           test_ingest_syslog_multi_vendor
    POST    /ingest/forti-report                     test_ingest_forti_report
    POST    /ingest/baseline/comms-matrix            test_baseline_comms_matrix
    POST    /ingest/baseline/approved-hosts          test_baseline_approved_hosts
    POST    /ingest/baseline/asset-inventory         test_baseline_asset_inventory
    POST    /ingest/baseline/asset-inventory/preview  test_inventory_import_routes
    GET     /ingest/baseline/asset-inventory/mappings  test_inventory_import_routes
    DELETE  /ingest/baseline/asset-inventory/mappings/{mapping_id}  test_inventory_import_routes
    POST    /ingest/baseline/reviewed-policies       test_baseline_reviewed_policies
    POST    /reviews/run                             test_reviews_run
    GET     /reviews/rules-not-judged                test_rules_not_judged_route
    GET     /reviews/schedule                        test_review_schedule_route
    PUT     /reviews/schedule                        test_review_schedule_route
    GET     /diagnostics                             test_diagnostics
    GET     /baselines                               test_baselines_list_and_activate
    POST    /baselines/{baseline_name}/activate      test_baselines_list_and_activate
    GET     /attestation                             test_attestation_flow
    POST    /attestation                             test_attestation_flow, test_attestation_errors
    GET     /attestation/{attestation_id}/proof      test_attestation_flow
    GET     /attestation/current                     test_attestation_flow
    GET     /topology/state                          test_topology_multi_fw_workflow
    POST    /topology/confirm-link                   test_topology_multi_fw_workflow
    POST    /topology/confirm-segment                test_topology_confirm_segment
    GET     /topology/firewall-groups                test_topology_firewall_groups
    POST    /topology/ha-pairs                       test_topology_firewall_groups
    POST    /topology/paired-firewalls               test_topology_firewall_groups
    DELETE  /topology/firewall-groups/{group_id}     test_topology_firewall_groups
    GET     /management/networks                     test_management_networks_routes
    POST    /management/networks                     test_management_networks_routes
    DELETE  /management/networks/{decl_id}           test_management_networks_routes
    GET     /management/fix-options                  test_management_networks_routes
    POST    /management/recheck                      test_management_networks_routes
    GET     /findings/{finding_id}/explanation       test_finding_explanation_route
    GET     /vpn/groups                              test_vpn_groups_routes
    POST    /vpn/groups                              test_vpn_groups_routes
    DELETE  /vpn/groups/{decl_id}                    test_vpn_groups_routes
    POST    /topology/set-interface-side             test_topology_set_interface_side
    POST    /ingest/pcap-fw                          test_pcap_fw_and_confirm
    POST    /ingest/pcap/{capture_id}/confirm        test_pcap_fw_and_confirm
    POST    /ingest/pcap/{capture_id}/associate      test_pcap_capture_point_routes
    GET     /ingest/pcap/captures                    test_pcap_capture_point_routes
    POST    /topology/run-checks                     test_topology_multi_fw_workflow
    POST    /topology/set-upstream                   test_topology_set_upstream
    POST    /topology/suggest-purdue                 test_topology_suggest_purdue
    GET     /topology/firewalls                      test_topology_multi_fw_workflow
    DELETE  /findings/{finding_id}                   test_delete_disabled_by_default, test_delete_finding
    DELETE  /attestation/{attestation_id}            test_delete_disabled_by_default, test_delete_attestation
    DELETE  /firewall-devices/{device_id}            test_delete_disabled_by_default, test_delete_firewall_device
    DELETE  /baselines/{baseline_name}               test_delete_disabled_by_default, test_delete_baseline
    DELETE  /hosts/{host_id}                         test_delete_disabled_by_default, test_delete_host
    GET     /sites                                   test_sites_routes
    POST    /sites                                   test_sites_routes
    GET     /sites/rollup                            test_sites_routes
    GET     /sites/{site_id}                         test_sites_routes
    PATCH   /sites/{site_id}                         test_sites_routes
    DELETE  /sites/{site_id}                         test_sites_routes
    GET     /site-devices                            test_site_devices_routes
    GET     /site-devices/unmapped                   test_site_devices_routes
    POST    /site-devices/unmapped/discard           test_site_devices_routes
    POST    /site-devices/unmapped/purge             test_site_devices_routes
    POST    /site-devices                            test_site_devices_routes
    PATCH   /site-devices/{device_id}                test_site_devices_routes
    DELETE  /site-devices/{device_id}                test_site_devices_routes
    POST    /site-devices/{device_id}/serials        test_site_device_serial_routes
    DELETE  /site-devices/{device_id}/serials/{serial} test_site_device_serial_routes
    GET     /site-devices/conflicts                  test_site_device_conflict_routes
    POST    /site-devices/conflicts/resolve          test_site_device_conflict_routes
    GET     /site-devices/conflicts/resolutions      test_site_device_conflict_routes
    GET     /reports/compliance.pdf                  test_compliance_pdf
    GET     /ui/attestation                          test_ui_pages
    GET     /ui/topology                             test_ui_pages
    GET     /ui/fw-topology                          test_ui_pages
    GET     /ui/upload                               test_ui_pages
    GET     /ui/findings                             test_ui_pages
    GET     /                                        test_root_redirects_to_ui
    GET     /ui                                      test_ui_pages
    GET     /ui/                                     test_ui_pages
    GET     /health                                  test_health
"""
import csv
import io
import re
import shutil
import textwrap
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.api.routes as routes_mod
import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    CHECK_TYPE_REFERENCE, Attestation, Finding, FirewallDevice, FirewallInterface,
    Host, NetworkSession,
)

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"


# --------------------------------------------------------------- fixtures --

@contextmanager
def _api(db_path: Path):
    """TestClient on a file SQLite DB built from Base.metadata."""
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


def up(c, url, name, params=None, content=None):
    data = content if content is not None else (SAMPLES / name).read_bytes()
    return c.post(url, params=params or {},
                  files={"file": (name, data, "application/octet-stream")})


def _ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.text[:500])
    return r.json()


def seed_all(c):
    """Every sample through the API, in the ui_demo_server.seed() order."""
    _ok(up(c, "/ingest/fortigate-config", "sample_fortigate_config.txt", {"firewall_name": "FW-OT"}))
    _ok(up(c, "/ingest/firewall", "sample_firewall_cisco.txt",
           {"firewall_device_name": "CISCO-EDGE", "purdue_zone_from": 4, "purdue_zone_to": 3}))
    _ok(up(c, "/ingest/firewall", "sample_firewall_pfsense.xml", {"firewall_device_name": "PFSENSE-LAB"}))
    _ok(up(c, "/ingest/firewall", "sample_firewall_panos.xml", {"firewall_device_name": "PA-XML"}))
    _ok(up(c, "/ingest/firewall", "sample_firewall_panos_set.txt", {"firewall_device_name": "PA-SET"}))
    for f in ("sample_switch_running_config.txt", "sample_switch_vlan_brief.txt",
              "sample_switch_lldp_neighbors.txt", "sample_switch_cdp_neighbors.txt"):
        _ok(up(c, "/ingest/switch", f, {"device_name": "SW-CORE"}))
    for f in ("sample_switch_hp_running_config.txt", "sample_switch_hp_lldp_brief.txt",
              "sample_switch_hp_lldp_detail.txt"):
        _ok(up(c, "/ingest/switch", f, {"device_name": "SW-HP", "vendor_hint": "hp"}))
    _ok(up(c, "/ingest/mac-table", "sample_mac_table_cisco.txt", {"device_name": "SW-CORE"}))
    _ok(up(c, "/ingest/mac-table", "sample_mac_table_hp.txt", {"device_name": "SW-HP"}))
    for f in ("sample_arp_cisco.txt", "sample_arp_unix.txt", "sample_arp_windows.txt"):
        _ok(up(c, "/ingest/arp", f))
    _ok(up(c, "/ingest/pcap", "multi_protocol_sample.pcap"))
    _ok(up(c, "/ingest/pcap", "modbus_sample.pcap"))
    _ok(up(c, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {"baseline_name": "B1"}))
    _ok(up(c, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {"baseline_name": "B1"}))
    _ok(up(c, "/ingest/baseline/asset-inventory", "sample_asset_inventory.csv", {"baseline_name": "B1"}))
    _ok(up(c, "/ingest/forti-syslog", "sample_forti_events.cef"))
    _ok(up(c, "/ingest/forti-report", "sample_forti_traffic.csv"))
    for f in ("sample_syslog_asa.log", "sample_syslog_panos.log", "sample_syslog_pfsense.log"):
        _ok(up(c, "/ingest/syslog", f))


@pytest.fixture(scope="module")
def seeded_db(tmp_path_factory):
    path = tmp_path_factory.mktemp("cov_routes") / "seed.db"
    with _api(path) as c:
        seed_all(c)
        _ok(c.post("/reviews/run"))
    return path


@pytest.fixture
def seeded(seeded_db, tmp_path):
    """Private, mutable copy of the fully seeded database."""
    copy = tmp_path / "seeded.db"
    shutil.copy(seeded_db, copy)
    with _api(copy) as c:
        yield c


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "empty.db") as c:
        yield c


@pytest.fixture
def deletes_on(monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")


# ------------------------------------------------------- route table guard --

_DECORATOR_RE = re.compile(r'@(?:router|app)\.(get|post|put|patch|delete)\(\s*"([^"]*)"')
_TABLE_RE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE)\s+(/\S*)\s+(test_\w+(?:\s*,\s*test_\w+)*)\s*$",
                       re.M)


def _declared_routes():
    out = set()
    for p in (ROOT / "app" / "api" / "routes.py", ROOT / "app" / "main.py"):
        for m in _DECORATOR_RE.finditer(p.read_text(encoding="utf-8")):
            out.add((m.group(1).upper(), m.group(2)))
    return out


def _table():
    return {(m.group(1), m.group(2)): [t.strip() for t in m.group(3).split(",")]
            for m in _TABLE_RE.finditer(__doc__)}


def test_every_route_is_listed_in_the_table():
    declared, table = _declared_routes(), _table()
    assert len(declared) >= 70
    missing = sorted(declared - set(table))
    stale = sorted(set(table) - declared)
    assert not missing, f"routes without an entry in the test_cov_routes table: {missing}"
    assert not stale, f"table entries for routes that no longer exist: {stale}"
    undefined = sorted({t for tests in table.values() for t in tests} - set(globals()))
    assert not undefined, f"table names tests that do not exist: {undefined}"


# ------------------------------------------------------------------ ingest --

def test_ingest_pcap(client):
    j = _ok(up(client, "/ingest/pcap", "multi_protocol_sample.pcap"))
    st = j["stats"]
    assert j["filename"] == "multi_protocol_sample.pcap"
    for k in ("packets", "hosts", "sessions", "protocol_frames", "classification",
              "industrial_write_check"):
        assert k in st
    assert st["packets"] > 0 and st["sessions"] > 0
    protos = {s["protocol"] for s in client.get("/sessions").json()}
    assert {"dnp3", "s7comm", "ethernet_ip"} <= protos


def test_ingest_pcap_errors(client, monkeypatch):
    r = up(client, "/ingest/pcap", "junk.pcap", content=b"this is not a pcap file" * 10)
    assert r.status_code == 415     # B-08: header checked before parsing
    assert "Not a pcap/pcapng capture" in r.json()["detail"]
    assert client.get("/hosts").json() == []
    monkeypatch.setattr(routes_mod, "_MAX_PCAP_BYTES", 100)
    assert up(client, "/ingest/pcap", "modbus_sample.pcap").status_code == 413
    assert client.post("/ingest/pcap").status_code == 422  # no file


def test_ingest_arp(client):
    j = _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt", {"format_hint": "cisco"}))
    assert j["stats"]["entries_found"] > 0 and j["stats"]["format_hint_used"] == "cisco"
    assert "classification" in j["stats"]
    assert any(h["mac"] for h in client.get("/hosts").json())
    r = up(client, "/ingest/arp", "x.txt", content=b"nothing that looks like arp\n")
    assert r.status_code == 422 and "No ARP entries" in r.json()["detail"]


def test_ingest_firewall(client):
    j = _ok(up(client, "/ingest/firewall", "sample_firewall_cisco.txt",
               {"firewall_device_name": "EDGE", "purdue_zone_from": "4", "purdue_zone_to": "L3.5"}))
    st = j["stats"]
    assert st["device_type"] == "cisco_ios" and st["rules_created"] > 0
    assert (st["purdue_zone_from"], st["purdue_zone_to"]) == (4, 3.5)
    dev = client.get("/firewall-devices").json()[0]
    assert dev["name"] == "EDGE" and dev["boundary_tagged"] is True
    # unknown format / mismatched vendor hint / bad level
    assert up(client, "/ingest/firewall", "x.txt", content=b"hello world",
              params={"firewall_device_name": "GHOST"}).status_code == 422
    # regression: a rejected upload must not leave a FirewallDevice behind
    assert [d["name"] for d in client.get("/firewall-devices").json()] == ["EDGE"]
    # regression: XML-vendor hint on non-XML text was an uncaught ParseError (500)
    for hint, body in (("pfsense", (SAMPLES / "sample_firewall_cisco.txt").read_bytes()),
                       ("palo_alto", b"<config><broken"),
                       (None, b"<pfsense><filter><rule>")):
        r = up(client, "/ingest/firewall", "f.cfg", content=body,
               params={"vendor_hint": hint} if hint else None)
        assert r.status_code == 422 and "Could not detect config format" in r.json()["detail"], hint
    r = up(client, "/ingest/firewall", "sample_firewall_cisco.txt", {"purdue_zone_from": "7"})
    assert r.status_code == 422 and "purdue_zone_from" in r.json()["detail"]


def test_ingest_fortigate_config(client):
    j = _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt",
               {"firewall_name": "FW-OT", "populate_approved_hosts": "true",
                "baseline_name": "FROM-FGT"}))
    assert j["firewall_name"] == "FW-OT"
    assert j["topology_state"] == "single" and j["is_multi_fw"] is False
    st = j["stats"]
    for k in ("rules_created", "interfaces_created", "findings_created", "firewall_id",
              "firewall_device_id", "classification", "nat_rules_created"):
        assert k in st
    assert st["rules_created"] > 0 and st["findings_created"] > 0
    assert "FROM-FGT" in {b["name"] for b in client.get("/baselines").json()}
    cats = client.get("/findings/summary").json()["by_category"]
    assert cats.get("config_review", 0) > 0
    # second, different firewall -> multi
    j2 = _ok(up(client, "/ingest/fortigate-config", "fw2.conf",
                content=_FW2_CONF.encode(), params={"generate_findings": "false"}))
    assert j2["firewall_name"] == "FW-Core"  # AU D9: config hostname beats the filename stem
    assert j2["is_multi_fw"] is True and j2["topology_state"] == "multi"


def test_ingest_fortigate_config_errors(client):
    r = up(client, "/ingest/fortigate-config", "empty.txt", content=b"   \n")
    assert r.status_code == 422 and r.json()["detail"] == "File is empty."
    r = up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt",
           {"purdue_zone_from": "banana"})
    assert r.status_code == 422
    assert client.post("/ingest/fortigate-config").status_code == 422


def test_ingest_switch(client):
    j = _ok(up(client, "/ingest/switch", "sample_switch_running_config.txt"))
    assert j["stats"]["config_type"] != "unknown" and j["stats"]["interfaces_touched"] > 0
    j = _ok(up(client, "/ingest/switch", "sample_switch_hp_lldp_detail.txt",
               {"device_name": "SW-HP", "vendor_hint": "hp"}))
    assert j["stats"]["vendor_hint_used"] == "hp"
    r = up(client, "/ingest/switch", "sample_switch_vlan_brief.txt", {"vendor_hint": "hp"})
    assert r.status_code == 422
    assert up(client, "/ingest/switch", "x.txt", content=b"lorem ipsum").status_code == 422


def test_ingest_mac_table(client):
    _ok(up(client, "/ingest/arp", "sample_arp_cisco.txt"))
    j = _ok(up(client, "/ingest/mac-table", "sample_mac_table_cisco.txt", {"device_name": "SW1"}))
    st = j["stats"]
    assert st["entries_found"] > 0 and st["table_type"] != "unknown" and "classification" in st
    j = _ok(up(client, "/ingest/mac-table", "sample_mac_table_hp.txt", {"vendor_hint": "hp"}))
    assert j["stats"]["entries_found"] > 0
    r = up(client, "/ingest/mac-table", "x.txt", content=b"no mac table here")
    assert r.status_code == 422 and "vendor_hint" in r.json()["detail"]


# ---------------------------------------------------------- simple getters --

def test_switch_interfaces(seeded):
    r = seeded.get("/switch-interfaces")
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows) > 0
    assert {"device_name", "port_name", "vlan", "vlan_name", "neighbor_device",
            "neighbor_protocol"} <= set(rows[0])
    only = seeded.get("/switch-interfaces", params={"device_name": "SW-HP"}).json()
    assert only and {i["device_name"] for i in only} == {"SW-HP"}
    page = seeded.get("/switch-interfaces", params={"limit": 2, "offset": 1}).json()
    assert [p["id"] for p in page] == [p["id"] for p in rows[1:3]]
    assert seeded.get("/switch-interfaces", params={"limit": 0}).status_code == 422


def test_classify(seeded):
    j = _ok(seeded.post("/classify"))
    assert "subnet_inference" in j and isinstance(j["subnet_inference"], dict)
    assert seeded.get("/classify").status_code == 405


def test_purdue_levels(client):
    j = _ok(client.get("/purdue-levels"))
    levels = [lv["level"] for lv in j["levels"]]
    assert levels == sorted(levels) and 3.5 in levels and {0, 5} <= set(levels)
    assert {"level", "label", "name", "is_dmz"} <= set(j["levels"][0])
    dts = {d["device_type"]: d for d in j["device_types"]}
    assert "plc" in dts and {"purdue_level", "label"} <= set(dts["plc"])


def _host_id(c, ip=None):
    hosts = c.get("/hosts").json()
    if ip:
        hosts = [h for h in hosts if h["ip"] == ip]
    return hosts[0]["id"]


def test_host_classification_level_only(seeded):
    """Host Topology drag and drop between levels (owner 2026-10-13): purdue_level
    without device_type sets the level manually and keeps the device type."""
    hid = _host_id(seeded)
    _ok(seeded.patch(f"/hosts/{hid}/classification", params={"device_type": "historian"}))
    j = _ok(seeded.patch(f"/hosts/{hid}/classification", params={"purdue_level": "2", "apply_to_same_mac": "true"}))
    assert (j["device_type"], j["purdue_level"], j["classification_source"]) == ("historian", 2, "manual")
    seeded.post("/classify")                       # manual survives re-classification
    h = [x for x in seeded.get("/hosts").json() if x["id"] == hid][0]
    assert (h["device_type"], h["purdue_level"]) == ("historian", 2)
    r = seeded.patch(f"/hosts/{hid}/classification")
    assert r.status_code == 400 and "device_type, purdue_level" in r.json()["detail"]
    # an unclassified host dropped on a lane: level set, no device type invented
    other = [x for x in seeded.get("/hosts").json() if x["id"] != hid and x.get("classification_source") != "manual"][0]
    j = _ok(seeded.patch(f"/hosts/{other['id']}/classification", params={"purdue_level": "dmz"}))
    assert j["purdue_level"] == 3.5 and j["device_type"] == other["device_type"]


def test_host_classification_pin_unclassified(seeded):
    """Host Topology drop on Unclassified (owner 2026-10-13): unclassified=true pins
    the host without a level (manual, type kept); /classify does not place it again;
    DELETE returns it to automatic classification."""
    hosts = seeded.get("/hosts").json()
    h = next(x for x in hosts if x.get("purdue_level") is not None and x.get("classification_source") != "manual")
    j = _ok(seeded.patch(f"/hosts/{h['id']}/classification", params={"unclassified": "true"}))
    assert (j["purdue_level"], j["classification_source"], j["device_type"]) == (None, "manual", h["device_type"])
    seeded.post("/classify")
    again = next(x for x in seeded.get("/hosts").json() if x["id"] == h["id"])
    assert (again["purdue_level"], again["classification_source"]) == (None, "manual")
    assert seeded.patch(f"/hosts/{h['id']}/classification",
                        params={"unclassified": "true", "purdue_level": "3"}).status_code == 400
    _ok(seeded.delete(f"/hosts/{h['id']}/classification"))
    back = next(x for x in seeded.get("/hosts").json() if x["id"] == h["id"])
    assert back["classification_source"] != "manual"


def test_host_classification(seeded):
    hid = _host_id(seeded)
    j = _ok(seeded.patch(f"/hosts/{hid}/classification", params={"device_type": "plc"}))
    assert j == {"id": hid, "device_type": "plc", "purdue_level": 1,
                 "classification_source": "manual", "updated_ids": [hid]}
    j = _ok(seeded.patch(f"/hosts/{hid}/classification",
                         params={"device_type": "jump_host", "purdue_level": "dmz"}))
    assert j["purdue_level"] == 3.5
    # manual survives re-classification
    seeded.post("/classify")
    h = [x for x in seeded.get("/hosts").json() if x["id"] == hid][0]
    assert (h["device_type"], h["purdue_level"]) == ("jump_host", 3.5)
    assert seeded.patch("/hosts/999999/classification", params={"device_type": "plc"}).status_code == 404
    r = seeded.patch(f"/hosts/{hid}/classification", params={"device_type": "toaster"})
    assert r.status_code == 400 and "no default purdue_level" in r.json()["detail"]
    assert seeded.patch(f"/hosts/{hid}/classification",
                        params={"device_type": "plc", "purdue_level": "9"}).status_code == 422
    # router: infrastructure, no level needed
    j = _ok(seeded.patch(f"/hosts/{hid}/classification", params={"device_type": "router"}))
    assert (j["device_type"], j["purdue_level"]) == ("router", None)
    # back to automatic
    j = _ok(seeded.delete(f"/hosts/{hid}/classification"))
    assert j["cleared"] == [hid] and j["hosts"][0]["classification_source"] != "manual"
    assert seeded.delete("/hosts/999999/classification").status_code == 404


def test_subnet_zones(tmp_path):
    from tests.test_subnet_zones import test_subnet_zones as _t
    _t(tmp_path)


def test_iec_zones_members(tmp_path):
    from tests.test_iec_zones import test_zones_span_levels_and_networks as _t
    _t(tmp_path)


def test_iec_conduits(tmp_path):
    from tests.test_iec_zones import test_conduits_policies_traffic_and_undocumented_pairs as _t
    _t(tmp_path)


def test_iec_conduit_rules(tmp_path, monkeypatch):
    from tests.test_sl0_conduit_rules import api_ctx, test_attach_rules_details_and_zone_check as _a, \
        test_validation_duplicates_and_detach as _b
    for sub, fn in (("a", _a), ("b", _b)):
        (tmp_path / sub).mkdir()
        with api_ctx(tmp_path / sub, monkeypatch) as x:
            fn(x)


def test_report_details(tmp_path, monkeypatch):
    import tests.test_report_details as trd
    with trd.api_ctx(tmp_path, monkeypatch) as x:
        trd.test_details_defaults_store_and_site_scope(x)


def test_report_check_selection(tmp_path, monkeypatch):
    import tests.test_report_checks as trc
    with trc.api_ctx(tmp_path, monkeypatch) as x:
        trc.test_selection_lists_every_check(x)
        trc.test_exclude_group_with_reason_per_site_and_put_back(x)


def test_findings_workbook(tmp_path, monkeypatch):
    import tests.test_findings_workbook as tfw
    with tfw.api_ctx(tmp_path, monkeypatch) as x:
        tfw.test_export_contents(x)
        tfw.test_round_trip_updates_status_name_and_notes(x)


def test_port_topology(tmp_path, monkeypatch):
    import tests.test_port_topology as tpt
    with tpt.api_ctx(tmp_path, monkeypatch) as x:
        tpt.test_ports_subnets_and_links(x)


def test_subnet_topology(tmp_path, monkeypatch):
    import tests.test_subnet_topology as tst
    with tst.api_ctx(tmp_path, monkeypatch) as x:
        tst.test_lanes_functions_and_separators(x)


def test_firewall_config_text(tmp_path, monkeypatch):
    import tests.test_config_store as tcs
    with tcs.api_ctx(tmp_path, monkeypatch) as x:
        tcs.test_config_stored_masked_and_served(x)
        tcs.test_snippets_policy_interface_admin_and_section(x)
        tcs.test_interface_block_fortios(x)


def test_findings_linked(tmp_path, monkeypatch):
    import tests.test_finding_links as tfl
    with tfl.api_ctx(tmp_path, monkeypatch) as x:
        for name in ("test_host_by_address_and_shared_mac", "test_policy_by_device_name_and_rule_row",
                     "test_zone_and_conduit", "test_link_counts"):
            getattr(tfl, name)(x)


def test_iec_zones_import(tmp_path):
    from tests.test_iec_zones import test_import_from_subnet_zones_and_fortigate as _t
    _t(tmp_path)


def test_iec_sl_c(tmp_path):
    from tests.test_iec_zones import test_sl_c_on_hosts_zones_and_conduit_firewalls as _t
    _t(tmp_path)


def test_iec_zone_edits(tmp_path):
    from tests.test_iec_zones import test_zone_and_conduit_edits as _t
    _t(tmp_path)


def test_external_comms(tmp_path):
    from tests.test_external_comms import test_external_comms_view_and_reviews as _t
    _t(tmp_path)


def test_host_classification_suggestion(seeded):
    hid = _host_id(seeded)
    j = _ok(seeded.get(f"/hosts/{hid}/classification-suggestion"))
    assert j["host"]["id"] == hid and isinstance(j["suggestions"], list) and "evidence" in j
    for sg in j["suggestions"]:
        assert {"device_type", "label", "purdue_level", "confidence", "reasons"} <= set(sg)
    assert seeded.get("/hosts/999999/classification-suggestion").status_code == 404


def test_host_role(seeded):
    hid = _host_id(seeded)
    j = _ok(seeded.patch(f"/hosts/{hid}/role", params={"role": "historian"}))
    assert (j["role"], j["role_source"]) == ("historian", "manual") and {"ip", "mac"} <= set(j)
    assert [h["id"] for h in seeded.get("/hosts", params={"role": "historian"}).json()] == [hid]
    j = _ok(seeded.patch(f"/hosts/{hid}/role", params={"role": ""}))
    assert j["role"] is None and j["role_source"] is None
    assert seeded.patch("/hosts/999999/role", params={"role": "plc"}).status_code == 404
    assert seeded.patch(f"/hosts/{hid}/role").status_code == 422


def test_hosts_list(seeded):
    r = seeded.get("/hosts")
    hosts = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(hosts) > 5
    assert {"id", "ip", "mac", "vendor", "hostname", "device_type", "purdue_level",
            "classification_source", "role", "vlan", "sources", "stale"} <= set(hosts[0])
    lvl = next(h["purdue_level"] for h in hosts if h["purdue_level"] is not None)
    sel = seeded.get("/hosts", params={"purdue_level": lvl}).json()
    assert sel and all(h["purdue_level"] == lvl for h in sel)
    dt = next(h["device_type"] for h in hosts if h["device_type"])
    assert all(h["device_type"] == dt for h in seeded.get("/hosts", params={"device_type": dt}).json())
    assert seeded.get("/hosts", params={"purdue_level": "L9"}).status_code == 422
    assert seeded.get("/hosts", params={"limit": 10001}).status_code == 422


def test_hosts_mark_stale(seeded):
    j = _ok(seeded.post("/hosts/mark-stale", params={"older_than_days": 3650}))
    assert {"cutoff", "older_than_days", "marked_stale", "cleared", "stale_total"} <= set(j)
    assert j["stale_total"] == 0
    with seeded.Session() as s:
        s.query(Host).update({Host.last_seen: Host.first_seen})  # keep non-null
        h = s.query(Host).filter(Host.last_seen.isnot(None)).first()
        from datetime import datetime, timedelta, timezone
        h.last_seen = datetime.now(timezone.utc) - timedelta(days=400)
        s.commit()
        hid = h.id
    j = _ok(seeded.post("/hosts/mark-stale", params={"older_than_days": 30}))
    assert j["marked_stale"] >= 1
    assert [h for h in seeded.get("/hosts").json() if h["id"] == hid][0]["stale"] is True
    assert seeded.post("/hosts/mark-stale", params={"older_than_days": -1}).status_code == 422


def test_host_history(seeded):
    hid = next(h["id"] for h in seeded.get("/hosts").json()
               if h["mac"] and h["ip"] and "arp" in (h["sources"] or []))
    j = _ok(seeded.get(f"/hosts/{hid}/history"))
    assert j["host_id"] == hid and {"ip", "mac", "stale", "history"} <= set(j)
    assert isinstance(j["history"], list) and j["history"]
    assert {"ip", "mac", "source"} <= set(j["history"][0])
    assert seeded.get("/hosts/999999/history").status_code == 404


def test_assets_list(seeded):
    r = seeded.get("/assets")
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows)
    assert {"criticality", "approved", "protocols", "site", "asset_tag", "model"} <= set(rows[0])
    assert any(row["protocols"] for row in rows)  # joined from ProtocolDetail
    hid = rows[0]["id"]
    seeded.patch(f"/assets/{hid}", params={"approved": "true", "location": "North Plant",
                                            "criticality": "high", "model": "S7-1500"})
    assert [a["id"] for a in seeded.get("/assets", params={"approved": "true"}).json()] == [hid]
    assert hid not in [a["id"] for a in seeded.get("/assets", params={"approved": "null"}).json()]
    assert seeded.get("/assets", params={"approved": "false"}).json() == []
    assert [a["id"] for a in seeded.get("/assets", params={"location": "north"}).json()] == [hid]
    assert [a["id"] for a in seeded.get("/assets", params={"criticality": "high"}).json()] == [hid]
    assert hid in [a["id"] for a in seeded.get("/assets", params={"search": "s7-15"}).json()]
    assert seeded.get("/assets", params={"purdue_level": "x"}).status_code == 422


def test_asset_update(seeded):
    hid = _host_id(seeded)
    j = _ok(seeded.patch(f"/assets/{hid}", params={
        "model": "M", "serial_number": "SN1", "firmware_version": "1.2", "building": "B",
        "panel": "P", "owner": "ops", "asset_tag": "AT-1", "notes": "n",
        "is_safety_function": "true", "approved": "false", "approved_by": "alice",
        "last_reviewed_by": "bob", "criticality": "low"}))
    assert (j["model"], j["serial_number"], j["is_safety_function"], j["approved"]) == \
        ("M", "SN1", True, False)
    assert j["approved_by"] == "alice" and j["approved_at"] and j["last_reviewed_at"]
    r = seeded.patch(f"/assets/{hid}", params={"criticality": "extreme"})
    assert r.status_code == 400 and "criticality" in r.json()["detail"]
    assert seeded.patch("/assets/999999", params={"model": "x"}).status_code == 404


def test_assets_export(seeded):
    hid = _host_id(seeded)
    seeded.patch(f"/assets/{hid}", params={"approved": "true", "location": "Plant-7",
                                            "criticality": "medium", "is_safety_function": "true"})
    r = seeded.get("/assets/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="iacs_asset_inventory_' in r.headers["content-disposition"]
    assert r.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert len(rows) == len(seeded.get("/hosts").json())
    assert {"asset_tag", "ip", "protocols", "approved", "purdue_level"} <= set(rows[0])
    sel = list(csv.DictReader(io.StringIO(seeded.get(
        "/assets/export", params={"approved": "true", "location": "plant", "criticality": "medium"}
    ).content.decode("utf-8-sig"))))
    assert len(sel) == 1 and sel[0]["approved"] == "yes" and sel[0]["is_safety_function"] == "yes"
    assert len(list(csv.DictReader(io.StringIO(seeded.get(
        "/assets/export", params={"approved": "false"}).content.decode("utf-8-sig"))))) == 0
    nul = seeded.get("/assets/export", params={"approved": "unset", "purdue_level": 1})
    assert nul.status_code == 200
    assert seeded.get("/assets/export", params={"purdue_level": "99"}).status_code == 422


def test_sessions_list(seeded):
    r = seeded.get("/sessions")
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows) > 0
    assert {"src_host", "dst_host", "dst_port", "protocol", "packet_count", "byte_count"} <= set(rows[0])
    assert {"id", "ip", "mac"} <= set(rows[0]["src_host"])
    modbus = seeded.get("/sessions", params={"protocol": "modbus"}).json()
    assert modbus and {s["protocol"] for s in modbus} == {"modbus"}
    assert seeded.get("/sessions", params={"offset": -1}).status_code == 422


def test_session_details(seeded):
    sid = seeded.get("/sessions", params={"protocol": "modbus"}).json()[0]["id"]
    r = seeded.get(f"/sessions/{sid}/details")
    rows = _ok(r)
    assert rows and int(r.headers["X-Total-Count"]) >= len(rows)
    assert {"protocol", "direction", "summary", "fields", "timestamp"} <= set(rows[0])
    assert seeded.get("/sessions/999999/details").status_code == 404


def test_firewall_rules(seeded):
    r = seeded.get("/firewall-rules")
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows) > 0
    assert {"policy_id", "src", "dst", "dst_port", "action", "enabled", "rule_order",
            "firewall_device_id", "firewall_id", "last_matched"} <= set(rows[0])
    devs = {d["name"]: d["id"] for d in seeded.get("/firewall-devices").json()}
    cisco = seeded.get("/firewall-rules", params={"firewall_device_id": devs["CISCO-EDGE"]}).json()
    assert cisco and {x["device_type"] for x in cisco} == {"cisco_ios"}
    assert seeded.get("/firewall-rules", params={"device_type": "cisco_ios"}).json() == cisco
    denies = seeded.get("/firewall-rules", params={"action": "deny"}).json()
    assert denies and {x["action"] for x in denies} == {"deny"}
    fw = [x for x in rows if x["firewall_id"]][0]
    assert seeded.get("/firewall-rules", params={"firewall_id": fw["firewall_id"]}).json()
    assert seeded.get("/firewall-rules", params={"device_name": fw["device_name"]}).json()
    assert all(x["enabled"] is False
               for x in seeded.get("/firewall-rules", params={"enabled": "false"}).json())
    assert seeded.get("/firewall-rules", params={"firewall_device_id": "abc"}).status_code == 422


def test_firewall_rules_shadowed(seeded):
    j = _ok(seeded.get("/firewall-rules/shadowed"))
    assert {"shadows", "unanalysed_rules", "rules_analysed", "devices_analysed",
            "findings_created"} <= set(j)
    assert j["rules_analysed"] > 0 and j["findings_created"] == 0
    devs = {d["name"]: d["id"] for d in seeded.get("/firewall-devices").json()}
    scoped = _ok(seeded.get("/firewall-rules/shadowed",
                            params={"firewall_device_id": devs["CISCO-EDGE"],
                                    "include_partial": "false"}))
    assert scoped["devices_analysed"] == 1
    assert all(s["shadow_type"] != "partial_shadow" for s in scoped["shadows"])
    gen = _ok(seeded.get("/firewall-rules/shadowed", params={"generate_findings": "true"}))
    assert gen["findings_created"] >= 0
    assert seeded.get("/firewall-rules/shadowed",
                      params={"generate_findings": "maybe"}).status_code == 422


def test_firewall_zones(seeded):
    rows = _ok(seeded.get("/firewall-zones"))
    assert rows and {"device_name", "interface_name", "zone_name", "ip_cidr", "vlan_id"} <= set(rows[0])
    name = rows[0]["device_name"]
    assert {z["device_name"] for z in seeded.get("/firewall-zones",
                                                 params={"device_name": name}).json()} == {name}
    assert seeded.get("/firewall-zones", params={"device_name": "nope"}).json() == []


def test_nat_rules(client):
    _ok(up(client, "/ingest/fortigate-config", "nat.conf", content=_FORTI_NAT.encode(),
           params={"firewall_name": "FW-NAT", "generate_findings": "false"}))
    r = client.get("/nat-rules")
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows) >= 3
    assert {"nat_type", "name", "ext_ip", "ext_port", "mapped_ip", "mapped_port", "orig_src",
            "firewall_id", "firewall_device_id", "enabled"} <= set(rows[0])
    dnat = client.get("/nat-rules", params={"nat_type": "DNAT"}).json()
    hmi = [n for n in dnat if n["name"] == "VIP-HMI"][0]
    assert (hmi["ext_ip"], hmi["mapped_ip"]) == ("203.0.113.10/32", "10.0.1.20/32")
    assert {n["nat_type"] for n in client.get("/nat-rules", params={"nat_type": "snat"}).json()} == {"snat"}
    assert client.get("/nat-rules", params={"firewall_id": 99999}).json() == []
    assert client.get("/nat-rules", params={"firewall_device_id": hmi["firewall_device_id"]}).json()
    assert client.get("/nat-rules", params={"nat_type": "pat"}).status_code == 422


def test_firewall_devices(seeded):
    rows = _ok(seeded.get("/firewall-devices"))
    by = {d["name"]: d for d in rows}
    assert {"FW-OT", "CISCO-EDGE", "PFSENSE-LAB"} <= set(by)
    assert {"vendor", "boundary_tagged", "rule_count", "disabled_rule_count",
            "firewall_id", "purdue_zone_from", "purdue_zone_to"} <= set(rows[0])
    assert by["CISCO-EDGE"]["boundary_tagged"] and by["CISCO-EDGE"]["rule_count"] > 0
    tagged = seeded.get("/firewall-devices", params={"purdue_zone_from": 4, "purdue_zone_to": 3}).json()
    assert [d["name"] for d in tagged] == ["CISCO-EDGE"]
    assert [d["name"] for d in seeded.get("/firewall-devices",
                                          params={"vendor": "pfsense"}).json()] == ["PFSENSE-LAB"]
    assert seeded.get("/firewall-devices", params={"purdue_zone_to": "6"}).status_code == 422


def test_firewall_device_boundary(seeded):
    dev = [d for d in seeded.get("/firewall-devices").json() if d["name"] == "PFSENSE-LAB"][0]
    j = _ok(seeded.patch(f"/firewall-devices/{dev['id']}/boundary",
                         params={"purdue_zone_from": "L3.5"}))
    assert j["purdue_zone_from"] == 3.5 and j["purdue_zone_to"] is None and j["updated"]
    j = _ok(seeded.patch(f"/firewall-devices/{dev['id']}/boundary", params={"purdue_zone_to": 2}))
    assert (j["purdue_zone_from"], j["purdue_zone_to"]) == (3.5, 2)
    names = [b["name"] for b in seeded.get("/topology").json()["firewall_boundaries"]]
    assert "PFSENSE-LAB" in names
    assert seeded.patch("/firewall-devices/99999/boundary",
                        params={"purdue_zone_to": 2}).status_code == 404
    assert seeded.patch(f"/firewall-devices/{dev['id']}/boundary",
                        params={"purdue_zone_to": "-1"}).status_code == 422


# ---------------------------------------------------------------- findings --

def test_findings_list(seeded):
    r = seeded.get("/findings", params={"limit": 5000})
    rows = _ok(r)
    assert int(r.headers["X-Total-Count"]) == len(rows) > 0
    assert {"id", "created_at", "category", "check_name", "severity", "status", "isa62443_sr",
            "checklist_id", "title", "detail", "device_name"} <= set(rows[0])
    for key in ("severity", "category", "check_name", "status"):
        val = rows[0][key]
        sub = seeded.get("/findings", params={key: val, "limit": 5000}).json()
        assert sub and all(f[key] == val for f in sub)
    sr = next(f["isa62443_sr"] for f in rows if f["isa62443_sr"])
    assert all(f["isa62443_sr"] == sr for f in seeded.get("/findings", params={"isa62443_sr": sr}).json())
    dn = next(f["device_name"] for f in rows if f["device_name"])
    assert all(f["device_name"] == dn for f in seeded.get("/findings", params={"device_name": dn}).json())
    q = seeded.get("/findings", params={"q": "UNKNOWN_DEV", "limit": 5000}).json()
    assert q and {f["check_name"] for f in q} == {"unknown_device"}
    assert seeded.get("/findings", params={"q": "%"}).json() == []  # wildcard escaped
    assert seeded.get("/findings", params={"q": "x" * 201}).status_code == 422


def test_findings_summary(seeded):
    j = _ok(seeded.get("/findings/summary"))
    assert set(j) == {"total_open", "by_severity", "by_category", "by_check_name", "by_status",
                      "target_sl", "fr", "by_security_level", "by_fr",
                      "site_id", "by_site"}  # multi-site: per-site open counts
    assert sum(x["open"] for x in j["by_site"]) == j["total_open"]
    assert j["total_open"] == sum(j["by_severity"].values()) == sum(j["by_check_name"].values())
    assert j["by_status"]["open"] == j["total_open"]


def test_findings_export(seeded):
    r = seeded.get("/findings/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    total = int(seeded.get("/findings", params={"limit": 1}).headers["X-Total-Count"])
    assert len(rows) == total
    assert {"finding_id", "check_name", "isa_sr", "firewall_id", "src_ip", "dst_port",
            "source_ref"} <= set(rows[0])
    hi = list(csv.DictReader(io.StringIO(seeded.get(
        "/findings/export", params={"severity": "critical,high", "status": "open",
                                    "category": "config_review,real_time"}
    ).content.decode("utf-8-sig"))))
    assert hi and {x["severity"] for x in hi} <= {"critical", "high"}
    assert {x["category"] for x in hi} <= {"config_review", "real_time"}
    one = list(csv.DictReader(io.StringIO(seeded.get(
        "/findings/export", params={"check_name": "unknown_device", "since": "2000-01-01",
                                    "until": "2999-12-31"}).content.decode("utf-8-sig"))))
    assert one and {x["check_name"] for x in one} == {"unknown_device"}
    assert len(list(csv.DictReader(io.StringIO(seeded.get(
        "/findings/export", params={"until": "2000-01-01T00:00:00"}).content.decode("utf-8-sig"))))) == 0
    # firewall_id filter matches int and str JSON values
    with seeded.Session() as s:
        s.add(Finding(category="config_review", check_name="config_logging_disabled",
                      severity="low", title="fid-int", detail={"firewall_id": 777}))
        s.add(Finding(category="config_review", check_name="config_logging_disabled",
                      severity="low", title="fid-str", detail={"fw_id": "777"}))
        s.commit()
    fid = list(csv.DictReader(io.StringIO(seeded.get(
        "/findings/export", params={"firewall_id": "777"}).content.decode("utf-8-sig"))))
    assert sorted(x["title"] for x in fid) == ["fid-int", "fid-str"]
    assert seeded.get("/findings/export", params={"since": "yesterday"}).status_code == 400
    assert seeded.get("/findings/export", params={"until": "2026-13-45"}).status_code == 400


def test_findings_export_summary(seeded):
    r = seeded.get("/findings/export/summary")
    assert r.status_code == 200 and "iasc_summary_" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows and set(rows[0]) == {"checklist_id", "isa_sr", "critical", "high", "medium",
                                     "low", "info", "total", "worst_severity"}
    total_open = seeded.get("/findings/summary").json()["total_open"]
    assert sum(int(x["total"]) for x in rows) == total_open
    for x in rows:
        sev = [s for s in ("critical", "high", "medium", "low", "info") if int(x[s])]
        assert x["worst_severity"] == (sev[0] if sev else "none")
    keys = [x["checklist_id"] for x in rows]
    numeric = [k for k in keys if re.fullmatch(r"[\d.]+", k)]
    assert numeric == sorted(numeric, key=lambda k: [int(p) for p in k.split(".")])
    closed = list(csv.DictReader(io.StringIO(seeded.get(
        "/findings/export/summary", params={"status": "closed", "since": "2000-01-01",
                                            "until": "2999-01-01"}).content.decode("utf-8-sig"))))
    assert closed == []
    assert seeded.get("/findings/export/summary", params={"until": "nope"}).status_code == 400


def test_findings_category_reference(client):
    rows = _ok(client.get("/findings/category-reference"))
    names = {r["check_name"] for r in rows}
    assert set(CHECK_TYPE_REFERENCE) <= names
    assert {"cross_fw_any_any_permit", "unauthorized_industrial_write"} <= names
    assert set(rows[0]) == {"check_name", "isa62443_sr", "checklist_id", "default_severity", "category",
                            "fr", "security_level"}
    assert client.post("/findings/category-reference").status_code == 405


def test_finding_status(seeded):
    fid = seeded.get("/findings", params={"limit": 1}).json()[0]["id"]
    j = _ok(seeded.patch(f"/findings/{fid}/status",
                         params={"status": "acknowledged", "acknowledged_by": "alice",
                                 "notes": "risk accepted"}))
    assert j["status"] == "acknowledged" and j["id"] == fid and j["updated_at"]
    f = [x for x in seeded.get("/findings", params={"status": "acknowledged"}).json() if x["id"] == fid][0]
    # C-20: notes are an appended, stamped trail - never overwritten
    assert f["acknowledged_by"] == "alice" and f["acknowledged_at"]
    assert f["notes"].endswith("alice -> acknowledged] risk accepted")
    _ok(seeded.patch(f"/findings/{fid}/status", params={"status": "closed", "notes": "fixed in change 42"}))
    f = [x for x in seeded.get("/findings", params={"status": "closed"}).json() if x["id"] == fid][0]
    assert f["closed_at"]
    assert "risk accepted" in f["notes"] and f["notes"].endswith("operator -> closed] fixed in change 42")
    assert seeded.patch(f"/findings/{fid}/status", params={"status": "deleted"}).status_code == 422
    assert seeded.patch("/findings/999999/status", params={"status": "open"}).status_code == 404


def test_scan_industrial_writes(client):
    _ok(up(client, "/ingest/pcap", "modbus_sample.pcap"))
    first = _ok(client.post("/findings/scan-industrial-writes"))
    assert isinstance(first, dict) and first
    n = client.get("/findings/summary").json()["by_check_name"].get("unauthorized_industrial_write", 0)
    assert n > 0  # fail-open: no approved engineering WS baseline yet
    _ok(client.post("/findings/scan-industrial-writes"))
    assert client.get("/findings/summary").json()["by_check_name"]["unauthorized_industrial_write"] == n
    assert client.get("/findings/scan-industrial-writes").status_code == 405


# ------------------------------------------------------ reachability/diff --

def test_reachability(seeded):
    j = _ok(seeded.get("/reachability"))
    assert {"matrix", "enforcement_points", "levels_with_hosts", "traffic_filter"} <= set(j)
    assert "4→3" in j["matrix"]
    cell = j["matrix"]["4→3"]
    assert cell["overall"] in {"permitted", "denied", "partial", "unknown", "no_policy"}
    one = _ok(seeded.get("/reachability", params={"src_level": 4, "dst_level": "3",
                                                 "dst_port": 502, "protocol": "tcp"}))
    assert list(one["matrix"]) == ["4→3"]
    assert one["traffic_filter"]["dst_port"] == 502
    assert seeded.get("/reachability", params={"src_level": "7"}).status_code == 422


def test_reachability_path(seeded):
    ip = next(h["ip"] for h in seeded.get("/hosts").json() if h["ip"])
    j = _ok(seeded.get("/reachability/path", params={"src": ip, "dst_level": 4}))
    assert j["overall"] in {"permitted", "denied", "unknown", "no_policy", "intra_level"}
    j = _ok(seeded.get("/reachability/path", params={"src": ip, "dst": "10.0.1.10",
                                                     "dst_port": 502, "protocol": "tcp"}))
    assert "overall" in j
    r = seeded.get("/reachability/path", params={"src": ip})
    assert r.status_code == 400 and "dst" in r.json()["detail"]
    assert seeded.get("/reachability/path", params={"dst": ip}).status_code == 422


def test_access_paths(seeded):
    j = _ok(seeded.get("/access-paths"))
    assert {"paths", "truncated", "counts"} <= set(j)
    assert j["counts"]["total"] == len(j["paths"])
    for p in j["paths"]:
        assert set(p) >= {"src", "dst", "service", "direction", "chain", "flags", "traffic", "tag_key", "classification", "report_include", "report_include_default"}
        assert p["traffic"]["status"] in {"seen", "not_seen", "no_capture", "partial"}
        assert p["direction"] in {"down", "up", "composed", "same"}
    # flagged_only narrows to rows carrying at least one flag.
    jf = _ok(seeded.get("/access-paths", params={"flagged_only": "true"}))
    assert all(p["flags"] for p in jf["paths"])
    assert seeded.get("/access-paths", params={"direction": "sideways"}).status_code == 422
    assert {"unmatched_observed", "unmatched_total"} <= set(j)
    assert "by_traffic" in j["counts"]
    ju = _ok(seeded.get("/access-paths", params={"traffic": "not_seen"}))
    assert all(p["traffic"]["status"] == "not_seen" for p in ju["paths"])
    assert seeded.get("/access-paths", params={"traffic": "maybe"}).status_code == 422
    assert "unmatched_observed" not in _ok(seeded.get("/access-paths",
                                                      params={"include_unmatched": "false"}))


def test_topology_firewall_groups(seeded):
    j = _ok(seeded.get("/topology/firewall-groups"))
    assert isinstance(j["groups"], list) and isinstance(j["suggestions"], list)
    assert seeded.post("/topology/ha-pairs", json={"firewall_ids": [999998, 999999]}).status_code in (404, 422)
    assert seeded.post("/topology/paired-firewalls", json={"firewall_ids": [1]}).status_code in (404, 422)
    assert seeded.delete("/topology/firewall-groups/999999").status_code == 404


def test_management_networks_routes(seeded):
    j = _ok(seeded.get("/management/networks"))
    assert {"declarations", "interfaces", "vlans", "suggestions", "sources"} <= set(j)
    assert seeded.post("/management/networks", json={"kind": "bogus"}).status_code == 422
    r = seeded.post("/management/networks", json={"kind": "subnet", "cidr": "10.250.0.0/24",
                                                  "recheck": False})
    assert r.status_code == 201, r.text
    did = r.json()["declaration"]["id"]
    assert seeded.post("/management/networks", json={"kind": "subnet", "cidr": "10.250.0.0/24",
                                                     "recheck": False}).status_code == 409
    assert seeded.get("/management/fix-options", params={"finding_id": 999999}).status_code == 404
    assert "after" in _ok(seeded.post("/management/recheck"))
    assert seeded.delete(f"/management/networks/{did}", params={"recheck": "false"}).status_code == 200
    assert seeded.delete(f"/management/networks/{did}").status_code == 404


def test_finding_explanation_route(seeded):
    fs = _ok(seeded.get("/findings", params={"limit": 50}))
    fs = fs if isinstance(fs, list) else fs.get("findings") or fs.get("items")
    assert fs
    for f in fs[:50]:
        j = _ok(seeded.get(f"/findings/{f['id']}/explanation"))
        assert j["why"] and j["resolve"] and j["close"] and j["severity"]["reason"], f["check_name"]
        assert j["what"]["text"]
    assert seeded.get("/findings/999999/explanation").status_code == 404


def test_vpn_groups_routes(seeded):
    j = _ok(seeded.get("/vpn/groups"))
    assert {"groups", "declarations", "categories"} <= set(j)
    assert seeded.post("/vpn/groups", json={"name": "X", "category": "bogus"}).status_code == 422
    r = seeded.post("/vpn/groups", json={"name": "Cov-Vendors", "category": "vendor", "recheck": False})
    assert r.status_code == 201, r.text
    did = r.json()["declaration"]["id"]
    assert seeded.post("/vpn/groups", json={"name": "Cov-Vendors", "category": "vendor",
                                            "recheck": False}).status_code == 409
    r = seeded.post("/vpn/groups", json={"name": "Cov-Vendors", "category": "it"})
    assert r.status_code == 201 and r.json()["created"] is False, r.text
    assert seeded.delete(f"/vpn/groups/{did}", params={"recheck": "false"}).status_code == 200
    assert seeded.delete(f"/vpn/groups/{did}").status_code == 404


def test_topology_confirm_segment(seeded):
    r = seeded.post("/topology/confirm-segment", json={"iface_ids": [999998, 999999]})
    assert r.status_code in (400, 404, 422), r.text
    r = seeded.post("/topology/confirm-segment", json={"iface_ids": []})
    assert r.status_code == 422


def test_access_path_hops(seeded):
    from app.db import get_write_db
    ov = main_mod.app.dependency_overrides
    ov[get_write_db] = ov[get_db]
    try:
        j = _ok(seeded.get("/access-paths/hops"))
        assert j["hops"] == [] and isinstance(j["suggestions"], list)
        r = seeded.post("/access-paths/hops",
                        json={"from_ip": "203.0.113.1", "to_ip": "203.0.113.2"})
        assert r.status_code == 422, r.text            # unknown hosts
        assert seeded.delete("/access-paths/hops/999999").status_code == 404
    finally:
        ov.pop(get_write_db, None)


def test_access_paths_classify(seeded):
    from app.db import get_write_db
    ov = main_mod.app.dependency_overrides
    ov[get_write_db] = ov[get_db]          # write route -> this test's database
    try:
        rows = _ok(seeded.get("/access-paths"))["paths"]
        assert rows, "seeded data should enumerate at least one path"
        key = rows[0]["tag_key"]
        j = _ok(seeded.post("/access-paths/classify", json={"items": [
            {"tag_key": key, "classification": "permissive", "report_include": False,
             "note": "cov", "classified_by": "tester"}]}))
        item = j["items"][0]
        assert item["tag_key"] == key and item["classification"] == "permissive"
        assert item["report_include"] is False and item["note"] == "cov"
        assert set(j["findings_sync"]) >= {"raised", "confirmed", "acknowledged", "reopened", "closed"}
        back = {p["tag_key"]: p for p in _ok(seeded.get("/access-paths"))["paths"]}
        assert back[key]["classification"] == "permissive"
        r = seeded.post("/access-paths/classify", json={"items": [{"tag_key": "p:nope:-:1:0"}]})
        assert r.status_code == 422
        r = seeded.post("/access-paths/classify",
                        json={"items": [{"tag_key": key, "classification": "bogus"}]})
        assert r.status_code == 422
    finally:
        ov.pop(get_write_db, None)


def test_diff(seeded):
    j = _ok(seeded.get("/diff"))
    assert {"unexpected_traffic", "unused_rules", "unresolvable_rules", "sessions_considered",
            "sessions_total"} <= set(j)
    assert j["sessions_total"] > 0
    assert isinstance(j["unused_rules"], list)
    assert seeded.post("/diff").status_code == 405


def test_topology(seeded):
    r = seeded.get("/topology")
    j = _ok(r)
    assert set(j) >= {"nodes", "edges", "firewall_boundaries", "hosts_total", "sessions_total",
                      "truncated"}
    assert r.headers["X-Hosts-Total"] == str(j["hosts_total"]) and j["truncated"] is False
    assert {"id", "label", "ip", "purdue_level", "hostname", "vlan"} <= set(j["nodes"][0])
    node_ids = {n["id"] for n in j["nodes"]}
    assert j["edges"] and all(e["source"] in node_ids and e["target"] in node_ids for e in j["edges"])
    assert {"protocol", "dst_port", "crosses_firewall"} <= set(j["edges"][0])
    b = [x for x in j["firewall_boundaries"] if x["name"] == "CISCO-EDGE"][0]
    assert (b["zone_lo"], b["zone_hi"]) == (3, 4)
    small = _ok(seeded.get("/topology", params={"host_limit": 2, "session_limit": 1}))
    assert len(small["nodes"]) == 2 and small["truncated"] is True
    ids = {n["id"] for n in small["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in small["edges"])
    assert seeded.get("/topology", params={"host_limit": 0}).status_code == 422


# ------------------------------------------------------------ log ingest --

_EVENT = {"devname": "FW-OT", "type": "traffic", "subtype": "forward", "srcip": "10.0.3.50",
          "dstip": "10.0.1.10", "srcport": 50000, "dstport": 23, "proto": 6, "action": "accept",
          "policyid": 99, "service": "TELNET", "date": "2026-09-30", "time": "10:00:00"}


def test_ingest_forti_event(client):
    j = _ok(client.post("/ingest/forti-event", json=_EVENT))
    assert j["status"] == "created" and j["duplicate"] is False and j["event_id"]
    assert {"findings_created", "finding_ids", "escalations", "rule_hits_updated",
            "device_name"} <= set(j)
    assert j["device_name"] == "FW-OT"
    dup = _ok(client.post("/ingest/forti-event", json=_EVENT))
    assert dup["duplicate"] is True and dup["event_id"] == j["event_id"] and dup["findings_created"] == 0
    ev = dict(_EVENT, srcport=50001)
    ev.pop("devname")
    named = _ok(client.post("/ingest/forti-event", json=ev, params={"device_name": "WEBHOOK-FW"}))
    assert named["device_name"] == "WEBHOOK-FW"
    assert client.post("/ingest/forti-event", json=["not", "a", "dict"]).status_code == 422
    # C-20: a body that is not UTF-8 text is the caller's error (422), not a 500
    r = client.post("/ingest/forti-event", content=b"\xff\xfe\x00garbage",
                    headers={"Content-Type": "text/plain"})
    assert r.status_code == 422 and "UTF-8" in r.text


def test_utf16_config_upload_is_transcoded(client):
    """C-20: a UTF-16 file (BOM) is decoded by its BOM instead of becoming
    NUL-studded garbage; the config parses like its UTF-8 twin."""
    raw = (SAMPLES / "sample_fortigate_config.txt").read_bytes().decode("utf-8")
    j = _ok(up(client, "/ingest/fortigate-config", "cfg16.txt", {"firewall_name": "FW-U16"},
               content=b"\xff\xfe" + raw.encode("utf-16-le")))
    k = _ok(up(client, "/ingest/fortigate-config", "cfg8.txt", {"firewall_name": "FW-U8"},
               content=raw.encode("utf-8")))
    assert j["stats"]["rules_created"] == k["stats"]["rules_created"] > 0
    assert j["stats"]["interfaces_created"] == k["stats"]["interfaces_created"] > 0


def test_ingest_forti_syslog(seeded, monkeypatch):
    content = (SAMPLES / "sample_forti_events.cef").read_bytes() + b"\n# comment\ngarbage line\n"
    # all sample lines are already in the seeded DB -> duplicates, not re-evaluated
    j = _ok(up(seeded, "/ingest/forti-syslog", "events.cef", content=content))
    st = j["stats"]
    assert st["events_created"] == 0 and st["duplicates_skipped"] > 0 and st["findings_created"] == 0
    assert st["parse_failures"] == 1 and st["lines"] == st["duplicates_skipped"] + 1
    line = ('date=2026-09-30 time=11:00:00 logid="0000000013" type=traffic subtype=forward srcip=10.0.3.51 '
            'dstip=10.0.1.10 srcport=50000 dstport=23 proto=6 action=accept policyid=99 '
            'service=TELNET\n')
    j = _ok(up(seeded, "/ingest/forti-syslog", "x.log", content=line.encode(),
               params={"device_name": "FALLBACK"}))
    assert j["device_name"] == "FALLBACK" and j["stats"]["events_created"] == 1
    assert {"finding_ids", "escalations", "rule_hits_updated"} <= set(j["stats"])
    monkeypatch.setattr(routes_mod, "_MAX_TEXT_BYTES", 10)
    assert up(seeded, "/ingest/forti-syslog", "sample_forti_events.cef").status_code == 413


def test_ingest_syslog_multi_vendor(client):
    j = _ok(up(client, "/ingest/syslog", "sample_syslog_asa.log", {"vendor_hint": "cisco_asa"}))
    assert j["vendor_hint"] == "cisco_asa" and j["stats"]["events_created"] > 0
    assert set(j["stats"]["by_vendor"]) == {"cisco_asa"}
    j = _ok(up(client, "/ingest/syslog", "sample_syslog_pfsense.log"))
    assert j["vendor_hint"] == "auto" and "pfsense" in j["stats"]["by_vendor"]
    again = _ok(up(client, "/ingest/syslog", "sample_syslog_pfsense.log", {"device_name": "PF"}))
    assert again["stats"]["events_created"] == 0
    assert again["stats"]["duplicates_skipped"] == j["stats"]["events_created"]
    r = up(client, "/ingest/syslog", "sample_syslog_asa.log", {"vendor_hint": "juniper"})
    assert r.status_code == 422 and "vendor_hint" in r.json()["detail"]


def test_ingest_forti_report(client):
    j = _ok(up(client, "/ingest/forti-report", "sample_forti_traffic.csv"))
    assert j["events_imported"] > 0 and j["filename"] == "sample_forti_traffic.csv"
    assert {"findings_created", "finding_ids", "rule_hits_updated", "escalations",
            "duplicates_skipped"} <= set(j)
    again = _ok(up(client, "/ingest/forti-report", "sample_forti_traffic.csv"))
    assert again["events_imported"] == 0 and again["findings_created"] == 0
    assert again["duplicates_skipped"] == j["events_imported"]
    assert client.post("/ingest/forti-report").status_code == 422


# --------------------------------------------------------------- baselines --

def test_baseline_comms_matrix(client):
    j = _ok(up(client, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv",
               {"baseline_name": "B1"}))
    assert j["stats"]["baseline"] == "B1" and j["stats"]["entries_loaded"] > 0
    again = _ok(up(client, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv",
                   {"baseline_name": "B1"}))
    assert again["stats"]["entries_loaded"] == 0  # upsert, no duplicates
    bad = _ok(up(client, "/ingest/baseline/comms-matrix", "bad.csv",
                 content=b"src,dst,dst_port\n10.0.0.1,10.0.0.2,99999\n10.0.0.1,,80\n"))
    assert bad["stats"]["rejected"] == 1 and bad["stats"]["skipped"] == 1
    assert bad["stats"]["errors"][0]["row"] == 2
    assert client.post("/ingest/baseline/comms-matrix").status_code == 422


def test_baseline_approved_hosts(client):
    j = _ok(up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv",
               {"baseline_name": "B2"}))
    assert j["stats"]["hosts_loaded"] > 0
    bl = {b["name"]: b for b in client.get("/baselines").json()}["B2"]
    assert bl["approved_hosts"] == j["stats"]["hosts_loaded"]
    bad = _ok(up(client, "/ingest/baseline/approved-hosts", "x.csv",
                 content=b"ip,role\n10.0.0.9,janitor\n,hmi\n"))
    assert bad["stats"]["skipped_bad_role"] == 1 and bad["stats"]["hosts_loaded"] == 0
    assert client.post("/ingest/baseline/approved-hosts").status_code == 422


def test_baseline_asset_inventory(client):
    j = _ok(up(client, "/ingest/baseline/asset-inventory", "sample_asset_inventory.csv"))
    assert j["stats"]["hosts_created_or_updated"] > 0
    manual = [h for h in client.get("/hosts").json() if h["classification_source"] == "manual"]
    assert manual
    bad = _ok(up(client, "/ingest/baseline/asset-inventory", "x.csv",
                 content=b"ip,mac,hostname,purdue_level\n,,ghost,1\n10.9.9.9,,h,banana\n"))
    assert bad["stats"]["skipped_no_identity"] == 1 and bad["stats"]["invalid_purdue_level"] == 1
    assert client.post("/ingest/baseline/asset-inventory").status_code == 422


def test_inventory_import_routes(client):
    body = b"IP_Address,Host Name,Vendor\n10.9.0.1,PLC-9,Siemens\n"
    files = {"file": ("inv.csv", body, "text/csv")}
    assert client.post("/sites", json={"name": "Inv", "code": "inv"}).status_code in (200, 201)
    sp = {"site": "inv"}
    p = _ok(client.post("/ingest/baseline/asset-inventory/preview", files=files, params=sp))
    assert p["can_import"] and p["column_map"]["ip_address"] == "ip" and p["ignored_columns"] == ["Vendor"]
    j = _ok(client.post("/ingest/baseline/asset-inventory", files=files, params=sp,
                        data={"column_map": '{"IP_Address": "ip", "Host Name": "hostname"}',
                              "save_mapping_as": "m1"}))
    assert j["stats"]["columns_ignored"] == ["vendor"] and j["mapping_saved"]["name"] == "m1"
    lst = _ok(client.get("/ingest/baseline/asset-inventory/mappings", params=sp))
    mid = lst["mappings"][0]["id"]
    assert _ok(client.delete(f"/ingest/baseline/asset-inventory/mappings/{mid}", params=sp)) == {"deleted": mid}
    assert client.delete(f"/ingest/baseline/asset-inventory/mappings/{mid}", params=sp).status_code == 404
    assert client.post("/ingest/baseline/asset-inventory/preview", params=sp).status_code == 422
    assert client.post("/ingest/baseline/asset-inventory/preview", files=files, params=sp,
                       data={"column_map": "nope"}).status_code == 422


def test_baseline_reviewed_policies(seeded):
    pid = next(r["policy_id"] for r in seeded.get("/firewall-rules").json() if r["policy_id"])
    body = f"policy_id,owner,conduit\n{pid},ot-team,C1\nNO-SUCH-POLICY,x,y\n,skip,me\n".encode()
    j = _ok(up(seeded, "/ingest/baseline/reviewed-policies", "pol.csv", content=body))
    assert j["stats"]["policies_matched"] >= 1 and j["stats"]["policies_not_found"] == 1
    owners = {r["owner"] for r in seeded.get("/firewall-rules").json() if r["policy_id"] == pid}
    assert owners == {"ot-team"}
    assert seeded.post("/ingest/baseline/reviewed-policies").status_code == 422


# ------------------------------------------------------------------ reviews --

def test_reviews_run(seeded):
    j = _ok(seeded.post("/reviews/run"))
    assert {"total_findings", "by_review", "failed_reviews", "escalations", "auto_resolved"} <= set(j)
    assert j["failed_reviews"] == [] and j["total_findings"] == sum(j["by_review"].values())
    assert "review_unused_policies" in j["by_review"]
    assert seeded.get("/reviews/run").status_code == 405


def test_diagnostics(seeded):
    seeded.post("/reviews/run")
    j = _ok(seeded.get("/diagnostics"))
    assert set(j) == {"unknown_check_names", "last_review"}
    assert set(j["last_review"]) == {"failed_reviews", "escalations", "auto_resolved", "finished_at"}
    assert j["last_review"]["finished_at"]


def test_baselines_list_and_activate(client):
    up(client, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {"baseline_name": "A"})
    up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {"baseline_name": "B"})
    rows = _ok(client.get("/baselines"))
    assert {"id", "name", "is_active", "comms_entries", "approved_hosts", "created_at"} <= set(rows[0])
    act = _ok(client.post("/baselines/B/activate"))
    assert act["activated"] == "B" and act["site"] == "Default"
    rows = client.get("/baselines").json()
    assert rows[0]["name"] == "B" and rows[0]["is_active"] and not rows[1]["is_active"]
    _ok(client.post("/baselines/A/activate"))
    assert [b["name"] for b in client.get("/baselines").json() if b["is_active"]] == ["A"]
    assert client.post("/baselines/nope/activate").status_code == 404


# -------------------------------------------------------------- attestation --

def _attest(c, cl="1.1", when="2026-09-30", baseline=None, proof=None, by="alice"):
    data = {"checklist_id": cl, "attested_by": by, "attested_at": when, "notes": " zone doc "}
    if baseline:
        data["baseline_name"] = baseline
    files = {"proof": proof} if proof else None
    return c.post("/attestation", data=data, files=files)


def test_attestation_flow(client):
    up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {"baseline_name": "B1"})
    a1 = _ok(_attest(client, baseline="B1",
                     proof=("../../etc/proof v1.pdf", b"%PDF-1.4 demo", "application/pdf")), 201)
    assert a1["has_proof"] and a1["proof_filename"] == "proof v1.pdf"
    assert a1["notes"] == "zone doc" and a1["is_current"] and a1["baseline_id"]
    a2 = _ok(_attest(client, baseline="B1", when="2026-10-01"), 201)
    a3 = _ok(_attest(client, cl="1.2"), 201)
    assert not a2["has_proof"] and a3["baseline_id"] is None
    r = client.get("/attestation")
    rows = _ok(r)
    assert r.headers["X-Total-Count"] == "3"
    assert {"id", "checklist_id", "attested_by", "attested_at", "has_proof", "is_current"} <= set(rows[0])
    assert "proof_data" not in rows[0]
    cur = client.get("/attestation", params={"current_only": "true", "checklist_id": "1.1"}).json()
    assert [a["id"] for a in cur] == [a2["id"]]
    p = client.get(f"/attestation/{a1['id']}/proof")
    assert p.status_code == 200 and p.content == b"%PDF-1.4 demo"
    assert p.headers["content-type"] == "application/pdf"
    cd = p.headers["content-disposition"]
    assert cd == "attachment; filename*=UTF-8''proof%20v1.pdf"
    assert client.get(f"/attestation/{a2['id']}/proof").status_code == 404
    assert client.get("/attestation/99999/proof").status_code == 404
    assert client.get("/attestation", params={"limit": 0}).status_code == 422
    # multi-site phase 2: current attestation per checklist row of one site
    cur = _ok(client.get("/attestation/current", params={"baseline_name": "B1"}))
    assert cur["baseline"] == "B1" and cur["rows"]["1.1"]["id"] == a2["id"]
    assert cur["rows"]["1.2"]["id"] == a3["id"] and cur["rows"]["1.3"] is None
    assert client.get("/attestation/current", params={"baseline_name": "zz"}).status_code == 404


def test_attestation_errors(client, monkeypatch):
    r = _attest(client, cl="2.1")
    assert r.status_code == 400 and "checklist_id" in r.json()["detail"]
    assert _attest(client, when="30/09/2026").status_code == 400
    r = _attest(client, baseline="missing")
    assert r.status_code == 404 and "missing" in r.json()["detail"]
    assert client.post("/attestation", data={"checklist_id": "1.1"}).status_code == 422
    monkeypatch.setattr(routes_mod, "_MAX_PROOF_BYTES", 4)
    assert _attest(client, proof=("p.pdf", b"0123456789", "application/pdf")).status_code == 413
    assert client.get("/attestation").json() == []


# ------------------------------------------------------- multi-FW topology --

_FW1_CONF = textwrap.dedent("""\
    config system global
        set hostname FW-Perimeter
    end
    config system interface
        edit "wan1"
            set ip 203.0.113.1 255.255.255.252
            set role wan
        next
        edit "dmz"
            set ip 10.10.10.1 255.255.255.0
            set role lan
        next
    end
    config firewall policy
        edit 1
            set srcintf "dmz"
            set dstintf "wan1"
            set action accept
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
        next
    end
""")

_FW2_CONF = textwrap.dedent("""\
    config system global
        set hostname FW-Core
    end
    config system interface
        edit "wan1"
            set ip 10.10.10.2 255.255.255.0
            set role wan
        next
        edit "internal"
            set ip 192.168.1.1 255.255.255.0
            set role lan
        next
    end
    config firewall policy
        edit 1
            set srcintf "internal"
            set dstintf "wan1"
            set action accept
            set srcaddr "all"
            set dstaddr "all"
            set service "HTTPS"
        next
    end
""")

_FORTI_NAT = textwrap.dedent("""\
    config firewall address
        edit "OT-NET"
            set subnet 10.0.1.0 255.255.255.0
        next
    end
    config firewall vip
        edit "VIP-HMI"
            set extip 203.0.113.10
            set extintf "wan1"
            set portforward enable
            set extport 8443
            set mappedport 443
            set mappedip "10.0.1.20"
        next
    end
    config firewall ippool
        edit "POOL1"
            set startip 198.51.100.8
            set endip 198.51.100.15
        next
    end
    config firewall policy
        edit 10
            set srcintf "wan1"
            set dstintf "port2"
            set srcaddr "all"
            set dstaddr "VIP-HMI"
            set action accept
            set service "HTTPS"
        next
        edit 20
            set srcintf "port2"
            set dstintf "wan1"
            set srcaddr "OT-NET"
            set dstaddr "all"
            set action accept
            set service "ALL"
            set nat enable
            set ippool enable
            set poolname "POOL1"
        next
        edit 21
            set srcintf "port3"
            set dstintf "wan1"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set service "ALL"
            set nat enable
        next
    end
""")


def _two_firewalls(c):
    _ok(up(c, "/ingest/fortigate-config", "fw1.conf", content=_FW1_CONF.encode(),
           params={"firewall_name": "FW-Perimeter"}))
    j = _ok(up(c, "/ingest/fortigate-config", "fw2.conf", content=_FW2_CONF.encode(),
               params={"firewall_name": "FW-Core"}))
    assert j["is_multi_fw"]


def test_topology_multi_fw_workflow(client):
    # FI-01: a fresh install has no site; an operation without one says so
    assert client.get("/topology/state").status_code == 409
    _ok(client.post("/sites", json={"name": "Default", "code": "default"}), 201)
    single = _ok(client.get("/topology/state"))
    assert single["firewall_count"] == 0 and single["pending_proposals"] == []
    _two_firewalls(client)
    st = _ok(client.get("/topology/state"))
    assert st["is_multi_fw"] is True and st["firewall_count"] == 2
    fw = st["firewalls"][0]
    assert {"id", "name", "vendor", "upstream_firewall_id", "topology_confirmed", "interfaces"} <= set(fw)
    assert {"id", "name", "network_cidr", "side", "purdue_level", "connects_to_interface_id",
            "is_ha", "is_mgmt_only"} <= set(fw["interfaces"][0])
    props = st["pending_proposals"]
    assert len(props) == 1
    p = props[0]
    assert {p["iface_a_cidr"], p["iface_b_cidr"]} == {"10.10.10.0/24"}
    assert p["confidence"] in {"high", "medium", "low"}
    j = _ok(client.post("/topology/confirm-link",
                        json={"iface_a_id": p["iface_a_id"], "iface_b_id": p["iface_b_id"]}))
    assert j["confirmed"] is True
    assert {j["link"]["iface_a"]["id"], j["link"]["iface_b"]["id"]} == {p["iface_a_id"], p["iface_b_id"]}
    assert "purdue_suggestions" in j and isinstance(j["cross_fw_checks"], dict)
    assert _ok(client.get("/topology/state"))["pending_proposals"] == []
    # cross-FW findings: FW-Perimeter's any->any permit on the linked interface
    names = set(client.get("/findings/summary").json()["by_check_name"])
    assert any(n.startswith("cross_fw_") for n in names)
    # re-run is idempotent
    before = client.get("/findings/summary").json()["total_open"]
    rc = _ok(client.post("/topology/run-checks"))
    assert "purdue_suggestions" in rc
    assert client.get("/findings/summary").json()["total_open"] == before
    fws = _ok(client.get("/topology/firewalls"))
    assert fws["count"] == 2
    assert {"id", "name", "vendor", "interface_count", "capture_count", "is_multi_fw"} <= set(fws["firewalls"][0])
    assert all(f["interface_count"] == 2 for f in fws["firewalls"])
    # errors
    r = client.post("/topology/confirm-link", json={"iface_a_id": p["iface_a_id"], "iface_b_id": 99999})
    assert r.status_code == 400 and "not found" in r.json()["detail"]
    assert client.post("/topology/confirm-link", json={"iface_a_id": p["iface_a_id"],
                                                       "iface_b_id": p["iface_a_id"]}).status_code == 400
    assert client.post("/topology/confirm-link", json={"iface_a_id": 1}).status_code == 422


def test_topology_set_interface_side(client):
    _two_firewalls(client)
    iface = client.get("/topology/state").json()["firewalls"][0]["interfaces"][0]
    j = _ok(client.post("/topology/set-interface-side",
                        json={"interface_id": iface["id"], "side": "inside",
                              "zone_label": "OT Floor", "purdue_level": "L3.5"}))
    assert j["updated"] and j["interface"]["side"] == "inside"
    assert (j["interface"]["zone_label"], j["interface"]["purdue_level"]) == ("OT Floor", 3.5)
    j = _ok(client.post("/topology/set-interface-side",
                        json={"interface_id": iface["id"], "clear": ["zone_label", "purdue_level"]}))
    assert j["interface"]["zone_label"] is None and j["interface"]["purdue_level"] is None
    assert j["interface"]["side"] == "inside"
    assert client.post("/topology/set-interface-side",
                       json={"interface_id": 99999, "side": "inside"}).status_code == 404
    assert client.post("/topology/set-interface-side",
                       json={"interface_id": iface["id"], "side": "upstairs"}).status_code == 422
    assert client.post("/topology/set-interface-side",
                       json={"interface_id": iface["id"], "zone_label": "x",
                             "clear": ["zone_label"]}).status_code == 422
    assert client.post("/topology/set-interface-side",
                       json={"interface_id": iface["id"], "purdue_level": 8}).status_code == 422


def test_topology_set_upstream(client):
    _two_firewalls(client)
    fws = {f["name"]: f["id"] for f in client.get("/topology/firewalls").json()["firewalls"]}
    j = _ok(client.post("/topology/set-upstream", json={
        "firewall_id": fws["FW-Core"], "upstream_firewall_id": fws["FW-Perimeter"],
        "purdue_level_ingress": "3.5", "purdue_level_egress": 3, "topology_confirmed": True}))
    f = j["firewall"]
    assert (f["upstream_firewall_id"], f["purdue_level_ingress"], f["purdue_level_egress"],
            f["topology_confirmed"]) == (fws["FW-Perimeter"], 3.5, 3, True)
    assert "purdue_suggestions" in j
    r = client.post("/topology/set-upstream", json={"firewall_id": fws["FW-Core"],
                                                    "upstream_firewall_id": fws["FW-Core"]})
    assert r.status_code == 400
    assert client.post("/topology/set-upstream", json={"firewall_id": 99999}).status_code == 400
    assert client.post("/topology/set-upstream", json={"firewall_id": fws["FW-Core"],
                                                       "purdue_level_egress": 6}).status_code == 422


def test_topology_suggest_purdue(client):
    _two_firewalls(client)
    j = _ok(client.post("/topology/suggest-purdue"))
    assert "interfaces_updated" in j and isinstance(j.get("by_source"), dict)
    assert client.get("/topology/suggest-purdue").status_code == 405


def test_pcap_fw_and_confirm(client):
    _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt", {"firewall_name": "FW-OT"}))
    fw = client.get("/topology/firewalls").json()["firewalls"][0]
    j = _ok(up(client, "/ingest/pcap-fw", "modbus_sample.pcap", {"side": "inside"}))
    assert {"capture_id", "packet_count", "sampled_ips", "suggestion", "stats"} <= set(j)
    assert j["packet_count"] > 0 and j["sampled_ips"] > 0 and j["stats"]["sessions"] > 0
    if j["suggestion"] is not None:
        assert {"interface_id", "confidence", "score"} <= set(j["suggestion"])
    assert client.get("/topology/firewalls").json()["firewalls"][0]["capture_count"] in (0, 1)
    j2 = _ok(up(client, "/ingest/pcap-fw", "multi_protocol_sample.pcap", {"firewall_id": fw["id"]}))
    iface = client.get("/topology/state").json()["firewalls"][0]["interfaces"][0]
    c = _ok(client.post(f"/ingest/pcap/{j['capture_id']}/confirm",
                        json={"interface_id": iface["id"]}))
    assert c["confirmed"] and c["side"] == "inside" and c["interface"]["id"] == iface["id"]
    c = _ok(client.post(f"/ingest/pcap/{j2['capture_id']}/confirm",
                        json={"interface_id": iface["id"], "side": "outside"}))
    assert c["side"] == "outside" and c["interface"]["firewall_id"] == fw["id"]
    assert client.get("/topology/firewalls").json()["firewalls"][0]["capture_count"] == 2
    # errors
    assert up(client, "/ingest/pcap-fw", "modbus_sample.pcap", {"side": "left"}).status_code == 422
    assert up(client, "/ingest/pcap-fw", "modbus_sample.pcap", {"firewall_id": 9999}).status_code == 404
    assert up(client, "/ingest/pcap-fw", "junk.pcap", content=b"garbage" * 20).status_code == 415
    assert client.post("/ingest/pcap/9999/confirm", json={"interface_id": iface["id"]}).status_code == 404
    assert client.post(f"/ingest/pcap/{j['capture_id']}/confirm",
                       json={"interface_id": 9999}).status_code == 404
    assert client.post(f"/ingest/pcap/{j['capture_id']}/confirm",
                       json={"interface_id": iface["id"], "side": "up"}).status_code == 422


def test_pcap_capture_point_routes(client):
    """VD-02a: every upload is a capture; capture-only uploads are listed as
    unassociated and can be associated later (tests/test_vd02a_capture_point.py
    covers the attribution itself)."""
    _ok(up(client, "/ingest/fortigate-config", "sample_fortigate_config.txt", {"firewall_name": "FW-CP"}))
    fw = next(f for f in client.get("/topology/firewalls").json()["firewalls"] if f["name"] == "FW-CP")
    j = _ok(up(client, "/ingest/pcap", "modbus_sample.pcap"))
    assert j["association"] == "none" and j["capture_id"] and j["capture_point_notes"]
    lst = _ok(client.get("/ingest/pcap/captures"))
    row = next(r for r in lst["captures"] if r["id"] == j["capture_id"])
    assert row["unassociated"] and lst["unassociated"] >= 1
    a = _ok(client.post(f"/ingest/pcap/{j['capture_id']}/associate", json={"firewall_id": fw["id"]}))
    assert a["association"] == "firewall" and a["capture"]["firewall"] == "FW-CP"
    assert {"hosts_merged", "macs_cleared", "gateway_macs", "classification"} <= set(a)
    a = _ok(client.post(f"/ingest/pcap/{j['capture_id']}/associate", json={}))
    assert a["association"] == "none"
    assert client.post(f"/ingest/pcap/{j['capture_id']}/associate",
                       json={"capture_networks": "x"}).status_code == 422
    assert client.post(f"/ingest/pcap/{j['capture_id']}/associate",
                       json={"firewall_id": fw["id"], "side": "up"}).status_code == 422
    assert client.post("/ingest/pcap/9999/associate", json={}).status_code == 404


# ------------------------------------------------------------------ deletes --

def test_delete_disabled_by_default(client):
    for url in ("/findings/1", "/attestation/1", "/firewall-devices/1", "/baselines/x", "/hosts/1"):
        r = client.delete(url)
        assert r.status_code == 403 and "IACS_ENABLE_DELETE" in r.json()["detail"], url


def test_delete_finding(seeded, deletes_on):
    f = seeded.get("/findings", params={"limit": 1}).json()[0]
    j = _ok(seeded.delete(f"/findings/{f['id']}"))
    assert j["deleted"] == "finding" and j["finding"]["id"] == f["id"]
    assert seeded.delete(f"/findings/{f['id']}").status_code == 404


def test_delete_attestation(client, deletes_on):
    a1 = _ok(_attest(client, when="2026-01-01"), 201)
    a2 = _ok(_attest(client, when="2026-02-01"), 201)
    j = _ok(client.delete(f"/attestation/{a2['id']}"))
    assert j["deleted"] == "attestation" and j["promoted_current_id"] == a1["id"]
    assert [a["id"] for a in client.get("/attestation", params={"current_only": "true"}).json()] == [a1["id"]]
    j = _ok(client.delete(f"/attestation/{a1['id']}"))
    assert j["promoted_current_id"] is None
    assert client.delete(f"/attestation/{a1['id']}").status_code == 404


def test_delete_firewall_device(seeded, deletes_on):
    dev = [d for d in seeded.get("/firewall-devices").json() if d["name"] == "CISCO-EDGE"][0]
    with seeded.Session() as s:
        rid = next(r["id"] for r in seeded.get("/firewall-rules",
                                                params={"firewall_device_id": dev["id"]}).json())
        s.add(Finding(category="periodic_review", check_name="unused_policy", severity="low",
                      title="linked", rule_id=rid))
        s.commit()
    j = _ok(seeded.delete(f"/firewall-devices/{dev['id']}"))
    assert j["deleted"] == "firewall_device" and j["firewall_rules"] == dev["rule_count"] + dev["disabled_rule_count"]
    assert j["findings_unlinked"] >= 1
    assert seeded.get("/firewall-rules", params={"firewall_device_id": dev["id"]}).json() == []
    assert any(f["title"] == "linked" for f in seeded.get("/findings", params={"limit": 5000}).json())
    assert seeded.delete(f"/firewall-devices/{dev['id']}").status_code == 404


def test_delete_baseline(client, deletes_on):
    up(client, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {"baseline_name": "B1"})
    up(client, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {"baseline_name": "B2"})
    _ok(_attest(client, baseline="B2"), 201)
    client.post("/baselines/B1/activate")
    r = client.delete("/baselines/B1")
    assert r.status_code == 409 and "active" in r.json()["detail"]
    r = client.delete("/baselines/B2")
    assert r.status_code == 409 and "attestation" in r.json()["detail"]
    j = _ok(client.delete("/baselines/B2", params={"force": "true"}))
    assert j["attestations"] == 1 and j["approved_hosts"] > 0 and j["was_active"] is False
    j = _ok(client.delete("/baselines/B1", params={"force": "true"}))
    assert j["was_active"] is True and j["approved_comms"] > 0
    assert client.get("/baselines").json() == []
    assert client.delete("/baselines/B1").status_code == 404


def test_delete_host(seeded, deletes_on):
    sess = seeded.get("/sessions", params={"protocol": "modbus"}).json()[0]
    hid = sess["src_host"]["id"]
    r = seeded.delete(f"/hosts/{hid}")
    assert r.status_code == 409 and "force=true" in r.json()["detail"]
    j = _ok(seeded.delete(f"/hosts/{hid}", params={"force": "true"}))
    assert j["deleted"] == "host" and j["sessions"] >= 1 and j["protocol_details"] >= 1
    assert hid not in {h["id"] for h in seeded.get("/hosts").json()}
    assert all(s["src_host"]["id"] != hid and s["dst_host"]["id"] != hid
               for s in seeded.get("/sessions").json())
    lonely = None
    with seeded.Session() as s:
        h = Host(ip="10.200.0.1", sources=["test"])
        s.add(h)
        s.commit()
        lonely = h.id
    assert _ok(seeded.delete(f"/hosts/{lonely}"))["sessions"] == 0
    assert seeded.delete(f"/hosts/{lonely}").status_code == 404


# ------------------------------------------------------------ reports & UI --

def test_compliance_pdf(seeded):
    seeded.post("/attestation", data={"checklist_id": "1.1", "attested_by": "a",
                                      "attested_at": "2026-09-30", "baseline_name": "B1"})
    r = seeded.get("/reports/compliance.pdf", params={"baseline": "B1", "site": "Plant 7",
                                                      "include_closed": "true"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF") and int(r.headers["content-length"]) == len(r.content)
    assert 'filename="iasc_compliance_' in r.headers["content-disposition"]
    r = seeded.get("/reports/compliance.pdf", params={"baseline": "no-such-baseline"})
    assert r.status_code == 404 and "no-such-baseline" in r.json()["detail"]
    assert seeded.get("/reports/compliance.pdf", params={"site": "x" * 129}).status_code == 422


_UI_PAGES = {"/ui/attestation": "attestation.html", "/ui/topology": "index.html",   # standalone mode
             "/ui/fw-topology": "fw_topology.html", "/ui/upload": "upload.html",
             "/ui/findings": "findings.html", "/ui": "index.html", "/ui/": "index.html"}


def test_ui_pages(client, monkeypatch, tmp_path):
    for url, fname in _UI_PAGES.items():
        r = client.get(url)
        assert r.status_code == 200, url
        assert r.headers["content-type"].startswith("text/html")
        assert r.text == (ROOT / "ui" / fname).read_text(encoding="utf-8")
    monkeypatch.setattr(routes_mod, "_UI_DIR", tmp_path / "no-ui")
    for url in _UI_PAGES:
        r = client.get(url)
        assert r.status_code == 404 and r.json()["detail"] == "UI file not found", url


def test_root_redirects_to_ui(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/ui"
    assert client.post("/").status_code == 405


def test_health(client):
    assert _ok(client.get("/health")) == {"status": "ok"}
    assert client.post("/health").status_code == 405


# ------------------------------------------------------------------- sites --
# (behaviour in depth: tests/test_sites_phase1.py, phase 4 roll-up: tests/test_sites_phase4.py)

def test_sites_routes(client, monkeypatch):
    assert _ok(client.get("/sites")) == []                    # FI-01: fresh install, no site
    _ok(client.post("/sites", json={"name": "Default", "code": "default"}), 201)
    sites = _ok(client.get("/sites"))
    assert [x["code"] for x in sites] == ["default"]
    ru = _ok(client.get("/sites/rollup"))
    assert [x["code"] for x in ru["sites"]] == ["default"] and ru["totals"]["open_findings"] == 0
    new = _ok(client.post("/sites", json={"name": "Plant Z"}), 201)
    assert new["code"] == "plant-z" and new["counts"]["hosts"] == 0
    assert _ok(client.get(f"/sites/{new['id']}"))["name"] == "Plant Z"
    assert _ok(client.patch(f"/sites/{new['id']}", json={"description": "d"}))["description"] == "d"
    assert client.delete(f"/sites/{new['id']}").status_code == 403
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    assert _ok(client.delete(f"/sites/{new['id']}"))["deleted"] == "site"


@pytest.mark.no_auto_site
def test_site_devices_routes(client, monkeypatch):
    line = ("<166>Sep 30 2026 12:00:01 asa-x : %ASA-6-106100: access-list a permitted tcp "
            "outside/203.0.113.5(51234) -> inside/10.10.1.20(502) hit-cnt 1 first hit [0x1, 0x0]")
    _ok(client.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit
    _ok(up(client, "/ingest/syslog", "x.log", content=line.encode()))
    um = _ok(client.get("/site-devices/unmapped", params={"detail": True}))
    assert um["pending_lines"] == 1 and um["devices"][0]["device_key"] == "asa-x"
    z = _ok(client.post("/sites", json={"name": "Plant Z"}), 201)
    dev = _ok(client.post("/site-devices", json={"site": "plant-z", "device_name": "ASA-X"}), 201)
    assert dev["replay"]["events_created"] == 1 and dev["site_id"] == z["id"]
    assert [d["device_name"] for d in _ok(client.get("/site-devices"))] == ["asa-x"]
    r = _ok(client.patch(f"/site-devices/{dev['id']}", json={"site": "default", "vendor": "cisco_asa"}))
    assert r["remapped"] is True and r["vendor"] == "cisco_asa"
    _ok(up(client, "/ingest/syslog", "y.log", content=line.replace("asa-x", "asa-y").encode()))
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")  # B-21: discard/purge are gated
    assert _ok(client.post("/site-devices/unmapped/discard", json={"device_key": "asa-y"}))["discarded"] == 1
    assert _ok(client.post("/site-devices/unmapped/purge"))["replayed_or_discarded"] == 2
    monkeypatch.delenv("IACS_ENABLE_DELETE")
    assert client.delete(f"/site-devices/{dev['id']}").status_code == 403
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    assert _ok(client.delete(f"/site-devices/{dev['id']}"))["deleted"] == "site_device"
    assert client.patch("/site-devices/999", json={}).status_code == 404


@pytest.mark.no_auto_site
def test_site_device_serial_routes(client, monkeypatch):
    """B-12: pre-register a member serial, remove it (delete gate)."""
    _ok(client.get("/sites"))
    dev = _ok(client.post("/site-devices", json={"site": "default", "device_name": "fw-m"}), 201)
    r = _ok(client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "M-1"}), 201)
    assert [m["serial"] for m in r["members"]] == ["M-1"] and r["added"]["source"] == "manual"
    assert client.post(f"/site-devices/{dev['id']}/serials", json={"serial": "M-2"}).status_code == 409
    assert client.delete(f"/site-devices/{dev['id']}/serials/M-1").status_code == 403
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    r = _ok(client.delete(f"/site-devices/{dev['id']}/serials/M-1"))
    assert r["device"]["members"] == []


def test_site_device_conflict_routes(client, monkeypatch):
    """B-11: a site_mismatch held, listed, resolved (same_device), audited."""
    line = ("<166>Sep 30 2026 12:00:01 asa-c : %ASA-6-106100: access-list a permitted tcp "
            "outside/203.0.113.5(51234) -> inside/10.10.1.20(502) hit-cnt 1 first hit [0x1, 0x0]")
    _ok(client.post("/sites", json={"name": "Default", "code": "default"}), 201)   # FI-01: explicit
    _ok(client.post("/sites", json={"name": "Plant C"}), 201)
    _ok(client.post("/site-devices", json={"site": "plant-c", "device_name": "asa-c"}), 201)
    st = _ok(up(client, "/ingest/syslog", "c.log", content=line.encode(),
                params={"site": "default"}))["stats"]
    assert st["conflicts"] == 1 and st["events_created"] == 0
    cf = _ok(client.get("/site-devices/conflicts", params={"detail": True}))
    assert cf["pending_conflicts"] == 1 and cf["conflicts"][0]["kind"] == "site_mismatch"
    assert len(cf["conflicts"][0]["lines"]) == 1
    assert client.get("/site-devices/conflicts", params={"site_id": 999999}).status_code == 422
    body = {"device_key": "asa-c", "kind": "site_mismatch", "action": "discard"}
    assert client.post("/site-devices/conflicts/resolve", json=body).status_code == 403
    r = _ok(client.post("/site-devices/conflicts/resolve", json={**body, "action": "same_device"}))
    assert r["replay"]["events_created"] == 1 and r["pending_conflicts"] == 0
    audit = _ok(client.get("/site-devices/conflicts/resolutions"))
    assert audit[0]["action"] == "same_device" and audit[0]["target_site"] == "Plant C"


def test_rules_not_judged_route(client):
    """MP-24 (details in tests/test_mp08_12_24.py)."""
    _ok(client.post("/sites", json={"name": "NJ", "code": "nj"}), 201)
    j = _ok(client.get("/reviews/rules-not-judged", params={"site": "nj"}))
    assert j["firewalls"] == [] and j["not_judged"] == 0 and j["total_rules"] == 0
    assert j["site"] == "NJ"


def test_review_schedule_route(client):
    """RS-01 (details in tests/test_review_schedule.py)."""
    j = _ok(client.get("/reviews/schedule"))
    assert j["enabled"] is True and j["effective"] in ("on", "disabled")
    j = _ok(client.put("/reviews/schedule", json={"enabled": False, "changed_by": "op"}))
    assert j["enabled"] is False and j["updated_by"] == "op"
    assert client.put("/reviews/schedule", json={}).status_code == 422
    assert client.put("/reviews/schedule", json={"enabled": True, "changed_by": "x" * 200}).status_code == 422
    _ok(client.put("/reviews/schedule", json={"enabled": True}))
