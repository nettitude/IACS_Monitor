"""
F-01 end-to-end: every file in sample_data/ goes through the HTTP API in the
order tests/ui_demo_server.py seed() uses (firewalls, switches/L2, traffic,
baselines, logs), Purdue levels are assigned to the FortiGate legs, periodic
reviews run, and:

  * the SET of check_names with open findings matches a snapshot (sets, not
    counts, so an extra finding of an existing check does not break it);
  * re-running reviews and re-uploading every sample does not increase the
    number of open findings (dedup / re-ingest stability).
"""
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import FirewallInterface, Host

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"

# (url, sample file, query params) - ui_demo_server.seed() order, plus the
# samples the demo does not load (PAN-OS, HP switch, extra ARP/MAC, pcap,
# multi-vendor syslog, FortiAnalyzer CSV report).
UPLOADS = [
    ("/ingest/fortigate-config", "sample_fortigate_config.txt", {"firewall_name": "FW-OT"}),
    ("/ingest/firewall", "sample_firewall_cisco.txt",
     {"firewall_device_name": "CISCO-EDGE", "purdue_zone_from": 4, "purdue_zone_to": 3}),
    ("/ingest/firewall", "sample_firewall_pfsense.xml", {"firewall_device_name": "PFSENSE-LAB"}),
    ("/ingest/firewall", "sample_firewall_panos.xml", {"firewall_device_name": "PA-XML"}),
    ("/ingest/firewall", "sample_firewall_panos_set.txt", {"firewall_device_name": "PA-SET"}),
    ("/ingest/switch", "sample_switch_running_config.txt", {"device_name": "SW-CORE"}),
    ("/ingest/switch", "sample_switch_vlan_brief.txt", {"device_name": "SW-CORE"}),
    ("/ingest/switch", "sample_switch_lldp_neighbors.txt", {"device_name": "SW-CORE"}),
    ("/ingest/switch", "sample_switch_cdp_neighbors.txt", {"device_name": "SW-CORE"}),
    ("/ingest/switch", "sample_switch_hp_running_config.txt", {"device_name": "SW-HP", "vendor_hint": "hp"}),
    ("/ingest/switch", "sample_switch_hp_lldp_brief.txt", {"device_name": "SW-HP", "vendor_hint": "hp"}),
    ("/ingest/switch", "sample_switch_hp_lldp_detail.txt", {"device_name": "SW-HP", "vendor_hint": "hp"}),
    ("/ingest/mac-table", "sample_mac_table_cisco.txt", {"device_name": "SW-CORE"}),
    ("/ingest/mac-table", "sample_mac_table_hp.txt", {"device_name": "SW-HP"}),
    ("/ingest/arp", "sample_arp_cisco.txt", {}),
    ("/ingest/arp", "sample_arp_unix.txt", {}),
    ("/ingest/arp", "sample_arp_windows.txt", {}),
    ("/ingest/pcap", "multi_protocol_sample.pcap", {}),
    ("/ingest/pcap", "modbus_sample.pcap", {}),
    ("/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {"baseline_name": "B1"}),
    ("/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {"baseline_name": "B1"}),
    ("/ingest/baseline/asset-inventory", "sample_asset_inventory.csv", {"baseline_name": "B1"}),
    ("/ingest/forti-syslog", "sample_forti_events.cef", {}),
    ("/ingest/forti-report", "sample_forti_traffic.csv", {}),
    ("/ingest/syslog", "sample_syslog_asa.log", {}),
    ("/ingest/syslog", "sample_syslog_panos.log", {}),
    ("/ingest/syslog", "sample_syslog_pfsense.log", {}),
]

# Open-finding check_names after the full pipeline (snapshot of the set).
EXPECTED_CHECKS = {
    # FortiGate config review
    "config_av_missing_on_file_policy", "config_dns_external",   # secondary 8.8.8.8 (every external resolver is reported)
    "config_ha_no_auth", "config_ids_ips_missing",
    # batch A (2026-10-15): the sample config has no banner / revision backup / HA monitor /
    # device detection and does not log the implicit deny
    "config_device_detection_disabled", "config_ha_no_monitor_interfaces", "config_implicit_deny_not_logged",
    "config_no_login_banner", "config_no_revision_backup",
    "config_no_dos_policy_ot",    # batch B: no DoS policy on the labelled OT interface (port1)
    "config_logging_disabled", "config_maintainer_account_enabled", "config_monitoring_readiness",
    "config_permit_any_any_any",   # sample policy 98 permits all services (owner 2026-10-12: 3.2 = all in ANY position)
    "config_mgmt_not_restricted_to_mgmt_zone",
    # DR-05: lockout / idle timeout left at the FortiOS defaults (3 tries, 5 min) are not findings
    "config_no_av_profile", "config_no_central_auth", "config_admin_no_two_factor",
    "config_no_password_policy", "config_no_scheduled_backup", "config_no_syslog_forwarding",
    "config_ntp_fortiguard", "config_same_zone_rule", "config_split_tunneling_enabled",
    "config_vpn_no_idle_timeout", "config_vpn_no_routing_policy", "config_vpn_source_unrestricted",
    # traffic (pcap)
    "unauthorized_industrial_write",
    # VPN tabletop H-05: the sample's PLCs share a subnet with L2 hosts
    "flat_control_segment",
    # the sample inventory seeds four IEC 62443 zones; they communicate with no documented conduit
    "undocumented_conduit",
    # real-time (logs)
    "auth_failure", "auth_from_non_admin_host", "fw_config_change", "ips_ot_conduit",
    "it_ot_bypass", "ot_internet_egress", "scanning_denied", "unauth_ot_write",
    # periodic reviews
    "conduit_matrix_drift", "denied_trend", "ip_conflict", "ntp_sync", "rule_conduit_drift",
    "shadow_rule", "undocumented_lldp_device", "unknown_device", "unused_policy",
    "zone_doc_1_1", "zone_doc_1_2", "zone_doc_1_3", "zone_doc_1_4", "zone_doc_1_5", "zone_doc_1_6",
    # Phase-6 rule twins, enabled by the Purdue levels assigned to FW-OT's legs
    "rule_cleartext_creds", "rule_it_ot_bypass", "rule_mgmt_protocol", "rule_mgmt_wrong_zone", "rule_ot_it_dependency",
    "dead_end_permit",   # Cisco edge permits any -> PLC 10.0.1.10:502 at L4/L3; nothing carries it to L1
    "chain_ot_upward_skip",  # G-02: PLCs (L1) -> DMZ historian (L3.5) tcp/443 through FW-OT #30
}


@contextmanager
def _api(db_path):
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


def _upload_all(c):
    for url, name, params in UPLOADS:
        r = c.post(url, params=params, files={"file": (name, (SAMPLES / name).read_bytes(),
                                                       "application/octet-stream")})
        assert r.status_code == 200, (url, name, r.status_code, r.text[:300])


def _open(c):
    s = c.get("/findings/summary").json()
    return s["total_open"], set(s["by_check_name"])


def test_every_sample_file_is_ingested():
    used = {name for _, name, _ in UPLOADS}
    on_disk = {p.name for p in SAMPLES.iterdir() if p.is_file() and p.suffix != ".py"}
    assert on_disk == used, on_disk ^ used


def test_full_pipeline_snapshot_and_idempotence(tmp_path):
    with _api(tmp_path / "e2e.db") as c:
        _upload_all(c)
        # As in seed(): FortiGate legs get Purdue levels (port2 = industrial DMZ)
        # and a DMZ jump host exists.
        with c.Session() as s:
            for i in s.query(FirewallInterface):
                i.purdue_level = {"port1": 1, "port2": 3.5, "port3": 4}.get(i.name, i.purdue_level)
            jh = s.query(Host).filter(Host.ip == "10.0.2.50").first() or Host(ip="10.0.2.50", sources=["demo"])
            jh.hostname, jh.device_type, jh.purdue_level, jh.classification_source = \
                "jumphost-dmz", "jump_host", 3.5, "manual"
            s.add(jh)
            s.commit()
        # the FortiGate config checks that depend on interface labels (DoS policy per OT
        # interface) need an upload after the labels exist: upload once more before the snapshot
        _upload_all(c)

        run = c.post("/reviews/run").json()
        assert run["failed_reviews"] == []
        total, checks = _open(c)
        missing, extra = EXPECTED_CHECKS - checks, checks - EXPECTED_CHECKS
        assert not missing and not extra, f"missing={sorted(missing)} extra={sorted(extra)}"

        # re-running reviews: nothing new, nothing lost
        again = c.post("/reviews/run").json()
        assert again["total_findings"] == 0 and again["failed_reviews"] == []
        assert _open(c) == (total, checks)

        # re-uploading every sample, then reviewing again: no growth
        _upload_all(c)
        c.post("/reviews/run")
        total2, checks2 = _open(c)
        assert total2 <= total, (total, total2)
        assert checks2 == checks
