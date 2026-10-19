"""
F-01: every public function of app/parsers/alert_engine.py is exercised
with a positive case (a finding is produced / the documented value is
returned) and a negative case (no finding / documented no-op).

COVERAGE maps each public function to the test(s) that exercise it;
test_every_public_function_is_mapped fails when a new public function is
added to alert_engine without a test listed here.

Real-time checks are driven through evaluate_event() with crafted
FortiAnalyzerEvent rows (positive) and called directly for the negative
case; periodic reviews are called directly and through run_periodic_reviews.
"""
import inspect
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import (
    ApprovedCommsEntry, ApprovedHost, Attestation, Baseline, Finding, Firewall,
    FirewallInterface, FirewallRule, FirewallZone, FortiAnalyzerEvent, Host,
    MacTableEntry, NetworkSession, ProtocolDetail, SwitchInterface, SwitchVlan,
)
from app.parsers import alert_engine as ae

COVERAGE = {
    "escalation_count": "test_escalation_count",
    "check_it_ot_bypass": "test_check_it_ot_bypass",
    "check_ot_internet_egress": "test_check_ot_internet_egress",
    "check_remote_access_bypass": "test_check_remote_access_bypass",
    "check_remote_access_app": "test_check_remote_access_app",
    "check_auth_failure": "test_check_auth_failure",
    "check_fw_config_change": "test_check_fw_config_change",
    "check_ips_ot_conduit": "test_check_ips_ot_conduit",
    "check_unauth_ot_write": "test_check_unauth_ot_write",
    "check_scanning_denied": "test_check_scanning_denied",
    "check_log_silence": "test_check_log_silence",
    "check_ha_system_error": "test_check_ha_system_error",
    "check_ha_failover": "test_check_ha_failover",
    "evaluate_event": "test_evaluate_event_isolates_failing_check",
    "review_conduit_matrix_drift": "test_review_conduit_matrix_drift",
    "review_session_no_permitting_rule": "test_review_session_no_permitting_rule_and_unused",
    "review_unused_policies": "test_review_session_no_permitting_rule_and_unused",
    "review_denied_trends": "test_review_denied_trends",
    "review_cleartext_protocols": "test_review_cleartext_protocols",
    "review_mgmt_protocols": "test_review_mgmt_protocols",
    "review_checks_map": "test_review_checks_map",
    "review_ot_it_dependencies": "test_review_ot_it_dependencies",
    "review_cleartext_credentials": "test_review_cleartext_credentials",
    "review_unknown_devices": "test_review_unknown_devices",
    "review_ip_conflicts": "test_review_ip_conflicts",
    "review_dead_default_gateways": "test_review_dead_default_gateways",
    "review_misplaced_devices": "test_review_misplaced_devices",
    "review_shadow_rules": "test_review_shadow_rules",
    "review_historian_in_control_zone": "test_review_role_placement",
    "review_sis_isolation": "test_review_sis_isolation",
    "review_transient_devices": "test_review_transient_devices",
    "review_switch_port_nac": "test_review_fortiswitch_ports",
    "review_switch_unused_ports": "test_review_fortiswitch_ports",
    "review_default_credentials": "test_review_default_credentials_and_weak_tls",
    "review_weak_tls": "test_review_default_credentials_and_weak_tls",
    "review_wireless_in_ot_zone": "test_review_role_placement",
    "review_single_path_critical_devices": "test_review_single_path_and_redundancy",
    "review_no_path_redundancy": "test_review_single_path_and_redundancy",
    "review_undocumented_lldp_devices": "test_review_undocumented_lldp_devices",
    "review_mgmt_access_from_wrong_zone": "test_review_mgmt_access_from_wrong_zone",
    "review_mgmt_access_not_restricted": "test_review_mgmt_access_not_restricted",
    "review_firmware_not_documented": "test_review_firmware_not_documented",
    "review_zone_documentation": "test_review_zone_documentation",
    "review_ntp_sync": "test_review_ntp_sync",
    "review_ns_it_ot_bypass": "test_review_ns_it_ot_bypass",
    "review_ns_ot_internet_egress": "test_review_ns_ot_internet_egress",
    "review_ns_remote_access_bypass": "test_review_ns_remote_access_bypass",
    "review_ns_scanning_anomaly": "test_review_ns_scanning_anomaly",
    "review_ns_remote_access_app": "test_review_ns_remote_access_app",
    "review_ns_mgmt_from_non_admin": "test_review_ns_mgmt_from_non_admin",
    "review_vlan_zone_mismatch": "test_review_vlan_zone_mismatch",
    "review_ghost_vlans": "test_review_ghost_vlans",
    "review_intervlan_routing": "test_review_intervlan_routing",
    "review_rule_cleartext_protocols": "test_rule_twins_positive_and_negative",
    "review_rule_mgmt_protocols": "test_rule_twins_positive_and_negative",
    "review_rule_cleartext_creds": "test_rule_twins_positive_and_negative",
    "review_rule_ot_it_dependency": "test_rule_twins_positive_and_negative",
    "review_rule_dns_external": "test_review_rule_dns_external",
    "review_rule_mgmt_wrong_zone": "test_rule_twins_positive_and_negative",
    "review_rule_it_ot_bypass": "test_rule_twins_positive_and_negative",
    "review_rule_conduit_drift": "test_rule_conduit_drift",
    "review_disabled_rules": "test_review_disabled_rules",
    "failed_reviews": "test_run_periodic_reviews_failure_isolation",
    "auto_resolved_counts": "test_run_periodic_reviews_auto_resolve",
    "unknown_check_name_counts": "test_unknown_check_name_counts",
    "rules_not_judged": "test_rules_not_judged",
    "last_review_info": "test_run_periodic_reviews_failure_isolation",
    "auto_resolve_enabled": "test_run_periodic_reviews_auto_resolve",
    "run_periodic_reviews": "test_run_periodic_reviews_failure_isolation, "
                            "test_run_periodic_reviews_auto_resolve",
}


def test_every_public_function_is_mapped():
    public = {n for n, f in inspect.getmembers(ae, inspect.isfunction)
              if not n.startswith("_") and f.__module__ == ae.__name__}
    assert len(public) >= 50
    assert public == set(COVERAGE), (sorted(public - set(COVERAGE)), sorted(set(COVERAGE) - public))
    tests = {t.strip() for v in COVERAGE.values() for t in v.split(",")}
    assert tests <= set(globals()), sorted(tests - set(globals()))


# ---------------------------------------------------------------- fixtures --

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


NOW = datetime.now(timezone.utc)
_ip_seq = iter(range(1, 10_000))


def host(db, ip=None, level=None, mac=None, **kw):
    h = Host(ip=ip, mac=mac, purdue_level=level, **kw)
    db.add(h)
    db.flush()
    return h


def ev(db, log_type="traffic", action="accept", src=None, dst=None, port=None, **kw):
    kw.setdefault("received_at", NOW)
    kw.setdefault("raw_fields", {})
    e = FortiAnalyzerEvent(source_type="api_push", log_type=log_type, action=action,
                           src_ip=src, dst_ip=dst, dst_port=port, device_name=kw.pop("device_name", "FGT1"),
                           **kw)
    db.add(e)
    db.flush()
    return e


def sess(db, src, dst, port, transport="tcp", protocol="unknown", packets=10):
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=port,
                       transport=transport, protocol=protocol, packet_count=packets)
    db.add(s)
    db.flush()
    return s


def baseline(db, name="B", hosts=(), comms=()):
    b = Baseline(name=name, is_active=True)
    db.add(b)
    db.flush()
    for ip, role, *rest in hosts:
        db.add(ApprovedHost(baseline_id=b.id, ip=ip, role=role, notes=rest[0] if rest else None))
    for src, dst, port, proto in comms:
        db.add(ApprovedCommsEntry(baseline_id=b.id, src=src, dst=dst, dst_port=port, protocol=proto))
    db.flush()
    return b


def names(findings):
    return {f.check_name for f in findings if f}


def evaluate(db, e):
    return names(ae.evaluate_event(e, db))


# ------------------------------------------------------- real-time checks --

def test_check_it_ot_bypass(db):
    host(db, "10.4.0.5", 4)
    host(db, "10.1.0.5", 1)
    host(db, "10.3.0.5", 3)
    host(db, "10.2.0.5", 2)
    f = ae.evaluate_event(ev(db, src="10.4.0.5", dst="10.1.0.5", port=502), db)
    hit = [x for x in f if x.check_name == "it_ot_bypass"][0]
    assert hit.detail["detection"] == "purdue_level" and hit.severity == "critical"
    # reverse direction (deep OT -> IT) is also a bypass
    assert ae.check_it_ot_bypass(ev(db, src="10.1.0.5", dst="10.4.0.5", port=1), db) is not None
    # classified but adjacent (L3 -> L2): no finding, heuristic not used
    assert ae.check_it_ot_bypass(ev(db, src="10.3.0.5", dst="10.2.0.5", port=502), db) is None
    # denied / non-traffic / public IP: no finding
    assert ae.check_it_ot_bypass(ev(db, action="deny", src="10.4.0.5", dst="10.1.0.5"), db) is None
    assert ae.check_it_ot_bypass(ev(db, log_type="event", src="10.4.0.5", dst="10.1.0.5"), db) is None
    assert ae.check_it_ot_bypass(ev(db, src="10.4.0.5", dst="8.8.8.8"), db) is None
    # heuristic path: unclassified hosts in different /16s
    h = ae.check_it_ot_bypass(ev(db, src="10.9.0.1", dst="192.168.5.5", port=80), db)
    assert h.detail["detection"] == "subnet_heuristic" and h.detail["src_classified"] is False
    assert ae.check_it_ot_bypass(ev(db, src="10.9.0.1", dst="10.9.7.7", port=80), db) is None


def test_check_ot_internet_egress(db):
    host(db, "10.1.0.7", 1)
    host(db, "10.4.0.7", 4)
    host(db, "10.6.0.7", None)
    f = ae.evaluate_event(ev(db, src="10.1.0.7", dst="8.8.8.8", port=53, service="DNS"), db)
    assert [x.severity for x in f if x.check_name == "ot_internet_egress"] == ["critical"]
    assert ae.check_ot_internet_egress(ev(db, src="10.6.0.7", dst="1.1.1.1", port=443), db).severity == "high"
    assert ae.check_ot_internet_egress(ev(db, src="10.200.0.1", dst="1.1.1.1", port=443), db).severity == "medium"
    assert ae.check_ot_internet_egress(ev(db, src="10.4.0.7", dst="8.8.8.8", port=443), db) is None
    assert ae.check_ot_internet_egress(ev(db, src="10.1.0.7", dst="10.4.0.7", port=443), db) is None
    assert ae.check_ot_internet_egress(ev(db, action="deny", src="10.1.0.7", dst="8.8.8.8"), db) is None


def test_check_remote_access_bypass(db):
    # path 1: VPN event, no baseline -> fires
    vpn = ev(db, log_type="event", subtype="vpn", action="tunnel-up", src="198.51.100.4", dst="10.0.2.20")
    assert "remote_access_bypass" in evaluate(db, vpn)
    baseline(db, hosts=[("10.0.2.50", "jump_host")])
    ok_vpn = ev(db, log_type="event", subtype="ssl-vpn", src="198.51.100.4", dst="10.0.2.50")
    assert ae.check_remote_access_bypass(ok_vpn, db) is None
    # path 2: external RDP to a non-jump host
    f = ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.0.2.21", port=3389), db)
    assert f.detail["detection"] == "external_port_match"
    # path 3: external traffic straight onto an OT host, any port
    host(db, "10.1.0.30", 1)
    f = ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.1.0.30", port=8080), db)
    assert f.detail["detection"] == "external_to_ot_direct"
    # negatives: to the jump host, from inside, denied, missing IPs
    assert ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.0.2.50", port=3389), db) is None
    assert ae.check_remote_access_bypass(ev(db, src="10.4.0.1", dst="10.1.0.30", port=22), db) is None
    assert ae.check_remote_access_bypass(ev(db, action="deny", src="198.51.100.9", dst="10.1.0.30"), db) is None
    assert ae.check_remote_access_bypass(ev(db, src=None, dst="10.1.0.30"), db) is None


def test_check_remote_access_app(db):
    assert "remote_access_app" in evaluate(db, ev(db, src="10.3.0.1", dst="1.2.3.4", app="TeamViewer"))
    assert ae.check_remote_access_app(ev(db, src="10.3.0.1", dst="1.2.3.4", app="HTTPS.BROWSER"), db) is None
    assert ae.check_remote_access_app(ev(db, src="10.3.0.1", dst="1.2.3.4"), db) is None


def test_check_auth_failure(db):
    fail = ev(db, log_type="event", subtype="login", action="failed", src="10.4.0.9", user="admin")
    assert "auth_failure" in evaluate(db, fail)
    # successful login without a baseline: nothing to compare against
    ok = dict(log_type="event", subtype="login", action="success", user="admin")
    assert ae.check_auth_failure(ev(db, src="10.4.0.9", **ok), db) is None
    baseline(db, hosts=[("10.3.0.10", "admin_ws")])
    f = ae.check_auth_failure(ev(db, src="10.4.0.9", **ok), db)
    assert f.check_name == "auth_from_non_admin_host"
    assert ae.check_auth_failure(ev(db, src="10.3.0.10", **ok), db) is None
    assert ae.check_auth_failure(ev(db, log_type="traffic", subtype="login", action="failed",
                                    src="10.4.0.9"), db) is None


def test_check_fw_config_change(db):
    chg = ev(db, log_type="event", subtype="system", action="Edit", user="admin",
             raw_fields={"msg": "Edit firewall.policy 12"}, raw_message="cfg edit")
    assert "fw_config_change" in evaluate(db, chg)
    assert ae.check_fw_config_change(ev(db, log_type="event", subtype="system",
                                        raw_fields={"msg": "user login ok"}), db) is None
    assert ae.check_fw_config_change(ev(db, log_type="event", subtype="vpn",
                                        raw_fields={"msg": "edit"}), db) is None


def test_check_ips_ot_conduit(db):
    for lt, st in (("ips", None), ("utm", "ips")):
        e = ev(db, log_type=lt, subtype=st, action="dropped", src="10.4.0.1", dst=f"10.1.0.{next(_ip_seq)}",
               attack_name="Modbus.Write.Coil", severity="high")
        assert "ips_ot_conduit" in evaluate(db, e)
    assert ae.check_ips_ot_conduit(ev(db, log_type="utm", subtype="webfilter"), db) is None


def test_check_unauth_ot_write(db):
    f = ae.evaluate_event(ev(db, src="10.3.0.20", dst="10.1.0.5", port=502), db)
    w = [x for x in f if x.check_name == "unauth_ot_write"][0]
    assert w.detail["baseline_loaded"] is False and w.detail["protocol"] == "Modbus/TCP"
    b = baseline(db, hosts=[("10.3.0.99", "jump_host")])
    f = ae.check_unauth_ot_write(ev(db, src="10.3.0.20", dst="10.1.0.5", port=102), db)
    assert f.detail["approved_engineering_hosts"] == 0
    db.add(ApprovedHost(baseline_id=b.id, ip="10.2.0.10", role="engineering_ws"))
    db.flush()
    f = ae.check_unauth_ot_write(ev(db, src="10.3.0.21", dst="10.1.0.5", port=44818), db)
    assert f.detail["approved_hosts"] == ["10.2.0.10"]
    assert ae.check_unauth_ot_write(ev(db, src="10.2.0.10", dst="10.1.0.5", port=502), db) is None
    assert ae.check_unauth_ot_write(ev(db, src="10.3.0.21", dst="10.1.0.5", port=443), db) is None
    assert ae.check_unauth_ot_write(ev(db, action="deny", src="10.3.0.21", dst="10.1.0.5", port=502), db) is None


def test_check_scanning_denied(db):
    anomaly = ev(db, log_type="traffic", action="deny", src="10.4.0.66", dst="10.1.0.1",
                 subtype="anomaly", raw_fields={"attack": "tcp_port_scan"})
    assert "scanning_denied" in evaluate(db, anomaly)
    t0 = datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc)
    last = None
    for i in range(20):
        last = ev(db, action="deny", src="10.4.0.77", dst="10.1.0.1", port=1000 + i,
                  event_time=t0 + timedelta(seconds=10 * i))
    f = ae.check_scanning_denied(last, db)
    assert f.detail["detection"] == "sliding_window_count" and f.detail["deny_count_in_window"] == 20
    # 3 denies spread over hours of a historical file: not a scan (T3-15)
    for i in range(3):
        last = ev(db, action="deny", src="10.4.0.88", dst="10.1.0.1", port=1,
                  event_time=t0 + timedelta(hours=i))
    assert ae.check_scanning_denied(last, db) is None
    assert ae.check_scanning_denied(ev(db, action="accept", src="10.4.0.88"), db) is None


def test_check_log_silence(db):
    e = ev(db, log_type="event", subtype="system", raw_fields={"msg": "Device offline"},
           device_name="FGT-CELL")
    assert "log_silence" in evaluate(db, e)
    assert ae.check_log_silence(ev(db, log_type="event", subtype="system",
                                   raw_fields={"msg": "x"}), db) is None
    assert ae.check_log_silence(ev(db, log_type="traffic", raw_fields={"msg": "logd"}), db) is None


def test_check_ha_system_error(db):
    e = ev(db, log_type="event", subtype="ha", raw_fields={"msg": "HA failover to member 2"})
    assert "ha_system_error" in evaluate(db, e)
    assert ae.check_ha_system_error(ev(db, log_type="event", subtype="user",
                                       raw_fields={"msg": "x"}), db) is None
    assert ae.check_ha_system_error(ev(db, log_type="traffic", raw_fields={"msg": "failover"}), db) is None


def test_check_ha_failover(db):
    """B-12: an a-p cluster's active member changes -> one low finding."""
    from app.models import Site, SiteDevice, SiteDeviceSerial
    site = Site(name="HA site", code="ha-site")
    db.add(site)
    db.flush()
    dev = SiteDevice(site_id=site.id, device_name="fw-ha", source="manual", is_ha=True,
                     ha_mode="a-p", serials=[SiteDeviceSerial(serial="HA-1", source="manual"),
                                             SiteDeviceSerial(serial="HA-2", source="manual")])
    db.add(dev)
    db.flush()

    def t(serial, minute, **kw):
        return ev(db, site_id=site.id, raw_fields={"devid": serial},
                  received_at=NOW + timedelta(minutes=minute), **kw)

    assert ae.check_ha_failover(t("HA-1", 1, subtype="forward"), db) is None   # baseline
    assert ae.check_ha_failover(t("HA-1", 2, subtype="forward"), db) is None
    f = ae.check_ha_failover(t("HA-2", 3, subtype="forward"), db)
    assert f.check_name == "ha_failover" and f.severity == "low" and f.site_id == site.id
    assert (f.detail["from_serial"], f.detail["to_serial"]) == ("HA-1", "HA-2")
    assert ae.check_ha_failover(t("HA-2", 4, subtype="forward"), db) is None
    assert ae.check_ha_failover(t("HA-1", 5, log_type="event", subtype="system"), db) is None
    assert ae.check_ha_failover(t("UNKNOWN", 6), db) is None
    dev.ha_mode = "a-a"
    assert ae.check_ha_failover(t("HA-1", 7, subtype="forward"), db) is None


def test_evaluate_event_isolates_failing_check(db, monkeypatch):
    assert ae.evaluate_event(ev(db, log_type="traffic", action="accept",
                                src="10.3.0.1", dst="10.3.0.2", port=443), db) == []

    def boom(e, s):
        s.add(Finding(category="real_time", check_name="x", severity="low", title="partial write"))
        s.flush()
        raise RuntimeError("check exploded")

    monkeypatch.setattr(ae, "_RT_CHECKS", [boom, ae.check_remote_access_app])
    out = ae.evaluate_event(ev(db, src="10.3.0.1", dst="1.2.3.4", app="AnyDesk"), db)
    assert names(out) == {"remote_access_app"}
    assert db.query(Finding).filter(Finding.title == "partial write").count() == 0


def test_escalation_count(db):
    assert ae.escalation_count(db) == 0
    ae.check_ot_internet_egress(ev(db, src="10.6.0.1", dst="8.8.8.8", port=443), db)  # medium
    db.flush()
    f = db.query(Finding).one()
    assert f.severity == "medium"
    # same severity again: re-detected, not escalated
    assert ae.check_ot_internet_egress(ev(db, src="10.6.0.1", dst="8.8.8.8", port=443), db) is None
    assert ae.escalation_count(db) == 0 and f.occurrence_count == 2
    host(db, "10.6.0.1", 1)
    assert ae.check_ot_internet_egress(ev(db, src="10.6.0.1", dst="8.8.8.8", port=443), db) is None
    assert ae.escalation_count(db) == 1 and f.severity == "critical"
    assert db.query(Finding).count() == 1


# --------------------------------------------------------- periodic reviews --

def test_review_conduit_matrix_drift(db):
    a, b = host(db, "10.1.0.10", 1), host(db, "10.2.0.10", 2)
    sess(db, b, a, 502)
    sess(db, b, a, 23)
    assert ae.review_conduit_matrix_drift(db) == []  # no baseline
    baseline(db, comms=[("10.2.0.0/24", "10.1.0.0/24", 502, "tcp")])
    out = ae.review_conduit_matrix_drift(db)
    assert len(out) == 1 and out[0].detail["dst_port"] == 23 and out[0].check_name == "conduit_matrix_drift"
    assert ae.review_conduit_matrix_drift(db) == []  # dedup: open finding re-detected


def test_review_session_no_permitting_rule_and_unused(db):
    a, b = host(db, "10.1.0.10", 1), host(db, "10.2.0.10", 2)
    sess(db, b, a, 23)
    db.add(FirewallRule(device_name="ACL", device_type="cisco_ios", src="10.2.0.0/24",
                        dst="10.1.0.0/24", protocol="tcp", dst_port="502", action="permit",
                        raw_line="permit tcp 10.2.0.0 0.0.0.255 10.1.0.0 0.0.0.255 eq 502"))
    db.flush()
    out = ae.review_session_no_permitting_rule(db)
    assert names(out) == {"session_no_permitting_rule"} and out[0].detail["dst_port"] == 23
    unused = ae.review_unused_policies(db)
    assert names(unused) == {"unused_policy"} and unused[0].rule_id is not None
    # session now matches the rule: neither check fires
    sess(db, b, a, 502)
    diff = {"unexpected_traffic": [], "unused_rules": [], "sessions_considered": 2}
    assert ae.review_session_no_permitting_rule(db, _diff=diff) == []
    assert ae.review_unused_policies(db, _diff=diff) == []


def test_review_denied_trends(db):
    for i in range(5):
        ev(db, action="deny", src="10.4.0.50", dst="10.1.0.1", port=100 + i)
    for i in range(4):
        ev(db, action="deny", src="10.4.0.51", dst="10.1.0.1", port=100 + i)
    ev(db, action="deny", src="10.4.0.52", dst="10.1.0.1", port=1,
       received_at=NOW - timedelta(days=200))
    out = ae.review_denied_trends(db)
    assert [f.detail["src_ip"] for f in out] == ["10.4.0.50"]
    assert out[0].detail["deny_count"] == 5 and out[0].severity == "info"


def test_review_cleartext_protocols(db):
    it, ot, ot2 = host(db, "10.3.0.1", 3), host(db, "10.1.0.1", 1), host(db, "10.1.0.2", 1)
    sess(db, it, ot, 23, protocol="telnet")
    sess(db, ot2, ot, 21, protocol="ftp")          # same level: skipped
    sess(db, host(db, "10.9.9.9"), ot, 80, protocol="http")  # unclassified src: skipped
    s = sess(db, it, host(db, "10.2.0.5", 2), 445, protocol="smb")
    db.add(ProtocolDetail(session_id=s.id, protocol="smb1", direction="request",
                          summary="SMBv1 negotiate", fields={"command": "negotiate"}, timestamp=NOW))
    db.flush()
    out = ae.review_cleartext_protocols(db)
    assert sorted(f.check_name for f in out) == ["cleartext_protocol", "smbv1_legacy"]
    ins = [f for f in out if f.check_name == "cleartext_protocol"][0]
    assert ins.detail["protocol_name"] == "Telnet"
    assert [f for f in out if f.check_name == "smbv1_legacy"][0].detail["smb_command"] == "negotiate"


def test_review_mgmt_protocols(db):
    it, ot, ot2 = host(db, "10.3.0.1", 3), host(db, "10.1.0.1", 1), host(db, "10.1.0.2", 1)
    sess(db, it, ot, 23, protocol="telnet")         # cleartext management: high
    sess(db, it, ot2, 22, protocol="ssh")           # encrypted management: medium
    sess(db, it, ot, 21, protocol="ftp")            # cleartext, not management
    sess(db, ot2, ot, 3389, protocol="rdp")         # same level: skipped
    out = ae.review_mgmt_protocols(db)
    got = sorted((f.detail["dst_port"], f.detail["cleartext"], f.severity) for f in out)
    assert got == [(22, False, "medium"), (23, True, "high")]
    assert {f.check_name for f in out} == {"mgmt_protocol"}


def test_review_ot_it_dependencies(db):
    dns = host(db, "10.4.0.53", 4)
    sess(db, host(db, "10.1.0.1", 1), dns, 53, transport="udp")
    sess(db, host(db, "10.3.0.1", 3), dns, 53, transport="udp")
    sess(db, host(db, "10.1.0.2", 1), dns, 502)
    out = ae.review_ot_it_dependencies(db)
    assert [(f.detail["src_ip"], f.detail["service"]) for f in out] == [("10.1.0.1", "DNS")]


def test_review_cleartext_credentials(db):
    src = host(db, "10.3.0.1", 3)
    sess(db, src, host(db, "10.1.0.1", 1), 21)
    sess(db, src, host(db, "10.7.0.1"), 23)          # unclassified dst: flagged with a note
    sess(db, src, host(db, "10.4.0.1", 4), 23)       # IT dst: not flagged
    sess(db, src, host(db, "10.1.0.2", 1), 443)      # not cleartext
    out = ae.review_cleartext_credentials(db)
    by = {f.detail["dst_ip"]: f for f in out}
    assert set(by) == {"10.1.0.1", "10.7.0.1"}
    assert "classification_note" in by["10.7.0.1"].detail
    assert "classification_note" not in by["10.1.0.1"].detail


def test_review_unknown_devices(db):
    host(db, "10.1.0.1", mac="aa:bb:cc:00:00:01")
    host(db, "10.1.0.2", mac="AA:BB:CC:00:00:02")
    host(db, "10.1.0.3", mac="aa:bb:cc:00:00:03")
    assert ae.review_unknown_devices(db) == []  # no baseline
    b = baseline(db, hosts=[("10.1.0.1", "hmi")])
    db.add(ApprovedHost(baseline_id=b.id, mac="aa:bb:cc:00:00:02", role="hmi"))
    db.flush()
    out = ae.review_unknown_devices(db)
    assert [f.detail["ip"] for f in out] == ["10.1.0.3"]


def test_review_ip_conflicts(db):
    host(db, "10.1.0.9", mac="aa:00:00:00:00:01")
    host(db, "10.1.0.9", mac="aa:00:00:00:00:02")
    host(db, "10.1.0.10", mac="aa:00:00:00:00:03")
    out = ae.review_ip_conflicts(db)
    assert [(f.detail["ip"], f.detail["mac_count"]) for f in out] == [("10.1.0.9", 2)]


def test_review_dead_default_gateways(db):
    from app.models import ConnectionAttempt
    def arp(src, dst, n=1):
        db.add(ConnectionAttempt(src_ip=src, dst_ip=dst, transport="arp", outcome="arp_unanswered", count=n))
    assert ae.review_dead_default_gateways(db) == []
    arp("192.168.0.10", "192.168.0.1"); arp("192.168.0.20", "192.168.0.1")   # two hosts: dead gateway
    arp("192.168.0.10", "192.168.0.99")                                      # one sweep probe: no
    arp("192.168.0.30", "192.168.0.5", 4)                                    # one host, 4 requests
    arp("192.168.0.10", "192.168.0.7"); arp("192.168.0.11", "192.168.0.7")
    host(db, "192.168.0.7")                                                  # claimed: no
    db.flush()
    out = ae.review_dead_default_gateways(db)
    by = {f.detail["ip"]: f for f in out}
    assert set(by) == {"192.168.0.1", "192.168.0.5"}
    assert by["192.168.0.1"].detail["requesting_hosts"] == ["192.168.0.10", "192.168.0.20"]
    assert by["192.168.0.1"].severity == "medium"


def test_review_misplaced_devices(db):
    assert ae.review_misplaced_devices(db) == []  # no zone data
    db.add_all([
        FirewallZone(device_name="FGT1", interface_name="port4", zone_name="CORP_USERS",
                     ip_cidr="10.50.0.0/24"),
        FirewallZone(device_name="FGT1", interface_name="port1", zone_name="OT_CELL",
                     ip_cidr="10.1.0.0/24"),
    ])
    host(db, "10.50.0.9", device_type="plc")
    host(db, "10.50.0.10", 4, device_type="workstation")
    host(db, "10.1.0.9", 1, device_type="plc")
    out = ae.review_misplaced_devices(db)
    assert [(f.detail["src_ip"], f.detail["zone_name"]) for f in out] == [("10.50.0.9", "CORP_USERS")]


def test_review_shadow_rules(db):
    for pid in ("1", "2"):
        db.add(FirewallRule(device_name="FGT1", device_type="fortigate", policy_id=pid,
                            src="10.0.0.0/8", dst="10.1.0.0/24", protocol="tcp",
                            dst_port="502", action="permit", rule_order=int(pid)))
    db.add(FirewallRule(device_name="OTHER", device_type="fortigate", policy_id="9",
                        src="10.0.0.0/8", dst="10.1.0.0/24", protocol="tcp",
                        dst_port="502", action="permit", rule_order=1))
    db.flush()
    out = ae.review_shadow_rules(db)
    assert len(out) == 1
    f = out[0]
    assert f.check_name == "shadow_rule" and f.detail["finding_type"] == "redundant"
    assert (f.detail["policy_id_a"], f.detail["policy_id_b"]) == ("1", "2")
    assert f.device_name == "FGT1"


def test_review_role_placement(db):
    host(db, "10.2.0.1", 2, role="historian", role_source="lldp")
    host(db, "10.3.0.1", 3, role="historian", role_source="lldp")
    host(db, "10.1.0.1", 1, role="ap", role_source="cdp")
    host(db, "10.4.0.1", 4, role="ap", role_source="cdp")
    assert [f.detail["ip"] for f in ae.review_historian_in_control_zone(db)] == ["10.2.0.1"]
    assert [f.detail["ip"] for f in ae.review_wireless_in_ot_zone(db)] == ["10.1.0.1"]


def test_review_sis_isolation(db):
    """Batch B (owner 2026-10-15): SIS hosts (is_safety_function) reached by, permitted from or
    sharing a network with non-safety hosts."""
    assert ae.review_sis_isolation(db) == []                       # no SIS host: nothing
    sis = host(db, "10.1.0.5", 1, is_safety_function=True, device_type="plc")
    sis2 = host(db, "10.1.0.6", 1, is_safety_function=True, device_type="plc")
    eng = host(db, "10.3.0.9", 3, device_type="engineering_workstation")
    hmi = host(db, "10.2.0.7", 2, device_type="hmi")
    other = host(db, "10.1.0.8", 1, device_type="plc")             # non-safety host on the SIS /24
    sess(db, hmi, sis, 502)                                        # flagged
    sess(db, hmi, sis, 44818)                                      # same pair: one finding
    sess(db, eng, sis, 102)                                        # engineering workstation: allowed
    sess(db, sis2, sis, 502)                                       # safety to safety: allowed
    db.add_all([
        FirewallRule(device_name="FGT1", device_type="fortigate", policy_id="10", src="10.2.0.0/24", dst="10.1.0.5/32", protocol="tcp",
                     dst_port="502", action="permit", rule_order=1),
        FirewallRule(device_name="FGT1", device_type="fortigate", policy_id="11", src="10.3.0.9/32", dst="10.1.0.5/32", protocol="tcp",
                     dst_port="102", action="permit", rule_order=2),
        FirewallRule(device_name="FGT1", device_type="fortigate", policy_id="12", src="any", dst="10.1.0.5/32", protocol="tcp",
                     dst_port="502", action="deny", rule_order=3),
    ])
    db.flush()
    out = ae.review_sis_isolation(db)
    kinds = sorted((f.detail["kind"], f.severity) for f in out)
    assert kinds == [("rule", "high"), ("session", "high"), ("subnet", "medium")]
    by = {f.detail["kind"]: f for f in out}
    assert by["session"].detail["src_ip"] == "10.2.0.7" and by["session"].detail["dst_ip"] == "10.1.0.5"
    assert by["rule"].detail["policy_id"] == "10" and by["rule"].detail["wide_sources"] == ["10.2.0.0/24"]
    assert by["subnet"].detail["network"] == "10.1.0.0/24" and by["subnet"].detail["other_hosts"] == ["10.1.0.8"]
    # idempotent: a second run updates the open findings (returns no new ones), never duplicates
    assert ae.review_sis_isolation(db) == []
    assert db.query(Finding).filter(Finding.check_name == "sis_zone_not_isolated").count() == 3


def test_review_transient_devices(db):
    """Batch C (owner 2026-10-15): laptop / IT-vendor OUIs on a control network with no identity."""
    assert ae.review_transient_devices(db) == []
    lap = host(db, "10.1.0.50", 1, mac="aa:bb:cc:00:00:50", vendor="Dell Inc.")
    plc = host(db, "10.1.0.5", 1, mac="aa:bb:cc:00:00:05", vendor="Siemens AG", device_type="plc")
    host(db, "10.3.0.50", 3, mac="aa:bb:cc:00:00:51", vendor="Lenovo")                  # L3: not a control network
    ok = host(db, "10.1.0.51", 1, mac="aa:bb:cc:00:00:52", vendor="Hewlett Packard", device_type="engineering_workstation",
              classification_source="manual")                                            # identified by hand
    appr = host(db, "10.1.0.52", 1, mac="aa:bb:cc:00:00:53", vendor="Dell Inc.")
    appr.approved = True                                                                   # approved on the page
    db.flush()
    out = ae.review_transient_devices(db)
    assert [f.detail["mac"] for f in out] == ["aa:bb:cc:00:00:50"] and out[0].severity == "medium"
    sess(db, lap, plc, 502)
    db.query(Finding).delete(); db.flush()
    out = ae.review_transient_devices(db)
    assert out[0].severity == "high" and out[0].detail["ics_targets"] == ["10.1.0.5:502"]
    lap.inventory_excluded = True
    db.flush(); db.query(Finding).delete(); db.flush()
    assert ae.review_transient_devices(db) == []


def test_review_default_credentials_and_weak_tls(db):
    """Batch C: sessions whose cleartext_auth records a default pair / community; ProtocolDetail
    rows with a weak negotiated version (written by the PCAP parser)."""
    assert ae.review_default_credentials(db) == [] and ae.review_weak_tls(db) == []
    a = host(db, "10.2.0.7", 2, device_type="hmi")
    b = host(db, "10.1.0.5", 1, device_type="plc")
    s1 = sess(db, a, b, 21)
    s1.cleartext_auth = "FTP login, default credentials (FTP)"
    s2 = sess(db, a, b, 161, transport="udp")
    s2.cleartext_auth = "SNMPv1/v2c community (default)"
    s3 = sess(db, a, b, 23)
    s3.cleartext_auth = "Telnet login"
    s4 = sess(db, a, b, 443)
    db.add(ProtocolDetail(session_id=s4.id, protocol="tls", summary="TLSv1.0 negotiated",
                          fields={"version": "TLSv1.0", "weak": True, "server_ip": "10.1.0.5", "server_port": 443}))
    db.flush()
    dc = ae.review_default_credentials(db)
    assert sorted(f.detail["dst_port"] for f in dc) == [21, 161] and all(f.severity == "high" for f in dc)
    wt = ae.review_weak_tls(db)
    assert len(wt) == 1 and wt[0].severity == "high" and wt[0].detail["cross_level"] is True   # L2 client -> L1 server
    assert ae.review_default_credentials(db) == [] and ae.review_weak_tls(db) == []            # idempotent


def test_review_single_path_and_redundancy(db):
    assert ae.review_single_path_critical_devices(db) == []  # no switch data
    assert ae.review_no_path_redundancy(db) == []
    host(db, "10.1.0.1", 1, role="plc")
    host(db, "10.1.0.2", 1, role="plc")
    host(db, "10.1.0.3", 1, role="plc")           # not visible: no determination
    host(db, "10.3.0.1", 3, role="switch")
    host(db, "10.3.0.2", 3, role="switch")
    db.add_all([
        SwitchInterface(device_name="SW1", port_name="Gi0/1", neighbor_ip="10.1.0.1"),
        SwitchInterface(device_name="SW1", port_name="Gi0/2", neighbor_ip="10.1.0.2"),
        SwitchInterface(device_name="SW2", port_name="Gi0/2", neighbor_ip="10.1.0.2"),
        SwitchInterface(device_name="SW1", port_name="Gi0/24", neighbor_ip="10.3.0.1"),
        SwitchInterface(device_name="SW1", port_name="Gi0/23", neighbor_ip="10.3.0.2"),
        SwitchInterface(device_name="SW2", port_name="Gi0/23", neighbor_ip="10.3.0.2"),
    ])
    db.flush()
    sp = ae.review_single_path_critical_devices(db)
    assert [f.detail["ip"] for f in sp] == ["10.1.0.1"]
    db.flush()
    red = ae.review_no_path_redundancy(db)
    by_ip = {f.detail["ip"]: f.detail for f in red}
    assert set(by_ip) == {"10.3.0.1", "10.1.0.1"}  # single-uplink switch + 7.1 device w/o HA
    assert by_ip["10.3.0.1"]["visible_uplinks"] == 1 and by_ip["10.1.0.1"]["ha_evidence"] is False


def test_review_undocumented_lldp_devices(db):
    host(db, "10.1.0.1", 1, role="plc", role_source="lldp")
    host(db, "10.1.0.2", 1, role="plc", role_source="cdp")
    host(db, "10.1.0.3", 1, role="plc", role_source="manual")
    assert ae.review_undocumented_lldp_devices(db) == []  # no baseline
    baseline(db, hosts=[("10.1.0.2", "hmi")])
    out = ae.review_undocumented_lldp_devices(db)
    assert [f.detail["ip"] for f in out] == ["10.1.0.1"]


def test_review_mgmt_access_from_wrong_zone(db):
    plc = host(db, "10.1.0.1", 1)
    rogue, admin, dmz = host(db, "10.4.0.20", 4), host(db, "10.3.0.10", 3), host(db, "10.35.0.5", 3.5)
    sess(db, rogue, plc, 22)
    sess(db, admin, plc, 22)
    sess(db, dmz, plc, 3389)
    sess(db, rogue, host(db, "10.4.0.21", 4), 22)  # IT -> IT: out of scope
    assert ae.review_mgmt_access_from_wrong_zone(db) == []  # no baseline
    baseline(db, hosts=[("10.3.0.10", "admin_ws")])
    out = {f.detail["src_ip"]: f for f in ae.review_mgmt_access_from_wrong_zone(db)}
    assert set(out) == {"10.4.0.20", "10.35.0.5"}
    assert out["10.35.0.5"].detail["dmz_source"] is True
    assert ae._SEVERITY_STEP_DOWN[out["10.4.0.20"].severity] == out["10.35.0.5"].severity


def test_review_mgmt_access_not_restricted(db):
    plc, plc2 = host(db, "10.1.0.1", 1), host(db, "10.1.0.2", 1)
    sess(db, host(db, "10.3.0.1", 3), plc, 22)
    sess(db, host(db, "10.4.0.1", 4), plc, 443)
    sess(db, host(db, "10.3.0.2", 3), plc2, 22)
    sess(db, host(db, "10.3.0.3", 3), plc2, 3389)
    out = ae.review_mgmt_access_not_restricted(db)
    assert [(f.detail["dst_ip"], f.detail["src_purdue_levels"]) for f in out] == [("10.1.0.1", [3, 4])]


def test_review_firmware_not_documented(db):
    host(db, "10.1.0.1", 1, role="plc")
    host(db, "10.1.0.2", 1, role="plc")
    host(db, "10.1.0.3", 1, role="plc")     # no CDP platform: can't evaluate
    db.add_all([
        SwitchInterface(device_name="SW1", port_name="1", neighbor_ip="10.1.0.1",
                        neighbor_platform="Siemens S7-1500"),
        SwitchInterface(device_name="SW1", port_name="2", neighbor_ip="10.1.0.2",
                        neighbor_platform="Siemens S7-1500"),
    ])
    db.flush()
    assert ae.review_firmware_not_documented(db) == []  # no baseline
    baseline(db, hosts=[("10.1.0.2", "hmi", "Firmware V2.9.4")])
    out = ae.review_firmware_not_documented(db)
    assert [f.detail["ip"] for f in out] == ["10.1.0.1"]
    assert out[0].detail["has_inventory_entry"] is False


def test_review_zone_documentation(db):
    out = ae.review_zone_documentation(db)
    assert sorted(f.check_name for f in out) == [f"zone_doc_1_{i}" for i in range(1, 7)]
    assert {f.detail["reason"] for f in out} == {"no attestation on record"}
    for f in out:
        f.status = "closed"
    db.add(Attestation(checklist_id="1.1", attested_by="a", attested_at=NOW, is_current=True))
    db.add(Attestation(checklist_id="1.2", attested_by="a", attested_at=NOW - timedelta(days=400),
                       is_current=True))
    db.flush()
    out = {f.check_name: f for f in ae.review_zone_documentation(db)}
    assert "zone_doc_1_1" not in out and len(out) == 5
    assert out["zone_doc_1_2"].detail["reason"].startswith("attestation stale")


def test_review_ntp_sync(db, monkeypatch):
    monkeypatch.setattr(ae, "_NTP_MIN_CAPTURE_SECONDS", 0)   # FO-11 roll-up tested below
    plc1, plc2, plc3 = host(db, "10.1.0.1", 1), host(db, "10.1.0.2", 1), host(db, "10.1.0.3", 2)
    internal = host(db, "10.3.0.123", 3)
    assert ae.review_ntp_sync(db) == []  # no NTP traffic anywhere: absence uninformative
    sess(db, plc1, host(db, "129.6.15.28"), 123, transport="udp")
    sess(db, plc2, internal, 123, transport="udp")
    out = ae.review_ntp_sync(db)
    pub = [f for f in out if f.detail.get("ntp_server_ip")]
    assert [(f.detail["ot_host_ip"], f.detail["ntp_server_ip"]) for f in pub] == [("10.1.0.1", "129.6.15.28")]
    silent = [f for f in out if f.detail.get("ip")]
    assert [f.detail["ip"] for f in silent] == ["10.1.0.3"]
    assert all(f.detail.get("ot_host_ip") != "10.1.0.2" for f in out)  # internal NTP = pass
    # FO-11: on a capture shorter than the threshold the silent devices are
    # one informational roll-up, not one finding each
    monkeypatch.setattr(ae, "_NTP_MIN_CAPTURE_SECONDS", 3600)
    roll = [f for f in ae.review_ntp_sync(db) if f.detail.get("device_count")]
    assert [(f.severity, f.detail["devices"]) for f in roll] == [("info", ["10.1.0.3"])]
    roll[0].status = "closed"
    monkeypatch.setattr(ae, "_NTP_MIN_CAPTURE_SECONDS", 0)
    # regression: each (OT host, public server) pair is its own finding, and
    # the FortiGate-config finding no longer collides with them on dedup
    sess(db, plc2, host(db, "216.239.35.0"), 123, transport="udp")
    db.add(Finding(category="config_review", check_name="config_ntp_fortiguard", severity="low",
                   title="ntp fortiguard", status="open"))
    db.flush()
    again = ae.review_ntp_sync(db)
    assert sorted(f.detail["source"] for f in again) == ["fortigate_config", "pcap_network_session"]
    assert [f.detail.get("ntp_server_ip") for f in again if f.detail.get("ntp_server_ip")] == ["216.239.35.0"]
    assert ae.review_ntp_sync(db) == []  # all re-detected, nothing new


def test_review_ns_it_ot_bypass(db):
    it, ot, ot2 = host(db, "10.4.0.1", 4), host(db, "10.1.0.1", 1), host(db, "10.2.0.1", 2)
    sess(db, it, ot, 502)
    sess(db, ot, it, 445)
    sess(db, it, ot2, 443)                  # L4 -> L2: bypass too (A-11), severity high
    out = ae.review_ns_it_ot_bypass(db)
    assert sorted(f.detail["dst_port"] for f in out) == [443, 445, 502]
    assert {f.detail["ot_host_ip"] for f in out} == {"10.1.0.1", "10.2.0.1"}
    assert {f.detail["dst_port"]: f.severity for f in out}[443] == "high"
    ev(db, src="1.1.1.1", dst="2.2.2.2")  # B-04: unrelated FAZ event no longer silences
    for f in out:
        f.status = "closed"
    assert len(ae.review_ns_it_ot_bypass(db)) == 3


def test_review_ns_ot_internet_egress(db):
    pub = host(db, "93.184.216.34")
    sess(db, host(db, "10.1.0.1", 1), pub, 443)
    sess(db, host(db, "10.2.0.1", 2), pub, 80)
    sess(db, host(db, "10.4.0.1", 4), pub, 443)
    sess(db, host(db, "10.1.0.5", 1), host(db, "10.3.0.1", 3), 443)
    out = {f.detail["src_ip"]: f.severity for f in ae.review_ns_ot_internet_egress(db)}
    assert out == {"10.1.0.1": "critical", "10.2.0.1": "high"}
    ev(db, src="1.1.1.1", dst="2.2.2.2")
    assert ae.review_ns_ot_internet_egress(db) == []


def test_review_ns_remote_access_bypass(db):
    ext = host(db, "203.0.113.9")
    baseline(db, hosts=[("10.35.0.5", "jump_host")])
    sess(db, ext, host(db, "10.1.0.1", 1), 8080)
    sess(db, ext, host(db, "10.4.0.1", 4), 3389)
    sess(db, ext, host(db, "10.35.0.5", 3.5), 3389)   # approved jump host
    sess(db, ext, host(db, "10.4.0.2", 4), 25)         # not a remote-access port
    sess(db, host(db, "10.4.0.9", 4), host(db, "10.1.0.9", 1), 22)  # internal source
    out = {f.detail["dst_ip"]: f.detail["path"] for f in ae.review_ns_remote_access_bypass(db)}
    assert out == {"10.1.0.1": "external_to_ot", "10.4.0.1": "external_to_non_jump_host"}
    ev(db, src="1.1.1.1", dst="2.2.2.2")
    assert ae.review_ns_remote_access_bypass(db) == []


def test_review_ns_scanning_anomaly(db):
    target = host(db, "10.1.0.200", 1)
    for i in range(10):
        sess(db, host(db, f"10.3.0.{i + 1}", 3), target, 502)
    assert ae.review_ns_scanning_anomaly(db) == []  # threshold below 5: too little data
    scanner = host(db, "10.4.0.66", 4)
    for p in range(1, 31):
        sess(db, scanner, target, p)
    out = ae.review_ns_scanning_anomaly(db)
    assert [(f.detail["src_ip"], f.detail["distinct_dst_ports"]) for f in out] == [("10.4.0.66", 30)]
    ev(db, src="1.1.1.1", dst="2.2.2.2")  # B-04: unrelated FAZ event no longer silences
    out[0].status = "closed"
    assert len(ae.review_ns_scanning_anomaly(db)) == 1


def test_review_ns_remote_access_app(db):
    """FO-06: a remote-access tool port to / from a public address."""
    ews, plc = host(db, "10.3.0.20", 3), host(db, "10.1.0.5", 1)
    tv, rdp_in = host(db, "217.146.28.39"), host(db, "198.51.100.9")
    assert ae.review_ns_remote_access_app(db) == []
    sess(db, ews, tv, 5938)
    sess(db, ews, host(db, "10.3.0.99", 3), 5900)          # VNC inside the plant: not this check
    out = ae.review_ns_remote_access_app(db)
    assert [(f.detail["tool"], f.severity) for f in out] == [("TeamViewer", "high")]
    sess(db, ews, plc, 502)                                 # the host also talks to L1
    sess(db, rdp_in, ews, 3389)                             # inbound: remote_access_bypass's
    out[0].status = "closed"
    out = sorted(ae.review_ns_remote_access_app(db), key=lambda f: f.detail["tool"])
    assert [(f.detail["tool"], f.detail["direction"], f.severity) for f in out] == [
        ("TeamViewer", "outbound", "critical")]


def test_review_ns_mgmt_from_non_admin(db):
    plc = host(db, "10.1.0.1", 1)
    admin, other = host(db, "10.3.0.10", 3), host(db, "10.4.0.20", 4)
    sess(db, admin, plc, 22)
    sess(db, other, plc, 3389)
    sess(db, other, plc, 502)                     # not a management port
    out = ae.review_ns_mgmt_from_non_admin(db)   # no baseline: fail-open, both flagged
    assert sorted(f.detail["src_ip"] for f in out) == ["10.3.0.10", "10.4.0.20"]
    assert {f.detail["baseline_present"] for f in out} == {False}
    for f in out:
        f.status = "closed"
    baseline(db, hosts=[("10.3.0.10", "admin_ws")])
    out = ae.review_ns_mgmt_from_non_admin(db)
    assert [f.detail["src_ip"] for f in out] == ["10.4.0.20"]


def test_review_vlan_zone_mismatch(db):
    db.add_all([
        SwitchVlan(device_name="SW1", vlan_id=20, vlan_name="CORP", purdue_level=4,
                   purdue_level_source="keyword_inferred"),
        SwitchVlan(device_name="SW1", vlan_id=30, vlan_name="CELL", purdue_level=1,
                   purdue_level_source="keyword_inferred"),
        SwitchVlan(device_name="SW1", vlan_id=40, vlan_name="X", purdue_level=4,
                   purdue_level_source="manual"),
    ])
    host(db, "10.1.0.1", 1, vlan="20,30", classification_source="protocol_inferred")
    host(db, "10.1.0.2", 1, vlan="30", classification_source="protocol_inferred")
    host(db, "10.1.0.3", 1, vlan="40", classification_source="protocol_inferred")
    host(db, "10.1.0.4", 1, vlan="20", classification_source="manual")
    host(db, "10.1.0.5", 1, vlan="trunk", classification_source="protocol_inferred")
    out = ae.review_vlan_zone_mismatch(db)
    assert [(f.detail["host_ip"], f.detail["vlan_id"]) for f in out] == [("10.1.0.1", 20)]


def test_review_ghost_vlans(db):
    db.add_all([
        SwitchVlan(device_name="SW1", vlan_id=99, vlan_name="OLD", status="inactive"),
        SwitchVlan(device_name="SW1", vlan_id=98, vlan_name="OLD2", status="inactive"),
        SwitchVlan(device_name="SW1", vlan_id=10, vlan_name="LIVE", status="active"),
        SwitchVlan(device_name="SW2", vlan_id=97, vlan_name="OLD3", status="inactive"),
        MacTableEntry(device_name="SW1", port_name="Gi0/5", mac="aa:bb:cc:dd:ee:01", vlan="99"),
        MacTableEntry(device_name="SW1", port_name="Gi0/6", mac="aa:bb:cc:dd:ee:02", vlan="10"),
        MacTableEntry(device_name=None, port_name="Gi0/7", mac="aa:bb:cc:dd:ee:03", vlan="97"),
    ])
    db.flush()
    out = {(f.detail["switch_device"], f.detail["vlan_id"]): f.detail for f in ae.review_ghost_vlans(db)}
    assert set(out) == {("SW1", 99), ("SW2", 97)}  # SW2 via device-less MAC rows
    assert out[("SW1", 99)]["mac_count"] == 1 and out[("SW1", 99)]["example_port"] == "Gi0/5"


def test_review_intervlan_routing(db):
    assert ae.review_intervlan_routing(db) == []
    fw = Firewall(name="FGT1", device_name="FGT1")
    db.add(fw)
    db.flush()
    parent = FirewallInterface(firewall_id=fw.id, name="port3")
    db.add(parent)
    db.flush()
    db.add_all([
        FirewallInterface(firewall_id=fw.id, name="port3.10", vlan_id="10", purdue_level=2,
                          parent_interface_id=parent.id),
        FirewallInterface(firewall_id=fw.id, name="port3.20", vlan_id="20", purdue_level=3,
                          parent_interface_id=parent.id),
        FirewallInterface(firewall_id=fw.id, name="port3.30", vlan_id="30", purdue_level=1,
                          parent_interface_id=parent.id),
    ])
    db.add(FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                        src_zone="port3.10", dst_zone="port3.20", src="all", dst="all",
                        protocol="tcp", dst_port="443", action="permit", enabled=True))
    db.flush()
    out = {f.detail["ot_interface"]: f.detail for f in ae.review_intervlan_routing(db)}
    # L2<->L3 and L1<->L3 cross IT/OT; L1<->L2 does not
    assert set(out) == {"port3.10", "port3.30"}
    assert out["port3.10"]["covered_ot_to_it"] is True and out["port3.10"]["covered_it_to_ot"] is False
    assert out["port3.10"]["parent_interface"] == "port3"
    for f in db.query(Finding):
        f.status = "closed"
    db.add_all([
        FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                     src_zone=a, dst_zone=b, src="all", dst="all", protocol="tcp",
                     dst_port="443", action="permit", enabled=True)
        for a, b in (("port3.20", "port3.10"), ("port3.30", "port3.20"), ("port3.20", "port3.30"))
    ])
    db.flush()
    assert ae.review_intervlan_routing(db) == []


# ----------------------------------------------------------- rule twins --

@pytest.fixture
def fw(db):
    fw = Firewall(name="FGT1", device_name="FGT1", vendor="fortigate")
    db.add(fw)
    db.flush()
    for name, lvl in (("it", 4), ("ops", 3), ("cell", 1), ("hmi", 2), ("dmz", 3.5)):
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl))
    db.flush()
    return fw


def rule(db, fw, src_zone, dst_zone, port, proto="tcp", action="permit", enabled=True, pid=None, **kw):
    r = FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                     policy_id=pid or str(next(_ip_seq)), src_zone=src_zone, dst_zone=dst_zone,
                     src=kw.pop("src", "all"), dst=kw.pop("dst", "all"), protocol=proto,
                     dst_port=port, action=action, enabled=enabled, **kw)
    db.add(r)
    db.flush()
    return r


def test_review_rule_dns_external(db, fw):
    """Owner 2026-10-11: any permit to an external DNS server; high from OT, low from IT;
    internal resolvers, `any` destinations, other ports and denies are not reported."""
    rule(db, fw, "cell", "it", "53", proto="udp", dst="8.8.8.8/32", pid="306")
    rule(db, fw, "cell", "it", "53", proto="tcp", dst="8.8.4.4/32", pid="306")      # same policy, second row
    rule(db, fw, "it", "it", "53", proto="udp", dst="1.1.1.1/32", pid="307")        # enterprise source
    rule(db, fw, "cell", "it", "53", proto="udp", dst="10.0.4.10/32")               # internal resolver
    rule(db, fw, "cell", "it", "53", proto="udp", dst="all")                        # any: egress chain's job
    rule(db, fw, "cell", "it", "443", dst="8.8.8.8/32")                             # not DNS
    rule(db, fw, "cell", "it", "53", proto="udp", dst="9.9.9.9/32", action="deny")
    out = {f.detail["policy_id"]: f for f in ae.review_rule_dns_external(db)}
    assert set(out) == {"306", "307"}
    assert out["306"].severity == "high" and sorted(out["306"].detail["external_destinations"]) == ["8.8.4.4/32", "8.8.8.8/32"]
    assert out["306"].detail["expanded_rows"] == 2 and out["306"].detail["transports"] == ["tcp", "udp"]
    assert out["307"].severity == "low"
    assert ae.review_rule_dns_external(db) == []            # no duplicates on a second run


def test_rule_twins_positive_and_negative(db, fw):
    telnet_it_cell = rule(db, fw, "it", "cell", "23")             # insecure, creds, mgmt, bypass
    rule(db, fw, "cell", "it", "53", proto="udp")                  # OT -> IT DNS
    rule(db, fw, "ops", "hmi", "443")                              # mgmt only (HTTPS), no bypass
    rule(db, fw, "dmz", "hmi", "22")                               # mgmt from DMZ (stepped down)
    # negatives: intra-zone cleartext, deny, disabled, IT->IT, unparseable port
    rule(db, fw, "cell", "cell", "21")
    rule(db, fw, "it", "cell", "23", action="deny")
    rule(db, fw, "it", "cell", "21", enabled=False)
    rule(db, fw, "it", "ops", "8080")
    rule(db, fw, "it", "cell", "not-a-port")

    ins = ae.review_rule_cleartext_protocols(db)
    assert {(f.detail["src_zone"], f.detail["dst_zone"]) for f in ins} == {("it", "cell")}
    assert ins[0].severity == "medium" and ins[0].detail["matched_services"] == ["Telnet"]
    assert ins[0].title.startswith("Cleartext protocol across zones")

    # management protocols across zones: Telnet (cleartext -> high) and SSH;
    # HTTPS / HTTP-alt are not management protocols for this check
    mp = {(f.detail["src_zone"], f.detail["dst_zone"]): f for f in ae.review_rule_mgmt_protocols(db)}
    assert set(mp) == {("it", "cell"), ("dmz", "hmi")}
    assert mp[("it", "cell")].severity == "high"
    assert mp[("it", "cell")].detail["cleartext_mgmt_ports"] == [23]
    assert mp[("dmz", "hmi")].severity == "medium"
    assert mp[("dmz", "hmi")].detail["matched_services"] == ["SSH"]

    creds = ae.review_rule_cleartext_creds(db)   # any source zone, OT destination
    assert sorted((f.detail["src_zone"], f.detail["dst_zone"], f.severity) for f in creds) == \
        [("cell", "cell", "high"), ("it", "cell", "high")]

    dep = ae.review_rule_ot_it_dependency(db)
    assert [(f.detail["src_zone"], f.detail["matched_services"]) for f in dep] == [("cell", ["DNS"])]
    assert dep[0].severity == "low"

    mgmt = {f.detail["src_zone"]: f for f in ae.review_rule_mgmt_wrong_zone(db)}
    assert set(mgmt) == {"it", "ops", "dmz"}
    assert mgmt["dmz"].detail["dmz_source"] is True and mgmt["dmz"].severity == "low"
    assert mgmt["it"].severity == "medium"

    byp = ae.review_rule_it_ot_bypass(db)
    assert {(f.detail["src_zone"], f.detail["dst_zone"]) for f in byp} == {("it", "cell")}
    assert byp[0].severity == "high" and byp[0].detail["confirmed_by_traffic"] is False

    # observed IT(L4) -> L1 telnet confirms the bypass: escalated in place
    sess(db, host(db, "10.4.0.1", 4), host(db, "10.1.0.1", 1), 23)
    assert ae.review_rule_it_ot_bypass(db) == []
    byp = {f.detail["policy_id"]: f for f in
           db.query(Finding).filter(Finding.check_name == "rule_it_ot_bypass")}
    f = byp[telnet_it_cell.policy_id]
    assert f.severity == "critical" and f.detail["confirmed_by_traffic"] is True
    # the unparseable-port IT->cell rule is still a bypass, but can't be confirmed
    assert [g.severity for p, g in byp.items() if p != telnet_it_cell.policy_id] == ["high"]


def test_rule_conduit_drift(db, fw):
    rule(db, fw, "ops", "cell", "502")
    rule(db, fw, "ops", "cell", "500-510")
    rule(db, fw, "ops", "cell", "443", proto="udp")
    assert ae.review_rule_conduit_drift(db) == []  # no baseline
    baseline(db, comms=[("10.0.0.0/8", "10.0.0.0/8", 502, "tcp"),
                        ("10.0.0.0/8", "10.0.0.0/8", 443, "tcp")])
    out = ae.review_rule_conduit_drift(db)
    got = sorted(f.detail["uncovered_ports"] for f in out)
    assert got == ["443", "500-501,503-510"], got
    assert {f.check_name for f in out} == {"rule_conduit_drift"}


def test_review_disabled_rules(db, fw):
    rule(db, fw, "it", "cell", "any", enabled=False, pid="7", src="all", dst="all")
    rule(db, fw, "ops", "ops", "443", enabled=False, pid="8", action="deny")
    rule(db, fw, "it", "cell", "23", enabled=True, pid="9")
    out = {f.detail["policy_id"]: f for f in ae.review_disabled_rules(db)}
    assert set(out) == {"7", "8"}
    assert out["7"].severity == "medium" and len(out["7"].detail["severity_reasons"]) == 2
    assert out["8"].severity == "low" and out["8"].detail["severity_reasons"] == []
    assert ae.review_disabled_rules(db) == []  # dedup on stable rule key


# ------------------------------------------------- run_periodic_reviews --

def test_run_periodic_reviews_failure_isolation(db, monkeypatch):
    host(db, "10.1.0.9", mac="aa:00:00:00:00:01")
    host(db, "10.1.0.9", mac="aa:00:00:00:00:02")
    stats = ae.run_periodic_reviews(db)
    assert ae.failed_reviews(db) == []
    assert stats["review_ip_conflicts"] == 1 and stats["review_zone_documentation"] == 6
    assert all(isinstance(v, int) for v in stats.values())
    info = ae.last_review_info()
    assert info["failed_reviews"] == [] and info["finished_at"]

    def boom(session):
        session.add(Finding(category="periodic_review", check_name="ip_conflict",
                            severity="low", title="should be rolled back"))
        session.flush()
        raise RuntimeError("review exploded")
    boom.__name__ = "review_ip_conflicts"
    monkeypatch.setattr(ae, "review_ip_conflicts", boom)
    stats = ae.run_periodic_reviews(db)
    assert ae.failed_reviews(db) == ["review_ip_conflicts"]
    assert stats["review_ip_conflicts"] == 0
    assert ae.last_review_info()["failed_reviews"] == ["review_ip_conflicts"]
    assert db.query(Finding).filter(Finding.title == "should be rolled back").count() == 0
    # a failed review never auto-resolves its open findings
    assert db.query(Finding).filter(Finding.check_name == "ip_conflict",
                                    Finding.status == "open").count() == 1


def test_run_periodic_reviews_auto_resolve(db, monkeypatch):
    a = host(db, "10.1.0.9", mac="aa:00:00:00:00:01")
    host(db, "10.1.0.9", mac="aa:00:00:00:00:02")
    ae.run_periodic_reviews(db)
    assert ae.auto_resolved_counts(db) == {}
    assert ae.auto_resolve_enabled() is True
    a.ip = "10.1.0.8"          # conflict gone
    db.commit()
    monkeypatch.setenv("IACS_AUTO_RESOLVE", "off")
    assert ae.auto_resolve_enabled() is False
    ae.run_periodic_reviews(db)
    assert ae.auto_resolved_counts(db) == {}
    assert db.query(Finding).filter(Finding.check_name == "ip_conflict").one().status == "open"
    monkeypatch.delenv("IACS_AUTO_RESOLVE")
    ae.run_periodic_reviews(db)
    assert ae.auto_resolved_counts(db) == {"review_ip_conflicts": 1}
    f = db.query(Finding).filter(Finding.check_name == "ip_conflict").one()
    assert f.status == "closed" and "Auto-resolved" in f.notes
    assert ae.last_review_info()["auto_resolved"] == {"review_ip_conflicts": 1}
    # zone documentation is human-owned: never auto-resolved
    assert db.query(Finding).filter(Finding.check_name.like("zone_doc_%"),
                                    Finding.status == "open").count() == 6


def test_unknown_check_name_counts(db):
    before = ae.unknown_check_name_counts().get("cov_not_a_check", 0)
    assert ae._make_finding(db, "cov_not_a_check", "t", "d", {}) is None
    assert ae.unknown_check_name_counts()["cov_not_a_check"] == before + 1
    assert db.query(Finding).count() == 0
    assert ae._make_finding(db, "ip_conflict", "t", "d", {"ip": "1.2.3.4"}) is not None
    assert "ip_conflict" not in ae.unknown_check_name_counts()


def test_rules_not_judged(db):
    """MP-24 (details in tests/test_mp08_12_24.py): permit policies with a
    side the twins cannot resolve are listed per firewall, with why."""
    fw = Firewall(name="FGT1", device_name="FGT1")
    db.add(fw)
    db.flush()
    db.add_all([FirewallInterface(firewall_id=fw.id, name="port1", purdue_level=4),
                FirewallInterface(firewall_id=fw.id, name="port2", purdue_level=3),
                FirewallInterface(firewall_id=fw.id, name="wan1")])
    for pid, sz in (("1", "port1"), ("2", "wan1"), ("3", "nosuch")):
        db.add(FirewallRule(firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
                            policy_id=pid, src_zone=sz, dst_zone="port2", src="any", dst="any",
                            protocol="tcp", dst_port="502", action="permit", rule_order=int(pid)))
    db.flush()
    out = ae.rules_not_judged(db)
    assert out["total_rules"] == 3 and out["not_judged"] == 2
    [e] = out["firewalls"]
    assert e["firewall"] == "FGT1" and [p["policy_id"] for p in e["policies"]] == ["2", "3"]
    assert e["reasons"] == {"src_zone: unlabelled interface": 1, "src_zone: unknown name": 1}


def test_review_ns_remote_access_bypass_with_gateway_role(db):
    """Product-neutral remote access: with a remote_access_gateway declared,
    external sessions to the gateway are fine, external sessions straight to
    the jump host are flagged (path 2b, high), everything else keeps path 2/3."""
    ext = host(db, "203.0.113.9")
    baseline(db, hosts=[("10.35.0.5", "jump_host"), ("10.35.0.6", "remote_access_gateway")])
    sess(db, ext, host(db, "10.35.0.6", 3.5), 443)    # the gateway: sanctioned entry point
    sess(db, ext, host(db, "10.35.0.5", 3.5), 3389)   # jump host, bypassing the gateway
    sess(db, ext, host(db, "10.4.0.1", 4), 3389)      # still a non-jump-host
    out = {f.detail["dst_ip"]: (f.detail["path"], f.severity)
           for f in ae.review_ns_remote_access_bypass(db)}
    assert out == {"10.35.0.5": ("external_to_jump_host_bypassing_gateway", "high"),
                   "10.4.0.1": ("external_to_non_jump_host", "critical")}


def test_remote_access_gateway_label_via_host_role_and_device_type(db):
    """A gateway labelled on the host (role) and a jump host labelled by
    device_type count without any baseline."""
    ext = host(db, "203.0.113.9")
    gw, jb = host(db, "10.35.0.6", 3.5), host(db, "10.35.0.5", 3.5)
    gw.role, jb.device_type = "remote_access_gateway", "jump_host"
    db.commit()
    sess(db, ext, gw, 443)
    sess(db, ext, jb, 22)
    out = {f.detail["dst_ip"]: f.detail["path"] for f in ae.review_ns_remote_access_bypass(db)}
    assert out == {"10.35.0.5": "external_to_jump_host_bypassing_gateway"}


def test_check_remote_access_bypass_knows_gateways_and_host_labels(db):
    """E-02: the real-time (FAZ) check uses the same labels as the session
    fallback: a gateway is a sanctioned destination, a device_type jump host
    counts, external straight to the jump host with a gateway declared is
    path 2b, and addresses compare in canonical form."""
    gw, jb = host(db, "10.35.0.6", 3.5), host(db, "10.35.0.5", 3.5)
    gw.role, jb.device_type = "Remote-Access-Gateway", "jump_host"   # role spelling is tolerated
    db.commit()
    # VPN tunnel terminating on the gateway: fine; elsewhere: finding
    assert ae.check_remote_access_bypass(ev(db, log_type="event", subtype="ssl-vpn",
                                            src="198.51.100.4", dst="10.35.0.6"), db) is None
    assert ae.check_remote_access_bypass(ev(db, log_type="event", subtype="ssl-vpn",
                                            src="198.51.100.4", dst="10.35.0.7"), db) is not None
    # external HTTPS to the gateway: sanctioned entry point
    assert ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.35.0.6", port=443), db) is None
    # external RDP straight to the jump host: path 2b, high
    f = ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.35.0.5", port=3389), db)
    assert f.detail["detection"] == "external_to_jump_host_bypassing_gateway" and f.severity == "high"
    # anything else on a remote-access port: path 2
    f = ae.check_remote_access_bypass(ev(db, src="198.51.100.9", dst="10.4.0.1", port=22), db)
    assert f.detail["detection"] == "external_port_match"
    # IPv6 label stored non-canonically still matches the event's address
    v6 = host(db, "2001:DB8:0:0:0:0:0:50", 3.5)
    v6.device_type = "jump_host"
    db.commit()
    f = ae.check_remote_access_bypass(ev(db, src="2001:db8:ffff::9", dst="2001:db8::50", port=22), db)
    assert f.detail["detection"] == "external_to_jump_host_bypassing_gateway"   # recognised as the jump host


def test_review_checks_map():
    m = ae.review_checks_map()
    assert m["review_unused_policies"] == ("unused_policy",)          # auto-resolved review
    assert m["review_denied_trends"] == ("denied_trend",)             # not auto-resolved
    assert all(isinstance(v, tuple) and v for v in m.values())


def test_review_fortiswitch_ports(db):
    """Owner 2026-10-19: FortiLink-managed switch ports without NAC and enabled unused ports."""
    from app.models import SwitchInterface, SwitchVlan, MacTableEntry
    assert ae.review_switch_port_nac(db) == [] and ae.review_switch_unused_ports(db) == []
    sid = db.query(Finding.site_id).first()  # noqa: F841 - the default site is used by the fixtures
    from app.sites import scope_site_id
    s_id = scope_site_id(db)
    db.add_all([SwitchVlan(site_id=s_id, device_name="sw1", vlan_id=20, purdue_level=1),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="port1", vlan="20", mode="access", source_file="fortilink:fw"),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="port2", vlan="30", mode="access", source_file="fortilink:fw",
                                port_security_policy="nac"),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="port3", vlan="30", mode="access", source_file="fortilink:fw",
                                admin_status="down"),
                SwitchInterface(site_id=s_id, device_name="sw1", port_name="port24", vlan="all", mode="trunk", uplink=True, source_file="fortilink:fw"),
                SwitchInterface(site_id=s_id, device_name="cisco1", port_name="Gi1/0/1", vlan="20", mode="access", source_file="cisco.txt"),
                MacTableEntry(site_id=s_id, device_name="sw1", port_name="port1", mac="aa:bb:cc:00:00:01", vlan="20")])
    db.flush()
    out = ae.review_switch_port_nac(db)
    assert len(out) == 1 and out[0].severity == "medium" and out[0].detail["ot_ports"] == ["port1"]
    out = ae.review_switch_unused_ports(db)                       # port1 has a MAC, port3 is down: port2 is enabled and unused
    assert len(out) == 1 and out[0].detail["ports"] == ["port2"]
    db.query(Finding).delete(); db.flush()
    db.add(SwitchInterface(site_id=s_id, device_name="sw1", port_name="port5", vlan="30", mode="access", source_file="fortilink:fw"))
    db.flush()
    out = ae.review_switch_unused_ports(db)
    assert len(out) == 1 and out[0].detail["ports"] == ["port2", "port5"]
