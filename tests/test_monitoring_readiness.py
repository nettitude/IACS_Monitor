"""
Logging / monitoring config (owner, 2026-10-12, "for 7 do option 2") and FortiGuard
DNS / NTP severity (owner: "for 8 do as suggested").

  config_no_syslog_forwarding  any off-box destination counts (syslog 1-4, FortiAnalyzer
                               1-3 / Cloud, FortiGate Cloud); row 6.3 (was 6.5, syslog 1 only)
  config_syslog_unencrypted    judged per enabled off-box destination
  config_monitoring_readiness  one finding per firewall: implicit-deny / local-in deny not
                               logged, event categories off, traffic not forwarded, permit
                               policies logging security events only, logs to an Internet service
  config_ntp_fortiguard /      FortiGuard: info with a WAN leg, low without; DNS low when FQDN
  config_dns_external          permit rules, medium when into OT; third-party DNS medium
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.explain import entry
from app.models import CHECK_TYPE_REFERENCE, Finding
from app.parsers.forti_config_parser import ingest_fortigate_config

_IFACES = """config system interface
    edit "port1"
        set ip 10.80.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.80.4.1 255.255.255.0
    next
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
    next
end
"""
_ROUTE = """config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
"""
_POLICIES = """config firewall address
    edit "vendor"
        set type fqdn
        set fqdn "updates.vendor.example"
    next
end
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic all
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
{P2LOG}    next
{FQDN}end
"""
_FQDN_POLICY = """    edit 3
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "vendor"
        set service "HTTPS"
        set action accept
        set logtraffic all
    next
"""


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _run(db, log="", wan=True, fqdn=False, dns="", purdue_zone_to=None, p2_all=False):
    pols = _POLICIES.replace("{FQDN}", _FQDN_POLICY if fqdn else "").replace(
        "{P2LOG}", "        set logtraffic all\n" if p2_all else "")
    cfg = ("config system global\n    set hostname \"FW-T\"\nend\n" + _IFACES + (_ROUTE if wan else "")
           + dns + pols + log)
    kw = {"purdue_zone_to": purdue_zone_to} if purdue_zone_to is not None else {}
    ingest_fortigate_config(cfg, db, firewall_name="FW-T", generate_findings=True, **kw)
    db.commit()
    return {f.check_name: f for f in db.query(Finding).filter(Finding.status == "open")}


# ─── catalogue ────────────────────────────────────────────────────────────────

def test_catalogue():
    assert CHECK_TYPE_REFERENCE["config_no_syslog_forwarding"][:3] == ("SR 6.1, SR 6.2, SR 2.9", "6.3", "high")
    assert CHECK_TYPE_REFERENCE["config_monitoring_readiness"] == (
        "SR 2.8, SR 6.1, SR 6.2", "6.1, 6.2", "medium", "config_review")
    assert CHECK_TYPE_REFERENCE["config_ntp_fortiguard"][2] == "info"
    assert entry("config_monitoring_readiness")["why"]


# ─── off-box forwarding ───────────────────────────────────────────────────────

@pytest.mark.parametrize("log", [
    'config log fortianalyzer setting\n    set status enable\n    set server "10.80.9.5"\nend\n',
    'config log syslogd2 setting\n    set status enable\n    set server "10.80.9.6"\nend\n',
    'config log fortiguard setting\n    set status enable\nend\n',
])
def test_any_off_box_destination_counts(db, log):
    assert "config_no_syslog_forwarding" not in _run(db, log)


def test_no_destination_is_row_6_3(db):
    f = _run(db, 'config log syslogd setting\n    set status disable\nend\n')["config_no_syslog_forwarding"]
    assert f.checklist_id == "6.3" and f.severity == "high" and "FortiAnalyzer" in f.title


def test_encryption_judged_per_destination(db):
    log = ('config log syslogd setting\n    set status enable\n    set server "10.80.9.6"\n    set mode reliable\n'
           '    set enc-algorithm high\nend\n'
           'config log syslogd2 setting\n    set status enable\n    set server "10.80.9.7"\nend\n'
           'config log fortianalyzer setting\n    set status enable\n    set server "10.80.9.5"\nend\n')
    f = _run(db, log)["config_syslog_unencrypted"]
    dests = {d["destination"]: d for d in f.detail["destinations"]}
    assert set(dests) == {"syslog 2 10.80.9.7"}            # syslog 1 is TLS + TCP; FAZ default not judged
    assert any("UDP" in p for p in dests["syslog 2 10.80.9.7"]["problems"])
    assert "10.80.1.0/24" not in f.title


def test_faz_explicit_weak_settings_reported(db):
    log = ('config log fortianalyzer setting\n    set status enable\n    set server "10.80.9.5"\n'
           '    set reliable disable\n    set enc-algorithm low\nend\n')
    f = _run(db, log)["config_syslog_unencrypted"]
    (d,) = f.detail["destinations"]
    assert d["kind"] == "fortianalyzer" and len(d["problems"]) == 2


# ─── monitoring readiness ─────────────────────────────────────────────────────

def test_readiness_gaps(db):
    log = ('config log fortianalyzer setting\n    set status enable\n    set server "10.80.9.5"\nend\n'
           'config log fortianalyzer filter\n    set forward-traffic disable\nend\n'
           'config log eventfilter\n    set user disable\nend\n')
    f = _run(db, log)["config_monitoring_readiness"]
    gaps = {g["gap"]: g for g in f.detail["gaps"]}
    # batch A (2026-10-15): implicit-deny logging is its own check (config_implicit_deny_not_logged)
    assert set(gaps) == {"local_in_deny_not_logged", "events_filtered",
                         "traffic_not_forwarded", "security_events_only"}
    assert gaps["events_filtered"]["categories"] == ["user"]
    assert gaps["security_events_only"]["policies"] == ["2"]      # policy 1 logs all
    assert f.severity == "medium" and f.detail["off_box_destinations"] == ["FortiAnalyzer 10.80.9.5"]


_GOOD_LOG = 'config log setting\n    set fwpolicy-implicit-log enable\n    set local-in-deny-unicast enable\nend\n'


def test_readiness_clean_config_has_no_finding(db):
    log = 'config log syslogd setting\n    set status enable\n    set server "10.80.9.6"\nend\n' + _GOOD_LOG
    assert "config_monitoring_readiness" not in _run(db, log, p2_all=True)


def test_readiness_default_utm_policy_is_a_gap(db):
    log = 'config log syslogd setting\n    set status enable\n    set server "10.80.9.6"\nend\n' + _GOOD_LOG
    f = _run(db, log)["config_monitoring_readiness"]
    assert [g["gap"] for g in f.detail["gaps"]] == ["security_events_only"] and f.severity == "medium"


def test_readiness_cloud_only_is_low(db):
    log = 'config log fortiguard setting\n    set status enable\nend\n' + _GOOD_LOG
    f = _run(db, log, p2_all=True)["config_monitoring_readiness"]
    assert [g["gap"] for g in f.detail["gaps"]] == ["logs_to_internet_service"] and f.severity == "low"


# ─── FortiGuard DNS / NTP severity ────────────────────────────────────────────

def test_fortiguard_ntp_info_with_wan_low_without(db):
    assert _run(db, wan=True)["config_ntp_fortiguard"].severity == "info"


def test_fortiguard_ntp_low_without_wan(db):
    f = _run(db, wan=False)["config_ntp_fortiguard"]
    assert f.severity == "low" and "no Internet (WAN) leg" in f.detail["severity_reason"]


def test_fortiguard_dns_default(db):
    f = _run(db, wan=True)["config_dns_external"]
    assert f.severity == "info" and f.detail["fortiguard_default"] is True


def test_fortiguard_dns_with_fqdn_rules_low_and_medium_into_ot(db):
    assert _run(db, wan=True, fqdn=True)["config_dns_external"].severity == "low"


def test_fortiguard_dns_fqdn_into_ot_medium(db):
    f = _run(db, wan=True, fqdn=True, purdue_zone_to=1)["config_dns_external"]
    assert f.severity == "medium" and f.detail["fqdn_permit_policies"] == ["3"]


def test_third_party_dns_stays_medium(db):
    dns = 'config system dns\n    set primary 8.8.8.8\nend\n'
    assert _run(db, wan=True, dns=dns)["config_dns_external"].severity == "medium"
