"""
Checklist 3.2 broadened and 3.11 added (owner, 2026-10-12: "do option 1 and add the
temporary rule check").

  config_permit_any_any_any  one finding per permit policy with "all" in source,
                             destination OR service: critical for all three, high into OT
                             (destination interface labelled L0-L2, or the firewall boundary
                             into OT) or out to the Internet (WAN interface / external
                             destination), medium otherwise
  config_temporary_rule      a policy named / commented temporary with no expiring schedule,
                             or an enabled policy whose one-time schedule has ended (3.11)
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.explain import entry
from app.models import CHECK_TYPE_REFERENCE, FirewallInterface, Finding
from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS, ingest_fortigate_config

BASE = """config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.10.4.1 255.255.255.0
    next
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
end
config firewall address
    edit "h1"
        set subnet 10.10.4.5 255.255.255.255
    next
    edit "h2"
        set subnet 10.10.1.9 255.255.255.255
    next
    edit "iproxy"
        set type fqdn
        set fqdn "iproxy.example.com"
    next
end
config firewall schedule onetime
    edit "old-window"
        set start "08:00 2020/01/01"
        set end "18:00 2020/01/31"
    next
    edit "future-window"
        set start "08:00 2030/01/01"
        set end "18:00 2030/01/31"
    next
end
config firewall schedule recurring
    edit "weekdays"
        set day monday tuesday wednesday thursday friday
    next
end
config firewall policy
{POLICIES}end
"""


def _pol(pid, name, src_i, dst_i, src, dst, svc, extra=""):
    return (f'    edit {pid}\n        set name "{name}"\n        set srcintf "{src_i}"\n        set dstintf "{dst_i}"\n'
            f'        set srcaddr "{src}"\n        set dstaddr "{dst}"\n        set service {svc}\n'
            f'        set action accept\n        set logtraffic all\n{extra}    next\n')


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _run(db, policies, label_ot=None):
    cfg = BASE.replace("{POLICIES}", policies)
    ingest_fortigate_config(cfg, db, firewall_name="FW", generate_findings=True)
    db.commit()
    if label_ot:
        for fi in db.query(FirewallInterface).filter(FirewallInterface.name.in_(label_ot)):
            fi.purdue_level = 1
        db.commit()
        ingest_fortigate_config(cfg, db, firewall_name="FW", generate_findings=True)   # labels survive
        db.commit()
    return {(f.check_name, f.detail.get("policy_id")): f for f in db.query(Finding).filter(Finding.status == "open")}


def test_catalogue():
    assert CHECK_TYPE_REFERENCE["config_temporary_rule"] == ("2-1 SPE 2", "3.11", "medium", "config_review")
    assert "config_temporary_rule" in FORTIGATE_CONFIG_CHECKS
    assert "temporary" in entry("config_temporary_rule")["why"]


def test_all_three_is_critical(db):
    f = _run(db, _pol(1, "Wide", "port2", "port1", "all", "all", '"ALL"'))[("config_permit_any_any_any", "1")]
    assert f.severity == "critical" and f.detail["all_positions"] == ["source", "destination", "service"]


def test_service_all_internal_is_medium(db):
    f = _run(db, _pol(2, "Jump", "port2", "port1", "h1", "h2", '"ALL"'))[("config_permit_any_any_any", "2")]
    assert f.severity == "medium" and f.detail["all_positions"] == ["service"] and "permits all services" in f.title


def test_service_all_to_internet_fqdn_is_high(db):
    out = _run(db, _pol(314, "LPS_To_Iproxy_Temp", "port2", "wan1", "h1", "iproxy", '"ALL"'))
    f = out[("config_permit_any_any_any", "314")]
    assert f.severity == "high" and f.detail["to_internet"] and "Internet" in f.detail["severity_reason"]


def test_all_into_labelled_ot_is_high(db):
    f = _run(db, _pol(3, "To_PLCs", "port2", "port1", "all", "h2", '"HTTPS"'), label_ot=["port1"])[
        ("config_permit_any_any_any", "3")]
    assert f.severity == "high" and f.detail["into_ot"] and f.detail["all_positions"] == ["source"]


def test_specific_policy_and_deny_not_reported(db):
    pols = _pol(4, "Ok", "port2", "port1", "h1", "h2", '"HTTPS"') + \
        '    edit 5\n        set srcintf "port2"\n        set dstintf "port1"\n        set srcaddr "all"\n' \
        '        set dstaddr "all"\n        set service "ALL"\n        set action deny\n    next\n'
    out = _run(db, pols)
    assert ("config_permit_any_any_any", "4") not in out and ("config_permit_any_any_any", "5") not in out


# ─── 3.11 temporary rules ─────────────────────────────────────────────────────

def test_temporary_name_without_expiry(db):
    f = _run(db, _pol(314, "LPS_To_Iproxy_Temp", "port2", "wan1", "h1", "iproxy", '"HTTPS"'))[
        ("config_temporary_rule", "314")]
    assert f.detail["problem"] == "no_expiry" and f.detail["schedule"] == "always" and f.checklist_id == "3.11"


def test_temporary_comment_with_recurring_schedule(db):
    extra = '        set comments "commissioning access, remove after SAT"\n        set schedule "weekdays"\n'
    f = _run(db, _pol(20, "Commissioning", "port2", "port1", "h1", "h2", '"SSH"', extra))[
        ("config_temporary_rule", "20")]
    assert f.detail["schedule_kind"] == "recurring"


def test_expired_one_time_schedule_still_enabled(db):
    extra = '        set schedule "old-window"\n'
    f = _run(db, _pol(21, "Vendor_window", "port2", "port1", "h1", "h2", '"SSH"', extra))[
        ("config_temporary_rule", "21")]
    assert f.detail["problem"] == "expired_still_active" and f.detail["schedule_end"].startswith("2020-01-31")


def test_temporary_with_future_end_and_plain_policy_pass(db):
    pols = _pol(22, "Temp_vendor", "port2", "port1", "h1", "h2", '"SSH"', '        set schedule "future-window"\n') + \
        _pol(23, "Historian", "port2", "port1", "h1", "h2", '"HTTPS"')
    out = _run(db, pols)
    assert ("config_temporary_rule", "22") not in out and ("config_temporary_rule", "23") not in out
