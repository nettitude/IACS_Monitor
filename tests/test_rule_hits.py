"""
F-10: FirewallRule.last_matched from ingested traffic events (rule_hits.py).
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import FirewallDevice, FirewallRule
from app.parsers.rule_hits import record_rule_hits, tuple_match
from app.parsers.syslog_vendors import ingest_syslog_any_ex

T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.engine_for_test = engine
    yield s
    s.close()


def _rule(db, **kw):
    base = dict(src="any", dst="any", protocol="any", dst_port="any", action="permit",
                enabled=True)
    base.update(kw)
    r = FirewallRule(**base)
    db.add(r)
    db.flush()
    return r


def _ingest(db, *lines):
    evs = []
    for l in lines:
        ev, st = ingest_syslog_any_ex(l, db)
        assert st == "created", l
        evs.append(ev)
    return evs


def _kv(policyid, dev="FGT-OT", action="accept", t="12:00:05", dst="93.184.216.34", port=443):
    return (f'date=2026-09-30 time={t} devname="{dev}" logid="0000000013" type="traffic" '
            f'subtype="forward" srcip=10.10.1.20 srcport=51515 dstip={dst} dstport={port} '
            f'proto=6 action="{action}" policyid={policyid}')


def test_fortios_by_device_and_policy_id(db):
    ot = _rule(db, device_name="FGT-OT", device_type="fortigate", policy_id="7")
    it = _rule(db, device_name="FGT-IT", device_type="fortigate", policy_id="7")
    st = record_rule_hits(db, _ingest(db, _kv(7, t="12:00:05"), _kv(7, t="12:10:00")))
    assert st["rules_updated"] == 1 and st["events_matched"] == 2
    assert ot.last_matched == T0 + timedelta(minutes=10)
    assert it.last_matched is None


def test_fortios_device_via_firewall_device_name_and_ambiguity(db):
    fd = FirewallDevice(name="Cell-FW-A", device_hostname="FGT-CELL")
    db.add(fd)
    db.flush()
    a = _rule(db, device_name="cfg-a", device_type="fortigate", policy_id="3",
              firewall_device_id=fd.id)
    b = _rule(db, device_name="cfg-b", device_type="fortigate", policy_id="3")
    record_rule_hits(db, _ingest(db, _kv(3, dev="FGT-CELL")))
    assert a.last_matched is not None and b.last_matched is None
    # Unknown device and two candidate devices -> ambiguous, nothing stamped.
    st = record_rule_hits(db, _ingest(db, _kv(3, dev="FGT-OTHER")))
    assert st["ambiguous"] == 1 and b.last_matched is None


def test_last_matched_only_moves_forward_and_policy_zero_ignored(db):
    r = _rule(db, device_name="FGT-OT", device_type="fortigate", policy_id="7")
    later = T0 + timedelta(days=1)
    r.last_matched = later
    st = record_rule_hits(db, _ingest(db, _kv(7), _kv(0, t="12:00:06")))
    assert r.last_matched == later and st["rules_updated"] == 0


def test_deny_events_only_stamp_deny_rules(db):
    permit = _rule(db, device_name="FGT-OT", device_type="fortigate", policy_id="7")
    deny = _rule(db, device_name="FGT-OT", device_type="fortigate", policy_id="9", action="deny")
    record_rule_hits(db, _ingest(db, _kv(7, action="deny"), _kv(9, action="deny", t="12:00:09")))
    assert permit.last_matched is None
    assert deny.last_matched == T0 + timedelta(seconds=9)


def test_panos_by_rule_name_and_legacy_device_name(db):
    from tests.test_syslog_vendors import panos_traffic
    named = _rule(db, device_name="PA-3220", device_type="panos_xml",
                  policy_name="OT-to-Internet")
    legacy = _rule(db, device_name="IT-to-PLC", device_type="panos_set")  # pre-identity rows
    evs = _ingest(db, panos_traffic("10.10.1.20", "93.184.216.34", 443, "OT-to-Internet"),
                  panos_traffic("10.40.1.10", "10.10.1.20", 502, "IT-to-PLC"))
    st = record_rule_hits(db, evs)
    assert st["rules_updated"] == 2
    assert named.last_matched == T0 + timedelta(seconds=5) == legacy.last_matched


def test_pfsense_by_tracker_and_disabled_never_hit(db):
    on = _rule(db, device_name="LAN", device_type="pfsense", policy_id="1770001001")
    off = _rule(db, device_name="LAN", device_type="pfsense", policy_id="1770001002",
                enabled=False)
    lines = [
        "<134>Sep 30 12:00:05 pfsense filterlog[1]: 12,,,1770001001,em1,match,pass,in,4,0x0,,63,"
        "4242,0,DF,6,tcp,60,10.10.1.20,93.184.216.34,51515,443,0,S,1,,64240,,mss",
        "<134>Sep 30 12:00:06 pfsense filterlog[1]: 14,,,1770001002,em2,match,pass,in,4,0x0,,64,"
        "555,0,DF,6,tcp,60,10.40.1.10,10.10.1.20,50001,502,0,S,1,,64240,,mss",
    ]
    st = record_rule_hits(db, _ingest(db, *lines))
    assert on.last_matched == T0 + timedelta(seconds=5)
    assert off.last_matched is None and st["unmatched"] == 1


def _asa_acl(db, acl="outside_access_in", fd_id=None):
    rows = [
        _rule(db, device_name="asa-cfg", device_type="cisco_ios", policy_name=acl, rule_order=1,
              protocol="tcp", dst="10.10.1.20/32", dst_port="22", action="deny",
              firewall_device_id=fd_id),
        _rule(db, device_name="asa-cfg", device_type="cisco_ios", policy_name=acl, rule_order=2,
              protocol="tcp", src="203.0.113.0/24", dst="10.10.1.20/32", dst_port="502",
              enabled=False, firewall_device_id=fd_id),
        _rule(db, device_name="asa-cfg", device_type="cisco_ios", policy_name=acl, rule_order=3,
              protocol="tcp", dst="10.10.1.0/24", dst_port="502", firewall_device_id=fd_id),
        _rule(db, device_name="asa-cfg", device_type="cisco_ios", policy_name=acl, rule_order=4,
              protocol="ip", firewall_device_id=fd_id),
    ]
    return rows


def test_asa_106100_first_match_skips_disabled(db):
    deny22, disabled, modbus, anyany = _asa_acl(db)
    _rule(db, device_name="asa-cfg", device_type="cisco_ios", policy_name="inside_access_in",
          rule_order=1, protocol="ip")
    evs = _ingest(db,
        "<166>Sep 30 2026 12:00:01 asa-fw01 : %ASA-6-106100: access-list outside_access_in "
        "permitted tcp outside/203.0.113.5(51234) -> inside/10.10.1.20(502) hit-cnt 1 first hit "
        "[0x1, 0x0]",
        '<164>Sep 30 2026 12:00:02 asa-fw01 : %ASA-4-106023: Deny tcp src outside:198.51.100.7/'
        '40000 dst inside:10.10.1.20/22 by access-group "outside_access_in" [0x0, 0x0]')
    st = record_rule_hits(db, evs)
    assert st["first_match_evaluations"] == 2 and st["rules_updated"] == 2
    assert modbus.last_matched == T0 + timedelta(seconds=1)
    assert deny22.last_matched == T0 + timedelta(seconds=2)
    assert disabled.last_matched is None and anyany.last_matched is None


def test_asa_built_without_acl_uses_ingress_interface_acl(db):
    _deny22, _dis, modbus, anyany = _asa_acl(db)
    inside_any = _rule(db, device_name="asa-cfg", device_type="cisco_ios",
                       policy_name="inside_access_in", rule_order=1, protocol="ip")
    evs = _ingest(db,
        "<166>Sep 30 2026 12:00:03 asa-fw01 : %ASA-6-302013: Built inbound TCP connection 7 for "
        "outside:198.51.100.9/40000 (198.51.100.9/40000) to inside:10.10.1.20/502 "
        "(203.0.113.20/502)",
        "<166>Sep 30 2026 12:00:04 asa-fw01 : %ASA-6-302013: Built outbound TCP connection 8 for "
        "outside:93.184.216.34/443 (93.184.216.34/443) to inside:10.10.1.20/52811 "
        "(203.0.113.10/52811)",
        # teardown has no reliable direction -> never used for rule hits
        "<166>Sep 30 2026 12:09:00 asa-fw01 : %ASA-6-302014: Teardown TCP connection 7 for "
        "outside:198.51.100.9/40000 to inside:10.10.1.20/502 duration 0:09:00 bytes 10")
    record_rule_hits(db, evs)
    assert modbus.last_matched == T0 + timedelta(seconds=3)
    assert inside_any.last_matched == T0 + timedelta(seconds=4)
    assert anyany.last_matched is None


def test_asa_first_match_stops_on_undecidable_rule(db):
    _rule(db, device_name="acl1", device_type="cisco_ios", rule_order=1, protocol="tcp",
          src="unresolved:OG-CLIENTS", dst="any", dst_port="502")
    later = _rule(db, device_name="acl1", device_type="cisco_ios", rule_order=2, protocol="ip")
    st = record_rule_hits(db, _ingest(db,
        "%ASA-6-106100: access-list acl1 permitted tcp outside/203.0.113.5(1) -> "
        "inside/10.10.1.20(502) hit-cnt 1 first hit [0x1, 0x0]"))
    assert st["ambiguous"] == 1 and later.last_matched is None


def test_tuple_match_semantics(db):
    class Ev:
        protocol, src_ip, dst_ip, dst_port = "tcp", "10.1.1.5", "10.2.2.2", 502
    r = FirewallRule(protocol="tcp", src="10.1.1.0 0.0.0.255", dst="host 10.2.2.2",
                     dst_port="eq 502", action="permit")
    assert tuple_match(r, Ev) is True
    r.dst_port = "80,443"
    assert tuple_match(r, Ev) is False
    r.dst_port, r.protocol = "any", "udp"
    assert tuple_match(r, Ev) is False
    r.protocol, r.src = "tcp", "network:LAN"
    assert tuple_match(r, Ev) is None


def test_batched_queries_not_per_event(db):
    _rule(db, device_name="FGT-OT", device_type="fortigate", policy_id="7")
    evs = _ingest(db, *[_kv(7, t=f"12:{m:02d}:00") for m in range(40)])
    selects = []

    def _count(conn, cursor, statement, *a):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(db.engine_for_test, "before_cursor_execute", _count)
    try:
        st = record_rule_hits(db, evs)
    finally:
        event.remove(db.engine_for_test, "before_cursor_execute", _count)
    assert st["events_matched"] == 40 and st["rules_updated"] == 1
    assert len(selects) <= 3
