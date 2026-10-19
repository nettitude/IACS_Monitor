"""
F-11: multi-vendor syslog parsing (Cisco ASA/FTD, pfSense/OPNsense filterlog,
PAN-OS CSV), auto-detection, dedup, real-time check parity with FortiGate,
and the POST /ingest/syslog route.
"""
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, configure_sqlite_engine, get_db
from app.models import Finding, FirewallRule, FortiAnalyzerEvent, Host
from app.parsers.alert_engine import evaluate_event
from app.parsers.forti_parser import ingest_syslog_line_ex
from app.parsers.syslog_vendors import (
    ingest_syslog_any_ex, normalise_vendor_hint, parse_asa_line, parse_panos_line,
    parse_pfsense_line, parse_syslog_any, parse_syslog_header,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


def _panos(cells: dict, n: int) -> str:
    c = [""] * n
    for i, v in cells.items():
        c[i] = v
    return ",".join(c)


def panos_traffic(src, dst, dport, rule, action="allow", sub="end", app="ssl",
                  ts="2026/09/30 12:00:05", sport=51515, device="PA-3220"):
    return _panos({0: "1", 1: ts, 2: "012801000001", 3: "TRAFFIC", 4: sub, 5: "2561", 6: ts,
                   7: src, 8: dst, 9: "0.0.0.0", 10: "0.0.0.0", 11: rule, 12: "corp\\jdoe",
                   14: app, 15: "vsys1", 16: "ot-zone", 17: "untrust", 18: "ethernet1/2",
                   19: "ethernet1/1", 20: "default", 21: ts, 22: "4242", 23: "1",
                   24: str(sport), 25: str(dport), 26: "0", 27: "0", 28: "0x400019",
                   29: "tcp", 30: action, 31: "5120", 32: "1200", 33: "3920", 34: "12",
                   35: ts, 36: "4", 37: "any", 46: "tcp-fin", 52: device}, 60)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


# ----------------------------------------------------------------- headers

def test_syslog_headers_rfc3164_asa_and_rfc5424():
    h = parse_syslog_header("<134>Sep 30 12:00:00 pfsense filterlog[123]: 5,,,")
    assert (h["host"], h["app"], h["msg"]) == ("pfsense", "filterlog", "5,,,")
    h = parse_syslog_header("<166>Sep 30 2026 12:00:01 asa-fw01 : %ASA-6-302013: x")
    assert h["host"] == "asa-fw01" and h["msg"].startswith("%ASA-6-302013")
    assert h["ts"] == datetime(2026, 9, 30, 12, 0, 1, tzinfo=timezone.utc)
    h = parse_syslog_header('<134>1 2026-09-30T14:00:00+02:00 opn filterlog 2 - [m a="x\\]y"][n b="2"] body')
    assert h["host"] == "opn" and h["app"] == "filterlog" and h["msg"] == "body"
    assert h["ts"] == datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------- Cisco ASA

def test_asa_106100_permit_and_icmp_deny():
    r = parse_asa_line("<166>Sep 30 2026 12:00:01 asa-fw01 : %ASA-6-106100: access-list "
                       "outside_access_in permitted tcp outside/203.0.113.5(51234) -> "
                       "inside/10.10.1.20(502) hit-cnt 1 first hit [0x1a2b3c4d, 0x0]")
    assert r["vendor"] == "cisco_asa" and r["source_type"] == "syslog_asa"
    assert (r["log_type"], r["action"], r["protocol"]) == ("traffic", "accept", "tcp")
    assert (r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]) == \
        ("203.0.113.5", 51234, "10.10.1.20", 502)
    assert r["policy_name"] == "outside_access_in" and r["device_name"] == "asa-fw01"
    assert r["raw_fields"]["hit_count"] == 1 and r["raw_fields"]["msg_id"] == "106100"
    r = parse_asa_line("%ASA-6-106100: access-list in_acl denied icmp inside/10.1.1.1(8) -> "
                       "outside/8.8.8.8(0) hit-cnt 3 300-second interval [0x1, 0x0]")
    assert r["action"] == "deny" and r["protocol"] == "icmp" and r["dst_port"] is None
    assert r["raw_fields"]["icmp_type"] == 8


def test_asa_106023_and_inbound_denies():
    r = parse_asa_line('%ASA-4-106023: Deny tcp src outside:198.51.100.7/40000 dst '
                       'inside:10.10.1.20/22 by access-group "outside_access_in" [0x0, 0x0]')
    assert (r["action"], r["policy_name"], r["dst_port"]) == ("deny", "outside_access_in", 22)
    r = parse_asa_line('%ASA-4-106023: Deny udp src outside:2001:db8::7/5000 dst '
                       'inside:2001:db8::20/161 by access-group "out6" [0x0, 0x0]')
    assert (r["src_ip"], r["dst_ip"], r["dst_port"]) == ("2001:db8::7", "2001:db8::20", 161)
    for line, port, proto in (
        ("%ASA-2-106001: Inbound TCP connection denied from 198.51.100.7/40001 to "
         "10.10.1.20/80 flags SYN  on interface outside", 80, "tcp"),
        ("%ASA-2-106006: Deny inbound UDP from 198.51.100.7/5353 to 10.10.1.20/161 on "
         "interface outside", 161, "udp"),
        ("%ASA-6-106015: Deny TCP (no connection) from 10.10.1.20/443 to 198.51.100.7/40002 "
         "flags RST  on interface inside", 40002, "tcp"),
    ):
        r = parse_asa_line(line)
        assert r["action"] == "deny" and r["dst_port"] == port and r["protocol"] == proto


def test_asa_built_direction_and_teardown_metrics():
    out = parse_asa_line("%ASA-6-302013: Built outbound TCP connection 9001 for "
                         "outside:93.184.216.34/443 (93.184.216.34/443) to "
                         "inside:10.10.1.20/52811 (203.0.113.10/52811)")
    assert (out["src_ip"], out["dst_ip"], out["dst_port"], out["action"]) == \
        ("10.10.1.20", "93.184.216.34", 443, "accept")
    assert out["raw_fields"]["src_interface"] == "inside"
    inb = parse_asa_line("%FTD-6-302015: Built inbound UDP connection 9002 for "
                         "outside:198.51.100.9/5000 (198.51.100.9/5000) to "
                         "inside:10.10.1.20/53 (203.0.113.20/53)")
    assert (inb["src_ip"], inb["dst_ip"], inb["dst_port"], inb["protocol"]) == \
        ("198.51.100.9", "10.10.1.20", 53, "udp")
    td = parse_asa_line("%ASA-6-302014: Teardown TCP connection 9001 for "
                        "outside:93.184.216.34/443 to inside:10.10.1.20/52811 "
                        "duration 1:01:05 bytes 51234 TCP FINs from inside")
    assert td["action"] == "close"
    assert td["raw_fields"]["duration_s"] == 3665 and td["raw_fields"]["bytes_total"] == 51234
    assert td["raw_fields"]["direction_known"] is False


def test_asa_auth_config_threat():
    r = parse_asa_line("%ASA-6-113005: AAA user authentication Rejected : reason = AAA "
                       "failure : server = 10.0.0.2 : user = jdoe : user IP = 10.20.1.9")
    assert (r["log_type"], r["subtype"], r["action"], r["user"], r["src_ip"]) == \
        ("event", "authentication", "failed", "jdoe", "10.20.1.9")
    assert parse_asa_line("%ASA-6-113004: AAA user authentication Successful : server = "
                          "10.0.0.2 : user = jdoe")["action"] == "success"
    assert parse_asa_line("%ASA-6-611101: User authentication succeeded: IP address: "
                          "10.20.1.9, Uname: admin")["subtype"] == "login"
    r = parse_asa_line('%ASA-6-605004: Login denied from 10.20.1.9/51000 to inside:10.0.0.1/ssh '
                       'for user "admin"')
    assert (r["action"], r["src_ip"], r["user"]) == ("failed", "10.20.1.9", "admin")
    r = parse_asa_line("%ASA-5-111010: User 'admin', running 'CLI' from IP 10.20.1.5, "
                       "executed 'write memory'")
    assert (r["subtype"], r["action"], r["user"], r["src_ip"]) == \
        ("config", "edit", "admin", "10.20.1.5")
    assert parse_asa_line("%ASA-5-111008: User 'admin' executed the 'show run' command.")[
        "action"] == "view"
    r = parse_asa_line("%ASA-4-733101: Host 198.51.100.7 is attacking. Current burst rate is "
                       "200 per second, max configured rate is 100")
    assert (r["log_type"], r["subtype"], r["action"], r["src_ip"]) == \
        ("utm", "anomaly", "deny", "198.51.100.7")
    assert parse_asa_line("%ASA-4-733100: [ Scanning] drop rate-1 exceeded. Current burst "
                          "rate is 10 per second, max configured rate is 10")["subtype"] == "anomaly"


def test_asa_unknown_or_malformed_is_none():
    assert parse_asa_line("%ASA-6-999999: something") is None
    assert parse_asa_line("%ASA-6-106100: access-list garbled") is None
    assert parse_asa_line("no asa here") is None


# ----------------------------------------------------------------- pfSense

def test_pfsense_filterlog_ipv4_ipv6_and_opnsense():
    r = parse_pfsense_line("<134>Sep 30 12:00:00 pfsense filterlog[12345]: 5,,,1000000103,em0,"
                           "match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.7,10.10.1.20,"
                           "51234,22,0,S,1234567,,64240,,mss")
    assert (r["vendor"], r["action"], r["policy_id"], r["protocol"]) == \
        ("pfsense", "deny", "1000000103", "tcp")
    assert (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"]) == \
        ("198.51.100.7", "10.10.1.20", 51234, 22)
    assert r["raw_fields"]["interface"] == "em0" and r["raw_fields"]["direction"] == "in"
    r = parse_pfsense_line("<134>1 2026-09-30T12:00:00.5+00:00 pfsense.local filterlog 12345 - - "
                           "77,,,1000008313,igb1,match,pass,out,6,0x00,0x00000,64,udp,17,60,"
                           "2001:db8::1,2001:db8::2,546,547,60")
    assert (r["action"], r["src_ip"], r["dst_port"], r["device_name"]) == \
        ("accept", "2001:db8::1", 547, "pfsense.local")
    r = parse_pfsense_line('<134>1 2026-09-30T12:00:06+00:00 OPNsense.localdomain filterlog 2 - '
                           '[meta sequenceId="1"] 82,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,'
                           'match,block,in,4,0x0,,64,0,0,DF,17,udp,76,198.51.100.7,10.10.1.20,'
                           '123,161,56')
    assert r["policy_id"] == "02f4bab031b57d1e30553ce08e0ec131" and r["dst_port"] == 161


def test_pfsense_rejects_bad_rows_and_bare_needs_hint():
    bare = "5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,1.2.3.4,10.0.0.1,1,22,0"
    assert parse_pfsense_line(bare) is None
    assert parse_pfsense_line(bare, allow_bare=True)["dst_port"] == 22
    assert parse_syslog_any(bare, vendor_hint="pfsense")["vendor"] == "pfsense"
    assert parse_pfsense_line("filterlog[1]: 5,,,1,em0,match,maybe,in,4,0,,64") is None
    assert parse_pfsense_line("filterlog[1]: 5,,,1,em0,match,pass,in,4,0x0,,64,0,0,DF,6,tcp,60,"
                              "notanip,10.0.0.1,1,22,0") is None


def test_pfsense_auth_lines():
    ok = parse_pfsense_line("Sep 30 12:01:00 pfsense php-fpm[384]: /index.php: Successful login "
                            "for user 'admin' from: 10.20.1.5 (Local Database)")
    bad = parse_pfsense_line("Sep 30 12:01:01 pfsense php-fpm[384]: /index.php: "
                             "webConfigurator authentication error for user 'admin' from: 10.20.1.9")
    assert (ok["subtype"], ok["action"], ok["user"]) == ("login", "success", "admin")
    assert (bad["action"], bad["src_ip"]) == ("failed", "10.20.1.9")


# ----------------------------------------------------------------- PAN-OS

def test_panos_traffic_fields_and_metrics():
    r = parse_panos_line("<14>Sep 30 12:00:05 PA-HDR " + panos_traffic(
        "10.10.1.20", "93.184.216.34", 443, "OT-to-Internet"))
    assert (r["vendor"], r["log_type"], r["action"], r["policy_name"], r["policy_id"]) == \
        ("panos", "traffic", "accept", "OT-to-Internet", "OT-to-Internet")
    assert r["device_name"] == "PA-3220"          # body device name beats header host
    assert (r["app"], r["src_user"], r["dst_port"], r["protocol"]) == \
        ("ssl", "corp\\jdoe", 443, "tcp")
    raw = r["raw_fields"]
    assert (raw["bytes_sent"], raw["bytes_received"], raw["duration_s"]) == (1200, 3920, 4)
    assert raw["session_end_reason"] == "tcp-fin" and raw["src_zone"] == "ot-zone"
    assert r["event_time"] == datetime(2026, 9, 30, 12, 0, 5, tzinfo=timezone.utc)
    for act in ("deny", "drop", "reset-both", "reset-client"):
        assert parse_panos_line(panos_traffic("1.1.1.1", "10.0.0.1", 22, "x", action=act))[
            "action"] == "deny"


def test_panos_threat_system_config_and_short_lines():
    lines = [l for l in (SAMPLES / "sample_syslog_panos.log").read_text().splitlines()
             if l and not l.startswith("#")]
    by_type = {}
    for l in lines:
        r = parse_panos_line(l)
        assert r is not None, l
        by_type.setdefault(r["raw_fields"].get("type"), []).append(r)
    ips = [r for r in by_type["THREAT"] if r["log_type"] == "ips"][0]
    assert ips["attack_name"] == "Schneider Electric Modbus Write Coil"
    assert ips["severity"] == "critical" and ips["raw_fields"]["threat_numeric_id"] == "36712"
    scan = [r for r in by_type["THREAT"] if r["subtype"] == "anomaly"][0]
    assert scan["log_type"] == "utm" and scan["action"] == "deny"
    auth = [r for r in by_type["SYSTEM"] if r["subtype"] == "login"][0]
    assert (auth["action"], auth["user"], auth["src_ip"]) == ("failed", "admin", "10.20.1.9")
    cfg = by_type["CONFIG"][0]
    assert (cfg["log_type"], cfg["subtype"], cfg["action"], cfg["user"]) == \
        ("event", "config", "edit", "admin")
    assert parse_panos_line("1,2026/09/30 12:00:05,0128,TRAFFIC,end,1,2026/09/30 12:00:05,"
                            "10.0.0.1,10.0.0.2") is None


# ----------------------------------------------------------------- dispatch

def test_sample_files_parse_fully_and_autodetect_vendor():
    for name, vendor in (("asa", "cisco_asa"), ("pfsense", "pfsense"), ("panos", "panos")):
        lines = [l for l in (SAMPLES / f"sample_syslog_{name}.log").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        assert lines
        for l in lines:
            r = parse_syslog_any(l)
            assert r is not None and r["vendor"] == vendor, l


def test_autodetect_prefers_fortinet_and_hint_restricts():
    kv = ('date=2026-09-30 time=12:00:05 devname="FGT-OT" devid="FG100F" logid="0000000013" '
          'type="traffic" subtype="forward" srcip=10.10.1.20 dstip=8.8.8.8 dstport=53 proto=17 '
          'action="accept" policyid=7')
    assert parse_syslog_any(kv)["vendor"] == "fortinet"
    asa = ('%ASA-4-106023: Deny tcp src outside:1.2.3.4/1 dst inside:10.0.0.1/22 '
           'by access-group "a" [0x0, 0x0]')
    assert parse_syslog_any(asa, "auto")["vendor"] == "cisco_asa"
    assert parse_syslog_any(asa, "panos") is None
    assert parse_syslog_any(asa, "fortinet") is None
    assert parse_syslog_any("hello world") is None
    assert normalise_vendor_hint("Palo_Alto") == "panos"
    with pytest.raises(ValueError):
        normalise_vendor_hint("checkpoint")


def test_dedup_on_reingest_and_shared_with_forti_ingest(db):
    asa = ('<164>Sep 30 2026 12:00:02 asa-fw01 : %ASA-4-106023: Deny tcp src '
           'outside:1.2.3.4/1 dst inside:10.0.0.1/22 by access-group "a" [0x0, 0x0]')
    ev, st = ingest_syslog_any_ex(asa, db)
    assert st == "created" and ev.vendor == "cisco_asa" and ev.source_type == "syslog_asa"
    ev2, st2 = ingest_syslog_any_ex(asa, db)
    assert st2 == "duplicate" and ev2.id == ev.id
    assert ingest_syslog_any_ex("garbage", db) == (None, "unparsed")
    kv = ('date=2026-09-30 time=12:00:05 devname="FGT-OT" logid="0000000013" type="traffic" '
          'subtype="forward" srcip=10.10.1.20 dstip=8.8.8.8 action="accept" policyid=7')
    f_ev, f_st = ingest_syslog_line_ex(kv, db)
    assert f_st == "created" and f_ev.vendor == "fortinet"
    assert ingest_syslog_any_ex(kv, db)[1] == "duplicate"
    assert db.query(FortiAnalyzerEvent).count() == 2


# ------------------------------------------- real-time check parity with Forti

FORTI_EGRESS = ('date=2026-09-30 time=12:00:05 devname="FGT-OT" devid="FG100F" '
                'logid="0000000013" type="traffic" subtype="forward" srcip=10.10.1.20 '
                'srcport=51515 dstip=93.184.216.34 dstport=443 proto=6 action="accept" '
                'policyid=7 policyname="OT-to-Internet" sentbyte=1200 rcvdbyte=3920 duration=4')
FORTI_BYPASS = ('date=2026-09-30 time=12:00:06 devname="FGT-OT" devid="FG100F" '
                'logid="0000000013" type="traffic" subtype="forward" srcip=10.40.1.10 '
                'srcport=50001 dstip=10.10.1.20 dstport=502 proto=6 action="accept" '
                'policyid=8 policyname="IT-to-PLC"')
FORTI_AUTH_FAIL = ('date=2026-09-30 time=12:03:01 devname="FGT-OT" logid="0100032002" '
                   'type="event" subtype="login" user="admin" srcip=10.20.1.9 action="failed"')

EQUIVALENT = {
    "fortinet": [FORTI_EGRESS, FORTI_BYPASS, FORTI_AUTH_FAIL],
    "cisco_asa": [
        "<166>Sep 30 2026 12:00:05 asa-fw01 : %ASA-6-302013: Built outbound TCP connection 1 "
        "for outside:93.184.216.34/443 (93.184.216.34/443) to inside:10.10.1.20/51515 "
        "(203.0.113.10/51515)",
        "<166>Sep 30 2026 12:00:06 asa-fw01 : %ASA-6-106100: access-list it_to_ot permitted tcp "
        "it/10.40.1.10(50001) -> ot/10.10.1.20(502) hit-cnt 1 first hit [0x1, 0x0]",
        "<166>Sep 30 2026 12:03:01 asa-fw01 : %ASA-6-605004: Login denied from 10.20.1.9/51000 "
        'to inside:10.0.0.1/ssh for user "admin"',
    ],
    "pfsense": [
        "<134>Sep 30 12:00:05 pfsense filterlog[1]: 12,,,1770001001,em1,match,pass,in,4,0x0,,63,"
        "4242,0,DF,6,tcp,60,10.10.1.20,93.184.216.34,51515,443,0,S,1,,64240,,mss",
        "<134>Sep 30 12:00:06 pfsense filterlog[1]: 14,,,1770001002,em2,match,pass,in,4,0x0,,64,"
        "555,0,DF,6,tcp,60,10.40.1.10,10.10.1.20,50001,502,0,S,1,,64240,,mss",
        "<38>Sep 30 12:03:01 pfsense php-fpm[384]: /index.php: webConfigurator authentication "
        "error for user 'admin' from: 10.20.1.9",
    ],
    "panos": [
        "<14>Sep 30 12:00:05 PA-3220 " + panos_traffic("10.10.1.20", "93.184.216.34", 443,
                                                       "OT-to-Internet"),
        "<14>Sep 30 12:00:06 PA-3220 " + panos_traffic("10.40.1.10", "10.10.1.20", 502,
                                                       "IT-to-PLC", app="modbus", sport=50001,
                                                       ts="2026/09/30 12:00:06"),
        "<14>Sep 30 12:03:01 PA-3220 1,2026/09/30 12:03:01,012801000001,SYSTEM,auth,0,"
        "2026/09/30 12:03:01,,auth-fail,admin,0,0,general,medium,\"failed authentication for "
        "user 'admin'.  Reason: Invalid username/password. From: 10.20.1.9.\",8001,0x0,0,0,0,0,,"
        "PA-3220",
    ],
}


def _findings_for(lines, db):
    db.add_all([Host(ip="10.10.1.20", purdue_level=1), Host(ip="10.40.1.10", purdue_level=3)])
    db.flush()
    for l in lines:
        ev, st = ingest_syslog_any_ex(l, db)
        assert st == "created", l
        evaluate_event(ev, db)
    db.commit()
    return sorted((f.check_name, f.severity) for f in db.query(Finding).all())


@pytest.mark.parametrize("vendor", ["cisco_asa", "pfsense", "panos"])
def test_realtime_findings_match_fortigate(vendor):
    def fresh():
        engine = create_engine("sqlite:///:memory:")
        configure_sqlite_engine(engine)
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()
    forti = _findings_for(EQUIVALENT["fortinet"], fresh())
    other = _findings_for(EQUIVALENT[vendor], fresh())
    names = {n for n, _ in forti}
    assert {"ot_internet_egress", "it_ot_bypass", "auth_failure"} <= names
    assert other == forti


def test_scanning_signal_from_asa_threat_detection_and_panos_scan(db):
    for line in ("%ASA-4-733101: Host 198.51.100.7 is attacking. Current burst rate is 200 "
                 "per second, max configured rate is 100",
                 [l for l in (SAMPLES / "sample_syslog_panos.log").read_text().splitlines()
                  if "Port Scan" in l][0]):
        ev, st = ingest_syslog_any_ex(line, db)
        assert st == "created"
        evaluate_event(ev, db)
    db.commit()
    assert db.query(Finding).filter(Finding.check_name == "scanning_denied").count() >= 1


# ----------------------------------------------------------------- route

@pytest.fixture
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'sv.db'}",
                           connect_args={"check_same_thread": False})
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

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        yield c, Session
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def _upload(client, path_or_text, name="x.log", **params):
    data = path_or_text.read_bytes() if isinstance(path_or_text, Path) else path_or_text.encode()
    return client.post("/ingest/syslog", params=params, files={"file": (name, data)})


def test_route_ingests_each_sample_and_skips_duplicates(api):
    client, _ = api
    for name, vendor in (("asa", "cisco_asa"), ("pfsense", "pfsense"), ("panos", "panos")):
        path = SAMPLES / f"sample_syslog_{name}.log"
        n = len([l for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")])
        r = _upload(client, path)
        assert r.status_code == 200, r.text
        s = r.json()["stats"]
        assert (s["lines"], s["events_created"], s["parse_failures"]) == (n, n, 0)
        assert s["by_vendor"] == {vendor: {"events_created": n, "duplicates_skipped": 0}}
        assert "rule_hits_updated" in s and "finding_ids" in s
        again = _upload(client, path).json()["stats"]
        assert (again["events_created"], again["duplicates_skipped"]) == (0, n)
        assert again["by_vendor"][vendor]["duplicates_skipped"] == n


def test_route_mixed_file_hint_and_device_fallback(api):
    client, Session = api
    text = "\n".join([FORTI_EGRESS] + EQUIVALENT["pfsense"][:1] + EQUIVALENT["panos"][:1]
                     + ["%ASA-6-106015: Deny TCP (no connection) from 10.10.1.20/443 to "
                        "198.51.100.7/40002 flags RST  on interface inside", "junk line"])
    s = _upload(client, text, device_name="FALLBACK-FW").json()["stats"]
    assert s["events_created"] == 4 and s["parse_failures"] == 1
    assert set(s["by_vendor"]) == {"fortinet", "pfsense", "panos", "cisco_asa"}
    with Session() as db:
        asa = db.query(FortiAnalyzerEvent).filter_by(vendor="cisco_asa").one()
        assert asa.device_name == "FALLBACK-FW"
    s = _upload(client, SAMPLES / "sample_syslog_asa.log", vendor_hint="pfsense").json()["stats"]
    assert s["events_created"] == 0 and s["parse_failures"] == s["lines"]
    assert _upload(client, "x", vendor_hint="checkpoint").status_code == 422


def test_routes_report_rule_hits(api):
    client, Session = api
    with Session() as db:
        db.add_all([
            FirewallRule(device_name="PA-3220", device_type="panos_xml", policy_name="OT-to-Internet",
                         policy_id="OT-to-Internet", src="any", dst="any", protocol="any",
                         dst_port="any", action="permit", enabled=True),
            FirewallRule(device_name="FGT-OT", device_type="fortigate", policy_id="7",
                         src="any", dst="any", protocol="any", dst_port="any",
                         action="permit", enabled=True),
        ])
        db.commit()
    s = _upload(client, EQUIVALENT["panos"][0]).json()["stats"]
    assert s["rule_hits_updated"] == 1
    r = client.post("/ingest/forti-syslog", files={"file": ("f.log", FORTI_EGRESS.encode())})
    assert r.json()["stats"]["rule_hits_updated"] == 1
    with Session() as db:
        assert all(r.last_matched is not None for r in db.query(FirewallRule).all())
    rules = client.get("/firewall-rules").json()
    rules = rules if isinstance(rules, list) else rules.get("rules", rules.get("items", []))
    assert any(r.get("last_matched") for r in rules)
