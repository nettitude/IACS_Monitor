"""
Tier-3 regression tests for app/parsers/forti_parser.py
(T3-06, T3-22 .. T3-27 in docs/code-review-remediation.md).
"""
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, FortiAnalyzerEvent
from app.parsers import forti_parser as fp
from app.parsers.forti_parser import (
    _parse_timestamp,
    ingest_forti_csv,
    ingest_forti_event_json,
    ingest_forti_event_json_ex,
    ingest_syslog_line,
    ingest_syslog_line_ex,
    parse_cef_line,
    parse_forti_csv_report,
    parse_forti_kv_line,
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()


def _utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


# FortiOS 7.x CEF as forwarded by FortiGate/FortiAnalyzer.
FTNT_CEF = (
    "CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward close|3|"
    "deviceExternalId=FG100FTK20001234 dvchost=FGT-PLANT-01 FTNTFGTlogid=0000000013 "
    "cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=root "
    "FTNTFGTeventtime=1759233600123456789 FTNTFGTtz=+0000 src=10.10.1.5 spt=51000 "
    "deviceInboundInterface=port3 FTNTFGTsrcintfrole=lan dst=10.20.0.10 dpt=502 "
    "deviceOutboundInterface=port4 FTNTFGTdstintfrole=dmz "
    "FTNTFGTpoluuid=8a0b5f4c-1111-51ef-2222-333344445555 externalId=987654 proto=6 "
    "act=accept FTNTFGTpolicyid=17 FTNTFGTpolicytype=policy app=Modbus "
    "FTNTFGTdstcountry=Reserved FTNTFGTsrccountry=United States FTNTFGTduration=180 "
    "out=4200 in=1337 FTNTFGTsentpkt=30 FTNTFGTrcvdpkt=28 "
    "msg=session closed by peer after idle"
)


# ------------------------------------------------------------------ T3-22 syslog headers

def test_cef_rfc3164_prefix_recognised():
    r = parse_cef_line("<134>Sep 30 12:00:00 fw1 " + FTNT_CEF)
    assert r is not None
    assert r["src_ip"] == "10.10.1.5" and r["dst_port"] == 502


def test_cef_rfc5424_prefix_recognised():
    line = ('<134>1 2026-09-30T12:00:00Z faz01 FortiAnalyzer - - '
            '[meta sequenceId="7"] ' + FTNT_CEF)
    r = parse_cef_line(line)
    assert r is not None and r["policy_id"] == "17"


def test_cef_rfc5424_nil_sd_prefix():
    r = parse_cef_line("<134>1 2026-09-30T12:00:00Z faz01 FortiAnalyzer 1234 - - " + FTNT_CEF)
    assert r is not None


def test_prefixed_cef_does_not_fall_through_to_kv(db):
    # CEF line whose extension has type=; keys are all non-key fields.
    line = "<134>Sep 30 12:00:00 fw1 CEF:0|Fortinet|Fortigate|v7.4|1|x|3|type=foo cn2=9"
    ev, status = ingest_syslog_line_ex(line, db)
    assert (ev, status) == (None, "unparsed")
    assert db.query(FortiAnalyzerEvent).count() == 0


def test_cef_inside_kv_value_is_not_cef():
    line = ('logid=0100032001 type=event subtype=system devname=FGT1 '
            'msg="CEF:0|a|b|c|d|e|f|src=1.2.3.4" action=login')
    assert parse_cef_line(line) is None
    assert parse_forti_kv_line(line)["action"] == "login"


# ------------------------------------------------------------------ T3-23 FTNTFGT keys

def test_ftntfgt_mapping():
    r = parse_cef_line(FTNT_CEF)
    assert r["device_name"] == "FGT-PLANT-01"          # dvchost preferred over serial
    assert r["policy_id"] == "17"
    assert r["protocol"] == "tcp"
    assert r["log_type"] == "traffic" and r["subtype"] == "forward"
    assert r["event_time"] == datetime.fromtimestamp(1759233600.123456789, tz=timezone.utc)
    raw = r["raw_fields"]
    assert raw["FTNTFGTpoluuid"].startswith("8a0b5f4c")
    assert raw["FTNTFGTsrccountry"] == "United States"
    assert raw["sentbyte"] == 4200 and raw["rcvdbyte"] == 1337
    assert raw["duration"] == 180 and raw["sessionid"] == 987654


def test_cef_numeric_proto_udp_icmp():
    base = "CEF:0|Fortinet|Fortigate|v7|13|traffic:forward accept|3|src=1.1.1.1 dst=2.2.2.2 proto="
    assert parse_cef_line(base + "17")["protocol"] == "udp"
    assert parse_cef_line(base + "1")["protocol"] == "icmp"


def test_cef_device_falls_back_to_serial():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v7|13|traffic:forward|3|"
                       "deviceExternalId=FG100FTK20001234 src=1.1.1.1")
    assert r["device_name"] == "FG100FTK20001234"


def test_cef_utm_ips_classified_ips():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v7|16384|utm:ips signature|5|"
                       "cat=utm:ips src=1.1.1.1 dst=2.2.2.2 FTNTFGTattack=Modbus.Func.Code.8 "
                       "FTNTFGTseverity=high act=dropped")
    assert r["log_type"] == "ips"
    assert r["attack_name"] == "Modbus.Func.Code.8" and r["severity"] == "high"


# ------------------------------------------------------------------ T3-24 cs labels

def test_cs1_labelled_srcintf_is_not_policy_id():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v6|13|traffic:forward|3|"
                       "src=1.1.1.1 cs1Label=srcintf cs1=port1 cs2Label=policyid cs2=42")
    assert r["policy_id"] == "42"
    assert r["raw_fields"]["cs1"] == "port1"


def test_unlabelled_cs1_ignored():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v6|13|traffic:forward|3|src=1.1.1.1 cs1=port1")
    assert r["policy_id"] is None


def test_ftntfgt_policyid_beats_cs_label():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v6|13|traffic:forward|3|src=1.1.1.1 "
                       "cs1Label=policyid cs1=99 FTNTFGTpolicyid=7")
    assert r["policy_id"] == "7"


def test_cs_label_before_value_and_policyname():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v6|13|traffic:forward|3|src=1.1.1.1 "
                       "cs3=OT-ALLOW cs3Label=policyname")
    assert r["policy_name"] == "OT-ALLOW" and r["policy_id"] is None


# ------------------------------------------------------------------ T3-25 value parsing

def test_cef_msg_with_spaces_and_escapes():
    r = parse_cef_line(r"CEF:0|Fortinet|Fortigate|v7|13|traffic:forward|3|src=1.1.1.1 "
                       r"msg=admin a\=b logged in\nfrom C:\\temp act=accept")
    assert r["raw_fields"]["msg"] == "admin a=b logged in\nfrom C:\\temp"
    assert r["action"] == "accept"


def test_cef_escaped_pipe_in_header():
    r = parse_cef_line(r"CEF:0|Fortinet|Forti\|gate|v7|13|traffic:forward|3|src=1.1.1.1")
    assert r is not None and r["src_ip"] == "1.1.1.1"


def test_kv_escaped_quote_injection_blocked():
    line = ('date=2026-09-30 time=12:00:00 logid="0316013056" type="utm" subtype="webfilter" '
            'devname="FGT1" srcip=10.1.1.1 action="blocked" '
            'hostname="evil.com\\" srcip=10.9.9.9 action=passthrough x=\\"" dstip=8.8.8.8')
    r = parse_forti_kv_line(line)
    assert r["src_ip"] == "10.1.1.1"
    assert r["action"] == "blocked"
    assert r["dst_ip"] == "8.8.8.8"
    assert r["raw_fields"]["hostname"] == 'evil.com" srcip=10.9.9.9 action=passthrough x="'
    assert r["device_name"] == "FGT1"


def test_kv_first_occurrence_wins():
    r = parse_forti_kv_line("logid=0000000013 type=traffic devname=F srcip=1.1.1.1 srcip=6.6.6.6")
    assert r["src_ip"] == "1.1.1.1"


def test_json_values_with_quotes_not_reparsed(db):
    ev = ingest_forti_event_json({
        "type": "traffic", "devname": "FGT1", "srcip": "10.1.1.1", "action": "deny",
        "msg": 'x" srcip=6.6.6.6 action="accept', "proto": 17, "sentbyte": "12",
    }, db)
    assert ev.src_ip == "10.1.1.1" and ev.action == "deny" and ev.protocol == "udp"
    assert ev.raw_fields["sentbyte"] == 12


# ------------------------------------------------------------------ T3-26 timestamps

@pytest.mark.parametrize("value", ["1759233600", "1759233600000",
                                   "1759233600000000", "1759233600000000000"])
def test_eventtime_magnitudes(value):
    r = parse_forti_kv_line(f"logid=0000000013 type=traffic devname=F srcip=1.1.1.1 "
                            f"date=2000-01-01 time=00:00:00 eventtime={value}")
    assert r["event_time"] == _utc(2025, 9, 30, 12, 0, 0)


def test_date_time_with_tz_offset():
    r = parse_forti_kv_line('date=2026-09-30 time=07:00:00 tz="-0500" logid=0000000013 '
                            'type=traffic devname=F srcip=1.1.1.1')
    assert r["event_time"] == _utc(2026, 9, 30, 12, 0, 0)
    r = parse_forti_kv_line('date=2026-09-30 time=13:00:00 tz="+0100" logid=0000000013 '
                            'type=traffic devname=F srcip=1.1.1.1')
    assert r["event_time"] == _utc(2026, 9, 30, 12, 0, 0)
    assert r["event_time"].tzinfo is not None


def test_cef_rt_formats():
    base = "CEF:0|Fortinet|Fortigate|v7|13|traffic:forward|3|src=1.1.1.1 rt="
    assert parse_cef_line(base + "Sep 30 2026 12:00:00")["event_time"] == _utc(2026, 9, 30, 12)
    assert parse_cef_line(base + "Sep 30 2026 14:00:00.250 +0200")["event_time"] == \
        _utc(2026, 9, 30, 12, 0, 0, 250000)
    assert parse_cef_line(base + "1759233600000")["event_time"] == _utc(2025, 9, 30, 12)


def test_huge_rt_does_not_raise(db):
    line = "CEF:0|Fortinet|Fortigate|v7|13|traffic:forward|3|src=1.1.1.1 rt=" + "9" * 25
    ev, status = ingest_syslog_line_ex(line, db)
    assert status == "created" and ev.event_time is None


@pytest.mark.parametrize("bad", ["", "garbage", "Sep 99 2026 12:00:00", "-5", "1e400",
                                 "2026-13-01 00:00:00", "Sep 30 2026 12:00:00 EST"])
def test_bad_timestamps_return_none(bad):
    assert _parse_timestamp(bad) is None


def test_eventtime_precedes_rt():
    r = parse_cef_line("CEF:0|Fortinet|Fortigate|v7|13|traffic:forward|3|src=1.1.1.1 "
                       "rt=Jan 01 2020 00:00:00 FTNTFGTeventtime=1759233600")
    assert r["event_time"] == _utc(2025, 9, 30, 12)


# ------------------------------------------------------------------ T3-27 CSV + kv signature

def test_csv_preamble_bom_variants_surplus():
    text = ("\ufeffFortiAnalyzer Report,Device Action Summary\n"
            "Device,FGT-PLANT-01\n"
            "Action,accept\n"
            "\n"
            "Date,Time,Device,Source IP,Destination IP,Source Port,Destination Port,"
            "Proto,Policy ID,Action,Sent Bytes\n"
            "2026-09-30,12:00:00,FGT1,10.1.1.1,10.2.2.2,40000,502,6,17,accept,900,EXTRA1,EXTRA2\n")
    recs = parse_forti_csv_report(text)
    assert len(recs) == 1
    r = recs[0]
    assert (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"]) == \
        ("10.1.1.1", "10.2.2.2", 40000, 502)
    assert r["protocol"] == "tcp" and r["policy_id"] == "17" and r["device_name"] == "FGT1"
    assert r["raw_fields"]["_extra"] == ["EXTRA1", "EXTRA2"]
    assert r["raw_fields"]["sentbyte"] == 900
    assert r["event_time"] == _utc(2026, 9, 30, 12)


def test_csv_bom_on_header_row():
    recs = parse_forti_csv_report("\ufeffSrcIP,DstIP,Dst Port\n1.1.1.1,2.2.2.2,44818\n")
    assert recs[0]["dst_port"] == 44818 and recs[0]["src_ip"] == "1.1.1.1"


def test_linux_audit_line_rejected(db):
    line = ('type=SYSCALL msg=audit(1759233600.123:4242): arch=c000003e syscall=59 '
            'success=yes exit=0 pid=1234 auid=1000 uid=0 comm="bash" exe="/usr/bin/bash"')
    assert parse_forti_kv_line(line) is None
    assert ingest_syslog_line_ex(line, db) == (None, "unparsed")


def test_kv_unknown_type_needs_logid():
    assert parse_forti_kv_line("type=weird devname=FGT1 srcip=1.1.1.1") is None
    assert parse_forti_kv_line("logid=9999999999 type=weird devname=FGT1 srcip=1.1.1.1") is not None


def test_kv_with_syslog_header_and_numeric_proto():
    r = parse_forti_kv_line('<189>Sep 30 12:00:00 fw1 date=2026-09-30 time=12:00:00 '
                            'devname="FGT1" devid="FG100F" logid="0000000013" type="traffic" '
                            'subtype="forward" srcip=10.1.1.1 dstip=10.2.2.2 proto=17 '
                            'sentbyte=100 rcvdbyte=200 duration=5 sessionid=77')
    assert r["protocol"] == "udp" and r["device_name"] == "FGT1"
    assert {k: r["raw_fields"][k] for k in ("sentbyte", "rcvdbyte", "duration", "sessionid")} == \
        {"sentbyte": 100, "rcvdbyte": 200, "duration": 5, "sessionid": 77}


def test_kv_without_key_fields_not_stored(db):
    assert ingest_syslog_line_ex("logid=0000000013 type=traffic devname=FGT1", db) == \
        (None, "unparsed")


# ------------------------------------------------------------------ T3-06 dedup

KV = ('date=2026-09-30 time=12:00:00 logid=0000000013 type=traffic subtype=forward '
      'devname=FGT1 srcip=10.1.1.1 dstip=10.2.2.2 dstport=502 action=accept')


def test_syslog_reupload_is_duplicate(db):
    lines = [KV, FTNT_CEF, "<134>Sep 30 12:00:00 fw1 " + FTNT_CEF]
    first = [ingest_syslog_line_ex(l, db) for l in lines]
    assert [s for _, s in first] == ["created"] * 3
    db.commit()
    second = [ingest_syslog_line_ex(l + "\r\n", db) for l in lines]
    assert [s for _, s in second] == ["duplicate"] * 3
    assert [e.id for e, _ in second] == [e.id for e, _ in first]
    assert ingest_syslog_line(KV, db) is None            # legacy wrapper
    assert db.query(FortiAnalyzerEvent).count() == 3


def test_identical_lines_in_one_upload_are_one_event(db):
    assert ingest_syslog_line_ex(KV, db)[1] == "created"
    assert ingest_syslog_line_ex(KV, db)[1] == "duplicate"
    assert ingest_syslog_line_ex(KV.replace("12:00:00", "12:00:01"), db)[1] == "created"


def test_dedup_hash_formula(db):
    import hashlib
    ev, _ = ingest_syslog_line_ex("  " + KV + "  ", db)
    assert ev.dedup_hash == hashlib.sha1(f"FGT1|{KV}".encode()).hexdigest()


def test_json_duplicate_returns_existing(db):
    payload = {"type": "traffic", "devname": "FGT1", "srcip": "1.1.1.1", "action": "accept"}
    ev1, s1 = ingest_forti_event_json_ex(payload, db)
    ev2, s2 = ingest_forti_event_json_ex(dict(reversed(list(payload.items()))), db)
    assert (s1, s2) == ("created", "duplicate") and ev1.id == ev2.id
    assert ingest_forti_event_json(payload, db).id == ev1.id
    assert db.query(FortiAnalyzerEvent).count() == 1


def test_csv_reupload_skips_duplicates(db):
    text = ("Date,Time,Device,SrcIP,DstIP,DstPort,Action\n"
            "2026-09-30,12:00:00,FGT1,1.1.1.1,2.2.2.2,502,accept\n"
            "2026-09-30,12:00:01,FGT1,1.1.1.1,2.2.2.2,502,accept\n")
    s1 = ingest_forti_csv(text, db, report_name="a.csv")
    s2 = ingest_forti_csv(text, db, report_name="b.csv")   # name-independent
    assert (s1["events_imported"], s1["duplicates_skipped"]) == (2, 0)
    assert (s2["events_imported"], s2["duplicates_skipped"], s2["event_ids"]) == (0, 2, [])
    assert db.query(FortiAnalyzerEvent).count() == 2


def test_concurrent_insert_race_is_duplicate(db, monkeypatch):
    """Another session inserted the same hash between our check and insert."""
    ev1, _ = ingest_syslog_line_ex(KV, db)
    other, _ = ingest_syslog_line_ex(KV.replace("10.1.1.1", "10.1.1.9"), db)
    real = fp._find_by_hash
    calls = {"n": 0}

    def racy(session, h, site_id=None):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(session, h, site_id)

    monkeypatch.setattr(fp, "_find_by_hash", racy)
    ev, status = ingest_syslog_line_ex(KV, db)
    assert status == "duplicate" and ev.id == ev1.id
    db.commit()                                   # outer transaction survived
    assert db.query(FortiAnalyzerEvent).count() == 2
    assert other.id is not None


def test_ingest_does_not_commit(db):
    ingest_syslog_line_ex(KV, db)
    db.rollback()
    assert db.query(FortiAnalyzerEvent).count() == 0
