"""
Tests for app/parsers/forti_parser.py
"""
import pytest
from datetime import timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, FortiAnalyzerEvent
from app.parsers.forti_parser import (
    parse_cef_line,
    parse_forti_kv_line,
    parse_forti_csv_report,
    ingest_syslog_line,
    ingest_forti_csv,
    ingest_forti_event_json,
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ------------------------------------------------------------------ CEF parsing

CEF_LINE = (
    "CEF:0|Fortinet|FortiGate|v7.4.2|0000000013|traffic:forward close|3|"
    "deviceExternalId=FGT01 src=192.168.1.100 dst=10.0.2.200 "
    "spt=54321 dpt=502 proto=tcp act=accept "
    "cs1Label=policyid cs1=42 cs2Label=policyname cs2=ICS-PERMIT "
    "rt=2024-01-15 10:30:00"
)


def test_cef_parse_returns_dict():
    result = parse_cef_line(CEF_LINE)
    assert result is not None
    assert isinstance(result, dict)


def test_cef_parse_src_dst():
    result = parse_cef_line(CEF_LINE)
    assert result["src_ip"] == "192.168.1.100"
    assert result["dst_ip"] == "10.0.2.200"


def test_cef_parse_ports():
    result = parse_cef_line(CEF_LINE)
    assert result["src_port"] == 54321
    assert result["dst_port"] == 502


def test_cef_parse_action():
    result = parse_cef_line(CEF_LINE)
    assert result["action"] == "accept"


def test_cef_parse_device_name():
    result = parse_cef_line(CEF_LINE)
    assert result["device_name"] == "FGT01"


def test_cef_parse_policy():
    result = parse_cef_line(CEF_LINE)
    assert result["policy_id"] == "42"
    assert result["policy_name"] == "ICS-PERMIT"


def test_cef_parse_source_type():
    result = parse_cef_line(CEF_LINE)
    assert result["source_type"] == "syslog_cef"


def test_cef_non_cef_line_returns_none():
    assert parse_cef_line("this is not a cef line") is None


def test_cef_empty_line_returns_none():
    assert parse_cef_line("") is None


# ------------------------------------------------------------------ FortiGate kv-format

FORTI_KV_LINE = (
    'date=2024-01-15 time=10:30:00 devname=FGT01 type=traffic subtype=forward '
    'action=accept srcip=192.168.1.100 dstip=10.0.2.200 '
    'srcport=54321 dstport=502 proto=tcp policyid=42 '
    'policyname=ICS-PERMIT service=Modbus'
)


def test_forti_kv_parse_returns_dict():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result is not None
    assert isinstance(result, dict)


def test_forti_kv_parse_ips():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["src_ip"] == "192.168.1.100"
    assert result["dst_ip"] == "10.0.2.200"


def test_forti_kv_parse_ports():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["src_port"] == 54321
    assert result["dst_port"] == 502


def test_forti_kv_parse_action():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["action"] == "accept"


def test_forti_kv_parse_device():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["device_name"] == "FGT01"


def test_forti_kv_parse_event_time():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["event_time"] is not None
    assert result["event_time"].year == 2024


def test_forti_kv_missing_type_returns_none():
    result = parse_forti_kv_line("srcip=1.2.3.4 dstip=5.6.7.8")
    assert result is None


def test_forti_kv_empty_returns_none():
    assert parse_forti_kv_line("") is None


def test_forti_kv_log_type_and_subtype():
    result = parse_forti_kv_line(FORTI_KV_LINE)
    assert result["log_type"] == "traffic"
    assert result["subtype"] == "forward"


# ------------------------------------------------------------------ CSV report

CSV_TEXT = """\
Date,Time,Device,SrcIP,DstIP,SrcPort,DstPort,Proto,PolicyID,PolicyName,Action
2024-01-15,10:30:00,FGT01,192.168.1.100,10.0.2.200,54321,502,tcp,42,ICS-PERMIT,accept
2024-01-15,10:31:00,FGT01,10.0.3.50,10.0.2.201,50001,44818,tcp,43,EtherNet-IP,accept
"""


def test_csv_parse_returns_records():
    records = parse_forti_csv_report(CSV_TEXT)
    assert len(records) == 2


def test_csv_parse_ips():
    records = parse_forti_csv_report(CSV_TEXT)
    assert records[0]["src_ip"] == "192.168.1.100"
    assert records[0]["dst_ip"] == "10.0.2.200"


def test_csv_parse_ports_as_int():
    records = parse_forti_csv_report(CSV_TEXT)
    assert records[0]["dst_port"] == 502


def test_csv_parse_action_lowercased():
    records = parse_forti_csv_report(CSV_TEXT)
    assert records[0]["action"] == "accept"


def test_csv_parse_source_type():
    records = parse_forti_csv_report(CSV_TEXT)
    assert records[0]["source_type"] == "csv_import"


def test_csv_empty_returns_empty():
    assert parse_forti_csv_report("") == []


def test_csv_only_header_returns_empty():
    records = parse_forti_csv_report("Date,Time,Device,SrcIP,DstIP\n")
    assert records == []


# ------------------------------------------------------------------ ingest to DB

def test_ingest_syslog_cef_creates_event(db):
    ev = ingest_syslog_line(CEF_LINE, db)
    assert ev is not None
    assert isinstance(ev, FortiAnalyzerEvent)
    assert ev.src_ip == "192.168.1.100"


def test_ingest_syslog_kv_creates_event(db):
    ev = ingest_syslog_line(FORTI_KV_LINE, db)
    assert ev is not None
    assert ev.src_ip == "192.168.1.100"


def test_ingest_syslog_garbage_returns_none(db):
    ev = ingest_syslog_line("this is not a log line", db)
    assert ev is None
    assert db.query(FortiAnalyzerEvent).count() == 0


def test_ingest_csv_creates_events(db):
    stats = ingest_forti_csv(CSV_TEXT, db)
    assert stats["events_imported"] == 2
    assert len(stats["event_ids"]) == 2


def test_ingest_csv_empty_no_events(db):
    stats = ingest_forti_csv("", db)
    assert stats["events_imported"] == 0


def test_ingest_json_creates_event(db):
    payload = {
        "type": "traffic",
        "subtype": "forward",
        "devname": "FGT01",
        "srcip": "192.168.1.100",
        "dstip": "10.0.2.200",
        "srcport": 12345,
        "dstport": 502,
        "proto": "tcp",
        "action": "accept",
        "date": "2024-01-15",
        "time": "10:30:00",
    }
    ev = ingest_forti_event_json(payload, db)
    assert ev is not None
    assert ev.source_type == "api_push"


def test_ingest_multiple_syslog_lines(db):
    lines = [CEF_LINE, FORTI_KV_LINE]
    for line in lines:
        ingest_syslog_line(line, db)
    db.commit()
    assert db.query(FortiAnalyzerEvent).count() == 2


def test_raw_message_truncated_if_too_long(db):
    long_line = CEF_LINE + " x=" + "A" * 5000
    ev = ingest_syslog_line(long_line, db)
    if ev is not None:
        assert len(ev.raw_message) <= 4096
