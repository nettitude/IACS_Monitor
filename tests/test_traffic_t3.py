"""
Tier-3 remediation tests for the decode / baseline / findings side:
T3-31 (DNP3 packed bits + qualifier 0x28, CIP typed values), T3-32
(approved-comms port ranges/lists), T3-33 (industrial-operation findings:
requests only, grouped dedup, high-impact ops, MAC-only approvals).
"""
import struct

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    ApprovedCommsEntry, ApprovedHost, Base, Baseline, Finding, Host, NetworkSession, ProtocolDetail,
)
from app.parsers.baseline_parser import ingest_approved_comms, parse_dst_port_spec
from app.parsers.dnp3_analyzer import _parse_object_header, parse_dnp3
from app.parsers.enip_cip_analyzer import _parse_cip_message
from app.parsers.s7comm_analyzer import parse_s7comm
from app.parsers.traffic_findings import check_unauthorized_industrial_writes


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


# ================================================================ T3-31 =====

def _dnp3(app_layer: bytes) -> bytes:
    """Wrap an application layer in a DNP3 link frame (CRCs zeroed - not validated)."""
    user = b"\xC0" + app_layer
    hdr = b"\x05\x64" + bytes([5 + len(user), 0x44]) + b"\x01\x00\x0a\x00" + b"\x00\x00"
    body = b""
    for i in range(0, len(user), 16):
        body += user[i:i + 16] + b"\x00\x00"
    return hdr + body


def test_dnp3_g1v1_packed_bits_then_g30v2():
    # response: g1v1 q=0x00 start 0 stop 9 -> 2 bytes of bits; then g30v2 q=0x00 0..1 (3 bytes each)
    bits = bytes([0b10100101, 0b00000010])
    g30 = b"\x01\x10\x00" + b"\x01\x2c\x01"
    app = b"\xC0\x81\x00\x00" + b"\x01\x01\x00\x00\x09" + bits + b"\x1e\x02\x00\x00\x01" + g30
    res = parse_dnp3(_dnp3(app))
    objs = res["fields"]["objects"]
    assert [(o["group"], o["variation"]) for o in objs] == [(1, 1), (30, 2)]
    values = [p["value"] for p in objs[0]["points"]]
    assert values == [True, False, True, False, False, True, False, True, False, True]
    assert [p["index"] for p in objs[1]["points"]] == [0, 1]
    assert objs[1]["points"][1]["raw_hex"] == "012c01"


@pytest.mark.parametrize("group", [10, 80])
def test_dnp3_other_packed_bit_objects(group):
    data = bytes([group, 1, 0x00, 0, 2, 0b101, 0x3C, 0x02, 0x06])
    hdr, off = _parse_object_header(data, 0)
    assert [p["value"] for p in hdr["points"]] == [True, False, True]
    assert off == 6                       # next header (g60v2 q=0x06) intact
    nxt, _ = _parse_object_header(data, off)
    assert (nxt["group"], nxt["variation"], nxt["range_code"]) == (60, 2, 6)


def test_dnp3_qualifier_0x28_crob():
    crob = bytes([0x03, 1]) + (1000).to_bytes(4, "little") + (0).to_bytes(4, "little") + b"\x00"
    app = b"\xC0\x05" + b"\x0c\x01\x28" + (2).to_bytes(2, "little") \
        + (300).to_bytes(2, "little") + crob + (301).to_bytes(2, "little") + crob
    res = parse_dnp3(_dnp3(app))
    assert res["summary"] == "direct_operate" and res["operation"] == "write"
    obj = res["fields"]["objects"][0]
    assert obj["qualifier"] == 0x28 and obj["count"] == 2
    assert [p["index"] for p in obj["points"]] == [300, 301]
    assert obj["points"][0]["op_type"] == "latch_on"
    assert obj["points"][0]["on_time_ms"] == 1000


def test_dnp3_qualifier_0x28_aob_float():
    app = b"\xC0\x05" + b"\x29\x03\x28" + (1).to_bytes(2, "little") + (7).to_bytes(2, "little") \
        + struct.pack("<f", 21.5) + b"\x00"
    obj = parse_dnp3(_dnp3(app))["fields"]["objects"][0]
    assert obj["points"] == [{"value": 21.5, "status": 0, "index": 7}]


@pytest.mark.parametrize("fc,name", [(0x0D, "cold_restart"), (0x0E, "warm_restart"),
                                     (0x0F, "initialize_data"), (0x10, "initialize_application"),
                                     (0x12, "stop_application")])
def test_dnp3_restart_and_stop_are_control(fc, name):
    res = parse_dnp3(_dnp3(bytes([0xC0, fc])))
    assert res["summary"] == name
    assert res["operation"] == "control"


def _cip_write(type_code: int, value_bytes: bytes, count: int = 1) -> bytes:
    path = b"\x91\x03Tag\x00"                             # symbolic, padded
    return bytes([0x4D, len(path) // 2]) + path + type_code.to_bytes(2, "little") \
        + count.to_bytes(2, "little") + value_bytes


def _cip_read_resp(type_code: int, value_bytes: bytes) -> bytes:
    return bytes([0xCC, 0x00, 0x00, 0x00]) + type_code.to_bytes(2, "little") + value_bytes


@pytest.mark.parametrize("code,fmt,value", [
    (0xCA, "<f", 21.5),
    (0xCB, "<d", -3.25),
    (0xC2, "<b", -5),
    (0xC3, "<h", -300),
    (0xC4, "<i", -70000),
    (0xC5, "<q", -2 ** 40),
    (0xC6, "<B", 200),
    (0xC7, "<H", 65000),
    (0xC8, "<I", 4_000_000_000),
    (0xC9, "<Q", 2 ** 63 + 5),
])
def test_cip_values_decoded_by_type(code, fmt, value):
    raw = struct.pack(fmt, value)
    w = _parse_cip_message(_cip_write(code, raw))
    r = _parse_cip_message(_cip_read_resp(code, raw))
    assert w["fields"]["value"] == value
    assert r["fields"]["value"] == value


def test_cip_real_is_not_an_int():
    w = _parse_cip_message(_cip_write(0xCA, struct.pack("<f", 21.5)))
    assert w["fields"]["data_type"] == "real"
    assert w["fields"]["value"] == 21.5 and w["fields"]["value"] != 1101791232


def test_cip_bool_and_multi_element():
    assert _parse_cip_message(_cip_write(0xC1, b"\x01"))["fields"]["value"] is True
    w = _parse_cip_message(_cip_write(0xC7, struct.pack("<3H", 1, 2, 65535), count=3))
    assert w["fields"]["values"] == [1, 2, 65535]


def test_cip_unknown_type_keeps_raw_hex():
    w = _parse_cip_message(_cip_write(0x02A0, b"\x12\x34\x56\x78"))
    assert "value" not in w["fields"] and w["fields"]["value_raw_hex"] == "12345678"


# ================================================================ T3-32 =====

@pytest.mark.parametrize("raw,expected", [
    ("", [(None, None)]),
    ("any", [(None, None)]),
    ("ANY", [(None, None)]),
    ("502", [(502, None)]),
    ("1024-65535", [(1024, 65535)]),
    ("502,102", [(502, None), (102, None)]),
    ("502; 2000-2010", [(502, None), (2000, 2010)]),
    ("7-7", [(7, None)]),
])
def test_parse_dst_port_spec(raw, expected):
    assert parse_dst_port_spec(raw) == expected


@pytest.mark.parametrize("raw", ["http", "502,any", "70000", "10-5", "502,", "1-2-3", "tcp/502"])
def test_parse_dst_port_spec_rejects(raw):
    with pytest.raises(ValueError):
        parse_dst_port_spec(raw)


def test_ingest_comms_ranges_lists_and_rejects(db):
    csv = (
        "src,dst,dst_port,protocol\n"
        "10.0.1.1,10.0.1.10,1024-65535,tcp\n"
        "10.0.1.1,10.0.1.10,\"502,102\",tcp\n"
        "10.0.1.1,10.0.1.10,modbus,tcp\n"
        "10.0.1.1,10.0.1.10,any,udp\n"
    )
    stats = ingest_approved_comms(csv, db, "B1")
    assert stats["entries_loaded"] == 4
    assert stats["rejected"] == 1
    assert stats["errors"][0]["row"] == 4 and stats["errors"][0]["dst_port"] == "modbus"
    rows = {(e.dst_port, e.dst_port_end, e.protocol) for e in db.query(ApprovedCommsEntry)}
    assert rows == {(1024, 65535, "tcp"), (502, None, "tcp"), (102, None, "tcp"), (None, None, "udp")}


def test_ingest_comms_dedup_includes_range_end(db):
    csv = "src,dst,dst_port\n10.0.1.1,10.0.1.10,1024-2000\n10.0.1.1,10.0.1.10,1024-3000\n"
    stats = ingest_approved_comms(csv, db, "B1")
    assert stats["entries_loaded"] == 2
    again = ingest_approved_comms(csv, db, "B1")
    assert again["entries_loaded"] == 0 and again["skipped"] == 2
    assert db.query(ApprovedCommsEntry).count() == 2


# ================================================================ T3-33 =====

def _hosts(db, client_ip="10.0.3.50", server_ip="10.0.1.10", client_mac=None):
    c = Host(ip=client_ip, mac=client_mac, sources=["pcap"])
    s = Host(ip=server_ip, sources=["pcap"])
    db.add_all([c, s])
    db.flush()
    return c, s


def _session(db, src, dst, sport, dport, protocol, source_file="cap1.pcap"):
    row = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, src_port=sport, dst_port=dport,
                         transport="tcp", protocol=protocol, source_file=source_file,
                         packet_count=1, byte_count=1)
    db.add(row)
    db.flush()
    return row


def _detail(db, session, protocol, summary, operation, direction):
    d = ProtocolDetail(session_id=session.id, protocol=protocol, summary=summary, direction=direction,
                       fields={"operation": operation, "direction": direction, "summary": summary})
    db.add(d)
    db.flush()
    return d


def test_three_modbus_writes_with_responses_one_finding(db):
    c, s = _hosts(db)
    sess = _session(db, c, s, 40000, 502, "modbus")
    for _ in range(3):
        _detail(db, sess, "modbus", "write_single_register", "write", "request")
        _detail(db, sess, "modbus", "write_single_register", "write", "response")
    db.commit()
    stats = check_unauthorized_industrial_writes(db)
    assert stats["findings_created"] == 1
    assert stats["responses_ignored"] == 3
    f = db.query(Finding).one()
    assert f.severity == "critical"
    assert f.detail["occurrences"] == 3
    assert f.detail["src_ip"] == "10.0.3.50" and f.detail["dst_ip"] == "10.0.1.10"


def test_client_side_inferred_when_response_came_first(db):
    """Session row oriented server->client (first packet was a response)."""
    c, s = _hosts(db)
    sess = _session(db, s, c, 502, 40000, "modbus")
    _detail(db, sess, "modbus", "write_single_register", "write", "request")
    db.commit()
    check_unauthorized_industrial_writes(db)
    assert db.query(Finding).one().detail["src_ip"] == "10.0.3.50"


def test_distinct_functions_and_captures_are_separate_findings(db):
    c, s = _hosts(db)
    s1 = _session(db, c, s, 40000, 502, "modbus", "cap1.pcap")
    s2 = _session(db, c, s, 40001, 502, "modbus", "cap2.pcap")
    _detail(db, s1, "modbus", "write_single_register", "write", "request")
    _detail(db, s1, "modbus", "write_multiple_registers", "write", "request")
    _detail(db, s2, "modbus", "write_single_register", "write", "request")
    db.commit()
    assert check_unauthorized_industrial_writes(db)["findings_created"] == 3


def test_rerun_updates_occurrences_without_new_finding(db):
    c, s = _hosts(db)
    sess = _session(db, c, s, 40000, 502, "modbus")
    _detail(db, sess, "modbus", "write_single_register", "write", "request")
    db.commit()
    check_unauthorized_industrial_writes(db)
    _detail(db, sess, "modbus", "write_single_register", "write", "request")
    db.commit()
    stats = check_unauthorized_industrial_writes(db)
    assert stats["findings_created"] == 0 and stats["already_flagged"] == 1
    assert db.query(Finding).one().detail["occurrences"] == 2


def _s7_frame(fc: int) -> bytes:
    s7 = b"\x32\x01\x00\x00\x00\x01\x00\x01\x00\x00" + bytes([fc])
    cotp = b"\x02\xf0\x80"
    return b"\x03\x00" + (4 + len(cotp) + len(s7)).to_bytes(2, "big") + cotp + s7


@pytest.mark.parametrize("protocol,port,decoded", [
    ("s7comm", 102, lambda: parse_s7comm(_s7_frame(0x29))),
    ("s7comm", 102, lambda: parse_s7comm(_s7_frame(0x1B))),
    ("dnp3", 20000, lambda: parse_dnp3(_dnp3(b"\xC0\x0D"))),
    ("dnp3", 20000, lambda: parse_dnp3(_dnp3(b"\xC0\x12"))),
])
def test_high_impact_operations_flagged(db, protocol, port, decoded):
    fields = decoded()
    assert fields["operation"] in ("program", "control")
    c, s = _hosts(db)
    sess = _session(db, c, s, 40000, port, protocol)
    db.add(ProtocolDetail(session_id=sess.id, protocol=protocol, summary=fields["summary"],
                          direction=fields["direction"], fields=fields))
    db.commit()
    stats = check_unauthorized_industrial_writes(db)
    assert stats["findings_created"] == 1 and stats["high_impact_ops"] == 1
    f = db.query(Finding).one()
    assert f.detail["high_impact"] is True
    assert fields["summary"] in f.title


def test_mac_only_approved_host_is_honoured(db):
    bl = Baseline(name="b", is_active=True)
    db.add(bl)
    db.flush()
    db.add(ApprovedHost(baseline_id=bl.id, mac="AA-BB-CC-00-11-22", role="engineering_ws"))
    c, s = _hosts(db, client_mac="aa:bb:cc:00:11:22")
    sess = _session(db, c, s, 40000, 502, "modbus")
    _detail(db, sess, "modbus", "write_single_register", "write", "request")
    db.commit()
    assert check_unauthorized_industrial_writes(db)["findings_created"] == 0


def test_findings_commit_false_only_flushes(db, monkeypatch):
    c, s = _hosts(db)
    sess = _session(db, c, s, 40000, 502, "modbus")
    _detail(db, sess, "modbus", "write_single_register", "write", "request")
    db.commit()
    calls = []
    monkeypatch.setattr(db, "commit", lambda: calls.append(1))
    check_unauthorized_industrial_writes(db, commit=False)
    assert calls == []
    assert db.query(Finding).count() == 1
