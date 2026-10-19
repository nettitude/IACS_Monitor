"""
Tests for app/parsers/pcap_parser.py

Strategy:
- Write minimal real PCAP files to disk and call ingest_pcap() with them.
- Use scapy to build packets so the PCAP is valid and readable by PcapReader.
- Test protocol dispatch, session creation, and stat counting.
"""
import os
import struct
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, NetworkSession, ProtocolDetail
from app.parsers.pcap_parser import ingest_pcap, _handle_tcp_protocols, _get_ethertype

# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Minimal PCAP writer (no scapy dependency for the file format itself)
# ---------------------------------------------------------------------------

def _pcap_global_header(snaplen=65535, network=1):
    """Write a libpcap global header (little-endian)."""
    return struct.pack("<IHHiIII",
        0xA1B2C3D4,  # magic
        2, 4,         # version
        0,            # thiszone
        0,            # sigfigs
        snaplen,
        network,      # 1 = Ethernet
    )


def _pcap_record(data: bytes, ts_sec=0, ts_usec=0):
    """Wrap raw packet bytes as a pcap record."""
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _eth_ip_tcp_packet(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    sport=12345, dport=502, payload=b""
):
    """Build a raw Ethernet+IP+TCP packet using scapy."""
    from scapy.all import Ether, IP, TCP, Raw
    pkt = Ether(src="00:11:22:33:44:55", dst="00:AA:BB:CC:DD:EE") / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport) / \
          Raw(load=payload)
    return bytes(pkt)


def _write_pcap(packets, path):
    """Write a list of raw packet bytes as a valid PCAP file."""
    with open(path, "wb") as f:
        f.write(_pcap_global_header())
        for pkt in packets:
            f.write(_pcap_record(pkt))


# ---------------------------------------------------------------------------
# Minimal valid Modbus/TCP payload (FC 3, Read Holding Registers request)
# ---------------------------------------------------------------------------

_MODBUS_READ_PAYLOAD = (
    b"\x00\x01"   # transaction id
    b"\x00\x00"   # protocol id
    b"\x00\x06"   # length
    b"\x01"       # unit id
    b"\x03"       # FC 3 = read holding registers
    b"\x00\x00"   # start address
    b"\x00\x0A"   # quantity
)

_MODBUS_WRITE_PAYLOAD = (
    b"\x00\x02"   # transaction id
    b"\x00\x00"   # protocol id
    b"\x00\x09"   # length
    b"\x01"       # unit id
    b"\x10"       # FC 16 = write multiple registers
    b"\x00\x00"   # start address
    b"\x00\x01"   # quantity
    b"\x02"       # byte count
    b"\x00\x42"   # value
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ingest_pcap_creates_hosts_and_session(db, tmp_path):
    """A single Modbus packet creates src host, dst host, and one session."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "test.pcap")
    _write_pcap([pkt], pcap_path)

    stats = ingest_pcap(pcap_path, db)

    assert stats["packets"] == 1
    assert stats["sessions"] == 1
    assert db.query(Host).count() == 2
    session = db.query(NetworkSession).first()
    assert session is not None
    assert session.dst_port == 502


def test_ingest_pcap_modbus_protocol_label(db, tmp_path):
    """Modbus packet on port 502 gets protocol='modbus' on the session."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "modbus.pcap")
    _write_pcap([pkt], pcap_path)

    ingest_pcap(pcap_path, db)

    session = db.query(NetworkSession).first()
    assert session.protocol == "modbus"


def test_ingest_pcap_modbus_creates_protocol_detail(db, tmp_path):
    """A Modbus payload creates a ProtocolDetail row."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "mb_detail.pcap")
    _write_pcap([pkt], pcap_path)

    ingest_pcap(pcap_path, db)

    detail = db.query(ProtocolDetail).first()
    assert detail is not None
    assert detail.protocol == "modbus"


def test_ingest_pcap_unknown_port_no_protocol_detail(db, tmp_path):
    """Payload on unknown port 9999 leaves session protocol='unknown', no ProtocolDetail."""
    pkt = _eth_ip_tcp_packet(dport=9999, payload=b"\xDE\xAD\xBE\xEF")
    pcap_path = str(tmp_path / "unknown.pcap")
    _write_pcap([pkt], pcap_path)

    ingest_pcap(pcap_path, db)

    session = db.query(NetworkSession).first()
    assert session is not None
    assert session.protocol == "unknown"
    assert db.query(ProtocolDetail).count() == 0


def test_ingest_pcap_multiple_packets_same_session(db, tmp_path):
    """Two packets on the same 5-tuple accumulate into one session, not two."""
    pkt1 = _eth_ip_tcp_packet(sport=12345, dport=502, payload=_MODBUS_READ_PAYLOAD)
    pkt2 = _eth_ip_tcp_packet(sport=12345, dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "same_session.pcap")
    _write_pcap([pkt1, pkt2], pcap_path)

    stats = ingest_pcap(pcap_path, db)

    assert stats["sessions"] == 1
    assert stats["packets"] == 2
    session = db.query(NetworkSession).first()
    assert session.packet_count == 2


def test_ingest_pcap_two_different_sessions(db, tmp_path):
    """Packets to two different dst ports create two sessions."""
    pkt1 = _eth_ip_tcp_packet(sport=11111, dport=502, payload=_MODBUS_READ_PAYLOAD)
    # FO-04: a data-less SYN would be a connection attempt, not a session
    pkt2 = _eth_ip_tcp_packet(sport=22222, dport=20000, payload=b"\x05\x64")
    pcap_path = str(tmp_path / "two_sessions.pcap")
    _write_pcap([pkt1, pkt2], pcap_path)

    stats = ingest_pcap(pcap_path, db)

    assert stats["sessions"] == 2


def test_ingest_pcap_stat_protocol_frames(db, tmp_path):
    """stat['protocol_frames']['modbus'] is incremented for Modbus traffic."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "frames.pcap")
    _write_pcap([pkt], pcap_path)

    stats = ingest_pcap(pcap_path, db)

    assert stats["protocol_frames"]["modbus"] >= 1


def test_ingest_pcap_write_modbus_session(db, tmp_path):
    """FC 16 (write multiple registers) creates a ProtocolDetail with operation='write'."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_WRITE_PAYLOAD)
    pcap_path = str(tmp_path / "write.pcap")
    _write_pcap([pkt], pcap_path)

    ingest_pcap(pcap_path, db)

    detail = db.query(ProtocolDetail).first()
    assert detail is not None
    assert detail.fields.get("operation") == "write"


def test_ingest_pcap_source_file_recorded(db, tmp_path):
    """source_file on the session matches the path passed to ingest_pcap."""
    pkt = _eth_ip_tcp_packet(dport=502, payload=_MODBUS_READ_PAYLOAD)
    pcap_path = str(tmp_path / "source.pcap")
    _write_pcap([pkt], pcap_path)

    ingest_pcap(pcap_path, db, source_file="my_capture.pcap")

    session = db.query(NetworkSession).first()
    assert session.source_file == "my_capture.pcap"


def test_handle_tcp_protocols_unknown_port_returns_none(db):
    """_handle_tcp_protocols returns None for an unrecognized port."""
    from app.models import NetworkSession as NS, Host
    src = Host(ip="1.1.1.1", sources=["pcap"])
    dst = Host(ip="2.2.2.2", sources=["pcap"])
    db.add_all([src, dst])
    db.flush()
    sess = NS(src_host_id=src.id, dst_host_id=dst.id, src_port=9999, dst_port=9998,
              protocol="unknown", transport="tcp", packet_count=0, byte_count=0)
    db.add(sess)
    db.flush()

    stats = {"protocol_frames": {
        "modbus": 0, "s7comm": 0, "dnp3": 0, "ethernet_ip": 0,
        "profinet": 0, "smb1": 0, "smb2_3": 0,
    }}
    result = _handle_tcp_protocols(b"\x00\x01\x02\x03", 9999, 9998, sess, stats)
    assert result is None


def test_dataless_syn_is_a_connection_attempt(db, tmp_path):
    """FO-04: a SYN with no data and no answer is recorded as an attempt."""
    from app.models import ConnectionAttempt, NetworkSession
    pkt = _eth_ip_tcp_packet(sport=33333, dport=102, payload=b"")
    pcap_path = str(tmp_path / "syn.pcap")
    _write_pcap([pkt], pcap_path)
    stats = ingest_pcap(pcap_path, db)
    assert stats["sessions"] == 0 and stats["connection_attempts"] == {"unanswered": 1}
    assert db.query(NetworkSession).count() == 0
    [a] = db.query(ConnectionAttempt).all()
    assert (a.src_ip, a.dst_ip, a.dst_port, a.outcome) == ("10.0.0.1", "10.0.0.2", 102, "unanswered")
