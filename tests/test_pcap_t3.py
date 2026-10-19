"""
Tier-3 remediation tests for the pcap ingest path:
T3-13 (single commit / commit=False), T3-28 (TCP reassembly with seq
tracking + resync), T3-29 (host merge + gateway MAC handling), T3-30
(packet timestamps, IPv6 visibility, analyzer isolation), the race-safe
session get-or-create, and F-13 (host cache).
"""
import logging
from datetime import datetime, timezone

import pytest
from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, NetworkSession, ProtocolDetail
from app.parsers import pcap_parser
from app.parsers.common import detect_gateway_macs, get_or_create_host
from app.parsers.pcap_parser import _drain_stream, _s7comm_frame_length, dnp3_crc, ingest_pcap


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


CLIENT_MAC = "00:11:22:33:44:55"
SERVER_MAC = "00:aa:bb:cc:dd:ee"
T0 = 1_700_000_000.0


def _tcp(payload=b"", seq=1000, sport=40000, dport=102, src="10.0.1.5", dst="10.0.1.10",
         smac=CLIENT_MAC, dmac=SERVER_MAC, t=T0, flags="PA"):
    p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    if payload:
        p = p / Raw(load=payload)
    p.time = t
    return p


def _write(tmp_path, pkts, name="t.pcap"):
    path = str(tmp_path / name)
    wrpcap(path, pkts)
    return path


# ---------------------------------------------------------------- frames ----

def _s7_read_var(ref: int) -> bytes:
    s7 = b"\x32\x01\x00\x00" + ref.to_bytes(2, "big") + b"\x00\x02\x00\x00" + b"\x04\x00"
    cotp = b"\x02\xf0\x80"
    return b"\x03\x00" + (4 + len(cotp) + len(s7)).to_bytes(2, "big") + cotp + s7


def _dnp3_frame(fc: int, seq: int = 0) -> bytes:
    user = bytes([0xC0 | seq, 0xC0 | seq, fc])            # transport, app ctl, fc
    hdr = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + (10).to_bytes(2, "little") + (1).to_bytes(2, "little")
    hdr += dnp3_crc(hdr).to_bytes(2, "little")
    return hdr + user + dnp3_crc(user).to_bytes(2, "little")


def _modbus_read(txid: int) -> bytes:
    return txid.to_bytes(2, "big") + b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"


# ----------------------------------------------------------- T3-28 -----------

def test_stray_bytes_before_five_s7_frames(db, tmp_path):
    frames = b"".join(_s7_read_var(i) for i in range(5))
    path = _write(tmp_path, [_tcp(b"\xde\xad\xbe" + frames)])
    stats = ingest_pcap(path, db)
    assert stats["protocol_frames"]["s7comm"] == 5
    assert db.query(ProtocolDetail).count() == 5
    assert stats["stream_resyncs"] >= 1
    assert stats["resync_bytes_skipped"] == 3


def test_misaligned_stream_recovers_across_segments(db, tmp_path):
    """Stray bytes in one segment, frames split mid-frame across later ones."""
    frames = b"".join(_s7_read_var(i) for i in range(5))
    seg1 = b"\x01\x02\x03"
    seg2, seg3 = frames[:10], frames[10:]
    pkts = [_tcp(seg1, seq=1000), _tcp(seg2, seq=1003, t=T0 + 1), _tcp(seg3, seq=1013, t=T0 + 2)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["s7comm"] == 5


def test_out_of_order_and_retransmitted_segments_decode_once(db, tmp_path):
    f = [_dnp3_frame(0x01, i) for i in range(3)]
    s0 = 5000
    seqs = [s0, s0 + len(f[0]), s0 + len(f[0]) + len(f[1])]
    pkts = [
        _tcp(seq=s0 - 1, dport=20000, flags="S"),          # handshake fixes the ISN
        _tcp(f[1], seq=seqs[1], dport=20000),              # arrives early
        _tcp(f[0], seq=seqs[0], dport=20000),              # fills the gap
        _tcp(f[0], seq=seqs[0], dport=20000),              # full retransmission
        _tcp(f[1][-4:] + f[2], seq=seqs[2] - 4, dport=20000),  # overlapping retransmission
        _tcp(f[2], seq=seqs[2], dport=20000),              # duplicate
    ]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["dnp3"] == 3
    assert stats["tcp_out_of_order_segments"] >= 1
    assert stats["tcp_retransmitted_segments"] >= 2
    fcs = [d.fields["transport"]["seq"] for d in db.query(ProtocolDetail).order_by(ProtocolDetail.id)]
    assert fcs == [0, 1, 2]          # delivered in sequence order


def test_reordering_mid_stream_without_handshake(db, tmp_path):
    """No SYN captured: the first data segment anchors the stream, later
    reordering is still put back in sequence."""
    f = [_s7_read_var(i) for i in range(4)]
    off = [100]
    for fr in f[:-1]:
        off.append(off[-1] + len(fr))
    pkts = [_tcp(f[0], seq=off[0]), _tcp(f[2], seq=off[2]), _tcp(f[3], seq=off[3]),
            _tcp(f[1], seq=off[1])]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["s7comm"] == 4
    refs = [d.fields["pdu_reference"] for d in db.query(ProtocolDetail).order_by(ProtocolDetail.id)]
    assert refs == [0, 1, 2, 3]


def test_modbus_requests_coalesced_into_one_segment(db, tmp_path):
    payload = b"".join(_modbus_read(i) for i in range(4))
    stats = ingest_pcap(_write(tmp_path, [_tcp(payload, dport=502)]), db)
    assert stats["protocol_frames"]["modbus"] == 4
    txids = [d.fields["transaction_id"] for d in db.query(ProtocolDetail).order_by(ProtocolDetail.id)]
    assert txids == [0, 1, 2, 3]


def test_modbus_request_split_across_segments(db, tmp_path):
    frame = _modbus_read(7)
    pkts = [_tcp(frame[:5], seq=1, dport=502), _tcp(frame[5:], seq=6, dport=502)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["modbus"] == 1


def test_lost_segment_gap_is_skipped(db, tmp_path):
    """A missing segment never arrives: frames after it still decode."""
    f = [_s7_read_var(i) for i in range(4)]
    s = 100
    pkts = [
        _tcp(f[0], seq=s),
        # f[1] (and the first half of f[2]) lost
        _tcp(f[2][8:] + f[3], seq=s + len(f[0]) + len(f[1]) + 8),
    ]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["s7comm"] == 2       # f[0] and f[3]
    assert stats["tcp_gaps"] == 1


def test_syn_sets_initial_sequence(db, tmp_path):
    frame = _s7_read_var(1)
    pkts = [_tcp(seq=999, flags="S"), _tcp(frame, seq=1000)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["s7comm"] == 1


def test_stream_buffer_cap(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_parser, "MAX_STREAM_BUFFER_BYTES", 200)
    # ENIP header announcing a 60000-byte payload that never completes.
    hdr = (0x6F).to_bytes(2, "little") + (60000).to_bytes(2, "little") + b"\x00" * 20
    pkts = [_tcp(hdr + b"\x00" * 150, seq=1, dport=44818),
            _tcp(b"\x00" * 150, seq=1 + 174, dport=44818)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["stream_buffer_overflows"] == 1


def test_drain_stream_unit():
    frames = b"".join(_s7_read_var(i) for i in range(2))
    stats = {"stream_resyncs": 0, "resync_bytes_skipped": 0}
    out, left = _drain_stream(b"\xff\x03" + frames + b"\x03\x00", _s7comm_frame_length, stats)
    assert len(out) == 2 and left == b"\x03\x00"
    assert stats["resync_bytes_skipped"] == 2


# ----------------------------------------------------------- T3-30 -----------

def test_packet_timestamps_used_for_sessions_hosts_details(db, tmp_path):
    pkts = [_tcp(_modbus_read(1), seq=1, dport=502, t=T0),
            _tcp(_modbus_read(2), seq=13, dport=502, t=T0 + 60)]
    ingest_pcap(_write(tmp_path, pkts), db)

    def utc(dt):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    first = datetime.fromtimestamp(T0, tz=timezone.utc)
    last = datetime.fromtimestamp(T0 + 60, tz=timezone.utc)
    sess = db.query(NetworkSession).one()
    assert utc(sess.first_seen) == first and utc(sess.last_seen) == last
    for h in db.query(Host).all():
        assert utc(h.first_seen) == first and utc(h.last_seen) == last
    stamps = sorted(utc(d.timestamp) for d in db.query(ProtocolDetail).all())
    assert stamps == [first, last]


def test_ipv6_packets_counted(db, tmp_path):
    p6 = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=1, dport=2)
    p6.time = T0
    stats = ingest_pcap(_write(tmp_path, [p6, _tcp(_modbus_read(1), dport=502)]), db)
    # F-07: IPv6 is ingested now; the old key stays at 0 for one release.
    assert stats["ipv6_packets"] == 1
    assert stats["ipv6_packets_skipped"] == 0
    assert stats["packets"] == 2


def test_analyzer_exception_is_isolated(db, tmp_path, monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("analyzer bug")

    monkeypatch.setattr(pcap_parser, "parse_modbus_tcp", boom)
    pkts = [_tcp(_modbus_read(i), seq=1 + 12 * i, dport=502) for i in range(3)]
    pkts.append(_tcp(_s7_read_var(1)))
    with caplog.at_level(logging.ERROR, logger="app.parsers.pcap_parser"):
        stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["analyzer_errors"] == 3
    assert stats["analyzer_errors_by_protocol"] == {"modbus": 3}
    assert stats["protocol_frames"]["s7comm"] == 1
    assert sum("modbus analyzer raised" in r.getMessage() for r in caplog.records) == 1


# ----------------------------------------------------------- T3-13 -----------

def test_commit_false_only_flushes(db, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(db, "commit", lambda: calls.append(1))
    stats = ingest_pcap(_write(tmp_path, [_tcp(_modbus_read(1), dport=502)]), db, commit=False)
    assert calls == []
    assert stats["sessions"] == 1
    monkeypatch.undo()
    db.rollback()
    assert db.query(Host).count() == 0
    assert db.query(NetworkSession).count() == 0


def test_commit_true_rolls_back_on_failure(db, tmp_path, monkeypatch):
    db.add(Host(ip="192.0.2.1", sources=["arp"]))
    db.commit()

    def fail(*a, **k):
        raise RuntimeError("late failure")

    monkeypatch.setattr(pcap_parser, "touch_host_times", fail)
    with pytest.raises(RuntimeError):
        ingest_pcap(_write(tmp_path, [_tcp(_modbus_read(1), dport=502)]), db)
    assert db.query(Host).count() == 1          # only the pre-existing row
    assert db.query(NetworkSession).count() == 0


def test_single_commit_on_success(db, tmp_path, monkeypatch):
    real_commit = db.commit
    calls = []

    def counting_commit():
        calls.append(1)
        real_commit()

    monkeypatch.setattr(db, "commit", counting_commit)
    ingest_pcap(_write(tmp_path, [_tcp(_modbus_read(i), seq=1 + 12 * i, dport=502) for i in range(3)]), db)
    assert calls == [1]


def test_pcap_capture_id_stamped(db, tmp_path):
    from app.models import PcapCapture
    cap = PcapCapture(filename="x.pcap")
    db.add(cap)
    db.flush()
    ingest_pcap(_write(tmp_path, [_tcp(_modbus_read(1), dport=502)]), db, pcap_capture_id=cap.id)
    assert db.query(NetworkSession).one().pcap_capture_id == cap.id


# -------------------------------------------------- session race (T3-10) -----

def test_session_insert_race_reuses_existing_row(db, tmp_path, monkeypatch):
    db.execute(text(
        "CREATE UNIQUE INDEX ux_test_session_5tuple ON network_sessions "
        "(src_host_id, dst_host_id, src_port, dst_port, transport)"
    ))
    a = get_or_create_host(db, "10.0.1.5", CLIENT_MAC, "pcap")
    b = get_or_create_host(db, "10.0.1.10", SERVER_MAC, "pcap")
    winner = NetworkSession(src_host_id=a.id, dst_host_id=b.id, src_port=40000, dst_port=102,
                            transport="tcp", protocol="unknown", packet_count=5, byte_count=0)
    db.add(winner)
    db.commit()

    real_find = pcap_parser._find_session
    calls = {"n": 0}

    def racy_find(*args, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return None          # the concurrent insert isn't visible yet
        return real_find(*args, **kw)

    monkeypatch.setattr(pcap_parser, "_find_session", racy_find)
    stats = ingest_pcap(_write(tmp_path, [_tcp(_s7_read_var(1))]), db)
    assert calls["n"] == 2
    assert db.query(NetworkSession).count() == 1
    row = db.query(NetworkSession).one()
    assert row.id == winner.id and row.packet_count == 6
    assert stats["protocol_frames"]["s7comm"] == 1
    assert db.query(ProtocolDetail).one().session_id == winner.id


def test_reingest_reuses_session_rows(db, tmp_path):
    path = _write(tmp_path, [_tcp(_modbus_read(1), dport=502)])
    ingest_pcap(path, db)
    ingest_pcap(path, db)
    assert db.query(NetworkSession).count() == 1
    assert db.query(NetworkSession).one().packet_count == 2


# ----------------------------------------------------------- T3-29 -----------

def test_ip_only_host_gets_mac_from_pcap(db, tmp_path):
    get_or_create_host(db, "10.0.1.10", None, "fortigate_config")
    db.commit()
    ingest_pcap(_write(tmp_path, [_tcp(_modbus_read(1), dport=502)]), db)
    rows = db.query(Host).filter(Host.ip == "10.0.1.10").all()
    assert len(rows) == 1
    assert rows[0].mac == SERVER_MAC
    assert set(rows[0].sources) == {"fortigate_config", "pcap"}


def test_get_or_create_host_merge_rules(db):
    ip_only = get_or_create_host(db, "10.9.0.1", None, "arp")
    merged = get_or_create_host(db, "10.9.0.1", "aa:aa:aa:00:00:01", "pcap")
    assert merged.id == ip_only.id and merged.mac == "aa:aa:aa:00:00:01"
    # IP-only observation of a host now known with a MAC -> same row
    assert get_or_create_host(db, "10.9.0.1", None, "config").id == ip_only.id
    # MAC-only row later seen with an IP -> IP attached
    mac_only = get_or_create_host(db, None, "aa:aa:aa:00:00:02", "mac_table")
    assert get_or_create_host(db, "10.9.0.2", "AA-AA-AA-00-00-02", "pcap").id == mac_only.id
    assert get_or_create_host(db, None, "aa:aa:aa:00:00:02", "mac_table").id == mac_only.id
    assert db.query(Host).count() == 2


def test_detect_gateway_macs_rules():
    r = "02:00:00:00:00:01"
    assert detect_gateway_macs({r: ["10.0.1.5", "10.0.1.6"]}) == set()
    # A-22: one off-subnet IP (possibly spoofed) is not enough; two are
    assert detect_gateway_macs({r: ["10.0.1.5", "172.16.0.9"]}) == set()
    assert detect_gateway_macs({r: ["10.0.1.5", "172.16.0.9", "172.16.0.10"]}) == {r}
    assert detect_gateway_macs({r: [f"10.0.1.{i}" for i in range(1, 11)]}) == {r}
    assert detect_gateway_macs({"ff:ff:ff:ff:ff:ff": ["10.0.1.1", "10.9.9.9"]}) == set()
    assert detect_gateway_macs({"01:00:5e:00:00:01": ["10.0.1.1", "10.9.9.9"]}) == set()
    # DHCP 0.0.0.0 -> real address isn't "multiple subnets"
    assert detect_gateway_macs({r: ["0.0.0.0", "10.0.1.5"]}) == set()
    # Reference subnet comes from the ARP-claimed own IP
    assert detect_gateway_macs({r: ["10.0.1.1", "10.0.1.2"]}, {r: {"192.168.0.1"}}) == {r}


def test_routed_remote_ips_do_not_get_gateway_mac(db, tmp_path):
    gw = "02:00:5e:10:00:01"
    local = "00:1b:1b:00:00:10"
    pkts = [Ether(src=gw, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, hwsrc=gw, psrc="10.0.1.1", hwdst="00:00:00:00:00:00", pdst="10.0.1.10")]
    pkts[0].time = T0
    for i, remote in enumerate(["172.16.5.20", "172.16.5.21", "192.168.9.9"]):
        pkts.append(_tcp(_modbus_read(i), seq=1, sport=41000 + i, dport=502,
                         src=remote, dst="10.0.1.10", smac=gw, dmac=local))
        pkts.append(_tcp(b"", seq=1, sport=502, dport=41000 + i,
                         src="10.0.1.10", dst=remote, smac=local, dmac=gw, flags="A"))
    # the router's own IP talking to the PLC keeps its MAC
    pkts.append(_tcp(b"", seq=1, sport=161, dport=1161, src="10.0.1.1", dst="10.0.1.10",
                     smac=gw, dmac=local, flags="A"))
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["gateway_macs"] == [gw]
    for remote in ["172.16.5.20", "172.16.5.21", "192.168.9.9"]:
        h = db.query(Host).filter(Host.ip == remote).one()
        assert h.mac is None and h.vendor is None
    assert db.query(Host).filter(Host.ip == "10.0.1.1").one().mac == gw
    assert db.query(Host).filter(Host.ip == "10.0.1.10").one().mac == local


# ------------------------------------------------------------- F-13 ----------

def test_host_cache_avoids_repeat_lookups(db, tmp_path):
    pkts = [_tcp(_modbus_read(i), seq=1 + 12 * i, dport=502) for i in range(20)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["host_cache_hits"] == 38     # 40 lookups, 2 distinct hosts
    assert stats["hosts"] == 2
