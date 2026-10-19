"""
F-07 (IPv6 capture), F-12 (IP defragmentation, DNP3 transport reassembly),
F-13 (bulk ProtocolDetail inserts / raw decoding) and F-16 (MAC kinds,
normalisation) for the pcap ingest path. All captures are crafted under
tmp_path.
"""
import pytest
from scapy.all import (
    ARP, Ether, IP, IPv6, TCP, UDP, Raw, fragment, fragment6, wrpcap,
)
from scapy.layers.inet6 import (
    ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptSrcLLAddr, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, NetworkSession, ProtocolDetail
from app.parsers import pcap_parser
from app.parsers.common import lookup_vendor, lookup_vendor_info, normalize_mac
from app.parsers.dnp3_analyzer import Dnp3TransportReassembler
from app.parsers.oui_database import mac_kind
from app.parsers.pcap_parser import dnp3_crc, ingest_pcap


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


A_MAC, B_MAC = "00:1b:1b:00:00:0a", "00:0e:8c:00:00:0b"
A6, B6 = "2001:db8:1::a", "2001:db8:1::b"
T0 = 1_700_000_000.0


def _write(tmp_path, pkts, name="f.pcap"):
    for i, p in enumerate(pkts):
        if not getattr(p, "_t_set", False):
            p.time = T0 + i * 0.001
    path = str(tmp_path / name)
    wrpcap(path, pkts)
    return path


def _modbus_read(txid: int) -> bytes:
    return txid.to_bytes(2, "big") + b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"


def _modbus_write_regs(txid: int, n: int) -> bytes:
    pdu = b"\x10\x00\x00" + n.to_bytes(2, "big") + bytes([2 * n]) + bytes(range(2 * n))
    return txid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + b"\x01" + pdu


# ------------------------------------------------------------------ F-07 ----

def test_ipv6_tcp_with_extension_headers_decodes_modbus(db, tmp_path):
    p = (Ether(src=A_MAC, dst=B_MAC) / IPv6(src=A6, dst=B6)
         / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
         / IPv6ExtHdrRouting(addresses=[B6], segleft=0) / IPv6ExtHdrDestOpt()
         / TCP(sport=40001, dport=502, seq=1, flags="PA") / Raw(_modbus_read(7)))
    reply = (Ether(src=B_MAC, dst=A_MAC) / IPv6(src=B6, dst=A6)
             / TCP(sport=502, dport=40001, seq=1, flags="PA")
             / Raw(b"\x00\x07\x00\x00\x00\x17\x01\x03\x14" + bytes(20)))
    stats = ingest_pcap(_write(tmp_path, [p, reply]), db)

    assert stats["ipv6_packets"] == 2 and stats["ipv6_packets_skipped"] == 0
    assert stats["ipv6_extension_headers"] == 4
    assert stats["packets"] == 2
    a = db.query(Host).filter(Host.ip == A6).one()
    b = db.query(Host).filter(Host.ip == B6).one()
    assert (a.mac, b.mac) == (A_MAC, B_MAC)
    sess = db.query(NetworkSession).one()
    assert sess.transport == "tcp" and sess.protocol == "modbus" and sess.packet_count == 2
    details = db.query(ProtocolDetail).order_by(ProtocolDetail.id).all()
    assert [d.direction for d in details] == ["request", "response"]
    assert stats["protocol_frames"]["modbus"] == 2


def test_ipv6_fragmented_tcp_is_reassembled(db, tmp_path):
    big = _modbus_write_regs(1, 100)                         # 213-byte ADU
    pkt = (Ether(src=A_MAC, dst=B_MAC) / IPv6(src=A6, dst=B6) / IPv6ExtHdrFragment(id=0x77)
           / TCP(sport=40002, dport=502, seq=1, flags="PA") / Raw(big))
    frags = fragment6(pkt, 120)
    assert len(frags) > 1
    stats = ingest_pcap(_write(tmp_path, list(reversed(frags))), db)
    assert stats["ipv6_fragments"] == len(frags)
    assert stats["ipv6_datagrams_reassembled"] == 1
    d = db.query(ProtocolDetail).one()
    assert d.summary == "write_multiple_registers" or d.fields.get("function_code") == 16
    assert db.query(NetworkSession).one().packet_count == 1


def test_ipv6_udp_enip_and_icmpv6_sessions(db, tmp_path):
    list_identity = b"\x63\x00" + b"\x00" * 22
    pkts = [
        Ether(src=A_MAC, dst=B_MAC) / IPv6(src=A6, dst=B6) / UDP(sport=44818, dport=44818)
        / Raw(list_identity),
        Ether(src=A_MAC, dst=B_MAC) / IPv6(src=A6, dst=B6) / ICMPv6EchoRequest(),
    ]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    transports = sorted(s.transport for s in db.query(NetworkSession).all())
    assert transports == ["icmpv6", "udp"]
    assert stats["protocol_frames"]["ethernet_ip"] == 1
    assert stats["icmpv6_packets"] == 1


def test_ipv6_multicast_counted_without_group_hosts(db, tmp_path):
    pkts = [Ether(src=A_MAC, dst="33:33:00:00:00:01") / IPv6(src="fe80::a", dst="ff02::1")
            / UDP(sport=5353, dport=5353) for _ in range(3)]
    pkts.append(Ether(src=A_MAC, dst="33:33:00:01:00:02") / IPv6(src="fe80::a", dst="ff02::1:2")
                / UDP(sport=546, dport=547))
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["ipv6_multicast_packets"] == 4
    assert stats["ipv6_multicast_groups"] == {"ff02::1": 3, "ff02::1:2": 1}
    assert db.query(Host).filter(Host.ip.like("ff%")).count() == 0
    assert db.query(Host).filter(Host.mac.like("33:33%")).count() == 0
    assert db.query(Host).one().ip == "fe80::a"             # the sender is real
    assert db.query(NetworkSession).count() == 0


def test_ndp_teaches_ip_mac_bindings(db, tmp_path):
    ns = (Ether(src=A_MAC, dst="33:33:ff:00:00:0b") / IPv6(src=A6, dst="ff02::1:ff00:b")
          / ICMPv6ND_NS(tgt=B6) / ICMPv6NDOptSrcLLAddr(lladdr=A_MAC))
    na = (Ether(src=B_MAC, dst=A_MAC) / IPv6(src=B6, dst=A6)
          / ICMPv6ND_NA(tgt=B6, R=0, S=1, O=1) / ICMPv6NDOptDstLLAddr(lladdr=B_MAC))
    dad = (Ether(src="00:0e:8c:00:00:0c", dst="33:33:ff:00:00:0c")
           / IPv6(src="::", dst="ff02::1:ff00:c") / ICMPv6ND_NS(tgt="2001:db8:1::c"))
    stats = ingest_pcap(_write(tmp_path, [ns, na, dad]), db)
    assert stats["ndp_packets"] == 3
    assert stats["ndp_bindings"] == 2
    b = db.query(Host).filter(Host.ip == B6).one()
    assert b.mac == B_MAC and "ndp" in b.sources
    assert db.query(Host).filter(Host.ip == A6).one().mac == A_MAC
    assert db.query(Host).filter(Host.ip == "::").count() == 0
    assert db.query(NetworkSession).count() == 0            # NDP is link noise


def test_ipv6_router_mac_not_given_to_remote_hosts(db, tmp_path):
    rtr, plc = "00:00:5e:00:02:01", "00:1b:1b:00:00:10"
    ra = (Ether(src=rtr, dst="33:33:00:00:00:01") / IPv6(src="fe80::1", dst="ff02::1")
          / ICMPv6ND_RA() / ICMPv6NDOptSrcLLAddr(lladdr=rtr))
    pkts = [ra]
    for i, remote in enumerate(["2001:db8:99::5", "2001:db8:77::6"]):
        pkts.append(Ether(src=rtr, dst=plc) / IPv6(src=remote, dst="2001:db8:1::10")
                    / TCP(sport=41000 + i, dport=502, seq=1, flags="PA") / Raw(_modbus_read(i)))
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert rtr in stats["gateway_macs"]
    for remote in ["2001:db8:99::5", "2001:db8:77::6"]:
        assert db.query(Host).filter(Host.ip == remote).one().mac is None
    assert db.query(Host).filter(Host.ip == "fe80::1").one().mac == rtr
    assert db.query(Host).filter(Host.ip == "2001:db8:1::10").one().mac == plc


# ------------------------------------------------------------------ F-12 ----

def test_fragmented_ipv4_modbus_reassembled_out_of_order(db, tmp_path):
    big = _modbus_write_regs(9, 110)
    pkt = (Ether(src=A_MAC, dst=B_MAC) / IP(src="10.0.1.5", dst="10.0.1.10", id=4242)
           / TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(big))
    frags = [Ether(src=A_MAC, dst=B_MAC) / f for f in fragment(pkt[IP], fragsize=64)]
    assert len(frags) >= 4
    order = [frags[2], frags[0], frags[-1]] + frags[3:-1] + [frags[1]]
    stats = ingest_pcap(_write(tmp_path, order), db)
    assert stats["ipv4_fragments"] == len(frags)
    assert stats["ipv4_datagrams_reassembled"] == 1
    assert stats["ipv4_fragments_dropped"] == 0
    assert stats["protocol_frames"]["modbus"] == 1
    d = db.query(ProtocolDetail).one()
    assert d.fields["function_code"] == 16
    sess = db.query(NetworkSession).one()
    assert sess.packet_count == 1
    assert sess.byte_count == sum(len(f) for f in frags)


def test_incomplete_and_timed_out_fragments_are_dropped(db, tmp_path):
    big = _modbus_write_regs(1, 100)
    p1 = IP(src="10.0.1.5", dst="10.0.1.10", id=1) / TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(big)
    p2 = IP(src="10.0.1.5", dst="10.0.1.10", id=2) / TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(big)
    f1 = [Ether(src=A_MAC, dst=B_MAC) / f for f in fragment(p1, fragsize=80)]
    f2 = [Ether(src=A_MAC, dst=B_MAC) / f for f in fragment(p2, fragsize=80)]
    pkts = f1[:-1] + f2[:1]                       # datagram 1 never completes
    for i, p in enumerate(pkts):
        p.time, p._t_set = T0 + i, True
    late = f2[1:]
    for p in late:                                # rest of datagram 2: 60 s later
        p.time, p._t_set = T0 + 100, True
    stats = ingest_pcap(_write(tmp_path, pkts + late), db)
    assert stats["ipv4_datagrams_reassembled"] == 0
    assert stats["ipv4_fragments_dropped"] == len(pkts) + len(late)
    assert db.query(ProtocolDetail).count() == 0


def _dnp3_link_frame(user: bytes, src=1, dst=10) -> bytes:
    hdr = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
    out = hdr + dnp3_crc(hdr).to_bytes(2, "little")
    for i in range(0, len(user), 16):
        chunk = user[i:i + 16]
        out += chunk + dnp3_crc(chunk).to_bytes(2, "little")
    return out


def _dnp3_segments(app: bytes, seq0: int = 5, size: int = 249) -> list:
    parts = [app[i:i + size] for i in range(0, len(app), size)]
    frames = []
    for i, part in enumerate(parts):
        th = ((seq0 + i) % 64) | (0x40 if i == 0 else 0) | (0x80 if i == len(parts) - 1 else 0)
        frames.append(_dnp3_link_frame(bytes([th]) + part))
    return frames


def _dnp3_big_response() -> bytes:
    # Response: 0x81, IIN, g30v1 start-stop 0..99 (100 x 5 bytes = 500 bytes)
    objs = bytes([30, 1, 0x00, 0, 99]) + b"".join(
        i.to_bytes(4, "little", signed=True) + b"\x01" for i in range(100))
    return bytes([0xC3, 0x81, 0x00, 0x00]) + objs


def test_dnp3_transport_reassembly_across_tcp_segments(db, tmp_path):
    app = _dnp3_big_response()
    frames = _dnp3_segments(app)
    assert len(frames) == 3
    pkts, seq = [], 1
    for fr in frames:
        pkts.append(Ether(src=B_MAC, dst=A_MAC) / IP(src="10.0.1.10", dst="10.0.1.5")
                    / TCP(sport=20000, dport=40100, seq=seq, flags="PA") / Raw(fr))
        seq += len(fr)
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["dnp3_transport_segments"] == 3
    assert stats["dnp3_fragments_reassembled"] == 1
    assert stats["protocol_frames"]["dnp3"] == 1
    d = db.query(ProtocolDetail).one()
    assert d.summary == "response"
    assert d.fields["transport"]["segments"] == 3
    obj = d.fields["fields"]["objects"][0]
    assert (obj["group"], obj["variation"]) == (30, 1)
    assert len(obj["points"]) == 100 and obj["points"][-1]["index"] == 99


def test_dnp3_reassembler_drops_out_of_sequence_segment():
    stats = {}
    r = Dnp3TransportReassembler(stats)
    f1, f2, f3 = _dnp3_segments(_dnp3_big_response())
    assert r.feed(f1) is None
    assert r.feed(f3) is None                  # f2 lost: sequence gap
    assert r.feed(f2) is None                  # no fragment in progress any more
    assert stats["dnp3_fragments_reassembled"] == 0
    assert stats["dnp3_transport_segments_dropped"] == 3
    single = _dnp3_link_frame(bytes([0xC0, 0xC0, 0x01]))      # FIR|FIN read request
    assert r.feed(single)["summary"] == "read"
    # a new FIR abandons an unfinished fragment
    assert r.feed(f1) is None
    assert r.feed(single)["summary"] == "read"
    assert stats["dnp3_transport_segments_dropped"] == 4


# ------------------------------------------------------------------ F-13 ----

def test_details_bulk_inserted_in_batches(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_parser, "DETAIL_BATCH_SIZE", 7)
    pkts = [Ether(src=A_MAC, dst=B_MAC) / IP(src="10.0.1.5", dst="10.0.1.10")
            / TCP(sport=40000, dport=502, seq=1 + 12 * i, flags="PA") / Raw(_modbus_read(i))
            for i in range(50)]
    stats = ingest_pcap(_write(tmp_path, pkts), db)
    assert stats["protocol_frames"]["modbus"] == 50
    rows = db.query(ProtocolDetail).all()
    assert len(rows) == 50
    sess = db.query(NetworkSession).one()
    assert {r.session_id for r in rows} == {sess.id}
    assert all(r.timestamp is not None and r.fields["transaction_id"] is not None for r in rows)


@pytest.mark.parametrize("linktype", [101, 0, 113])
def test_non_ethernet_link_types(db, tmp_path, linktype):
    from scapy.all import CookedLinux, Loopback
    tcp = TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(_modbus_read(1))
    ip = IP(src="10.0.1.5", dst="10.0.1.10") / tcp
    if linktype == 101:
        pkt = ip
    elif linktype == 0:
        pkt = Loopback(type=2) / ip
    else:
        pkt = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6,
                          src=bytes.fromhex("001b1b00000a") + b"\x00\x00", proto=0x0800) / ip
    pkt.time = T0
    path = str(tmp_path / f"lt{linktype}.pcap")
    wrpcap(path, [pkt], linktype=linktype)
    stats = ingest_pcap(path, db)
    assert stats["packets"] == 1 and stats["protocol_frames"]["modbus"] == 1
    assert db.query(Host).count() == 2


def test_pcapng_and_ethernet_padding(db, tmp_path):
    from scapy.utils import PcapNgWriter
    # short ARP-sized frame padded to 60 bytes must not leak padding into L4
    p = (Ether(src=A_MAC, dst=B_MAC) / IP(src="10.0.1.5", dst="10.0.1.10")
         / UDP(sport=44818, dport=44818) / Raw(b"\x63\x00" + b"\x00" * 22))
    raw = bytes(p) + b"\xee" * 10
    padded = Ether(raw)
    padded.time = T0 + 0.25
    path = str(tmp_path / "x.pcapng")
    w = PcapNgWriter(path)
    w.write(padded)
    w.close()
    stats = ingest_pcap(path, db)
    assert stats["protocol_frames"]["ethernet_ip"] == 1
    sess = db.query(NetworkSession).one()
    assert sess.first_seen.timestamp() == pytest.approx(T0 + 0.25, abs=1e-3)


# ------------------------------------------------------------------ F-16 ----

@pytest.mark.parametrize("raw", [
    "0011.2233.4455", "00-11-22-33-44-55", "001122334455", "00:11:22:33:44:55",
    "0:11:22:33:44:55", "001122-334455", "00 11 22 33 44 55", " 0011.2233.4455 ",
    "00:11:22:33:44:55".upper(),
])
def test_normalize_mac_accepts_all_notations(raw):
    assert normalize_mac(raw) == "00:11:22:33:44:55"


@pytest.mark.parametrize("raw", ["", "0011.2233.44", "zz:11:22:33:44:55", "0011223344556",
                                 "00:11:22:33:44"])
def test_normalize_mac_rejects_garbage(raw):
    assert normalize_mac(raw) is None


def test_mac_kind_and_vendor_markers():
    assert mac_kind("00:1b:1b:00:00:01") == "universal"
    assert mac_kind("02:1b:1b:00:00:01") == "locally_administered"
    assert mac_kind("DA-A1-19-00-00-01") == "locally_administered"   # randomised phone MAC
    assert mac_kind("01:00:5e:00:00:01") == "multicast"
    assert mac_kind("ff:ff:ff:ff:ff:ff") == "multicast"
    assert mac_kind("nonsense") is None

    siemens = lookup_vendor_info("001b.1b00.0001")
    assert siemens["mac_kind"] == "universal" and siemens["vendor"].startswith("Siemens")
    # Same OUI digits with the U/L bit set: no (misleading) vendor
    assert lookup_vendor_info("02:1b:1b:00:00:01") == {"vendor": None,
                                                      "mac_kind": "locally_administered"}
    assert lookup_vendor_info("01:00:5e:00:00:01") == {"vendor": None, "mac_kind": "multicast"}
    assert lookup_vendor("02:1b:1b:00:00:01") is None


def test_custom_manuf_file_ignored_for_local_macs(tmp_path, monkeypatch):
    from app.parsers import common
    manuf = tmp_path / "manuf"
    manuf.write_text("02:1B:1B\tFake\tFake Vendor\n00:1B:1B\tReal\tReal Vendor\n")
    monkeypatch.setenv("IACS_MANUF_FILE", str(manuf))
    monkeypatch.setattr(common, "_manuf_db", None)
    monkeypatch.setattr(common, "_manuf_db_load_attempted", False)
    assert lookup_vendor("00:1b:1b:00:00:01") == "Real Vendor"
    assert lookup_vendor("02:1b:1b:00:00:01") is None


def test_pcap_host_with_randomised_mac_has_no_vendor(db, tmp_path):
    p = (Ether(src="da:a1:19:00:00:01", dst=B_MAC) / IP(src="10.0.1.5", dst="10.0.1.10")
         / TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(_modbus_read(1)))
    ingest_pcap(_write(tmp_path, [p]), db)
    assert db.query(Host).filter(Host.ip == "10.0.1.5").one().vendor is None
    assert db.query(Host).filter(Host.ip == "10.0.1.10").one().vendor.startswith("Siemens")
