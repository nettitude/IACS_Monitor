"""N-24 (vendor-hint mismatch, MAC VLAN names) and N-26 (DNP3/UDP, IPv4
multicast/broadcast hosts)."""
from pathlib import Path

import pytest
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, MacTableEntry, NetworkSession, ProtocolDetail, Site, SwitchVlan
from app.parsers.mac_table_parser import ingest_mac_table, _lookup_vlan_name
from app.parsers.pcap_parser import dnp3_crc, ingest_pcap
from app.parsers.switch_parser import (
    VendorMismatchError, detect_switch_vendor, ingest_switch_config,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


HP_CFG = (SAMPLES / "sample_switch_hp_running_config.txt").read_text()
CISCO_CFG = (SAMPLES / "sample_switch_running_config.txt").read_text()


# ------------------------------------------------------------- N-24 (a) ---

def test_hp_config_with_cisco_hint_rejected(db):
    assert detect_switch_vendor(HP_CFG) == "hp"
    with pytest.raises(VendorMismatchError) as e:
        ingest_switch_config(HP_CFG, db, vendor_hint="cisco")
    assert "hp" in str(e.value) and "Cisco" not in str(e.value).split("looks like")[0]
    assert db.query(SwitchVlan).count() == 0


def test_cisco_config_with_hp_hint_rejected(db):
    assert detect_switch_vendor(CISCO_CFG) == "cisco"
    with pytest.raises(VendorMismatchError):
        ingest_switch_config(CISCO_CFG, db, vendor_hint="hp")


def test_matching_and_absent_hint_still_parse(db):
    assert ingest_switch_config(HP_CFG, db, vendor_hint="hp")["config_type"] == "hp_running_config"
    assert ingest_switch_config(CISCO_CFG, db, vendor_hint="cisco")["config_type"] == "running_config"
    assert ingest_switch_config(HP_CFG, db)["config_type"] == "hp_running_config"


def test_api_switch_and_mac_mismatch_422(tmp_path):
    from tests.test_cov_routes import _api, up
    with _api(tmp_path / "n24.db") as c:
        r = up(c, "/ingest/switch", "hp.txt", {"vendor_hint": "cisco"}, content=HP_CFG.encode())
        assert r.status_code == 422 and "vendor_hint='cisco'" in r.json()["detail"] and "hp" in r.json()["detail"]
        r = up(c, "/ingest/mac-table", "sample_mac_table_hp.txt", {"vendor_hint": "cisco"})
        assert r.status_code == 422 and "looks like HP" in r.json()["detail"]
        r = up(c, "/ingest/mac-table", "sample_mac_table_cisco.txt", {"vendor_hint": "hp"})
        assert r.status_code == 422 and "looks like Cisco" in r.json()["detail"]
        assert up(c, "/ingest/mac-table", "sample_mac_table_hp.txt", {"vendor_hint": "hp"}).status_code == 200


# ------------------------------------------------------------- N-24 (b) ---

def _site(db, name):
    s = Site(name=name, code=name.lower())
    db.add(s)
    db.commit()
    return s


def test_mac_rows_resolve_vlan_names_same_site_only(db):
    a, b = _site(db, "SiteA"), _site(db, "SiteB")
    db.add_all([SwitchVlan(site_id=a.id, device_name="SW1", vlan_id=10, vlan_name="ENG_A"),
                SwitchVlan(site_id=b.id, device_name="SW1", vlan_id=10, vlan_name="OTHER_B"),
                SwitchVlan(site_id=b.id, device_name="SW1", vlan_id=30, vlan_name="ONLY_B")])
    db.commit()
    table = (" 10  0011.2233.4455  DYNAMIC  Gi1/0/1\n"
             " 30  aabb.ccdd.eeff  DYNAMIC  Gi1/0/2\n")
    stats = ingest_mac_table(table, db, device_name="SW1", site_id=a.id)
    assert stats["vlan_names"] == {"10": "ENG_A"}          # B's names never leak into A
    by_vlan = {e["vlan"]: e["vlan_name"] for e in stats["entries"]}
    assert by_vlan == {"10": "ENG_A", "30": None}
    assert db.query(MacTableEntry).count() == 2


# ------------------------------------------------------------------ N-26 ---

A, B = "00:1b:1b:00:00:0a", "00:0e:8c:00:00:0b"


def _pcap(tmp_path, pkts):
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i * 0.001
    path = str(tmp_path / "t.pcap")
    wrpcap(path, pkts)
    return path


def _link(user: bytes, src=1, dst=10) -> bytes:
    hdr = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
    out = hdr + dnp3_crc(hdr).to_bytes(2, "little")
    for i in range(0, len(user), 16):
        ch = user[i:i + 16]
        out += ch + dnp3_crc(ch).to_bytes(2, "little")
    return out


def _udp_pkt(payload, sport=40000, dport=20000, src="10.0.0.1", dst="10.0.0.2",
             smac=A, dmac=B):
    return Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)


def test_dnp3_over_udp_dispatched(db, tmp_path):
    read = _link(bytes([0xC0, 0xC1, 0x01, 30, 1, 0x00, 0, 3]))   # FIR|FIN, app read g30v1
    long_user = bytes([0xC0, 0xC2, 0x02, 12, 1, 0x28, 1, 0, 0, 0, 0x41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    two = _link(long_user) + _link(bytes([0xC0, 0xC3, 0x01, 60, 1, 0x06]))   # 2 frames in one datagram
    pkts = [_udp_pkt(read), _udp_pkt(two),
            _udp_pkt(b"\x05\x64\x20"),                     # truncated link header
            _udp_pkt(b"\x05\x64\x10\xc4\x0a\x00\x01\x00\x00\x00\x01"),  # truncated frame
            _udp_pkt(b"garbage-not-dnp3"),
            _udp_pkt(read[:-1] + b"\x00" * 40)]            # trailing junk
    stats = ingest_pcap(_pcap(tmp_path, pkts), db)
    assert stats["analyzer_errors"] == 0
    assert stats["protocol_frames"]["dnp3"] >= 3
    sess = db.query(NetworkSession).one()
    assert sess.transport == "udp" and sess.protocol == "dnp3" and sess.dst_port == 20000
    details = db.query(ProtocolDetail).filter_by(protocol="dnp3").all()
    assert len(details) == stats["protocol_frames"]["dnp3"]
    assert any(d.summary == "read" for d in details)
    assert any(d.fields.get("operation") == "write" for d in details)
    assert stats["dnp3_udp_malformed"] >= 3


def test_dnp3_udp_and_tcp_both_dispatched(db, tmp_path):
    from scapy.all import TCP
    read = _link(bytes([0xC0, 0xC1, 0x01, 30, 1, 0x00, 0, 3]))
    tcp = (Ether(src=A, dst=B) / IP(src="10.0.0.1", dst="10.0.0.2")
           / TCP(sport=40001, dport=20000, flags="PA", seq=1) / Raw(read))
    stats = ingest_pcap(_pcap(tmp_path, [_udp_pkt(read), tcp]), db)
    assert stats["protocol_frames"]["dnp3"] == 2
    assert sorted(s.transport for s in db.query(NetworkSession).all()) == ["tcp", "udp"]


def test_ipv4_multicast_broadcast_create_no_hosts(db, tmp_path):
    pkts = [
        _udp_pkt(b"x" * 20, 5353, 5353, "10.0.0.1", "224.0.0.251", A, "01:00:5e:00:00:fb"),
        _udp_pkt(b"x" * 20, 319, 319, "10.0.0.1", "224.0.1.129", A, "01:00:5e:00:01:81"),
        _udp_pkt(b"x" * 20, 68, 67, "0.0.0.0", "255.255.255.255", "00:aa:00:00:00:09", "ff:ff:ff:ff:ff:ff"),
        _udp_pkt(b"x" * 20, 68, 67, "10.0.0.7", "255.255.255.255", "00:aa:00:00:00:07", "ff:ff:ff:ff:ff:ff"),
        _udp_pkt(b"x" * 20, 5000, 5001, "10.0.0.1", "10.0.0.2"),     # ordinary unicast
    ]
    stats = ingest_pcap(_pcap(tmp_path, pkts), db)
    ips = {h.ip for h in db.query(Host).all()}
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.7"}
    assert not any(i and (i.startswith("224.") or i.startswith("255.") or i == "0.0.0.0") for i in ips)
    macs = {h.mac for h in db.query(Host).all()}
    assert "ff:ff:ff:ff:ff:ff" not in macs and "01:00:5e:00:00:fb" not in macs
    assert "00:aa:00:00:00:09" not in macs               # 0.0.0.0 source: no host
    assert stats["ipv4_multicast_groups"] == {"224.0.0.251": 1, "224.0.1.129": 1}
    assert stats["ipv4_broadcast_packets"] == 1          # the 0.0.0.0 one is dropped
    # IO-07: the unicast UDP request got no reply - a connection attempt
    assert db.query(NetworkSession).count() == 0
    assert stats["connection_attempts"].get("unanswered") == 1


def test_multicast_enip_still_counted(db, tmp_path):
    list_identity = b"\x63\x00" + b"\x00" * 22
    pkts = [_udp_pkt(list_identity, 44818, 44818, "10.0.0.1", "239.192.1.1", A, "01:00:5e:40:01:01")]
    stats = ingest_pcap(_pcap(tmp_path, pkts), db)
    assert stats["protocol_frames"]["ethernet_ip"] == 1
    assert db.query(Host).filter(Host.ip.like("239.%")).count() == 0
