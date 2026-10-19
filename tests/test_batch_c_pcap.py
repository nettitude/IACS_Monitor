"""
Batch C of the Evidence Automation Matrix gap analysis (owner 2026-10-15, "do batch c"):
PCAP evidence - default credentials (kind only, never the secret), weak TLS / SSH
versions, service banners and device identities (CIP ListIdentity, S7 SZL) into the
inventory, transient IT devices on control networks.  The reviews are covered in
tests/test_cov_alert_engine.py.
"""
import base64
import struct

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Host, NetworkSession, ObservedName, ProtocolDetail, Site
from app.parsers import pcap_parser as pp
from app.parsers.enip_cip_analyzer import parse_enip
from app.parsers.s7comm_analyzer import parse_s7comm
from app.parsers.site_scope import ingest_site
from tests.test_pcap_parser import _eth_ip_tcp_packet, _write_pcap


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'c.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Site(name="C", code="c"))
    s.commit()
    yield s
    s.close()
    engine.dispose()


def _mac(ip):
    """One stable MAC per address, so both directions of a conversation see the same two hosts."""
    return "00:11:22:33:44:%02x" % int(ip.rsplit(".", 1)[1])


def _udp_packet(src_ip, dst_ip, sport, dport, payload):
    from scapy.all import Ether, IP, UDP, Raw
    return bytes(Ether(src=_mac(src_ip), dst=_mac(dst_ip)) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload))


def _tcp(src, dst, sport, dport, payload, flags="PA"):
    from scapy.all import Ether, IP, TCP, Raw
    return bytes(Ether(src=_mac(src), dst=_mac(dst)) / IP(src=src, dst=dst)
                 / TCP(sport=sport, dport=dport, flags=flags) / Raw(load=payload))


# ------------------------------------------------------------ pure helpers --

def test_default_pairs_and_stream_detection():
    assert pp._is_default_pair("admin", "admin") and pp._is_default_pair("root", "") and pp._is_default_pair("Operator", "operator")
    assert not pp._is_default_pair("jsmith", "admin") and not pp._is_default_pair("admin", "Tr0ub4dor&3")
    tr = {}
    assert pp._default_credentials(b"USER admin\r\n", 40000, 21, tr) is None and tr["ct_user_default"] is True
    assert "admin" not in str(tr.values())                                   # the name is never kept verbatim
    assert pp._default_credentials(b"PASS admin\r\n", 40000, 21, tr) == "default credentials (FTP)"
    tr2 = {}
    pp._default_credentials(b"USER jsmith\r\n", 40000, 21, tr2)
    assert pp._default_credentials(b"PASS admin\r\n", 40000, 21, tr2) is None
    tok = base64.b64encode(b"admin:password").decode()
    assert pp._default_credentials(f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {tok}\r\n\r\n".encode(), 40000, 80, {}) \
        == "default credentials (HTTP Basic)"
    tok = base64.b64encode(b"\x00root\x00root").decode()
    assert pp._default_credentials(f"AUTH PLAIN {tok}\r\n".encode(), 40000, 25, {}) == "default credentials (SMTP)"
    assert pp._weak_transport(b"\x16\x03\x01\x00\x2a\x02\x00\x00\x26\x03\x01" + b"\x00" * 38) == "TLSv1.0"
    assert pp._weak_transport(b"\x16\x03\x03\x00\x2a\x02\x00\x00\x26\x03\x03" + b"\x00" * 38) is None
    assert pp._weak_transport(b"SSH-1.5-OpenSSH_2\r\n", 22) == "SSH-1" and pp._weak_transport(b"SSH-2.0-OpenSSH_9\r\n", 22) is None
    assert pp._weak_transport(b"SSH-1.5-PuTTY\r\n", 40000) is None            # a client banner is not the server's
    assert pp._weak_transport(b"SSH-1.99-Cisco-1.25\r\n", 22) is None          # SSH-2 with v1 compatibility
    assert not pp._is_default_pair("jsmith", "jsmith") and not pp._is_default_pair("anonymous", "anonymous")
    snmp_public = bytes.fromhex("302602010004067075626c6963a0190204" + "00" * 4 + "020100020100300b300906052b060102010500")
    assert pp._snmp_community(snmp_public) == "SNMPv1/v2c community (default)"
    snmp_other = snmp_public.replace(b"\x06public", b"\x06s3cr3t")
    assert pp._snmp_community(snmp_other) == "SNMPv1/v2c community"


def _list_identity_reply(name=b"1756-L73/B LOGIX5573"):
    item = (struct.pack("<H", 1) + b"\x00" * 16 + struct.pack("<HHH", 1, 14, 0x5A)   # encap ver, sockaddr, vendor, type, code
            + bytes([31, 11]) + struct.pack("<H", 0x30) + struct.pack("<I", 0x00C0FFEE)
            + bytes([len(name)]) + name + b"\x03")
    cpf = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(item)) + item
    hdr = struct.pack("<HHIIQI", 0x0063, len(cpf), 0, 0, 0, 0)
    return hdr + cpf


def test_cip_list_identity_reply_parsed():
    d = parse_enip(_list_identity_reply())
    assert d["identity"]["product_name"] == "1756-L73/B LOGIX5573" and d["identity"]["revision"] == "31.011"
    assert d["identity"]["vendor_id"] == 1 and d["identity"]["serial_number"] == "00c0ffee" and d["direction"] == "response"
    assert parse_enip(struct.pack("<HHIIQI", 0x0063, 0, 0, 0, 0, 0)).get("identity") is None   # the request


def _szl_response(szl_id, entries, entry_len):
    param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
    body = b"".join(entries)
    data = bytes([0xFF, 0x09]) + struct.pack(">H", 8 + len(body)) + struct.pack(">HHHH", szl_id, 0, entry_len, len(entries)) + body
    s7 = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">HH", len(param), len(data)) + param + data
    tpkt = b"\x03\x00" + struct.pack(">H", 4 + 3 + len(s7)) + b"\x02\xf0\x80" + s7
    return tpkt


def test_s7_szl_identity_parsed():
    # Siemens layout: Ausbg = 'V' (0x56) + major, Ausbe = minor.patch -> V3.2.6
    e1 = struct.pack(">H", 1) + b"6ES7 315-2EH14-0AB0 ".ljust(20)[:20] + struct.pack(">HHH", 0, 0x5601, 0x0000)
    e6 = struct.pack(">H", 6) + b"6ES7 315-2EH14-0AB0 ".ljust(20)[:20] + struct.pack(">HHH", 0, 0x5603, 0x0206)
    d = parse_s7comm(_szl_response(0x0011, [e1, e6], 28))
    assert d["identity"]["order_number"] == "6ES7 315-2EH14-0AB0" and d["identity"]["firmware_version"] == "V3.2.6"
    assert d["direction"] == "response"
    n1 = struct.pack(">H", 1) + b"PLC_LINE_3".ljust(32, b"\x00")
    n2 = struct.pack(">H", 2) + b"CPU 315-2 PN/DP".ljust(32, b"\x00")
    n5 = struct.pack(">H", 5) + b"S C-X1Y2Z3".ljust(32, b"\x00")
    d = parse_s7comm(_szl_response(0x001C, [n1, n2, n5], 34))
    assert d["identity"]["plc_name"] == "PLC_LINE_3" and d["identity"]["module_name"] == "CPU 315-2 PN/DP"
    assert d["identity"]["serial_number"] == "S C-X1Y2Z3" and d["summary"] == "read_szl_0x001c"


# ---------------------------------------------------------------- ingest --

def test_pcap_evidence_lands_on_sessions_and_hosts(db, tmp_path):
    pkts = [
        # FTP with default credentials (client 10.1.0.20 -> server 10.1.0.5)
        _tcp("10.1.0.20", "10.1.0.5", 40001, 21, b"USER admin\r\n"),
        _tcp("10.1.0.20", "10.1.0.5", 40001, 21, b"PASS admin\r\n"),
        # TLS 1.0 ServerHello from 10.1.0.6:443 + an HTTP Server banner + SSH-1 banner
        _tcp("10.1.0.20", "10.1.0.6", 40002, 443, b"\x16\x03\x01\x00\x80\x01" + b"\x00" * 100),
        _tcp("10.1.0.6", "10.1.0.20", 443, 40002, b"\x16\x03\x01\x00\x2a\x02\x00\x00\x26\x03\x01" + b"\x00" * 38),
        _tcp("10.1.0.7", "10.1.0.20", 80, 40003, b"HTTP/1.1 200 OK\r\nServer: GoAhead-Webs/2.5 PLC-WEB\r\n\r\n"),
        _tcp("10.1.0.8", "10.1.0.20", 22, 40004, b"SSH-1.5-OpenSSH_2.9\r\n"),
        # SNMP with the default community to 10.1.0.9
        _udp_packet("10.1.0.20", "10.1.0.9", 40005, 161,
                    bytes.fromhex("302602010004067075626c6963a0190204" + "00" * 4 + "020100020100300b300906052b060102010500")),
        # the agent answers (an unanswered UDP packet is a connection attempt, not a session)
        _udp_packet("10.1.0.9", "10.1.0.20", 161, 40005,
                    bytes.fromhex("302602010004067075626c6963a2190204" + "00" * 4 + "020100020100300b300906052b060102010500")),
        # CIP ListIdentity reply from 10.1.0.10 (UDP) and an S7 SZL response from 10.1.0.11 (TCP 102)
        _udp_packet("10.1.0.10", "10.1.0.20", 44818, 40006, _list_identity_reply()),
        _tcp("10.1.0.11", "10.1.0.20", 102, 40007, _szl_response(0x0011, [
            struct.pack(">H", 1) + b"6ES7 315-2EH14-0AB0 "[:20] + struct.pack(">HHH", 0, 0x5601, 0x0000),
            struct.pack(">H", 6) + b"6ES7 315-2EH14-0AB0 "[:20] + struct.pack(">HHH", 0, 0x5603, 0x0206)], 28)),
        # audit: RSLinx-style scan from port 44818 - the identity belongs to the sender, not the port
        _udp_packet("10.1.0.20", "10.1.0.12", 44818, 44818, struct.pack("<HHIIQI", 0x0063, 0, 0, 0, 0, 0)),
        _udp_packet("10.1.0.12", "10.1.0.20", 44818, 44818, _list_identity_reply(b"1769-L33ER/A")),
        # audit: a "Server:" inside a response body is not a banner
        _tcp("10.1.0.13", "10.1.0.20", 80, 40008, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: fake-from-body\r\n"),
    ]
    path = tmp_path / "c.pcap"
    _write_pcap(pkts, str(path))
    with ingest_site(db, 1):
        stats = pp.ingest_pcap(str(path), db)
    assert stats.get("cleartext_logins", 0) >= 2 and stats.get("weak_transport_sessions") == 2
    assert stats.get("device_identities") == 3
    auth = {(db.get(Host, s.dst_host_id).ip, s.dst_port): s.cleartext_auth for s in db.query(NetworkSession) if s.cleartext_auth}
    assert "default credentials (FTP)" in auth[("10.1.0.5", 21)] and "FTP login" in auth[("10.1.0.5", 21)]
    assert auth[("10.1.0.9", 161)] == "SNMPv1/v2c community (default)"
    weak = {(d.fields["server_ip"], d.fields["server_port"]): d.fields["version"] for d in db.query(ProtocolDetail)
            if d.protocol in ("tls", "ssh")}
    assert weak == {("10.1.0.6", 443): "TLSv1.0", ("10.1.0.8", 22): "SSH-1"}
    names = {(n.ip, n.source): n.name for n in db.query(ObservedName)}
    assert names[("10.1.0.7", "http_server")] == "GoAhead-Webs/2.5 PLC-WEB"
    assert names[("10.1.0.10", "cip_identity")] == "1756-L73/B LOGIX5573 31.011"
    hosts = {h.ip: h for h in db.query(Host)}
    assert hosts["10.1.0.10"].model == "1756-L73/B LOGIX5573" and hosts["10.1.0.10"].firmware_version == "31.011"
    assert hosts["10.1.0.10"].serial_number == "00c0ffee"
    assert hosts["10.1.0.11"].model == "6ES7 315-2EH14-0AB0" and hosts["10.1.0.11"].firmware_version == "V3.2.6"
    assert hosts["10.1.0.12"].model == "1769-L33ER/A" and hosts["10.1.0.20"].model is None      # sender, not the scanner
    assert ("10.1.0.13", "http_server") not in names
    # the reviews pick it up
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, 1):
        dc = ae.review_default_credentials(db)
        wt = ae.review_weak_tls(db)
    assert sorted((f.detail["dst_ip"], f.detail["dst_port"]) for f in dc) == [("10.1.0.5", 21), ("10.1.0.9", 161)]
    assert sorted((f.detail["ip"], f.detail["dst_port"], f.severity) for f in wt) == [("10.1.0.6", 443, "medium"), ("10.1.0.8", 22, "medium")]
