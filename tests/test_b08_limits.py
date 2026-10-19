"""
B-08: DoS / resource limits on ingest.

1. Per-ingest FirewallRule row budget (IACS_MAX_RULE_ROWS_PER_INGEST) across
   every vendor config parser - over budget the upload is rejected (413) and
   nothing is stored; the budget is charged before rows are materialised.
2. Compressed / non-capture pcap uploads are refused (415) and scapy is never
   allowed to gunzip a capture itself.
3. Per-pcap caps (IACS_PCAP_MAX_PACKETS / _NEW_HOSTS / _SESSIONS / _SECONDS):
   processing stops, what was processed is committed, the response says
   truncated + which limit + counts.
4. Text uploads: compressed -> 415; the size limit applies to bytes read.
"""
import bz2
import gzip
import io
import lzma
import struct
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, Raw, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.routes as routes_mod
import app.main as main_mod
from app.db import Base, get_db
from app.models import (
    Firewall, FirewallDevice, FirewallRule, Host, NatRule, NetworkSession, ProtocolDetail,
)
from app.parsers import firewall_parser as fp
from app.parsers import pcap_parser
from app.parsers.common import (
    IngestLimitExceeded, capture_format, compressed_format, rule_row_budget,
)
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.pcap_parser import UnsupportedCaptureError, ingest_pcap

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"


# --------------------------------------------------------------- fixtures --

@contextmanager
def _api(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("IACS_REVIEW_ENABLED", "false")
        mp.setattr(main_mod, "init_db", lambda: None)
        prev = main_mod.app.dependency_overrides.get(get_db)
        main_mod.app.dependency_overrides[get_db] = _get_db
        try:
            with TestClient(main_mod.app) as c:
                c.Session = Session
                yield c
        finally:
            if prev is None:
                main_mod.app.dependency_overrides.pop(get_db, None)
            else:
                main_mod.app.dependency_overrides[get_db] = prev
            engine.dispose()


@pytest.fixture
def client(tmp_path):
    with _api(tmp_path / "b08.db") as c:
        yield c


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _count(c, model):
    with c.Session() as s:
        return s.query(model).count()


def _post(c, url, name, data, params=None):
    return c.post(url, params={"site": "default", **(params or {})},
                  files={"file": (name, io.BytesIO(data))})


# ----------------------------------------------------------- generators --

def _forti_bomb(nsrc=150, ndst=150, npol=8) -> str:
    """Small config (~25 KB) whose policies expand to npol x nsrc x ndst rows."""
    lines = ["config firewall address"]
    for i in range(nsrc):
        lines += [f'    edit "s{i}"', f"        set subnet 10.1.{i // 250}.{i % 250 + 1} "
                  "255.255.255.255", "    next"]
    for i in range(ndst):
        lines += [f'    edit "d{i}"', f"        set subnet 10.2.{i // 250}.{i % 250 + 1} "
                  "255.255.255.255", "    next"]
    lines += ["end", "config firewall addrgrp",
              '    edit "GS"', "        set member " + " ".join(f'"s{i}"' for i in range(nsrc)),
              "    next",
              '    edit "GD"', "        set member " + " ".join(f'"d{i}"' for i in range(ndst)),
              "    next", "end", "config firewall policy"]
    for p in range(1, npol + 1):
        lines += [f"    edit {p}", f'        set name "p{p}"', '        set srcintf "port1"',
                  '        set dstintf "port2"', '        set srcaddr "GS"',
                  '        set dstaddr "GD"', "        set action accept",
                  '        set service "ALL"', "    next"]
    return "\n".join(lines + ["end", ""])


def _cisco_bomb(nsrc=40, ndst=40, naces=10) -> str:
    lines = ["object-group network SRC"] + [f" host 10.1.0.{i + 1}" for i in range(nsrc)]
    lines += ["object-group network DST"] + [f" host 10.2.0.{i + 1}" for i in range(ndst)]
    lines += ["ip access-list extended OT"]
    lines += [f" {10 * (k + 1)} permit tcp object-group SRC object-group DST eq {500 + k}"
              for k in range(naces)]
    return "\n".join(lines + [""])


def _pfsense_bomb(n=30, nrules=10) -> str:
    alias = lambda name, base: (f"<alias><name>{name}</name><type>host</type><address>"
                                + " ".join(f"{base}.{i + 1}" for i in range(n))
                                + "</address></alias>")
    rules = "".join(
        f"<rule><type>pass</type><interface>lan</interface><protocol>tcp/udp</protocol>"
        f"<source><address>SRCS</address></source><destination><address>DSTS</address>"
        f"<port>{500 + k}</port></destination><tracker>{k + 1}</tracker></rule>"
        for k in range(nrules))
    return (f"<?xml version=\"1.0\"?><pfsense><aliases>{alias('SRCS', '10.1.0')}"
            f"{alias('DSTS', '10.2.0')}</aliases><filter>{rules}</filter></pfsense>")


def _panos_bomb(n=30, nrules=10) -> str:
    addrs = "".join(f'<entry name="a{b}{i}"><ip-netmask>10.{b}.0.{i + 1}/32</ip-netmask></entry>'
                    for b in (1, 2) for i in range(n))
    groups = "".join(
        f'<entry name="G{b}"><static>' + "".join(f"<member>a{b}{i}</member>" for i in range(n))
        + "</static></entry>" for b in (1, 2))
    rules = "".join(
        f'<entry name="r{k}"><from><member>trust</member></from><to><member>untrust</member></to>'
        f"<source><member>G1</member></source><destination><member>G2</member></destination>"
        f"<service><member>any</member></service><application><member>any</member></application>"
        f"<action>allow</action></entry>" for k in range(nrules))
    return (f'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            f"<address>{addrs}</address><address-group>{groups}</address-group>"
            f"<rulebase><security><rules>{rules}</rules></security></rulebase>"
            f"</entry></vsys></entry></devices></config>")


MAC_SRV = "00:aa:bb:cc:dd:ee"


def _pkt(i, src=None, sport=None, payload=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"):
    p = (Ether(src="02:00:00:00:%02x:%02x" % (i >> 8 & 255, i & 255), dst=MAC_SRV)
         / IP(src=src or f"10.9.{i // 250}.{i % 250 + 1}", dst="10.0.0.1")
         / TCP(sport=sport or 40000 + i, dport=502, flags="PA", seq=1000) / Raw(payload))
    p.time = 1_700_000_000 + i * 0.01
    return p


def _pcap_bytes(tmp_path, pkts, name="t.pcap") -> bytes:
    path = tmp_path / name
    wrpcap(str(path), pkts)
    return path.read_bytes()


def _empty_record_pcap(n: int) -> bytes:
    """A 'pcap bomb': global header + n zero-length records."""
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1_700_000_000, 0, 0, 0)
    return hdr + rec * n


# ===================================================== 1. rule-row budget ==

def test_forti_bomb_rejected_413_nothing_stored(client):
    """The audit reproduction (a ~25 KB config) with DEFAULT limits."""
    text = _forti_bomb().encode()
    assert len(text) < 40_000
    r = _post(client, "/ingest/fortigate-config", "bomb.conf", text, {"firewall_name": "FW-B"})
    assert r.status_code == 413, r.text
    detail = r.json()["detail"]
    assert "IACS_MAX_RULE_ROWS_PER_INGEST" in detail and "100,000" in detail
    assert "nothing was stored" in detail
    for model in (FirewallRule, Firewall, FirewallDevice, NatRule, Host):
        assert _count(client, model) == 0, model.__name__


def test_forti_budget_charged_before_rows_built(db):
    """8 x 22,500 rows: rejected at the 5th policy (112,500), long before
    the 180,000-row product exists."""
    with pytest.raises(IngestLimitExceeded) as ei:
        ingest_fortigate_config(_forti_bomb(), db, firewall_name="X")
    assert ei.value.observed == 112_500 and ei.value.limit == 100_000
    assert ei.value.env_var == "IACS_MAX_RULE_ROWS_PER_INGEST"
    db.rollback()
    assert db.query(FirewallRule).count() == 0


def test_budget_env_override(db, monkeypatch):
    monkeypatch.setenv("IACS_MAX_RULE_ROWS_PER_INGEST", "300000")
    stats = ingest_fortigate_config(_forti_bomb(npol=8), db, firewall_name="X")
    assert stats["rules_created"] == 180_000 == db.query(FirewallRule).count()


@pytest.mark.parametrize("name,text,vendor", [
    ("cisco.txt", _cisco_bomb(), "cisco"),          # 10 x 1,600 rows
    ("pf.xml", _pfsense_bomb(), "pfsense"),         # 10 x 900 x 2 (tcp/udp) rows
    ("pa.xml", _panos_bomb(), "palo_alto"),         # 10 x 900 rows
])
def test_generic_vendors_rejected_413(client, monkeypatch, name, text, vendor):
    monkeypatch.setenv("IACS_MAX_RULE_ROWS_PER_INGEST", "5000")
    r = _post(client, "/ingest/firewall", name, text.encode(),
              {"vendor_hint": vendor, "firewall_device_name": "DEV"})
    assert r.status_code == 413, r.text
    assert "IACS_MAX_RULE_ROWS_PER_INGEST" in r.json()["detail"]
    for model in (FirewallRule, FirewallDevice, NatRule):
        assert _count(client, model) == 0, model.__name__


@pytest.mark.parametrize("text,vendor,rows", [
    (_cisco_bomb(), "cisco", 16_000),
    (_pfsense_bomb(), "pfsense", 18_000),
    (_panos_bomb(), "palo_alto", 9_000),
])
def test_generic_vendors_within_budget(text, vendor, rows, monkeypatch):
    monkeypatch.setenv("IACS_MAX_RULE_ROWS_PER_INGEST", str(rows))
    device_type, rules = fp.parse_firewall_config(text, vendor_hint=vendor)
    assert len(rules) == rows
    monkeypatch.setenv("IACS_MAX_RULE_ROWS_PER_INGEST", str(rows - 1))
    with pytest.raises(IngestLimitExceeded):
        fp.parse_firewall_config(text, vendor_hint=vendor)


def test_budget_shared_and_resets():
    with rule_row_budget(10) as b:
        with rule_row_budget(999) as inner:
            assert inner is b                       # nested shares the outer budget
        fp.charge_rule_rows(10)
        with pytest.raises(IngestLimitExceeded):
            fp.charge_rule_rows(1)
    fp.charge_rule_rows(10 ** 9)                    # no active budget -> no-op


def test_per_rule_cap_default_and_env():
    assert fp.MAX_RULE_ROWS == 25_000


# ================================================ 2. compressed captures ==

def test_magic_helpers():
    assert compressed_format(gzip.compress(b"x")) == "gzip"
    assert compressed_format(bz2.compress(b"x")) == "bzip2"
    assert compressed_format(lzma.compress(b"x")) == "xz"
    assert compressed_format(b"PK\x03\x04....") == "zip"
    assert compressed_format(b"config firewall") is None
    assert compressed_format(b"BZh is a word") is None
    assert capture_format(b"\xd4\xc3\xb2\xa1") == "pcap"
    assert capture_format(b"\x0a\x0d\x0d\x0a") == "pcapng"


def _zip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.pcap", data)
    return buf.getvalue()


@pytest.mark.parametrize("path", ["/ingest/pcap", "/ingest/pcap-fw"])
@pytest.mark.parametrize("codec", ["gzip", "bzip2", "xz", "zip"])
def test_compressed_pcap_rejected_415(client, tmp_path, path, codec):
    raw = _pcap_bytes(tmp_path, [_pkt(i) for i in range(5)])
    data = {"gzip": gzip.compress, "bzip2": bz2.compress, "xz": lzma.compress,
            "zip": _zip}[codec](raw)
    r = _post(client, path, "x.pcap.gz", data)
    assert r.status_code == 415, r.text
    assert codec in r.json()["detail"] and "ompressed" in r.json()["detail"]
    assert _count(client, Host) == 0 and _count(client, NetworkSession) == 0


def test_non_capture_rejected_415(client):
    r = _post(client, "/ingest/pcap", "x.pcap", b"<html>not a capture</html>")
    assert r.status_code == 415 and "Not a pcap" in r.json()["detail"]
    r = _post(client, "/ingest/pcap", "x.pcap", b"")
    assert r.status_code == 415


def test_parser_never_decompresses(db, tmp_path):
    """Even called directly (bypassing the route), a gzip capture is refused
    instead of being inflated by scapy."""
    raw = _pcap_bytes(tmp_path, [_pkt(i) for i in range(5)])
    gz = tmp_path / "c.pcap"
    gz.write_bytes(gzip.compress(raw))
    with pytest.raises(UnsupportedCaptureError):
        ingest_pcap(str(gz), db)
    assert db.query(Host).count() == 0


def test_pcapng_still_accepted(client, tmp_path):
    from scapy.utils import PcapNgWriter
    p = tmp_path / "n.pcapng"
    w = PcapNgWriter(str(p))
    for i in range(3):
        w.write(_pkt(i))
    w.close()
    r = _post(client, "/ingest/pcap", "n.pcapng", p.read_bytes())
    assert r.status_code == 200, r.text
    assert r.json()["stats"]["packets"] == 3 and r.json()["truncated"] is False


# ======================================================== 3. pcap caps ==

def test_packet_cap_truncates_and_commits(client, tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_PACKETS", "10")
    r = _post(client, "/ingest/pcap", "p.pcap", _pcap_bytes(tmp_path, [_pkt(i) for i in range(50)]))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["truncated"] is True
    t = j["truncation"]
    assert t["limit"] == "max_packets" and t["env_var"] == "IACS_PCAP_MAX_PACKETS"
    assert t["limit_value"] == 10 and t["records_processed"] == 10 and t["packets"] == 10
    assert j["stats"]["truncated_by"] == "max_packets"
    # partial data committed: 10 clients + the server, 10 sessions
    assert _count(client, Host) == 11 and _count(client, NetworkSession) == 10
    assert _count(client, ProtocolDetail) == 10


def test_new_host_cap(client, tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_NEW_HOSTS", "5")
    r = _post(client, "/ingest/pcap", "h.pcap", _pcap_bytes(tmp_path, [_pkt(i) for i in range(40)]))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["truncated"] is True and j["truncation"]["limit"] == "max_new_hosts"
    assert j["truncation"]["hosts_created"] == 5
    assert _count(client, Host) == 5
    assert _count(client, NetworkSession) == j["truncation"]["sessions"] >= 1


def test_session_cap(client, tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_SESSIONS", "3")
    # one client, many source ports -> many sessions, 2 hosts
    pkts = [_pkt(0, src="10.9.0.1", sport=41000 + i) for i in range(20)]
    r = _post(client, "/ingest/pcap", "s.pcap", _pcap_bytes(tmp_path, pkts))
    j = r.json()
    assert j["truncated"] is True and j["truncation"]["limit"] == "max_sessions"
    assert _count(client, NetworkSession) == 3 == j["stats"]["sessions"]


def test_time_cap(db, tmp_path, monkeypatch):
    class _Clock:
        t = 0.0

        @classmethod
        def monotonic(cls):
            cls.t += 1.0
            return cls.t
    monkeypatch.setattr(pcap_parser, "time", _Clock)
    # Each clock read advances 1 s.  Reads: start, prescan (records 0 / 1024 /
    # 2048), reconcile (1 binding), main pass (records 0, 1024 -> over 6.5 s).
    monkeypatch.setenv("IACS_PCAP_MAX_SECONDS", "5.5")
    path = tmp_path / "t.pcap"
    wrpcap(str(path), [_pkt(0) for _ in range(3000)])
    stats = ingest_pcap(str(path), db)
    assert stats["truncated"] is True and stats["truncated_by"] == "max_seconds"
    assert stats["records_processed"] == 1024 == stats["packets"]
    assert db.query(Host).count() == 2           # committed partial result
    assert db.query(NetworkSession).one().packet_count == 1024


def test_empty_record_bomb_capped(client, monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_PACKETS", "1000")
    r = _post(client, "/ingest/pcap", "bomb.pcap", _empty_record_pcap(20_000))
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["truncated"] is True and j["truncation"]["records_processed"] == 1000
    assert _count(client, Host) == 0


def test_pcap_fw_reports_truncation(client, tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_PACKETS", "4")
    r = _post(client, "/ingest/pcap-fw", "p.pcap", _pcap_bytes(tmp_path, [_pkt(i) for i in range(9)]))
    assert r.status_code == 200, r.text
    assert r.json()["truncated"] is True and r.json()["truncation"]["packets"] == 4
    assert _count(client, NetworkSession) == 4


def test_invalid_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("IACS_PCAP_MAX_PACKETS", "lots")
    monkeypatch.setenv("IACS_PCAP_MAX_SECONDS", "-1")
    lim = pcap_parser._PcapLimits()
    assert lim.max_packets == 2_000_000 and lim.max_seconds == 600.0


# ---------------------------------- host fast path keeps identity rules --

def test_reingest_reuses_hosts_and_sessions(db, tmp_path):
    path = tmp_path / "r.pcap"
    wrpcap(str(path), [_pkt(i) for i in range(30)])
    s1 = ingest_pcap(str(path), db)
    s2 = ingest_pcap(str(path), db)
    assert s1["hosts"] == 31 and s2["hosts"] == 0
    assert db.query(Host).count() == 31 and db.query(NetworkSession).count() == 30
    assert all(h.sources == ["pcap"] for h in db.query(Host))
    assert sum(s.packet_count for s in db.query(NetworkSession)) == 60


def test_fast_path_attaches_mac_to_ip_only_host(db, tmp_path):
    """An IP-only host (e.g. from ARP/config) must still get the MAC attached
    instead of a duplicate row being created."""
    db.add(Host(ip="10.9.0.1", mac=None, sources=["config"]))
    db.commit()
    path = tmp_path / "m.pcap"
    wrpcap(str(path), [_pkt(0)])
    ingest_pcap(str(path), db)
    rows = db.query(Host).filter(Host.ip == "10.9.0.1").all()
    assert len(rows) == 1 and rows[0].mac == "02:00:00:00:00:00"
    assert set(rows[0].sources) == {"config", "pcap"}


# ============================================== normal samples unchanged ==

@pytest.mark.parametrize("name", ["modbus_sample.pcap", "multi_protocol_sample.pcap"])
def test_sample_pcaps_not_truncated_and_unchanged(db, name, monkeypatch):
    stats = ingest_pcap(str(SAMPLES / name), db)
    assert stats["truncated"] is False and stats["truncated_by"] is None
    assert stats["records_processed"] >= stats["packets"] > 0
    hosts, sessions = db.query(Host).count(), db.query(NetworkSession).count()
    # same result with effectively unlimited caps
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db2 = sessionmaker(bind=engine)()
    for env in ("IACS_PCAP_MAX_PACKETS", "IACS_PCAP_MAX_NEW_HOSTS", "IACS_PCAP_MAX_SESSIONS"):
        monkeypatch.setenv(env, str(10 ** 9))
    s2 = ingest_pcap(str(SAMPLES / name), db2)
    assert (s2["packets"], s2["sessions"], s2["hosts"]) == \
        (stats["packets"], stats["sessions"], stats["hosts"])
    assert (db2.query(Host).count(), db2.query(NetworkSession).count()) == (hosts, sessions)
    db2.close()


def test_sample_uploads_still_accepted(client):
    def up(url, name, params=None):
        r = _post(client, url, name, (SAMPLES / name).read_bytes(), params)
        assert r.status_code == 200, (name, r.text[:300])
        return r.json()
    j = up("/ingest/fortigate-config", "sample_fortigate_config.txt", {"firewall_name": "FW"})
    assert j["stats"]["rules_created"] > 0
    for f, dev in (("sample_firewall_cisco.txt", "C"), ("sample_firewall_pfsense.xml", "P"),
                   ("sample_firewall_panos.xml", "X"), ("sample_firewall_panos_set.txt", "S")):
        assert up("/ingest/firewall", f, {"firewall_device_name": dev})["stats"]["rules_created"] > 0
    j = up("/ingest/pcap", "multi_protocol_sample.pcap")
    assert j["truncated"] is False and "truncation" not in j
    up("/ingest/arp", "sample_arp_cisco.txt")
    up("/ingest/switch", "sample_switch_running_config.txt")
    up("/ingest/mac-table", "sample_mac_table_cisco.txt", {"device_name": "SW"})
    up("/ingest/syslog", "sample_syslog_asa.log")


# ====================================================== 4. text uploads ==

@pytest.mark.parametrize("url,name,params", [
    ("/ingest/firewall", "sample_firewall_cisco.txt", {}),
    ("/ingest/fortigate-config", "sample_fortigate_config.txt", {}),
    ("/ingest/arp", "sample_arp_cisco.txt", {}),
    ("/ingest/switch", "sample_switch_running_config.txt", {}),
    ("/ingest/mac-table", "sample_mac_table_cisco.txt", {}),
    ("/ingest/syslog", "sample_syslog_asa.log", {}),
    ("/ingest/forti-syslog", "sample_forti_events.cef", {}),
    ("/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {"baseline_name": "B"}),
])
def test_compressed_text_upload_rejected_415(client, url, name, params):
    data = gzip.compress((SAMPLES / name).read_bytes())
    r = _post(client, url, name + ".gz", data, params)
    assert r.status_code == 415, r.text
    assert "gzip" in r.json()["detail"]
    assert _count(client, FirewallRule) == 0 and _count(client, Host) == 0


class _LyingUpload:
    """An UploadFile whose declared size understates what it streams."""

    def __init__(self, data: bytes, declared: int):
        self._buf = io.BytesIO(data)
        self.size = declared
        self.filename = "x.txt"

    async def read(self, n=-1):
        return self._buf.read(n)


def test_size_limit_applies_to_bytes_read():
    import asyncio
    up = _LyingUpload(b"a" * 5000, declared=10)
    with pytest.raises(HTTPException) as ei:
        asyncio.run(routes_mod._read_limited(up, 1024, "Config", content="text"))
    assert ei.value.status_code == 413
    ok = _LyingUpload(b"plain text", declared=None)
    assert asyncio.run(routes_mod._read_limited(ok, 1024, "Config", content="text")) == b"plain text"
