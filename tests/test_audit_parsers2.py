"""Audit 2026-10-01, parser findings A-18..A-23, A-29, A-30.

Hostile / malformed input must never abort a whole upload: bad lines or
blocks are skipped and counted, and nothing is silently widened.
"""
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Finding, Host
from app.parsers import firewall_parser as fw
from app.parsers import forti_config_parser as fc
from app.parsers import pcap_parser
from app.parsers.baseline_parser import ingest_asset_inventory
from app.parsers.common import detect_gateway_macs
from app.parsers.syslog_vendors import parse_syslog_header

SAMPLE_FGT = Path(__file__).resolve().parent.parent / "sample_data" / "sample_fortigate_config.txt"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, autoflush=False)()
    yield s
    s.close()


# ------------------------------------------------------------------ A-18 --

@pytest.mark.parametrize("bad", ["10.050.1.0", "510.0.1.0"])
def test_a18_malformed_cisco_ace_is_skipped_and_counted(bad):
    text = (f"access-list A extended permit ip {bad} 255.255.255.0 any\n"
            "access-list A extended permit tcp host 1.2.3.4 any eq 22\n")
    stats = {}
    dev, rules = fw.parse_firewall_config(text, "cisco", stats=stats)
    assert dev == "cisco_ios"
    assert [r["src"] for r in rules] == ["1.2.3.4"]
    assert stats["lines_rejected"] == 1
    assert bad in stats["reject_reasons"][0]


def test_a18_invalid_host_and_object_members_rejected_not_widened():
    text = ("object network O\n subnet 10.050.1.0 255.255.255.0\n"
            "object-group network G\n network-object host 999.1.1.1\n"
            " network-object host 10.0.0.9\n"
            "access-list A extended permit ip object O any\n"
            "access-list A extended permit ip object-group G any\n"
            "access-list A extended permit ip host 300.1.1.1 any\n"
            "access-list 10 permit 10.050.1.0 0.0.0.255\n")
    stats = {}
    _, rules = fw.parse_firewall_config(text, "cisco", stats=stats)
    srcs = {r["src"] for r in rules}
    assert srcs == {"10.0.0.9"}                 # never "any"
    assert stats["lines_rejected"] >= 4


def test_a18_cisco_nat_bad_addresses_skipped():
    text = ("object network N\n host 10.0.0.1\n nat (inside,outside) static 510.1.1.1\n"
            "nat (inside,outside) source static 10.050.1.1 9.9.9.9\n"
            "ip nat inside source static 10.050.1.1 300.1.1.1\n"
            "ip nat pool P 1.1.1.300 1.1.1.1 netmask 255.255.255.0\n"
            "access-list 1 permit 10.0.0.0 0.0.0.255\n"
            "ip nat inside source list 1 pool P overload\n"
            "ip nat inside source static tcp 10.1.1.1 80 1.1.1.1 80\n"
            "access-list A extended permit ip any any\n")
    stats = {}
    nats = fw.parse_cisco_nat(text, stats)
    assert [(n["ext_ip"], n["mapped_ip"]) for n in nats] == [("1.1.1.1/32", "10.1.1.1/32")]
    assert stats["nat_lines_rejected"] == 4


def test_a18_ingest_does_not_500(db):
    text = ("access-list A extended permit ip 10.050.1.0 255.255.255.0 any\n"
            "access-list A extended permit ip any host 10.0.0.1\n"
            "nat (inside,outside) source static 10.050.1.1 9.9.9.9\n")
    st = fw.ingest_firewall_config(text, db, firewall_device_name="asa")
    assert st["rules_created"] == 1
    assert st["lines_rejected"] == 1
    assert st["nat_lines_rejected"] == 1


# ------------------------------------------------------------------ A-19 --

DEEP = 3000


@pytest.mark.parametrize("kind,text", [
    ("network", "".join(f"object-group network C{i}\n group-object C{i+1}\n" for i in range(DEEP))
     + f"object-group network C{DEEP}\n network-object host 1.1.1.1\n"
     "access-list A extended permit ip object-group C0 any\n"),
    ("service", "".join(f"object-group service S{i}\n group-object S{i+1}\n" for i in range(DEEP))
     + "access-list A extended permit object-group S0 any any\n"),
    ("port", "".join(f"object-group service S{i} tcp\n group-object S{i+1}\n" for i in range(DEEP))
     + "access-list A extended permit tcp any any object-group S0\n"),
    ("protocol", "".join(f"object-group protocol P{i}\n group-object P{i+1}\n" for i in range(DEEP))
     + "access-list A extended permit object-group P0 any any\n"),
])
def test_a19_deep_cisco_chains_hit_depth_limit(kind, text):
    stats = {}
    _, rules = fw.parse_firewall_config(text, "cisco", stats=stats)
    assert rules and stats["groups_over_limit"] >= 1
    joined = " ".join(f'{r["src"]} {r["dst_port"]} {r["protocol"]}' for r in rules)
    assert "too-large:" in joined
    assert fw.parse_cisco_nat(text) == []          # NAT path resolves groups too


# ------------------------------------------------------------------ A-20 --

def test_a20_malformed_forti_blocks_skipped(db):
    base = SAMPLE_FGT.read_text()
    junk = ("config firewall address\n set stray value\n edit \"X\"\n set type ipmask extra\n"
            " set subnet 10.0.0.0 255.0.0.0\n next\nend\n"
            "config system interface\n edit \"p9\"\n set zone a b\n set interface x y\n next\nend\n"
            "config vdom\n set junk 1\nend\n")
    st = fc.ingest_fortigate_config(base + junk, db)
    assert st["rules_created"] > 0
    assert st["blocks_rejected"] >= 1


def _mutate(lines, r):
    L = list(lines)
    for _ in range(r.randint(1, 8)):
        i = r.randrange(len(L))
        line, m = L[i], r.randrange(8)
        if m == 0:
            del L[i]
        elif m == 1:
            L.insert(r.randrange(len(L)), line)
        elif m == 2 and line.strip().startswith("set "):
            L[i] = line + ' "x y" extra'
        elif m == 3 and line.strip().startswith("set "):
            L[i] = " ".join(line.split()[:2])
        elif m == 4:
            L.insert(i, " set " + r.choice(["name", "interface", "member", "type", "zone",
                                            "status", "action", "vdom"])
                     + " " + r.choice(["a b", '"A" "B"', "1.2.3.4 255.255.255.0 x", ""]))
        elif m == 5:
            L.insert(i, r.choice(["next", "end", "config system interface",
                                  'edit "port1"', "config firewall policy", "edit 1"]))
        elif m == 6 and line.strip().startswith("edit"):
            L.insert(i, " set " + line.split()[1].strip('"') + " foo bar")
        else:
            j = r.randrange(len(L))
            L[i], L[j] = L[j], L[i]
    return "\n".join(L)


def test_a20_fuzz_ingest_never_raises():
    logging.disable(logging.CRITICAL)
    try:
        lines = SAMPLE_FGT.read_text().splitlines()
        t0, n = time.monotonic(), 0
        while time.monotonic() - t0 < 8 and n < 400:
            engine = create_engine("sqlite://", poolclass=StaticPool,
                                   connect_args={"check_same_thread": False})
            Base.metadata.create_all(engine)
            s = sessionmaker(bind=engine, autoflush=False)()
            txt = _mutate(lines, random.Random(n))
            try:
                fc.ingest_fortigate_config(txt, s, generate_findings=bool(n % 2))
            except Exception as e:      # pragma: no cover - failure path
                pytest.fail(f"seed {n}: {type(e).__name__}: {e}")
            finally:
                s.close()
                engine.dispose()
            n += 1
        assert n >= 20
    finally:
        logging.disable(logging.NOTSET)


# ------------------------------------------------------------------ A-21 --

def test_a21_duplicate_source_ref_in_one_ingest(db, monkeypatch):
    now = datetime.now(timezone.utc)
    f = {"check_name": "dup_check", "category": "config_review", "severity": "high",
         "status": "open", "isa62443_sr": "SR 5.1", "checklist_id": "X",
         "title": "t", "detail": {"policy_id": "1"}, "device_name": "d",
         "created_at": now}
    monkeypatch.setattr(fc, "_config_findings", lambda *a, **k: [dict(f), dict(f, severity="low")])
    st = fc.ingest_fortigate_config(SAMPLE_FGT.read_text(), db, generate_findings=True)
    rows = db.query(Finding).filter(Finding.source_ref.like("config:%:dup_check:1")).all()
    assert len(rows) == 1 and rows[0].severity == "low"
    assert st["findings_created"] >= 1


# ------------------------------------------------------------------ A-22 --

def test_a22_single_spoofed_offsubnet_ip_not_gateway():
    host = "02:00:00:00:00:05"
    assert detect_gateway_macs({host: ["10.0.1.5", "8.8.8.8"]}) == set()
    assert detect_gateway_macs({host: ["10.0.1.5"]}, {host: {"10.0.1.5"}}) == set()
    assert detect_gateway_macs({host: ["10.0.1.5", "8.8.8.8", "1.1.1.1"]}) == {host}


def test_a22_gateway_detection_is_fast():
    ips = [f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}" for i in range(200_000)]
    t0 = time.perf_counter()
    gw = detect_gateway_macs({"02:00:00:00:00:01": ips,
                              "02:00:00:00:00:02": ips[:5] * 1000})
    assert time.perf_counter() - t0 < 2.0
    assert gw == {"02:00:00:00:00:01"}


# ------------------------------------------------------------------ A-23 --

def test_a23_asset_inventory_rejects_bad_identities(db):
    csv_text = ("ip,mac,hostname\n"
                ",zz:zz,badmac\n"
                "10.0.0.1,zz:zz,badmac-with-ip\n"
                "224.0.0.5,,mcast\n"
                "255.255.255.255,,bcast\n"
                ",ff:ff:ff:ff:ff:ff,bcastmac\n"
                ",01:00:5e:00:00:01,mcastmac\n"
                "10.0.0.999,,badip\n"
                ",,\n"
                "10.0.0.2,00:11:22:33:44:55,good\n")
    st = ingest_asset_inventory(csv_text, db, "b")
    assert st["hosts_created_or_updated"] == 1
    assert st["rows_rejected"] == 7
    assert len(st["reject_reasons"]) == 5
    assert [h.hostname for h in db.query(Host).all()] == ["good"]


# ------------------------------------------------------------------ A-29 --

@pytest.mark.parametrize("zone,hour", [("EST", 17), ("PST", 20), ("CET", 11),
                                       ("UTC", 12), ("GMT", 12), ("CEST", 10)])
def test_a29_syslog_timezone_abbreviation(zone, hour):
    h = parse_syslog_header(f"<166>Oct 01 2026 12:00:00 {zone} asa1 : %ASA-6-302013: x")
    assert h["host"] == "asa1"
    assert h["ts"] == datetime(2026, 10, 1, hour, 0, tzinfo=timezone.utc)
    assert h["msg"].startswith("%ASA-6-302013")


def test_a29_unknown_zone_token_is_still_hostname():
    h = parse_syslog_header("Oct 01 2026 12:00:00 FW %ASA-6-302013: x")
    assert h["host"] == "FW"
    assert h["ts"] == datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ A-30 --

def _s7_partial(sport, n=200, t=1_700_000_000.0):
    # TPKT header claims 4000 bytes; only n are sent -> bytes stay buffered
    payload = b"\x03\x00\x0f\xa0" + b"\x02\xf0\x80" + b"\x00" * (n - 7)
    p = (Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:0b")
         / IP(src="10.0.1.5", dst="10.0.1.10")
         / TCP(sport=sport, dport=102, seq=1000, flags="PA") / Raw(load=payload))
    p.time = t + sport / 1000
    return p


def test_a30_stream_count_cap(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_parser, "MAX_TCP_STREAMS", 3)
    path = str(tmp_path / "s.pcap")
    wrpcap(path, [_s7_partial(40000 + i) for i in range(10)])
    st = pcap_parser.ingest_pcap(path, db)
    assert st["streams_evicted"] == 7


def test_a30_reassembly_memory_cap(db, tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_parser, "MAX_REASSEMBLY_BYTES", 500)
    path = str(tmp_path / "m.pcap")
    wrpcap(path, [_s7_partial(41000 + i, n=300) for i in range(4)])
    st = pcap_parser.ingest_pcap(path, db)
    assert st["streams_evicted"] == 3
