"""
Tests for app/parsers/arp_parser.py

Covers parse_arp_table and ingest_arp_table.
ingest_arp_table calls db.commit() so StaticPool is used.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Host
from app.parsers.arp_parser import parse_arp_table, ingest_arp_table, ArpEntry


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


# Sample inputs
CISCO_TEXT = (
    "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
    "Internet  10.0.1.1                -   0011.2233.4455  ARPA   Vlan10\n"
)

WINDOWS_TEXT = (
    "Interface: 10.0.1.5 --- 0x3\n"
    "  Internet Address      Physical Address      Type\n"
    "  10.0.1.1              00-11-22-33-44-55     dynamic\n"
)

UNIX_TEXT = "? (10.0.1.10) at 00:22:33:44:55:66 [ether] on eth0\n"

UNIX_SHORT_MAC_TEXT = "? (10.0.1.11) at 0:11:22:33:44:55 [ether] on eth0\n"


# ---------------------------------------------------------------------------
# parse_arp_table
# ---------------------------------------------------------------------------

def test_parse_cisco_format():
    entries = parse_arp_table(CISCO_TEXT)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == "10.0.1.1"
    assert e.mac == "0011.2233.4455"
    assert e.interface == "Vlan10"


def test_parse_windows_format():
    entries = parse_arp_table(WINDOWS_TEXT)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == "10.0.1.1"
    assert e.mac == "00-11-22-33-44-55"
    assert e.interface == "10.0.1.5"


def test_parse_unix_format():
    entries = parse_arp_table(UNIX_TEXT)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == "10.0.1.10"
    assert e.mac == "00:22:33:44:55:66"
    assert e.interface == "eth0"


def test_parse_unix_short_mac():
    entries = parse_arp_table(UNIX_SHORT_MAC_TEXT)
    assert len(entries) == 1
    e = entries[0]
    assert e.ip == "10.0.1.11"
    # Mac has unpadded leading byte "0" — parser captures raw format
    assert "0:11:22:33:44:55" in e.mac or e.mac == "0:11:22:33:44:55"


def test_format_hint_cisco():
    entries = parse_arp_table(CISCO_TEXT, format_hint="cisco")
    assert len(entries) == 1
    assert entries[0].ip == "10.0.1.1"


def test_empty_text_returns_empty():
    entries = parse_arp_table("")
    assert entries == []


# ---------------------------------------------------------------------------
# ingest_arp_table
# ---------------------------------------------------------------------------

def test_ingest_creates_hosts(db):
    stats = ingest_arp_table(CISCO_TEXT, db)
    hosts = db.query(Host).all()
    assert len(hosts) >= 1
    assert any(h.ip == "10.0.1.1" for h in hosts)


def test_ingest_returns_stats(db):
    stats = ingest_arp_table(CISCO_TEXT, db)
    assert "entries_found" in stats
    assert "hosts_created_or_updated" in stats
    assert "hosts_total" in stats
    assert stats["entries_found"] == 1
    assert stats["hosts_created_or_updated"] == 1


def test_ingest_deduplicates(db):
    ingest_arp_table(CISCO_TEXT, db)
    first_count = db.query(Host).count()
    ingest_arp_table(CISCO_TEXT, db)
    second_count = db.query(Host).count()
    assert first_count == second_count


def test_ingest_empty_stats(db):
    stats = ingest_arp_table("", db)
    assert stats["entries_found"] == 0
    assert stats["hosts_created_or_updated"] == 0
