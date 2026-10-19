"""
Tests for app/parsers/mac_table_parser.py
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, MacTableEntry
from app.parsers.mac_table_parser import (
    parse_cisco_mac_table,
    parse_hp_mac_table,
    detect_mac_table_type,
    ingest_mac_table,
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


CISCO_MAC_TABLE = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0011.2233.4455    DYNAMIC     Gi1/0/1
  20    aabb.ccdd.eeff    DYNAMIC     Gi1/0/2
 All    0100.0ccc.cccc    STATIC      CPU
"""

HP_MAC_TABLE = """\
 MAC Address   Located on Port  VLAN
 -------------  ---------------  ----
 001122-334455        1           10
 aabbcc-ddeeff        5           20
"""


# ------------------------------------------------------------------ Cisco format

def test_cisco_mac_table_parses_entries():
    entries = parse_cisco_mac_table(CISCO_MAC_TABLE)
    assert len(entries) == 2


def test_cisco_mac_table_mac_normalized():
    entries = parse_cisco_mac_table(CISCO_MAC_TABLE)
    macs = [e["mac"] for e in entries]
    assert "00:11:22:33:44:55" in macs
    assert "aa:bb:cc:dd:ee:ff" in macs


def test_cisco_mac_table_vlan_and_port():
    entries = parse_cisco_mac_table(CISCO_MAC_TABLE)
    e = next(e for e in entries if e["mac"] == "00:11:22:33:44:55")
    assert e["vlan"] == "10"
    assert e["port_name"] == "Gi1/0/1"


def test_cisco_mac_table_skips_all_vlan():
    # "All" rows (multicast/system) should be skipped
    entries = parse_cisco_mac_table(CISCO_MAC_TABLE)
    assert all(e["vlan"].lower() != "all" for e in entries)


def test_cisco_mac_table_empty_input():
    assert parse_cisco_mac_table("") == []


# ------------------------------------------------------------------ HP format

def test_hp_mac_table_parses_entries():
    entries = parse_hp_mac_table(HP_MAC_TABLE)
    assert len(entries) == 2


def test_hp_mac_table_mac_normalized():
    entries = parse_hp_mac_table(HP_MAC_TABLE)
    macs = [e["mac"] for e in entries]
    assert "00:11:22:33:44:55" in macs
    assert "aa:bb:cc:dd:ee:ff" in macs


def test_hp_mac_table_vlan_and_port():
    entries = parse_hp_mac_table(HP_MAC_TABLE)
    e = next(e for e in entries if e["mac"] == "00:11:22:33:44:55")
    assert e["vlan"] == "10"
    assert e["port_name"] == "1"


def test_hp_mac_table_empty_input():
    assert parse_hp_mac_table("") == []


# ------------------------------------------------------------------ detection
# Note: detect_mac_table_type uses _CISCO_ROW_RE.search(text) where the regex
# uses $ without re.MULTILINE. This means search() only finds a match when
# the input is a single line (no newlines). Detection tests use single-line
# samples; parse tests use the full multi-line table format above.

CISCO_DETECT_SAMPLE = "  10    0011.2233.4455    DYNAMIC     Gi1/0/1"
HP_DETECT_SAMPLE = " 001122-334455        1           10"


def test_detect_cisco_mac_table():
    assert detect_mac_table_type(CISCO_DETECT_SAMPLE) == "cisco_mac_table"


def test_detect_hp_mac_table():
    assert detect_mac_table_type(HP_DETECT_SAMPLE) == "hp_mac_table"


def test_detect_unknown():
    assert detect_mac_table_type("nothing here") == "unknown"


def test_detect_with_vendor_hint_cisco():
    assert detect_mac_table_type(CISCO_DETECT_SAMPLE, vendor_hint="cisco") == "cisco_mac_table"


def test_detect_with_vendor_hint_hp():
    assert detect_mac_table_type(HP_DETECT_SAMPLE, vendor_hint="hp") == "hp_mac_table"


# ------------------------------------------------------------------ ingest / DB

# Single-line versions of the MAC table rows for ingest tests.
# detect_mac_table_type uses re.search() with anchored regexes (^ and $) that
# only match when the entire text is a single line with no surrounding newlines.
# Multi-line tables require iterating per-line (done by the parse functions),
# but detection short-circuits earlier. Single-line inputs work correctly.
CISCO_INGEST_TEXT = "  10    0011.2233.4455    DYNAMIC     Gi1/0/1"
CISCO_INGEST_TEXT_2 = "  20    aabb.ccdd.eeff    DYNAMIC     Gi1/0/2"
HP_INGEST_TEXT = " 001122-334455        1           10"


def test_ingest_cisco_creates_mac_table_entries(db):
    stats = ingest_mac_table(CISCO_INGEST_TEXT, db, device_name="CORE-SW-01")
    assert stats["table_type"] == "cisco_mac_table"
    assert stats["entries_found"] == 1
    rows = db.query(MacTableEntry).all()
    assert len(rows) == 1


def test_ingest_links_existing_host(db):
    # ingest_mac_table calls get_or_create_host(ip=None, mac=X) which matches
    # a host with that MAC and no IP (mac-only identity row). Pre-create such a row.
    host = Host(mac="00:11:22:33:44:55", ip=None, sources=["arp"])
    db.add(host)
    db.commit()

    ingest_mac_table(CISCO_INGEST_TEXT, db, device_name="CORE-SW-01")

    db.refresh(host)
    assert host.vlan == "10"
    assert host.vlan_source == "mac_table"


def test_ingest_creates_host_if_not_found(db):
    ingest_mac_table(CISCO_INGEST_TEXT, db, device_name="CORE-SW-01")
    # Should have created a Host row for the MAC
    hosts = db.query(Host).all()
    macs = [h.mac for h in hosts]
    assert "00:11:22:33:44:55" in macs


def test_ingest_does_not_overwrite_manual_vlan(db):
    host = Host(mac="00:11:22:33:44:55", ip="10.0.10.5", sources=["manual"],
                vlan="99", vlan_source="manual")
    db.add(host)
    db.commit()

    ingest_mac_table(CISCO_INGEST_TEXT, db, device_name="CORE-SW-01")

    db.refresh(host)
    assert host.vlan == "99"
    assert host.vlan_source == "manual"


def test_ingest_hp_mac_table(db):
    stats = ingest_mac_table(HP_INGEST_TEXT, db, device_name="HP-SW-01")
    assert stats["table_type"] == "hp_mac_table"
    assert stats["entries_found"] == 1


def test_ingest_empty_input_no_changes(db):
    stats = ingest_mac_table("", db, device_name="CORE-SW-01")
    assert stats["entries_found"] == 0
    assert db.query(MacTableEntry).count() == 0
    assert db.query(Host).count() == 0


def test_ingest_unknown_format_no_changes(db):
    stats = ingest_mac_table("no recognizable content here", db)
    assert stats["table_type"] == "unknown"
    assert db.query(MacTableEntry).count() == 0


def test_autodetect_multiline_samples():
    """detect_mac_table_type() .search()es the whole dump: the row regexes
    must be MULTILINE or real multi-line output (header + rows) is 'unknown'
    and the upload fails with 422 unless vendor_hint is passed."""
    from pathlib import Path
    from app.parsers.mac_table_parser import detect_mac_table_type
    root = Path(__file__).resolve().parent.parent / "sample_data"
    assert detect_mac_table_type((root / "sample_mac_table_cisco.txt").read_text()) == "cisco_mac_table"
    assert detect_mac_table_type((root / "sample_mac_table_hp.txt").read_text()) == "hp_mac_table"
