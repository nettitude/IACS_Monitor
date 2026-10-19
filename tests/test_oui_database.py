"""
Tests for app/parsers/oui_database.py

Covers parse_manuf_text, lookup_manuf, and load_manuf_file.
No DB interaction — no fixture needed.
"""
import pytest

from app.parsers.oui_database import parse_manuf_text, lookup_manuf, load_manuf_file


# ---------------------------------------------------------------------------
# parse_manuf_text
# ---------------------------------------------------------------------------

def test_parse_simple_entry():
    text = "00:11:22  Acme  Acme Corporation\n"
    entries = parse_manuf_text(text)
    # 3-byte OUI => 24 bits left
    assert (24, 0x001122) in entries
    short, long = entries[(24, 0x001122)]
    assert short == "Acme"
    assert long == "Acme Corporation"


def test_parse_long_name_preferred():
    text = "AA:BB:CC  ShortCo  Long Company Name\n"
    entries = parse_manuf_text(text)
    key = (24, 0xAABBCC)
    assert key in entries
    short, long = entries[key]
    assert long == "Long Company Name"


def test_parse_short_name_fallback():
    text = "AA:BB:CC  ShortOnly\n"
    entries = parse_manuf_text(text)
    key = (24, 0xAABBCC)
    assert key in entries
    short, long = entries[key]
    assert short == "ShortOnly"
    assert long is None


def test_parse_comment_lines_skipped():
    text = (
        "# This is a comment\n"
        "00:11:22  Acme  Acme Corporation\n"
        "# Another comment\n"
    )
    entries = parse_manuf_text(text)
    assert len(entries) == 1
    assert (24, 0x001122) in entries


def test_parse_masked_entry():
    # /40 means 40 significant bits => bits_left = 48-40 = 8
    text = "00:11:22:33:44/40  MaskedVendor  Masked Vendor Inc\n"
    entries = parse_manuf_text(text)
    # prefix bytes are 00:11:22:33:44 -> 5 bytes, but /40 means bits_left=8
    # mac_int for "00:11:22:33:44" right-padded = 0x001122334400
    # key = (8, 0x001122334400 >> 8) = (8, 0x0011223344)
    key = (8, 0x0011223344)
    assert key in entries
    short, long = entries[key]
    assert short == "MaskedVendor"


# ---------------------------------------------------------------------------
# lookup_manuf
# ---------------------------------------------------------------------------

def _make_entries():
    """Build a small entries dict for lookup tests."""
    text = (
        "00:11:22  OuiVendor  OUI Vendor Corp\n"
        "00:11:22:33:44/40  MaskedVendor  Masked Vendor Inc\n"
    )
    return parse_manuf_text(text)


def test_lookup_exact_oui_match():
    entries = parse_manuf_text("00:11:22  OuiVendor  OUI Vendor Corp\n")
    result = lookup_manuf("00:11:22:99:88:77", entries)
    assert result == "OUI Vendor Corp"


def test_lookup_longer_prefix_wins():
    entries = _make_entries()
    # MAC 00:11:22:33:44:xx matches both the /24 OUI and the /40 masked entry
    # /40 is more specific (bits_left=8 < bits_left=24), so it wins
    result = lookup_manuf("00:11:22:33:44:ff", entries)
    assert result == "Masked Vendor Inc"


def test_lookup_no_match():
    entries = parse_manuf_text("00:11:22  OuiVendor  OUI Vendor Corp\n")
    result = lookup_manuf("ff:ee:dd:cc:bb:aa", entries)
    assert result is None


def test_lookup_malformed_mac():
    entries = parse_manuf_text("00:11:22  OuiVendor  OUI Vendor Corp\n")
    result = lookup_manuf("not-a-mac", entries)
    assert result is None


def test_load_manuf_file(tmp_path):
    content = "00:11:22  TestVendor  Test Vendor Ltd\n"
    manuf_file = tmp_path / "manuf"
    manuf_file.write_text(content, encoding="utf-8")

    entries = load_manuf_file(str(manuf_file))
    assert (24, 0x001122) in entries
    short, long = entries[(24, 0x001122)]
    assert short == "TestVendor"
    assert long == "Test Vendor Ltd"
