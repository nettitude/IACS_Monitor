"""
Tests for app/parsers/dnp3_analyzer.py
"""
import pytest
from app.parsers.dnp3_analyzer import (
    parse_dnp3,
    _dechunk_user_data,
    _decode_iin,
    DNP3_TCP_PORT,
    FUNCTION_CODES,
)


# ---------------------------------------------------------------------------
# Frame builder helpers
# ---------------------------------------------------------------------------

def _build_dnp3_frame(
    src=1, dst=2, function_code=0x01,
    app_control=0xC0, extra_app=b"",
    transport_header=0xC0,
):
    """
    Build a minimal DNP3 frame with a single 16-byte-or-less user-data
    block (no CRC stripping needed for single-block frames if we fake the
    length to match the data we actually provide).

    Layout:
        0x05 0x64  (sync)
        length     (control + dest + src + user_data length)
        control
        dest LE
        src LE
        header CRC (2 dummy bytes)
        [user data: transport(1) + app_control(1) + fc(1) + extra_app]
        [block CRC: 2 dummy bytes]
    """
    user_data = bytes([transport_header, app_control, function_code]) + extra_app
    # DNP3 length = control(1)+dest(2)+src(2)+user_data
    length = 1 + 2 + 2 + len(user_data)
    # Chunk the user data: each block up to 16 bytes gets a 2-byte CRC appended
    chunked = bytearray()
    offset = 0
    while offset < len(user_data):
        chunk = user_data[offset:offset + 16]
        chunked += chunk
        chunked += b"\x00\x00"  # fake CRC
        offset += 16

    frame = (
        b"\x05\x64"
        + bytes([length])
        + b"\x44"  # control
        + dst.to_bytes(2, "little")
        + src.to_bytes(2, "little")
        + b"\x00\x00"  # header CRC (fake)
        + bytes(chunked)
    )
    return frame


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_dnp3_read_request():
    """FC 0x01 (read) is recognized as operation='read'."""
    # qualifier 0x06 = no range (all points), group 30 var 0
    frame = _build_dnp3_frame(function_code=0x01, extra_app=b"\x1E\x00\x06")
    result = parse_dnp3(frame)
    assert result is not None
    assert result["summary"] == "read"
    assert result["operation"] == "read"
    assert result["direction"] == "request"


def test_parse_dnp3_write_request():
    """FC 0x02 (write) is operation='write'."""
    frame = _build_dnp3_frame(function_code=0x02, extra_app=b"\x1E\x00\x06")
    result = parse_dnp3(frame)
    assert result is not None
    assert result["operation"] == "write"


def test_parse_dnp3_direct_operate():
    """FC 0x05 (direct_operate) is also a write operation."""
    frame = _build_dnp3_frame(function_code=0x05)
    result = parse_dnp3(frame)
    assert result is not None
    assert result["operation"] == "write"
    assert result["summary"] == "direct_operate"


def test_parse_dnp3_response():
    """FC 0x81 (response) is direction='response'."""
    # IIN bytes (2) must follow for responses
    frame = _build_dnp3_frame(function_code=0x81, extra_app=b"\x00\x00")
    result = parse_dnp3(frame)
    assert result is not None
    assert result["direction"] == "response"
    assert result["summary"] == "response"


def test_parse_dnp3_unknown_function_code():
    """Unknown FC is labeled as 'unknown_fc_...' and doesn't crash."""
    frame = _build_dnp3_frame(function_code=0x99)
    result = parse_dnp3(frame)
    assert result is not None
    assert "unknown_fc_" in result["summary"]


def test_parse_dnp3_too_short_returns_none():
    """Payload shorter than 10 bytes returns None."""
    assert parse_dnp3(b"\x05\x64\x00") is None


def test_parse_dnp3_wrong_sync_returns_none():
    """Wrong sync bytes return None."""
    bad = b"\xFF\xFF" + b"\x00" * 10
    assert parse_dnp3(bad) is None


def test_dechunk_user_data_single_block():
    """Single block under 16 bytes strips its 2-byte CRC."""
    raw = b"\x01\x02\x03\x04\x00\x00"  # 4 data bytes + 2 CRC bytes
    result = _dechunk_user_data(raw, 4)
    assert result == b"\x01\x02\x03\x04"


def test_decode_iin_device_restart_flag():
    """IIN byte2 bit 0 = device_restart."""
    result = _decode_iin(b"\x00\x01")
    assert "device_restart" in result["flags"]


def test_dnp3_tcp_port_constant():
    assert DNP3_TCP_PORT == 20000
