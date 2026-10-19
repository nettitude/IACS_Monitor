"""
Tests for app/parsers/enip_cip_analyzer.py
"""
import struct
import pytest
from app.parsers.enip_cip_analyzer import (
    parse_enip,
    _parse_encapsulation_header,
    _parse_epath,
    _parse_cip_message,
    ENIP_TCP_PORT,
    ENCAPSULATION_COMMANDS,
    CIP_SERVICE_CODES,
)


# ---------------------------------------------------------------------------
# Frame-building helpers
# ---------------------------------------------------------------------------

def _enip_header(command=0x006F, session=0x1234, data=b""):
    """Build a 24-byte ENIP encapsulation header + data."""
    length = len(data)
    return (
        struct.pack("<HH", command, length)
        + struct.pack("<I", session)  # session handle
        + struct.pack("<I", 0)        # status
        + b"\x00" * 8                 # sender context
        + struct.pack("<I", 0)        # options
        + data
    )


def _send_rr_data_body(cip_data: bytes):
    """
    Build the body of a SendRRData command:
    interface_handle(4) + timeout(2) + cpf_item_count(2) +
    null_item(type=0, len=0, 4 bytes) +
    unconnected_data_item(type=0x00B2, len, data)
    """
    null_item = struct.pack("<HH", 0x0000, 0x0000)
    data_item = struct.pack("<HH", 0x00B2, len(cip_data)) + cip_data
    cpf = struct.pack("<HH", 0, 0) + b"\x00\x00"  # interface handle + timeout
    item_count = struct.pack("<H", 2)
    return cpf + item_count + null_item + data_item


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_enip_list_identity():
    """ListIdentity (0x0063) command is handled as operation='other'."""
    frame = _enip_header(command=0x0063)
    result = parse_enip(frame)
    assert result is not None
    assert result["command"] == "list_identity"
    assert result["operation"] == "other"


def test_parse_enip_register_session():
    """RegisterSession (0x0065) is operation='other'."""
    data = b"\x01\x00\x00\x00"  # minimal register session body
    frame = _enip_header(command=0x0065, data=data)
    result = parse_enip(frame)
    assert result is not None
    assert result["command"] == "register_session"


def test_parse_enip_read_tag_request():
    """Read Tag Service (0x4C) in a SendRRData is operation='read'."""
    # CIP request: service=0x4C, symbolic tag "Motor"
    tag_name = b"Motor"
    path = bytes([0x91, len(tag_name)]) + tag_name + (b"\x00" if len(tag_name) % 2 else b"")
    path_words = len(path) // 2
    element_count = struct.pack("<H", 1)
    cip = bytes([0x4C, path_words]) + path + element_count
    # _send_rr_data_body already includes the interface_handle(4) + timeout(2) prefix
    body = _send_rr_data_body(cip)
    frame = _enip_header(command=0x006F, data=body)
    result = parse_enip(frame)
    assert result is not None
    assert result["operation"] == "read"
    assert result["summary"] == "read_tag"
    assert result["fields"]["path"]["tag_name"] == "Motor"


def test_parse_enip_write_tag_request():
    """Write Tag Service (0x4D) is operation='write'."""
    # CIP write: service=0x4D, path=empty (0 words), type=DINT(0xC4), count=1, value=42
    cip = bytes([0x4D, 0x00]) + struct.pack("<HHi", 0xC4, 1, 42)
    body = _send_rr_data_body(cip)
    frame = _enip_header(command=0x006F, data=body)
    result = parse_enip(frame)
    assert result is not None
    assert result["operation"] == "write"


def test_parse_enip_too_short_returns_none():
    """Payload shorter than 24 bytes returns None."""
    assert parse_enip(b"\x00" * 20) is None


def test_parse_encapsulation_header_fields():
    """Header fields are correctly extracted."""
    frame = _enip_header(command=0x006F, session=0xABCD)
    hdr = _parse_encapsulation_header(frame)
    assert hdr is not None
    assert hdr["command"] == 0x006F
    assert hdr["session_handle"] == 0xABCD


def test_parse_epath_symbolic_segment():
    """Symbolic EPATH 0x91 extracts tag name."""
    tag = b"Pump1"
    epath_bytes = bytes([0x91, len(tag)]) + tag
    if len(epath_bytes) % 2:
        epath_bytes += b"\x00"
    result = _parse_epath(epath_bytes, len(epath_bytes) // 2)
    assert result["tag_name"] == "Pump1"


def test_enip_response_read_tag_with_value():
    """Read Tag response with DINT value is decoded."""
    # CIP response: service=0x4C|0x80=0xCC, reserved=0, status=0, ext_status_size=0,
    # data_type=DINT(0xC4), value=99 (little-endian 4 bytes)
    cip = bytes([0xCC, 0x00, 0x00, 0x00]) + struct.pack("<Hi", 0xC4, 99)
    body = _send_rr_data_body(cip)
    frame = _enip_header(command=0x006F, data=body)
    result = parse_enip(frame)
    assert result is not None
    assert result["operation"] == "read"
    assert result["fields"].get("value") == 99


def test_enip_tcp_port_constant():
    assert ENIP_TCP_PORT == 44818
