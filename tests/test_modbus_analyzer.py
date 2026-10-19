"""
Tests for app/parsers/modbus_analyzer.py
"""
import pytest
from app.parsers.modbus_analyzer import (
    parse_modbus_tcp,
    _decode_registers,
    MODBUS_TCP_PORT,
    FUNCTION_CODES,
    MODBUS_EXCEPTIONS,
)


# ---------------------------------------------------------------------------
# Helpers to build minimal Modbus/TCP frames
# ---------------------------------------------------------------------------

def _mbap(transaction_id=1, unit_id=1, function_code=3, data=b""):
    """Build a minimal MBAP header + PDU."""
    pdu = bytes([function_code]) + data
    length = 1 + 1 + len(data)  # unit_id + function_code + data
    header = (
        transaction_id.to_bytes(2, "big")
        + b"\x00\x00"           # protocol id = 0
        + length.to_bytes(2, "big")
        + bytes([unit_id])
    )
    return header + pdu


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_modbus_tcp_read_holding_registers_request():
    """FC 3 request decodes start_address and quantity."""
    payload = _mbap(transaction_id=1, unit_id=1, function_code=3,
                    data=b"\x00\x0A\x00\x05")  # start=10, qty=5
    result = parse_modbus_tcp(payload, is_request=True)
    assert result is not None
    assert result["function_code"] == 3
    assert result["operation"] == "read"
    assert result["summary"] == "read_holding_registers"
    assert result["direction"] == "request"
    assert result["fields"]["start_address"] == 10
    assert result["fields"]["quantity"] == 5


def test_parse_modbus_tcp_write_single_register():
    """FC 6 write single register request."""
    payload = _mbap(transaction_id=2, unit_id=1, function_code=6,
                    data=b"\x00\x01\x00\xFF")  # address=1, value=255
    result = parse_modbus_tcp(payload, is_request=True)
    assert result is not None
    assert result["operation"] == "write"
    assert result["summary"] == "write_single_register"
    assert result["fields"]["address"] == 1
    assert result["fields"]["value"] == 255


def test_parse_modbus_tcp_write_multiple_registers_request():
    """FC 16 write multiple registers includes start address, quantity, and values."""
    # 2 registers: 0x0064 (100) and 0x00C8 (200)
    data = b"\x00\x00\x00\x02\x04\x00\x64\x00\xC8"
    payload = _mbap(transaction_id=3, unit_id=1, function_code=16, data=data)
    result = parse_modbus_tcp(payload, is_request=True)
    assert result is not None
    assert result["operation"] == "write"
    assert result["fields"]["start_address"] == 0
    assert result["fields"]["quantity"] == 2
    assert 100 in result["fields"]["values"]
    assert 200 in result["fields"]["values"]


def test_parse_modbus_tcp_exception_response():
    """Exception response (FC | 0x80) is parsed correctly."""
    # FC 3 exception, code 2 = illegal_data_address
    payload = _mbap(function_code=0x83, data=b"\x02")
    result = parse_modbus_tcp(payload, is_request=False)
    assert result is not None
    assert result["operation"] == "exception"
    assert result["direction"] == "response"
    assert result["fields"]["exception_code"] == 2
    assert result["fields"]["exception_name"] == "illegal_data_address"


def test_parse_modbus_tcp_unknown_function_code():
    """Unrecognized function code falls back to raw hex, no crash."""
    payload = _mbap(function_code=0x42, data=b"\xDE\xAD")
    result = parse_modbus_tcp(payload, is_request=True)
    assert result is not None
    assert result["operation"] == "other"
    assert "raw_hex" in result["fields"]


def test_parse_modbus_tcp_too_short_returns_none():
    """Payload shorter than 8 bytes returns None."""
    assert parse_modbus_tcp(b"\x00\x01\x00\x00\x00", is_request=True) is None


def test_parse_modbus_tcp_wrong_protocol_id_returns_none():
    """Protocol ID != 0 returns None (not Modbus)."""
    bad = b"\x00\x01\xFF\xFF\x00\x06\x01\x03\x00\x00\x00\x0A"
    assert parse_modbus_tcp(bad, is_request=True) is None


def test_decode_registers_basic():
    """_decode_registers splits bytes into big-endian 16-bit values."""
    data = b"\x00\x64\x01\x00"  # 100, 256
    assert _decode_registers(data) == [100, 256]


def test_write_single_coil_on():
    """FC 5 coil value 0xFF00 maps to 'ON'."""
    payload = _mbap(function_code=5, data=b"\x00\x01\xFF\x00")
    result = parse_modbus_tcp(payload, is_request=True)
    assert result is not None
    assert result["fields"]["value"] == "ON"


def test_modbus_tcp_port_constant():
    assert MODBUS_TCP_PORT == 502
