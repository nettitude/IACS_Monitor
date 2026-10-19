"""
Tests for app/parsers/s7comm_analyzer.py
"""
import pytest
from app.parsers.s7comm_analyzer import (
    parse_s7comm,
    _parse_tpkt_cotp,
    S7COMM_TCP_PORT,
    FUNCTION_CODES,
    ROSCTR_TYPES,
)


# ---------------------------------------------------------------------------
# Frame-building helpers
# ---------------------------------------------------------------------------

def _build_s7_frame(rosctr=0x01, function_code=0x04, param_extra=b"", data=b""):
    """
    Build a minimal valid TPKT+COTP+S7comm frame.

    TPKT:  03 00 <total_length 2 BE>
    COTP:  02 F0 80  (length=2, Data PDU, TPDU#=0x80)
    S7:    32 <rosctr> 00 00 <pdu_ref 2> <param_len 2> <data_len 2>
           <function_code> <param_extra> <data>
    """
    s7_param = bytes([function_code]) + param_extra
    s7_header = (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"  # redundancy id
        + b"\x00\x01"  # pdu reference
        + len(s7_param).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
    )
    s7_payload = s7_header + s7_param + data
    cotp = b"\x02\xF0\x80"
    tpkt_len = 4 + len(cotp) + len(s7_payload)
    tpkt = b"\x03\x00" + tpkt_len.to_bytes(2, "big")
    return tpkt + cotp + s7_payload


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_s7comm_read_var_request():
    """FC 0x04 (read_var) with zero items decodes as a read request."""
    # param: fc(1) + item_count(1) = 2 bytes
    frame = _build_s7_frame(rosctr=0x01, function_code=0x04, param_extra=b"\x00")
    result = parse_s7comm(frame)
    assert result is not None
    assert result["summary"] == "read_var"
    assert result["operation"] == "read"
    assert result["direction"] == "request"


def test_parse_s7comm_write_var_request():
    """FC 0x05 (write_var) is an operation='write'."""
    frame = _build_s7_frame(rosctr=0x01, function_code=0x05, param_extra=b"\x00")
    result = parse_s7comm(frame)
    assert result is not None
    assert result["summary"] == "write_var"
    assert result["operation"] == "write"


def test_parse_s7comm_plc_stop():
    """FC 0x29 (plc_stop) is a high-impact operation='control' (T3-33), not 'other'."""
    frame = _build_s7_frame(rosctr=0x01, function_code=0x29)
    result = parse_s7comm(frame)
    assert result is not None
    assert result["summary"] == "plc_stop"
    assert result["operation"] == "control"


@pytest.mark.parametrize("fc", [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
def test_parse_s7comm_block_transfer_is_program(fc):
    """Block download/upload FCs 0x1A-0x1F are operation='program' (T3-33)."""
    result = parse_s7comm(_build_s7_frame(rosctr=0x01, function_code=fc))
    assert result["operation"] == "program"


def test_parse_s7comm_ack_data_response():
    """ROSCTR 0x03 (ack_data) is a response direction."""
    # ack_data needs 2 extra bytes for error_class + error_code
    s7_param = bytes([0x04]) + b"\x00"  # fc=read_var, 0 items
    s7_header = (
        b"\x32\x03\x00\x00\x00\x01"
        + len(s7_param).to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x00"  # error_class, error_code
    )
    s7_payload = s7_header + s7_param
    cotp = b"\x02\xF0\x80"
    tpkt_len = 4 + len(cotp) + len(s7_payload)
    tpkt = b"\x03\x00" + tpkt_len.to_bytes(2, "big")
    frame = tpkt + cotp + s7_payload
    result = parse_s7comm(frame)
    assert result is not None
    assert result["direction"] == "response"


def test_parse_s7comm_unknown_function_code():
    """Unrecognized function code doesn't crash; operation is 'other'."""
    frame = _build_s7_frame(function_code=0x77)
    result = parse_s7comm(frame)
    assert result is not None
    assert result["operation"] == "other"
    assert "unknown_fc" in result["summary"]


def test_parse_s7comm_too_short_returns_none():
    """Payload shorter than TPKT header returns None."""
    assert parse_s7comm(b"\x03\x00\x00\x0A") is None


def test_parse_s7comm_wrong_tpkt_version_returns_none():
    """Wrong TPKT version byte (not 0x03) returns None."""
    bad = b"\x02\x00\x00\x15" + b"\x00" * 17
    assert parse_s7comm(bad) is None


def test_parse_tpkt_cotp_non_data_pdu_returns_none():
    """COTP PDU type != 0xF0 (Data) returns None (connection setup frames)."""
    # COTP PDU type 0xE0 = Connection Request
    tpkt = b"\x03\x00\x00\x0B"
    cotp = b"\x06\xE0\x00\x00\x00\x00\x00"
    result = _parse_tpkt_cotp(tpkt + cotp)
    assert result is None


def test_s7comm_tcp_port_constant():
    assert S7COMM_TCP_PORT == 102
