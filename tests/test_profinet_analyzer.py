"""
Tests for app/parsers/profinet_analyzer.py
"""
import pytest
from app.parsers.profinet_analyzer import (
    parse_profinet,
    _classify_frame_id,
    _parse_dcp,
    PROFINET_ETHERTYPE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_dcp_frame(service_id=5, service_type=0, xid=0x00000001, blocks=b""):
    """
    Build a minimal PROFINET DCP frame payload (starting after EtherType,
    i.e. starting with the 2-byte Frame ID for identify=0xFEFF).
    Layout: FrameID(2) | ServiceID(1) | ServiceType(1) | Xid(4) |
            ResponseDelay(2) | DcpDataLength(2) | blocks
    """
    frame_id = 0xFEFF  # DCP Identify Request
    response_delay = 0  # only in requests (service_type=0)
    header = bytes([service_id, service_type]) + xid.to_bytes(4, "big")
    if service_type == 0:  # request
        header += response_delay.to_bytes(2, "big")
    header += len(blocks).to_bytes(2, "big")
    return frame_id.to_bytes(2, "big") + header + blocks


def _cyclic_rt_frame(frame_id=0x8000):
    """Build a cyclic RT I/O frame payload (no DCP)."""
    return frame_id.to_bytes(2, "big") + b"\x00" * 4


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_profinet_dcp_identify_request():
    """DCP Identify Request (Frame ID 0xFEFF, service_id=5) is decoded."""
    payload = _build_dcp_frame(service_id=5, service_type=0)
    result = parse_profinet(payload)
    assert result is not None
    assert result["frame_id"] == 0xFEFF
    assert "dcp_identify" in result["summary"]
    assert result["operation"] == "discovery"


def test_parse_profinet_dcp_set_request():
    """DCP Set Request (service_id=4) is decoded as dcp_set."""
    payload = _build_dcp_frame(service_id=4, service_type=0)
    result = parse_profinet(payload)
    assert result is not None
    assert "dcp_set" in result["summary"]


def test_parse_profinet_dcp_get_request():
    """DCP Get Request (service_id=3) is decoded as dcp_get."""
    payload = _build_dcp_frame(service_id=3, service_type=0)
    result = parse_profinet(payload)
    assert result is not None
    assert "dcp_get" in result["summary"]


def test_parse_profinet_dcp_with_block():
    """DCP frame with one block records the block's option/suboption."""
    # Option 2, Suboption 2 = Station name block; length=4, data=ABCD
    block = bytes([0x02, 0x02, 0x00, 0x04]) + b"ABCD"
    payload = _build_dcp_frame(service_id=5, service_type=0, blocks=block)
    result = parse_profinet(payload)
    assert result is not None
    assert len(result["fields"]["blocks"]) == 1
    assert result["fields"]["blocks"][0]["option"] == 2


def test_parse_profinet_cyclic_rt_io():
    """Non-DCP frame IDs in cyclic range are classified as cyclic_rt_io_data."""
    payload = _cyclic_rt_frame(frame_id=0x8000)
    result = parse_profinet(payload)
    assert result is not None
    assert result["summary"] == "cyclic_rt_io_data"
    assert result["operation"] == "cyclic_io"


def test_parse_profinet_reserved_frame_id():
    """Frame IDs in the reserved/sync range are classified correctly."""
    payload = (0x0010).to_bytes(2, "big") + b"\x00" * 4
    result = parse_profinet(payload)
    assert result is not None
    assert result["summary"] == "reserved_or_sync"


def test_parse_profinet_too_short_returns_none():
    """Payload shorter than 2 bytes returns None."""
    assert parse_profinet(b"\xFE") is None


def test_classify_frame_id_cyclic_range():
    assert _classify_frame_id(0x5000) == "cyclic_rt_io_data"


def test_classify_frame_id_reserved_range():
    assert _classify_frame_id(0x0050) == "reserved_or_sync"


def test_profinet_ethertype_constant():
    assert PROFINET_ETHERTYPE == 0x8892
