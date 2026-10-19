"""
Tests for app/parsers/smb_analyzer.py
"""
import pytest
from app.parsers.smb_analyzer import (
    sniff_smb,
    SMB1_SIG,
    SMB2_SIG,
    SMB1_COMMANDS,
    SMB2_COMMANDS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _smb1_frame(command=0x72):
    """Build a minimal SMBv1 frame starting with the 4-byte signature."""
    # sig(4) + command(1) + status(4) + flags(1) + flags2(2) + rest padding
    return SMB1_SIG + bytes([command]) + b"\x00" * 20


def _smb2_frame(command=0x0000):
    """
    Build a minimal SMB2 frame.
    SMB2 header: sig(4) + StructureSize(2) + CreditCharge(2) + Status(4) +
                 Command(2,LE) + CreditRequest(2) + Flags(4) + NextCommand(4) +
                 MessageId(8) + ProcessId(4) + TreeId(4) + SessionId(8) + Signature(16)
    Command is at offset 12 from start (after sig).
    """
    header = SMB2_SIG + b"\x00" * 8  # sig + 8 bytes (StructureSize+CreditCharge+Status)
    header += command.to_bytes(2, "little")  # command at offset 12
    header += b"\x00" * 30  # padding to full 64-byte header
    return header


def _netbios_wrap(smb_bytes):
    """Wrap SMB bytes with a 4-byte NetBIOS SESSION MESSAGE header."""
    length = len(smb_bytes)
    return bytes([0x00]) + length.to_bytes(3, "big") + smb_bytes


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_sniff_smb1_negotiate():
    """SMBv1 negotiate command (0x72) is correctly identified."""
    frame = _smb1_frame(command=0x72)
    result = sniff_smb(frame)
    assert result is not None
    assert result["version"] == "SMBv1"
    assert result["command"] == "negotiate"
    assert result["command_code"] == 0x72
    assert "SMBv1" in result["summary"]


def test_sniff_smb1_write_command():
    """SMBv1 write command (0x1D) is identified."""
    frame = _smb1_frame(command=0x1D)
    result = sniff_smb(frame)
    assert result is not None
    assert result["command"] == "write"


def test_sniff_smb1_unknown_command():
    """Unknown SMBv1 command byte returns fallback name."""
    frame = _smb1_frame(command=0xEE)
    result = sniff_smb(frame)
    assert result is not None
    assert result["version"] == "SMBv1"
    assert "unknown_0x" in result["command"]


def test_sniff_smb2_negotiate():
    """SMB2 negotiate (0x0000) is correctly identified."""
    frame = _smb2_frame(command=0x0000)
    result = sniff_smb(frame)
    assert result is not None
    assert result["version"] == "SMB2/3"
    assert result["smb2_command"] == "negotiate"
    assert "SMB2/3" in result["summary"]


def test_sniff_smb2_write():
    """SMB2 write (0x0009) is identified."""
    frame = _smb2_frame(command=0x0009)
    result = sniff_smb(frame)
    assert result is not None
    assert result["smb2_command"] == "write"
    assert result["smb2_command_code"] == 0x0009


def test_sniff_smb_netbios_wrapped_smb1():
    """NetBIOS-wrapped SMBv1 is detected and flagged as wrapped='netbios'."""
    smb = _smb1_frame(command=0x72)
    wrapped = _netbios_wrap(smb)
    result = sniff_smb(wrapped)
    assert result is not None
    assert result["version"] == "SMBv1"
    assert result.get("wrapped") == "netbios"


def test_sniff_smb_netbios_wrapped_smb2():
    """NetBIOS-wrapped SMB2 is detected and flagged as wrapped='netbios'."""
    smb = _smb2_frame(command=0x0001)
    wrapped = _netbios_wrap(smb)
    result = sniff_smb(wrapped)
    assert result is not None
    assert result["version"] == "SMB2/3"
    assert result.get("wrapped") == "netbios"


def test_sniff_smb_empty_payload_returns_none():
    """Empty payload returns None."""
    assert sniff_smb(b"") is None


def test_sniff_smb_non_smb_payload_returns_none():
    """Random bytes that don't start with SMB signature return None."""
    assert sniff_smb(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08") is None


def test_smb1_sig_constant():
    assert SMB1_SIG == b"\xff\x53\x4d\x42"


def test_smb2_sig_constant():
    assert SMB2_SIG == b"\xfe\x53\x4d\x42"
