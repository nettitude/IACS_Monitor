"""
SMB version sniffer.

Detects whether a TCP payload on port 445 or 139 carries SMBv1 (legacy,
end-of-life per MS17-010/EternalBlue family) or SMB2/3 (current) traffic,
and extracts the SMB command byte where available.

Background
----------
Both SMB versions begin with a 4-byte protocol signature immediately after
any transport-layer framing:

  SMBv1  \xff\x53\x4d\x42  ('\\xffSMB')
  SMB2+  \xfe\x53\x4d\x42  ('\\xfeSMB')

Port 445 carries SMB directly over TCP; the signature appears at byte 0.

Port 139 carries SMB inside a NetBIOS Session Service (RFC 1002) wrapper:
  Bytes 0-3: 4-byte big-endian payload length (type 0x00 = SESSION MESSAGE)
  Bytes 4+:  the SMB header (signature at offset 4)

The SMBv1 header layout after the 4-byte signature:
  [4]  Command (1 byte)
  [5-8] NT Status (4 bytes)
  [9]  Flags
  [10-11] Flags2
  ...

SMB2 header layout:
  [4-5]  StructureSize (always 0x0040)
  [6-7]  Credit Charge
  [8-11] Status / Channel Sequence
  [12-13] Command (2 bytes, LE)

This module only surfaces what's needed for the security check:
  - version: "SMBv1" | "SMB2/3"
  - command / command_code: human-readable command name + numeric byte (SMBv1)
  - smb2_command / smb2_command_code: human-readable + numeric (SMB2/3)
  - wrapped: "netbios" when the 4-byte length prefix was present
  - summary: one-line human-readable string

Usage
-----
Called from pcap_parser._handle_tcp_protocols() on ports 445 and 139.
Returns None for any payload that doesn't look like SMB (short, wrong sig,
or decode error), so the caller can skip writing a ProtocolDetail row.
"""

# ── signature bytes ──────────────────────────────────────────────────────────
SMB1_SIG: bytes = b"\xff\x53\x4d\x42"   # \xffSMB
SMB2_SIG: bytes = b"\xfe\x53\x4d\x42"   # \xfeSMB

# ── SMBv1 command codes (most common; full list is 256 entries) ──────────────
SMB1_COMMANDS: dict[int, str] = {
    0x04: "close",
    0x06: "delete",
    0x08: "rename",
    0x09: "query_information",
    0x0b: "flush",
    0x0c: "delete_directory",
    0x0d: "open",
    0x1d: "write",
    0x1f: "lock_and_read",
    0x20: "write_and_unlock",
    0x22: "read_raw",
    0x23: "read_mpx",
    0x25: "write_raw",
    0x26: "write_mpx",
    0x29: "write_and_close",
    0x2e: "read",
    0x2f: "read_andx",
    0x31: "write_andx",
    0x32: "transaction2",
    0x33: "transaction2_secondary",
    0x34: "find_close2",
    0x50: "check_directory",
    0x52: "process_exit",
    0x53: "seek",
    0x54: "lock_and_read_andx",
    0x56: "old_lock_and_read",
    0x70: "tree_connect",
    0x71: "tree_disconnect",
    0x72: "negotiate",
    0x73: "session_setup_andx",
    0x74: "logoff_andx",
    0x75: "tree_connect_andx",
    0x80: "query_information_disk",
    0x81: "search",
    0x82: "find",
    0x83: "find_unique",
    0x84: "find_close",
    0xa0: "nt_transact",
    0xa1: "nt_transact_secondary",
    0xa2: "nt_create_andx",
    0xa4: "nt_cancel",
    0xa5: "nt_rename",
    0xc0: "open_print_file",
    0xc1: "write_print_file",
    0xc2: "close_print_file",
    0xc3: "get_print_queue",
    0xd8: "read_bulk",
    0xd9: "write_bulk",
    0xda: "write_bulk_data",
    0xfe: "invalid",
    0xff: "no_andx_command",
}

# ── SMB2 command codes ────────────────────────────────────────────────────────
SMB2_COMMANDS: dict[int, str] = {
    0x0000: "negotiate",
    0x0001: "session_setup",
    0x0002: "logoff",
    0x0003: "tree_connect",
    0x0004: "tree_disconnect",
    0x0005: "create",
    0x0006: "close",
    0x0007: "flush",
    0x0008: "read",
    0x0009: "write",
    0x000a: "lock",
    0x000b: "ioctl",
    0x000c: "cancel",
    0x000d: "echo",
    0x000e: "query_directory",
    0x000f: "change_notify",
    0x0010: "query_info",
    0x0011: "set_info",
    0x0012: "oplock_break",
}


def sniff_smb(payload: bytes) -> dict | None:
    """
    Inspect *payload* (raw TCP segment bytes) and return a dict describing
    the SMB version and command, or None if the payload doesn't look like
    SMB at all.

    The returned dict always contains:
        version         "SMBv1" or "SMB2/3"
        summary         one-line string

    For SMBv1 it also contains:
        command         human-readable command name (str)
        command_code    raw command byte (int, 0-255)

    For SMB2/3 it also contains:
        smb2_command        human-readable command name (str)
        smb2_command_code   raw command code (int, 16-bit LE from bytes 12-13)

    When a NetBIOS wrapper was detected:
        wrapped         "netbios"
    """
    if not payload:
        return None

    try:
        offset = 0
        wrapped = False

        # ── detect & skip NetBIOS Session Service header on port 139 ─────────
        # Type byte at offset 0 == 0x00 (SESSION MESSAGE), then 3 length bytes.
        # After stripping the 4-byte prefix the SMB signature must follow.
        if (
            len(payload) >= 9
            and payload[0] == 0x00          # SESSION MESSAGE type
            and (payload[4:8] == SMB1_SIG or payload[4:8] == SMB2_SIG)
        ):
            offset = 4
            wrapped = True

        sig_end = offset + 4

        if len(payload) < sig_end + 1:
            return None

        sig = payload[offset:sig_end]

        # ── SMBv1 ─────────────────────────────────────────────────────────────
        if sig == SMB1_SIG:
            cmd_byte = payload[sig_end]
            cmd_name = SMB1_COMMANDS.get(cmd_byte, f"unknown_0x{cmd_byte:02x}")
            result: dict = {
                "version": "SMBv1",
                "command": cmd_name,
                "command_code": cmd_byte,
                "summary": f"SMBv1 {cmd_name}",
            }
            if wrapped:
                result["wrapped"] = "netbios"
            return result

        # ── SMB2/3 ────────────────────────────────────────────────────────────
        if sig == SMB2_SIG:
            # SMB2 command is a 2-byte LE at header offset 12 (absolute offset+12)
            cmd_offset = offset + 12
            if len(payload) >= cmd_offset + 2:
                cmd_code = int.from_bytes(payload[cmd_offset:cmd_offset + 2], "little")
                cmd_name = SMB2_COMMANDS.get(cmd_code, f"unknown_0x{cmd_code:04x}")
            else:
                cmd_code = -1
                cmd_name = "unknown"

            result = {
                "version": "SMB2/3",
                "smb2_command": cmd_name,
                "smb2_command_code": cmd_code,
                "summary": f"SMB2/3 {cmd_name}",
            }
            if wrapped:
                result["wrapped"] = "netbios"
            return result

    except Exception:
        # Malformed packet bytes — treat as non-SMB
        return None

    return None
