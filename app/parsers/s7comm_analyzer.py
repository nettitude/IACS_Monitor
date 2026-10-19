"""
S7comm protocol analyzer (Siemens PLCs, ISO-on-TCP / RFC1006, port 102).

S7comm rides on top of two wrapper layers before the actual S7 payload
is reached:

    TPKT (4 bytes):  Version(1)=3 | Reserved(1)=0 | Length(2, BE, includes
                     these 4 bytes)
    COTP (variable): Length(1) | PDU Type(1) | ... (for a Data TPDU,
                     PDU Type is 0xF0 and there's a 1-byte TPDU number
                     after it; Connection Request/Confirm TPDUs, used
                     only during session setup, have a different and
                     longer structure that this parser doesn't decode -
                     see scope note below)
    S7 header:       Protocol ID(1)=0x32 | ROSCTR(1) | Redundancy ID(2) |
                     PDU Reference(2) | Parameter Length(2) | Data
                     Length(2) | [Error Class(1) Error Code(1) - ack/
                     ack-data only] | Parameter | Data

CONFIDENCE NOTE (read before trusting this for anything safety-critical):
The TPKT/COTP/S7-header framing and the ROSCTR/function-code tables
below are long-standing, widely cross-referenced values (Wireshark's
s7comm dissector, Snap7, and general ICS security literature all agree
on them), so those are implemented with confidence. The per-item
address decode (area code, DB number, byte/bit offset) for Read/Write
Var requests is also a stable, well-documented structure and is
implemented in full. What is NOT implemented with the same confidence:
the exact byte-vs-bit unit semantics of the "length" field in Data
items for Write Var requests and Read Var responses varies by the
item's transport-size code in ways this module doesn't convert - the
raw transport-size code and raw byte count are reported as-is rather
than asserting a specific bit/byte interpretation that could be wrong
for some type codes. If you need exact value decoding (not just "which
address was written"), verify the transport-size table against a real
capture or the official S7comm protocol documentation before relying on
it.
"""
from typing import Optional

S7COMM_TCP_PORT = 102

ROSCTR_TYPES = {
    0x01: "job_request",
    0x02: "ack",
    0x03: "ack_data",
    0x07: "userdata",
}

FUNCTION_CODES = {
    0x04: "read_var",
    0x05: "write_var",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_control",  # covers both start and a subset of stop variants
    0x29: "plc_stop",
    0xF0: "setup_communication",
}

# High-impact function codes (T3-33): block download/upload is a program
# transfer ("program"), PLC stop / PLC control (start, copy RAM to ROM,
# compress, ...) changes the CPU run state ("control"). Reported with those
# operation values - never "other" - so traffic findings flag them.
_PROGRAM_FUNCTION_CODES = frozenset({0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F})
_CONTROL_FUNCTION_CODES = frozenset({0x28, 0x29})

_AREA_CODES = {
    0x81: "input",       # I
    0x82: "output",      # Q
    0x83: "bit_memory",  # M
    0x84: "db",          # data block
    0x85: "instance_db", # DI (instance data block)
    # Counter/timer area codes exist (older S5-style addressing) but
    # aren't included here with confidence - unrecognized codes fall
    # back to a hex label rather than a guessed name.
}

_TRANSPORT_SIZE_NAMES = {
    0x01: "bit",
    0x02: "byte",
    0x03: "char",
    0x04: "word",
    0x05: "int",
    0x06: "dword",
    0x07: "dint",
    0x08: "real",
    0x09: "date",
    0x0A: "time_of_day",
    0x0B: "time",
    0x0E: "date_and_time",
}


def _parse_tpkt_cotp(payload: bytes) -> Optional[tuple]:
    """
    Strip TPKT + COTP headers, returning (s7_payload, tpkt_length) or
    None if this doesn't look like a Data TPDU carrying S7 traffic.
    Connection-setup TPDUs (COTP Connection Request/Confirm, used only
    during the initial ISO-on-TCP handshake) have a different structure
    and aren't decoded - they carry no S7comm payload anyway.
    """
    if len(payload) < 7 or payload[0] != 0x03:
        return None  # not TPKT (version must be 3)

    tpkt_length = int.from_bytes(payload[1:3], "big")
    cotp_length = payload[4]
    cotp_pdu_type = payload[5] & 0xF0  # high nibble is PDU type for most types

    if cotp_pdu_type != 0xF0:
        return None  # not a Data TPDU (e.g. Connection Request/Confirm)

    # Data TPDU: Length(1) | PDU Type+Flags(1) | TPDU Number(1) -> 3 bytes
    # of COTP header after the 4-byte TPKT header.
    s7_start = 4 + 1 + cotp_length  # TPKT(4) + COTP length-field(1) + rest-of-COTP(cotp_length)
    if s7_start >= len(payload):
        return None
    return payload[s7_start:], tpkt_length


def _parse_item_spec(data: bytes, offset: int) -> Optional[dict]:
    """
    Parse one S7ANY variable-specification item (used in both Read Var
    and Write Var requests): 10 bytes starting with spec type 0x12.
    """
    if offset + 10 > len(data):
        return None
    if data[offset] != 0x12:
        return None  # not an S7ANY spec - other addressing modes exist but aren't decoded here

    length_of_spec = data[offset + 1]
    syntax_id = data[offset + 2]
    transport_size_code = data[offset + 3]
    num_elements = int.from_bytes(data[offset + 4:offset + 6], "big")
    db_number = int.from_bytes(data[offset + 6:offset + 8], "big")
    area_code = data[offset + 8]
    address_raw = int.from_bytes(data[offset + 9:offset + 12], "big") if offset + 12 <= len(data) else 0

    byte_offset = address_raw >> 3
    bit_offset = address_raw & 0x07

    return {
        "syntax_id": syntax_id,
        "transport_size": _TRANSPORT_SIZE_NAMES.get(transport_size_code, f"unknown_{transport_size_code:#x}"),
        "num_elements": num_elements,
        "area": _AREA_CODES.get(area_code, f"unknown_area_{area_code:#x}"),
        "db_number": db_number if area_code == 0x84 else None,
        "byte_offset": byte_offset,
        "bit_offset": bit_offset,
        "_consumed": 12,
    }


def _parse_szl_response(param_bytes: bytes, data_bytes: bytes) -> Optional[dict]:
    """Userdata parameter: 00 01 12, length, method (0x12 = response), type /
    function group (0x44 = response, CPU functions), subfunction (0x01 read
    SZL), sequence ...  Data: return code, transport size, length, SZL-ID,
    index, then (responses) list length, list count and the entries."""
    if len(param_bytes) < 8 or param_bytes[:3] != b"\x00\x01\x12":
        return None
    if param_bytes[4] != 0x12 or (param_bytes[5] & 0x0F) != 0x04 or param_bytes[6] != 0x01:
        return None
    if len(data_bytes) < 12 or data_bytes[0] != 0xFF:
        return None
    szl_id = int.from_bytes(data_bytes[4:6], "big")
    entry_len = int.from_bytes(data_bytes[8:10], "big")
    count = int.from_bytes(data_bytes[10:12], "big")
    body = data_bytes[12:]
    out = {"szl_id": f"{szl_id:#06x}", "source": "s7_szl"}
    if szl_id == 0x0011 and entry_len >= 28:
        for i in range(min(count, 16)):
            e = body[i * entry_len:(i + 1) * entry_len]
            if len(e) < 28:
                break
            idx = int.from_bytes(e[0:2], "big")
            mlfb = e[2:22].decode("ascii", "replace").strip("\x00 ")
            ausbg = int.from_bytes(e[24:26], "big")
            ausbe = int.from_bytes(e[26:28], "big")
            # Ausbg: 'V' (0x56) in the high byte, major in the low byte; Ausbe: minor.patch
            ver = f"V{ausbg & 0xFF}.{ausbe >> 8}.{ausbe & 0xFF}"
            if idx == 0x0001 and mlfb:
                out["order_number"] = mlfb
                out["hardware_version"] = ver
            elif idx == 0x0006:
                out["firmware_version"] = ver
    elif szl_id == 0x001C and entry_len >= 34:
        for i in range(min(count, 16)):
            e = body[i * entry_len:(i + 1) * entry_len]
            if len(e) < 34:
                break
            idx = int.from_bytes(e[0:2], "big")
            name = e[2:34].decode("ascii", "replace").strip("\x00 ")
            # SZL 0x001C indexes: 1 automation system name, 2 module name, 3 plant designation,
            # 5 module serial number, 7 module type name
            if idx == 0x0001 and name:
                out["plc_name"] = name
            elif idx == 0x0002 and name:
                out["module_name"] = name
            elif idx == 0x0005 and name:
                out["serial_number"] = name
            elif idx == 0x0007 and name:
                out["module_type"] = name
    else:
        return None
    return out if len(out) > 2 else None


def parse_s7comm(payload: bytes) -> Optional[dict]:
    """
    Parse a single S7comm frame, including its TPKT/COTP wrapper.
    Returns None if this doesn't look like S7comm traffic (wrong TPKT
    version, not a Data TPDU, or wrong S7 protocol ID byte).
    """
    stripped = _parse_tpkt_cotp(payload)
    if stripped is None:
        return None
    s7_payload, _tpkt_length = stripped

    if len(s7_payload) < 10 or s7_payload[0] != 0x32:
        return None  # not S7comm (protocol ID must be 0x32)

    rosctr_code = s7_payload[1]
    rosctr = ROSCTR_TYPES.get(rosctr_code, f"unknown_{rosctr_code:#x}")
    pdu_reference = int.from_bytes(s7_payload[4:6], "big")
    param_length = int.from_bytes(s7_payload[6:8], "big")
    data_length = int.from_bytes(s7_payload[8:10], "big")

    header_len = 10
    error_class = error_code = None
    if rosctr_code in (0x02, 0x03):  # ack / ack-data carry a 2-byte error field
        if len(s7_payload) >= 12:
            error_class, error_code = s7_payload[10], s7_payload[11]
        header_len = 12

    param_start = header_len
    param_bytes = s7_payload[param_start:param_start + param_length]
    data_bytes = s7_payload[param_start + param_length:param_start + param_length + data_length]

    result = {
        "rosctr": rosctr,
        "pdu_reference": pdu_reference,
        "direction": "response" if rosctr_code in (0x02, 0x03) else "request",
        "fields": {},
    }
    if error_class is not None:
        result["fields"]["error_class"] = error_class
        result["fields"]["error_code"] = error_code

    if not param_bytes:
        result["summary"] = "no_parameter"
        return result

    if rosctr_code == 0x07:
        # batch C (owner 2026-10-15): userdata - a read-SZL response carrying the
        # module identification (0x0011: order number / firmware) or the component
        # identification (0x001C: PLC / module name) is version evidence (AST-02).
        result["summary"] = "userdata"
        result["operation"] = "other"
        if len(param_bytes) >= 5 and param_bytes[4] == 0x12:
            result["direction"] = "response"
        ident = _parse_szl_response(param_bytes, data_bytes)
        if ident:
            result["identity"] = ident
            result["direction"] = "response"
            result["summary"] = f"read_szl_{ident['szl_id']}"
        return result

    function_code = param_bytes[0]
    fn_name = FUNCTION_CODES.get(function_code, f"unknown_fc_{function_code:#x}")
    result["summary"] = fn_name

    if function_code in (0x04, 0x05) and len(param_bytes) >= 2:  # Read Var / Write Var
        result["operation"] = "read" if function_code == 0x04 else "write"
        item_count = param_bytes[1]
        items = []
        offset = 2
        for _ in range(item_count):
            item = _parse_item_spec(param_bytes, offset)
            if item is None:
                break
            offset += item.pop("_consumed")
            items.append(item)
        result["fields"]["item_count"] = item_count
        result["fields"]["items"] = items
        if data_bytes:
            result["fields"]["data_raw_hex"] = data_bytes.hex()
            result["fields"]["data_byte_length"] = len(data_bytes)
    else:
        if function_code in _PROGRAM_FUNCTION_CODES:
            result["operation"] = "program"
        elif function_code in _CONTROL_FUNCTION_CODES:
            result["operation"] = "control"
        else:
            result["operation"] = "other"
        if param_bytes:
            result["fields"]["parameter_raw_hex"] = param_bytes.hex()
        if data_bytes:
            result["fields"]["data_raw_hex"] = data_bytes.hex()

    return result
