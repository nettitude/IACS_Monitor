"""
EtherNet/IP (ENIP) + CIP protocol analyzer.

EtherNet/IP is the encapsulation protocol; CIP (Common Industrial
Protocol) is the application layer riding inside it. This is the
protocol Rockwell/Allen-Bradley PLCs (ControlLogix, CompactLogix,
MicroLogix, and the "Allen-Bradley" brand generally - Allen-Bradley is
Rockwell Automation's product brand, not a separate protocol) use for
explicit messaging, and is also used by other ODVA-compliant CIP
devices more broadly.

    ENIP Encapsulation Header (24 bytes):
        Command(2,LE) | Length(2,LE) | Session Handle(4,LE) |
        Status(4,LE) | Sender Context(8) | Options(4,LE)

    For SendRRData/SendUnitData, the command-specific data is:
        Interface Handle(4,LE) | Timeout(2,LE) | CPF Item Count(2,LE) |
        [Item Type(2,LE) | Item Length(2,LE) | Item Data] ...

    The CIP message lives inside the "data item" (type 0x00B2
    Unconnected, or 0x00B1 Connected) and starts with a Service byte
    (high bit set = response) followed by a request path (EPATH) and
    service-specific data.

CONFIDENCE NOTE: the ENIP encapsulation header, CPF item framing, the
request/response bit on the CIP service byte, and Rockwell's four
Logix5000 tag-service codes (Read/Write Tag, Read/Write Tag Fragmented)
are all extremely well and consistently documented (ODVA's public CIP
spec, Wireshark's cip/enip dissectors, and widely-used open-source
tools like pycomm3/pylogix all agree). Those are implemented with
confidence, including symbolic-segment tag-name extraction, which is
the actual "what got read/written" answer this tool needs.

What is NOT implemented with the same confidence: the full CIP general
status-code table (dozens of codes exist; only the handful seen most
often in practice are mapped, with a numeric fallback for the rest),
and the elementary-data-type table beyond the common numeric types
(BOOL/SINT/INT/DINT/LINT, the unsigned USINT/UINT/UDINT/ULINT and
REAL/LREAL floats - decoded by type code, T3-31) - less common CIP types fall back to a
type-code label plus raw hex rather than a guessed conversion. Fully
generic EPATH decoding (logical segments beyond class/instance/
attribute, or non-symbolic addressing) also isn't implemented - the
request path is preserved as raw hex when it isn't a plain Class+
Instance+Symbolic pattern.
"""
import struct
from typing import Optional

ENIP_TCP_PORT = 44818
ENIP_UDP_IO_PORT = 2222

ENCAPSULATION_COMMANDS = {
    0x0001: "nop",
    0x0004: "list_services",
    0x0063: "list_identity",
    0x0064: "list_interfaces",
    0x0065: "register_session",
    0x0066: "unregister_session",
    0x006F: "send_rr_data",
    0x0070: "send_unit_data",
}

# Rockwell/Allen-Bradley Logix5000 vendor-specific tag services (the
# "read/write and data" case this tool cares about most for CIP).
CIP_SERVICE_CODES = {
    0x01: "get_attributes_all",
    0x0E: "get_attribute_single",
    0x10: "set_attribute_single",
    0x4C: "read_tag",
    0x4D: "write_tag",
    0x4E: "read_tag_fragmented",
    0x4F: "write_tag_fragmented",
}

CIP_GENERAL_STATUS = {
    0x00: "success",
    0x01: "connection_failure",
    0x05: "path_destination_unknown",
    0x08: "service_not_supported",
    0x0E: "attribute_not_settable",
    0x13: "not_enough_data",
    0x1E: "embedded_service_error",
    0xFF: "general_error",
}

# CIP elementary data types (only the common numeric ones - see module
# docstring on confidence scope).
CIP_DATA_TYPES = {
    0xC1: ("bool", 1),
    0xC2: ("sint", 1),
    0xC3: ("int", 2),
    0xC4: ("dint", 4),
    0xC5: ("lint", 8),
    0xC6: ("usint", 1),
    0xC7: ("uint", 2),
    0xC8: ("udint", 4),
    0xC9: ("ulint", 8),
    0xCA: ("real", 4),
    0xCB: ("lreal", 8),
}


# struct format per CIP elementary type (all little-endian on the wire).
_CIP_STRUCT_FORMATS = {
    0xC1: "<B",   # BOOL (one byte, 0 / non-zero)
    0xC2: "<b",   # SINT
    0xC3: "<h",   # INT
    0xC4: "<i",   # DINT
    0xC5: "<q",   # LINT
    0xC6: "<B",   # USINT
    0xC7: "<H",   # UINT
    0xC8: "<I",   # UDINT
    0xC9: "<Q",   # ULINT
    0xCA: "<f",   # REAL
    0xCB: "<d",   # LREAL
}

_MAX_DECODED_ELEMENTS = 64


def _decode_cip_values(type_code: int, value_bytes: bytes, element_count: Optional[int] = None) -> Optional[list]:
    """
    Decode CIP elementary-type values by their data type code (T3-31):
    REAL/LREAL as IEEE floats, U* types unsigned, BOOL as bool. Returns
    None when the type isn't an elementary numeric type or there aren't
    enough bytes for even one element.
    """
    fmt = _CIP_STRUCT_FORMATS.get(type_code)
    if fmt is None:
        return None
    size = struct.calcsize(fmt)
    available = len(value_bytes) // size
    if available == 0:
        return None
    n = available if element_count is None else min(max(element_count, 1), available)
    n = min(n, _MAX_DECODED_ELEMENTS)
    values = [struct.unpack_from(fmt, value_bytes, i * size)[0] for i in range(n)]
    if type_code == 0xC1:
        values = [bool(v) for v in values]
    return values


def _set_decoded_value(fields: dict, type_code: int, value_bytes: bytes, element_count: Optional[int] = None) -> None:
    values = _decode_cip_values(type_code, value_bytes, element_count)
    if values is None:
        fields["value_raw_hex"] = value_bytes.hex()
        return
    fields["value"] = values[0]
    if len(values) > 1:
        fields["values"] = values


def _parse_encapsulation_header(payload: bytes) -> Optional[dict]:
    if len(payload) < 24:
        return None
    command = int.from_bytes(payload[0:2], "little")
    length = int.from_bytes(payload[2:4], "little")
    session_handle = int.from_bytes(payload[4:8], "little")
    status = int.from_bytes(payload[8:12], "little")
    return {
        "command": command,
        "command_name": ENCAPSULATION_COMMANDS.get(command, f"unknown_{command:#06x}"),
        "length": length,
        "session_handle": session_handle,
        "status": status,
        "data": payload[24:24 + length],
    }


def _parse_identity_reply(data: bytes) -> Optional[dict]:
    """The CIP Identity item (type 0x000C) of a ListIdentity reply: encap
    version (2), socket address (16), vendor id (2), device type (2), product
    code (2), revision major / minor (1 + 1), status (2), serial (4), product
    name (1 + n), state (1).  None when the reply holds no identity item."""
    for item in _parse_cpf_items(data):
        if item["type"] != 0x000C:
            continue
        d = item["data"]
        if len(d) < 33:
            return None
        vendor_id = int.from_bytes(d[18:20], "little")
        device_type = int.from_bytes(d[20:22], "little")
        product_code = int.from_bytes(d[22:24], "little")
        rev_major, rev_minor = d[24], d[25]
        serial = int.from_bytes(d[28:32], "little")
        name_len = d[32]
        name = d[33:33 + name_len].decode("ascii", "replace").strip()
        return {"vendor_id": vendor_id, "device_type": device_type, "product_code": product_code,
                "revision": f"{rev_major}.{rev_minor:03d}", "serial_number": f"{serial:08x}",
                "product_name": name, "source": "cip_identity"}
    return None


def _parse_cpf_items(data: bytes) -> list:
    """
    Parse Common Packet Format items out of a SendRRData/SendUnitData
    command's data section (after the 4-byte interface handle and
    2-byte timeout that precede the CPF item count).
    """
    if len(data) < 2:
        return []
    item_count = int.from_bytes(data[0:2], "little")
    items = []
    offset = 2
    for _ in range(item_count):
        if offset + 4 > len(data):
            break
        item_type = int.from_bytes(data[offset:offset + 2], "little")
        item_length = int.from_bytes(data[offset + 2:offset + 4], "little")
        item_data = data[offset + 4:offset + 4 + item_length]
        items.append({"type": item_type, "data": item_data})
        offset += 4 + item_length
    return items


def _parse_epath(data: bytes, path_word_length: int) -> dict:
    """
    Parse a CIP request path (EPATH). Only the two common patterns are
    decoded: Class(0x20)+Instance(0x24) logical segments, and Symbolic
    segment (0x91) tag names (ANSI extended symbol) - the latter is
    what Rockwell's Read/Write Tag Service actually uses to name the
    tag being accessed. Anything else is preserved as raw hex.
    """
    path_bytes = data[:path_word_length * 2]
    result = {"class_id": None, "instance_id": None, "tag_name": None, "raw_hex": None}

    offset = 0
    matched_known_segment = False
    while offset < len(path_bytes):
        segment_type = path_bytes[offset]
        if segment_type == 0x20 and offset + 2 <= len(path_bytes):  # 8-bit class segment
            result["class_id"] = path_bytes[offset + 1]
            offset += 2
            matched_known_segment = True
        elif segment_type == 0x24 and offset + 2 <= len(path_bytes):  # 8-bit instance segment
            result["instance_id"] = path_bytes[offset + 1]
            offset += 2
            matched_known_segment = True
        elif segment_type == 0x91 and offset + 2 <= len(path_bytes):  # ANSI extended symbol (tag name)
            name_length = path_bytes[offset + 1]
            name_bytes = path_bytes[offset + 2:offset + 2 + name_length]
            result["tag_name"] = name_bytes.decode("ascii", errors="replace")
            offset += 2 + name_length
            if offset % 2:  # symbolic segments pad to an even length
                offset += 1
            matched_known_segment = True
        else:
            break

    if not matched_known_segment or offset < len(path_bytes):
        result["raw_hex"] = path_bytes.hex()

    return result


def _parse_cip_message(data: bytes) -> Optional[dict]:
    if len(data) < 2:
        return None

    service_byte = data[0]
    is_response = bool(service_byte & 0x80)
    service_code = service_byte & 0x7F
    service_name = CIP_SERVICE_CODES.get(service_code, f"unknown_service_{service_code:#04x}")

    result = {
        "service_code": service_code,
        "service_name": service_name,
        "direction": "response" if is_response else "request",
        "fields": {},
    }

    if is_response:
        if len(data) < 4:
            return result
        general_status = data[2]
        extended_status_size = data[3]  # in 16-bit words
        result["fields"]["general_status"] = CIP_GENERAL_STATUS.get(
            general_status, f"unknown_{general_status:#04x}"
        )
        offset = 4 + extended_status_size * 2
        remaining = data[offset:]

        if service_code in (0x4C, 0x4E) and len(remaining) >= 2:  # Read Tag (Fragmented) response
            data_type_code = int.from_bytes(remaining[0:2], "little")
            type_name, _type_size = CIP_DATA_TYPES.get(data_type_code, (f"unknown_{data_type_code:#06x}", None))
            value_bytes = remaining[2:]
            result["fields"]["data_type"] = type_name
            _set_decoded_value(result["fields"], data_type_code, value_bytes)
        elif remaining:
            result["fields"]["data_raw_hex"] = remaining.hex()

        result["operation"] = "read" if service_code in (0x4C, 0x4E) else (
            "write" if service_code in (0x4D, 0x4F) else "other"
        )
        return result

    # Request
    if len(data) < 2:
        return result
    path_word_length = data[1]
    path_bytes_end = 2 + path_word_length * 2
    epath = _parse_epath(data[2:path_bytes_end], path_word_length)
    result["fields"]["path"] = epath
    remainder = data[path_bytes_end:]

    if service_code == 0x4C:  # Read Tag Service request: just an element count
        result["operation"] = "read"
        if len(remainder) >= 2:
            result["fields"]["element_count"] = int.from_bytes(remainder[0:2], "little")
    elif service_code == 0x4D:  # Write Tag Service request: type + count + data
        result["operation"] = "write"
        if len(remainder) >= 4:
            data_type_code = int.from_bytes(remainder[0:2], "little")
            element_count = int.from_bytes(remainder[2:4], "little")
            type_name, _type_size = CIP_DATA_TYPES.get(data_type_code, (f"unknown_{data_type_code:#06x}", None))
            result["fields"]["data_type"] = type_name
            result["fields"]["element_count"] = element_count
            value_bytes = remainder[4:]
            _set_decoded_value(result["fields"], data_type_code, value_bytes, element_count)
    else:
        result["operation"] = "other"
        if remainder:
            result["fields"]["data_raw_hex"] = remainder.hex()

    return result


def parse_enip(payload: bytes) -> Optional[dict]:
    """
    Parse a single EtherNet/IP encapsulation frame. Returns a dict
    describing the encapsulation command, and - for SendRRData/
    SendUnitData carrying a CIP data item - the decoded CIP message.
    Returns None if this doesn't look like a valid ENIP frame.
    """
    header = _parse_encapsulation_header(payload)
    if header is None:
        return None

    result = {
        "command": header["command_name"],
        "session_handle": header["session_handle"],
        "status": header["status"],
    }

    if header["command"] == 0x0063 and header["data"]:
        # batch C (owner 2026-10-15): a ListIdentity REPLY carries the device's
        # identity (vendor id, product code, revision, serial, product name) -
        # the capture's version evidence for the asset inventory (AST-02).
        result["summary"] = header["command_name"]
        result["operation"] = "other"
        result["fields"] = {}
        ident = _parse_identity_reply(header["data"])
        if ident:
            result["identity"] = ident
            result["direction"] = "response"
            result["summary"] = "list_identity_reply"
        return result
    if header["command"] not in (0x006F, 0x0070):
        result["summary"] = header["command_name"]
        result["operation"] = "other"
        result["fields"] = {}
        return result

    cmd_data = header["data"]
    if len(cmd_data) < 6:
        result["summary"] = header["command_name"]
        result["operation"] = "other"
        result["fields"] = {}
        return result

    cpf_data = cmd_data[6:]  # skip 4-byte interface handle + 2-byte timeout
    items = _parse_cpf_items(cpf_data)

    cip_message = None
    for item in items:
        if item["type"] in (0x00B2, 0x00B1):  # Unconnected / Connected data item
            cip_message = _parse_cip_message(item["data"])
            break

    if cip_message is None:
        result["summary"] = header["command_name"]
        result["operation"] = "other"
        result["fields"] = {}
        return result

    result["summary"] = cip_message["service_name"]
    result["direction"] = cip_message["direction"]
    result["operation"] = cip_message.get("operation", "other")
    result["fields"] = cip_message["fields"]
    return result
