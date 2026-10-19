"""
Modbus/TCP protocol analyzer.

Decodes a single Modbus/TCP frame (MBAP header + PDU) into a structured
dict suitable for storing as a ProtocolDetail row. This is intentionally
scoped to Modbus/TCP (not serial/RTU) since that's what shows up in
pcap captures.

Frame layout (Modbus Application Protocol, MBAP header is 7 bytes):

    [0:2]  Transaction Identifier
    [2:4]  Protocol Identifier   (always 0x0000 for Modbus)
    [4:6]  Length                (byte count of everything after this field)
    [6]    Unit Identifier
    [7]    Function Code
    [8:]   Data (function-code specific)

Reference for function codes: Modbus Application Protocol V1.1b3.
Only the function codes most commonly seen on ICS networks are decoded
in full; anything else falls back to a raw hex dump rather than
guessing at a structure.
"""
from typing import Optional

MODBUS_TCP_PORT = 502

# function_code -> (human_name, operation_kind)
FUNCTION_CODES = {
    1: ("read_coils", "read"),
    2: ("read_discrete_inputs", "read"),
    3: ("read_holding_registers", "read"),
    4: ("read_input_registers", "read"),
    5: ("write_single_coil", "write"),
    6: ("write_single_register", "write"),
    7: ("read_exception_status", "read"),
    15: ("write_multiple_coils", "write"),
    16: ("write_multiple_registers", "write"),
    22: ("mask_write_register", "write"),
    23: ("read_write_multiple_registers", "read_write"),
    43: ("encapsulated_interface_transport", "other"),
}

MODBUS_EXCEPTIONS = {
    1: "illegal_function",
    2: "illegal_data_address",
    3: "illegal_data_value",
    4: "slave_device_failure",
    5: "acknowledge",
    6: "slave_device_busy",
    8: "memory_parity_error",
    10: "gateway_path_unavailable",
    11: "gateway_target_failed_to_respond",
}


def _decode_registers(data: bytes) -> list:
    """Split a byte string into big-endian 16-bit register values."""
    return [
        int.from_bytes(data[i:i + 2], "big")
        for i in range(0, len(data) - 1, 2)
    ]


def parse_modbus_tcp(payload: bytes, is_request: bool) -> Optional[dict]:
    """
    Parse a single Modbus/TCP application frame.

    Args:
        payload: raw bytes of the TCP payload, expected to start with the
            MBAP header. Assumes one frame per call - if you're reading
            straight off the wire with possible TCP segmentation/coalescing,
            reassemble frames using the `Length` field before calling this.
        is_request: True if this payload is client->server (used to decide
            how to interpret function-code-specific data, since request and
            response bodies for the same function code differ).

    Returns:
        A dict ready to store in ProtocolDetail.fields, or None if this
        doesn't look like a valid Modbus/TCP frame.
    """
    if len(payload) < 8:
        return None

    protocol_id = int.from_bytes(payload[2:4], "big")
    if protocol_id != 0:
        # Not Modbus (protocol identifier is always 0 for Modbus/TCP).
        return None

    transaction_id = int.from_bytes(payload[0:2], "big")
    unit_id = payload[6]
    function_code = payload[7]
    pdu = payload[8:]

    # High bit set on the function code signals an exception response.
    if function_code & 0x80:
        base_fc = function_code & 0x7F
        name, _kind = FUNCTION_CODES.get(base_fc, (f"unknown_fc_{base_fc}", "other"))
        exception_code = pdu[0] if pdu else None
        return {
            "transaction_id": transaction_id,
            "unit_id": unit_id,
            "function_code": function_code,
            "summary": f"{name}_exception",
            "operation": "exception",
            "direction": "response",
            "fields": {
                "exception_code": exception_code,
                "exception_name": MODBUS_EXCEPTIONS.get(exception_code, "unknown"),
            },
        }

    name, kind = FUNCTION_CODES.get(function_code, (f"unknown_fc_{function_code}", "other"))
    direction = "request" if is_request else "response"
    fields: dict = {}

    try:
        if function_code in (1, 2, 3, 4):  # read coils/discrete/holding/input
            if is_request:
                fields = {
                    "start_address": int.from_bytes(pdu[0:2], "big"),
                    "quantity": int.from_bytes(pdu[2:4], "big"),
                }
            else:
                byte_count = pdu[0]
                data = pdu[1:1 + byte_count]
                fields = {"byte_count": byte_count, "data_hex": data.hex()}
                if function_code in (3, 4):  # register reads decode cleanly
                    fields["values"] = _decode_registers(data)

        elif function_code == 5:  # write single coil
            addr = int.from_bytes(pdu[0:2], "big")
            value = int.from_bytes(pdu[2:4], "big")
            fields = {"address": addr, "value": "ON" if value == 0xFF00 else "OFF"}

        elif function_code == 6:  # write single register
            fields = {
                "address": int.from_bytes(pdu[0:2], "big"),
                "value": int.from_bytes(pdu[2:4], "big"),
            }

        elif function_code == 15:  # write multiple coils
            if is_request:
                fields = {
                    "start_address": int.from_bytes(pdu[0:2], "big"),
                    "quantity": int.from_bytes(pdu[2:4], "big"),
                    "byte_count": pdu[4],
                }
            else:
                fields = {
                    "start_address": int.from_bytes(pdu[0:2], "big"),
                    "quantity": int.from_bytes(pdu[2:4], "big"),
                }

        elif function_code == 16:  # write multiple registers
            if is_request:
                byte_count = pdu[4]
                data = pdu[5:5 + byte_count]
                fields = {
                    "start_address": int.from_bytes(pdu[0:2], "big"),
                    "quantity": int.from_bytes(pdu[2:4], "big"),
                    "values": _decode_registers(data),
                }
            else:
                fields = {
                    "start_address": int.from_bytes(pdu[0:2], "big"),
                    "quantity": int.from_bytes(pdu[2:4], "big"),
                }

        else:
            # Unrecognized/uncommon function code - preserve raw bytes
            # rather than guessing at a structure.
            fields = {"raw_hex": pdu.hex()}

    except (IndexError, ValueError):
        fields = {"parse_error": True, "raw_hex": pdu.hex()}

    return {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "summary": name,
        "operation": kind,
        "direction": direction,
        "fields": fields,
    }
