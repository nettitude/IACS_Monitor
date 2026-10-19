"""
DNP3 protocol analyzer (DNP3 over TCP, port 20000).

DNP3 has a real structural quirk that a naive byte-slicer will get
wrong: the link layer splits user data (transport header + application
layer) into blocks of up to 16 bytes, each followed by its own 2-byte
CRC - not one CRC at the end. Skipping the wrong number of bytes here
silently corrupts everything after the first block. This module strips
those per-block CRCs correctly (verified in isolation before being
wired in here) without attempting to *validate* them - DNP3's CRC uses
a non-standard polynomial that would need to be sourced from the spec
to implement correctly, and getting a CRC algorithm subtly wrong is
worse than not checking it at all. This parser is integrity-agnostic:
it trusts the frame is well-formed and focuses on function code and
data extraction, the same posture taken for Modbus (which has no CRC
at the TCP layer to begin with).

Frame layout:
    Link header (10 bytes): 0x05 0x64 | Length | Control | Dest(LE,2) |
                             Src(LE,2) | Header CRC(2)
    User data (de-chunked):
        Transport header (1 byte): FIN | FIR | SEQ(6 bits)
        Application layer:
            Application Control (1 byte): FIR | FIN | CON | UNS | SEQ(4 bits)
            Function code (1 byte)
            [Internal Indications (2 bytes) - responses only, fc 0x81/0x82]
            Object header(s): Group | Variation | Qualifier | Range | data

SCOPE LIMITS (documented rather than silently guessed around):
  - parse_dnp3() decodes one link frame as a complete application
    fragment. Fragments split over several transport segments (FIR ...
    FIN, 6-bit sequence) are reassembled by Dnp3TransportReassembler
    (F-12), which pcap_parser runs per TCP direction.
  - Packed-bit objects (g1v1, g10v1, g80v1) are decoded as ceil(count/8)
    bytes of bits under start-stop qualifiers (T3-31), and index-prefixed
    qualifiers 0x17/0x28 (and the other 1/2/4-byte prefix + count forms)
    are walked for CROB/AOB and the fixed-size types in _FIXED_POINT_SIZES.
  - Restart / initialize / start / stop application function codes
    (13-18) are reported with operation="control".
  - Full point-data decode is only implemented for two object types:
    Group 12 Var 1 (CROB - Control Relay Output Block, used by SELECT/
    OPERATE/DIRECT_OPERATE - the actual "write, with data" case for
    binary outputs) and Group 41 Var 1/2 (Analog Output Block - the
    "write, with data" case for analog outputs). These are the two
    object types that carry the control values you'd actually want to
    see in a monitoring tool. Every other group/variation is preserved
    as raw hex under the parsed header rather than guessed at, since an
    incorrect per-variation byte-width would misparse anything that
    follows it in the same frame - the same "don't fabricate a decode
    I'm not confident in" principle used for uncommon Modbus function
    codes and unresolved PAN-OS service objects.
  - Multi-object frames are now decoded: _parse_object_header returns
    (header, new_offset) so parse_dnp3 walks all headers in sequence.
    When a header's point data can't be sized (unknown variation), the raw
    remainder is captured under "raw_hex" and parsing stops there — later
    headers after that point are not decoded, but earlier ones are.
"""
import struct
from typing import Optional

DNP3_TCP_PORT = 20000
DNP3_UDP_PORT = 20000   # IEEE 1815 also defines DNP3 over UDP on 20000 (datagram-framed)
_SYNC_BYTES = b"\x05\x64"

FUNCTION_CODES = {
    0x00: "confirm",
    0x01: "read",
    0x02: "write",
    0x03: "select",
    0x04: "operate",
    0x05: "direct_operate",
    0x06: "direct_operate_no_ack",
    0x07: "immediate_freeze",
    0x08: "immediate_freeze_no_ack",
    0x09: "freeze_clear",
    0x0A: "freeze_clear_no_ack",
    0x0B: "freeze_at_time",
    0x0C: "freeze_at_time_no_ack",
    0x0D: "cold_restart",
    0x0E: "warm_restart",
    0x0F: "initialize_data",
    0x10: "initialize_application",
    0x11: "start_application",
    0x12: "stop_application",
    0x13: "save_configuration",
    0x14: "enable_unsolicited",
    0x15: "disable_unsolicited",
    0x16: "assign_class",
    0x17: "delay_measurement",
    0x18: "record_current_time",
    0x19: "open_file",
    0x1A: "close_file",
    0x1B: "delete_file",
    0x1C: "get_file_info",
    0x1D: "authenticate_file",
    0x1E: "abort_file",
    0x81: "response",
    0x82: "unsolicited_response",
}

# IIN (Internal Indications) bit flags, second byte only (the ones most
# relevant to a monitoring tool - device state and error signaling).
_IIN2_FLAGS = {
    0x01: "device_restart",
    0x02: "no_func_code_support",
    0x04: "object_unknown",
    0x08: "parameter_error",
    0x10: "event_buffer_overflow",
    0x20: "already_executing",
    0x40: "config_corrupt",
}


def _decode_iin(iin_bytes: bytes) -> dict:
    iin1, iin2 = iin_bytes[0], iin_bytes[1]
    flags = [name for bit, name in _IIN2_FLAGS.items() if iin2 & bit]
    return {"iin1": iin1, "iin2": iin2, "flags": flags}


def _dechunk_user_data(raw_after_header: bytes, user_data_length: int) -> bytes:
    """
    Strip the 2-byte CRC that follows every 16-byte (or shorter, for the
    final block) chunk of user data, reconstructing the contiguous
    transport+application-layer bytes.
    """
    offset = 0
    remaining = user_data_length
    out = bytearray()
    while remaining > 0 and offset < len(raw_after_header):
        chunk_size = min(16, remaining)
        out += raw_after_header[offset:offset + chunk_size]
        offset += chunk_size + 2
        remaining -= chunk_size
    return bytes(out)


# Packed single-bit objects: ceil(count/8) bytes of point data (T3-31).
_PACKED_BIT_OBJECTS = frozenset({
    (1, 1),    # Binary Input, packed format
    (10, 1),   # Binary Output, packed format
    (80, 1),   # Internal Indications (IIN) packed bits
})

# Fixed per-point byte sizes for common static/event objects.
_FIXED_POINT_SIZES: dict[tuple[int, int], int] = {
    (1, 2): 1,   # Binary Input with flags
    (2, 1): 1,   # Binary Input Change, no timestamp
    (2, 2): 7,   # Binary Input Change with absolute time
    (2, 3): 3,   # Binary Input Change with relative time
    (10, 2): 1,  # Binary Output status with flags
    (20, 1): 5,  # Binary Counter 32-bit with flag
    (20, 2): 3,  # Binary Counter 16-bit with flag
    (20, 5): 4,  # Binary Counter 32-bit, no flag
    (20, 6): 2,  # Binary Counter 16-bit, no flag
    (30, 1): 5,  # Analog Input 32-bit with flag
    (30, 2): 3,  # Analog Input 16-bit with flag
    (30, 3): 4,  # Analog Input 32-bit, no flag
    (30, 4): 2,  # Analog Input 16-bit, no flag
    (30, 5): 5,  # Analog Input SP float with flag
    (32, 1): 5,  # Analog Input Change 32-bit, no timestamp
    (32, 2): 3,  # Analog Input Change 16-bit, no timestamp
    (32, 3): 11, # Analog Input Change 32-bit with absolute time
    (40, 1): 5,  # Analog Output Status 32-bit with flag
    (40, 2): 3,  # Analog Output Status 16-bit with flag
    (12, 1): 11, # CROB
}

# Analog Output Block variation -> point size.
_AOB_SIZES = {1: 5, 2: 3, 3: 5, 4: 9}

# High-impact (non-write) function codes: device restarts, application
# stop/start and initialisation. Classified as operation="control" so
# traffic_findings flags them instead of letting them fall into "other".
_CONTROL_FUNCTION_CODES = frozenset({0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12})


def _parse_crob(data: bytes) -> dict:
    """Group 12 Var 1 - Control Relay Output Block. 11 bytes per point."""
    control_code = data[0]
    count = data[1]
    on_time_ms = int.from_bytes(data[2:6], "little")
    off_time_ms = int.from_bytes(data[6:10], "little")
    status = data[10]
    return {
        "control_code": control_code,
        "op_type": {0x01: "pulse_on", 0x02: "pulse_off", 0x03: "latch_on", 0x04: "latch_off"}.get(
            control_code & 0x0F, f"unknown_{control_code & 0x0F:#x}"
        ),
        "count": count,
        "on_time_ms": on_time_ms,
        "off_time_ms": off_time_ms,
        "status": status,
    }


def _parse_aob(data: bytes, variation: int) -> dict:
    """Group 41 (Analog Output Block). Var 1 = 32-bit signed + status (5 bytes),
    Var 2 = 16-bit signed + status (3 bytes), Var 3 = 32-bit float + status
    (5 bytes), Var 4 = 64-bit float + status (9 bytes)."""
    if variation == 1:
        value = int.from_bytes(data[0:4], "little", signed=True)
        status = data[4]
    elif variation == 3:
        value = struct.unpack("<f", data[0:4])[0]
        status = data[4]
    elif variation == 4:
        value = struct.unpack("<d", data[0:8])[0]
        status = data[8]
    else:
        value = int.from_bytes(data[0:2], "little", signed=True)
        status = data[2]
    return {"value": value, "status": status}


def _parse_object_header(data: bytes, offset: int) -> Optional[tuple[dict, int]]:
    """
    Parse one DNP3 object header (group, variation, qualifier, range),
    decoding point data only for the object types documented in the
    module docstring as fully supported.

    Returns (header_dict, new_offset) on success, or None if there isn't
    enough data left to read a header. new_offset is the byte position
    immediately after the last byte consumed by this header, so the caller
    can call _parse_object_header again at that position to decode
    subsequent headers in the same application layer.

    When point data can't be sized confidently (an unrecognized
    group/variation, or a start-stop range whose per-variation byte width
    isn't in the table), the raw remainder is preserved under "raw_hex"
    and new_offset is set to len(data) — the caller should stop there
    rather than attempt a further header at an unknown position.
    """
    if offset + 3 > len(data):
        return None

    group = data[offset]
    variation = data[offset + 1]
    qualifier = data[offset + 2]
    offset += 3

    prefix_code = (qualifier & 0xF0) >> 4
    range_code = qualifier & 0x0F

    header = {
        "group": group,
        "variation": variation,
        "qualifier": qualifier,
        "prefix_code": prefix_code,
        "range_code": range_code,
        "points": [],
    }

    if range_code == 0x06:
        # No range field - "all points of this type" (the common READ
        # request pattern). No point data follows; next header starts here.
        return header, offset

    if range_code in (0x00, 0x01, 0x02):
        # Start-stop range: 1, 2, or 4 bytes per index respectively.
        width = {0x00: 1, 0x01: 2, 0x02: 4}[range_code]
        if offset + width * 2 > len(data):
            return header, len(data)
        start = int.from_bytes(data[offset:offset + width], "little")
        stop = int.from_bytes(data[offset + width:offset + width * 2], "little")
        offset += width * 2
        header["range"] = {"start": start, "stop": stop}
        if stop < start:
            header["raw_hex"] = data[offset:].hex()
            return header, len(data)
        count = stop - start + 1
        if (group, variation) in _PACKED_BIT_OBJECTS:
            # Packed single-bit objects (T3-31): ceil(count/8) bytes, bit 0
            # of the first byte is the point at `start`.
            nbytes = (count + 7) // 8
            if offset + nbytes > len(data):
                header["raw_hex"] = data[offset:].hex()
                return header, len(data)
            packed = data[offset:offset + nbytes]
            for i in range(count):
                header["points"].append({
                    "index": start + i,
                    "value": bool(packed[i // 8] & (1 << (i % 8))),
                })
            return header, offset + nbytes
        # Known fixed sizes for the most common OT monitoring types:
        point_size = _FIXED_POINT_SIZES.get((group, variation))
        if point_size is not None:
            for idx in range(start, stop + 1):
                if offset + point_size > len(data):
                    break
                header["points"].append({
                    "index": idx,
                    "raw_hex": data[offset:offset + point_size].hex(),
                })
                offset += point_size
            return header, offset
        # Unknown variation — preserve remainder and signal stop.
        header["raw_hex"] = data[offset:].hex()
        return header, len(data)

    if prefix_code in (0x01, 0x02, 0x03) and range_code in (0x07, 0x08, 0x09):
        # Index-prefixed objects with a count: prefix 1/2/3 = 1/2/4-byte
        # index, range 7/8/9 = 1/2/4-byte count. 0x17 (1-byte index +
        # 1-byte count) and 0x28 (2-byte index + 2-byte count) are the
        # standard patterns for CROB (group 12 var 1) and AOB (group 41)
        # control operations (0x28: F-12 partial).
        idx_width = {0x01: 1, 0x02: 2, 0x03: 4}[prefix_code]
        cnt_width = {0x07: 1, 0x08: 2, 0x09: 4}[range_code]
        if offset + cnt_width > len(data):
            return header, len(data)
        count = int.from_bytes(data[offset:offset + cnt_width], "little")
        offset += cnt_width
        header["count"] = count
        for _ in range(count):
            if offset + idx_width > len(data):
                break
            index = int.from_bytes(data[offset:offset + idx_width], "little")
            offset += idx_width
            if group == 12 and variation == 1 and offset + 11 <= len(data):
                point = _parse_crob(data[offset:offset + 11])
                offset += 11
            elif group == 41 and variation in _AOB_SIZES:
                size = _AOB_SIZES[variation]
                if offset + size > len(data):
                    break
                point = _parse_aob(data[offset:offset + size], variation)
                offset += size
            elif (group, variation) in _FIXED_POINT_SIZES:
                size = _FIXED_POINT_SIZES[(group, variation)]
                if offset + size > len(data):
                    break
                point = {"raw_hex": data[offset:offset + size].hex()}
                offset += size
            else:
                # Unrecognized group/variation under this qualifier -
                # can't size the point reliably, so stop decoding
                # further points/headers and preserve what's left.
                header["points"].append({"index": index, "raw_hex": data[offset:].hex()})
                return header, len(data)
            point["index"] = index
            header["points"].append(point)
        return header, offset

    # Any other prefix/range combination isn't decoded point-by-point;
    # preserve the remainder as raw hex and signal stop.
    header["raw_hex"] = data[offset:].hex()
    return header, len(data)


def _parse_link(payload: bytes) -> Optional[tuple[dict, bytes]]:
    """Link header + de-chunked user data, or None if not a DNP3 frame."""
    if len(payload) < 10 or payload[0:2] != _SYNC_BYTES:
        return None
    length = payload[2]
    user_data_length = length - 5  # length counts control+dest+src+userdata
    if user_data_length < 0:
        return None
    link = {
        "control": payload[3],
        "destination": int.from_bytes(payload[4:6], "little"),
        "source": int.from_bytes(payload[6:8], "little"),
    }
    # payload[8:10] is the header CRC - not validated, see module docstring.
    return link, _dechunk_user_data(payload[10:], user_data_length)


def _decode_application(app_layer: bytes, result: dict) -> dict:
    """Decode an application-layer fragment into ``result`` (in place)."""
    if len(app_layer) < 2:
        result["summary"] = "transport_only"
        result["fields"] = {}
        return result

    app_control = app_layer[0]
    function_code = app_layer[1]
    fn_name = FUNCTION_CODES.get(function_code, f"unknown_fc_{function_code:#x}")

    fields = {
        "app_control": {
            "fir": bool(app_control & 0x80),
            "fin": bool(app_control & 0x40),
            "con": bool(app_control & 0x20),
            "uns": bool(app_control & 0x10),
            "seq": app_control & 0x0F,
        },
    }

    offset = 2
    if function_code in (0x81, 0x82):
        if len(app_layer) >= 4:
            fields["iin"] = _decode_iin(app_layer[2:4])
        offset = 4

    objects = []
    # Walk all object headers in the application layer. _parse_object_header
    # returns (header, new_offset); when the new_offset equals len(data) the
    # remainder was unrecognizable and has been preserved as raw_hex — stop
    # there rather than risk misaligning on the next header.
    while offset < len(app_layer):
        obj_result = _parse_object_header(app_layer, offset)
        if obj_result is None:
            break
        hdr, new_offset = obj_result
        objects.append(hdr)
        if new_offset <= offset:
            # Shouldn't happen, but guard against infinite loop
            break
        if new_offset >= len(app_layer):
            break
        offset = new_offset

    fields["objects"] = objects
    result["direction"] = "response" if function_code in (0x81, 0x82) else "request"
    result["summary"] = fn_name
    if function_code in (0x02, 0x03, 0x04, 0x05, 0x06):
        result["operation"] = "write"
    elif function_code == 0x01:
        result["operation"] = "read"
    elif function_code in _CONTROL_FUNCTION_CODES:
        result["operation"] = "control"
    else:
        result["operation"] = "other"
    result["fields"] = fields
    return result


def parse_dnp3(payload: bytes) -> Optional[dict]:
    """
    Parse a single DNP3/TCP frame starting at the 0x05 0x64 sync bytes,
    treating its transport segment as a complete application fragment.
    (Use Dnp3TransportReassembler for traffic where application fragments
    span several link frames.)

    Returns None if the payload doesn't start with a valid DNP3 sync
    sequence, or is too short to contain a full link header.
    """
    parsed = _parse_link(payload)
    if parsed is None:
        return None
    link, user_data = parsed
    if len(user_data) < 1:
        return {**link, "summary": "link_layer_only", "fields": {}}

    transport_header = user_data[0]
    result = {
        **link,
        "transport": {
            "fin": bool(transport_header & 0x80),
            "fir": bool(transport_header & 0x40),
            "seq": transport_header & 0x3F,
        },
    }
    return _decode_application(user_data[1:], result)


# ---------------------------------------------------------------------------
# Transport-layer reassembly (F-12)
# ---------------------------------------------------------------------------
# An application fragment (up to ~2048 bytes, larger on some outstations)
# is carried in one or more transport segments, each in its own link frame
# (at most 249 application bytes per segment). The 1-byte transport header
# has FIR (first), FIN (final) and a 6-bit sequence that increments mod 64
# per segment. Segments are collected per (link source, link destination)
# - the caller keeps one reassembler per TCP direction - and the fragment
# is decoded once FIN arrives. A segment that arrives out of sequence, or a
# non-FIR segment with nothing in progress, discards the partial fragment
# (IEEE 1815 section 8.2.1.2 receiver rules).

MAX_DNP3_FRAGMENT_BYTES = 65536
MAX_DNP3_PARTIAL_FRAGMENTS = 256


class Dnp3TransportReassembler:
    """Feed whole DNP3 link frames; get back decoded results for complete
    application fragments (and for link-only frames)."""

    def __init__(self, stats: Optional[dict] = None):
        self.partial: dict[tuple[int, int], dict] = {}
        self.stats = stats if stats is not None else {}
        for key in ("dnp3_transport_segments", "dnp3_fragments_reassembled",
                    "dnp3_transport_segments_dropped"):
            self.stats.setdefault(key, 0)

    def _drop(self, n: int) -> None:
        self.stats["dnp3_transport_segments_dropped"] += n

    def feed(self, frame: bytes) -> Optional[dict]:
        parsed = _parse_link(frame)
        if parsed is None:
            return None
        link, user_data = parsed
        if len(user_data) < 1:
            return {**link, "summary": "link_layer_only", "fields": {}}

        th = user_data[0]
        fir, fin, seq = bool(th & 0x40), bool(th & 0x80), th & 0x3F
        self.stats["dnp3_transport_segments"] += 1
        key = (link["source"], link["destination"])
        state = self.partial.get(key)

        if fir:
            if state is not None:               # previous fragment never finished
                self._drop(state["segments"])
            if fin:
                self.partial.pop(key, None)
                result = {**link, "transport": {"fin": True, "fir": True, "seq": seq,
                                                "segments": 1}}
                return _decode_application(user_data[1:], result)
            if len(self.partial) >= MAX_DNP3_PARTIAL_FRAGMENTS and key not in self.partial:
                oldest = next(iter(self.partial))
                self._drop(self.partial.pop(oldest)["segments"])
            self.partial[key] = {"data": bytearray(user_data[1:]), "seq": seq,
                                 "first_seq": seq, "segments": 1}
            return None

        if state is None or seq != (state["seq"] + 1) % 64:
            if state is not None:
                self._drop(state["segments"])
                del self.partial[key]
            self._drop(1)
            return None

        state["data"] += user_data[1:]
        state["seq"] = seq
        state["segments"] += 1
        if len(state["data"]) > MAX_DNP3_FRAGMENT_BYTES:
            self._drop(state["segments"])
            del self.partial[key]
            return None
        if not fin:
            return None

        del self.partial[key]
        self.stats["dnp3_fragments_reassembled"] += 1
        result = {**link, "transport": {"fin": True, "fir": True, "seq": state["first_seq"],
                                        "last_seq": seq, "segments": state["segments"],
                                        "reassembled": True}}
        return _decode_application(bytes(state["data"]), result)

    def flush(self) -> None:
        """End of capture: count fragments that never completed."""
        for state in self.partial.values():
            self._drop(state["segments"])
        self.partial.clear()
