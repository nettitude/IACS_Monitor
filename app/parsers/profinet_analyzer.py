"""
PROFINET protocol analyzer.

PROFINET is structurally different from every other protocol in this
package: its real-time traffic (RT_CLASS_1/2/3 cyclic I/O, and DCP -
Discovery and Configuration Protocol) rides directly on Ethernet
(EtherType 0x8892), with NO IP/TCP/UDP layer underneath. This is why
`pcap_parser.py` has a separate ingestion path that checks EtherType
before even looking for an IP layer - Profinet traffic would otherwise
be invisible to a TCP/UDP-only pipeline.

(Acyclic PROFINET IO parameter read/write - the actual "read tag,
write tag" equivalent to Modbus/CIP - runs over UDP port 34964 using a
DCE/RPC-based Context Manager protocol, which is NOT implemented here;
see the scope note below.)

CONFIDENCE NOTE (this protocol has the least certain implementation in
this package, and that's stated plainly rather than glossed over):
  - The DCP (Discovery and Configuration Protocol) header fields -
    Service ID, Service Type, Xid, and the Option/Suboption/Length
    block structure - are well and consistently documented, and are
    implemented with confidence.
  - The mapping from DCP Service ID to name (Get=3, Set=4, Identify=5,
    Hello=6) follows the commonly-cited values, but I do not have a
    way to cross-check the exact numeric assignments against the
    official PROFINET specification in this environment, so treat the
    service *names* as likely-correct-but-unverified rather than
    certain - if a captured frame's Service ID doesn't match what
    you'd expect from the traffic context, that's a signal to check
    against Wireshark's pn_dcp dissector or the IEC 61158 spec rather
    than assume this table is wrong or right.
  - Cyclic RT_CLASS_1/2/3 I/O data frames are NOT decoded beyond
    reporting their Frame ID as a raw number. These frames carry
    pre-configured, engineering-tool-defined I/O data with no generic
    structure - decoding them meaningfully requires the device's GSD
    (General Station Description) file from the specific PROFINET
    project, which isn't available to a passive network monitoring
    tool. This is a genuine protocol limitation, not a shortcut: no
    generic PROFINET RT decoder can show you "what value was written"
    without that engineering data, the same way no generic tool can
    interpret a raw Modbus register's *meaning* without knowing what's
    mapped there - the difference is Modbus at least exposes the
    address; Profinet RT doesn't expose anything beyond Frame ID.
  - The Frame ID boundary between "alarm" and "cyclic data" traffic is
    reported as a coarse range rather than an exact cited boundary,
    for the same reason - verify against a real capture if precision
    matters.
"""
from typing import Optional

PROFINET_ETHERTYPE = 0x8892

_DCP_SERVICE_IDS = {
    3: "get",
    4: "set",
    5: "identify",
    6: "hello",
}

_DCP_SERVICE_TYPES = {
    0: "request",
    1: "response_success",
    5: "response_unsupported",
}


def _classify_frame_id(frame_id: int) -> str:
    """
    Coarse classification only - see module docstring's confidence note.
    Frame ID 0xFEFC-0xFEFF is the DCP range (handled separately, before
    this function is reached); everything else is bucketed loosely.
    """
    if frame_id <= 0x0100:
        return "reserved_or_sync"
    if frame_id < 0xFC00:
        return "cyclic_rt_io_data"
    if frame_id < 0xFEFC:
        return "alarm_or_acyclic"
    return "unclassified"


def _parse_dcp(payload: bytes) -> dict:
    """
    Parse a DCP frame (Service ID/Type/Xid + block list). `payload`
    starts right after the 2-byte Frame ID.
    """
    if len(payload) < 8:
        return {"summary": "dcp_malformed", "fields": {"raw_hex": payload.hex()}}

    service_id = payload[0]
    service_type = payload[1]
    xid = int.from_bytes(payload[2:6], "big")

    fields = {
        "service_id": service_id,
        "service_name": _DCP_SERVICE_IDS.get(service_id, f"unknown_{service_id:#x}"),
        "service_type": _DCP_SERVICE_TYPES.get(service_type, f"unknown_{service_type:#x}"),
        "xid": xid,
    }

    # Requests have a 2-byte Response Delay before the block list;
    # responses go straight to DCPDataLength.
    offset = 8 if service_type == 0 else 6
    if len(payload) >= offset + 2:
        dcp_data_length = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2
        blocks = []
        block_end = min(len(payload), offset + dcp_data_length)
        while offset + 4 <= block_end:
            option = payload[offset]
            suboption = payload[offset + 1]
            block_length = int.from_bytes(payload[offset + 2:offset + 4], "big")
            block_data = payload[offset + 4:offset + 4 + block_length]
            blocks.append({"option": option, "suboption": suboption, "data_hex": block_data.hex()})
            offset += 4 + block_length
            if block_length % 2:  # DCP blocks pad to even length
                offset += 1
        fields["blocks"] = blocks

    # IO-06: a DCP Set REQUEST reconfigures the device (station name, IP
    # address, DHCP) or resets it - a configuration write, not discovery.
    operation, summary = "discovery", f"dcp_{fields['service_name']}"
    if service_id == 4 and service_type == 0:
        what = []
        operation = "write"
        for b in fields.get("blocks") or []:
            opt, sub = b["option"], b["suboption"]
            if opt == 5 and sub in (5, 6):
                operation = "control"
                what.append("factory_reset")
            elif opt == 1:
                what.append("ip")
            elif opt == 2 and sub == 2:
                what.append("name_of_station")
            elif opt == 3:
                what.append("dhcp")
            elif opt == 5:
                what.append("control")
        summary = "dcp_set_" + "_".join(dict.fromkeys(what or ["parameter"]))
    return {
        "summary": summary,
        "operation": operation,
        "fields": fields,
    }


def parse_profinet(payload: bytes) -> Optional[dict]:
    """
    Parse a raw PROFINET Ethernet frame (the bytes immediately after the
    Ethernet header - no IP/TCP/UDP layer involved). Returns None if the
    payload is too short to contain even a Frame ID.
    """
    if len(payload) < 2:
        return None

    frame_id = int.from_bytes(payload[0:2], "big")
    rest = payload[2:]

    if 0xFEFC <= frame_id <= 0xFEFF:
        result = _parse_dcp(rest)
        result["frame_id"] = frame_id
        # DCP request/response is in service_type, not src/dst port direction
        st = (result.get("fields") or {}).get("service_type")
        result["direction"] = None if st in (None, "request") else "response"
        return result

    return {
        "frame_id": frame_id,
        "summary": _classify_frame_id(frame_id),
        "operation": "cyclic_io" if _classify_frame_id(frame_id) == "cyclic_rt_io_data" else "other",
        "fields": {"note": "no generic decode - see module docstring"},
    }
