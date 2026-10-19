"""
Generates a small synthetic multi-protocol pcap for exercising the
ingest pipeline end-to-end without needing a real ICS network capture.

Requires scapy (already a project dependency). Run from the project root:

    python sample_data/generate_sample_pcap.py

Produces sample_data/modbus_sample.pcap (Modbus only, unchanged from
before; Modbus write + read request/response pairs) and
sample_data/multi_protocol_sample.pcap containing one packet each for:
DNP3 (a CROB direct-operate write), S7comm (a Read Var request),
EtherNet/IP+CIP (a Write Tag request) and a PROFINET DCP Identify request
(raw Ethernet, no IP/TCP - built directly rather than through build_packet).
Modbus lives only in modbus_sample.pcap; ingest both for full coverage.
"""
from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw


def modbus_frame(txid: int, unit: int, fc: int, data: bytes) -> bytes:
    pdu = bytes([fc]) + data
    length = len(pdu) + 1  # + unit id byte
    return txid.to_bytes(2, "big") + (0).to_bytes(2, "big") + length.to_bytes(2, "big") + bytes([unit]) + pdu


def build_packet(src_ip, dst_ip, src_port, dst_port, payload, seq=1000):
    return (
        Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, seq=seq, flags="PA")
        / Raw(load=payload)
    )


def main():
    engineering_ws = "10.0.1.50"
    plc = "10.0.1.10"
    client_port = 51000

    packets = []

    # --- Write multiple registers: request + response ---
    write_req = modbus_frame(
        txid=1, unit=1, fc=16,
        data=(0).to_bytes(2, "big") + (2).to_bytes(2, "big") + bytes([4]) + (100).to_bytes(2, "big") + (200).to_bytes(2, "big"),
    )
    write_resp = modbus_frame(
        txid=1, unit=1, fc=16,
        data=(0).to_bytes(2, "big") + (2).to_bytes(2, "big"),
    )
    packets.append(build_packet(engineering_ws, plc, client_port, 502, write_req, seq=1000))
    packets.append(build_packet(plc, engineering_ws, 502, client_port, write_resp, seq=2000))

    # --- Read holding registers: request + response ---
    read_req = modbus_frame(
        txid=2, unit=1, fc=3,
        data=(0).to_bytes(2, "big") + (2).to_bytes(2, "big"),
    )
    read_resp = modbus_frame(
        txid=2, unit=1, fc=3,
        data=bytes([4]) + (200).to_bytes(2, "big") + (300).to_bytes(2, "big"),
    )
    packets.append(build_packet(engineering_ws, plc, client_port, 502, read_req, seq=1020))
    packets.append(build_packet(plc, engineering_ws, 502, client_port, read_resp, seq=2020))

    wrpcap("sample_data/modbus_sample.pcap", packets)
    print(f"Wrote {len(packets)} packets to sample_data/modbus_sample.pcap")


# --------------------------------------------------- DNP3 sample frame ---

def _dnp3_chunk(user_data: bytes) -> bytes:
    out = bytearray()
    offset = 0
    while offset < len(user_data):
        chunk = user_data[offset:offset + 16]
        out += chunk + b"\x00\x00"  # fake CRC, not checked by the analyzer
        offset += 16
    return bytes(out)


def dnp3_direct_operate_frame(dest: int, src: int) -> bytes:
    """A DIRECT_OPERATE request: CROB latch-on at index 0."""
    transport = bytes([0xC0])
    app_control = bytes([0xC0])
    function_code = bytes([0x05])  # direct_operate
    crob = bytes([0x03, 1]) + (1000).to_bytes(4, "little") + (0).to_bytes(4, "little") + bytes([0])
    object_header = bytes([12, 1, 0x17, 1, 0]) + crob  # group=12 var=1, qualifier=0x17, count=1, index=0
    user_data = transport + app_control + function_code + object_header
    length_byte = 5 + len(user_data)
    header = b"\x05\x64" + bytes([length_byte]) + bytes([0xC4]) + dest.to_bytes(2, "little") + src.to_bytes(2, "little") + b"\xAA\xAA"
    return header + _dnp3_chunk(user_data)


# ------------------------------------------------- S7comm sample frame ---

def s7comm_read_var_frame() -> bytes:
    """A Read Var request for DB1, byte offset 10, INT type."""
    address_raw = (10 << 3) | 0
    item_spec = bytes([0x12, 0x0A, 0x10, 0x05]) + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes([0x84]) + address_raw.to_bytes(3, "big")
    parameter = bytes([0x04, 1]) + item_spec  # function=read_var, item_count=1
    s7_header = bytes([0x32, 0x01]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big") + len(parameter).to_bytes(2, "big") + (0).to_bytes(2, "big")
    s7_payload = s7_header + parameter
    cotp = bytes([2, 0xF0, 0x80])
    total_len = 4 + len(cotp) + len(s7_payload)
    tpkt = bytes([3, 0]) + total_len.to_bytes(2, "big")
    return tpkt + cotp + s7_payload


# ------------------------------------------------ EtherNet/IP + CIP ---

def enip_write_tag_frame(tag_name: bytes, value: int) -> bytes:
    """A Write Tag Service request for the given tag name and DINT value."""
    path_segment = bytes([0x91, len(tag_name)]) + tag_name
    if len(tag_name) % 2:
        path_segment += b"\x00"  # pad to even length
    path_word_length = len(path_segment) // 2
    cip_message = (
        bytes([0x4D, path_word_length]) + path_segment
        + (0xC4).to_bytes(2, "little") + (1).to_bytes(2, "little") + value.to_bytes(4, "little", signed=True)
    )
    cpf_data = (2).to_bytes(2, "little")
    cpf_data += (0x0000).to_bytes(2, "little") + (0).to_bytes(2, "little")
    cpf_data += (0x00B2).to_bytes(2, "little") + len(cip_message).to_bytes(2, "little") + cip_message
    cmd_data = (0).to_bytes(4, "little") + (0).to_bytes(2, "little") + cpf_data
    header = (0x006F).to_bytes(2, "little") + len(cmd_data).to_bytes(2, "little") + (0x12345678).to_bytes(4, "little") + (0).to_bytes(4, "little") + bytes(8) + bytes(4)
    return header + cmd_data


# ------------------------------------------------------ PROFINET DCP ---

def profinet_dcp_identify_frame() -> bytes:
    """A DCP Identify request (raw Ethernet payload, no IP/TCP)."""
    frame_id = 0xFEFE
    block = bytes([0xFF, 0xFF]) + (0).to_bytes(2, "big")  # option=all, suboption=all, length=0
    payload = bytes([5, 0]) + (1).to_bytes(4, "big") + (0).to_bytes(2, "big") + len(block).to_bytes(2, "big") + block
    return frame_id.to_bytes(2, "big") + payload


def build_multi_protocol_pcap():
    plc_s7 = "10.0.1.11"        # Siemens PLC
    plc_dnp3 = "10.0.1.12"      # DNP3 outstation (e.g. a protective relay)
    plc_ab = "10.0.1.13"        # Allen-Bradley/Rockwell PLC
    engineering_ws = "10.0.1.50"
    client_port = 51000

    packets = []

    # DNP3: master (source=1) sends CROB direct-operate to outstation (dest=4)
    dnp3_bytes = dnp3_direct_operate_frame(dest=4, src=1)
    packets.append(build_packet(engineering_ws, plc_dnp3, client_port, 20000, dnp3_bytes, seq=1000))

    # S7comm: engineering workstation reads DB1 from the Siemens PLC
    s7_bytes = s7comm_read_var_frame()
    packets.append(build_packet(engineering_ws, plc_s7, client_port, 102, s7_bytes, seq=1000))

    # EtherNet/IP + CIP: write "Motor1_Speed" = 1500 to the Rockwell PLC
    enip_bytes = enip_write_tag_frame(b"Motor1_Speed", 1500)
    packets.append(build_packet(engineering_ws, plc_ab, client_port, 44818, enip_bytes, seq=1000))

    # PROFINET DCP: raw Ethernet, no IP/TCP layer at all - built directly
    # rather than through build_packet, and given EtherType 0x8892 by
    # wrapping in a raw Ether frame with type set explicitly.
    dcp_bytes = profinet_dcp_identify_frame()
    packets.append(
        Ether(src="aa:bb:cc:00:00:03", dst="ff:ff:ff:ff:ff:ff", type=0x8892) / Raw(load=dcp_bytes)
    )

    wrpcap("sample_data/multi_protocol_sample.pcap", packets)
    print(f"Wrote {len(packets)} packets to sample_data/multi_protocol_sample.pcap")


if __name__ == "__main__":
    main()
    build_multi_protocol_pcap()
