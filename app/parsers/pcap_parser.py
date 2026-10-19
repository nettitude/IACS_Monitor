"""
PCAP ingestion.

Reads a pcap/pcapng file with Scapy, builds/updates Host and
NetworkSession rows for every conversation seen, and dispatches
payloads to the appropriate protocol analyzer by well-known port (or,
for PROFINET, by EtherType - see below).

Protocols dispatched by TCP port:
    502    Modbus/TCP        -> modbus_analyzer
    102    S7comm (Siemens)  -> s7comm_analyzer
    20000  DNP3               -> dnp3_analyzer
    44818  EtherNet/IP (CIP, Rockwell/Allen-Bradley) -> enip_cip_analyzer
           (also dispatched over UDP - ENIP's ListIdentity discovery
           commonly broadcasts over UDP using the same encapsulation
           header format as TCP explicit messaging)

Dispatched differently - PROFINET rides directly on Ethernet (EtherType
0x8892) with no IP/TCP/UDP layer underneath at all, so it's the one
protocol here that can't be reached through the IP-layer dispatch below.
A separate branch checks EtherType before even looking for an IP layer;
see profinet_analyzer.py for why its cyclic RT I/O data isn't decoded
beyond a Frame ID (it genuinely can't be, without engineering-tool data
that isn't visible on the wire).

NOT decoded: EtherNet/IP's UDP port 2222 Implicit/IO (Class 1 connected)
messaging. Unlike its TCP/UDP-44818 explicit-messaging sibling, Class 1
I/O data doesn't carry the ENIP encapsulation header at all - it's raw
per-connection I/O data whose meaning depends on the Forward_Open
parameters that established the connection, which aren't visible in
individual packets. Attempting to parse it with the same analyzer would
silently produce garbage, so it's left alone rather than guessed at.

Reassembly:
  TCP segments are buffered per-stream (4-tuple: src_ip, src_port,
  dst_ip, dst_port) for the three protocols whose length fields are
  well-documented and stable: S7comm (TPKT length at bytes 2-3, big-
  endian, includes the 4-byte TPKT header), EtherNet/IP / CIP (ENIP
  encapsulation Length at bytes 2-3, little-endian, payload bytes after
  the 24-byte header), and DNP3 (Length at byte 2, counts control+
  dest+src+userdata — adjusted from link header offset). Each new TCP
  segment is appended to its stream buffer; when a complete frame is
  present, it is sliced out and dispatched. Multiple frames per segment
  ("coalesced ACK" or Nagle) are also handled.  Modbus/TCP is reassembled
  the same way using the MBAP header (protocol id 0, Length at bytes 4-5
  counting unit id + PDU), so coalesced requests all decode.  SMB is not
  buffered: its header detection is signature-based (already tolerant of
  partial payloads).

  T3-28: each direction tracks TCP sequence numbers - segments are
  ordered by seq, retransmitted/overlapping bytes are dropped, out-of-order
  segments are held until the gap fills, and a gap that never fills (lost
  segment, capture started mid-stream) is skipped.  Whenever the buffer
  does not start on a valid frame header (stray bytes, post-gap data) the
  drainer scans forward for the next plausible header of that protocol
  instead of stalling forever.  Buffers are capped at
  MAX_STREAM_BUFFER_BYTES per direction.

  "Client" vs "server" is inferred purely from well-known port numbers.
  Safe for these protocols specifically since they all have fixed
  well-known ports - won't generalize to protocols without one.
"""
from collections import OrderedDict
import ipaddress
from datetime import datetime, timedelta, timezone
import logging
import socket
import struct
import re
import time
from typing import Callable, Optional

from scapy.all import RawPcapReader, conf
from scapy.layers.inet import IP, TCP, UDP  # noqa: F401  (TCP/UDP kept for importers)
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q
from sqlalchemy import and_, insert, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.sites import site_ingest
from app.models import Host, NetworkSession, ProtocolDetail
from app.parsers.modbus_analyzer import parse_modbus_tcp, MODBUS_TCP_PORT
from app.parsers.dnp3_analyzer import parse_dnp3, DNP3_TCP_PORT, DNP3_UDP_PORT, Dnp3TransportReassembler
from app.parsers.s7comm_analyzer import parse_s7comm, S7COMM_TCP_PORT
from app.parsers.enip_cip_analyzer import parse_enip, ENIP_TCP_PORT
from app.parsers.profinet_analyzer import parse_profinet, PROFINET_ETHERTYPE
from app.parsers.smb_analyzer import sniff_smb
from app.parsers import name_sniff as _ns
from app.parsers.common import (
    as_utc, capture_format, compressed_format, detect_gateway_macs,
    detect_gateway_macs_v6, env_float, env_int, get_or_create_host, insert_host_row, is_group_mac, normalize_mac,
    refresh_host, touch_host_times,
)
from app.parsers.host_identity import (
    HostIdentityResolver, is_unicast_host_ip, site_broadcast_addresses,
)

log = logging.getLogger(__name__)

# SMB runs on port 445 (direct-over-TCP, MS-DS) and port 139 (NetBIOS
# Session Service wrapper).  Both ports may carry SMBv1 or SMB2/3.
SMB_PORTS: frozenset[int] = frozenset({139, 445})

# Per-direction reassembly limits (T3-28).
MAX_STREAM_BUFFER_BYTES = 1024 * 1024      # contiguous bytes awaiting a frame
MAX_OOO_SEGMENTS = 64                      # held out-of-order segments
MAX_OOO_BYTES = 256 * 1024                 # held out-of-order bytes
# A-30: global reassembly caps. Over either, the least-recently-used stream
# is flushed (whatever is decodable is decoded) and evicted
# (stats["streams_evicted"]); a later segment of it starts a fresh stream.
MAX_TCP_STREAMS = 50_000
MAX_REASSEMBLY_BYTES = 256 * 1024 * 1024

_SEQ_MOD = 1 << 32

# ---------------------------------------------------------------------------
# B-08: per-ingest resource limits.  Each is read from the environment at
# ingest time.  When one is hit the ingest STOPS, keeps (commits) what was
# processed so far and reports ``truncated: true`` + which limit + counts.
# Defaults: a 50 MB capture holds at most ~690k minimum-size frames, so 2M
# records only bounds pathological files (empty-record "pcap bombs"); real
# OT captures have hundreds to a few thousand hosts.
# ---------------------------------------------------------------------------
PCAP_LIMITS = {
    # limit name       env var                    default
    "max_packets":   ("IACS_PCAP_MAX_PACKETS",   2_000_000),
    "max_new_hosts": ("IACS_PCAP_MAX_NEW_HOSTS", 20_000),
    "max_sessions":  ("IACS_PCAP_MAX_SESSIONS",  200_000),
    "max_seconds":   ("IACS_PCAP_MAX_SECONDS",   600.0),
}


class UnsupportedCaptureError(ValueError):
    """The file is not an uncompressed pcap/pcapng capture (B-08).  The API
    maps it to HTTP 415.  Compressed captures are refused because scapy
    would otherwise inflate them transparently, defeating the upload size
    limit (a 50 MB .gz can hold ~50 GB of records)."""

    status_code = 415


def check_capture_file(pcap_path: str) -> str:
    """Return "pcap" / "pcapng" or raise UnsupportedCaptureError."""
    with open(pcap_path, "rb") as fh:
        head = fh.read(8)
    return check_capture_head(head)


def check_capture_head(head: bytes) -> str:
    fmt = capture_format(head)
    if fmt:
        return fmt
    comp = compressed_format(head)
    if comp:
        raise UnsupportedCaptureError(
            f"Compressed capture ({comp}) is not accepted - decompress it and upload "
            f"the plain .pcap/.pcapng (the size limit applies to the capture itself).")
    if not head:
        raise UnsupportedCaptureError("Capture file is empty.")
    raise UnsupportedCaptureError(
        "Not a pcap/pcapng capture (unrecognised file header). Upload a libpcap "
        ".pcap or a .pcapng file.")


class _PcapLimitHit(Exception):
    def __init__(self, limit: str):
        super().__init__(limit)
        self.limit = limit


class _PcapLimits:
    """Live limit state for one ingest (see PCAP_LIMITS)."""

    def __init__(self):
        self.max_packets = env_int(*PCAP_LIMITS["max_packets"])
        self.max_new_hosts = env_int(*PCAP_LIMITS["max_new_hosts"])
        self.max_sessions = env_int(*PCAP_LIMITS["max_sessions"])
        self.max_seconds = env_float(*PCAP_LIMITS["max_seconds"])
        self.start = time.monotonic()
        self.deadline = self.start + self.max_seconds
        self.records = 0            # records read by the main pass

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise _PcapLimitHit("max_seconds")

    def values(self) -> dict:
        return {name: getattr(self, name) for name in PCAP_LIMITS}

# ---------------------------------------------------------------------------
# TCP stream reassembly
# ---------------------------------------------------------------------------
# Stream key: (src_ip, src_port, dst_ip, dst_port) — directional, because
# request and response frames interleave and each direction's length fields
# are independent.  Keyed separately so a TPKT length from the server side
# doesn't get confused with one from the client side.

_StreamKey = tuple  # (src_ip: str, sport: int, dst_ip: str, dport: int)

# Frame-length functions: fn(buf, off, strict) returns
#   None -> not enough bytes yet to decide
#   0    -> the bytes at `off` are NOT a valid frame header
#   n>0  -> total length of the frame starting at `off`
# `strict` is used while resynchronising (scanning forward through bytes of
# unknown alignment) and applies extra plausibility checks so a random byte
# pattern is unlikely to be mistaken for a header.
_FrameLenFn = Callable[[bytes, int, bool], Optional[int]]

_COTP_PDU_TYPES = frozenset({0xE0, 0xD0, 0x80, 0xC0, 0xF0, 0x70, 0x10, 0x20, 0x50, 0x60})


def _s7comm_frame_length(buf, off: int = 0, strict: bool = False) -> Optional[int]:
    """TPKT (RFC1006): 0x03 0x00 | length(2, BE, includes the 4-byte header)."""
    avail = len(buf) - off
    if avail < 1:
        return None
    if buf[off] != 0x03:
        return 0
    if avail < 2:
        return None
    if buf[off + 1] != 0x00:
        return 0
    if avail < 4:
        return None
    length = (buf[off + 2] << 8) | buf[off + 3]
    if length < 7:
        return 0
    if strict:
        if avail < 6:
            return None
        cotp_len = buf[off + 4]
        if cotp_len < 2 or cotp_len > length - 5 or (buf[off + 5] & 0xF0) not in _COTP_PDU_TYPES:
            return 0
    return length


def _mbap_frame_length(buf, off: int = 0, strict: bool = False) -> Optional[int]:
    """Modbus/TCP MBAP: txid(2) | protocol id(2)=0 | length(2, BE) | unit | fc."""
    avail = len(buf) - off
    if avail >= 4 and (buf[off + 2] or buf[off + 3]):
        return 0
    if avail < 8:
        return None
    length = (buf[off + 4] << 8) | buf[off + 5]
    if length < 2 or length > 254:
        return 0
    fc = buf[off + 7] & 0x7F
    if fc == 0:
        return 0
    return 6 + length


_ENIP_COMMANDS = frozenset({0x0001, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066,
                            0x006F, 0x0070, 0x0072, 0x0073})


def _enip_frame_length(buf, off: int = 0, strict: bool = False) -> Optional[int]:
    """ENIP encapsulation: command(2,LE) | length(2,LE) | ... 24-byte header."""
    avail = len(buf) - off
    if avail >= 2:
        command = buf[off] | (buf[off + 1] << 8)
        if command not in _ENIP_COMMANDS:
            return 0
    if avail < 24:
        return None
    payload_len = buf[off + 2] | (buf[off + 3] << 8)
    if payload_len > 65511:
        return 0
    if strict and any(buf[off + 20:off + 24]):   # options must be zero
        return 0
    return 24 + payload_len


def dnp3_crc(data: bytes) -> int:
    """CRC-16/DNP (poly 0x3D65 reflected = 0xA6BC, init 0, xorout 0xFFFF)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def _dnp3_frame_length(buf, off: int = 0, strict: bool = False) -> Optional[int]:
    """Return the total on-wire DNP3 frame length (10-byte link header +
    chunked user data with CRCs)."""
    avail = len(buf) - off
    if avail < 1:
        return None
    if buf[off] != 0x05:
        return 0
    if avail < 2:
        return None
    if buf[off + 1] != 0x64:
        return 0
    if avail < 3:
        return None
    # DNP3 Length field = control(1) + dest(2) + src(2) + user_data_length
    # Total wire bytes = 10 (header) + ceil(user_data_length/16)*18 chunks
    # where each 16-byte chunk adds a 2-byte CRC.
    user_data_length = buf[off + 2] - 5
    if user_data_length < 0:
        return 0
    if strict:
        # While resyncing, require the link-header CRC to check out -
        # "05 64" alone is far too weak a signature inside arbitrary data.
        if avail < 10:
            return None
        hdr = bytes(buf[off:off + 8])
        if dnp3_crc(hdr) != (buf[off + 8] | (buf[off + 9] << 8)):
            return 0
    full_chunks, remainder = divmod(user_data_length, 16)
    wire_user_bytes = full_chunks * 18 + (remainder + 2 if remainder else 0)
    return 10 + wire_user_bytes


def _split_dnp3_datagram(payload: bytes) -> tuple[list[bytes], int]:
    """Split one UDP datagram into DNP3 link frames (no TCP stream framing:
    the datagram boundary bounds the data). Returns (complete_frames,
    malformed_count). Truncated or non-DNP3 trailing bytes are counted and
    dropped; link CRC blocks are stripped later by the analyzer."""
    frames: list[bytes] = []
    bad = 0
    pos, n = 0, len(payload)
    while pos < n:
        length = _dnp3_frame_length(payload, pos, False)
        if not length:                      # None (too short) or 0 (not DNP3)
            bad += 1
            break
        if pos + length > n:                # truncated frame
            bad += 1
            break
        frames.append(bytes(payload[pos:pos + length]))
        pos += length
    return frames, bad


# Map each reassembled port to its frame-length function.
_REASSEMBLED_PORTS: dict[int, _FrameLenFn] = {
    MODBUS_TCP_PORT: _mbap_frame_length,
    S7COMM_TCP_PORT: _s7comm_frame_length,
    ENIP_TCP_PORT: _enip_frame_length,
    DNP3_TCP_PORT: _dnp3_frame_length,
}


def _drain_stream(buf, frame_len_fn: _FrameLenFn, stats: Optional[dict] = None) -> tuple[list[bytes], bytes]:
    """
    Extract all complete frames from buf using frame_len_fn to determine
    each frame's length.  Returns (list_of_complete_frames, leftover_bytes).

    If the bytes at the current position are not a valid header, scan
    forward (strict mode) to the next position that is - or that could
    still become one once more bytes arrive - and continue from there,
    counting the skip in stats["stream_resyncs"] / ["resync_bytes_skipped"].
    """
    frames: list[bytes] = []
    pos = 0
    n = len(buf)
    while pos < n:
        length = frame_len_fn(buf, pos, False)
        if length is None:
            break
        if length == 0:
            nxt = pos + 1
            while nxt < n and frame_len_fn(buf, nxt, True) == 0:
                nxt += 1
            if stats is not None:
                stats["stream_resyncs"] += 1
                stats["resync_bytes_skipped"] += nxt - pos
            pos = nxt
            continue
        if pos + length > n:
            break
        frames.append(bytes(buf[pos:pos + length]))
        pos += length
    return frames, bytes(buf[pos:])


def _seq_diff(a: int, b: int) -> int:
    """Signed distance a - b in 32-bit sequence space."""
    d = (a - b) % _SEQ_MOD
    return d - _SEQ_MOD if d >= _SEQ_MOD // 2 else d


class _TcpStream:
    """Per-direction reassembly state (T3-28)."""
    __slots__ = ("next_seq", "buf", "ooo", "ooo_bytes", "frame_len_fn",
                 "session_row", "sport", "dport", "last_ts", "dnp3", "sender_id")

    def __init__(self, frame_len_fn: _FrameLenFn):
        self.sender_id = None                      # batch C: the host sending this direction
        self.next_seq: Optional[int] = None
        self.buf = bytearray()
        self.ooo: dict[int, bytes] = {}
        self.ooo_bytes = 0
        self.frame_len_fn = frame_len_fn
        self.session_row = None
        self.sport = 0
        self.dport = 0
        self.last_ts = None
        self.dnp3: Optional[Dnp3TransportReassembler] = None   # F-12, DNP3 streams only

    def reset(self) -> None:
        self.next_seq = None
        self.buf = bytearray()
        self.ooo.clear()
        self.ooo_bytes = 0

    def _append(self, data: bytes, stats: dict) -> None:
        self.buf += data
        self.next_seq = (self.next_seq + len(data)) % _SEQ_MOD
        if len(self.buf) > MAX_STREAM_BUFFER_BYTES:
            stats["stream_buffer_overflows"] += 1
            self.buf = bytearray()

    def _pull_ooo(self, stats: dict) -> None:
        while self.ooo:
            best = min(self.ooo, key=lambda s: _seq_diff(s, self.next_seq))
            d = _seq_diff(best, self.next_seq)
            if d > 0:
                return
            seg = self.ooo.pop(best)
            self.ooo_bytes -= len(seg)
            if -d >= len(seg):
                stats["tcp_retransmitted_segments"] += 1
                continue
            self._append(seg[-d:] if d else seg, stats)

    def skip_gap(self, stats: dict) -> bool:
        """Give up on missing bytes: drop the partial frame before the gap
        and continue from the earliest held segment. Returns False when
        there is nothing held (no gap to skip)."""
        if not self.ooo:
            return False
        stats["tcp_gaps"] += 1
        if self.buf:
            stats["resync_bytes_skipped"] += len(self.buf)
            self.buf = bytearray()
        self.next_seq = min(self.ooo, key=lambda s: _seq_diff(s, self.next_seq))
        self._pull_ooo(stats)
        return True

    def add_segment(self, seq: int, data: bytes, stats: dict) -> None:
        if self.next_seq is None:
            self.next_seq = seq
        d = _seq_diff(seq, self.next_seq)
        if d < 0:
            if -d >= len(data):
                stats["tcp_retransmitted_segments"] += 1
                return
            data = data[-d:]         # keep only the bytes we haven't seen
            d = 0
        if d == 0:
            self._append(data, stats)
            self._pull_ooo(stats)
            return
        stats["tcp_out_of_order_segments"] += 1
        held = self.ooo.get(seq)
        if held is None or len(held) < len(data):
            self.ooo_bytes += len(data) - (len(held) if held else 0)
            self.ooo[seq] = data
        if len(self.ooo) > MAX_OOO_SEGMENTS or self.ooo_bytes > MAX_OOO_BYTES:
            self.skip_gap(stats)

    def mem(self) -> int:
        """Bytes held for reassembly (A-30 accounting)."""
        return len(self.buf) + self.ooo_bytes

    def drain(self, stats: dict) -> list[bytes]:
        frames, leftover = _drain_stream(self.buf, self.frame_len_fn, stats)
        self.buf = bytearray(leftover)
        return frames


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _find_session(db: DBSession, a_id: int, a_port, b_id: int, b_port, transport: str):
    """Look up an existing NetworkSession for this conversation in either
    orientation (sessions are bidirectional; see _get_or_create_session)."""
    def _eq(col, val):
        return col.is_(None) if val is None else col == val

    return (
        db.query(NetworkSession)
        .filter(
            NetworkSession.transport == transport,
            or_(
                and_(NetworkSession.src_host_id == a_id, NetworkSession.dst_host_id == b_id,
                     _eq(NetworkSession.src_port, a_port), _eq(NetworkSession.dst_port, b_port)),
                and_(NetworkSession.src_host_id == b_id, NetworkSession.dst_host_id == a_id,
                     _eq(NetworkSession.src_port, b_port), _eq(NetworkSession.dst_port, a_port)),
            ),
        )
        .order_by(NetworkSession.id)
        .first()
    )


def _get_or_create_session(
    db: DBSession,
    sessions_cache: dict,
    src_host: Host,
    dst_host: Host,
    src_port: Optional[int],
    dst_port: Optional[int],
    transport: str,
    source_file: str,
    seen_at: Optional[datetime] = None,
    new_hosts: Optional[set] = None,
    max_sessions: Optional[int] = None,
) -> NetworkSession:
    """
    Race-safe get-or-create of the NetworkSession for a conversation.

    Sessions are cached per-direction-normalized-tuple within a single
    ingest run so repeated packets in the same conversation accumulate
    onto one row instead of creating a new row per packet. `src_port`/
    `dst_port` are None for transport="ethernet" (PROFINET), which has
    no port concept at all.

    On a cache miss an existing row for the conversation (either
    orientation) is reused. Otherwise the insert runs inside a SAVEPOINT;
    if a concurrent ingest inserted the same 5-tuple first (UNIQUE
    ux_session_5tuple -> IntegrityError) only the savepoint is rolled back
    and the winner's row is re-queried and used.

    ``new_hosts`` (F-13): ids of Host rows this (uncommitted) ingest created.
    No committed session can reference them, so the lookup is skipped -
    and so is the SAVEPOINT (B-08): no concurrent transaction can insert a
    session pointing at an uncommitted host.

    ``max_sessions`` (B-08): a cache miss with that many sessions already in
    ``sessions_cache`` raises _PcapLimitHit("max_sessions").
    """
    # Multi-site (phase 2): both endpoints come from get_or_create_host
    # scoped to the upload's site, so the host ids - and therefore the
    # 5-tuple lookup / ux_session_5tuple - are inherently per site.  A
    # session spanning two sites would break isolation; refuse it.
    if (src_host.site_id is not None and dst_host.site_id is not None
            and src_host.site_id != dst_host.site_id):
        raise ValueError("session endpoints belong to different sites "
                         f"({src_host.site_id} != {dst_host.site_id})")
    # frozenset makes the key direction-agnostic: A→B and B→A map to the
    # same NetworkSession row, accumulating all packets from both directions
    # into one bidirectional flow. This is intentional — the session model
    # represents a conversation, not a unidirectional stream — but it means
    # src_host/dst_host in the stored row reflect whichever packet arrived
    # first in the file, not which side initiated. (P4-I5 documentation)
    canonical = frozenset(
        [(src_host.id, src_port), (dst_host.id, dst_port)]
    )
    cache_key = (canonical, transport)

    cached = sessions_cache.get(cache_key)
    if cached is not None:
        return cached
    if max_sessions is not None and len(sessions_cache) >= max_sessions:
        raise _PcapLimitHit("max_sessions")

    fresh = bool(new_hosts) and (src_host.id in new_hosts or dst_host.id in new_hosts)
    if fresh:
        session_row = None
    else:
        session_row = _find_session(db, src_host.id, src_port, dst_host.id, dst_port, transport)
    if session_row is None:
        seen_at = seen_at or datetime.now(timezone.utc)
        candidate = NetworkSession(
            src_host_id=src_host.id,
            dst_host_id=dst_host.id,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            protocol="unknown",
            source_file=source_file,
            packet_count=0,
            byte_count=0,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        try:
            if fresh:
                db.add(candidate)
                db.flush()
            else:
                with db.begin_nested():
                    db.add(candidate)
                    db.flush()
            session_row = candidate
        except IntegrityError:
            session_row = _find_session(db, src_host.id, src_port, dst_host.id, dst_port, transport)
            if session_row is None:
                raise
    sessions_cache[cache_key] = session_row
    return session_row


def _get_ethertype(pkt) -> Optional[int]:
    """Effective EtherType, looking past a VLAN tag (Dot1Q) if present."""
    if Dot1Q in pkt:
        return pkt[Dot1Q].type
    if Ether in pkt:
        return pkt[Ether].type
    return None


def _run_analyzer(protocol: str, fn, args: tuple, stats: dict, logged: Optional[set]):
    """Call one analyzer, isolating its exceptions (T3-30): a decode bug on
    one frame is counted and logged once per protocol, never aborting the
    ingest."""
    try:
        return fn(*args)
    except Exception:
        stats["analyzer_errors"] = stats.get("analyzer_errors", 0) + 1
        by_proto = stats.setdefault("analyzer_errors_by_protocol", {})
        by_proto[protocol] = by_proto.get(protocol, 0) + 1
        if logged is None or protocol not in logged:
            if logged is not None:
                logged.add(protocol)
            log.exception("%s analyzer raised; frame skipped (further errors for this "
                          "analyzer in this ingest are counted, not logged)", protocol)
        return None


def _decode_tcp_protocols(
    payload: bytes, sport: int, dport: int, stats: dict,
    logged: Optional[set] = None, dnp3_reassembler: Optional[Dnp3TransportReassembler] = None,
) -> Optional[tuple[str, dict]]:
    """
    Dispatch a TCP payload to whichever protocol analyzer matches the port.
    Returns (protocol, decoded) or None if nothing matched/decoded (or the
    analyzer raised). With ``dnp3_reassembler`` DNP3 link frames are fed
    through transport-layer reassembly (F-12) and only complete
    application fragments decode.
    """
    if sport == MODBUS_TCP_PORT or dport == MODBUS_TCP_PORT:
        protocol = "modbus"
        decoded = _run_analyzer(protocol, parse_modbus_tcp,
                                (payload, dport == MODBUS_TCP_PORT), stats, logged)
    elif sport == S7COMM_TCP_PORT or dport == S7COMM_TCP_PORT:
        protocol = "s7comm"
        decoded = _run_analyzer(protocol, parse_s7comm, (payload,), stats, logged)
    elif sport == DNP3_TCP_PORT or dport == DNP3_TCP_PORT:
        protocol = "dnp3"
        if dnp3_reassembler is not None:
            decoded = _run_analyzer(protocol, dnp3_reassembler.feed, (payload,), stats, logged)
        else:
            decoded = _run_analyzer(protocol, parse_dnp3, (payload,), stats, logged)
    elif sport == ENIP_TCP_PORT or dport == ENIP_TCP_PORT:
        protocol = "ethernet_ip"
        decoded = _run_analyzer(protocol, parse_enip, (payload,), stats, logged)
    elif sport in SMB_PORTS or dport in SMB_PORTS:
        decoded = _run_analyzer("smb", sniff_smb, (payload,), stats, logged)
        # Map detected SMB version to protocol label; fall through on None
        # so we don't write an empty ProtocolDetail for non-SMB payloads
        # on these ports (e.g. TLS handshake bytes on 445).
        if decoded is None:
            return None
        version = decoded.get("version", "smb")
        protocol = "smb1" if version == "SMBv1" else "smb2_3"
    else:
        return None

    if not decoded:
        return None
    stats["protocol_frames"][protocol] += 1
    return protocol, decoded


def _handle_tcp_protocols(
    payload: bytes, sport: int, dport: int, session_row: NetworkSession, stats: dict,
    logged: Optional[set] = None, ts: Optional[datetime] = None,
) -> Optional[ProtocolDetail]:
    """
    Dispatch a TCP payload to whichever protocol analyzer matches the
    port, update the session's protocol label and frame-count stats,
    and return a ProtocolDetail ready to add to the session - or None
    if nothing matched or decoded (or the analyzer raised).
    """
    hit = _decode_tcp_protocols(payload, sport, dport, stats, logged)
    if hit is None:
        return None
    protocol, decoded = hit
    session_row.protocol = protocol
    detail = ProtocolDetail(
        session_id=session_row.id,
        protocol=protocol,
        direction=decoded.get("direction"),
        summary=decoded.get("summary"),
        fields=decoded,
    )
    if ts is not None:
        detail.timestamp = ts
    return detail


# ---------------------------------------------------------------------------
# Raw frame decoding (F-07 / F-12 / F-13)
# ---------------------------------------------------------------------------
# Packets are decoded straight from the capture bytes with struct instead of
# full scapy dissection: ~10x cheaper per packet, and it lets IPv4/IPv6
# fragments be reassembled before the L4 header is read. Link types handled
# natively: Ethernet (1, with any number of 802.1Q/QinQ tags), BSD loopback
# (0, 108), raw IP (101, 12, 14, 228, 229), Linux cooked v1/v2 (113, 276).
# Anything else falls back to scapy's dissector for that link type.

_ETH_IPV4, _ETH_IPV6, _ETH_ARP = 0x0800, 0x86DD, 0x0806
_VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})
_PROTO_TCP, _PROTO_UDP, _PROTO_ICMPV6 = 6, 17, 58

# IPv6 extension headers walked to find the upper-layer header.
_IPV6_EXT_GENERIC = frozenset({0, 43, 60, 135, 139, 140})   # (len+1)*8 octets
_IPV6_EXT_FRAGMENT, _IPV6_EXT_AH, _IPV6_EXT_ESP, _IPV6_NO_NEXT = 44, 51, 50, 59
_MAX_IPV6_EXT_HEADERS = 16

_NDP_TYPES = frozenset({133, 134, 135, 136, 137})
_MAX_MCAST_GROUPS = 256

# IP fragment reassembly limits (pcap time).
FRAG_TIMEOUT_SECONDS = 30.0
MAX_PENDING_DATAGRAMS = 4096
MAX_FRAGMENTS_PER_DATAGRAM = 128
MAX_DATAGRAM_BYTES = 65535 + 40

# ProtocolDetail rows are bulk-inserted in batches of this size (F-13).
DETAIL_BATCH_SIZE = 2000

_mac_str_cache: dict = {}


def _mac_str(b: bytes) -> str:
    s = _mac_str_cache.get(b)
    if s is None:
        s = b.hex(":")
        if len(_mac_str_cache) < 65536:
            _mac_str_cache[b] = s
    return s


def _ip4_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


_ip6_str_cache: dict = {}


def _ip6_str(b: bytes) -> str:
    s = _ip6_str_cache.get(b)
    if s is None:
        s = socket.inet_ntop(socket.AF_INET6, b)
        if len(_ip6_str_cache) < 65536:
            _ip6_str_cache[b] = s
    return s


def _is_link_local6(ip: str) -> bool:
    return ip[:3] in ("fe8", "fe9", "fea", "feb")


def _l3_from_version(data: bytes, off: int):
    if len(data) <= off:
        return None
    v = data[off] >> 4
    if v == 4:
        return _ETH_IPV4
    if v == 6:
        return _ETH_IPV6
    return None


def _decode_l2(data: bytes, linktype: int):
    """-> (src_mac, dst_mac, ethertype, offset_of_l3) or None.
    MACs are strings or None (no Ethernet header)."""
    if linktype == 1:
        if len(data) < 14:
            return None
        etype = (data[12] << 8) | data[13]
        off = 14
        while etype in _VLAN_ETHERTYPES and len(data) >= off + 4:
            etype = (data[off + 2] << 8) | data[off + 3]
            off += 4
        return _mac_str(data[6:12]), _mac_str(data[0:6]), etype, off
    if linktype in (0, 108):
        return None, None, _l3_from_version(data, 4), 4
    if linktype in (101, 12, 14, 228, 229):
        return None, None, _l3_from_version(data, 0), 0
    if linktype == 113 and len(data) >= 16:        # Linux cooked v1
        halen = (data[4] << 8) | data[5]
        arphrd = (data[2] << 8) | data[3]
        src = _mac_str(data[6:12]) if halen == 6 and arphrd == 1 else None
        return src, None, (data[14] << 8) | data[15], 16
    if linktype == 276 and len(data) >= 20:        # Linux cooked v2
        arphrd = (data[8] << 8) | data[9]
        src = _mac_str(data[12:18]) if data[11] == 6 and arphrd == 1 else None
        return src, None, (data[0] << 8) | data[1], 20
    return _decode_l2_scapy(data, linktype)


def _vlan_id(data: bytes, linktype: int) -> Optional[int]:
    """RS-07: the (outer) 802.1Q / QinQ VLAN id of an Ethernet frame, or None."""
    if linktype != 1 or len(data) < 18:
        return None
    if ((data[12] << 8) | data[13]) in _VLAN_ETHERTYPES:
        return ((data[14] & 0x0F) << 8) | data[15]
    return None


#: RS-01: frames whose two IPv4 addresses lie in different /24s, kept per
#: (src mac, dst mac, src ip, dst ip) - layer-2 evidence must come from ONE frame
_PRESCAN_MAX_DIRECT = 20000
_PRESCAN_MAX_SRC_VLANS = 65536


def _decode_l2_scapy(data: bytes, linktype: int):
    """Fallback for link types without a native decoder: let scapy find the
    IP/IPv6 layer, then continue on its raw bytes."""
    cls = conf.l2types.num2layer.get(linktype)
    if cls is None:
        return None
    try:
        pkt = cls(data)
    except Exception:
        return None
    src = dst = None
    if Ether in pkt:
        src, dst = pkt[Ether].src, pkt[Ether].dst
    for layer, etype in ((IP, _ETH_IPV4), (IPv6, _ETH_IPV6)):
        if layer in pkt:
            raw = bytes(pkt[layer])
            return src, dst, etype, ("raw", raw)
    return None


class _Datagram:
    """One IPv4/IPv6 datagram ready for L4 decoding."""
    __slots__ = ("version", "src", "dst", "proto", "payload", "frame_bytes", "frames")

    def __init__(self, version, src, dst, proto, payload, frame_bytes, frames=1):
        self.version = version
        self.src = src
        self.dst = dst
        self.proto = proto
        self.payload = payload
        self.frame_bytes = frame_bytes
        self.frames = frames


class _Defragmenter:
    """
    IPv4 / IPv6 fragment reassembly keyed by (src, dst, id, proto) -
    RFC 791 / RFC 8200. Overlapping bytes keep the first copy received.
    Datagrams still incomplete FRAG_TIMEOUT_SECONDS (pcap time) after their
    first fragment, beyond MAX_FRAGMENTS_PER_DATAGRAM, larger than
    MAX_DATAGRAM_BYTES or evicted by MAX_PENDING_DATAGRAMS are dropped and
    their fragments counted in <prefix>_fragments_dropped.
    """

    def __init__(self, stats: dict, prefix: str):
        self.stats = stats
        self.prefix = prefix
        self.pending: dict = {}
        for k in ("fragments", "datagrams_reassembled", "fragments_dropped"):
            stats.setdefault(f"{prefix}_{k}", 0)

    def _drop(self, key) -> None:
        entry = self.pending.pop(key, None)
        if entry is not None:
            self.stats[f"{self.prefix}_fragments_dropped"] += len(entry["frags"])

    def expire(self, now: float) -> None:
        while self.pending:
            key = next(iter(self.pending))
            if now - self.pending[key]["t0"] <= FRAG_TIMEOUT_SECONDS:
                return
            self._drop(key)

    def add(self, key, offset: int, more: bool, data: bytes, now: float, frame_len: int):
        """Returns (payload, total_frame_bytes, n_fragments) once complete."""
        self.stats[f"{self.prefix}_fragments"] += 1
        self.expire(now)
        entry = self.pending.get(key)
        if entry is None:
            if len(self.pending) >= MAX_PENDING_DATAGRAMS:
                self._drop(next(iter(self.pending)))
            entry = {"t0": now, "frags": [], "total": None, "bytes": 0}
            self.pending[key] = entry
        entry["frags"].append((offset, data))
        entry["bytes"] += frame_len
        if not more:
            end = offset + len(data)
            if entry["total"] is not None and entry["total"] != end:
                self._drop(key)                  # inconsistent last fragments
                return None
            entry["total"] = end
        if (len(entry["frags"]) > MAX_FRAGMENTS_PER_DATAGRAM
                or offset + len(data) > MAX_DATAGRAM_BYTES):
            self._drop(key)
            return None
        total = entry["total"]
        if total is None:
            return None
        covered = 0
        for off, chunk in sorted(entry["frags"], key=lambda f: f[0]):
            if off > covered:
                return None                      # hole
            covered = max(covered, off + len(chunk))
        if covered < total:
            return None
        buf = bytearray(total)
        # Write in reverse arrival order so the first copy of any
        # overlapping byte is the one that survives.
        for off, chunk in reversed(entry["frags"]):
            chunk = chunk[:max(0, total - off)]
            buf[off:off + len(chunk)] = chunk
        del self.pending[key]
        self.stats[f"{self.prefix}_datagrams_reassembled"] += 1
        return bytes(buf), entry["bytes"], len(entry["frags"])

    def flush(self) -> None:
        for key in list(self.pending):
            self._drop(key)


def _ipv4_datagram(l3: bytes, frame_len: int, now: float, defrag: Optional[_Defragmenter],
                   stats: dict) -> Optional[_Datagram]:
    if len(l3) < 20:
        stats["malformed_packets"] += 1
        return None
    ihl = (l3[0] & 0x0F) * 4
    total = (l3[2] << 8) | l3[3]
    if ihl < 20 or len(l3) < ihl:
        stats["malformed_packets"] += 1
        return None
    if ihl <= total <= len(l3):
        l3 = l3[:total]                          # strip Ethernet padding
    proto = l3[9]
    src, dst = _ip4_str(l3[12:16]), _ip4_str(l3[16:20])
    ff = (l3[6] << 8) | l3[7]
    more, frag_off = bool(ff & 0x2000), (ff & 0x1FFF) * 8
    payload = l3[ihl:]
    if more or frag_off:
        if defrag is None:
            return None
        done = defrag.add((src, dst, l3[4:6], proto), frag_off, more, payload, now, frame_len)
        if done is None:
            return None
        payload, nbytes, nfrags = done
        return _Datagram(4, src, dst, proto, payload, nbytes, nfrags)
    return _Datagram(4, src, dst, proto, payload, frame_len)


def _walk_ipv6_ext(nh: int, buf: bytes, off: int, stats: dict):
    """Skip extension headers. -> (next_header, offset, fragment_info|None)
    or None when malformed. fragment_info = (offset, more, ident, nh_after)."""
    for _ in range(_MAX_IPV6_EXT_HEADERS):
        if nh in _IPV6_EXT_GENERIC:
            if len(buf) < off + 2:
                return None
            stats["ipv6_extension_headers"] += 1
            nxt, hlen = buf[off], (buf[off + 1] + 1) * 8
            if len(buf) < off + hlen:
                return None
            nh, off = nxt, off + hlen
        elif nh == _IPV6_EXT_AH:
            if len(buf) < off + 2:
                return None
            stats["ipv6_extension_headers"] += 1
            nxt, hlen = buf[off], (buf[off + 1] + 2) * 4
            if len(buf) < off + hlen:
                return None
            nh, off = nxt, off + hlen
        elif nh == _IPV6_EXT_FRAGMENT:
            if len(buf) < off + 8:
                return None
            stats["ipv6_extension_headers"] += 1
            nxt = buf[off]
            fo = (buf[off + 2] << 8) | buf[off + 3]
            frag = ((fo >> 3) * 8, bool(fo & 1), bytes(buf[off + 4:off + 8]), nxt)
            off += 8
            if frag[0] == 0 and not frag[1]:     # atomic fragment
                nh = nxt
                continue
            return nh, off, frag
        else:
            return nh, off, None
    return None


def _ipv6_datagram(l3: bytes, frame_len: int, now: float, defrag: Optional[_Defragmenter],
                   stats: dict) -> Optional[_Datagram]:
    if len(l3) < 40:
        stats["malformed_packets"] += 1
        return None
    plen = (l3[4] << 8) | l3[5]
    if plen and 40 + plen <= len(l3):
        l3 = l3[:40 + plen]                      # strip Ethernet padding
    src, dst = _ip6_str(l3[8:24]), _ip6_str(l3[24:40])
    walked = _walk_ipv6_ext(l3[6], l3, 40, stats)
    if walked is None:
        stats["malformed_packets"] += 1
        return None
    nh, off, frag = walked
    if frag is None:
        return _Datagram(6, src, dst, nh, l3[off:], frame_len)
    frag_off, more, ident, nh_after = frag
    if defrag is None:
        return None
    done = defrag.add((src, dst, ident), frag_off, more, l3[off:], now, frame_len)
    if done is None:
        return None
    payload, nbytes, nfrags = done
    walked = _walk_ipv6_ext(nh_after, payload, 0, stats)
    if walked is None or walked[2] is not None:
        stats["malformed_packets"] += 1
        return None
    nh, off, _ = walked
    return _Datagram(6, src, dst, nh, payload[off:], nbytes, nfrags)


def _ndp_options(body: bytes, start: int) -> dict:
    """{option_type: value_bytes} for NDP options (RFC 4861 4.6)."""
    out = {}
    off = start
    while off + 2 <= len(body):
        otype, olen = body[off], body[off + 1] * 8
        if olen == 0 or off + olen > len(body):
            break
        out.setdefault(otype, body[off + 2:off + olen])
        off += olen
    return out


def _ndp_bindings(icmp: bytes, src_ip: str, src_mac: Optional[str]):
    """-> (list of (ip, mac) bindings, is_router_advert). Only Ethernet
    (6-byte) link-layer options are used."""
    if len(icmp) < 4:
        return [], False
    itype = icmp[0]
    out = []
    if itype == 135 and len(icmp) >= 24:          # Neighbor Solicitation
        sll = _ndp_options(icmp, 24).get(1)
        if src_ip != "::" and sll and len(sll) >= 6:
            out.append((src_ip, _mac_str(sll[:6])))
    elif itype == 136 and len(icmp) >= 24:        # Neighbor Advertisement
        target = _ip6_str(icmp[8:24])
        tll = _ndp_options(icmp, 24).get(2)
        if tll and len(tll) >= 6:
            out.append((target, _mac_str(tll[:6])))
        elif src_ip == target and src_mac:
            out.append((target, src_mac))
    elif itype == 134 and len(icmp) >= 16:        # Router Advertisement
        sll = _ndp_options(icmp, 16).get(1)
        mac = _mac_str(sll[:6]) if sll and len(sll) >= 6 else src_mac
        if mac and src_ip != "::":
            out.append((src_ip, mac))
        return out, True
    elif itype == 133 and len(icmp) >= 8:         # Router Solicitation
        sll = _ndp_options(icmp, 8).get(1)
        if src_ip != "::" and sll and len(sll) >= 6:
            out.append((src_ip, _mac_str(sll[:6])))
    return out, False


def _frame_time(meta, nano: bool) -> datetime:
    try:
        if hasattr(meta, "tshigh"):
            if meta.tshigh is None:
                return datetime.now(timezone.utc)
            ticks = (meta.tshigh << 32) + meta.tslow
            res = meta.tsresol or 1_000_000
            sec, frac = divmod(ticks, res)
            return (datetime.fromtimestamp(sec, tz=timezone.utc)
                    + timedelta(microseconds=frac * 1_000_000 // res))
        sub = meta.usec // 1000 if nano else meta.usec
        return datetime.fromtimestamp(meta.sec, tz=timezone.utc) + timedelta(microseconds=sub)
    except (TypeError, ValueError, OverflowError, OSError, AttributeError):
        return datetime.now(timezone.utc)


def _iter_frames(pcap_path: str, limits: Optional["_PcapLimits"] = None, main: bool = False):
    """Yield (data, linktype, metadata, nano) for every record in the file.

    B-08: the header is validated first (UnsupportedCaptureError for
    compressed / non-capture files) and scapy gets an already-open file
    object, so it never wraps the file in a gzip decoder.  With ``limits``
    reading stops with _PcapLimitHit after max_packets records or once
    max_seconds has elapsed (``main``: count records in limits.records)."""
    check_capture_file(pcap_path)
    n = 0
    with open(pcap_path, "rb") as fh, RawPcapReader(fh) as reader:
        default_lt = getattr(reader, "linktype", 1)
        nano = bool(getattr(reader, "nano", False))
        for data, meta in reader:
            if limits is not None:
                if n >= limits.max_packets:
                    raise _PcapLimitHit("max_packets")
                if not n & 0x3FF:
                    limits.check_time()
            n += 1
            if main and limits is not None:
                limits.records = n
            yield data, getattr(meta, "linktype", default_lt), meta, nano


def _frames_until_limit(pcap_path: str, limits: Optional["_PcapLimits"], stopped: list,
                        main: bool = False):
    """_iter_frames that ends quietly at a B-08 limit, appending its name to
    ``stopped``."""
    try:
        yield from _iter_frames(pcap_path, limits, main=main)
    except _PcapLimitHit as hit:
        stopped.append(hit.limit)


def _packet_time(pkt) -> datetime:
    try:
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Pre-pass: MAC <-> IP observations for gateway detection (T3-29) and host
# identity (F-09)
# ---------------------------------------------------------------------------

def _l3_bytes(data: bytes, l2) -> Optional[bytes]:
    off = l2[3]
    if isinstance(off, tuple):
        return off[1]
    return data[off:]


_PRESCAN_MAX_MACS = env_int("IACS_PCAP_PRESCAN_MAX_MACS", 65_536)
_PRESCAN_MAX_IPS_PER_MAC = env_int("IACS_PCAP_PRESCAN_MAX_IPS_PER_MAC", 4_096)


def _prescan(pcap_path: str, limits: Optional["_PcapLimits"] = None) -> dict:
    """
    Cheap header-only pass over the capture collecting, per unicast MAC, the
    IPv4/IPv6 addresses seen with it (src MAC/src IP and dst MAC/dst IP, in
    capture order), the addresses it claimed itself in ARP or NDP, NDP
    bindings, and the MACs that sent IPv6 Router Advertisements.
    """
    mac_ips: dict[str, dict] = {}
    arp_ips: dict[str, set] = {}
    ndp_ips: dict[str, set] = {}
    router_macs: set = set()
    # LS-05 / MV-07: per source MAC, up to 64 distinct (src ip, dst ip) pairs
    # it sent - routed frames are the ones whose two addresses lie in
    # different known interface networks (l3_switch.routed_by)
    mac_pairs: dict[str, set] = {}
    # VD-02a: the same per DESTINATION MAC - with a known capture point a
    # frame delivered to a MAC for an off-segment address names the gateway
    mac_dst_pairs: dict[str, set] = {}
    # FO-04: per requesting MAC, the addresses it asked for in ARP (a sweep
    # ARPs for every address; most of them never answer) - bounded
    arp_requests: dict[str, dict] = {}
    # AU full review E-M1: a synthetic capture (random MACs / addresses) made
    # these dicts grow with the frame count; bounded, with the overflow counted.
    dropped = {"macs": 0, "ips": 0}

    def _note(mac: Optional[str], ip: str) -> None:
        if mac is None or int(mac[0:2], 16) & 0x01:
            return
        ips = mac_ips.get(mac)
        if ips is None:
            if len(mac_ips) >= _PRESCAN_MAX_MACS:
                dropped["macs"] += 1
                return
            ips = mac_ips[mac] = {}
        if ip not in ips:
            if len(ips) >= _PRESCAN_MAX_IPS_PER_MAC:
                dropped["ips"] += 1
                return
            ips[ip] = None

    def _pair(mac: Optional[str], sip: str, dip: str, table: Optional[dict] = None) -> None:
        if mac is None or int(mac[0:2], 16) & 0x01:
            return
        ps = (mac_pairs if table is None else table).setdefault(mac, set())
        if len(ps) < 64:
            ps.add((sip, dip))

    # RS-07: per (source MAC, source address) the 802.1Q VLAN ids it was seen in
    src_vlans: dict = {}
    # RS-01: (src mac, dst mac, src ip, dst ip) of frames between two /24s
    direct: set = set()

    def _src_vlan(mac, ip, vid) -> None:
        if vid is None or mac is None or int(mac[0:2], 16) & 0x01:
            return
        k = (mac, ip)
        v = src_vlans.get(k)
        if v is None:
            if len(src_vlans) >= _PRESCAN_MAX_SRC_VLANS:
                return
            v = src_vlans[k] = set()
        if len(v) < 8:
            v.add(vid)

    stopped: list = []          # B-08: limit that ended the scan (if any)
    for data, linktype, _meta, _nano in _frames_until_limit(pcap_path, limits, stopped):
        l2 = _decode_l2(data, linktype)
        if l2 is None:
            continue
        src_mac, dst_mac, etype, off = l2
        vid = _vlan_id(data, linktype)
        if etype == _ETH_IPV4:
            l3 = _l3_bytes(data, l2)
            if len(l3) >= 20:
                _sip, _dip = _ip4_str(l3[12:16]), _ip4_str(l3[16:20])
                _note(src_mac, _sip)
                _note(dst_mac, _dip)
                _pair(src_mac, _sip, _dip)
                _pair(dst_mac, _sip, _dip, mac_dst_pairs)
                _src_vlan(src_mac, _sip, vid)
                if l3[12:15] != l3[16:19] and src_mac and dst_mac and len(direct) < _PRESCAN_MAX_DIRECT \
                        and not int(dst_mac[0:2], 16) & 0x01:
                    direct.add((src_mac, dst_mac, _sip, _dip))
        elif etype == _ETH_IPV6:
            l3 = _l3_bytes(data, l2)
            if len(l3) < 40:
                continue
            src, dst = _ip6_str(l3[8:24]), _ip6_str(l3[24:40])
            if src != "::":
                _note(src_mac, src)
            if not dst.startswith("ff"):
                _note(dst_mac, dst)
                if src != "::":
                    _pair(src_mac, src, dst)
                    _pair(dst_mac, src, dst, mac_dst_pairs)
            walked = _walk_ipv6_ext(l3[6], l3, 40, {"ipv6_extension_headers": 0})
            if walked and walked[0] == _PROTO_ICMPV6 and walked[2] is None:
                icmp = l3[walked[1]:]
                if icmp and icmp[0] in _NDP_TYPES:
                    binds, is_ra = _ndp_bindings(icmp, src, src_mac)
                    for ip, mac in binds:
                        if not int(mac[0:2], 16) & 0x01:
                            _s = ndp_ips.setdefault(mac, set())
                            if len(_s) < _PRESCAN_MAX_IPS_PER_MAC:
                                _s.add(ip)
                            _note(mac, ip)
                    if is_ra and src_mac:
                        router_macs.add(src_mac)
        elif etype == _ETH_ARP and not isinstance(off, tuple) and len(data) >= off + 28:
            # ARP sender hardware / protocol address (IPv4 over Ethernet)
            if data[off + 4] == 6 and data[off + 5] == 4:
                sha = data[off + 8:off + 14]
                spa = data[off + 14:off + 18]
                if spa != b"\x00\x00\x00\x00":
                    _src_vlan(_mac_str(sha), _ip4_str(spa), vid)
                if not sha[0] & 0x01:
                    _m = _mac_str(sha)
                    _s = arp_ips.get(_m)
                    if _s is None:
                        if len(arp_ips) >= _PRESCAN_MAX_MACS:
                            dropped["macs"] += 1
                            continue
                        _s = arp_ips[_m] = set()
                    if len(_s) < _PRESCAN_MAX_IPS_PER_MAC:
                        _s.add(_ip4_str(spa))
                    else:
                        dropped["ips"] += 1
                    # FO-04: a who-has (op 1) for another address
                    tpa = data[off + 24:off + 28]
                    if data[off + 6:off + 8] == b"\x00\x01" and tpa != spa and spa != b"\x00\x00\x00\x00":
                        _r = arp_requests.setdefault(_m, {})
                        if len(_r) < 1024:
                            _t = _ip4_str(tpa)
                            _r.setdefault(_t, [_ip4_str(spa), 0])
                            _r[_t][1] += 1
    return {"mac_ips": mac_ips, "arp_ips": arp_ips, "ndp_ips": ndp_ips, "mac_pairs": mac_pairs,
            "mac_dst_pairs": mac_dst_pairs, "arp_requests": arp_requests,
            "src_vlans": src_vlans, "direct_pairs": direct,
            "router_macs": router_macs, "stopped_by": stopped[0] if stopped else None,
            "prescan_macs_dropped": dropped["macs"], "prescan_ips_dropped": dropped["ips"]}


def _new_stats() -> dict:
    return {
        "packets": 0,
        "sessions": 0,
        "hosts": 0,          # filled at end: hosts created by this ingest
        "hosts_total": 0,    # total Host rows in DB after ingest
        "protocol_frames": {
            "modbus": 0, "s7comm": 0, "dnp3": 0, "ethernet_ip": 0,
            "profinet": 0, "smb1": 0, "smb2_3": 0,
        },
        # F-07: IPv6 is ingested now. ipv6_packets_skipped is kept (always 0)
        # for one release so existing consumers don't break.
        "ipv6_packets": 0,
        "ipv6_packets_skipped": 0,
        "ipv6_extension_headers": 0,
        "ipv6_multicast_packets": 0,
        "ipv6_multicast_groups": {},
        "ipv4_multicast_packets": 0,
        "ipv4_multicast_groups": {},
        "ipv4_broadcast_packets": 0,
        "icmpv6_packets": 0,
        "ndp_packets": 0,
        "ndp_bindings": 0,
        "malformed_packets": 0,
        "analyzer_errors": 0,
        "analyzer_errors_by_protocol": {},
        "tcp_retransmitted_segments": 0,
        "tcp_out_of_order_segments": 0,
        "tcp_gaps": 0,
        "stream_resyncs": 0,
        "resync_bytes_skipped": 0,
        "stream_buffer_overflows": 0,
        "streams_evicted": 0,
        "gateway_macs": [],
        "host_cache_hits": 0,
        "host_insert_conflicts": 0,
    }


#: PostgreSQL advisory-lock class of pcap ingests (second key: site id).
_PCAP_PG_LOCK_ID = 0x1A5C_0B08 & 0x7FFFFFFF


def _serialize_site_ingest(db: DBSession) -> None:
    """B-08 follow-up: on PostgreSQL, overlapping pcap ingests of the SAME
    site run one after the other (transaction-scoped advisory lock, released
    by the ingest's - or with commit=False the caller's - commit/rollback),
    like SQLite's BEGIN IMMEDIATE writers.  Taken before the per-ingest
    host cache / site ip+mac sets are loaded, so they are never stale with
    respect to another pcap ingest: host_identity reconciliation (same ip
    with a new mac, IP-only merge, ...) always sees the other ingest's rows,
    and two overlapping uploads cannot deadlock on each other's uncommitted
    host / session inserts.  Different sites still ingest concurrently.
    Writers that do not take it (ARP / config / MAC-table ingests) are
    covered by insert_host_row's ON CONFLICT handling."""
    if db.get_bind().dialect.name != "postgresql":
        return
    from app.sites import scope_site_id
    db.execute(text("SELECT pg_advisory_xact_lock(:k, :s)"),
               {"k": _PCAP_PG_LOCK_ID, "s": int(scope_site_id(db))})


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_pcap(
    pcap_path: str,
    db: DBSession,
    source_file: Optional[str] = None,
    pcap_capture_id: Optional[int] = None,
    commit: bool = True,
    capture_point: Optional[dict] = None,
) -> dict:
    """
    Parse a pcap file and populate Host / NetworkSession / ProtocolDetail.

    Args:
        pcap_path: Local filesystem path to the pcap file.
        db: Active SQLAlchemy session.
        source_file: Human-readable filename for display (defaults to pcap_path).
        pcap_capture_id: If provided, every NetworkSession created or touched
            during this ingest has its ``pcap_capture_id`` set to this value,
            linking sessions back to the PcapCapture row created by the
            multi-FW aware upload endpoint.
        commit: True (default) commits ONCE at the end and rolls back on any
            exception. False only flushes: the caller owns the transaction
            and must commit/rollback (T3-13 - e.g. /ingest/pcap-fw, so a
            later failure in the route leaves no partial capture behind).
        capture_point: VD-02a - where the capture was taken
            (app.parsers.capture_point.resolve).  Decides gateway MACs on a
            single frame; None = the router heuristics alone.

    Returns a small summary dict (counts) so the API can report back
    what happened without the caller needing to query the DB.

    B-08: raises UnsupportedCaptureError for a compressed / non-capture file
    (before touching the DB).  The PCAP_LIMITS caps stop processing early;
    what was processed is kept and the stats carry ``truncated`` /
    ``truncated_by`` / ``records_processed`` / ``limits``.
    """
    try:
        _serialize_site_ingest(db)
        stats = _ingest_pcap(pcap_path, db, source_file, pcap_capture_id, capture_point)
        if commit:
            db.commit()
        else:
            db.flush()
    except Exception:
        if commit:
            db.rollback()
        raise
    from app.sites import scope_site_id
    stats["hosts_total"] = db.query(Host).filter(Host.site_id == scope_site_id(db), real_host_clause()).count()
    return stats


# B-14a: NetworkSession.dst_host_id is NOT NULL, yet a DNP3 request sent to
# a broadcast / multicast group has no destination host.  Rather than invent
# a Host per group address (the phantom hosts B-14b removes), each site gets
# ONE synthetic marker Host standing for "a broadcast/multicast group":
# MAC ff:ff:ff:ff:ff:ff, no IP, classification_source "manual" (so device
# classification never turns it into an RTU/PLC).  Group-addressed DNP3 is
# recorded on a session sender -> marker, and every ProtocolDetail carries
# the real group address in fields["dst_group"], so
# check_unauthorized_industrial_writes sees the write (client = sender).
from app.models import GROUP_MARKER_MAC, real_host_clause  # noqa: E402,F401
GROUP_MARKER_HOSTNAME = "(broadcast/multicast group)"
GROUP_MARKER_SOURCE = "group_marker"


def get_group_marker_host(db: DBSession, site_id: int, seen_at: Optional[datetime] = None) -> Host:
    """The per-site broadcast/multicast group marker Host (created on first use)."""
    host = (db.query(Host)
            .filter(Host.site_id == site_id, Host.mac == GROUP_MARKER_MAC, Host.ip.is_(None))
            .order_by(Host.id).first())
    if host is None:
        seen_at = seen_at or datetime.now(timezone.utc)
        host = Host(site_id=site_id, ip=None, mac=GROUP_MARKER_MAC,
                    hostname=GROUP_MARKER_HOSTNAME, vendor=None,
                    sources=[GROUP_MARKER_SOURCE], classification_source="manual",
                    first_seen=seen_at, last_seen=seen_at, stale=False)
        db.add(host)
        db.flush()
    return host


def is_group_marker_host(host) -> bool:
    return bool(host is not None and host.ip is None and host.mac == GROUP_MARKER_MAC
                and GROUP_MARKER_SOURCE in (host.sources or []))


#: FO-07: ports whose payload is checked for a cleartext login
_CT_HTTP_PORTS = frozenset({80, 81, 8000, 8008, 8080, 8081, 8888})
_TELNET_PROMPTS = (b"login:", b"username:", b"user name:", b"password:")


def _cleartext_auth(payload: bytes, sport: int, dport: int, tr: dict) -> Optional[str]:
    """FO-07: the kind of cleartext login this TCP payload shows, or None.
    Never returns or stores the secret itself.  ``tr`` is the session's
    tracking dict (telnet: the server's prompt must come first)."""
    head = payload[:512]
    low = head.lower()
    if dport in (21, 110):
        if low.startswith(b"pass "):
            return "FTP login" if dport == 21 else "POP3 login"
        if low.startswith(b"apop ") and dport == 110:
            return "POP3 login"
        return None
    if dport == 143:
        first = low.split(b"\r\n", 1)[0]
        return "IMAP login" if b" login " in first else None
    if dport in (25, 587):
        return "SMTP AUTH" if low.startswith((b"auth plain", b"auth login")) else None
    if sport == 23:
        if any(pr in low for pr in _TELNET_PROMPTS):
            tr["telnet_prompt"] = True
        return None
    if dport == 23:
        return "Telnet login" if tr.get("telnet_prompt") and head.strip() else None
    if dport in _CT_HTTP_PORTS or b"http/1." in low[:256]:
        if b"\r\nauthorization: basic " in low:
            return "HTTP Basic auth"
    return None


# batch C (owner 2026-10-15): default credential pairs - compared in the
# stream, never stored (IAC-08 "default credentials in cleartext protocols").
_DEFAULT_USERS = frozenset({"admin", "administrator", "root", "user", "guest", "operator", "service", "support",
                            "manager", "supervisor", "engineer", "siemens", "rockwell", "plc", "hmi", "scada",
                            "test", "default", "cisco", "ubnt", "pi"})
_DEFAULT_PASSWORDS = frozenset({"", "admin", "password", "passw0rd", "1234", "12345", "123456", "12345678",
                                "root", "default", "guest", "operator", "service", "support", "manager", "user",
                                "pass", "letmein", "welcome", "changeme", "siemens", "rockwell", "plc", "hmi",
                                "scada", "public", "private", "test", "0000", "00000000", "cisco", "ubnt",
                                "raspberry", "qwerty", "abc123", "administrator", "toor"})


def _is_default_pair(user: str, password: str) -> bool:
    """A well-known default user with a default password (or its own name as password)."""
    u, pw = user.strip().lower(), password.strip().lower()
    return bool(u) and u in _DEFAULT_USERS and (pw in _DEFAULT_PASSWORDS or pw == u)


def _user_digest(user: str) -> bytes:
    import hashlib
    return hashlib.sha256(user.strip().lower().encode("utf-8", "replace")).digest()


def _default_credentials(payload: bytes, sport: int, dport: int, tr: dict) -> Optional[str]:
    """'default credentials (<proto>)' when a cleartext login in this payload uses
    a well-known default user / password pair; the values are never kept."""
    head = payload[:512]
    low = head.lower()
    try:
        if dport in (21, 110):
            if low.startswith(b"user "):
                # the user name is kept only as "is a default user" + a digest (never verbatim)
                u = head[5:].split(b"\r\n", 1)[0].decode("latin-1", "replace").strip().lower()
                tr["ct_user_default"] = u in _DEFAULT_USERS
                tr["ct_user_digest"] = _user_digest(u)
                return None
            if low.startswith(b"pass "):
                pw = head[5:].split(b"\r\n", 1)[0].decode("latin-1", "replace").strip().lower()
                if tr.get("ct_user_default") and (pw in _DEFAULT_PASSWORDS or _user_digest(pw) == tr.get("ct_user_digest")):
                    return "default credentials (FTP)" if dport == 21 else "default credentials (POP3)"
            return None
        if dport in (25, 587) and low.startswith(b"auth plain "):
            import base64
            try:
                raw = base64.b64decode(head.split(b" ", 2)[2].strip(), validate=False)
            except Exception:
                return None
            parts = raw.split(b"\x00")
            if len(parts) >= 3 and _is_default_pair(parts[1].decode("latin-1", "replace"), parts[2].decode("latin-1", "replace")):
                return "default credentials (SMTP)"
            return None
        if (dport in _CT_HTTP_PORTS or b"http/1." in low[:256]) and b"\r\nauthorization: basic " in low:
            import base64
            i = low.index(b"\r\nauthorization: basic ") + len(b"\r\nauthorization: basic ")
            tok = head[i:].split(b"\r\n", 1)[0].strip()
            try:
                raw = base64.b64decode(tok, validate=False).decode("latin-1", "replace")
            except Exception:
                return None
            if ":" in raw and _is_default_pair(*raw.split(":", 1)):
                return "default credentials (HTTP Basic)"
    except (IndexError, UnicodeDecodeError):
        return None
    return None


# batch C: negotiated TLS / SSH versions below the floor (DT-03 / DT-04)
_WEAK_TLS = {b"\x03\x00": "SSLv3", b"\x03\x01": "TLSv1.0", b"\x03\x02": "TLSv1.1"}
_SSH_BANNER_RE = re.compile(rb"^SSH-(\d\.\d+)-([^\r\n]{1,80})")


def _weak_transport(payload: bytes, sport: int = 0) -> Optional[str]:
    """'TLSv1.0' / 'TLSv1.1' / 'SSLv3' when this payload is a TLS ServerHello
    negotiating that version, 'SSH-1' for an SSH-1 server banner (port 22;
    "SSH-1.99" is an SSH-2 server with v1 compatibility - not weak), else None."""
    if len(payload) >= 11 and payload[0] == 0x16 and payload[5] == 0x02:
        return _WEAK_TLS.get(bytes(payload[9:11]))
    if sport == 22 and payload[:6] == b"SSH-1." and payload[:8] != b"SSH-1.99":
        return "SSH-1"
    return None


def _snmp_community(payload: bytes) -> Optional[str]:
    """FO-07: 'SNMPv1/v2c community' when the UDP payload is an SNMP v1/v2c
    message carrying a community string (BER: SEQUENCE, INTEGER version 0/1,
    OCTET STRING community)."""
    try:
        if len(payload) < 8 or payload[0] != 0x30:
            return None
        i = 2 if payload[1] < 0x80 else 2 + (payload[1] & 0x7F)
        if payload[i] != 0x02 or payload[i + 1] != 1 or payload[i + 2] not in (0, 1):
            return None
        i += 3
        if payload[i] != 0x04 or payload[i + 1] == 0:
            return None
        # batch C: the default strings are reported as such (the value is never stored)
        n = payload[i + 1]
        if n < 0x80 and bytes(payload[i + 2:i + 2 + n]).lower() in (b"public", b"private"):
            return "SNMPv1/v2c community (default)"
        return "SNMPv1/v2c community"
    except IndexError:
        return None


def _capture_segment(capture_point: Optional[dict], scan: dict, gateway_macs: set) -> Optional[dict]:
    """FO-01: the layer-2 segment this capture shows.  The capture point's
    networks when the operator named an interface / segment; otherwise the
    /24 networks of the on-link IPv4 addresses (claimed in ARP, or carried
    by a MAC that is not a router), keeping a /24 with two or more of them.
    Returns {networks, basis, gateway_macs, on_link} or None."""
    import ipaddress as _ipa
    gws = sorted({normalize_mac(m) or m for m in gateway_macs})
    local = (capture_point or {}).get("local_networks") or []
    if local and (capture_point or {}).get("association") in ("interface", "segment"):
        return {"networks": [str(n) for n in local], "basis": "capture point", "gateway_macs": gws,
                "on_link": None}
    on_link: set = set()
    for table in (scan.get("arp_ips") or {}, scan.get("ndp_ips") or {}):
        for mac, ips in table.items():
            if mac not in gateway_macs:
                on_link.update(ips)
    for mac, ips in (scan.get("mac_ips") or {}).items():
        if mac not in gateway_macs:
            on_link.update(ips)
    per_net: dict = {}
    for ip in on_link:
        try:
            a = _ipa.ip_address(ip)
        except ValueError:
            continue
        if a.version != 4 or not a.is_private or a.is_link_local or a.is_multicast or a.is_loopback \
                or a.is_unspecified or str(a).endswith(".255"):
            continue
        n = _ipa.ip_network(f"{a}/24", strict=False)
        per_net.setdefault(n, set()).add(ip)
    nets = sorted((n for n, ips in per_net.items() if len(ips) >= 2), key=lambda n: int(n.network_address))
    if not nets:
        return None
    seg = {"networks": [str(n) for n in nets], "basis": "inferred: /24 of the on-link addresses",
           "gateway_macs": gws, "on_link": sum(len(per_net[n]) for n in nets),
           "domains": _l2_domains(nets, scan, gateway_macs)}
    vl = _net_vlans(nets, scan, gateway_macs)
    if vl:
        seg["vlans"] = {n: sorted(v) for n, v in vl.items()}        # RS-07
    return seg


def _net_vlans(nets: list, scan: dict, gateway_macs: set) -> dict:
    """RS-07: the 802.1Q VLAN ids each capture network's own hosts sent in
    (frames of router MACs left out: a router sends into every VLAN)."""
    import ipaddress as _ipa
    out: dict = {}
    for (mac, ip), vids in (scan.get("src_vlans") or {}).items():
        if mac in gateway_macs:
            continue
        try:
            a = _ipa.ip_address(ip)
        except ValueError:
            continue
        for n in nets:
            if a.version == n.version and a in n:
                out.setdefault(str(n), set()).update(vids)
                break
    return out


def _l2_domains(nets: list, scan: dict, gateway_macs: set) -> list:
    """IO-03: which capture networks share one layer-2 segment.  Evidence
    that two subnets sit on one wire with no router between them: a MAC that
    is no router uses / claims addresses in both (a multi-homed host), or ONE
    frame between hosts of the two subnets goes MAC to MAC (neither its
    source nor its destination MAC is a router).  RS-01: two subnets whose
    hosts were seen in different 802.1Q VLANs are never one segment, and the
    two copies a SPAN shows of a routed packet (host -> router, router ->
    host) are separate frames, not MAC-to-MAC evidence.  Returns the networks
    grouped (union-find); a network without such evidence is a domain of its
    own."""
    import ipaddress as _ipa
    parent = {str(n): str(n) for n in nets}
    vlans = _net_vlans(nets, scan, gateway_macs)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        va, vb = vlans.get(a), vlans.get(b)
        if va and vb and not (va & vb):
            return                      # different VLANs: separate broadcast domains
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    def net_of(ip):
        try:
            a = _ipa.ip_address(ip)
        except ValueError:
            return None
        for n in nets:
            if a.version == n.version and a in n:
                return str(n)
        return None

    claimed: dict = {}
    for table in (scan.get("arp_ips") or {}, scan.get("ndp_ips") or {}):
        for mac, ips in table.items():
            claimed.setdefault(mac, set()).update(ips)
    for mac in set(claimed) | set(scan.get("mac_ips") or {}):
        if mac in gateway_macs:
            continue
        own = claimed.get(mac) or set(list((scan.get("mac_ips") or {}).get(mac, {}))[:1])
        ns = {net_of(ip) for ip in own} - {None}
        for a in ns:
            for b in ns:
                union(a, b)
    for smac, dmac, sip, dip in scan.get("direct_pairs") or ():
        if smac in gateway_macs or dmac in gateway_macs:
            continue
        na, nb = net_of(sip), net_of(dip)
        if na and nb and na != nb:
            union(na, nb)
    groups: dict = {}
    for n in nets:
        groups.setdefault(find(str(n)), []).append(str(n))
    return sorted(groups.values())


#: IO-07: UDP ports whose traffic is one-way by design (no reply expected)
_UDP_ONE_WAY = frozenset({514, 162, 2055, 4739, 6343, 9995, 9996, 20000, 2222, 34962, 34963, 34964,
                          47808, 44818, 5353, 1900, 137, 138, 67, 68, 546, 547, 319, 320, 6514})


def _dhcp_reply(payload: bytes) -> Optional[dict]:
    """IO-04: a DHCP server reply (BOOTREPLY with message type OFFER / ACK):
    {type, yiaddr, router, server_id} or None."""
    import ipaddress as _ipa
    if len(payload) < 240 or payload[0] != 2 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    out = {"yiaddr": str(_ipa.IPv4Address(payload[16:20])), "type": None, "router": None, "server_id": None}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        ln = payload[i + 1]
        val = payload[i + 2:i + 2 + ln]
        if code == 53 and ln >= 1:
            out["type"] = {2: "offer", 5: "ack"}.get(val[0])
        elif code == 3 and ln >= 4:
            out["router"] = str(_ipa.IPv4Address(val[:4]))
        elif code == 54 and ln >= 4:
            out["server_id"] = str(_ipa.IPv4Address(val[:4]))
        i += 2 + ln
    return out if out["type"] else None


def _store_attempts(db: DBSession, attempts: dict, pcap_capture_id) -> dict:
    """FO-04: upsert ConnectionAttempt rows (one per source, target, port,
    transport, outcome) for this ingest's site; returns counts by outcome."""
    from app.models import ConnectionAttempt
    out: dict = {}
    for (sip, dip, port, transport, outcome), a in attempts.items():
        q = db.query(ConnectionAttempt).filter(
            ConnectionAttempt.src_ip == sip, ConnectionAttempt.dst_ip == dip,
            ConnectionAttempt.transport == transport, ConnectionAttempt.outcome == outcome,
            ConnectionAttempt.dst_port.is_(None) if port is None else ConnectionAttempt.dst_port == port)
        row = q.first()
        first, last = as_utc(a["first"]), as_utc(a["last"])
        if row is None:
            db.add(ConnectionAttempt(src_ip=sip, src_mac=a["src_mac"], dst_ip=dip, dst_port=port,
                                     transport=transport, outcome=outcome, count=a["count"],
                                     first_seen=first, last_seen=last, pcap_capture_id=pcap_capture_id))
        else:
            row.count = (row.count or 0) + a["count"]
            if first and (row.first_seen is None or first < as_utc(row.first_seen)):
                row.first_seen = first
            if last and (row.last_seen is None or last > as_utc(row.last_seen)):
                row.last_seen = last
            if pcap_capture_id is not None:
                row.pcap_capture_id = pcap_capture_id
        out[outcome] = out.get(outcome, 0) + 1
    if attempts:
        db.flush()
    return out


def _ingest_pcap(
    pcap_path: str,
    db: DBSession,
    source_file: Optional[str],
    pcap_capture_id: Optional[int],
    capture_point: Optional[dict] = None,
) -> dict:
    source_file = source_file or pcap_path
    limits = _PcapLimits()      # B-08
    stopped: list = []          # B-08: name of the limit that stopped the ingest
    sessions_cache: dict = {}
    # Per-direction TCP reassembly state (Modbus, S7comm, ENIP/CIP, DNP3).
    # A-30: LRU order (oldest first) for MAX_TCP_STREAMS / MAX_REASSEMBLY_BYTES
    tcp_streams: "OrderedDict[_StreamKey, _TcpStream]" = OrderedDict()
    reasm_bytes = [0]           # running total of _TcpStream.mem()
    stats = _new_stats()
    logged_analyzers: set = set()
    defrag4 = _Defragmenter(stats, "ipv4")
    defrag6 = _Defragmenter(stats, "ipv6")
    dnp3_stats = {"dnp3_transport_segments": 0, "dnp3_fragments_reassembled": 0,
                  "dnp3_transport_segments_dropped": 0}
    mcast_groups: dict = stats["ipv6_multicast_groups"]

    # F-13: per-ingest host cache keyed by (ip, normalized mac, source) so
    # repeated hosts don't cost two SELECTs per packet. Packet-time bounds per
    # host / session / address are accumulated in memory and written once.
    host_cache: dict[tuple, Host] = {}
    host_times: dict[int, list] = {}
    session_times: dict[int, list] = {}
    # FO-04: per TCP session row touched by this ingest - was it new, did a
    # handshake complete, did any payload flow, who sent the SYN
    tcp_track: dict[int, dict] = {}
    udp_auth: dict[int, list] = {}          # FO-07: SNMP community strings per UDP row
    udp_track: dict[int, dict] = {}         # IO-07: UDP rows - first sender, answered?
    dhcp_servers: dict = {}                 # IO-04: DHCP offers / acks per server
    addr_obs: dict[tuple, list] = {}
    ndp_seen: set = set()
    detail_rows: list[dict] = []

    # T3-29 / F-07: decide which MACs are routers before touching any Host row.
    scan = _prescan(pcap_path, limits)
    if scan["stopped_by"] == "max_seconds":
        stopped.append("max_seconds")
    arp_ips, ndp_ips = scan["arp_ips"], scan["ndp_ips"]
    own_ips: dict[str, set] = {}
    for src in (arp_ips, ndp_ips):
        for mac, ips in src.items():
            own_ips.setdefault(mac, set()).update(ips)
    v4_mac_ips = {m: [ip for ip in ips if ":" not in ip] for m, ips in scan["mac_ips"].items()}
    gateway_macs = detect_gateway_macs(v4_mac_ips, arp_ips)
    gateway_macs |= detect_gateway_macs_v6(scan["mac_ips"], ndp_ips, scan["router_macs"])
    # MV-07 / LS-05: routers the site already knows - firewall / routing-switch
    # interface MACs (switch ARP table) - and MACs carrying addresses of two
    # or more known interface networks.  Their own addresses are the
    # interface addresses.
    try:
        from app.parsers import l3_switch as _l3
        for m, ips in _l3.known_router_macs(db).items():
            gateway_macs.add(m)
            for raw in scan["mac_ips"]:
                if normalize_mac(raw) == m:
                    own_ips.setdefault(raw, set()).update(ips)
            own_ips.setdefault(m, set()).update(ips)
        _nets = _l3.known_networks(db)
        gateway_macs |= _l3.multi_network_macs(scan["mac_ips"], own_ips, _nets)
        gateway_macs |= _l3.routed_by(scan.get("mac_pairs") or {}, own_ips, _nets)
    except Exception:                                   # noqa: BLE001 - never fail the ingest
        log.warning("known router lookup failed", exc_info=True)
    # VD-02a: the capture point decides on a single frame; MACs learned from
    # earlier associated captures of the site count as routers too.
    from app.parsers import capture_point as _cp
    try:
        from app.sites import scope_site_id as _ssid
        for m, ips in _cp.known_capture_gateways(db, _ssid(db)).items():
            for raw in scan["mac_ips"]:
                if normalize_mac(raw) == m:
                    gateway_macs.add(raw)
                    own_ips.setdefault(raw, set()).update(ips)
    except Exception:                                   # noqa: BLE001
        log.warning("capture gateway lookup failed", exc_info=True)
    cp_gws, cp_own, cp_ev = _cp.gateways_from_scan(capture_point, scan, normalize_mac)
    gateway_macs |= cp_gws
    for m, ips in cp_own.items():
        own_ips.setdefault(m, set()).update(ips)
    stats["capture_point"] = _cp.describe(capture_point)
    stats["gateway_macs_by_capture_point"] = cp_ev
    stats["capture_point_fit"] = _cp.fit(capture_point, scan)
    stats["capture_point_notes"] = _cp.notes_for(capture_point, stats["capture_point_fit"], cp_ev)
    stats["capture_segment"] = _capture_segment(capture_point, scan, gateway_macs)
    try:
        stats["capture_point_suggestion"] = _cp.suggest_interface(db, capture_point, scan)
    except Exception:                                   # noqa: BLE001
        log.warning("capture point suggestion failed", exc_info=True)
        stats["capture_point_suggestion"] = None
    stats["gateway_macs"] = sorted(gateway_macs)
    if scan.get("prescan_macs_dropped") or scan.get("prescan_ips_dropped"):
        stats["prescan_macs_dropped"] = scan["prescan_macs_dropped"]
        stats["prescan_ips_dropped"] = scan["prescan_ips_dropped"]
        stats.setdefault("warnings", []).append(
            "prescan address table capped: %d MACs / %d addresses not tracked" %
            (scan["prescan_macs_dropped"], scan["prescan_ips_dropped"]))
    # LS-03: frozenset(host ids) -> {router MAC | None: frames}.  Counted per
    # frame, so the device that carried most of the pair's traffic wins
    # deterministically (dual gateways / asymmetric routing: see the doc);
    # None counts the frames with no router MAC, so a pair re-seen on one
    # segment clears a stale carrier.
    carriers: dict = {}

    def _carrier(sip, dip, smac, dmac) -> Optional[str]:
        if smac and smac in gateway_macs and sip not in own_ips.get(smac, ()) and not _is_link_local6(sip):
            return smac
        if dmac and dmac in gateway_macs and dip not in own_ips.get(dmac, ()) and not _is_link_local6(dip):
            return dmac
        return None

    def _note_carrier(src_host, dst_host, sip, dip, smac, dmac) -> None:
        if src_host is None or dst_host is None:
            return
        cm = _carrier(sip, dip, smac, dmac)
        slot = carriers.setdefault(frozenset((src_host.id, dst_host.id)), {})
        slot[cm] = slot.get(cm, 0) + 1

    def _effective_mac(ip: Optional[str], mac: Optional[str]) -> Optional[str]:
        if (ip and mac and mac in gateway_macs and ip not in own_ips.get(mac, ())
                and not _is_link_local6(ip)):
            # Routed traffic: the frame carries the gateway's MAC, not this
            # remote IP's own - don't give the remote host the router's
            # MAC/vendor.
            return None
        return mac

    # F-09: identity reconciliation (DHCP renumbering / IP-only merge / IP
    # conflicts) runs for every binding in the capture BEFORE the packet
    # loop, so no merge can invalidate a cached Host or session mid-ingest.
    # B-14b: broadcast addresses of the site's known subnets are never hosts.
    from app.sites import scope_site_id
    bcasts = site_broadcast_addresses(db, scope_site_id(db))
    bindings: dict[str, set] = {}
    for mac, ips in scan["mac_ips"].items():
        for ip in ips:
            if is_unicast_host_ip(ip, broadcasts=bcasts) and _effective_mac(ip, mac) == mac:
                bindings.setdefault(mac, set()).add(ip)
    # AU full review E-H2: an address a MAC claimed in ARP / NDP but never
    # used in an IP frame of this capture (a router's own interface address,
    # a host that only answered ARP) is a binding too - without it the
    # resolver never saw the renumbering / conflict it implies.
    for src in (arp_ips, ndp_ips):
        for mac, ips in src.items():
            for ip in ips:
                if is_unicast_host_ip(ip, broadcasts=bcasts):
                    bindings.setdefault(mac, set()).add(ip)
    resolver = HostIdentityResolver(db, "pcap", observed=bindings)
    # B-08: the site's known ips / macs, kept current for the whole ingest
    # (a superset is harmless; every row this ingest creates or fills in is
    # added).  A binding whose ip AND mac are both unknown cannot renumber,
    # merge or conflict, so reconcile() - 3 queries + a flush - is skipped,
    # and _host() inserts such hosts without the get_or_create lookups.
    site_ips: set = {ip for (ip,) in db.query(Host.ip).filter(
        Host.site_id == resolver.site_id, Host.ip.isnot(None))}
    site_macs: set = {m for (m,) in db.query(Host.mac).filter(
        Host.site_id == resolver.site_id, Host.mac.isnot(None))}
    # An existing exact (ip, mac) row makes reconcile() return at once (and a
    # pair observed in this capture is never renumbered or merged away).
    site_pairs: set = set(db.query(Host.ip, Host.mac).filter(
        Host.site_id == resolver.site_id, Host.ip.isnot(None), Host.mac.isnot(None)))
    try:
        for i, mac in enumerate(sorted(bindings)):
            if stopped:
                break
            if not i & 0xFF:
                limits.check_time()
            nmac = normalize_mac(mac)
            for ip in sorted(bindings[mac]):
                if (ip not in site_ips and nmac not in site_macs) or (ip, nmac) in site_pairs:
                    continue
                resolver.reconcile(ip, mac)
                site_ips.add(ip)
                if nmac:
                    site_macs.add(nmac)
    except _PcapLimitHit as hit:
        stopped.append(hit.limit)
    db.flush()
    # B-08: the site's hosts by exact (ip, mac) - the first match rule of
    # get_or_create_host for ip+mac, ip-only and mac-only lookups alike (the
    # unique indexes make each key unique) - so a host already known to the
    # site costs no query.  Loaded after reconcile() (which may merge rows).
    site_hosts: dict = {(h.ip, h.mac): h for h in db.query(Host).filter(
        Host.site_id == resolver.site_id)}
    site_host_key: dict = {id(h): k for k, h in site_hosts.items()}

    # Track host IDs present before the packet loop so we can report only
    # the hosts added (created) by THIS run, not the total DB count. (P4-L4)
    hosts_before: set[int] = {h.id for h in db.query(Host.id).filter(
        Host.site_id == resolver.site_id).all()}
    new_host_ids: set[int] = set()
    created_ids: set[int] = set()

    def _host(ip: Optional[str], mac: Optional[str], ts: datetime,
              source: str = "pcap") -> Optional[Host]:
        if source != "ndp":
            mac = _effective_mac(ip, mac)
        key = (ip, mac, source)
        host = host_cache.get(key)
        if host is None:
            if len(created_ids) >= limits.max_new_hosts:
                raise _PcapLimitHit("max_new_hosts")      # B-08
            host = _lookup_host(ip, mac, source, ts)
            if host is None:
                return None
            host_cache[key] = host
            new_host_ids.add(host.id)
            if host.id not in hosts_before:
                created_ids.add(host.id)
        else:
            stats["host_cache_hits"] += 1
        t = host_times.get(host.id)
        if t is None:
            host_times[host.id] = [host, ts, ts]
        else:
            if ts < t[1]:
                t[1] = ts
            if ts > t[2]:
                t[2] = ts
        okey = (host.id, ip, mac, source)
        o = addr_obs.get(okey)
        if o is None:
            addr_obs[okey] = [host, ts, ts, 1]
        else:
            if ts < o[1]:
                o[1] = ts
            if ts > o[2]:
                o[2] = ts
            o[3] += 1
        return host

    def _lookup_host(ip, mac, source, ts) -> Optional[Host]:
        """get_or_create_host, minus its lookup queries (B-08): an exact
        (ip, mac) row already in the site is reused from memory, and when the
        site certainly has no row with this ip or mac the host is inserted
        directly - race-safe (insert_host_row: ON CONFLICT DO NOTHING, then
        the row a concurrent ingest of the site inserted meanwhile is
        re-selected with the get_or_create_host rules and reused)."""
        nmac = normalize_mac(mac)
        ip = ip or None
        if not ip and not nmac:
            return None
        known = site_hosts.get((ip, nmac))
        if known is not None:
            return refresh_host(known, ip, nmac, source, as_utc(ts) or datetime.now(timezone.utc))
        if (not ip or ip not in site_ips) and (not nmac or nmac not in site_macs):
            host, created = insert_host_row(db, ip, nmac, source,
                                            as_utc(ts) or datetime.now(timezone.utc),
                                            resolver.site_id)
            if not created:
                hosts_before.add(host.id)     # another ingest created it
                stats["host_insert_conflicts"] += 1
        else:
            host = get_or_create_host(db, ip, mac, source=source, seen_at=ts)
        if host is not None:
            if host.ip:
                site_ips.add(host.ip)
            if host.mac:
                site_macs.add(host.mac)
            old = site_host_key.pop(id(host), None)       # ip/mac may be filled in
            if old is not None and site_hosts.get(old) is host:
                del site_hosts[old]
            site_hosts[(host.ip, host.mac)] = host
            site_host_key[id(host)] = (host.ip, host.mac)
        return host

    def _session(src_host, dst_host, sport, dport, transport, ts, nbytes, npkts=1) -> NetworkSession:
        row = _get_or_create_session(
            db, sessions_cache, src_host, dst_host, sport, dport, transport, source_file, ts,
            created_ids, limits.max_sessions,
        )
        row.packet_count = (row.packet_count or 0) + npkts
        row.byte_count = (row.byte_count or 0) + nbytes
        t = session_times.get(id(row))
        if t is None:
            session_times[id(row)] = [row, ts, ts]
        else:
            if ts < t[1]:
                t[1] = ts
            if ts > t[2]:
                t[2] = ts
        return row

    def _flush_details() -> None:
        if detail_rows:
            db.execute(insert(ProtocolDetail), detail_rows)
            detail_rows.clear()

    def _apply_identity(session_row: NetworkSession, ident: dict, ts, sender_id) -> None:
        """batch C (AST-02): a device's own identity from CIP ListIdentity / S7 SZL
        fills the inventory's model / firmware / hostname when they are empty.
        The identity belongs to the host that SENT the reply (audit 2026-10-15:
        RSLinx scans from port 44818 too, so ports cannot tell the sides apart)."""
        if sender_id is None:
            return
        h = db.get(Host, sender_id)
        if h is None:
            return
        model = ident.get("product_name") or ident.get("order_number")
        fw = ident.get("revision") or ident.get("firmware_version")
        if model and not h.model:
            h.model = str(model)[:128]
        if fw and not h.firmware_version:
            h.firmware_version = str(fw)[:128]
        if ident.get("serial_number") and not h.serial_number:
            h.serial_number = str(ident["serial_number"])[:128]
        if ident.get("plc_name") and not h.hostname:
            h.hostname = str(ident["plc_name"])[:255]
        if h.ip and model:
            _seen_name(h.ip, f"{model}{' ' + fw if fw else ''}"[:255], ident.get("source", "identity"), ts)
        stats["device_identities"] = stats.get("device_identities", 0) + 1

    def _add_detail(session_row: NetworkSession, protocol: str, decoded: dict, ts, sender_id=None) -> None:
        # F-13: bulk-inserted in batches instead of one ORM object per frame.
        if decoded.get("identity") and decoded.get("direction") == "response":
            _apply_identity(session_row, decoded["identity"], ts, sender_id)
        session_row.protocol = protocol
        detail_rows.append({
            "session_id": session_row.id,
            "protocol": protocol,
            "timestamp": ts,
            "direction": decoded.get("direction"),
            "summary": decoded.get("summary"),
            "fields": decoded,
        })
        if len(detail_rows) >= DETAIL_BATCH_SIZE:
            _flush_details()

    def _evict_oldest() -> None:
        """A-30: flush and drop the least-recently-used TCP stream."""
        _key, old = tcp_streams.popitem(last=False)
        reasm_bytes[0] -= old.mem()
        stats["streams_evicted"] += 1
        try:
            while old.skip_gap(stats):
                _dispatch_stream(old)
            if old.dnp3 is not None:
                old.dnp3.flush()
        except Exception:       # never let a flush abort the ingest
            stats["analyzer_errors"] += 1

    def _dispatch_stream(stream: _TcpStream) -> None:
        for frame in stream.drain(stats):
            hit = _decode_tcp_protocols(frame, stream.sport, stream.dport, stats,
                                        logged_analyzers, stream.dnp3)
            if hit is not None:
                _add_detail(stream.session_row, hit[0], hit[1], stream.last_ts, getattr(stream, "sender_id", None))

    seen_names: dict = {}

    def _seen_name(ip, name, source, ts) -> None:
        k = (ip, name[:255], source)
        v = seen_names.get(k)
        if v is None:
            if len(seen_names) >= 50000:
                return
            seen_names[k] = [ts, ts, 1]
        else:
            v[1] = ts if ts > v[1] else v[1]
            v[2] += 1

    def _tcp(dg: _Datagram, src_host, dst_host, ts) -> None:
        seg = dg.payload
        if len(seg) < 20:
            stats["malformed_packets"] += 1
            return
        sport, dport, seq = struct.unpack_from("!HHI", seg, 0)
        doff = (seg[12] >> 4) * 4
        flags = seg[13]
        payload = seg[doff:] if doff >= 20 else b""
        session_row = _session(src_host, dst_host, sport, dport, "tcp", ts, dg.frame_bytes, 1)
        tr = tcp_track.get(id(session_row))
        if tr is None:
            tr = tcp_track[id(session_row)] = {
                "row": session_row, "new": (session_row.packet_count or 0) <= 1, "payload": False,
                "syn": None, "synack": False, "rst": False, "first": ts, "last": ts}
        tr["last"] = ts
        if payload:
            tr["payload"] = True
            kind = _cleartext_auth(payload, sport, dport, tr)
            if kind:
                tr.setdefault("auth", set()).add(kind)
            dflt = _default_credentials(payload, sport, dport, tr)
            if dflt:
                tr.setdefault("auth", set()).add(dflt)
            weak = _weak_transport(payload, sport)
            if weak and src_host is not None:
                # the server side: the host that sent the ServerHello / banner
                tr.setdefault("weak", {})[weak] = (src_host.ip, sport, ts)
            if src_host is not None and src_host.ip and len(payload) > 8:
                # batch C: service banners of the server side (AST-02 version evidence)
                if payload[:5] == b"HTTP/":
                    hdr_block = payload[:2048].split(b"\r\n\r\n", 1)[0]
                    j = hdr_block.lower().find(b"\r\nserver: ")
                    if j >= 0:
                        srv = hdr_block[j + 10:j + 10 + 120].split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
                        if srv:
                            _seen_name(src_host.ip, srv[:255], "http_server", ts)
                else:
                    m_ssh = _SSH_BANNER_RE.match(payload[:96])
                    if m_ssh and sport == 22:                     # the server's banner
                        _seen_name(src_host.ip, m_ssh.group(0).decode("latin-1", "replace")[:255], "ssh_banner", ts)
            if not tr.get("named") and dst_host is not None and dst_host.ip:
                # G5: the name the client asked the server for (TLS SNI / HTTP Host)
                nm = _ns.tls_sni(payload) if payload[0] == 0x16 else _ns.http_host(payload)
                if nm:
                    _seen_name(dst_host.ip, nm, "tls_sni" if payload[0] == 0x16 else "http_host", ts)
                    tr["named"] = True
        if flags & 0x02 and not flags & 0x10:          # SYN: the initiator
            if tr["syn"] is None:
                tr["syn"] = (src_host.ip, src_host.mac, dst_host.ip, dport)
        elif flags & 0x12 == 0x12:                       # SYN-ACK
            tr["synack"] = True
        if flags & 0x04 and tr["syn"] is not None and src_host.ip == tr["syn"][2]:
            tr["rst"] = True                             # RST from the target

        # Determine whether this port uses reassembly.
        reassemble_port = (
            dport if dport in _REASSEMBLED_PORTS
            else sport if sport in _REASSEMBLED_PORTS
            else None
        )
        if reassemble_port is not None:
            stream_key: _StreamKey = (dg.src, sport, dg.dst, dport)
            stream = tcp_streams.get(stream_key)
            if stream is None:
                while len(tcp_streams) >= MAX_TCP_STREAMS:
                    _evict_oldest()
                stream = _TcpStream(_REASSEMBLED_PORTS[reassemble_port])
                if reassemble_port == DNP3_TCP_PORT:
                    stream.dnp3 = Dnp3TransportReassembler(dnp3_stats)
                tcp_streams[stream_key] = stream
            else:
                tcp_streams.move_to_end(stream_key)
            mem_before = stream.mem()
            if flags & 0x02:          # SYN: new connection, ISN
                stream.reset()
                stream.next_seq = (seq + 1) % _SEQ_MOD
                seq = stream.next_seq
            stream.session_row = session_row
            stream.sender_id = src_host.id if src_host is not None else None   # a stream is one direction
            stream.sport, stream.dport = sport, dport
            stream.last_ts = ts
            if payload:
                stream.add_segment(seq, payload, stats)
                _dispatch_stream(stream)
            reasm_bytes[0] += stream.mem() - mem_before
            while reasm_bytes[0] > MAX_REASSEMBLY_BYTES and len(tcp_streams) > 1:
                _evict_oldest()
        elif payload:
            hit = _decode_tcp_protocols(payload, sport, dport, stats, logged_analyzers)
            if hit is not None:
                _add_detail(session_row, hit[0], hit[1], ts, src_host.id if src_host is not None else None)

    dnp3_udp: "OrderedDict" = OrderedDict()   # per-flow transport reassemblers (UDP)

    def _dnp3_udp(payload: bytes, dg: _Datagram, sport, dport, session_row, ts,
                  extra: Optional[dict] = None) -> None:
        frames, bad = _split_dnp3_datagram(payload)
        if bad:
            stats["dnp3_udp_malformed"] = stats.get("dnp3_udp_malformed", 0) + bad
        if not frames:
            return
        key = (dg.src, sport, dg.dst, dport)
        reasm = dnp3_udp.get(key)
        if reasm is None:
            while len(dnp3_udp) >= 1024:
                _k, old = dnp3_udp.popitem(last=False)
                old.flush()
            reasm = dnp3_udp[key] = Dnp3TransportReassembler(dnp3_stats)
        else:
            dnp3_udp.move_to_end(key)
        for frame in frames:
            decoded = _run_analyzer("dnp3", reasm.feed, (frame,), stats, logged_analyzers)
            if decoded:
                stats["protocol_frames"]["dnp3"] += 1
                if extra:
                    decoded = {**decoded, **extra}
                _add_detail(session_row, "dnp3", decoded, ts)

    marker: list = []           # B-14a: the site's group marker Host (lazy)

    def _group_dnp3(dg: _Datagram, src_host, ts) -> None:
        """B-14a: decode DNP3/UDP sent to a broadcast/multicast group, on a
        session sender -> group marker (see get_group_marker_host)."""
        seg = dg.payload
        if src_host is None or dg.proto != _PROTO_UDP or len(seg) <= 8:
            return
        sport, dport, ulen = struct.unpack_from("!HHH", seg, 0)
        if DNP3_UDP_PORT not in (sport, dport):
            return
        payload = seg[8:ulen] if 8 <= ulen <= len(seg) else seg[8:]
        if not payload:
            return
        if not marker:
            marker.append(get_group_marker_host(db, resolver.site_id, ts))
            site_macs.add(GROUP_MARKER_MAC)
        session_row = _session(src_host, marker[0], sport, dport, "udp", ts, dg.frame_bytes, 1)
        stats["dnp3_group_packets"] = stats.get("dnp3_group_packets", 0) + 1
        _dnp3_udp(payload, dg, sport, dport, session_row, ts, extra={"dst_group": dg.dst})

    def _udp(dg: _Datagram, src_host, dst_host, ts) -> None:
        seg = dg.payload
        if len(seg) < 8:
            stats["malformed_packets"] += 1
            return
        sport, dport, ulen = struct.unpack_from("!HHH", seg, 0)
        payload = seg[8:ulen] if 8 <= ulen <= len(seg) else seg[8:]
        session_row = _session(src_host, dst_host, sport, dport, "udp", ts, dg.frame_bytes, 1)
        # IO-07: who sent first, and did the other side ever answer
        ut = udp_track.get(id(session_row))
        if ut is None:
            ut = udp_track[id(session_row)] = {
                "row": session_row, "new": (session_row.packet_count or 0) <= 1,
                "first": (src_host.ip, src_host.mac, dst_host.ip, dport, sport),
                "reply": False, "t0": ts, "t1": ts}
        else:
            ut["t1"] = ts
            if src_host.ip != ut["first"][0]:
                ut["reply"] = True
        if payload and sport == 53:
            for addr, nm in _ns.dns_answers(payload):           # G5: names the devices resolved
                _seen_name(addr, nm, "dns", ts)
        if payload and (dport in (161, 162) or sport in (161, 162)):
            kind = _snmp_community(payload)
            if kind:
                udp_auth.setdefault(id(session_row), [session_row, set()])[1].add(kind)
        if payload and (sport == ENIP_TCP_PORT or dport == ENIP_TCP_PORT):
            decoded = _run_analyzer("ethernet_ip", parse_enip, (payload,), stats, logged_analyzers)
            if decoded:
                stats["protocol_frames"]["ethernet_ip"] += 1
                _add_detail(session_row, "ethernet_ip", decoded, ts, src_host.id if src_host is not None else None)
        elif payload and (sport == DNP3_UDP_PORT or dport == DNP3_UDP_PORT):
            _dnp3_udp(payload, dg, sport, dport, session_row, ts)

    def _ndp(dg: _Datagram, src_mac, ts) -> None:
        stats["ndp_packets"] += 1
        binds, _is_ra = _ndp_bindings(dg.payload, dg.src, src_mac)
        for ip, mac in binds:
            if int(mac[0:2], 16) & 0x01:
                continue
            _host(ip, mac, ts, source="ndp")
            if (ip, mac) not in ndp_seen:
                ndp_seen.add((ip, mac))
                stats["ndp_bindings"] += 1

    def _handle_v6(dg: _Datagram, src_mac, dst_mac, ts) -> None:
        if dg.proto == _PROTO_ICMPV6:
            stats["icmpv6_packets"] += 1
            if dg.payload and dg.payload[0] in _NDP_TYPES:
                _ndp(dg, src_mac, ts)            # link noise: bindings, no session
                return
        if dg.dst.startswith("ff"):
            # Multicast group: counted per group, no Host row for the group.
            stats["ipv6_multicast_packets"] += 1
            if dg.dst in mcast_groups or len(mcast_groups) < _MAX_MCAST_GROUPS:
                mcast_groups[dg.dst] = mcast_groups.get(dg.dst, 0) + 1
            else:
                mcast_groups["other"] = mcast_groups.get("other", 0) + 1
            if dg.src != "::":
                _group_dnp3(dg, _host(dg.src, src_mac, ts), ts)
            return
        if dg.src == "::":
            return
        if dg.proto not in (_PROTO_TCP, _PROTO_UDP, _PROTO_ICMPV6):
            return
        stats["packets"] += 1
        src_ips_seen.add(dg.src)
        src_host = _host(dg.src, src_mac, ts)
        dst_host = _host(dg.dst, dst_mac, ts)
        if gateway_macs:
            _note_carrier(src_host, dst_host, dg.src, dg.dst, src_mac, dst_mac)
        if dg.proto == _PROTO_TCP:
            _tcp(dg, src_host, dst_host, ts)
        elif dg.proto == _PROTO_UDP:
            _udp(dg, src_host, dst_host, ts)
        else:
            _session(src_host, dst_host, None, None, "icmpv6", ts, dg.frame_bytes, 1)

    def _v4_group(dg: _Datagram, src_mac, dst_mac, ts) -> None:
        addr = ipaddress.IPv4Address(dg.dst)
        if dg.dst == "255.255.255.255" or not addr.is_multicast and (
                dst_mac == GROUP_MARKER_MAC or dg.dst in bcasts):
            stats["ipv4_broadcast_packets"] += 1
            if dg.dst != "255.255.255.255":
                stats["ipv4_directed_broadcast_packets"] = \
                    stats.get("ipv4_directed_broadcast_packets", 0) + 1
        else:
            stats["ipv4_multicast_packets"] += 1
            groups = stats["ipv4_multicast_groups"]
            if dg.dst in groups or len(groups) < _MAX_MCAST_GROUPS:
                groups[dg.dst] = groups.get(dg.dst, 0) + 1
            else:
                groups["other"] = groups.get("other", 0) + 1
        src_host = _host(dg.src, src_mac, ts)
        # Keep multicast-carried industrial protocols visible (e.g. ENIP
        # implicit I/O on 224.x:44818) as frame counters; no session row.
        seg = dg.payload
        if dg.proto == _PROTO_UDP and len(seg) > 8:
            sport, dport = struct.unpack_from("!HH", seg, 0)
            if sport == ENIP_TCP_PORT or dport == ENIP_TCP_PORT:
                if _run_analyzer("ethernet_ip", parse_enip, (seg[8:],), stats, logged_analyzers):
                    stats["protocol_frames"]["ethernet_ip"] += 1
            elif DNP3_UDP_PORT in (sport, dport):
                # B-14a: a broadcast/multicast DNP3 write must still reach
                # the industrial-write check.
                _group_dnp3(dg, src_host, ts)

    last_now = 0.0
    # RS-02: addresses that sent a frame (or claimed themselves in ARP)
    src_ips_seen: set = set()
    # RS-11: a SPAN of a router shows a routed packet twice (ingress and
    # egress VLAN, other MACs, TTL one lower): the second copy is the same
    # IP packet - counted once.  key -> (time, src mac, dst mac, vlan)
    recent_pkts: dict = {}
    from collections import deque as _deque
    recent_order: _deque = _deque()
    frames = _iter_frames(pcap_path, limits, main=True) if not stopped else iter(())
    try:
        for data, linktype, meta, nano in frames:
            l2 = _decode_l2(data, linktype)
            if l2 is None:
                continue
            src_mac, dst_mac, etype, off = l2
            if etype == _ETH_IPV4 or etype == _ETH_IPV6:
                ts = _frame_time(meta, nano)
                now = ts.timestamp()
                if now - last_now > 1.0 or now < last_now:
                    defrag4.expire(now)
                    defrag6.expire(now)
                    last_now = now
                l3 = _l3_bytes(data, l2)
                if etype == _ETH_IPV4:
                    dg = _ipv4_datagram(l3, len(data), now, defrag4, stats)
                    if dg is None or dg.proto not in (_PROTO_TCP, _PROTO_UDP):
                        continue
                    if dg.proto == _PROTO_UDP and len(dg.payload) >= 8 \
                            and dg.payload[0:2] == b"\x00\x43" and dg.payload[2:4] == b"\x00\x44":
                        rep = _dhcp_reply(dg.payload[8:])          # IO-04: server -> client
                        if rep and src_mac:
                            srv = dhcp_servers.setdefault(src_mac, {"ip": dg.src, "mac": normalize_mac(src_mac),
                                                                    "offers": 0, "acks": 0, "leases": [],
                                                                    "router": None})
                            srv["offers" if rep["type"] == "offer" else "acks"] += 1
                            if rep["yiaddr"] not in srv["leases"] and len(srv["leases"]) < 50:
                                srv["leases"].append(rep["yiaddr"])
                            srv["router"] = rep["router"] or srv["router"]
                    if not is_unicast_host_ip(dg.src, broadcasts=bcasts):
                        continue    # 0.0.0.0 / multicast / broadcast source: not a host
                    if not is_unicast_host_ip(dg.dst, dst_mac, bcasts):
                        # N-26: multicast (224/4) / limited broadcast: counted per
                        # group, no Host row and no session for the group address
                        # (mirrors IPv6 multicast). The sender is a real host.
                        # B-14b: directed broadcasts too - a group/broadcast dst
                        # MAC or a known subnet's broadcast address.
                        _v4_group(dg, src_mac, dst_mac, ts)
                        continue
                    src_ips_seen.add(dg.src)
                    src_host = _host(dg.src, src_mac, ts)
                    dst_host = _host(dg.dst, dst_mac, ts)
                    if gateway_macs:
                        _note_carrier(src_host, dst_host, dg.src, dg.dst, src_mac, dst_mac)
                    # RS-11: same IP packet (addresses, IP id, protocol, length,
                    # first transport bytes) seen again within 10 ms with
                    # other MACs / VLAN: the routed copy, not a new packet
                    if len(l3) >= 28:
                        hl = (l3[0] & 0x0F) * 4
                        pk = bytes(l3[12:20]) + bytes(l3[4:6]) + bytes(l3[9:10]) + bytes(l3[2:4]) + bytes(l3[hl:hl + 16])
                        seen = recent_pkts.get(pk)
                        frame_id = (src_mac, dst_mac, _vlan_id(data, linktype))
                        if seen is not None and now - seen[0] <= 0.01 and seen[1] != frame_id:
                            stats["span_duplicates"] = stats.get("span_duplicates", 0) + 1
                            continue
                        recent_pkts[pk] = (now, frame_id)
                        recent_order.append(pk)
                        if len(recent_order) > 8192:
                            recent_pkts.pop(recent_order.popleft(), None)
                    stats["packets"] += 1
                    if dg.proto == _PROTO_TCP:
                        _tcp(dg, src_host, dst_host, ts)
                    else:
                        _udp(dg, src_host, dst_host, ts)
                else:
                    stats["ipv6_packets"] += 1
                    dg = _ipv6_datagram(l3, len(data), now, defrag6, stats)
                    if dg is not None:
                        _handle_v6(dg, src_mac, dst_mac, ts)

            elif etype == _ETH_ARP and not isinstance(off, tuple) and len(data) >= off + 28 \
                    and data[off + 4] == 6 and data[off + 5] == 4:
                # IO-10: the sender of an ARP frame claims its address - a
                # device that only ever ARPs is still a device
                sha = data[off + 8:off + 14]
                if not sha[0] & 0x01:
                    spa = _ip4_str(data[off + 14:off + 18])
                    if is_unicast_host_ip(spa, broadcasts=bcasts):
                        src_ips_seen.add(spa)
                        _host(spa, _mac_str(sha), _frame_time(meta, nano))
            elif etype == PROFINET_ETHERTYPE and linktype == 1:
                # PROFINET rides directly on Ethernet - no IP/TCP/UDP layer
                # at all, so hosts here are identified by MAC only.
                stats["packets"] += 1
                ts = _frame_time(meta, nano)
                if src_mac is None or is_group_mac(src_mac):
                    continue
                src_host = _host(None, src_mac, ts)
                if src_host is None:
                    continue
                group_dst = None
                if dst_mac is None or is_group_mac(dst_mac):
                    # AU full review E-M3: DCP identify-all / RT class 3 go to
                    # the PROFINET multicast MACs (01:0e:cf:..) - a group, not
                    # a device; record on sender -> group marker like DNP3.
                    group_dst = dst_mac
                    if not marker:
                        marker.append(get_group_marker_host(db, resolver.site_id, ts))
                        site_macs.add(GROUP_MARKER_MAC)
                    dst_host = marker[0]
                    stats["profinet_group_packets"] = stats.get("profinet_group_packets", 0) + 1
                else:
                    dst_host = _host(None, dst_mac, ts)
                    if dst_host is None:
                        continue

                session_row = _session(src_host, dst_host, None, None, "ethernet", ts, len(data))
                session_row.protocol = "profinet"
                decoded = _run_analyzer("profinet", parse_profinet, (bytes(data[off:]),),
                                        stats, logged_analyzers)
                if decoded:
                    stats["protocol_frames"]["profinet"] += 1
                    if group_dst:
                        decoded = {**decoded, "dst_group": group_dst}
                    _add_detail(session_row, "profinet", decoded, ts)
    except _PcapLimitHit as hit:
        # B-08: stop here and keep everything processed so far.
        stopped.append(hit.limit)
    finally:
        close = getattr(frames, "close", None)
        if close is not None:
            close()

    # End of capture: anything still held out-of-order is behind a gap that
    # will never fill - skip the gap(s) and decode what follows.
    for stream in tcp_streams.values():
        while stream.skip_gap(stats):
            _dispatch_stream(stream)
        if stream.dnp3 is not None:
            stream.dnp3.flush()
    for reasm in dnp3_udp.values():
        reasm.flush()
    defrag4.flush()
    defrag6.flush()
    _flush_details()
    stats.update(dnp3_stats)

    # FO-04: a TCP row this ingest created that carried no payload and began
    # with a SYN is a connection attempt (refused, a data-less open-port
    # probe, or unanswered), not a conversation: record it as such and drop
    # the session, so a scan is never read as traffic.
    attempts: dict = {}
    dropped_rows: set = set()
    for tr in tcp_track.values():
        if not tr["new"] or tr["payload"] or tr["syn"] is None:
            continue
        row = tr["row"]
        sip, smac, dip, dport = tr["syn"]
        if not sip or not dip:
            continue
        outcome = "refused" if tr["rst"] and not tr["synack"] else "open" if tr["synack"] else "unanswered"
        key = (sip, dip, dport, "tcp", outcome)
        a = attempts.setdefault(key, {"src_mac": smac, "count": 0, "first": tr["first"], "last": tr["last"]})
        a["count"] += 1
        a["first"], a["last"] = min(a["first"], tr["first"]), max(a["last"], tr["last"])
        dropped_rows.add(id(row))
    # IO-07: a UDP request the other side never answered (DNS to a dead
    # resolver, NTP to an unreachable server) is an attempt as well - except
    # protocols that are one-way by design
    for ut in udp_track.values():
        if not ut["new"] or ut["reply"]:
            continue
        sip, smac, dip, dport, sport = ut["first"]
        if not sip or not dip or dport in _UDP_ONE_WAY or sport in _UDP_ONE_WAY:
            continue
        key = (sip, dip, dport, "udp", "unanswered")
        a = attempts.setdefault(key, {"src_mac": smac, "count": 0, "first": ut["t0"], "last": ut["t1"]})
        a["count"] += 1
        a["first"], a["last"] = min(a["first"], ut["t0"]), max(a["last"], ut["t1"])
        dropped_rows.add(id(ut["row"]))
    if dropped_rows:
        for k in [k for k, r in sessions_cache.items() if id(r) in dropped_rows]:
            row = sessions_cache.pop(k)
            session_times.pop(id(row), None)
            db.delete(row)
        db.flush()
    # unanswered ARP requests (a sweep of empty addresses) - an address any
    # frame carried, or that anybody claimed, is not "unanswered"
    seen_ips = set()
    for ips in scan.get("mac_ips", {}).values():
        seen_ips.update(ips)
    for mac, reqs in (scan.get("arp_requests") or {}).items():
        if mac in gateway_macs:
            continue
        for tip, (sip, n) in reqs.items():
            if tip in seen_ips:
                continue
            key = (sip, tip, None, "arp", "arp_unanswered")
            a = attempts.setdefault(key, {"src_mac": normalize_mac(mac), "count": 0, "first": None, "last": None})
            a["count"] += n
    stats["connection_attempts"] = _store_attempts(db, attempts, pcap_capture_id)

    # RS-02: a host this ingest created for an address that never sent a
    # frame, never claimed itself in ARP / NDP, has no MAC of its own and is
    # left with no session (its only traffic was an unanswered / refused
    # attempt) is not a device: the sweep / attempt evidence keeps it.
    if created_ids:
        claimed_ips = set()
        for tbl in (scan.get("arp_ips") or {}, scan.get("ndp_ips") or {}):
            for ips in tbl.values():
                claimed_ips.update(ips)
        used = set()
        for r in sessions_cache.values():
            used.add(r.src_host_id)
            used.add(r.dst_host_id)
        by_id = {t[0].id: t[0] for t in host_times.values()}
        silent = [by_id[h] for h in created_ids
                  if h in by_id and h not in used and not by_id[h].mac
                  and by_id[h].ip and by_id[h].ip not in src_ips_seen and by_id[h].ip not in claimed_ips
                  and not is_group_marker_host(by_id[h])]
        if silent:
            gone = {h.id for h in silent}
            for k in [k for k, v in host_times.items() if v[0].id in gone]:
                del host_times[k]
            for k in [k for k, v in addr_obs.items() if v[0].id in gone]:
                del addr_obs[k]
            for k in [k for k, v in host_cache.items() if v is not None and v.id in gone]:
                del host_cache[k]
            for h in silent:
                site_hosts.pop((h.ip, h.mac), None)
                db.delete(h)
            new_host_ids.difference_update(gone)
            created_ids.difference_update(gone)
            db.flush()
            stats["silent_addresses_not_hosts"] = len(silent)

    # RS-07: the 802.1Q VLAN each host sent in (one VLAN only; router MACs,
    # which send into every VLAN, excluded).  A switch MAC table or the
    # operator still wins.
    sv = scan.get("src_vlans") or {}
    if sv:
        n_v = 0
        for (mac, ip), vids in sv.items():
            if mac in gateway_macs or len(vids) != 1:
                continue
            nm = normalize_mac(mac)
            h = site_hosts.get((ip, nm))
            if h is None or h.vlan_source in ("mac_table", "manual"):
                continue
            v = str(next(iter(vids)))
            if (h.vlan, h.vlan_source) != (v, "pcap_8021q"):
                h.vlan, h.vlan_source = v, "pcap_8021q"
                n_v += 1
        if n_v:
            stats["vlans_from_capture"] = n_v
    if dhcp_servers:                                       # IO-04
        stats["dhcp_servers"] = list(dhcp_servers.values())
        seg = stats.get("capture_segment") or {"networks": [], "basis": "none", "gateway_macs": [],
                                               "on_link": 0, "domains": []}
        seg["dhcp_servers"] = stats["dhcp_servers"]
        stats["capture_segment"] = seg

    # FO-07: cleartext logins seen on a session (kind only, never the secret)
    n_auth = 0
    for row, kinds in [(t["row"], t.get("auth")) for t in tcp_track.values()] + \
            [(r, k) for r, k in udp_auth.values()]:
        if not kinds or id(row) in dropped_rows:
            continue
        have = {k.strip() for k in (row.cleartext_auth or "").split(",") if k.strip()}
        merged = ", ".join(sorted(have | kinds))[:128]
        if merged != (row.cleartext_auth or ""):
            row.cleartext_auth = merged
        n_auth += 1
    if n_auth:
        stats["cleartext_logins"] = n_auth
    # batch C: weak TLS / SSH versions negotiated on a session (one detail row per version)
    n_weak = 0
    for t in tcp_track.values():
        row = t["row"]
        if not t.get("weak") or id(row) in dropped_rows or row.id is None:
            continue
        for ver, (sip, sp, wts) in t["weak"].items():
            detail_rows.append({"session_id": row.id, "protocol": "tls" if ver != "SSH-1" else "ssh",
                                "timestamp": wts, "direction": "response", "summary": f"{ver} negotiated",
                                "fields": {"version": ver, "weak": True, "server_ip": sip, "server_port": sp}})
            n_weak += 1
    if n_weak:
        stats["weak_transport_sessions"] = n_weak
        _flush_details()

    # Apply packet-time bounds (T3-30: packet time, not ingest wall-clock).
    for host, first, last in host_times.values():
        touch_host_times(host, first)
        touch_host_times(host, last)
        if host.stale:
            host.stale = False
    for row, first, last in session_times.values():
        cur_first, cur_last = as_utc(row.first_seen), as_utc(row.last_seen)
        row.first_seen = first if cur_first is None or first < cur_first else cur_first
        row.last_seen = last if cur_last is None or last > cur_last else cur_last

    # LS-03: the router MAC each session's frames carried (the most frequent
    # one of the pair; ties broken by MAC order, None last)
    if carriers:
        for (canon, _tr), row in sessions_cache.items():
            slot = carriers.get(frozenset(h for h, _p in canon))
            if not slot:
                continue
            cm = max(slot, key=lambda m: (slot[m], m is not None, m or ""))
            row.carrier_mac = normalize_mac(cm)[:17] if cm else None

    # If this ingest is linked to a PcapCapture, stamp every session that was
    # created or touched during this run so the UI can filter by capture.
    if pcap_capture_id is not None:
        for row in sessions_cache.values():
            row.pcap_capture_id = pcap_capture_id

    # F-09: address history for every (host, ip, mac, source) observed.
    for (_hid, ip, mac, source), (host, first, last, n) in addr_obs.items():
        if ip is None and mac is None:
            continue
        resolver.observe(host, ip, mac, first, source=source, count=n)
        if last != first:
            resolver.observe(host, ip, mac, last, source=source, count=0)
    resolver.finish()
    for key in ("hosts_renumbered", "hosts_merged", "ip_conflicts",
                "address_changes", "ip_conflict_events"):
        stats[key] = resolver.stats[key]

    # G5: names seen for addresses (DNS answers, TLS SNI, HTTP Host)
    if seen_names:
        from app.models import ObservedName
        have = {}
        ips = list({k[0] for k in seen_names})
        for i in range(0, len(ips), 900):
            for row in db.query(ObservedName).filter(ObservedName.site_id == resolver.site_id,
                                                     ObservedName.ip.in_(ips[i:i + 900])):
                have[(row.ip, row.name, row.source)] = row
        for (ip, name, source), (first, last, n) in seen_names.items():
            row = have.get((ip, name, source))
            if row is None:
                db.add(ObservedName(site_id=resolver.site_id, ip=ip, name=name, source=source,
                                    count=n, first_seen=first, last_seen=last))
            else:
                row.count = (row.count or 0) + n
                if row.first_seen is None or as_utc(first) < as_utc(row.first_seen):
                    row.first_seen = first
                if row.last_seen is None or as_utc(last) > as_utc(row.last_seen):
                    row.last_seen = last
        stats["observed_names"] = len(seen_names)

    db.flush()
    stats["sessions"] = len(sessions_cache)
    stats["hosts"] = len(new_host_ids - hosts_before)   # created this run (P4-L4)
    # B-08: truncation report (always present; truncated_by None when complete).
    stats["records_processed"] = limits.records
    stats["truncated"] = bool(stopped)
    stats["truncated_by"] = stopped[0] if stopped else None
    stats["limits"] = limits.values()
    stats["elapsed_seconds"] = round(time.monotonic() - limits.start, 3)
    if stopped:
        env_var = PCAP_LIMITS[stopped[0]][0]
        log.warning("pcap %r truncated by %s (%s=%s): %d records, %d new hosts, %d sessions "
                    "processed and kept", source_file, stopped[0], env_var,
                    getattr(limits, stopped[0]), limits.records, stats["hosts"],
                    stats["sessions"])
    return stats
