"""G5: the names a capture shows for addresses - DNS answers, TLS server
names (ClientHello SNI) and HTTP Host headers.  Only what the devices
themselves resolved or asked for; nothing is looked up."""
from __future__ import annotations

import socket
import struct
from typing import Optional

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _dns_name(buf: bytes, off: int, depth: int = 0) -> tuple[Optional[str], int]:
    """(name, offset after it) of a (possibly compressed) DNS name."""
    labels, end = [], None
    while off < len(buf) and depth < 20:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                return None, len(buf)
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            if ptr >= off:
                return None, end
            off, depth = ptr, depth + 1
            continue
        lab = buf[off + 1:off + 1 + n]
        if len(lab) < n:
            return None, len(buf)
        labels.append(lab.decode("ascii", "replace"))
        off += 1 + n
    name = ".".join(labels).lower().rstrip(".")
    return (name or None), (end if end is not None else off)


def dns_answers(payload: bytes) -> list[tuple[str, str]]:
    """[(address, name)] of the A / AAAA answers of a DNS response.  The
    name is the QUESTION name (what the device asked for), not the CNAME
    target the address finally belongs to."""
    if len(payload) < 12 or not payload[2] & 0x80:            # not a response
        return []
    qd, an = struct.unpack_from("!HH", payload, 4)
    if qd == 0 or an == 0 or an > 64:
        return []
    off = 12
    qname = None
    for _ in range(min(qd, 4)):
        nm, off = _dns_name(payload, off)
        if nm is None:
            return []
        qname = qname or nm
        off += 4
    out = []
    for _ in range(an):
        _nm, off = _dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", payload, off)
        off += 10
        rd = payload[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            out.append((socket.inet_ntoa(rd), qname))
        elif rtype == 28 and rdlen == 16:
            out.append((socket.inet_ntop(socket.AF_INET6, rd), qname))
    return [(a, n) for a, n in out if n]


def tls_sni(payload: bytes) -> Optional[str]:
    """Server name of a TLS ClientHello (first client payload), or None."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return None
        off = 9 + 2 + 32                       # record(5) + hs header(4) + version(2) + random(32)
        sid = payload[off]
        off += 1 + sid
        cs = struct.unpack_from("!H", payload, off)[0]
        off += 2 + cs
        cm = payload[off]
        off += 1 + cm
        ext_len = struct.unpack_from("!H", payload, off)[0]
        off += 2
        end = min(len(payload), off + ext_len)
        while off + 4 <= end:
            et, el = struct.unpack_from("!HH", payload, off)
            off += 4
            if et == 0 and el >= 5:
                ln = struct.unpack_from("!H", payload, off + 3)[0]
                name = payload[off + 5:off + 5 + ln].decode("ascii", "replace").lower()
                return name or None
            off += el
    except (IndexError, struct.error):
        return None
    return None


def http_host(payload: bytes) -> Optional[str]:
    """Host header of a cleartext HTTP request, or None."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload[:2048].split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("ascii", "replace").lower()
            host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            return host or None
    return None
