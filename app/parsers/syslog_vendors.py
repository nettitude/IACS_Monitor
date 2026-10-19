"""
Non-Fortinet syslog parsers (F-11): Cisco ASA/FTD, pfSense/OPNsense
filterlog, Palo Alto PAN-OS CSV.

Every parser returns the same normalised field dict that
forti_parser._build_event consumes (FortiAnalyzerEvent column names plus
``raw_fields`` / ``raw_message``), using the *Fortinet vocabulary* the
real-time checks in alert_engine expect:

  log_type  "traffic" | "event" | "utm" | "ips"
  action    permit / pass / allow / est-allowed     -> "accept"
            deny / block / reject / drop / reset-*  -> "deny"
            ASA teardown                            -> "close"
            auth                                    -> "success" | "failed"
  protocol  "tcp" | "udp" | "icmp" | ...
  event_time aware UTC (syslog/PAN-OS timestamps without a zone are UTC)

plus ``vendor`` ("cisco_asa" | "pfsense" | "panos") and ``source_type``
("syslog_asa" | "syslog_pfsense" | "syslog_panos").

raw_fields always keeps the vendor-native fields and, where the source
has them, the vendor-neutral integer metrics ``bytes_sent``,
``bytes_received``, ``bytes_total`` (ASA teardown only reports a total)
and ``duration_s`` - plus the FortiOS aliases sentbyte/rcvdbyte/duration
so consumers written for FortiGate data keep working.

Supported messages
------------------
Cisco ASA / FTD (``%ASA-<lvl>-<id>`` / ``%FTD-<lvl>-<id>``):
  106100 ACL permitted/denied (acl name, hit-cnt)   -> traffic
  106023 Deny ... by access-group "<acl>"            -> traffic deny
  106001 / 106006 / 106015 inbound / no-connection deny -> traffic deny
  302013 / 302015 Built in/outbound TCP/UDP          -> traffic accept
  302014 / 302016 Teardown (duration, bytes)         -> traffic close
  113004 / 113005 AAA auth success / rejected        -> event authentication
  611101 / 611102 user auth succeeded / failed       -> event login
  605004 / 605005 management login denied/permitted  -> event login
  111008 / 111010 configuration command executed     -> event config
  733100 / 733101 threat detection (drop rate / host attacking) -> utm anomaly
pfSense / OPNsense ``filterlog`` CSV, IPv4 and IPv6 (documented raw
filter format), plus pfSense webConfigurator login success/failure.
PAN-OS syslog CSV: TRAFFIC, THREAT, SYSTEM, CONFIG.

Lines that cannot be parsed confidently return None.

Syslog transport headers: RFC3164 (``<pri>Mmm dd [yyyy] hh:mm:ss host
tag[pid]:``), the ASA variant (``host : %ASA-...``), and RFC5424
(``<pri>1 ts host app procid msgid sd msg``).
"""
from __future__ import annotations

import sys
import logging
import csv
import io
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.sites import site_ingest
from app.parsers import forti_parser as fp

log = logging.getLogger(__name__)

VENDOR_FORTINET = "fortinet"
VENDOR_ASA = "cisco_asa"
VENDOR_PFSENSE = "pfsense"
VENDOR_PANOS = "panos"
VENDORS = (VENDOR_FORTINET, VENDOR_ASA, VENDOR_PFSENSE, VENDOR_PANOS)

_HINT_ALIASES = {
    None: None, "": None, "auto": None, "any": None,
    "fortinet": VENDOR_FORTINET, "forti": VENDOR_FORTINET, "fortigate": VENDOR_FORTINET,
    "fortianalyzer": VENDOR_FORTINET,
    "cisco_asa": VENDOR_ASA, "asa": VENDOR_ASA, "cisco": VENDOR_ASA, "ftd": VENDOR_ASA,
    "pfsense": VENDOR_PFSENSE, "opnsense": VENDOR_PFSENSE,
    "panos": VENDOR_PANOS, "pan-os": VENDOR_PANOS, "paloalto": VENDOR_PANOS,
    "palo_alto": VENDOR_PANOS, "pan": VENDOR_PANOS,
}


def normalise_vendor_hint(hint: Optional[str]) -> Optional[str]:
    """'auto'/None -> None; known alias -> canonical vendor; else ValueError."""
    key = hint.strip().lower() if isinstance(hint, str) else hint
    if key not in _HINT_ALIASES:
        raise ValueError(f"unknown vendor_hint {hint!r}")
    return _HINT_ALIASES[key]


# ------------------------------------------------------------------ helpers

def _to_int(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _valid_ip(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


def _hms_to_s(s: Optional[str]) -> Optional[int]:
    """'0:00:05' / '25:01:02' -> seconds."""
    if not s:
        return None
    parts = s.split(":")
    if not all(p.isdigit() for p in parts) or not 1 <= len(parts) <= 4:
        return None
    total = 0
    for p, mult in zip(reversed(parts), (1, 60, 3600, 86400)):
        total += int(p) * mult
    return total


def _metrics(raw: dict, sent=None, received=None, total=None, duration=None) -> None:
    """Vendor-neutral + FortiOS-alias integer metrics into raw_fields."""
    for neutral, alias, val in (("bytes_sent", "sentbyte", sent),
                                ("bytes_received", "rcvdbyte", received),
                                ("duration_s", "duration", duration)):
        iv = _to_int(val)
        if iv is not None:
            raw[neutral] = iv
            raw[alias] = iv
    tv = _to_int(total)
    if tv is not None:
        raw["bytes_total"] = tv


def _fields(*, vendor, source_type, line, raw, device_name=None, log_type=None,
            subtype=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None,
            protocol=None, action=None, policy_id=None, policy_name=None,
            service=None, app=None, attack_name=None, severity=None, user=None,
            src_user=None, event_time=None) -> dict:
    return {
        "source_type": source_type,
        "vendor": vendor,
        "device_name": fp._s(device_name),
        "log_type": fp._lower(log_type),
        "subtype": fp._lower(subtype),
        "src_ip": fp._s(src_ip),
        "dst_ip": fp._s(dst_ip),
        "src_port": _to_int(src_port),
        "dst_port": _to_int(dst_port),
        "protocol": fp._protocol(protocol),
        "action": fp._lower(action),
        "policy_id": fp._s(policy_id),
        "policy_name": fp._s(policy_name),
        "service": fp._s(service),
        "app": fp._lower(app),
        "attack_name": fp._s(attack_name),
        "severity": fp._lower(severity),
        "user": fp._s(user),
        "src_user": fp._s(src_user),
        "event_time": event_time,
        "raw_message": line,
        "raw_fields": raw,
    }


# B-02: longest line handed to any vendor regex. Longer lines are truncated
# (never hang); real syslog datagrams are <= ~8 KiB.
MAX_LINE_CHARS = 8192


def _cap_line(line: Optional[str]) -> str:
    line = (line or "").strip()
    if len(line) > MAX_LINE_CHARS:
        line = line[:MAX_LINE_CHARS].rstrip()
    return line


# ------------------------------------------------------------ syslog header

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$",
    re.S,
)
_TS3164_RE = re.compile(
    r"^:?\s*(?P<ts>"
    r"[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r")(?:\s+(?P<zone>[A-Z]{1,5}|[+-]\d{2}:?\d{2}))?:?\s+"
)

# A-29: timezone abbreviations seen in ASA / IOS headers (`logging timestamp
# ... timezone`; `clock timezone EST -5`). Offsets in minutes east of UTC.
# Ambiguous abbreviations resolve to the convention used by Cisco/US
# deployments and are documented here: CST = US Central (-6, not China
# +8), IST = India (+5:30, not Irish/Israel), BST = British Summer (+1, not
# Bangladesh), AST = Atlantic (-4, not Arabia +3), EST/EDT = US Eastern.
# An unknown upper-case token is NOT consumed as a zone (it may be the
# hostname) - the header is then parsed exactly as before.
_TZ_ABBREV_MIN = {
    "UTC": 0, "GMT": 0, "Z": 0, "UT": 0, "WET": 0, "WEST": 60,
    "BST": 60, "CET": 60, "CEST": 120, "MET": 60, "MEST": 120,
    "EET": 120, "EEST": 180, "MSK": 180, "IST": 330, "PKT": 300,
    "ICT": 420, "SGT": 480, "HKT": 480, "AWST": 480, "JST": 540, "KST": 540,
    "ACST": 570, "ACDT": 630, "AEST": 600, "AEDT": 660, "NZST": 720, "NZDT": 780,
    "AST": -240, "ADT": -180, "EST": -300, "EDT": -240, "CST": -360,
    "CDT": -300, "MST": -420, "MDT": -360, "PST": -480, "PDT": -420,
    "AKST": -540, "AKDT": -480, "HST": -600, "NST": -210, "NDT": -150,
}


def _zone_offset_min(zone: Optional[str]) -> Optional[int]:
    """Minutes east of UTC for a header zone token, None if unknown."""
    if not zone:
        return None
    if zone in _TZ_ABBREV_MIN:
        return _TZ_ABBREV_MIN[zone]
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", zone)
    if m and int(m.group(2)) <= 14 and int(m.group(3)) < 60:
        v = int(m.group(2)) * 60 + int(m.group(3))
        return v if m.group(1) == "+" else -v
    return None
_HOST_RE = re.compile(r"([A-Za-z0-9][\w.\-]*)\s+(?=\S)")
_TAG_RE = re.compile(r"([\w./\-]+)(?:\[(\d+)\])?:\s*")


def parse_syslog_header(line: str) -> dict:
    """
    Split a syslog line into {"ts": aware UTC|None, "host", "app", "msg"}.
    Never raises; an unrecognised header leaves everything in ``msg``.
    """
    s = _cap_line(line)
    s = _PRI_RE.sub("", s, count=1)
    out = {"ts": None, "host": None, "app": None, "msg": s}
    m = _RFC5424_RE.match(s)
    if m:
        ts, host, app = m.group(2), m.group(3), m.group(4)
        out["ts"] = fp._parse_timestamp(ts) if ts != "-" else None
        out["host"] = host if host != "-" else None
        out["app"] = app if app != "-" else None
        out["msg"] = (m.group(8) or "").lstrip("﻿").strip()
        return out
    rest = s
    m = _TS3164_RE.match(rest)
    if m:
        ts, zone = m.group("ts"), m.group("zone")
        off = _zone_offset_min(zone)
        if zone and off is None:
            # A-29: not a zone we know - may be the hostname; re-match
            # without consuming it.
            end = m.start("zone")
            out["ts"] = fp._parse_timestamp(ts)
            rest = rest[end:].lstrip()
        else:
            dt = fp._parse_timestamp(ts)
            if dt is not None and off:
                try:
                    dt = dt - timedelta(minutes=off)
                except OverflowError:
                    dt = None
            out["ts"] = dt
            rest = rest[m.end():]
    hm = _HOST_RE.match(rest)
    if hm:
        after = rest[hm.end():]
        if m or after.startswith(("%", ":")) or _TAG_RE.match(after):
            out["host"] = hm.group(1)
            rest = after
    if rest.startswith(":"):
        rest = rest[1:].lstrip()
    tm = _TAG_RE.match(rest)
    if tm and not rest.startswith("%"):
        out["app"] = tm.group(1)
        rest = rest[tm.end():]
    out["msg"] = rest.strip()
    return out


def _header_for(line: str, body_start: int) -> dict:
    """Header of ``line`` when the vendor body starts at ``body_start``."""
    return parse_syslog_header(line[:body_start] + "x")


# ================================================================ Cisco ASA

_ASA_RE = re.compile(r"%(ASA|FTD|PIX|FWSM)-(?:[A-Za-z]+-)?([0-7])-(\d{6})\s*:?\s*(.*)$")
_IP = r"[0-9A-Fa-f.:]+?"
_IPG = r"[0-9A-Fa-f.:]+"
_USER_SUFFIX = r"(?:\s*\([^)]*\))?"

_ASA_106100 = re.compile(
    r"access-list (?P<acl>\S+) (?P<act>permitted|denied|est-allowed) (?P<proto>\S+) "
    rf"(?P<sif>[^\s/]+)/(?P<src>{_IPG})\((?P<sport>\d+)\){_USER_SUFFIX} -> "
    rf"(?P<dif>[^\s/]+)/(?P<dst>{_IPG})\((?P<dport>\d+)\){_USER_SUFFIX} "
    r"hit-cnt (?P<hits>\d+)(?P<tail>.*)$",
    re.S,
)


class _D:
    """Minimal match-like wrapper (groupdict/group) for the split-based parsers."""

    def __init__(self, d: dict):
        self._d = d

    def groupdict(self) -> dict:
        return dict(self._d)

    def group(self, k):
        return self._d.get(k)


class _FlagsIface:
    """
    ``... flags <flags> on interface <if>`` without a lazy ``.*?`` followed by
    ``\\s+`` (quadratic on whitespace runs): locate the literal instead.
    """

    def __init__(self, head):
        self._head = head

    def search(self, body: str):
        m = self._head.search(body)
        if not m:
            return None
        rest = m.group("rest")
        k = 0
        while True:
            i = rest.find("on interface ", k)
            if i < 0:
                return None
            k = i + 1
            if i > 0 and rest[i - 1].isspace():
                sif = rest[i + len("on interface "):].split(None, 1)
                if sif and not rest[i + len("on interface "):][:1].isspace():
                    d = m.groupdict()
                    d.pop("rest")
                    d["flags"] = rest[:i].rstrip()
                    d["sif"] = sif[0]
                    return _D(d)


def _asa_106100_tail(tail: str):
    """
    Linear-time validation of what follows ``hit-cnt N`` in ASA 106100:
    ``[ <interval>] [ [<hash>]]`` + trailing whitespace. Returns
    ``(ok, hash_or_None)``. (Replaces a lazy-quantifier + adjacent ``\\s*``
    regex tail that was cubic on long whitespace runs.)
    """
    i = tail.find("[")
    if i < 0:
        # empty / whitespace only, or " <interval>" (the interval is unused)
        return (tail == "" or tail[0] == " " or not tail.strip()), None
    head = tail[:i]
    if not (head == "" or head[0] == " " or not head.strip()):
        return False, None
    j = tail.find("]", i + 1)
    if j < 0 or tail[j + 1:].strip():
        return False, None
    return True, tail[i + 1:j]


_ASA_106023 = re.compile(
    r"Deny (?:protocol )?(?P<proto>\S+) "
    rf"src (?P<sif>[^\s:]+):(?P<src>{_IP})(?:/(?P<sport>\d+))?{_USER_SUFFIX} "
    rf"dst (?P<dif>[^\s:]+):(?P<dst>{_IP})(?:/(?P<dport>\d+))?{_USER_SUFFIX}"
    r"(?: \(type (?P<itype>\d+), code (?P<icode>\d+)\))? "
    r'by access-group "(?P<acl>[^"]+)"'
)
_ASA_106001 = _FlagsIface(re.compile(
    rf"Inbound (?P<proto>TCP) connection denied from (?P<src>{_IPG})/(?P<sport>\d+) "
    rf"to (?P<dst>{_IPG})/(?P<dport>\d+) flags (?P<rest>.*)$",
    re.S
))
_ASA_106006 = re.compile(
    rf"Deny inbound (?P<proto>UDP) from (?P<src>{_IPG})/(?P<sport>\d+) "
    rf"to (?P<dst>{_IPG})/(?P<dport>\d+) on interface (?P<sif>\S+)"
)
_ASA_106015 = _FlagsIface(re.compile(
    rf"Deny (?P<proto>TCP) \(no connection\) from (?P<src>{_IPG})/(?P<sport>\d+) "
    rf"to (?P<dst>{_IPG})/(?P<dport>\d+) flags (?P<rest>.*)$",
    re.S
))
_ASA_BUILT = re.compile(
    r"Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP) connection (?P<cid>\d+) "
    rf"for (?P<aif>[^\s:]+):(?P<aip>{_IP})/(?P<aport>\d+) \((?P<amip>{_IP})/(?P<amport>\d+)\){_USER_SUFFIX} "
    rf"to (?P<bif>[^\s:]+):(?P<bip>{_IP})/(?P<bport>\d+) \((?P<bmip>{_IP})/(?P<bmport>\d+)\){_USER_SUFFIX}"
)
_ASA_TEARDOWN = re.compile(
    r"Teardown (?P<proto>TCP|UDP) connection (?P<cid>\d+) "
    rf"for (?P<aif>[^\s:]+):(?P<aip>{_IP})/(?P<aport>\d+){_USER_SUFFIX} "
    rf"to (?P<bif>[^\s:]+):(?P<bip>{_IP})/(?P<bport>\d+){_USER_SUFFIX} "
    r"duration (?P<dur>\d+(?::\d{2}){1,3}) bytes (?P<bytes>\d+)(?:\s+(?P<reason>.*?))?\s*$"
)
_ASA_113004_HEAD = re.compile(
    r"AAA user (?P<kind>authentication|authorization|accounting) Successful\s*:\s*"
    r"server\s*=\s*(?P<server>\S+)\s*:\s*user\s*=\s*"
)
_ASA_113005_HEAD = re.compile(
    r"AAA user (?P<kind>authentication|authorization) Rejected\s*:\s*reason\s*=\s*"
)
_ASA_113005_SERVER = re.compile(r":\s*server\s*=\s*(?P<server>\S+)\s*:\s*user\s*=\s*")
_ASA_113005_UIP = re.compile(r":\s*user IP\s*=\s*(?P<uip>\S+)\s*$")


class _Aaa113004:
    @staticmethod
    def search(body: str):
        m = _ASA_113004_HEAD.search(body)
        if not m:
            return None
        user = body[m.end():].strip()
        if not user:
            return None
        d = m.groupdict()
        d["user"] = user
        return _D(d)


class _Aaa113005:
    @staticmethod
    def search(body: str):
        m = _ASA_113005_HEAD.search(body)
        if not m:
            return None
        rest = body[m.end():]
        sm = _ASA_113005_SERVER.search(rest)
        if not sm:
            return None
        rem = rest[sm.end():]
        um = _ASA_113005_UIP.search(rem)
        d = m.groupdict()
        d.update(reason=rest[:sm.start()].rstrip(), server=sm.group("server"),
                 user=(rem[:um.start()] if um else rem).rstrip(),
                 uip=um.group("uip") if um else None)
        return _D(d)


_ASA_113004 = _Aaa113004
_ASA_113005 = _Aaa113005
_ASA_6111 = re.compile(
    r"User authentication (?P<res>succeeded|failed):\s*(?:IP address:\s*(?P<ip>[^,\s]+),\s*)?"
    r"Uname:\s*(?P<user>\S+)"
)
_ASA_6050 = re.compile(
    rf"Login (?P<res>denied|permitted) from (?P<src>{_IPG})/(?P<sport>\d+) "
    rf"to (?P<dif>[^\s:]+):(?P<dst>{_IP})/(?P<svc>\S+) for user \"(?P<user>[^\"]*)\""
)
_ASA_111008 = re.compile(r"User '(?P<user>[^']*)' executed the '(?P<cmd>.*)' command\.?\s*$")
_ASA_111010 = re.compile(
    r"User '(?P<user>[^']*)', running '(?P<client>[^']*)' from IP (?P<ip>\S+?),? executed '(?P<cmd>.*)'\s*$"
)
_ASA_733100_TAIL = re.compile(
    r"\s*drop rate-?(?P<rid>\d+) exceeded\.\s*"
    r"Current burst rate is (?P<burst>\d+) per second"
)


def _asa_733100_search(body: str):
    """
    Linear-time ``[ obj ] drop rate-N exceeded. Current burst rate is N per
    second`` search (B-02: the single-regex form was quadratic on long runs of
    ``[``/whitespace without a closing bracket). Returns ``(obj, match)`` or None.
    """
    pos = 0
    while True:
        i = body.find("[", pos)
        if i < 0:
            return None
        j = body.find("]", i + 1)
        if j < 0:
            return None
        content = body[i + 1:j]
        if content:
            m = _ASA_733100_TAIL.match(body, j + 1)
            if m:
                return (content.strip() or content[-1]), m
        pos = j + 1


_ASA_733101 = re.compile(
    r"(?P<kind>Host|Subnet) (?P<ip>[0-9A-Fa-f.:]+) is (?P<role>attacking|targeted)\."
)
_READ_ONLY_CMDS = ("show", "more", "ping", "traceroute", "dir", "copy running-config tftp",
                   "terminal", "pager", "who", "enable")

_ASA_ACTIONS = {"permitted": "accept", "est-allowed": "accept", "denied": "deny"}


def _asa_proto_ports(proto: str, sport, dport):
    """ICMP 'ports' in 106100 are type/code -> not ports."""
    p = fp._protocol(proto)
    if p in ("icmp", "icmpv6", "icmp6"):
        return p, None, None, {"icmp_type": _to_int(sport), "icmp_code": _to_int(dport)}
    return p, sport, dport, {}


def parse_asa_line(line: str) -> Optional[dict]:
    """Parse one Cisco ASA/FTD syslog line; None if unsupported/unparseable."""
    line = _cap_line(line)
    m = _ASA_RE.search(line)
    if not m:
        return None
    platform, level, msg_id, body = m.group(1), m.group(2), m.group(3), m.group(4).strip()
    hdr = _header_for(line, m.start())
    raw: dict = {"platform": platform.lower(), "level": int(level), "msg_id": msg_id}
    base = dict(vendor=VENDOR_ASA, source_type="syslog_asa", line=line, raw=raw,
                device_name=hdr["host"], event_time=hdr["ts"])

    def traffic(g, action, policy_name=None, **extra):
        proto, sport, dport, icmp = _asa_proto_ports(g["proto"], g.get("sport"), g.get("dport"))
        raw.update({k: v for k, v in icmp.items() if v is not None})
        src, dst = _valid_ip(g["src"]), _valid_ip(g["dst"])
        if not src or not dst:
            return None
        return _fields(**base, log_type="traffic", subtype="forward", src_ip=src, dst_ip=dst,
                       src_port=sport, dst_port=dport, protocol=proto, action=action,
                       policy_name=policy_name, **extra)

    if msg_id == "106100":
        g = _ASA_106100.search(body)
        if not g:
            return None
        g = g.groupdict()
        ok, g["hash"] = _asa_106100_tail(g["tail"])
        if not ok:
            return None
        raw.update({"acl": g["acl"], "asa_action": g["act"], "src_interface": g["sif"],
                    "dst_interface": g["dif"], "hit_count": int(g["hits"])})
        if g.get("hash"):
            raw["ace_hash"] = g["hash"].strip()
        return traffic(g, _ASA_ACTIONS[g["act"]], policy_name=g["acl"])

    if msg_id == "106023":
        g = _ASA_106023.search(body)
        if not g:
            return None
        g = g.groupdict()
        raw.update({"acl": g["acl"], "asa_action": "deny", "src_interface": g["sif"],
                    "dst_interface": g["dif"]})
        if g.get("itype") is not None:
            raw.update({"icmp_type": int(g["itype"]), "icmp_code": int(g["icode"])})
        return traffic(g, "deny", policy_name=g["acl"])

    if msg_id in ("106001", "106006", "106015"):
        rx = {"106001": _ASA_106001, "106006": _ASA_106006, "106015": _ASA_106015}[msg_id]
        g = rx.search(body)
        if not g:
            return None
        g = g.groupdict()
        raw.update({"asa_action": "deny", "src_interface": g["sif"]})
        if g.get("flags"):
            raw["tcp_flags"] = g["flags"].strip()
        if msg_id == "106015":
            raw["reason"] = "no connection"
        return traffic(g, "deny")

    if msg_id in ("302013", "302015"):
        g = _ASA_BUILT.search(body)
        if not g:
            return None
        g = g.groupdict()
        # "for" side = initiator on inbound, responder on outbound.
        if g["dir"] == "inbound":
            s, d = ("aif", "aip", "aport", "amip"), ("bif", "bip", "bport", "bmip")
        else:
            s, d = ("bif", "bip", "bport", "bmip"), ("aif", "aip", "aport", "amip")
        raw.update({"connection_id": g["cid"], "direction": g["dir"],
                    "src_interface": g[s[0]], "dst_interface": g[d[0]],
                    "src_mapped_ip": g[s[3]], "dst_mapped_ip": g[d[3]],
                    "sessionid": _to_int(g["cid"])})
        return traffic({"proto": g["proto"], "src": g[s[1]], "sport": g[s[2]],
                        "dst": g[d[1]], "dport": g[d[2]]}, "accept")

    if msg_id in ("302014", "302016"):
        g = _ASA_TEARDOWN.search(body)
        if not g:
            return None
        g = g.groupdict()
        # Teardown carries no direction: the "for"/"to" order is reported
        # as-is and flagged so consumers (rule hits) don't rely on it.
        raw.update({"connection_id": g["cid"], "src_interface": g["aif"],
                    "dst_interface": g["bif"], "direction_known": False,
                    "sessionid": _to_int(g["cid"])})
        if g.get("reason"):
            raw["teardown_reason"] = g["reason"]
        _metrics(raw, total=g["bytes"], duration=_hms_to_s(g["dur"]))
        return traffic({"proto": g["proto"], "src": g["aip"], "sport": g["aport"],
                        "dst": g["bip"], "dport": g["bport"]}, "close")

    if msg_id in ("113004", "113005"):
        g = (_ASA_113004 if msg_id == "113004" else _ASA_113005).search(body)
        if not g:
            return None
        g = g.groupdict()
        raw.update({"aaa_server": g["server"], "aaa_type": g["kind"]})
        if g.get("reason"):
            raw["reason"] = g["reason"]
        return _fields(**base, log_type="event", subtype="authentication",
                       action="success" if msg_id == "113004" else "failed",
                       user=g["user"], src_ip=_valid_ip(g.get("uip")))

    if msg_id in ("611101", "611102"):
        g = _ASA_6111.search(body)
        if not g:
            return None
        return _fields(**base, log_type="event", subtype="login",
                       action="success" if g.group("res") == "succeeded" else "failed",
                       user=g.group("user"), src_ip=_valid_ip(g.group("ip")))

    if msg_id in ("605004", "605005"):
        g = _ASA_6050.search(body)
        if not g:
            return None
        raw.update({"mgmt_service": g.group("svc"), "dst_interface": g.group("dif")})
        return _fields(**base, log_type="event", subtype="login",
                       action="success" if g.group("res") == "permitted" else "failed",
                       user=g.group("user"), src_ip=_valid_ip(g.group("src")),
                       src_port=g.group("sport"), dst_ip=_valid_ip(g.group("dst")))

    if msg_id in ("111008", "111010"):
        g = (_ASA_111008 if msg_id == "111008" else _ASA_111010).search(body)
        if not g:
            return None
        g = g.groupdict()
        cmd = g["cmd"].strip()
        read_only = cmd.lower().startswith(_READ_ONLY_CMDS)
        raw.update({"command": cmd, "cfg_action": "view" if read_only else "edit"})
        if g.get("client"):
            raw["client"] = g["client"]
        return _fields(**base, log_type="event", subtype="config",
                       action="view" if read_only else "edit",
                       user=g["user"], src_ip=_valid_ip(g.get("ip")))

    if msg_id == "733100":
        hit = _asa_733100_search(body)
        if not hit:
            return None
        obj, g = hit
        raw.update({"threat_object": obj, "rate_id": int(g.group("rid")),
                    "burst_rate": int(g.group("burst")), "threat_detection": "drop rate exceeded"})
        return _fields(**base, log_type="utm", subtype="anomaly", action="deny",
                       attack_name=f"ASA threat detection: {obj}", severity="high",
                       src_ip=_valid_ip(obj))

    if msg_id == "733101":
        g = _ASA_733101.search(body)
        if not g:
            return None
        ip = g.group("ip")
        raw.update({"threat_object": f"{g.group('kind')} {ip}", "role": g.group("role"),
                    "threat_detection": "scanning" if "scanning" in body.lower() else "attack"})
        attacking = g.group("role") == "attacking"
        return _fields(**base, log_type="utm", subtype="anomaly", action="deny",
                       attack_name=f"ASA threat detection: {g.group('kind').lower()} {g.group('role')}",
                       severity="high",
                       src_ip=_valid_ip(ip) if attacking else None,
                       dst_ip=None if attacking else _valid_ip(ip))
    return None


# ================================================================ pfSense

_FILTERLOG_TAG_RE = re.compile(r"\bfilterlog(?:\[\d+\])?:\s*")
_TRACKER_RE = re.compile(r"\d{1,20}|[0-9a-fA-F]{32}")
_PF_ACTIONS = {"pass": "accept", "block": "deny", "reject": "deny"}
_PF_AUTH_OK = re.compile(
    r"Successful login for user '(?P<user>[^']*)' from:?\s*(?P<ip>[0-9A-Fa-f.:]+)")
_PF_AUTH_FAIL = re.compile(
    r"webConfigurator authentication error for user '(?P<user>[^']*)' from:?\s*(?P<ip>[0-9A-Fa-f.:]+)")


def _parse_filterlog_csv(body: str) -> Optional[dict]:
    """Documented pfSense raw filter format -> dict of named fields, or None."""
    f = body.strip().split(",")
    if len(f) < 9:
        return None
    rule, sub, anchor, tracker, iface, reason, action, direction, ipver = f[:9]
    if not rule.isdigit() or action not in _PF_ACTIONS or direction not in ("in", "out"):
        return None
    # pfSense trackers are decimal; OPNsense uses a 32-hex rule label.
    if tracker and not _TRACKER_RE.fullmatch(tracker):
        return None
    d = {"rule_number": rule, "sub_rule": sub or None, "anchor": anchor or None,
         "tracker": tracker or None, "interface": iface, "reason": reason,
         "pf_action": action, "direction": direction, "ip_version": ipver}
    if ipver == "4":
        if len(f) < 20:
            return None
        d.update({"tos": f[9], "ecn": f[10], "ttl": f[11], "ip_id": f[12],
                  "offset": f[13], "ip_flags": f[14], "proto_id": f[15],
                  "proto": f[16].lower(), "length": f[17], "src": f[18], "dst": f[19]})
        rest = f[20:]
    elif ipver == "6":
        if len(f) < 17:
            return None
        d.update({"class": f[9], "flow_label": f[10], "hop_limit": f[11],
                  "proto": f[12].lower(), "proto_id": f[13], "length": f[14],
                  "src": f[15], "dst": f[16]})
        rest = f[17:]
    else:
        return None
    if not _valid_ip(d["src"]) or not _valid_ip(d["dst"]):
        return None
    if d["proto"] in ("tcp", "udp") and len(rest) >= 3:
        d.update({"sport": rest[0], "dport": rest[1], "data_length": rest[2]})
        if d["proto"] == "tcp" and len(rest) >= 4:
            d["tcp_flags"] = rest[3]
    elif d["proto"] in ("icmp", "ipv6-icmp", "icmp6", "icmpv6") and rest:
        d["icmp_type"] = rest[0]
    return d


def parse_pfsense_line(line: str, allow_bare: bool = False) -> Optional[dict]:
    """
    Parse a pfSense/OPNsense filterlog line (RFC3164 ``filterlog[pid]:`` tag
    or RFC5424 app-name ``filterlog``) or a webConfigurator login line.
    ``allow_bare`` accepts a header-less filterlog CSV body (vendor hint).
    """
    line = _cap_line(line)
    if not line:
        return None
    hdr = parse_syslog_header(line)
    body = None
    if hdr["app"] == "filterlog":
        body = hdr["msg"]
    else:
        m = _FILTERLOG_TAG_RE.search(line)
        if m:
            body = line[m.end():]
            hdr = _header_for(line, m.start())
        elif allow_bare:
            body = hdr["msg"]
    if body is not None:
        d = _parse_filterlog_csv(body)
        if d is None:
            return None
        raw = {k: v for k, v in d.items() if v not in (None, "")}
        for k in ("length", "data_length", "ttl", "hop_limit"):
            if _to_int(raw.get(k)) is not None:
                raw[k] = _to_int(raw[k])
        proto = d["proto"]
        if proto in ("ipv6-icmp", "icmp6"):
            proto = "icmpv6"
        return _fields(
            vendor=VENDOR_PFSENSE, source_type="syslog_pfsense", line=line, raw=raw,
            device_name=hdr["host"], event_time=hdr["ts"], log_type="traffic",
            subtype="forward", src_ip=_valid_ip(d["src"]), dst_ip=_valid_ip(d["dst"]),
            src_port=d.get("sport"), dst_port=d.get("dport"), protocol=proto,
            action=_PF_ACTIONS[d["pf_action"]], policy_id=d["tracker"],
        )
    if "php-fpm" in line or "/index.php" in line:
        for rx, action in ((_PF_AUTH_OK, "success"), (_PF_AUTH_FAIL, "failed")):
            m = rx.search(line)
            if m:
                return _fields(
                    vendor=VENDOR_PFSENSE, source_type="syslog_pfsense", line=line,
                    raw={"auth_source": "webConfigurator"}, device_name=hdr["host"],
                    event_time=hdr["ts"], log_type="event", subtype="login",
                    action=action, user=m.group("user"), src_ip=_valid_ip(m.group("ip")),
                )
    return None


# ================================================================ PAN-OS

_PANOS_BODY_RE = re.compile(
    r"(?:^|(?<=[\s>:]))(\d*,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG),)"
)
_PANOS_DENY = {"deny", "drop", "drop-icmp", "drop-all", "drop-all-packets", "reset-client",
               "reset-server", "reset-both", "block-url", "block-ip", "block",
               "block-continue", "block-override", "sinkhole", "random-drop"}
_PANOS_IPS_SUBTYPES = {"vulnerability", "spyware", "virus", "wildfire-virus", "wildfire"}
_PANOS_UTM_SUBTYPES = {"url": "webfilter", "file": "file-filter", "data": "dlp",
                       "scan": "anomaly", "flood": "anomaly"}
# 0-based CSV positions (PAN-OS 8.x-11.x syslog field reference).
_PT = {"receive_time": 1, "serial": 2, "type": 3, "subtype": 4, "generated_time": 6,
       "src": 7, "dst": 8, "nat_src": 9, "nat_dst": 10, "rule": 11, "src_user": 12,
       "dst_user": 13, "app": 14, "vsys": 15, "src_zone": 16, "dst_zone": 17,
       "inbound_if": 18, "outbound_if": 19, "log_action": 20, "session_id": 22,
       "repeat_count": 23, "sport": 24, "dport": 25, "nat_sport": 26, "nat_dport": 27,
       "flags": 28, "proto": 29, "action": 30}
_PT_TRAFFIC = {"bytes": 31, "bytes_sent": 32, "bytes_received": 33, "packets": 34,
               "start_time": 35, "elapsed": 36, "category": 37,
               "session_end_reason": 46, "device_name": 52}
_PT_THREAT = {"misc": 31, "threat_id": 32, "category": 33, "severity": 34, "direction": 35,
              "device_name": 59}
_PT_SYSTEM = {"vsys": 7, "event_id": 8, "object": 9, "module": 12, "severity": 13,
              "description": 14, "device_name": 22}
_PT_CONFIG = {"host": 7, "vsys": 8, "command": 9, "admin": 10, "client": 11,
              "result": 12, "config_path": 13}
_THREAT_NAME_RE = re.compile(r"^(?P<name>.*?)\s*\((?P<id>\d+)\)\s*$")
_PAN_USER_RE = re.compile(r"(?:for user|user)\s+'(?P<user>[^']+)'", re.I)
_PAN_FROM_RE = re.compile(r"From:\s*(?P<ip>[0-9A-Fa-f.:]+?)\.?(?:\s|$)")


def _pan_action(a: str) -> Optional[str]:
    a = (a or "").strip().lower()
    if a == "allow":
        return "accept"
    if a in _PANOS_DENY or a.startswith(("reset-", "drop", "block")):
        return "deny"
    if a == "alert":
        return "detected"
    return a or None


def _pick(cells: list, idx_map: dict) -> dict:
    return {k: cells[i].strip() for k, i in idx_map.items() if i < len(cells) and cells[i].strip()}


def parse_panos_line(line: str) -> Optional[dict]:
    """Parse a PAN-OS syslog CSV line (TRAFFIC / THREAT / SYSTEM / CONFIG)."""
    line = _cap_line(line)
    m = _PANOS_BODY_RE.search(line)
    if not m:
        return None
    hdr = _header_for(line, m.start(1))
    try:
        cells = next(csv.reader(io.StringIO(line[m.start(1):])))
    except (csv.Error, StopIteration):
        return None
    log = cells[3].upper()
    gen_time = fp._parse_timestamp(cells[6]) if len(cells) > 6 else None
    event_time = gen_time or fp._parse_timestamp(cells[1]) or hdr["ts"]
    base = dict(vendor=VENDOR_PANOS, source_type="syslog_panos", line=line,
                event_time=event_time)

    if log in ("TRAFFIC", "THREAT"):
        if len(cells) < (37 if log == "TRAFFIC" else 36):
            return None
        raw = _pick(cells, _PT)
        raw.update(_pick(cells, _PT_TRAFFIC if log == "TRAFFIC" else _PT_THREAT))
        src, dst = _valid_ip(raw.get("src")), _valid_ip(raw.get("dst"))
        if not src or not dst:
            return None
        rule = raw.get("rule")
        device = raw.get("device_name") or hdr["host"]
        common = dict(device_name=device, src_ip=src, dst_ip=dst, src_port=raw.get("sport"),
                      dst_port=raw.get("dport"), protocol=raw.get("proto"),
                      action=_pan_action(raw.get("action")), policy_id=rule,
                      policy_name=rule, app=raw.get("app"),
                      user=raw.get("src_user"), src_user=raw.get("src_user"))
        if common["app"] in ("not-applicable", "incomplete"):
            raw["app_state"] = common.pop("app")
        if raw.get("session_id"):
            raw["sessionid"] = _to_int(raw["session_id"])
        sub = (raw.get("subtype") or "").lower()
        if log == "TRAFFIC":
            _metrics(raw, sent=raw.get("bytes_sent"), received=raw.get("bytes_received"),
                     total=raw.get("bytes"), duration=raw.get("elapsed"))
            return _fields(**base, raw=raw, log_type="traffic", subtype=sub or "forward",
                           **common)
        tm = _THREAT_NAME_RE.match(raw.get("threat_id", ""))
        threat = tm.group("name") if tm else raw.get("threat_id")
        if tm:
            raw["threat_numeric_id"] = tm.group("id")
        if sub in _PANOS_IPS_SUBTYPES:
            log_type, subtype = "ips", "ips"
        else:
            log_type, subtype = "utm", _PANOS_UTM_SUBTYPES.get(sub, sub or None)
        return _fields(**base, raw=raw, log_type=log_type, subtype=subtype,
                       attack_name=threat, severity=raw.get("severity"), **common)

    if log == "SYSTEM":
        if len(cells) < 15:
            return None
        raw = _pick(cells, {"receive_time": 1, "serial": 2, "type": 3, "subtype": 4,
                            "generated_time": 6, **_PT_SYSTEM})
        desc = raw.get("description", "")
        event_id = (raw.get("event_id") or "").lower()
        sub = (raw.get("subtype") or "").lower()
        um, fm = _PAN_USER_RE.search(desc), _PAN_FROM_RE.search(desc)
        user = um.group("user") if um else None
        src = _valid_ip(fm.group("ip")) if fm else None
        if event_id in ("auth-fail", "auth-failure") or "failed authentication" in desc.lower():
            subtype, action = "login", "failed"
        elif event_id == "auth-success" or "authenticated for user" in desc.lower():
            subtype, action = "login", "success"
        elif sub == "globalprotect" or sub == "vpn":
            subtype, action = "vpn", None
        else:
            subtype, action = (sub or "system"), None
        return _fields(**base, raw=raw, device_name=raw.get("device_name") or hdr["host"],
                       log_type="event", subtype=subtype, action=action,
                       severity=raw.get("severity"), user=user, src_ip=src)

    if log == "CONFIG":
        if len(cells) < 13:
            return None
        raw = _pick(cells, {"receive_time": 1, "serial": 2, "type": 3,
                            "generated_time": 6, **_PT_CONFIG})
        cmd = (raw.get("command") or "").lower()
        raw["cfg_action"] = cmd or None
        return _fields(**base, raw=raw, device_name=hdr["host"], log_type="event",
                       subtype="config", action=cmd or None, user=raw.get("admin"),
                       src_ip=_valid_ip(raw.get("host")))
    return None


# ================================================================ dispatch

def _parse_fortinet(line: str) -> Optional[dict]:
    if fp._locate_cef(line) is not None:
        return fp.parse_cef_line(line)      # CEF never falls through to kv
    return fp.parse_forti_kv_line(line)


def parse_syslog_any(line: str, vendor_hint: Optional[str] = None) -> Optional[dict]:
    """
    Parse one syslog line from any supported vendor into the normalised
    field dict (no dedup_hash). ``vendor_hint`` (canonical or alias, or
    "auto"/None) restricts parsing to that vendor; auto-detect order is
    Fortinet CEF/kv, Cisco ASA, pfSense, PAN-OS. Never raises on bad input.
    """
    line = _cap_line(line)
    if not line:
        return None
    vendor = normalise_vendor_hint(vendor_hint)
    parsers = {
        VENDOR_FORTINET: _parse_fortinet,
        VENDOR_ASA: parse_asa_line,
        VENDOR_PFSENSE: lambda l: parse_pfsense_line(l, allow_bare=vendor == VENDOR_PFSENSE),
        VENDOR_PANOS: parse_panos_line,
    }
    order = (vendor,) if vendor else VENDORS
    for v in order:
        try:
            fields = parsers[v](line)
        except Exception:  # defensive: a parser bug must not abort an upload
            # AU full review D12: say so - a silent None looked like "no vendor matched"
            log.warning("%s syslog parser failed on a line (%s): %r", v, type(sys.exc_info()[1]).__name__,
                        line[:200])
            fields = None
        if fields:
            if fields.get("raw_message") and len(fields["raw_message"]) > fp._RAW_MESSAGE_MAX:
                fields["raw_message"] = fields["raw_message"][:fp._RAW_MESSAGE_MAX]
            return fields
    return None


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_syslog_any_ex(line: str, db, vendor_hint: Optional[str] = None) -> tuple:
    """
    Parse and persist one syslog line from any supported vendor.

    Returns ``(event, status)`` exactly like forti_parser.ingest_syslog_line_ex:
    "created" (flushed, not committed), "duplicate" (EXISTING row with the
    same dedup_hash) or "unparsed" (None). dedup_hash is
    sha1(f"{device_name or ''}|{line.strip()}") for every vendor, so a
    FortiGate line uploaded through either route is the same event.
    """
    line = (line or "").strip()
    if not line:
        return None, fp.STATUS_UNPARSED
    fields = parse_syslog_any(line, vendor_hint)
    if not fields:
        return None, fp.STATUS_UNPARSED
    fields["dedup_hash"] = fp._sha1(f"{fields.get('device_name') or ''}|{line}")
    return fp._persist(fields, db)


_SOURCE_TYPE_VENDOR = {"syslog_asa": VENDOR_ASA, "syslog_pfsense": VENDOR_PFSENSE,
                       "syslog_panos": VENDOR_PANOS, "syslog_cef": VENDOR_FORTINET,
                       "api_push": VENDOR_FORTINET, "csv_import": VENDOR_FORTINET}


def event_vendor(ev) -> str:
    """Vendor of a stored event (legacy rows without ``vendor`` by source_type)."""
    v = getattr(ev, "vendor", None)
    if v:
        return v
    return _SOURCE_TYPE_VENDOR.get(getattr(ev, "source_type", None) or "", "unknown")
