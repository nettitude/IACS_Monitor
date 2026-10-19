"""
FortiAnalyzer ingest: three delivery methods, one normalized model.

FortiAnalyzer can deliver data to the monitor in three ways:
  1. Syslog/CEF log forwarding (real-time, from Log Forwarding settings)
  2. REST API push (the monitor POSTs a webhook URL to FortiAnalyzer
     event handlers, or FortiAnalyzer calls a custom connector script)
  3. CSV report import (scheduled FortiAnalyzer reports exported as CSV,
     uploaded manually or via the /ingest/forti-report endpoint)

All three are first translated into a dict keyed by *FortiOS log field
names* (srcip, dstip, srcport, policyid, devname, eventtime, ...) and then
normalised by one function (_normalise) into FortiAnalyzerEvent columns,
so the three paths cannot drift apart. The raw log is always preserved in
raw_fields/raw_message so nothing is irreversibly discarded.

CEF (FortiOS "CEF support" mapping)
-----------------------------------
FortiOS emits the standard ArcSight keys it has an equivalent for and
``FTNTFGT<fortios field name>`` for everything else:

  src / dst / spt / dpt        -> srcip / dstip / srcport / dstport
  act                          -> action
  proto (IANA number: 6/17/1)  -> protocol (tcp/udp/icmp ...)
  deviceInboundInterface       -> srcintf    deviceOutboundInterface -> dstintf
  out / in                     -> sentbyte / rcvdbyte
  externalId                   -> sessionid
  dvchost                      -> devname (hostname, preferred device_name)
  deviceExternalId             -> devid (serial number; device_name fallback)
  duser / suser                -> dstuser / srcuser
  cat = "<type>:<subtype>"     -> log type / subtype
  FTNTFGTxxx                   -> xxx   (FTNTFGTpolicyid, FTNTFGTeventtime, ...)
  csN + csNLabel=<name>        -> <name> (lowest precedence; an unlabelled
                                  csN is never interpreted - T3-24)

The syslog transport header in front of "CEF:" may be RFC3164
(``<134>Sep 30 12:00:00 fw1 CEF:0|...``) or RFC5424
(``<134>1 2026-09-30T12:00:00Z fw1 app - - [sd] CEF:0|...``).

FortiGate key=value syslog
--------------------------
Native FortiOS format. Quoted values honour backslash escapes (``\\"``),
and the FIRST occurrence of a key wins, so text inside a value can never
override srcip/action. A line is only accepted when it carries a FortiGate
signature: ``type=`` plus either ``logid=`` or (``devname=``/``devid=`` and
a known FortiOS log type).

Timestamps (all results are timezone-aware UTC; bad input -> None, never raises)
  eventtime (epoch s/ms/us/ns, inferred by magnitude)
  -> date + time (+ tz="-0500")
  -> CEF rt / start / end (epoch ms or "MMM dd yyyy HH:mm:ss[.SSS] [zone]")

Deduplication (T3-06)
---------------------
Every row carries ``dedup_hash`` (sha1, unique index):
  syslog: sha1(f"{device_name or ''}|{line.strip()}")
  JSON:   sha1("json|" + json.dumps(payload, sort_keys=True))
  CSV:    sha1("csv|"  + json.dumps([header, row]))   (report name ignored)
Byte-identical inputs are therefore treated as the *same* event - two
identical lines in one upload create one row. FortiOS lines carry
eventtime/sessionid/logid, so genuinely repeated events differ in content.

CSV
---
The header row is the row (among the first 20) with the most recognised
column names; a UTF-8 BOM is stripped; column names are matched after
removing case/spaces/punctuation ("Destination Port" == "dstport").
Surplus cells beyond the header are kept in raw_fields["_extra"].

raw_fields always gets integer ``sentbyte``/``rcvdbyte``/``duration``/
``sessionid`` when the source provides them (groundwork for F-10).
"""
import csv
import hashlib
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.sites import site_ingest
from app.models import FortiAnalyzerEvent

# Status strings returned by the *_ex entry points.
STATUS_CREATED = "created"
STATUS_DUPLICATE = "duplicate"
STATUS_UNPARSED = "unparsed"

_FORTI_TRAFFIC_SUBTYPES = {"forward", "local", "multicast"}
_FORTI_AUTH_SUBTYPES = {"login", "logout", "authentication"}
_FORTI_CONFIG_SUBTYPES = {"system", "config"}

_REMOTE_ACCESS_APPS = {
    "teamviewer", "anydesk", "vnc", "rdp", "logmein", "gotomypc",
    "splashtop", "netmanage", "connectwise", "bomgar", "screenconnect",
}

# FortiOS log "type" values (FortiOS 5.x-7.x log reference). A kv line
# without logid= must use one of these AND carry devname=/devid=.
_FORTI_LOG_TYPES = {
    "traffic", "event", "utm", "anomaly", "virus", "webfilter", "ips",
    "app-ctrl", "dlp", "emailfilter", "voip", "dns", "ssh", "ssl", "waf",
    "file-filter", "icap", "gtp", "cifs",
}

_IP_PROTOCOLS = {
    "1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre",
    "50": "esp", "51": "ah", "58": "icmpv6", "89": "ospf", "132": "sctp",
}

# Columns that must not ALL be empty for an event to be stored.
_KEY_COLUMNS = (
    "src_ip", "dst_ip", "action", "policy_id", "app", "attack_name",
    "user", "src_user", "service", "subtype",
)

_METRIC_FIELDS = ("sentbyte", "rcvdbyte", "duration", "sessionid")

_RAW_MESSAGE_MAX = 4096   # storage bound for raw_message (column is Text)


# --------------------------------------------------------------- timestamps

def _epoch_to_dt(value) -> Optional[datetime]:
    """Epoch in s / ms / us / ns (inferred by magnitude) -> aware UTC."""
    try:
        v = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not v > 0 or v != v:          # rejects <=0 and NaN
        return None
    if v < 1e11:
        secs = v                     # seconds (until year ~5138)
    elif v < 1e14:
        secs = v / 1e3               # milliseconds
    elif v < 1e17:
        secs = v / 1e6               # microseconds
    elif v < 1e20:
        secs = v / 1e9               # nanoseconds
    else:
        return None
    try:
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def _parse_tz(tz) -> Optional[timezone]:
    """'-0500' / '+01:00' / 'UTC' / 'Z' / IANA name -> tzinfo, else None."""
    if tz is None:
        return None
    s = str(tz).strip()
    if not s:
        return None
    if s.upper() in ("Z", "UTC", "GMT"):
        return timezone.utc
    m = _OFFSET_RE.match(s)
    if m:
        hours, minutes = int(m.group(2)), int(m.group(3))
        if hours > 23 or minutes > 59:
            return None
        delta = timedelta(hours=hours, minutes=minutes)
        return timezone(-delta if m.group(1) == "-" else delta)
    if "/" in s:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(s)
        except Exception:
            return None
    return None


_TRAILING_ZONE_RE = re.compile(
    r"^(.*\d)\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2}|[A-Za-z]+/[A-Za-z_/+-]+|[A-Z]{3,4})$"
)
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M",
    "%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
)
_YEARLESS_FORMATS = ("%Y %b %d %H:%M:%S", "%Y %b %d %H:%M:%S.%f")


def _parse_timestamp(ts_str, tz=None) -> Optional[datetime]:
    """
    Parse a timestamp string into an aware UTC datetime. ``tz`` (e.g. the
    FortiOS tz="-0500" field) applies to naive values only; an explicit
    zone inside the string wins. An unparseable tz falls back to UTC.
    Never raises.
    """
    try:
        if ts_str is None:
            return None
        s = " ".join(str(ts_str).split())
        if not s:
            return None
        if re.fullmatch(r"\d+(\.\d+)?", s):
            return _epoch_to_dt(s)
        default_zone = _parse_tz(tz) or timezone.utc

        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=default_zone)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        zone = default_zone
        m = _TRAILING_ZONE_RE.match(s)
        if m:
            parsed_zone = _parse_tz(m.group(2))
            if parsed_zone is None:
                return None     # unknown abbreviation (EST, CEST...): don't guess
            s, zone = m.group(1).strip(), parsed_zone

        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=zone).astimezone(timezone.utc)
            except ValueError:
                continue

        now = datetime.now(timezone.utc)
        for fmt in _YEARLESS_FORMATS:
            try:
                dt = datetime.strptime(f"{now.year} {s}", fmt).replace(tzinfo=zone)
            except ValueError:
                continue
            if dt.astimezone(timezone.utc) > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
            return dt.astimezone(timezone.utc)
        return None
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def _event_time(f: dict, fallbacks=()) -> Optional[datetime]:
    """eventtime -> date+time(+tz) -> fallbacks (CEF rt/start/end)."""
    et = _epoch_to_dt(f.get("eventtime")) if f.get("eventtime") else None
    if et:
        return et
    date_s, time_s = f.get("date") or "", f.get("time") or ""
    if date_s or time_s:
        et = _parse_timestamp(f"{date_s} {time_s}".strip(), f.get("tz"))
        if et:
            return et
    for fb in fallbacks:
        et = _parse_timestamp(fb)
        if et:
            return et
    return None


# --------------------------------------------------------------- helpers

def _safe_int(val) -> Optional[int]:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def _s(val) -> Optional[str]:
    """Stringify a scalar; empty -> None."""
    if val is None:
        return None
    if isinstance(val, bool):
        val = str(val).lower()
    s = str(val).strip()
    return s or None


def _lower(val) -> Optional[str]:
    s = _s(val)
    return s.lower() if s else None


def _protocol(val) -> Optional[str]:
    s = _lower(val)
    if s is None:
        return None
    return _IP_PROTOCOLS.get(s, s)


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


# Vendor-neutral metric names shared with syslog_vendors (F-10/F-11):
# every vendor's raw_fields carries bytes_sent / bytes_received / duration_s.
_NEUTRAL_METRICS = {"sentbyte": "bytes_sent", "rcvdbyte": "bytes_received",
                    "duration": "duration_s"}


def _metrics_into(raw: dict, f: dict) -> None:
    """Copy integer sentbyte/rcvdbyte/duration/sessionid into raw_fields
    (plus the vendor-neutral bytes_sent/bytes_received/duration_s)."""
    for k in _METRIC_FIELDS:
        v = _safe_int(f.get(k))
        if v is not None:
            raw[k] = v
            if k in _NEUTRAL_METRICS:
                raw.setdefault(_NEUTRAL_METRICS[k], v)


def _normalise(f: dict, source_type: str, raw_message: Optional[str],
               raw_fields: dict, time_fallbacks=()) -> dict:
    """FortiOS-named field dict (lower-case keys) -> FortiAnalyzerEvent columns."""
    raw = dict(raw_fields)
    _metrics_into(raw, f)
    return {
        "source_type": source_type,
        "vendor": "fortinet",
        "device_name": _s(f.get("devname")) or _s(f.get("devid")),
        "log_type": _lower(f.get("type")),
        "subtype": _lower(f.get("subtype")),
        "src_ip": _s(f.get("srcip")),
        "dst_ip": _s(f.get("dstip")),
        "src_port": _safe_int(f.get("srcport")),
        "dst_port": _safe_int(f.get("dstport")),
        "protocol": _protocol(f.get("proto")),
        "action": _lower(f.get("action")),
        "policy_id": _s(f.get("policyid")),
        "policy_name": _s(f.get("policyname")),
        "service": _s(f.get("service")),
        "app": _lower(f.get("app")) or _lower(f.get("appcat")),
        "attack_name": _s(f.get("attack")),
        "severity": _lower(f.get("severity")),
        "user": _s(f.get("dstuser")) or _s(f.get("user")),
        "src_user": _s(f.get("srcuser")),
        "event_time": _event_time(f, time_fallbacks),
        "raw_message": raw_message,
        "raw_fields": raw,
    }


def _has_content(fields: dict) -> bool:
    return any(fields.get(c) not in (None, "") for c in _KEY_COLUMNS)


# --------------------------------------------------------------- CEF

_PRI_RE = re.compile(r"^<\d{1,3}>")
_CEF_START_RE = re.compile(r"CEF:\d+\|")
_RFC5424_PREFIX_RE = re.compile(
    r"^<\d{1,3}>\d{1,2} \S+ \S+ \S+ \S+ \S+ (?:-|\[.*\])\s*﻿?$"
)
_CEF_KEY_RE = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]+)=")
_CEF_LABEL_RE = re.compile(r"^((?:cs|cn|flexString|flexNumber)\d+)Label$")

_CEF_STD_TO_FORTI = {
    "src": "srcip", "dst": "dstip", "spt": "srcport", "dpt": "dstport",
    "act": "action", "proto": "proto",
    "deviceInboundInterface": "srcintf", "deviceOutboundInterface": "dstintf",
    "out": "sentbyte", "in": "rcvdbyte", "externalId": "sessionid",
    "dvchost": "devname", "deviceExternalId": "devid",
    "duser": "dstuser", "suser": "srcuser", "msg": "msg",
    "app": "app", "requestApplication": "app",
}


def _locate_cef(line: str) -> Optional[int]:
    """
    Index of "CEF:" in ``line`` if it is a CEF record, optionally behind a
    syslog transport header (RFC3164 or RFC5424). A "CEF:" that appears
    inside a key=value body (prefix contains '=' but is not an RFC5424
    structured-data header) is not CEF.
    """
    m = _CEF_START_RE.search(line)
    if not m:
        return None
    prefix = line[:m.start()]
    if not prefix.strip():
        return m.start()
    if "=" not in prefix and '"' not in prefix:
        return m.start()          # RFC3164 / ISO-timestamp BSD header
    if _RFC5424_PREFIX_RE.match(prefix):
        return m.start()
    return None


def _split_cef_header(s: str):
    """'CEF:v|a|b|c|d|e|f|ext' -> ([v, a..f], ext) honouring \\| and \\\\."""
    parts, buf, i, n = [], [], 4, len(s)
    while i < n and len(parts) < 7:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in "|\\":
            buf.append(s[i + 1])
            i += 2
            continue
        if c == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if len(parts) < 7 or not parts[0].isdigit():
        return None
    return parts, s[i:]


def _cef_unescape(v: str) -> str:
    out, i, n = [], 0, len(v)
    while i < n:
        c = v[i]
        if c == "\\" and i + 1 < n:
            nxt = v[i + 1]
            if nxt in "=\\":
                out.append(nxt)
            elif nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            else:
                out.append(c + nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_cef_extension(ext_raw: str) -> dict:
    """
    Parse a CEF extension: each value runs until the next ` key=` token
    (so values may contain spaces), with \\= \\\\ \\n \\r escapes. First
    occurrence of a key wins.
    """
    ext: dict = {}
    matches = list(_CEF_KEY_RE.finditer(ext_raw))
    for idx, m in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(ext_raw)
        value = ext_raw[m.end():end].rstrip()
        ext.setdefault(m.group(1), _cef_unescape(value))
    return ext


def _norm_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", label.lower())


def parse_cef_line(line: str) -> Optional[dict]:
    """
    Parse a single CEF syslog line (optionally behind an RFC3164/RFC5424
    header). Returns a normalized dict, or None if the line is not CEF or
    carries none of the key fields.
    """
    line = (line or "").strip()
    start = _locate_cef(line)
    if start is None:
        return None
    split = _split_cef_header(line[start:])
    if split is None:
        return None
    header, ext_raw = split
    _version, vendor, product, _dev_version, signature, name, _sev = header
    ext = parse_cef_extension(ext_raw)

    # FortiOS-named view: FTNTFGT<x> > standard CEF keys > labelled csN.
    f: dict = {}
    for k, v in ext.items():
        if k.startswith("FTNTFGT") and len(k) > 7:
            f.setdefault(k[7:].lower(), v)
    for k, fk in _CEF_STD_TO_FORTI.items():
        if k in ext:
            f.setdefault(fk, ext[k])
    for k, v in ext.items():
        lm = _CEF_LABEL_RE.match(k)
        if lm and v and lm.group(1) in ext:
            f.setdefault(_norm_label(v), ext[lm.group(1)])
    if "logid" not in f and signature.isdigit() and "fortinet" in vendor.lower():
        f["logid"] = signature

    # log type / subtype: FTNTFGTtype/subtype > cat "<type>:<subtype>" > header name
    cat = (ext.get("cat") or "").strip()
    cat_type, _, cat_sub = cat.partition(":")
    name_type, _, name_rest = name.partition(":")
    log_type = f.get("type") or (cat_type if cat_type else None)
    if not log_type and name_type.strip().lower() in _FORTI_LOG_TYPES:
        log_type = name_type.strip()
    subtype = f.get("subtype") or (cat_sub.strip() if cat_sub else None)
    if not subtype and name_rest and log_type and name_type.strip().lower() == log_type.lower():
        subtype = name_rest.split()[0] if name_rest.split() else None
    lt = (log_type or "").lower()
    # Legacy CEF classification kept for the alert engine: cat mentioning
    # ips -> "ips"; auth -> "event"; no type but addresses -> "traffic".
    if "ips" in cat.lower() or (lt == "utm" and (subtype or "").lower() == "ips"):
        lt = "ips"
    elif not lt and "auth" in cat.lower():
        lt = "event"
    elif not lt and (f.get("srcip") or f.get("dstip")):
        lt = "traffic"
    f["type"] = lt or None
    f["subtype"] = subtype

    fields = _normalise(
        f, "syslog_cef", line, ext,
        time_fallbacks=(ext.get("rt"), ext.get("start"), ext.get("end")),
    )
    if not _has_content(fields):
        return None
    if "fortinet" not in vendor.lower():
        fields["vendor"] = (_lower(vendor) or "cef")[:32]
    return fields


# --------------------------------------------------------------- FortiGate kv

_KV_KEY_RE = re.compile(r"([A-Za-z0-9_.\-]+)=")


def parse_forti_kv_pairs(line: str) -> dict:
    """
    Tokenise FortiOS key=value text. Quoted values honour \\" and \\\\
    escapes; unquoted values run to the next whitespace; tokens that are
    not key=value (syslog header words) are skipped. First occurrence of a
    key wins, so a later duplicate can never override it.
    """
    out: dict = {}
    s = _PRI_RE.sub("", line.strip(), count=1)
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        m = _KV_KEY_RE.match(s, i)
        if not m:
            while i < n and not s[i].isspace():
                i += 1
            continue
        key, i = m.group(1), m.end()
        if i < n and s[i] == '"':
            i += 1
            buf = []
            while i < n:
                c = s[i]
                if c == "\\" and i + 1 < n and s[i + 1] in '"\\':
                    buf.append(s[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            value = "".join(buf)
        else:
            j = i
            while j < n and not s[j].isspace():
                j += 1
            value, i = s[i:j], j
        out.setdefault(key, value)
    return out


def _lower_view(d: dict) -> dict:
    view: dict = {}
    for k, v in d.items():
        view.setdefault(str(k).lower(), v)
    return view


def _has_forti_signature(f: dict) -> bool:
    log_type = (f.get("type") or "").strip().lower()
    if not log_type:
        return False
    if f.get("logid"):
        return True
    return log_type in _FORTI_LOG_TYPES and bool(f.get("devname") or f.get("devid"))


def parse_forti_kv_line(line: str) -> Optional[dict]:
    """
    Parse a FortiGate key=value syslog line (FortiOS native format).
    Returns None unless the line carries a FortiGate signature (type= plus
    logid=, or devname=/devid= with a known FortiOS type) and at least one
    key field.
    """
    line = (line or "").strip()
    if not line or "type=" not in line or _locate_cef(line) is not None:
        return None
    fields = parse_forti_kv_pairs(line)
    f = _lower_view(fields)
    if not _has_forti_signature(f):
        return None
    out = _normalise(f, "syslog_cef", line, fields)
    if not _has_content(out):
        return None
    return out


# --------------------------------------------------------------- CSV

def _compact(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.replace("﻿", "").lower())


# compact column name -> FortiOS field name
_CSV_COL_MAP = {
    "srcip": "srcip", "sourceip": "srcip", "src": "srcip", "sourceaddress": "srcip",
    "dstip": "dstip", "destinationip": "dstip", "destip": "dstip", "dst": "dstip",
    "destinationaddress": "dstip",
    "srcport": "srcport", "sourceport": "srcport", "sport": "srcport",
    "dstport": "dstport", "destinationport": "dstport", "destport": "dstport",
    "dport": "dstport",
    "proto": "proto", "protocol": "proto",
    "action": "action",
    "policyid": "policyid", "policy": "policyid",
    "policyname": "policyname",
    "service": "service",
    "app": "app", "application": "app", "appname": "app",
    "appcat": "appcat", "applicationcategory": "appcat",
    "attackname": "attack", "attack": "attack",
    "severity": "severity",
    "user": "user", "dstuser": "dstuser", "destinationuser": "dstuser",
    "srcuser": "srcuser", "sourceuser": "srcuser",
    "device": "devname", "devname": "devname", "devicename": "devname",
    "devid": "devid", "deviceid": "devid",
    "subtype": "subtype", "logtype": "type", "type": "type",
    "date": "date", "time": "time", "datetime": "date", "timestamp": "date",
    "tz": "tz", "timezone": "tz", "eventtime": "eventtime",
    "sentbyte": "sentbyte", "sentbytes": "sentbyte", "bytessent": "sentbyte",
    "rcvdbyte": "rcvdbyte", "rcvdbytes": "rcvdbyte", "receivedbytes": "rcvdbyte",
    "bytesreceived": "rcvdbyte",
    "duration": "duration", "sessionid": "sessionid",
}
_CSV_HEADER_SCAN_ROWS = 20


def _header_score(row) -> int:
    return len({_CSV_COL_MAP[c] for c in (_compact(x) for x in row) if c in _CSV_COL_MAP})


def _csv_line(cells) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(cells)
    return buf.getvalue()


def _parse_csv_rows(csv_text: str, report_name: Optional[str] = None,
                    with_raw: bool = False) -> list:
    """-> list of (normalized_fields | None, dedup_hash). None = no key fields.

    ``with_raw=True`` appends a third element: a self-contained two-line CSV
    (header + this row) that re-parses to the same fields and dedup_hash
    (multi-site phase 3: held in unmapped_log_events for replay)."""
    csv_text = (csv_text or "").lstrip("﻿")
    try:
        rows = list(csv.reader(io.StringIO(csv_text)))
    except csv.Error as exc:
        # C-13: not really a CSV (random bytes / UTF-16 decoded to garbage).
        # Re-raise with a clear message for the route to turn into a 422; this
        # runs before any DB write, so nothing is stored.
        raise csv.Error(
            "Could not parse the uploaded file as CSV - it may be binary, a "
            "non-UTF-8 encoding such as UTF-16, or corrupted "
            f"({exc})."
        ) from exc
    if not rows:
        return []

    best_idx, best_score = None, 0
    for i, row in enumerate(rows[:_CSV_HEADER_SCAN_ROWS]):
        score = _header_score(row)
        if score > best_score:
            best_idx, best_score = i, score
    if best_idx is None:
        return []

    header = [c.replace("﻿", "").strip().lower() for c in rows[best_idx]]
    out = []
    for row in rows[best_idx + 1:]:
        if not any(c.strip() for c in row):
            continue
        cells = [c.strip() for c in row]
        raw: dict = {}
        f: dict = {}
        for i, col in enumerate(header):
            if i >= len(cells):
                break
            raw.setdefault(col, cells[i])
            fk = _CSV_COL_MAP.get(_compact(col))
            if fk and cells[i]:
                f.setdefault(fk, cells[i])
        if len(cells) > len(header):
            raw["_extra"] = cells[len(header):]
        dedup = _sha1("csv|" + json.dumps([header, cells], ensure_ascii=False))
        fields = _normalise(f, "csv_import", ",".join(row), raw)
        item = (fields if _has_content(fields) else None, dedup)
        if with_raw:
            item = item + (_csv_line(header) + "\n" + _csv_line(cells),)
        out.append(item)
    return out


def parse_forti_csv_report(csv_text: str, report_name: Optional[str] = None) -> list:
    """
    Parse a FortiAnalyzer CSV report export into normalized dicts (each
    with ``dedup_hash``). Rows without any key field are dropped.
    """
    records = []
    for fields, dedup in _parse_csv_rows(csv_text, report_name):
        if fields is not None:
            fields["dedup_hash"] = dedup
            records.append(fields)
    return records


# --------------------------------------------------------------- persistence

def _build_event(fields: dict) -> FortiAnalyzerEvent:
    """Build a FortiAnalyzerEvent ORM object from a normalized field dict."""
    ev = FortiAnalyzerEvent()
    for col in [
        "source_type", "device_name", "log_type", "subtype",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "action", "policy_id", "policy_name", "service", "app",
        "attack_name", "severity", "user", "src_user",
        "event_time", "raw_message", "dedup_hash", "vendor",
    ]:
        if fields.get(col) is not None and hasattr(FortiAnalyzerEvent, col):
            setattr(ev, col, fields[col])
    if ev.raw_message and len(ev.raw_message) > _RAW_MESSAGE_MAX:
        ev.raw_message = ev.raw_message[:_RAW_MESSAGE_MAX]
    ev.raw_fields = fields.get("raw_fields", {})
    return ev


def _find_by_hash(db: DBSession, dedup_hash: str,
                  site_id: Optional[int] = None) -> Optional[FortiAnalyzerEvent]:
    # Phase 2: dedup is per site (ux_fortiana_events_site_dedup_hash).
    from app.sites import scope_site_id
    sid = scope_site_id(db, site_id)
    return db.execute(
        select(FortiAnalyzerEvent).where(FortiAnalyzerEvent.site_id == sid,
                                         FortiAnalyzerEvent.dedup_hash == dedup_hash).limit(1)
    ).scalar_one_or_none()


def _persist(fields: dict, db: DBSession) -> tuple:
    """
    Insert unless an event with the same dedup_hash exists. The insert runs
    in a SAVEPOINT so a concurrent upload that wins the race (unique index
    violation) only rolls back this row, not the caller's transaction.
    """
    from app.sites import scope_site_id
    dedup_hash = fields["dedup_hash"]
    sid = scope_site_id(db)
    existing = _find_by_hash(db, dedup_hash, sid)
    if existing is not None:
        return existing, STATUS_DUPLICATE
    ev = _build_event(fields)
    if getattr(ev, "site_id", None) is None:
        ev.site_id = sid
    try:
        if _savepoint_safe(db):
            with db.begin_nested():
                db.add(ev)
                db.flush()
        else:
            # pysqlite with no transaction open yet: a SAVEPOINT would become
            # the outermost transaction and its RELEASE would COMMIT the row
            # behind the caller's back. No write is pending on this
            # connection, so on a conflict a full rollback loses nothing.
            db.add(ev)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                raise
    except IntegrityError:
        existing = _find_by_hash(db, dedup_hash, sid)
        if existing is None:
            raise
        return existing, STATUS_DUPLICATE
    return ev, STATUS_CREATED


def _savepoint_safe(db: DBSession) -> bool:
    """SAVEPOINT is safe except on pysqlite outside a driver transaction."""
    try:
        if db.get_bind().dialect.name != "sqlite":
            return True
        raw = db.connection().connection.dbapi_connection
        return bool(getattr(raw, "in_transaction", False))
    except Exception:
        return False


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_syslog_line_ex(line: str, db: DBSession) -> tuple:
    """
    Parse and persist one syslog line (CEF or FortiGate kv).

    Returns ``(event, status)``:
      ("created",   new FortiAnalyzerEvent)   - flushed, not committed
      ("duplicate", EXISTING FortiAnalyzerEvent with the same dedup_hash)
      ("unparsed",  None)
    (tuple order is (event, status)). Identical raw lines are one event.
    """
    line = (line or "").strip()
    if not line:
        return None, STATUS_UNPARSED
    if _locate_cef(line) is not None:
        fields = parse_cef_line(line)      # CEF never falls through to kv
    else:
        fields = parse_forti_kv_line(line)
    if not fields:
        return None, STATUS_UNPARSED
    fields["dedup_hash"] = _sha1(f"{fields.get('device_name') or ''}|{line}")
    return _persist(fields, db)


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_syslog_line(line: str, db: DBSession) -> Optional[FortiAnalyzerEvent]:
    """
    Backwards-compatible wrapper: returns the NEW event, or None when the
    line is unparsed OR a duplicate of an already-stored event. Use
    ingest_syslog_line_ex to tell those two apart.
    """
    ev, status = ingest_syslog_line_ex(line, db)
    return ev if status == STATUS_CREATED else None


def _json_fields(payload: dict) -> dict:
    """Build the normalized dict directly from JSON (no kv re-serialisation)."""
    f: dict = {}
    for k, v in payload.items():
        if v is None or isinstance(v, (dict, list)):
            continue
        f.setdefault(str(k).lower(), v)
    canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    fields = _normalise(f, "api_push", canonical, payload)
    fields["dedup_hash"] = _sha1("json|" + canonical)
    return fields


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_forti_event_json_ex(payload: dict, db: DBSession) -> tuple:
    """
    Ingest one webhook JSON event. Returns ``(event, status)`` with status
    "created" or "duplicate" (event is then the EXISTING row). A posted
    payload is always stored, even without key fields (raw preserved).
    """
    return _persist(_json_fields(payload or {}), db)


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_forti_event_json(payload: dict, db: DBSession) -> FortiAnalyzerEvent:
    """
    Ingest a single event delivered by FortiAnalyzer as a JSON POST. On a
    duplicate payload the EXISTING event is returned (use
    ingest_forti_event_json_ex to distinguish).
    """
    ev, _status = ingest_forti_event_json_ex(payload, db)
    return ev


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_forti_csv(csv_text: str, db: DBSession, report_name: Optional[str] = None) -> dict:
    """
    Import a FortiAnalyzer scheduled report CSV. Returns
    {"events_imported", "event_ids" (new rows only), "duplicates_skipped",
    "rows_skipped" (rows with no key field)}. Does not commit.
    """
    events, duplicates, skipped = [], 0, 0
    for fields, dedup in _parse_csv_rows(csv_text, report_name):
        if fields is None:
            skipped += 1
            continue
        fields["dedup_hash"] = dedup
        ev, status = _persist(fields, db)
        if status == STATUS_CREATED:
            events.append(ev)
        else:
            duplicates += 1
    return {
        "events_imported": len(events),
        "event_ids": [ev.id for ev in events],
        "duplicates_skipped": duplicates,
        "rows_skipped": skipped,
    }
