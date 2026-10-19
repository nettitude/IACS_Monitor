"""
Firewall config ingestion.

Parses Cisco IOS / ASA ACLs, pfSense XML exports, and Palo Alto (PAN-OS)
XML or `set`-command configs into the normalized FirewallRule shape. This
is your "allowed" topology - later diffed against NetworkSession (the
"observed" topology from pcap/ARP) to flag shadow traffic or rules that
never actually get used.

Each format has a genuinely different rule model, so each gets its own
parser function that all funnel into the same normalized dict shape:

    {
        "device_name": str | None,
        "src": str,          # "any", bare host IP, CIDR, or a tagged
                             # unresolved reference ("object-group:X",
                             # "alias:X", "wildcard:A/W", ...)
        "dst": str,
        "protocol": str,     # "tcp", "udp", "icmp", "any", or another
                             # lowercase IP protocol name
        "dst_port": str,     # CANONICAL port field - see below
        "action": str,       # "permit" | "deny"
        "raw_line": str,     # original text (+ parser notes), for audit
        "rule_order": int,   # evaluation position; rows expanded from one
                             # source rule share the same value
    }

CANONICAL dst_port FORMAT (shared with forti_config_parser and the
downstream reachability / shadow code):
    "any"                -> all ports
    "22", "80,443", "1-1024", "80,443,1000-2000"
                         -> comma-joined ports / ranges, ascending, merged,
                            no spaces
    "unknown:NAME"       -> a port name the parser could not map (counted
                            in stats["unknown_port_names"]; never silently
                            widened to "any")
    "object-group:NAME" / "alias:NAME"
                         -> unresolvable named object
A canonical list longer than 255 chars is split over several rows.

Disabled rules are stored with enabled=False; PAN-OS rules with no action
are not stored, and negated-address DENY rules are skipped (conservative -
under-approximates what is blocked). Negated PERMIT rules have the negated
side widened to "any" (over-approximates exposure) with a note appended to
raw_line. Every skip is counted in the stats dict.

IPv6 (F-07): IPv6 rules are STORED (Cisco `ipv6 access-list`, ASA v6
entries, pfSense inet6/inet46, PAN-OS v6 addresses). An IPv6 row carries
IPv6 values on BOTH sides - an "any" side of an IPv6 rule is written as
"::/0", never "any", so a v6 row can never match an IPv4 query. "any" on
a row therefore always means "any IPv4" (legacy behaviour). src x dst pairs
mixing families (v4 member of a group paired with a v6 member) can never
match traffic and are dropped (stats["mixed_family_pairs_skipped"]).
stats["rules_ipv6"] counts source rules that produced IPv6 rows.
"rules_skipped_ipv6" is kept as a key for API/UI compatibility but is
always 0 now.

Rule identity (for syslog correlation), additional row keys:
    "policy_id"   str | None  - Cisco: None (rule_order keeps ACE line
                                order); pfSense: <tracker>; PAN-OS: rule
                                name when <= 32 chars (column width), else
                                None.
    "policy_name" str | None  - Cisco: ACL name; pfSense: <descr>; PAN-OS:
                                rule name.
    "device_name"             - unchanged (Cisco ACL name, pfSense descr or
                                interface, PAN-OS rule name).

Interface binding: Cisco `interface X / ip access-group ACL in|out` (and
`ipv6 traffic-filter`), ASA `access-group ACL in|out interface NAMEIF`:
`in` on X -> src_zone = X, `out` on X -> dst_zone = X for every row of that
ACL (several interfaces are comma-joined; an ACL bound in both directions
gets one copy of its rows per direction). pfSense rows get src_zone =
<interface> (filter rules are evaluated inbound on that interface).

NAT (F-05): parse_nat_config() returns normalised NatRule dicts; see
app.models.NatRule for semantics.
"""
import hashlib
import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as _safe_ET  # AU D11: no entity expansion / external entities
from typing import Iterable, Optional

from sqlalchemy.orm import Session as DBSession

from app.sites import site_ingest
from app.models import Firewall, FirewallDevice, FirewallRule, NatRule
from app.parsers.common import (
    IngestLimitExceeded, RULE_ROWS_ENV, charge_rule_rows, env_int, rule_row_budget,
)

log = logging.getLogger(__name__)


# ====================================================== stats plumbing ==

#: Counters every parser may increment. Always present in ingest stats.
SKIP_STAT_KEYS = (
    "rules_disabled",               # stored with enabled=False (flagged by review_disabled_rules)
    "rules_skipped_negated_deny",
    "rules_skipped_no_action",
    "rules_skipped_ipv6",           # DEPRECATED (F-07): IPv6 rules are stored now; always 0
    "rules_ipv6",                   # source rules that produced IPv6 rows
    "mixed_family_pairs_skipped",   # v4 x v6 src/dst pairs dropped (cannot match)
    "unresolved_object_groups",
    "empty_object_groups",          # AU D2: group expanded to nothing -> "unresolved:NAME" token
    "unknown_port_names",
    "dynamic_address_groups",       # PAN-OS dynamic address groups ("dynamic-group:NAME")
    "acl_bindings",                 # Cisco/ASA access-group bindings applied to rows
    "groups_over_limit",            # A-02: group > MAX_GROUP_MEMBERS or nested > MAX_GROUP_DEPTH
    "rules_over_limit",             # A-02: rule whose src x dst x svc > MAX_RULE_ROWS
    "rules_skipped_match",          # A-08: pfSense <type>match</type> (no allow/block effect)
    "rules_skipped_unknown_action", # A-07/A-08: action we cannot map -> not stored
    "lines_rejected",               # A-18: malformed ACE / object / NAT line skipped
)

#: A-18: at most this many sample reasons are kept in stats["reject_reasons"].
MAX_REJECT_SAMPLES = 5

# ------------------------------------------------ expansion caps (A-02) --
#: Max distinct resolved members of one address/service group. Larger
#: groups resolve to a single unresolved token "too-large:NAME" (never
#: "any": downstream treats it as unknown).
MAX_GROUP_MEMBERS = 10_000
#: Max rows one source rule may expand to (src x dst x services). Over the
#: cap the largest side(s) collapse to "too-large:NAME".  B-08: env
#: IACS_MAX_RULE_ROWS (default 25,000; was 50,000).  The total across ALL
#: rules of one ingest is bounded separately by IACS_MAX_RULE_ROWS_PER_INGEST
#: (common.rule_row_budget) - over that the whole upload is rejected.
MAX_RULE_ROWS = env_int("IACS_MAX_RULE_ROWS", 25_000)
#: Max group nesting depth (also guards against RecursionError).
MAX_GROUP_DEPTH = 64
TOO_LARGE_PREFIX = "too-large:"


class _Memo:
    """Per-config memo of resolved groups. `cycles` is bumped whenever a
    resolution is truncated (cycle / depth), so path-dependent partial
    results are never cached."""
    __slots__ = ("data", "cycles")

    def __init__(self):
        self.data: dict = {}
        self.cycles = 0


def _memo_of(container) -> "_Memo":
    m = getattr(container, "_memo", None)
    return m if m is not None else _Memo()


class _MemoDict(dict):
    """dict that carries a resolution memo (aliases, service groups)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._memo = _Memo()


def _group_over(stats, name: str, why: str) -> str:
    _bump(stats, "groups_over_limit")
    log.warning("firewall group %r not expanded (%s); stored as %s%s",
                name, why, TOO_LARGE_PREFIX, name)
    return f"{TOO_LARGE_PREFIX}{name}"


def _memo_enter(memo: "_Memo", key, seen, stats, name):
    """Common prologue. Returns (result_or_None, c0)."""
    if key in memo.data:
        return list(memo.data[key]), None
    if key in seen:
        memo.cycles += 1
        return [], None
    if len(seen) >= MAX_GROUP_DEPTH:
        memo.cycles += 1
        return [_group_over(stats, name, f"nesting deeper than {MAX_GROUP_DEPTH}")], None
    return None, memo.cycles


def _memo_store(memo: "_Memo", key, out: list, c0: int, stats, name,
                wrap=lambda tok: tok) -> list:
    out = _dedupe(out)
    if len(out) > MAX_GROUP_MEMBERS:
        out = [wrap(_group_over(stats, name, f"{len(out)} members > {MAX_GROUP_MEMBERS}"))]
    if not out:
        # AU full review D2: an empty group (or one whose members are all
        # cycles) expanded to nothing, and the rule's src x dst product was
        # then empty - the rule vanished without a trace.  Keep it visible
        # as an unresolved token instead.
        _bump(stats, "empty_object_groups")
        log.warning("firewall group %r is empty / unresolvable; stored as unresolved:%s", name, name)
        out = [wrap(f"unresolved:{name}")]
    if memo.cycles == c0:
        memo.data[key] = out
    return list(out)


def _cap_rule(sides: list, stats, rule_label: str, factor: int = 1) -> list:
    """A-02 row cap. `sides` = [(values, label, token_fn)]; while the
    product exceeds MAX_RULE_ROWS the largest side is replaced by
    [token_fn("too-large:LABEL")]. Returns the (possibly capped) value lists.

    B-08: the resulting product (times ``factor`` - extra per-row fan-out the
    caller applies, e.g. pfSense tcp/udp) is charged to the per-ingest row
    budget BEFORE any row is built; over budget raises IngestLimitExceeded."""
    vals = [list(v) for v, _l, _t in sides]

    def _prod():
        n = 1
        for v in vals:
            n *= max(len(v), 1)
        return n
    if _prod() <= MAX_RULE_ROWS:
        charge_rule_rows(_prod() * max(factor, 1), rule_label)
        return vals
    total = _prod()
    while _prod() > MAX_RULE_ROWS:
        i = max(range(len(vals)), key=lambda k: len(vals[k]))
        if len(vals[i]) <= 1:
            break
        vals[i] = [sides[i][2](f"{TOO_LARGE_PREFIX}{sides[i][1]}")]
    _bump(stats, "rules_over_limit")
    log.warning("firewall rule %r expands to %d rows > %d; over-limit side(s) "
                "stored as %s tokens", rule_label, total, MAX_RULE_ROWS, TOO_LARGE_PREFIX)
    charge_rule_rows(_prod() * max(factor, 1), rule_label)
    return vals


def _new_stats() -> dict:
    return {k: 0 for k in SKIP_STAT_KEYS}


def _bump(stats: Optional[dict], key: str, n: int = 1) -> None:
    if stats is not None:
        stats[key] = stats.get(key, 0) + n


def _reject(stats: Optional[dict], raw: str, err, key: str = "lines_rejected") -> None:
    """A-18: count one skipped malformed line and keep a few sample reasons."""
    _bump(stats, key)
    if stats is None:
        return
    samples = stats.setdefault("reject_reasons", [])
    if len(samples) < MAX_REJECT_SAMPLES:
        samples.append(f"{str(raw)[:120]}: {str(err)[:120]}")


def _check_ip(tok) -> None:
    """A-18: a token that looks like a dotted-quad (optionally /len) must be a
    valid address (no octet > 255, no leading zeros) - else ValueError, so
    the containing line is rejected instead of stored verbatim."""
    if not isinstance(tok, str):
        return
    base, _, plen = tok.partition("/")
    if _IP_RE.match(base):
        ipaddress.ip_address(base)
        if plen:
            ipaddress.ip_network(tok, strict=False)


# ================================================== canonical ports ======

MAX_PORT_FIELD_LEN = 255
_ALL_PORTS = (1, 65535)


def _merge_ranges(ranges: Iterable[tuple]) -> list:
    rs = sorted((int(lo), int(hi)) for lo, hi in ranges)
    merged: list = []
    for lo, hi in rs:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def canonical_ports(ranges: Iterable[tuple]) -> str:
    """
    Render (lo, hi) port ranges in the canonical dst_port format.
    Ranges covering 1-65535 (port 0 is irrelevant) collapse to "any".
    Returns "" for an empty set (caller decides what that means).
    """
    cleaned = []
    for lo, hi in ranges:
        lo, hi = int(lo), int(hi)
        if lo > hi:
            lo, hi = hi, lo
        lo, hi = max(lo, 0), min(hi, 65535)
        if lo > hi:
            continue
        cleaned.append((lo, hi))
    merged = _merge_ranges(cleaned)
    if not merged:
        return ""
    if any(lo <= 1 and hi >= 65535 for lo, hi in merged):
        return "any"
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in merged)


_CANON_TOKEN_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_canonical_ports(value: Optional[str]) -> Optional[list]:
    """
    Parse a canonical dst_port string back into (lo, hi) ranges.
    Returns None for "any"/empty (all ports); raises ValueError for a
    non-canonical value (e.g. "unknown:foo").
    """
    if value is None:
        return None
    v = str(value).strip()
    if v in ("", "any"):
        return None
    out = []
    for tok in v.split(","):
        m = _CANON_TOKEN_RE.match(tok)
        if not m:
            raise ValueError(f"not a canonical port field: {value!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        out.append((lo, hi))
    return out


def port_field_hits(value: Optional[str], ports: Iterable[int]) -> bool:
    """True when an explicit canonical port field includes any of `ports`
    ("any" and unresolved values return False)."""
    try:
        ranges = parse_canonical_ports(value)
    except ValueError:
        return False
    if ranges is None:
        return False
    return any(lo <= int(p) <= hi for p in ports for lo, hi in ranges)


def split_port_field(value: Optional[str], limit: int = MAX_PORT_FIELD_LEN) -> list:
    """Split a canonical port field longer than `limit` into several
    canonical fields (on comma boundaries). Non-canonical values pass
    through unchanged."""
    if value is None or len(value) <= limit:
        return [value]
    chunks, cur = [], ""
    for tok in value.split(","):
        cand = f"{cur},{tok}" if cur else tok
        if len(cand) > limit and cur:
            chunks.append(cur)
            cur = tok
        else:
            cur = cand
    if cur:
        chunks.append(cur)
    return chunks


def _finalize_rows(rows: list) -> list:
    """Split any row whose dst_port exceeds the column width."""
    out = []
    for r in rows:
        parts = split_port_field(r.get("dst_port"))
        if len(parts) == 1:
            out.append(r)
            continue
        for p in parts:
            nr = dict(r)
            nr["dst_port"] = p
            out.append(nr)
    return out


def _parse_port_text(text: str, sep_chars: str = "-:") -> Optional[list]:
    """
    Parse "80", "80-443", "80:443", "80,443,1000-2000" or a space-separated
    list into ranges. Returns None if any token isn't numeric.
    """
    ranges = []
    for tok in re.split(r"[,\s]+", text.strip()):
        if not tok:
            continue
        m = re.match(r"^(\d{1,5})(?:[" + re.escape(sep_chars) + r"](\d{1,5}))?$", tok)
        if not m:
            return None
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        ranges.append((lo, hi))
    return ranges


def _note(raw: str, notes: list) -> str:
    return raw + ("".join(f" [{n}]" for n in notes) if notes else "")


# ================================================ address families (F-07) ==

_ANY_TOKENS = ("any", "any4", "any6")
V6_ANY = "::/0"


def addr_family(tok: Optional[str]) -> Optional[int]:
    """4 / 6 for a concrete address token (host, CIDR, "range:a-b",
    "::/0", "any4"/"any6"), None for "any" and named / unresolved tokens."""
    if not tok:
        return None
    t = str(tok).strip()
    if t == "any6":
        return 6
    if t == "any4":
        return 4
    if t.startswith("range:"):
        t = t[len("range:"):].split("-", 1)[0]
    try:
        return ipaddress.ip_network(t, strict=False).version
    except ValueError:
        return None


def _family_any(tok: str, fam: int) -> str:
    if tok in _ANY_TOKENS:
        return "any" if fam == 4 else V6_ANY
    return tok


def _pair_families(srcs: list, dsts: list, default_families=(4,),
                   stats: Optional[dict] = None, restrict: bool = False) -> list:
    """
    Expand src x dst into [(src, dst, family)]. A concrete address fixes
    the family of the pair; "any" and named tokens follow the other side
    or, when both sides are family-less, expand to each of
    `default_families`. Cross-family pairs are dropped and counted, as are
    (with `restrict`) pairs whose family the rule does not apply to
    (pfSense: an IPv6 alias member in an inet-only rule).
    """
    out = []
    for s in srcs:
        for d in dsts:
            fs, fd = addr_family(s), addr_family(d)
            if fs and fd and fs != fd:
                _bump(stats, "mixed_family_pairs_skipped")
                continue
            fam = fs or fd
            if restrict and fam and fam not in default_families:
                _bump(stats, "mixed_family_pairs_skipped")
                continue
            for f in ([fam] if fam else list(default_families)):
                out.append((_family_any(s, f), _family_any(d, f), f))
    return out


def _norm_addr(value: str) -> str:
    """Normalise a literal IPv4/IPv6 address or CIDR (host -> bare IP,
    /0 -> "any" or "::/0"); other text is returned unchanged."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return value
    return _cidr(str(net.network_address), net.prefixlen)


def _nat_addr(value: Optional[str]) -> Optional[str]:
    """NatRule address form: hosts as /32 (/128), "any" for 0/0."""
    if value is None:
        return None
    v = str(value).strip()
    if v in _ANY_TOKENS or v == "":
        return "any"
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return v
    if net.prefixlen == 0:
        return "any"
    return str(net)


def _nat_range(a: str, b: str) -> str:
    """Address range for NatRule: one exact CIDR when the range is
    CIDR-aligned, else "range:a-b"."""
    try:
        nets = list(ipaddress.summarize_address_range(
            ipaddress.ip_address(a), ipaddress.ip_address(b)))
        if len(nets) == 1:
            return _nat_addr(str(nets[0]))
    except (ValueError, TypeError):
        pass
    return f"range:{a}-{b}"


def nat_row(nat_type: str, **kw) -> dict:
    """Build a normalised NAT dict (keys = NatRule columns)."""
    row = {
        "nat_type": nat_type, "name": None, "policy_id": None,
        "protocol": "any", "src_intf": None, "orig_src": None,
        "ext_ip": None, "ext_port": None, "mapped_ip": None,
        "mapped_port": None, "orig_port": None, "enabled": True, "raw": None,
        "device_name": None,
    }
    row.update(kw)
    # B-15(b): address / policy lists are stored whole (NatRule Text
    # columns) - never cut mid-token.
    return row


# ======================================================== Cisco IOS/ASA ==

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PORT_OPERATORS = {"eq", "gt", "lt", "neq", "range"}

#: Cisco IOS / ASA well-known port keywords.
CISCO_PORT_NAMES = {
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20,
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "time": 37,
    "nameserver": 42, "whois": 43, "tacacs": 49, "domain": 53,
    "bootps": 67, "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79,
    "www": 80, "http": 80, "hostname": 101, "pop2": 109, "pop3": 110,
    "sunrpc": 111, "ident": 113, "nntp": 119, "ntp": 123,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
    "imap4": 143, "snmp": 161, "snmptrap": 162, "xdmcp": 177, "bgp": 179,
    "irc": 194, "dnsix": 195, "ldap": 389, "mobile-ip": 434, "https": 443,
    "pim-auto-rp": 496, "isakmp": 500, "biff": 512, "exec": 512,
    "login": 513, "who": 513, "cmd": 514, "rsh": 514, "syslog": 514,
    "lpd": 515, "talk": 517, "rip": 520, "uucp": 540, "klogin": 543,
    "kshell": 544, "rtsp": 554, "ldaps": 636, "kerberos": 88,
    "lotusnotes": 1352, "citrix-ica": 1494, "sqlnet": 1521,
    "radius": 1645, "radius-acct": 1646, "h323": 1720, "pptp": 1723,
    "nfs": 2049, "ctiqbe": 2748, "cifs": 3020, "sip": 5060, "aol": 5190,
    "secureid-udp": 5510, "pcanywhere-data": 5631,
    "pcanywhere-status": 5632, "mssql": 1433, "rdp": 3389, "vxlan": 4789,
    "non500-isakmp": 4500, "imap": 143, "tacacs-ds": 65,
}

_CISCO_PROTO_NUMBERS = {"0": "any", "1": "icmp", "6": "tcp", "17": "udp",
                        "47": "gre", "50": "esp", "51": "ah", "89": "ospf",
                        "132": "sctp"}
_PORTED_PROTOCOLS = {"tcp", "udp", "sctp", "tcp-udp"}

# Tokens that may trail an ACE and must not be mistaken for port values.
_CISCO_TRAILING = {
    "log", "log-input", "established", "time-range", "precedence", "tos",
    "dscp", "fragments", "inactive", "ack", "fin", "psh", "rst", "syn",
    "urg", "match-any", "match-all", "option", "ttl", "reflect",
    "interval", "disable", "default",
}

_NOT_PRESENT = object()


def _norm_protocol(p: str) -> str:
    p = p.lower()
    if p in _CISCO_PROTO_NUMBERS:
        return _CISCO_PROTO_NUMBERS[p]
    if p in ("ip", "ipv4", "ipv6"):
        return "any"
    return p


def _mask_prefix(mask: str, default_kind: str) -> Optional[int]:
    """
    Convert a dotted mask to a prefix length. IOS ACLs use wildcard masks
    (0.0.0.255), ASA / object-groups use netmasks (255.255.255.0); the
    kind is detected from the bit pattern (contiguous ones from the left =
    netmask, from the right = wildcard). 0.0.0.0 and 255.255.255.255 are
    ambiguous and resolved with `default_kind`. Non-contiguous masks
    return None.
    """
    try:
        m = int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    inv = (~m) & 0xFFFFFFFF
    is_wild = (m & (m + 1)) == 0            # 0...01...1
    is_net = (inv & (inv + 1)) == 0         # 1...10...0
    if is_wild and is_net:
        kind = default_kind
    elif is_net:
        kind = "netmask"
    elif is_wild:
        kind = "wildcard"
    else:
        return None
    ones = bin(m).count("1")
    return ones if kind == "netmask" else 32 - ones


def _cidr(ip: str, prefix: int) -> str:
    _check_ip(ip)
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    if net.prefixlen == 0:
        return "any" if net.version == 4 else V6_ANY
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)     # bare host IP (legacy shape)
    return str(net)


def _addr_with_mask(ip: str, mask: str, default_kind: str) -> str:
    prefix = _mask_prefix(mask, default_kind)
    if prefix is None:
        return f"wildcard:{ip}/{mask}"
    return _cidr(ip, prefix)


def _range_cidrs(a: str, b: str, strict: bool = False) -> list:
    if strict:      # A-18 (Cisco): malformed endpoints reject the line
        _check_ip(a)
        _check_ip(b)
    try:
        nets = ipaddress.summarize_address_range(
            ipaddress.ip_address(a), ipaddress.ip_address(b))
        return [_cidr(str(n.network_address), n.prefixlen) for n in nets]
    except (ValueError, TypeError):
        return [f"range:{a}-{b}"]


def _is_v6(addr: str) -> bool:
    return addr_family(addr) == 6


class _CiscoObjects:
    """Object / object-group definitions collected from a Cisco config."""

    def __init__(self):
        self.net_objects: dict = {}   # object network   -> [addr]
        self.net_groups: dict = {}    # object-group network -> [(kind, val)]
        self.svc_objects: dict = {}   # object service   -> [(proto, ports)]
        self.svc_groups: dict = {}    # object-group service (no proto) -> [item]
        self.port_groups: dict = {}   # object-group service NAME tcp|udp -> [item]
        self.proto_groups: dict = {}  # object-group protocol -> [item]
        self.other_groups: set = set()  # icmp-type etc. (known, not expanded)
        self.object_nats: list = []     # ASA object NAT: (object name, tokens)
        self._memo_net = _Memo()
        self._memo_ports = _Memo()
        self._memo_svc = _Memo()

    def is_port_group(self, name: str) -> bool:
        return name in self.port_groups

    # -- address resolution (A-02: memoised, deduped, capped) --
    def resolve_net_group(self, name, stats, _seen=frozenset()) -> list:
        memo = self._memo_net
        hit, c0 = _memo_enter(memo, name, _seen, stats, name)
        if hit is not None:
            return hit
        if name not in self.net_groups:
            _bump(stats, "unresolved_object_groups")
            return [f"object-group:{name}"]
        _seen = _seen | {name}
        out = []
        for kind, val in self.net_groups[name]:
            if kind == "addr":
                out.append(val)
            elif kind == "group":
                out.extend(self.resolve_net_group(val, stats, _seen))
            elif kind == "object":
                out.extend(self.resolve_net_object(val, stats))
        return _memo_store(memo, name, out, c0, stats, name)

    def resolve_net_object(self, name, stats) -> list:
        if name in self.net_objects:
            return list(self.net_objects[name])
        _bump(stats, "unresolved_object_groups")
        return [f"object:{name}"]

    # -- service resolution --
    def resolve_ports(self, name, stats, _seen=frozenset()):
        """Port group -> list of ranges, None (any) or unknown string."""
        memo = self._memo_ports
        if name in memo.data:
            v = memo.data[name]
            return list(v) if isinstance(v, list) else v
        if name in _seen:
            memo.cycles += 1
            return []
        if len(_seen) >= MAX_GROUP_DEPTH:
            memo.cycles += 1
            return _group_over(stats, name, f"nesting deeper than {MAX_GROUP_DEPTH}")
        c0 = memo.cycles
        _seen = _seen | {name}
        ranges: list = []
        result = None
        for item in self.port_groups.get(name, []):
            if item[0] == "ports":
                if item[1] is None or isinstance(item[1], str):
                    result = item[1]
                    break
                ranges.extend(item[1])
            elif item[0] == "group":
                sub = self.resolve_ports(item[1], stats, _seen)
                if sub is None or isinstance(sub, str):
                    result = sub
                    break
                ranges.extend(sub)
            # diamonds: merge as we go so duplicates never accumulate
            if len(ranges) > 64:
                ranges = _merge_ranges(ranges)
        else:
            result = _merge_ranges(ranges) if ranges else []
        if memo.cycles == c0:
            memo.data[name] = result
        return list(result) if isinstance(result, list) else result

    def resolve_services(self, name, stats, _seen=frozenset()) -> list:
        """Service group/object -> [(proto, ports)]."""
        memo = self._memo_svc
        hit, c0 = _memo_enter(memo, name, _seen, stats, name)
        if hit is not None:
            # depth-limit token is a bare string: wrap it as a service
            return [("any", h) if isinstance(h, str) else h for h in hit]
        _seen = _seen | {name}
        if name in self.svc_objects:
            return list(self.svc_objects[name])
        if name in self.port_groups:
            # A port group used in the protocol slot is unusual; treat as tcp-udp
            return [("tcp-udp", self.resolve_ports(name, stats))]
        wrap = lambda tok: ("any", tok)  # noqa: E731
        if name in self.proto_groups:
            out = []
            for item in self.proto_groups[name]:
                if item[0] == "proto":
                    out.append((item[1], None))
                elif item[0] == "group":
                    out.extend(self.resolve_services(item[1], stats, _seen))
            return _memo_store(memo, name, out, c0, stats, name, wrap)
        if name not in self.svc_groups:
            _bump(stats, "unresolved_object_groups")
            return [("any", f"object-group:{name}")]
        out = []
        for item in self.svc_groups[name]:
            if item[0] == "svc":
                out.append((item[1], item[2]))
            elif item[0] in ("group", "object"):
                if item[0] == "object" and item[1] not in self.svc_objects:
                    _bump(stats, "unresolved_object_groups")
                    out.append(("any", f"object:{item[1]}"))
                    continue
                out.extend(self.resolve_services(item[1], stats, _seen))
        return _memo_store(memo, name, out, c0, stats, name, wrap)


def _port_value(tok: str, stats) -> Optional[int]:
    if tok.isdigit():
        return int(tok)
    return CISCO_PORT_NAMES.get(tok.lower())


def _consume_port_op(tokens: list, idx: int, stats):
    """
    Consume '[eq|neq|gt|lt] <port>...' or 'range <a> <b>' at idx.
    Returns (ports, new_idx) where ports is a list of (lo, hi) ranges,
    or an "unknown:NAME" string; (_NOT_PRESENT, idx) if no operator.
    """
    if idx >= len(tokens) or tokens[idx] not in _PORT_OPERATORS:
        return _NOT_PRESENT, idx
    op = tokens[idx]
    idx += 1
    if op == "range":
        if idx + 1 >= len(tokens):
            return _NOT_PRESENT, idx
        a, b = tokens[idx], tokens[idx + 1]
        pa, pb = _port_value(a, stats), _port_value(b, stats)
        if pa is None or pb is None:
            _bump(stats, "unknown_port_names")
            bad = a if pa is None else b
            return f"unknown:{bad}", idx + 2
        return [(pa, pb)], idx + 2
    if idx >= len(tokens):
        return _NOT_PRESENT, idx
    values = [tokens[idx]]
    idx += 1
    if op in ("eq", "neq"):
        # IOS allows several ports after eq/neq ("eq www 443 8080")
        while (idx < len(tokens) and tokens[idx] not in _CISCO_TRAILING
               and tokens[idx] not in _PORT_OPERATORS
               and _port_value(tokens[idx], stats) is not None
               and not _IP_RE.match(tokens[idx])):
            values.append(tokens[idx])
            idx += 1
    nums = []
    for v in values:
        n = _port_value(v, stats)
        if n is None:
            _bump(stats, "unknown_port_names")
            return f"unknown:{v}", idx
        nums.append(n)
    if op == "eq":
        return [(n, n) for n in nums], idx
    if op == "gt":
        return [(nums[0] + 1, 65535)], idx
    if op == "lt":
        return [(1, nums[0] - 1)], idx
    # neq: every port except the listed ones
    ranges, lo = [], 1
    for n in sorted(set(nums)):
        if n > lo:
            ranges.append((lo, n - 1))
        lo = max(lo, n + 1)
    if lo <= 65535:
        ranges.append((lo, 65535))
    return ranges, idx


def _ports_field(ports) -> Optional[str]:
    """ranges | None | 'unknown:..' | _NOT_PRESENT -> canonical field.
    Returns None only when the range set is empty (matches nothing)."""
    if ports is _NOT_PRESENT or ports is None:
        return "any"
    if isinstance(ports, str):
        return ports
    field = canonical_ports(ports)
    return field or None


def _consume_address(tokens: list, idx: int, objs: _CiscoObjects,
                     default_kind: str, stats) -> tuple:
    """
    Consume one ACL address operand. Returns (list_of_addresses, idx).
    Accepts any/any4/any6, host X, object-group N, object N,
    interface N, A W / A M pairs, A/len and bare A.
    """
    if idx >= len(tokens):
        return ["any"], idx
    t = tokens[idx]
    if t in ("any", "any4"):
        return ["any"], idx + 1
    if t == "any6":
        return ["any6"], idx + 1
    if t == "host" and idx + 1 < len(tokens):
        h = tokens[idx + 1]
        _check_ip(h)
        return [_norm_addr(h) if ":" in h else h], idx + 2
    if t == "object-group" and idx + 1 < len(tokens):
        return objs.resolve_net_group(tokens[idx + 1], stats), idx + 2
    if t == "object" and idx + 1 < len(tokens):
        return objs.resolve_net_object(tokens[idx + 1], stats), idx + 2
    if t == "interface" and idx + 1 < len(tokens):
        return [f"interface:{tokens[idx + 1]}"], idx + 2
    if _IP_RE.match(t) and idx + 1 < len(tokens) and _IP_RE.match(tokens[idx + 1]):
        return [_addr_with_mask(t, tokens[idx + 1], default_kind)], idx + 2
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            return [_cidr(str(net.network_address), net.prefixlen)], idx + 1
        except ValueError:
            _check_ip(t)
    _check_ip(t)
    return [t], idx + 1


def _looks_standard(tokens: list) -> bool:
    """ACE body (after action) of a standard ACL starts with an address."""
    return bool(tokens) and (tokens[0] in ("any", "host") or bool(_IP_RE.match(tokens[0])))


def _parse_ace(body: list, kind: str, objs: _CiscoObjects,
               default_kind: str, stats, families=(4,)) -> Optional[dict]:
    """
    Parse the tokens after permit/deny. Returns
    {"combos": [(src, dst, proto, ports_field, family)], "inactive": bool}
    or None when the line can't be parsed. `families` is what a bare
    "any" means (4 for IPv4 ACLs, 6 inside `ipv6 access-list`).
    """
    if not body:
        return None
    inactive = "inactive" in body
    if kind == "standard" or (kind == "auto" and _looks_standard(body)):
        srcs, _ = _consume_address(body, 0, objs, default_kind, stats)
        return {"combos": [(s, d, "any", "any", f) for s, d, f in
                           _pair_families(srcs, ["any"], families, stats)],
                "inactive": inactive}

    idx = 0
    tok = body[idx]
    services: list          # [(proto, ports or _NOT_PRESENT)]
    explicit_services = False
    if tok == "object-group" and idx + 1 < len(body):
        services = objs.resolve_services(body[idx + 1], stats)
        explicit_services = True
        idx += 2
    elif tok == "object" and idx + 1 < len(body):
        name = body[idx + 1]
        if name in objs.svc_objects:
            services = list(objs.svc_objects[name])
        else:
            _bump(stats, "unresolved_object_groups")
            services = [("any", f"object:{name}")]
        explicit_services = True
        idx += 2
    else:
        services = [(_norm_protocol(tok), _NOT_PRESENT)]
        idx += 1

    ported = any(p in _PORTED_PROTOCOLS for p, _ in services)

    svc_label = body[idx - 1]
    src_i0 = idx
    srcs, idx = _consume_address(body, idx, objs, default_kind, stats)
    src_span = (src_i0, idx)
    # optional source-port operator / port group (consumed, not stored)
    if ported:
        _sp, idx = _consume_port_op(body, idx, stats)
        if (_sp is _NOT_PRESENT and idx + 1 < len(body) and body[idx] == "object-group"
                and objs.is_port_group(body[idx + 1])):
            idx += 2
    dst_i0 = idx
    dsts, idx = _consume_address(body, idx, objs, default_kind, stats)
    dst_span = (dst_i0, idx)
    dst_ports = _NOT_PRESENT
    if ported and not explicit_services:
        dst_ports, idx = _consume_port_op(body, idx, stats)
        if (dst_ports is _NOT_PRESENT and idx + 1 < len(body)
                and body[idx] == "object-group" and objs.is_port_group(body[idx + 1])):
            dst_ports = objs.resolve_ports(body[idx + 1], stats)
            idx += 2
        services = [(p, dst_ports) for p, _ in services]

    def _label(i0, i1):
        return body[i1 - 1] if i1 - i0 == 2 and body[i0] in ("object-group", "object") \
            else " ".join(body[i0:i1])
    srcs, dsts, services = _cap_rule(
        [(srcs, _label(*src_span), str), (dsts, _label(*dst_span), str),
         (services, svc_label, lambda tok: ("any", tok))],
        stats, " ".join(body),
        factor=2 if any(p == "tcp-udp" for p, _ in services) else 1)
    combos = []
    pairs = _pair_families(srcs, dsts, families, stats)
    for p, ports in services:
        protos = ["tcp", "udp"] if p == "tcp-udp" else [p]
        for proto in protos:
            field = _ports_field(ports) if proto in ("tcp", "udp", "sctp") else (
                ports if isinstance(ports, str) else "any")
            if field is None:
                continue        # empty port set (e.g. "lt 1") matches nothing
            for s, d, fam in pairs:
                combos.append((s, d, proto, field, fam))
    return {"combos": combos, "inactive": inactive}


def _parse_port_items(tokens: list, stats):
    """'eq 22' / 'range 1 2' / '' -> ranges | None | unknown-str."""
    ports, _ = _consume_port_op(tokens, 0, stats)
    if ports is _NOT_PRESENT:
        return None
    return ports


def _parse_service_spec(tokens: list, stats):
    """
    Parse '<proto> [source <op..>] [destination <op..>]' or
    '<proto> [<op..>]' (IOS object-group service / ASA service-object).
    Returns (proto, ports) where ports is ranges | None | unknown-str.
    """
    if not tokens:
        return None
    proto = _norm_protocol(tokens[0])
    rest = tokens[1:]
    if proto not in _PORTED_PROTOCOLS:
        return (proto, None)
    ports = None
    i = 0
    while i < len(rest):
        if rest[i] == "source":
            _sp, i = _consume_port_op(rest, i + 1, stats)
            if _sp is _NOT_PRESENT:
                i += 1
            continue
        if rest[i] == "destination":
            i += 1
        p, j = _consume_port_op(rest, i, stats)
        if p is _NOT_PRESENT:
            i += 1
            continue
        ports = p
        i = j
    return (proto, ports)


def _object_child(ctx: tuple, toks: list, objs: _CiscoObjects, stats) -> None:
    """Handle one line inside an object / object-group definition."""
    ctype, name = ctx[1], ctx[2]
    head = toks[0]
    if head == "description":
        return
    if ctype == "object-network":
        lst = objs.net_objects.setdefault(name, [])
        if head == "host" and len(toks) > 1:
            _check_ip(toks[1])
            lst.append(toks[1])
        elif head == "subnet" and len(toks) > 2:
            lst.append(_addr_with_mask(toks[1], toks[2], "netmask"))
        elif head == "subnet" and len(toks) == 2:
            lst.append(_norm_addr(toks[1]))
        elif head == "range" and len(toks) > 2:
            lst.extend(_range_cidrs(toks[1], toks[2], strict=True))
        elif head == "fqdn":
            lst.append(f"fqdn:{toks[-1]}")
        elif head == "nat":
            objs.object_nats.append((name, toks))
        return
    if ctype == "object-service":
        if head == "service":
            spec = _parse_service_spec(toks[1:], stats)
            if spec:
                objs.svc_objects.setdefault(name, []).append(spec)
        return
    if ctype == "network":
        lst = objs.net_groups.setdefault(name, [])
        if head == "network-object":
            toks = toks[1:]
            if not toks:
                return
            head = toks[0]
            if head == "object" and len(toks) > 1:
                lst.append(("object", toks[1]))
                return
        if head == "group-object" and len(toks) > 1:
            lst.append(("group", toks[1]))
        elif head == "host" and len(toks) > 1:
            _check_ip(toks[1])
            lst.append(("addr", toks[1]))
        elif head == "range" and len(toks) > 2:
            lst.extend(("addr", c) for c in _range_cidrs(toks[1], toks[2], strict=True))
        elif head == "any":
            lst.append(("addr", "any"))
        elif _IP_RE.match(head) and len(toks) > 1 and _IP_RE.match(toks[1]):
            lst.append(("addr", _addr_with_mask(head, toks[1], "netmask")))
        elif "/" in head or _IP_RE.match(head) or ":" in head:
            try:
                net = ipaddress.ip_network(head, strict=False)
                lst.append(("addr", _cidr(str(net.network_address), net.prefixlen)))
            except ValueError:
                _check_ip(head)
                lst.append(("addr", head))
        return
    if ctype == "service":          # no protocol on header: service-objects / IOS entries
        lst = objs.svc_groups.setdefault(name, [])
        if head == "group-object" and len(toks) > 1:
            lst.append(("group", toks[1]))
        elif head == "service-object":
            if len(toks) > 2 and toks[1] == "object":
                lst.append(("object", toks[2]))
            else:
                spec = _parse_service_spec(toks[1:], stats)
                if spec:
                    lst.append(("svc", spec[0], spec[1]))
        elif head == "port-object":
            # port-object without protocol on header: ambiguous, treat tcp-udp
            lst.append(("svc", "tcp-udp", _parse_port_items(toks[1:], stats)))
        else:
            spec = _parse_service_spec(toks, stats)
            if spec:
                lst.append(("svc", spec[0], spec[1]))
        return
    if ctype == "port":
        lst = objs.port_groups.setdefault(name, [])
        if head == "port-object":
            lst.append(("ports", _parse_port_items(toks[1:], stats)))
        elif head == "group-object" and len(toks) > 1:
            lst.append(("group", toks[1]))
        return
    if ctype == "protocol":
        lst = objs.proto_groups.setdefault(name, [])
        if head == "protocol-object" and len(toks) > 1:
            lst.append(("proto", _norm_protocol(toks[1])))
        elif head == "group-object" and len(toks) > 1:
            lst.append(("group", toks[1]))
        return


def _parse_cisco(text: str, stats: Optional[dict] = None) -> tuple:
    """
    One pass over a Cisco IOS / ASA config. Returns (rules, nat_rows);
    see parse_cisco_acl / parse_cisco_nat.
    """
    if stats is None:
        stats = _new_stats()
    objs = _CiscoObjects()
    pending: list = []           # (acl, kind, mask_kind, body, raw, families, seq)
    # ("acl", name, kind, mask, families) | ("obj", type, name) | ("iface", name)
    ctx: Optional[tuple] = None
    bindings: dict = {}          # acl -> {"in": [iface], "out": [iface]}
    acl_pos: dict = {}           # acl -> ACE count (positional policy_id)
    nat_lines: list = []         # ("ios" | "asa", tokens, raw)
    nat_pools: dict = {}         # ip nat pool NAME -> tokens
    nat_outside: list = []       # interfaces with `ip nat outside`

    def _bind(acl: str, direction: str, iface: str) -> None:
        d = bindings.setdefault(acl, {"in": [], "out": []})
        if iface not in d[direction]:
            d[direction].append(iface)
            _bump(stats, "acl_bindings")

    remarks: dict = {}           # acl -> remark text preceding the next ACE (MV-04)

    def _add(acl, kind, mask, body, raw, fams, seq):
        if acl is not None:
            acl_pos[acl] = acl_pos.get(acl, 0) + 1
            if seq is None:
                seq = str(acl_pos[acl])
            rm_ = remarks.pop(acl, None)
            if rm_:
                raw = f"{raw}  ! remark: {rm_}"
        pending.append((acl, kind, mask, body, raw, fams, seq))

    for raw_line in text.splitlines():
        s = raw_line.strip()
        if not s or s.startswith("!") or s.startswith("#"):
            continue
        indented = raw_line[:1] in (" ", "\t")
        toks = s.split()
        head = toks[0].lower()

        # ------------------------------------------ interface children --
        if ctx is not None and ctx[0] == "iface":
            if indented:
                if (head in ("ip", "ipv6") and len(toks) >= 4
                        and toks[1] in ("access-group", "traffic-filter")
                        and toks[3] in ("in", "out")):
                    _bind(toks[2], toks[3], ctx[1])
                elif head == "ip" and toks[1:3] == ["nat", "outside"]:
                    nat_outside.append(ctx[1])
                continue
            ctx = None

        # ---------------------------------------------------- headers --
        if head == "interface" and len(toks) > 1 and not indented:
            ctx = ("iface", " ".join(toks[1:]))
            continue
        if head == "access-group" and len(toks) >= 3:
            # ASA: access-group ACL in|out interface NAMEIF  (| global: no zone)
            if len(toks) >= 5 and toks[2] in ("in", "out") and toks[3] == "interface":
                _bind(toks[1], toks[2], toks[4])
            ctx = None
            continue
        if head == "ip" and len(toks) > 3 and toks[1] == "nat":
            if toks[2] == "pool":
                nat_pools[toks[3]] = toks[4:]
            elif toks[2] == "inside" and toks[3] == "source":
                nat_lines.append(("ios", toks, s))
            ctx = None
            continue
        if head == "nat" and not indented and len(toks) > 2 and toks[1].startswith("("):
            nat_lines.append(("asa", toks, s))     # ASA twice NAT
            ctx = None
            continue
        if head == "ipv6" and len(toks) > 2 and toks[1] == "access-list":
            name, rest = toks[2], toks[3:]
            if name in ("log-update", "resequence"):
                ctx = None
                continue
            if rest[:1] == ["line"] and len(rest) > 2:
                rest = rest[2:]
            if rest and rest[0] in ("permit", "deny"):     # ASA 8.x one-line v6 ACE
                _add(name, "extended", "netmask", rest, s, (6,), None)
                ctx = None
                continue
            ctx = ("acl", name, "extended", "wildcard", (6,))
            continue
        if head == "ip" and len(toks) > 2 and toks[1] == "access-list":
            if toks[2] in ("extended", "standard") and len(toks) > 3:
                ctx = ("acl", toks[3], toks[2], "wildcard", (4,))
            elif toks[2] in ("resequence", "logging", "log-update"):
                ctx = None
            else:
                ctx = ("acl", toks[2], "extended", "wildcard", (4,))   # NX-OS style
            continue
        if head == "object-group" and len(toks) > 2:
            gtype, gname = toks[1], toks[2]
            if gtype == "service" and len(toks) > 3 and toks[3] in ("tcp", "udp", "tcp-udp"):
                ctx = ("obj", "port", gname)
                objs.port_groups.setdefault(gname, [])
            elif gtype in ("network", "service", "protocol"):
                ctx = ("obj", gtype, gname)
                {"network": objs.net_groups, "service": objs.svc_groups,
                 "protocol": objs.proto_groups}[gtype].setdefault(gname, [])
            else:
                ctx = ("obj", "other", gname)
                objs.other_groups.add(gname)
            continue
        if head == "object" and len(toks) > 2 and toks[1] in ("network", "service"):
            ctx = ("obj", f"object-{toks[1]}", toks[2])
            if toks[1] == "network":
                objs.net_objects.setdefault(toks[2], [])
            else:
                objs.svc_objects.setdefault(toks[2], [])
            continue
        if head == "access-list" and len(toks) > 2:
            ctx = None
            name = toks[1]
            rest = toks[2:]
            seq = None
            if rest[0] == "line" and len(rest) > 2:
                seq = rest[1]
                rest = rest[2:]
            if rest[0] == "remark":
                remarks[name] = " ".join(rest[1:])[:200]
                continue
            if name.isdigit():
                n = int(name)
                kind = "standard" if (1 <= n <= 99 or 1300 <= n <= 1999) else "extended"
                mask_kind = "wildcard"
                if rest[0] == "dynamic" and len(rest) > 2:
                    rest = rest[2:]
                    while rest and rest[0] in ("timeout",):
                        rest = rest[2:]
            else:
                mask_kind = "netmask"        # ASA
                if rest[0] in ("extended", "standard"):
                    kind = rest[0]
                    rest = rest[1:]
                elif rest[0] in ("webtype", "ethertype"):
                    continue
                else:
                    kind = "auto"
            if rest and rest[0] in ("permit", "deny"):
                _add(name, kind, mask_kind, rest, s, (4,), seq)
            continue

        # --------------------------------------------- context children --
        if ctx is not None and ctx[0] == "obj":
            if indented or head in (
                    "host", "network-object", "group-object", "port-object",
                    "service-object", "protocol-object", "subnet", "range",
                    "description", "service", "fqdn", "icmp-object"):
                try:
                    _object_child(ctx, toks, objs, stats)
                except (ValueError, IndexError, TypeError) as e:
                    _reject(stats, s, e)       # A-18: skip the bad member only
                continue
            ctx = None

        body = toks
        seq = None
        if body and body[0].isdigit() and len(body) > 1:
            seq, body = body[0], body[1:]            # IOS sequence number
        elif len(body) > 2 and body[0] == "sequence" and body[1].isdigit():
            seq, body = body[1], body[2:]            # IOS ipv6 access-list
        is_ace = bool(body) and body[0] in ("permit", "deny")
        is_remark = bool(body) and body[0] == "remark"

        if ctx is not None and ctx[0] == "acl":
            if is_remark:
                remarks[ctx[1]] = " ".join(body[1:])[:200]
                continue
            if is_ace:
                _add(ctx[1], ctx[2], ctx[3], body, s, ctx[4], seq)
                continue
            if indented:
                continue                          # statistics per-entry etc.
            ctx = None

        if is_remark:
            continue
        if is_ace:
            # Bare ACE outside any ACL header (pasted fragment)
            pending.append((None, "auto", "wildcard", body, s, (4,), seq))

    rules = []
    order = 0
    for acl, kind, mask_kind, body, raw, fams, seq in pending:
        action = "permit" if body[0] == "permit" else "deny"
        try:
            parsed = _parse_ace(body[1:], kind, objs, mask_kind, stats, fams)
        except (ValueError, IndexError, TypeError) as e:
            _reject(stats, raw, e)             # A-18: skip this ACE, keep the upload
            continue
        if parsed is None or not parsed["combos"]:
            continue
        # ASA `inactive` ACEs enforce nothing; keep them flagged (enabled=False)
        # so they can be reported for removal (3.8 / SR 7.7).
        enabled = not parsed["inactive"]
        order += 1
        variants = [(None, None)]
        b = bindings.get(acl) if acl else None
        if b and (b["in"] or b["out"]):
            variants = []
            if b["in"]:
                variants.append((",".join(b["in"]), None))
            if b["out"]:
                variants.append((None, ",".join(b["out"])))
        if len(variants) > 1:   # B-08: in+out bindings duplicate every row
            charge_rule_rows((len(variants) - 1) * len(parsed["combos"]), raw)
        for src_zone, dst_zone in variants:
            for src, dst, proto, port, _fam in parsed["combos"]:
                rules.append({
                    "device_name": acl,
                    # MV-04: policy_id = "<acl>:<ACE position / IOS sequence>"
                    # so every entry has its own identity in paths and
                    # findings; syslog rule hits still match on the ACL name
                    # (policy_name) and ACE order (rule_order).
                    "policy_id": _ace_id(acl, seq),
                    "policy_name": acl,
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "dst_port": port,
                    "action": action,
                    "raw_line": raw,
                    "rule_order": order,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "enabled": enabled,
                })
        if any(c[4] == 6 for c in parsed["combos"]):
            _bump(stats, "rules_ipv6")
        if not enabled:
            _bump(stats, "rules_disabled")

    nats = _cisco_nat_rows(nat_lines, nat_pools, nat_outside, objs, rules, stats)
    return _finalize_rows(rules), nats


def _cisco_port(tok: Optional[str]) -> str:
    if not tok:
        return "any"
    n = _port_value(tok, None)
    return canonical_ports([(n, n)]) if n is not None else f"unknown:{tok}"


def _cisco_nat_rows(nat_lines, nat_pools, nat_outside, objs, rules, stats) -> list:
    """Normalise IOS `ip nat inside source ...` and ASA object / twice NAT."""
    out: list = []
    outside = ",".join(nat_outside) or None

    def _acl_sources(acl: str) -> list:
        srcs = []
        for r in rules:
            if r["policy_name"] == acl and r["action"] == "permit" and r["src"] not in srcs:
                srcs.append(r["src"])
        return srcs or [f"acl:{acl}"]

    def _pool(name: str) -> str:
        v = nat_pools.get(name) or []
        if len(v) >= 2 and _IP_RE.match(v[0]) and _IP_RE.match(v[1]):
            _check_ip(v[0])
            _check_ip(v[1])
            return _nat_range(v[0], v[1])
        return f"pool:{name}"

    def _asa_addr(tok: str, mapped_if: Optional[str] = None) -> list:
        if tok in _ANY_TOKENS:
            return ["any"]
        if tok == "interface":
            return [f"interface:{mapped_if}"]
        if tok in objs.net_objects:
            return objs.net_objects[tok] or [f"object:{tok}"]
        if tok in objs.net_groups:
            return objs.resolve_net_group(tok, stats)
        _check_ip(tok)
        if addr_family(tok):
            return [tok]
        return [f"object:{tok}"]

    def _one_nat_line(kind, toks, raw):
        if kind == "ios":
            rest = toks[4:]
            if not rest:
                return
            if rest[0] == "static":
                r = rest[1:]
                proto = "any"
                if r and r[0] in ("tcp", "udp"):
                    proto, r = r[0], r[1:]
                if r and r[0] == "network" and len(r) >= 3:
                    mask = r[3] if len(r) > 3 else "/32"
                    pfx = int(mask[1:]) if mask.startswith("/") else (
                        _mask_prefix(mask, "netmask") or 32)
                    local = f"{r[1]}/{pfx}"
                    glob = f"{r[2]}/{pfx}"
                    lport = gport = None
                else:
                    if not r:
                        return
                    local, i, lport = r[0], 1, None
                    if proto != "any" and i < len(r):
                        lport, i = r[i], i + 1
                    if i < len(r) and r[i] == "interface" and i + 1 < len(r):
                        glob, i = f"interface:{r[i + 1]}", i + 2
                    elif i < len(r):
                        glob, i = r[i], i + 1
                    else:
                        return
                    gport = r[i] if proto != "any" and i < len(r) else None
                _check_ip(local)
                if not glob.startswith("interface:"):
                    _check_ip(glob)
                out.append(nat_row(
                    "dnat", name="static", protocol=proto, src_intf=outside,
                    ext_ip=_nat_addr(glob), ext_port=_cisco_port(gport),
                    mapped_ip=_nat_addr(local), mapped_port=_cisco_port(lport),
                    raw=raw))
            elif rest[0] in ("list", "route-map") and len(rest) > 1:
                ref = rest[1]
                srcs = _acl_sources(ref) if rest[0] == "list" else [f"route-map:{ref}"]
                mapped = None
                if "interface" in rest:
                    j = rest.index("interface")
                    if j + 1 < len(rest):
                        mapped = f"interface:{rest[j + 1]}"
                elif "pool" in rest:
                    j = rest.index("pool")
                    if j + 1 < len(rest):
                        mapped = _pool(rest[j + 1])
                for src in srcs:
                    out.append(nat_row(
                        "snat", name=ref, orig_src=_nat_addr(src),
                        mapped_ip=mapped, raw=raw))
            return

        # ASA twice NAT: nat (real,mapped) [after-auto] source static|dynamic REAL MAPPED
        #                [destination static MAPPED_DST REAL_DST] ...
        ifs = toks[1].strip("()").split(",")
        real_if = ifs[0] or None
        mapped_if = ifs[1] if len(ifs) > 1 else None
        enabled = "inactive" not in toks
        if "source" not in toks:
            return
        j = toks.index("source")
        if len(toks) < j + 4:
            return
        mode, real, mapped = toks[j + 1], toks[j + 2], toks[j + 3]
        if "destination" in toks:
            k = toks.index("destination")
            if len(toks) > k + 3:
                for ext in _asa_addr(toks[k + 2], mapped_if):
                    for inner in _asa_addr(toks[k + 3], mapped_if):
                        out.append(nat_row(
                            "dnat", name="twice-nat", src_intf=mapped_if,
                            ext_ip=_nat_addr(ext), ext_port="any",
                            mapped_ip=_nat_addr(inner), mapped_port="any",
                            enabled=enabled, raw=" ".join(toks)))
                return
        mapped_addrs = _asa_addr(mapped, mapped_if)
        for r in _asa_addr(real, mapped_if):
            if mode == "dynamic":
                out.append(nat_row(
                    "snat", name="twice-nat", src_intf=real_if,
                    orig_src=_nat_addr(r),
                    mapped_ip=",".join(_nat_addr(m) for m in mapped_addrs),
                    enabled=enabled, raw=" ".join(toks)))
            else:
                for m in mapped_addrs:
                    out.append(nat_row(
                        "dnat", name="twice-nat", src_intf=mapped_if,
                        ext_ip=_nat_addr(m), ext_port="any",
                        mapped_ip=_nat_addr(r), mapped_port="any",
                        enabled=enabled, raw=" ".join(toks)))


    # ASA object NAT: object network X / nat (real,mapped) static|dynamic MAPPED
    def _one_object_nat(objname, toks):
        if len(toks) < 4 or not toks[1].startswith("("):
            return
        ifs = toks[1].strip("()").split(",")
        real_if = ifs[0] or None
        mapped_if = ifs[1] if len(ifs) > 1 else None
        mode, mapped = toks[2], toks[3]
        reals = objs.net_objects.get(objname) or [f"object:{objname}"]
        mapped_addrs = _asa_addr(mapped, mapped_if)
        proto, rport, mport = "any", None, None
        if "service" in toks:
            k = toks.index("service")
            if len(toks) > k + 3:
                proto, rport, mport = toks[k + 1], toks[k + 2], toks[k + 3]
        raw = f"object network {objname} / {' '.join(toks)}"
        for r in reals:
            if mode == "dynamic":
                out.append(nat_row(
                    "snat", name=objname, src_intf=real_if, orig_src=_nat_addr(r),
                    mapped_ip=",".join(_nat_addr(m) for m in mapped_addrs), raw=raw))
            elif mode == "static":
                for m in mapped_addrs:
                    out.append(nat_row(
                        "dnat", name=objname, protocol=proto, src_intf=mapped_if,
                        ext_ip=_nat_addr(m), ext_port=_cisco_port(mport),
                        mapped_ip=_nat_addr(r), mapped_port=_cisco_port(rport),
                        raw=raw))

    for kind, toks, raw in nat_lines:
        try:
            _one_nat_line(kind, toks, raw)
        except (ValueError, IndexError, TypeError) as e:
            _reject(stats, raw, e, "nat_lines_rejected")

    for objname, toks in objs.object_nats:
        try:
            _one_object_nat(objname, toks)
        except (ValueError, IndexError, TypeError) as e:
            _reject(stats, f"object network {objname} / {' '.join(toks)}", e,
                    "nat_lines_rejected")
    return out



def _ace_id(acl: Optional[str], seq) -> Optional[str]:
    """``<acl>:<sequence / position>`` within the 32-char policy_id column.
    A long ACL name is shortened to a prefix plus a hash of the full name,
    so two long names never collide and the sequence is always kept."""
    if not acl or not seq:
        return None
    pid = f"{acl}:{seq}"
    if len(pid) <= 32:
        return pid
    keep = max(1, 32 - len(str(seq)) - 6)       # "~" + 4 hex + ":"
    return f"{acl[:keep]}~{hashlib.sha1(acl.encode()).hexdigest()[:4]}:{seq}"


def parse_cisco_acl(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    Parse Cisco IOS and ASA access lists.

    Supported:
      * IOS named ACLs (`ip access-list extended|standard NAME`, NX-OS
        `ip access-list NAME`) with or without sequence numbers
      * IOS numbered ACLs (`access-list 10 ...` standard, `access-list 101
        ...` extended)
      * ASA `access-list NAME [line N] extended|standard ...`
      * IOS `ipv6 access-list NAME` (incl. `sequence N`), ASA any6 / IPv6
        entries: stored as IPv6 rows (F-07, see module docstring)
      * IOS/ASA object-groups (network, service, protocol) and ASA
        `object network|service` definitions, expanded into one row per
        src x dst x service (all rows share rule_order)
      * wildcard vs netmask detection, `remark`, `log`, `established`,
        `time-range`, ASA `inactive` (stored with enabled=False)
      * `interface X / ip access-group ACL in|out` and ASA `access-group
        ACL in|out interface N` -> src_zone (in) / dst_zone (out)
    """
    return _parse_cisco(text, stats)[0]


def parse_cisco_nat(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    NAT from a Cisco config (F-05):
      IOS `ip nat inside source static [tcp|udp] LOCAL [LPORT] GLOBAL|interface IF [GPORT]`
          -> dnat (ext = global, mapped = local; src_intf = `ip nat outside` interfaces)
      IOS `ip nat inside source list ACL|route-map RM interface IF|pool P [overload]`
          -> snat, one row per permitted source of the ACL
      ASA object NAT `object network X / nat (real,mapped) static|dynamic MAPPED
          [service tcp|udp REAL MAPPED]` and basic twice NAT
          `nat (real,mapped) source static|dynamic REAL MAPPED [destination static MD RD]`.
    """
    return _parse_cisco(text, stats)[1]


# =============================================================== pfSense ==

def _looks_like_address(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def _pf_aliases(root: ET.Element) -> dict:
    aliases = _MemoDict()
    for a in root.findall(".//aliases/alias"):
        name = (a.findtext("name") or "").strip()
        if name:
            aliases[name] = {
                "type": (a.findtext("type") or "").strip().lower(),
                "items": (a.findtext("address") or "").split(),
            }
    return aliases


def _pf_resolve_addr(value: str, aliases: dict, stats=None, _seen=frozenset(),
                     _memo=None) -> list:
    if _looks_like_address(value):
        net = ipaddress.ip_network(value, strict=False)
        return [_cidr(str(net.network_address), net.prefixlen) if "/" in value else value]
    m = re.match(r"^(\d[\d.]+)-(\d[\d.]+)$", value)
    if m:
        return _range_cidrs(m.group(1), m.group(2))
    if value in aliases and aliases[value]["type"] in ("host", "network"):
        memo = _memo or _memo_of(aliases)
        key = ("a", value)
        if key in memo.data:
            if memo.data[key]:
                return list(memo.data[key])
        elif value in _seen:
            memo.cycles += 1            # cycle -> falls through to alias token
        elif len(_seen) >= MAX_GROUP_DEPTH:
            memo.cycles += 1
            return [_group_over(stats, value, f"nesting deeper than {MAX_GROUP_DEPTH}")]
        else:
            c0 = memo.cycles
            out = []
            for item in aliases[value]["items"]:
                out.extend(_pf_resolve_addr(item, aliases, stats, _seen | {value}, memo))
            out = _memo_store(memo, key, out, c0, stats, value)
            if out:
                return out
    if value not in aliases and re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$", value):
        return [f"fqdn:{value}"]
    _bump(stats, "unresolved_object_groups")
    return [f"alias:{value}"]


def _pf_resolve_ports(value: str, aliases: dict, stats, _seen=frozenset(), _memo=None):
    """pfSense port field -> ranges | 'alias:NAME' | 'too-large:NAME'."""
    ranges = _parse_port_text(value, "-:")
    if ranges is not None:
        return ranges
    if value in aliases and value not in _seen and aliases[value]["type"] == "port":
        memo = _memo or _memo_of(aliases)
        key = ("p", value)
        if key in memo.data:
            v = memo.data[key]
            return list(v) if isinstance(v, list) else v
        if len(_seen) >= MAX_GROUP_DEPTH:
            memo.cycles += 1
            return _group_over(stats, value, f"nesting deeper than {MAX_GROUP_DEPTH}")
        c0 = memo.cycles
        out = []
        result = None
        for item in aliases[value]["items"]:
            sub = _pf_resolve_ports(item, aliases, stats, _seen | {value}, memo)
            if isinstance(sub, str):
                result = sub
                break
            out.extend(sub)
            if len(out) > 64:
                out = _merge_ranges(out)
        else:
            result = _merge_ranges(out) if out else []
        if memo.cycles == c0:
            memo.data[key] = result
        return list(result) if isinstance(result, list) else result
    if value in _seen:
        (_memo or _memo_of(aliases)).cycles += 1
    _bump(stats, "unresolved_object_groups")
    return f"alias:{value}"


def _pf_endpoint(elem: Optional[ET.Element], aliases: dict, stats=None, nets=None) -> tuple:
    """Return (addresses, orig_text, negated).  ``nets``: interface macros
    ({'lan': '10.50.0.0/16', 'lanip': '10.50.0.1/32'}, MV-06)."""
    if elem is None:
        return ["any"], "any", False
    negated = elem.find("not") is not None
    if elem.find("any") is not None:
        return ["any"], "any", negated
    addr = (elem.findtext("address") or "").strip()
    if addr:
        return _pf_resolve_addr(addr, aliases, stats), addr, negated
    net = (elem.findtext("network") or "").strip()
    if net:
        nets = nets or {}
        if net in nets:
            return [nets[net]], f"network:{net}", negated
        if net == "(self)":
            own = [v for k, v in nets.items() if k.endswith("ip")]
            if own:
                return own, "network:(self)", negated
        return [f"network:{net}"], f"network:{net}", negated
    return ["any"], "any", negated


_PF_FAMILIES = {"inet": (4,), "inet6": (6,), "inet46": (4, 6)}


def parse_pfsense_xml(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    Parse pfSense config.xml <filter><rule> entries. Rule <type> maps
    pass -> permit, block/reject -> deny; match (A-08, no allow/block
    effect) and unknown types are skipped and counted. Floating rules get a
    quick / non-quick (last-match) note in raw_line. A missing <protocol> tag means
    all protocols ("any"); "tcp/udp" is emitted as one row per protocol.
    Host/network/port aliases are resolved from <aliases>; unresolved
    aliases are stored as "alias:NAME". `<disabled/>` rules are stored
    with enabled=False, `<not/>` endpoints follow the conservative negation
    policy. <ipprotocol> inet6 / inet46 rules produce IPv6 rows (F-07).
    Identity: policy_id = <tracker>, policy_name = <descr>, src_zone =
    <interface> (floating rules: per <direction>).
    """
    if stats is None:
        stats = _new_stats()
    root = _safe_ET.fromstring(text)
    aliases = _pf_aliases(root)
    from app.parsers.fw_interfaces import pfsense_iface_nets
    nets = pfsense_iface_nets(text)
    rules = []
    order = 0

    for rule in root.findall(".//filter/rule"):
        # <disabled/> rules are stored with enabled=False (flagged for removal).
        enabled = rule.find("disabled") is None
        ipproto = (rule.findtext("ipprotocol") or "inet").strip().lower()
        families = _PF_FAMILIES.get(ipproto, (4,))
        rule_type = (rule.findtext("type") or "block").strip().lower()
        notes = []
        if rule_type == "pass":
            action = "permit"
        elif rule_type in ("block", "reject"):
            action = "deny"
            if rule_type == "reject":
                notes.append("pfSense reject (deny with RST/ICMP unreachable)")
        elif rule_type == "match":
            # A-08: floating "match" rules only apply queues/limiters; no
            # allow/block effect -> must not become a deny.
            _bump(stats, "rules_skipped_match")
            continue
        else:
            _bump(stats, "rules_skipped_unknown_action")
            log.warning("pfSense rule with unknown <type> %r skipped", rule_type)
            continue
        protocol_raw = (rule.findtext("protocol") or "any").strip().lower()
        protocols = protocol_raw.split("/") if protocol_raw else ["any"]

        srcs, src_orig, src_neg = _pf_endpoint(rule.find("source"), aliases, stats, nets)
        dsts, dst_orig, dst_neg = _pf_endpoint(rule.find("destination"), aliases, stats, nets)
        if src_neg or dst_neg:
            if action == "deny" and enabled:
                _bump(stats, "rules_skipped_negated_deny")
                continue
            if src_neg:
                srcs = ["any"]
                notes.append(f"negated src: {src_orig}")
            if dst_neg:
                dsts = ["any"]
                notes.append(f"negated dst: {dst_orig}")

        port_raw = (rule.findtext("destination/port") or "").strip()
        ports = _pf_resolve_ports(port_raw, aliases, stats) if port_raw else None

        descr = (rule.findtext("descr") or "").strip() or None
        interface = (rule.findtext("interface") or "").strip() or None
        device_name = descr or interface
        tracker = (rule.findtext("tracker") or "").strip() or None
        src_zone = dst_zone = None
        floating = rule.find("floating") is not None and (
            (rule.findtext("floating") or "yes").strip().lower() in ("yes", ""))
        if floating:
            # pf: floating rules without <quick> are LAST-match (a later
            # interface rule overrides them); rows stay in config order and
            # the semantics are flagged for the reviewer.
            quick = rule.find("quick") is not None and (
                (rule.findtext("quick") or "yes").strip().lower() in ("yes", ""))
            notes.append("floating quick (first match)" if quick else
                         "floating non-quick: last-match, overridden by later matching rules")
            direction = (rule.findtext("direction") or "any").strip().lower()
            if direction == "in":
                src_zone = interface
            elif direction == "out":
                dst_zone = interface
        else:
            src_zone = interface
        raw = _note(ET.tostring(rule, encoding="unicode").strip(), notes)

        if isinstance(ports, list) and len(ports) > MAX_GROUP_MEMBERS:
            ports = _group_over(stats, port_raw, f"{len(ports)} port ranges")
        srcs, dsts = _cap_rule([(srcs, src_orig, str), (dsts, dst_orig, str)],
                               stats, tracker or descr or src_orig,
                               factor=len(protocols))
        pairs = _pair_families(srcs, dsts, families, stats, restrict=True)
        rows = []
        for proto in protocols:
            proto = _norm_protocol(proto) if proto != "any" else "any"
            if proto == "icmp6":
                proto = "ipv6-icmp"
            if proto in ("tcp", "udp", "sctp"):
                field = _ports_field(ports)
            else:
                field = "any"
            if field is None:
                continue
            for s, d, fam in pairs:
                rows.append({
                    "device_name": device_name,
                    "policy_id": tracker,
                    "policy_name": descr,
                    "src": s,
                    "dst": d,
                    "protocol": proto,
                    "dst_port": field,
                    "action": action,
                    "raw_line": raw,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "enabled": enabled,
                    "_fam": fam,
                })
        if rows:
            if not enabled:
                _bump(stats, "rules_disabled")
            if any(r["_fam"] == 6 for r in rows):
                _bump(stats, "rules_ipv6")
            order += 1
            for r in rows:
                r["rule_order"] = order
                del r["_fam"]
            rules.extend(rows)

    return _finalize_rows(rules)


def _pf_nat_target(value: str, aliases: dict, stats) -> str:
    vals = _pf_resolve_addr(value, aliases, stats) if value else []
    return ",".join(_nat_addr(v) for v in vals) if vals else "any"


def _pf_nat_endpoint(elem: Optional[ET.Element], aliases: dict, stats) -> list:
    if elem is None or elem.find("any") is not None:
        return ["any"]
    addr = (elem.findtext("address") or "").strip()
    if addr:
        return [_nat_addr(v) for v in _pf_resolve_addr(addr, aliases, stats)]
    net = (elem.findtext("network") or "").strip()
    if net:
        # "wanip" / "lanip" = the interface address; "lan" = its subnet
        return [f"interface:{net[:-2]}" if net.endswith("ip") else f"network:{net}"]
    return ["any"]


def parse_pfsense_nat(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    pfSense NAT (F-05):
      <nat><rule>              port forward -> dnat (ext = destination
                               address[:destination/port], mapped = <target>
                               [:<local-port>], src_intf = <interface>)
      <nat><outbound><rule>    outbound NAT -> snat (orig_src = <source>,
                               mapped = <target> / <targetip> or
                               "interface:<interface>"); <nonat/> rules
                               (do-not-NAT exclusions) are skipped.
    tcp/udp rules give one row per protocol; <disabled/> -> enabled=False.
    """
    if stats is None:
        stats = _new_stats()
    root = _safe_ET.fromstring(text)
    aliases = _pf_aliases(root)
    out = []
    for rule in root.findall(".//nat/rule"):
        enabled = rule.find("disabled") is None
        iface = (rule.findtext("interface") or "").strip() or None
        proto_raw = (rule.findtext("protocol") or "any").strip().lower()
        protos = proto_raw.split("/") if proto_raw else ["any"]
        ext_port_raw = (rule.findtext("destination/port") or "").strip()
        ext_ranges = _pf_resolve_ports(ext_port_raw, aliases, stats) if ext_port_raw else None
        local_raw = (rule.findtext("local-port") or "").strip()
        ext_field = _ports_field(ext_ranges) or "any"
        mapped_field = ext_field
        if local_raw:
            lr = _parse_port_text(local_raw, "-:")
            if lr and isinstance(ext_ranges, list) and len(ext_ranges) == 1:
                lo, hi = ext_ranges[0]
                mapped_field = canonical_ports([(lr[0][0], lr[0][0] + (hi - lo))])
            elif lr:
                mapped_field = canonical_ports(lr)
        target = _pf_nat_target((rule.findtext("target") or "").strip(), aliases, stats)
        descr = (rule.findtext("descr") or "").strip() or None
        raw = ET.tostring(rule, encoding="unicode").strip()
        for ext in _pf_nat_endpoint(rule.find("destination"), aliases, stats):
            for p in protos:
                p = _norm_protocol(p) if p != "any" else "any"
                ported = p in ("tcp", "udp", "sctp")
                out.append(nat_row(
                    "dnat", name=descr, protocol=p, src_intf=iface,
                    ext_ip=ext, ext_port=ext_field if ported else "any",
                    mapped_ip=target, mapped_port=mapped_field if ported else "any",
                    enabled=enabled, raw=raw))
    for rule in root.findall(".//nat/outbound/rule"):
        if rule.find("nonat") is not None:
            continue
        enabled = rule.find("disabled") is None
        iface = (rule.findtext("interface") or "").strip() or None
        src = rule.find("source")
        if src is not None and src.findtext("network"):
            origs = [_nat_addr(_norm_addr(src.findtext("network").strip()))]
        else:
            origs = _pf_nat_endpoint(src, aliases, stats)
        target = (rule.findtext("target") or "").strip()
        if target in ("", "wanip") or target.endswith("ip") and not addr_family(target):
            mapped = f"interface:{iface}"
        elif target == "other-subnet":
            tip = (rule.findtext("targetip") or "").strip()
            tsub = (rule.findtext("targetip_subnet") or "").strip()
            mapped = _nat_addr(f"{tip}/{tsub}" if tsub else tip) if tip else f"interface:{iface}"
        else:
            mapped = _pf_nat_target(target, aliases, stats)
        descr = (rule.findtext("descr") or "").strip() or None
        raw = ET.tostring(rule, encoding="unicode").strip()
        for o in origs:
            out.append(nat_row(
                "snat", name=descr, protocol=(rule.findtext("protocol") or "any").strip().lower() or "any",
                src_intf=iface, orig_src=o, mapped_ip=mapped, enabled=enabled, raw=raw))
    return out


# ============================================================= Palo Alto ==

_SERVICE_PORT_RE = re.compile(r"^(tcp|udp)-(\d+)(?:-(\d+))?$", re.IGNORECASE)

_PANOS_PREDEFINED_SERVICES = {
    "service-http": [("tcp", [(80, 80), (8080, 8080)])],
    "service-https": [("tcp", [(443, 443)])],
}

_PANOS_DENY_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}

#: MV-09: default ports of common App-IDs, used for `service application-default`
#: (owner decision: default ports, not "any").  Unknown applications keep
#: "any" and say so in the rule's raw line.
_PANOS_APP_DEFAULT_PORTS = {
    "ms-rdp": [("tcp", [(3389, 3389)]), ("udp", [(3389, 3389)])],
    "ssh": [("tcp", [(22, 22)])], "telnet": [("tcp", [(23, 23)])],
    "web-browsing": [("tcp", [(80, 80)])], "ssl": [("tcp", [(443, 443)])],
    "ftp": [("tcp", [(21, 21)])], "dns": [("udp", [(53, 53)]), ("tcp", [(53, 53)])],
    "ntp": [("udp", [(123, 123)])], "snmp": [("udp", [(161, 162)])],
    "ldap": [("tcp", [(389, 389)])], "kerberos": [("tcp", [(88, 88)]), ("udp", [(88, 88)])],
    "ms-ds-smb": [("tcp", [(445, 445)])], "smb": [("tcp", [(445, 445)])],
    "msrpc": [("tcp", [(135, 135)])], "mssql-db": [("tcp", [(1433, 1433)])],
    "mysql": [("tcp", [(3306, 3306)])], "oracle": [("tcp", [(1521, 1521)])],
    "smtp": [("tcp", [(25, 25)])], "syslog": [("udp", [(514, 514)])],
    "vnc": [("tcp", [(5900, 5900)])], "http-proxy": [("tcp", [(8080, 8080)])],
    "modbus": [("tcp", [(502, 502)])], "s7comm": [("tcp", [(102, 102)])],
    "siemens-s7": [("tcp", [(102, 102)])], "dnp3": [("tcp", [(20000, 20000)])],
    "iec-60870-5-104": [("tcp", [(2404, 2404)])], "bacnet": [("udp", [(47808, 47808)])],
    "opc-ua": [("tcp", [(4840, 4840)])], "ethernet-ip": [("tcp", [(44818, 44818)]), ("udp", [(2222, 2222)])],
    "cip-ethernet-ip": [("tcp", [(44818, 44818)])], "profinet": [("udp", [(34962, 34964)])],
    "mqtt": [("tcp", [(1883, 1883)])], "icmp": [("icmp", None)], "ping": [("icmp", None)],
}


def _panos_app_default(apps) -> tuple:
    """([(proto, port)], note) for `service application-default` on the
    rule's applications."""
    apps = [a for a in (apps or []) if a and a.lower() != "any"]
    if not apps:
        return [("any", "any")], "service application-default with application any: any service"
    out, unknown = [], []
    for a in apps:
        spec = _PANOS_APP_DEFAULT_PORTS.get(a.lower())
        if spec is None:
            unknown.append(a)
            continue
        for proto, ranges in spec:
            out.append((proto, canonical_ports(ranges) if ranges else "any"))
    if unknown:
        out.append(("any", "any"))
        return out, (f"service application-default: default ports of {', '.join(a for a in apps if a not in unknown)}; "
                     f"no port table for {', '.join(unknown)} (any service assumed)")
    return out, f"service application-default: default ports of {', '.join(apps)}"


def _panos_resolve_service(name: str, svc_objects: dict, svc_groups: dict,
                           stats, _seen=frozenset(), _memo=None) -> list:
    """
    Resolve a PAN-OS service reference to [(protocol, canonical_port, note)].
    """
    low = name.lower()
    if low == "any":
        return [("any", "any", None)]
    if low == "application-default":
        return [("any", "any", "service application-default: ports per App-ID")]
    memo = _memo or _memo_of(svc_groups)
    if name in _seen:
        memo.cycles += 1
        return []
    _seen = _seen | {name}
    if name in svc_objects:
        out = []
        for proto, ranges in svc_objects[name]:
            if isinstance(ranges, str):
                _bump(stats, "unknown_port_names")
                field = ranges
            elif ranges is None:
                field = "any"
            else:
                field = canonical_ports(ranges) or "any"
            out.append((proto, field, None))
        return out
    if name in svc_groups:
        if name in memo.data:
            return list(memo.data[name])
        if len(_seen) >= MAX_GROUP_DEPTH:
            memo.cycles += 1
            return [("any", _group_over(stats, name, f"nesting deeper than {MAX_GROUP_DEPTH}"), None)]
        c0 = memo.cycles
        out = []
        for m in svc_groups[name]:
            out.extend(_panos_resolve_service(m, svc_objects, svc_groups, stats, _seen, memo))
        return _memo_store(memo, name, out, c0, stats, name, lambda t: ("any", t, None))
    if low in _PANOS_PREDEFINED_SERVICES:
        return [(p, canonical_ports(r), None) for p, r in _PANOS_PREDEFINED_SERVICES[low]]
    match = _SERVICE_PORT_RE.match(name)
    if match:
        lo = int(match.group(2))
        hi = int(match.group(3)) if match.group(3) else lo
        return [(match.group(1).lower(), canonical_ports([(lo, hi)]), None)]
    _bump(stats, "unknown_port_names")
    return [("any", f"unknown:{name}", None)]


def _panos_port_ranges(text: Optional[str]):
    if not text:
        return None
    r = _parse_port_text(text.replace(" ", ""), "-")
    return r if r is not None else f"unknown:{text}"


def _panos_xml_services(root: ET.Element) -> tuple:
    svc_objects: dict = {}
    svc_groups: dict = _MemoDict()
    for entry in root.findall(".//service/entry"):
        name = entry.get("name")
        proto_el = entry.find("protocol")
        if not name or proto_el is None:
            continue
        specs = []
        for p in proto_el:
            proto = p.tag.lower()
            specs.append((proto, _panos_port_ranges(p.findtext("port"))))
        svc_objects[name] = specs
    for entry in root.findall(".//service-group/entry"):
        name = entry.get("name")
        if not name:
            continue
        members = [m.text for m in entry.findall("members/member") if m.text]
        members += [m.text for m in entry.findall("member") if m.text]
        svc_groups[name] = members
    return svc_objects, svc_groups


def _panos_members(entry: ET.Element, tag: str) -> list:
    el = entry.find(tag)
    if el is None:
        return ["any"]
    members = [m.text.strip() for m in el.findall("member") if m.text]
    return members or ["any"]


def _panos_literal(value: str) -> Optional[list]:
    """A literal address used directly in a rule: IP, CIDR or a-b range."""
    v = value.strip()
    if "-" in v:
        a, _, b = v.partition("-")
        if addr_family(a) and addr_family(b):
            return _range_cidrs(a.strip(), b.strip())
    if addr_family(v):
        return [_norm_addr(v)]
    return None


def _panos_addr_values(kind: str, value: Optional[str]) -> Optional[list]:
    """Normalise one PAN-OS <address><entry> definition."""
    if not value:
        return None
    value = value.strip()
    if kind == "ip-netmask":
        return [_norm_addr(value)]
    if kind == "ip-range":
        a, _, b = value.partition("-")
        return _range_cidrs(a.strip(), b.strip()) if b else [_norm_addr(a)]
    if kind == "fqdn":
        return [f"fqdn:{value}"]
    if kind == "ip-wildcard":
        ip, _, mask = value.partition("/")
        if _IP_RE.match(mask or ""):
            return [_addr_with_mask(ip, mask, "wildcard")]
        return [_norm_addr(value)]
    return None


class _PanAddressBook:
    """
    PAN-OS address objects and address groups keyed by scope: "shared",
    "vsys:NAME", "device-group:NAME" or "local" (set format without a
    scope prefix). Lookup order for a reference made in scope S: S, then
    shared, then any other scope (Panorama parent device-groups are not
    modelled; a name defined elsewhere in the same file is the best
    available match). Unknown names -> "object:NAME" (unresolved, counted).
    """

    _ADDR_KINDS = ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")

    def __init__(self):
        self.addrs: dict = {}     # scope -> {name: [values]}
        self.groups: dict = {}    # scope -> {name: ("static", [members]) | ("dynamic", filter)}
        self._memo = _Memo()     # A-02: resolved groups, keyed (name, scope)

    def add_address(self, scope: str, name: str, kind: str, value) -> None:
        vals = _panos_addr_values(kind, value)
        if vals is not None:
            self.addrs.setdefault(scope, {})[name] = vals

    def add_static(self, scope: str, name: str, members: list) -> None:
        g = self.groups.setdefault(scope, {})
        if name not in g or g[name][0] != "static":
            g[name] = ("static", [])
        g[name][1].extend(m for m in members if m)

    def add_dynamic(self, scope: str, name: str, flt: Optional[str]) -> None:
        self.groups.setdefault(scope, {})[name] = ("dynamic", flt)

    def _lookup(self, name: str, scope: str) -> tuple:
        others = sorted((set(self.addrs) | set(self.groups)) - {scope, "shared"})
        for sc in [scope, "shared"] + others:
            if name in self.addrs.get(sc, {}):
                return "addr", self.addrs[sc][name], sc
            if name in self.groups.get(sc, {}):
                return "group", self.groups[sc][name], sc
        return None, None, None

    def resolve(self, name: str, scope: str, stats, _seen=frozenset()) -> list:
        n = (name or "").strip()
        if n.lower() in ("any", ""):
            return ["any"]
        if n in _seen:
            self._memo.cycles += 1
            return []
        kind, val, sc = self._lookup(n, scope)
        if kind == "addr":
            return list(val)
        if kind == "group":
            if val[0] == "dynamic":
                _bump(stats, "dynamic_address_groups")
                return [f"dynamic-group:{n}"]
            memo = self._memo
            hit, c0 = _memo_enter(memo, (n, sc), frozenset(), stats, n)
            if hit is not None:
                return hit
            if len(_seen) >= MAX_GROUP_DEPTH:
                memo.cycles += 1
                return [_group_over(stats, n, f"nesting deeper than {MAX_GROUP_DEPTH}")]
            out: list = []
            for m in val[1]:
                out.extend(self.resolve(m, sc, stats, _seen | {n}))
            return _memo_store(memo, (n, sc), out, c0, stats, n)
        lit = _panos_literal(n)
        if lit is not None:
            return lit
        _bump(stats, "unresolved_object_groups")
        return [f"object:{n}"]


def _panos_xml_addresses(root: ET.Element, scope_of) -> _PanAddressBook:
    book = _PanAddressBook()
    for container in root.iter("address"):
        for entry in container.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            for kind in _PanAddressBook._ADDR_KINDS:
                if entry.find(kind) is not None:
                    book.add_address(scope_of(entry), name, kind, entry.findtext(kind))
                    break
    for container in root.iter("address-group"):
        for entry in container.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            scope = scope_of(entry)
            dyn = entry.find("dynamic")
            if dyn is not None:
                book.add_dynamic(scope, name, dyn.findtext("filter"))
                continue
            members = [m.text.strip() for m in entry.findall("static/member") if m.text]
            members += [m.text.strip() for m in entry.findall("member") if m.text]
            book.add_static(scope, name, members)
    return book


def _panos_scope_fn(root: ET.Element):
    parent = {c: p for p in root.iter() for c in p}

    def scope_of(el: ET.Element) -> str:
        cur = el
        while cur in parent:
            p = parent[cur]
            if cur.tag == "entry" and p.tag in ("vsys", "device-group"):
                return f"{p.tag}:{cur.get('name')}"
            cur = p
        return "shared"
    return scope_of


def _dedupe(values: Iterable) -> list:
    """Order-preserving dedupe (linear; unhashable values keyed by repr)."""
    out, seen = [], set()
    for v in values:
        try:
            k = ("h", v)
            hash(k)
        except TypeError:
            k = ("r", repr(v))
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out


def _panos_emit(name, fields_get, svc_objects, svc_groups, stats, raw_line, order,
                resolve_addr=None):
    """
    Common PAN-OS rule normalisation for XML and set formats.
    `fields_get(key)` returns the list of values for a rule field or None;
    `resolve_addr(name)` resolves an address reference (N-03).
    Returns a list of rows, or [] if the rule was skipped.
    """
    if resolve_addr is None:
        def resolve_addr(n):
            return _panos_literal(n) or [n]
    # `disabled yes` rules are stored with enabled=False (flagged for removal).
    enabled = (fields_get("disabled") or ["no"])[0].lower() != "yes"
    action_vals = fields_get("action")
    if not action_vals:
        _bump(stats, "rules_skipped_no_action")
        return []
    act = action_vals[0].lower()
    action = "permit" if act in ("allow", "permit") else "deny"

    sources = fields_get("source") or ["any"]
    destinations = fields_get("destination") or ["any"]
    services = fields_get("service") or ["any"]
    neg_src = (fields_get("negate-source") or ["no"])[0].lower() == "yes"
    neg_dst = (fields_get("negate-destination") or ["no"])[0].lower() == "yes"
    notes = []
    if neg_src or neg_dst:
        if action == "deny" and enabled:
            _bump(stats, "rules_skipped_negated_deny")
            return []
        if neg_src:
            notes.append(f"negated src: {','.join(sources)}")
            sources = ["any"]
        if neg_dst:
            notes.append(f"negated dst: {','.join(destinations)}")
            destinations = ["any"]

    srcs = _dedupe(v for n in sources for v in resolve_addr(n))
    dsts = _dedupe(v for n in destinations for v in resolve_addr(n))

    resolved = []
    for svc in services:
        if svc.lower() == "application-default":
            pairs, note = _panos_app_default(fields_get("application"))
            if note not in notes:
                notes.append(note)
            resolved.extend(pairs)
            continue
        for proto, port, note in _panos_resolve_service(svc, svc_objects, svc_groups, stats):
            if note and note not in notes:
                notes.append(note)
            resolved.append((proto, port))

    resolved = _dedupe(resolved)
    srcs, dsts, resolved = _cap_rule(
        [(srcs, ",".join(sources), str), (dsts, ",".join(destinations), str),
         (resolved, ",".join(services), lambda t: ("any", t))], stats, name or raw_line)
    src_zone = ",".join(fields_get("from") or []) or None
    dst_zone = ",".join(fields_get("to") or []) or None
    raw = _note(raw_line, notes)
    policy_id = name if name and len(name) <= 32 else None
    rows = []
    v6 = False
    for src, dst, fam in _pair_families(srcs, dsts, (4,), stats):
        v6 = v6 or fam == 6
        for proto, port in resolved:
            rows.append({
                "device_name": name,
                "policy_id": policy_id,
                "policy_name": name,
                "src": src,
                "dst": dst,
                "protocol": proto,
                "dst_port": port,
                "action": action,
                "raw_line": raw,
                "rule_order": order,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "enabled": enabled,
            })
    if rows and not enabled:
        _bump(stats, "rules_disabled")
    if rows and v6:
        _bump(stats, "rules_ipv6")
    return rows


def _panos_xml_entries(root: ET.Element, kind: str) -> list:
    """Rule entries of rulebase `kind` ("security" | "nat") in evaluation
    order: shared pre, device-group pre, local, device-group post, shared post."""
    def _collect(base: str) -> tuple:
        path = f"{base}/{kind}/rules/entry"
        all_entries = root.findall(f".//{path}")
        if root.tag == "shared":
            shared = root.findall(f"./{path}")
        else:
            shared = root.findall(f".//shared/{path}")
        shared_ids = {id(e) for e in shared}
        others = [e for e in all_entries if id(e) not in shared_ids]
        return shared, others

    pre_shared, pre_dg = _collect("pre-rulebase")
    local = root.findall(f".//rulebase/{kind}/rules/entry")
    if root.tag == "rulebase":          # partial export rooted at <rulebase>
        local = root.findall(f"./{kind}/rules/entry") + local
    post_shared, post_dg = _collect("post-rulebase")
    return pre_shared + pre_dg + local + post_dg + post_shared


def _xml_fields_get(entry: ET.Element):
    def fields_get(key):
        if key in ("source", "destination", "service", "from", "to", "application"):
            el = entry.find(key)
            if el is None:
                return None
            vals = [m.text.strip() for m in el.findall("member") if m.text]
            if not vals and el.text and el.text.strip():
                vals = [el.text.strip()]        # NAT <service>any</service>
            return vals or None
        val = entry.findtext(key)
        return [val.strip()] if val and val.strip() else None
    return fields_get


def parse_paloalto_xml(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    Parse a PAN-OS / Panorama XML config. Only SECURITY rulebases are
    read here (NAT: parse_paloalto_nat_xml):
        pre-rulebase/security   (Panorama; shared first, then device-group)
        rulebase/security       (local firewall rules)
        post-rulebase/security  (Panorama; device-group first, then shared)
    rule_order follows that evaluation sequence. Rules with
    <disabled>yes</disabled> are stored with enabled=False; rules with no
    <action> are skipped (counted). Service objects/groups and (N-03)
    address objects / address groups defined in shared, device-group and
    vsys scopes are resolved (most specific scope wins).

    One row is emitted per (source x destination x service) combination.
    """
    if stats is None:
        stats = _new_stats()
    root = _safe_ET.fromstring(text)
    svc_objects, svc_groups = _panos_xml_services(root)
    scope_of = _panos_scope_fn(root)
    book = _panos_xml_addresses(root, scope_of)

    rules = []
    for order, entry in enumerate(_panos_xml_entries(root, "security"), start=1):
        scope = scope_of(entry)
        rules.extend(_panos_emit(
            entry.get("name"), _xml_fields_get(entry), svc_objects, svc_groups, stats,
            ET.tostring(entry, encoding="unicode").strip(), order,
            resolve_addr=lambda n, _s=scope: book.resolve(n, _s, stats)))

    return _finalize_rows(rules)


_SET_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|(\S+)')


def _set_tokens(line: str) -> list:
    """Split a PAN-OS `set` line; double- or single-quoted values (rule
    names with spaces, dynamic filters with embedded quotes) stay one
    token. Apostrophes inside a word do not break the line."""
    toks = []
    for m in _SET_TOKEN_RE.finditer(line):
        if m.group(1) is not None:
            toks.append(m.group(1))
        elif m.group(2) is not None:
            toks.append(m.group(2))
        else:
            toks.append(m.group(3))
    return [t for t in toks if t not in ("[", "]")]


def _parse_panos_set_lines(text: str):
    """Shared set-format reader -> (security, nat, svc_objects, svc_groups, book)
    where security / nat map (bucket, scope, name) -> {key: [values]}."""
    security: dict = {}
    nat: dict = {}
    svc_objects: dict = {}
    svc_groups: dict = _MemoDict()
    book = _PanAddressBook()

    for line in text.splitlines():
        if not line.strip().startswith("set "):
            continue
        toks = _set_tokens(line.strip())
        i = 1
        scope = "local"
        while i < len(toks) and toks[i] in ("device-group", "vsys", "template"):
            scope = f"{toks[i]}:{toks[i + 1] if i + 1 < len(toks) else ''}"
            i += 2
        if i < len(toks) and toks[i] == "shared":
            scope = "shared"
            i += 1
        if i >= len(toks):
            continue
        word = toks[i]
        if word == "service" and i + 2 < len(toks):
            name = toks[i + 1]
            rest = toks[i + 2:]
            if rest and rest[0] == "protocol" and len(rest) > 1:
                proto = rest[1].lower()
                port = None
                if "port" in rest[2:]:
                    j = rest.index("port", 2)
                    if j + 1 < len(rest):
                        port = _panos_port_ranges(rest[j + 1])
                entries = svc_objects.setdefault(name, [])
                entries[:] = [e for e in entries if e[0] != proto] + [(proto, port)]
            continue
        if word == "service-group" and i + 2 < len(toks):
            name = toks[i + 1]
            rest = toks[i + 2:]
            if rest and rest[0] == "members":
                svc_groups.setdefault(name, []).extend(rest[1:])
            continue
        if word == "address" and i + 3 < len(toks):
            book.add_address(scope, toks[i + 1], toks[i + 2], toks[i + 3])
            continue
        if word == "address-group" and i + 2 < len(toks):
            name, rest = toks[i + 1], toks[i + 2:]
            if rest[0] == "static":
                book.add_static(scope, name, rest[1:])
            elif rest[0] == "dynamic":
                flt = rest[2] if len(rest) > 2 and rest[1] == "filter" else None
                book.add_dynamic(scope, name, flt)
            continue
        if word not in ("rulebase", "pre-rulebase", "post-rulebase"):
            continue
        if len(toks) < i + 5 or toks[i + 2] != "rules" or toks[i + 1] not in ("security", "nat"):
            continue
        name, key, values = toks[i + 3], toks[i + 4], toks[i + 5:]
        bucket = {"pre-rulebase": 0, "rulebase": 1, "post-rulebase": 2}[word]
        target = security if toks[i + 1] == "security" else nat
        target.setdefault((bucket, scope, name), {}).setdefault(key, []).extend(values)

    def _sort_key(item):
        (bucket, scope, _name), _ = item
        # shared pre-rules before device-group pre-rules; shared post last
        shared_rank = 0 if scope == "shared" else 1
        if bucket == 2:
            shared_rank = 1 - shared_rank
        return (bucket, shared_rank)

    return (sorted(security.items(), key=_sort_key),      # stable: keeps config order
            sorted(nat.items(), key=_sort_key),
            svc_objects, svc_groups, book)


def parse_paloalto_set(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    Parse PAN-OS `set` command format, e.g.:

        set rulebase security rules Allow-Modbus from trust
        set rulebase security rules "Allow Modbus" source 10.0.1.0/24
        set rulebase security rules Allow-Modbus service tcp-502
        set rulebase security rules Allow-Modbus action allow

    Also accepts `set vsys NAME rulebase security rules ...`, Panorama
    `set device-group DG pre-rulebase|post-rulebase security rules ...` and
    `set shared pre-rulebase ...`, and resolves `set service NAME protocol
    tcp port 80,443` / `set service-group NAME members [ ... ]` and (N-03)
    `set [scope] address NAME ip-netmask|ip-range|fqdn|ip-wildcard V` /
    `set [scope] address-group NAME static [ ... ] | dynamic filter F`.
    Lines are accumulated per rule before being normalized. Disabled
    rules are stored with enabled=False; rules with no action and negated
    deny rules are skipped (counted in stats).
    """
    if stats is None:
        stats = _new_stats()
    security, _nat, svc_objects, svc_groups, book = _parse_panos_set_lines(text)
    rules = []
    for order, ((_b, scope, name), fields) in enumerate(security, start=1):
        raw_line = "; ".join(f"{k} {' '.join(v)}" for k, v in fields.items())
        rules.extend(_panos_emit(
            name, lambda k, f=fields: f.get(k) or None,
            svc_objects, svc_groups, stats, raw_line, order,
            resolve_addr=lambda n, _s=scope: book.resolve(n, _s, stats)))

    return _finalize_rows(rules)


# ------------------------------------------------------------ PAN-OS NAT --

_PAN_NAT_KEYWORDS = {
    "dynamic-ip-and-port", "dynamic-ip", "static-ip", "interface-address",
    "translated-address", "translated-port", "interface", "ip",
    "bi-directional", "fallback", "floating-ip", "distribution",
}


def _pan_nat_keyvals(tokens: list) -> dict:
    """['static-ip', 'translated-address', '1.2.3.4', 'bi-directional', 'yes']
    -> {'static-ip': [], 'translated-address': ['1.2.3.4'], ...}"""
    out: dict = {}
    cur = None
    for t in tokens:
        if t in _PAN_NAT_KEYWORDS:
            cur = t
            out.setdefault(cur, [])
        elif cur is not None:
            out[cur].append(t)
    return out


def _panos_nat_emit(name, fields_get, snat: Optional[dict], dnat: Optional[dict],
                    resolve, svc_objects, svc_groups, stats, raw) -> list:
    """
    snat: {"mapped": [tokens] | None, "interface": str | None}
    dnat: {"address": token, "port": str | None}
    """
    out = []
    enabled = (fields_get("disabled") or ["no"])[0].lower() != "yes"
    src_intf = ",".join(fields_get("from") or []) or None
    sources = _dedupe(v for n in (fields_get("source") or ["any"]) for v in resolve(n))
    dests = _dedupe(v for n in (fields_get("destination") or ["any"]) for v in resolve(n))
    if snat is not None:
        if snat.get("mapped"):
            mapped = ",".join(_dedupe(_nat_addr(v) for n in snat["mapped"] for v in resolve(n)))
        elif snat.get("interface"):
            mapped = f"interface:{snat['interface']}"
        else:
            mapped = None
        for s in sources:
            out.append(nat_row("snat", name=name, src_intf=src_intf, orig_src=_nat_addr(s),
                               mapped_ip=mapped, enabled=enabled, raw=raw))
    if dnat is not None and dnat.get("address"):
        mapped = ",".join(_nat_addr(v) for v in resolve(dnat["address"]))
        svcs = []
        for svc in fields_get("service") or ["any"]:
            svcs.extend(_panos_resolve_service(svc, svc_objects, svc_groups, stats))
        for d in dests:
            for proto, port, _note_ in svcs:
                mport = port
                if dnat.get("port"):
                    r = _parse_port_text(dnat["port"], "-")
                    mport = canonical_ports(r) if r else f"unknown:{dnat['port']}"
                out.append(nat_row("dnat", name=name, protocol=proto, src_intf=src_intf,
                                   ext_ip=_nat_addr(d), ext_port=port,
                                   mapped_ip=mapped, mapped_port=mport,
                                   enabled=enabled, raw=raw))
    return out


def parse_paloalto_nat_xml(text: str, stats: Optional[dict] = None) -> list[dict]:
    """
    PAN-OS NAT rulebase (F-05): <source-translation> dynamic-ip-and-port
    (translated-address members or interface-address ip/interface),
    dynamic-ip, static-ip -> snat (one row per original source);
    <destination-translation> translated-address / translated-port ->
    dnat (one row per original destination x service; mapped_port defaults
    to the service port). src_intf = the rule's from-zones.
    """
    if stats is None:
        stats = _new_stats()
    root = _safe_ET.fromstring(text)
    svc_objects, svc_groups = _panos_xml_services(root)
    scope_of = _panos_scope_fn(root)
    book = _panos_xml_addresses(root, scope_of)
    out = []
    for entry in _panos_xml_entries(root, "nat"):
        scope = scope_of(entry)

        def resolve(n, _s=scope):
            return book.resolve(n, _s, stats)
        snat = dnat = None
        st = entry.find("source-translation")
        if st is not None:
            for mode in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
                m = st.find(mode)
                if m is None:
                    continue
                ia = m.find("interface-address")
                if ia is not None:
                    ip = (ia.findtext("ip") or "").strip()
                    snat = {"mapped": [ip] if ip else None,
                            "interface": (ia.findtext("interface") or "").strip() or None}
                else:
                    ta = m.find("translated-address")
                    vals = []
                    if ta is not None:
                        vals = [x.text.strip() for x in ta.findall("member") if x.text]
                        if not vals and ta.text and ta.text.strip():
                            vals = [ta.text.strip()]
                    snat = {"mapped": vals, "interface": None}
                break
        for tag in ("destination-translation", "dynamic-destination-translation"):
            dt = entry.find(tag)
            if dt is not None:
                dnat = {"address": (dt.findtext("translated-address") or "").strip() or None,
                        "port": (dt.findtext("translated-port") or "").strip() or None}
                break
        if snat is None and dnat is None:
            continue
        out.extend(_panos_nat_emit(
            entry.get("name"), _xml_fields_get(entry), snat, dnat, resolve,
            svc_objects, svc_groups, stats, ET.tostring(entry, encoding="unicode").strip()))
    return out


def parse_paloalto_nat_set(text: str, stats: Optional[dict] = None) -> list[dict]:
    """Set-format counterpart of parse_paloalto_nat_xml
    (`set [scope] rulebase nat rules NAME source-translation ...`)."""
    if stats is None:
        stats = _new_stats()
    _sec, nat, svc_objects, svc_groups, book = _parse_panos_set_lines(text)
    out = []
    for (_b, scope, name), fields in nat:
        def resolve(n, _s=scope):
            return book.resolve(n, _s, stats)
        snat = dnat = None
        if fields.get("source-translation"):
            kv = _pan_nat_keyvals(fields["source-translation"])
            if "interface-address" in kv:
                ip = (kv.get("ip") or [None])[0]
                snat = {"mapped": [ip] if ip else None,
                        "interface": (kv.get("interface") or [None])[0]}
            else:
                snat = {"mapped": kv.get("translated-address") or [], "interface": None}
        for key in ("destination-translation", "dynamic-destination-translation"):
            if fields.get(key):
                kv = _pan_nat_keyvals(fields[key])
                dnat = {"address": (kv.get("translated-address") or [None])[0],
                        "port": (kv.get("translated-port") or [None])[0]}
                break
        if snat is None and dnat is None:
            continue
        raw = "; ".join(f"{k} {' '.join(v)}" for k, v in fields.items())
        out.extend(_panos_nat_emit(
            name, lambda k, f=fields: f.get(k) or None, snat, dnat, resolve,
            svc_objects, svc_groups, stats, raw))
    return out


# ========================================================== dispatch ====

def parse_firewall_config(text: str, vendor_hint: Optional[str] = None,
                          stats: Optional[dict] = None) -> tuple:
    """
    Parse the config, either using content-based auto-detection (the
    default) or, when `vendor_hint` is given, going straight to that
    vendor's parser(s).

    `vendor_hint` accepts: "cisco", "pfsense", "palo_alto". Palo Alto
    covers both its XML and `set`-command sub-formats. An unrecognized
    `vendor_hint` value falls through to auto-detection.

    Pass a `stats` dict to receive the skip counters (SKIP_STAT_KEYS).

    Returns (device_type, list[dict]) where device_type is one of
    "cisco_ios", "pfsense", "panos_xml", "panos_set", or "unknown".
    """
    if stats is None:
        stats = _new_stats()
    for k in SKIP_STAT_KEYS:
        stats.setdefault(k, 0)
    # F-01: malformed / non-XML input for an XML vendor (pfsense hint on a
    # Cisco file, truncated config.xml) is "unknown format", not a crash.
    # B-08: every rule's expansion is charged to one per-ingest row budget
    # (IACS_MAX_RULE_ROWS_PER_INGEST) before its rows are built; over budget
    # raises IngestLimitExceeded (callers store nothing).
    with rule_row_budget() as budget:
        try:
            device_type, rules = _parse_firewall_config(text, vendor_hint, stats)
        except ET.ParseError:
            return "unknown", []
        if len(rules) > budget.limit:       # belt and braces: exact count
            raise IngestLimitExceeded("Firewall rule expansion (rows across all policies)",
                                      len(rules), budget.limit, RULE_ROWS_ENV)
    return device_type, rules


def _parse_firewall_config(text: str, vendor_hint: Optional[str], stats: dict) -> tuple:
    if vendor_hint == "cisco":
        return "cisco_ios", parse_cisco_acl(text, stats)
    if vendor_hint == "pfsense":
        return "pfsense", parse_pfsense_xml(text, stats)
    if vendor_hint == "palo_alto":
        if text.strip().startswith("<"):
            return "panos_xml", parse_paloalto_xml(text, stats)
        return "panos_set", parse_paloalto_set(text, stats)

    stripped = text.strip()

    if stripped.startswith("<"):
        lowered = stripped.lower()
        if "<pfsense" in lowered or "<filter>" in lowered:
            return "pfsense", parse_pfsense_xml(text, stats)
        if "rulebase" in lowered or re.search(r'<entry\s+name="', text):
            return "panos_xml", parse_paloalto_xml(text, stats)
        return "unknown", []

    if re.search(r"^[ \t]*set\s+(?:\S+\s+){0,3}(?:pre-|post-)?rulebase\s+security\s+rules",
                 text, re.MULTILINE):
        return "panos_set", parse_paloalto_set(text, stats)

    if re.search(r"access-list|ip access-list", text):
        return "cisco_ios", parse_cisco_acl(text, stats)

    return "unknown", []


def parse_nat_config(text: str, device_type: str,
                     stats: Optional[dict] = None) -> list[dict]:
    """
    NAT rows (F-05) for a config already identified by
    parse_firewall_config. Rule counters are not touched (the security
    rules were counted by the rule pass); returns [] for unknown types or
    unparseable input.
    """
    scratch = stats if stats is not None else _new_stats()
    try:
        if device_type in ("cisco_ios", "cisco_asa"):
            return parse_cisco_nat(text, scratch)
        if device_type == "pfsense":
            return parse_pfsense_nat(text, scratch)
        if device_type == "panos_xml":
            return parse_paloalto_nat_xml(text, scratch)
        if device_type == "panos_set":
            return parse_paloalto_nat_set(text, scratch)
    except ET.ParseError:
        return []
    return []


def _clip(value, n: int):
    if value is None:
        return None
    v = str(value)
    return v if len(v) <= n else v[:n]


# ------------------------------------------------------------- ingest ---

def get_or_create_firewall_device(
    db: DBSession,
    name: str,
    vendor: Optional[str] = None,
    device_hostname: Optional[str] = None,
    source_file: Optional[str] = None,
    purdue_zone_from: Optional[int] = None,
    purdue_zone_to: Optional[int] = None,
    site_id: Optional[int] = None,
) -> "FirewallDevice":
    """
    Find an existing FirewallDevice by name, or create one.  If the row
    already exists, Purdue zone fields are updated whenever the caller
    passes non-None values — so re-ingesting a config with a different
    boundary hint updates the boundary rather than silently ignoring it.

    This helper is shared across firewall_parser and forti_config_parser
    so every ingest path creates the same FirewallDevice shape.
    """
    from datetime import datetime, timezone
    from app.sites import scope_site_id
    # Phase 2: device names are unique per site (ux_firewall_devices_site_name).
    sid = scope_site_id(db, site_id)
    device = (db.query(FirewallDevice)
              .filter(FirewallDevice.site_id == sid, FirewallDevice.name == name).first())
    if device is None:
        device = FirewallDevice(
            site_id=sid,
            name=name,
            vendor=vendor,
            device_hostname=device_hostname,
            source_file=source_file,
            purdue_zone_from=purdue_zone_from,
            purdue_zone_to=purdue_zone_to,
        )
        db.add(device)
        db.flush()  # populate device.id without a full commit
    else:
        # Update fields that the caller has opinions about
        if vendor and not device.vendor:
            device.vendor = vendor
        if device_hostname and not device.device_hostname:
            device.device_hostname = device_hostname
        if source_file:
            device.source_file = source_file
        if purdue_zone_from is not None:
            device.purdue_zone_from = purdue_zone_from
        if purdue_zone_to is not None:
            device.purdue_zone_to = purdue_zone_to
        device.updated_at = datetime.now(timezone.utc)
    return device


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_firewall_config(
    text: str,
    db: DBSession,
    source_file: Optional[str] = None,
    vendor_hint: Optional[str] = None,
    firewall_device_name: Optional[str] = None,
    purdue_zone_from: Optional[int] = None,
    purdue_zone_to: Optional[int] = None,
) -> dict:
    """
    Parse firewall config text and populate FirewallRule rows.

    Pass ``firewall_device_name`` to tag all emitted rules with a
    FirewallDevice row (created if it doesn't exist yet).  Use
    ``purdue_zone_from`` / ``purdue_zone_to`` to record the Purdue boundary
    this firewall protects.  Both default to NULL when omitted.

    The returned stats include the counters in SKIP_STAT_KEYS (disabled /
    negated-deny / no-action rules, IPv6 rules, unresolved object groups,
    unknown port names, ...) and `nat_rules_created`.

    With ``firewall_device_name`` a re-ingest REPLACES that device's
    FirewallRule and NatRule rows (rows from a FortiGate ingest, which
    carry firewall_id, are never touched). Without it rows are appended.
    """
    parse_stats = _new_stats()
    device_type, parsed_rules = parse_firewall_config(
        text, vendor_hint=vendor_hint, stats=parse_stats)
    stats = {
        "device_type": device_type,
        "rules_created": 0,
        "vendor_hint_used": vendor_hint,
        "firewall_device_name": firewall_device_name,
        "purdue_zone_from": purdue_zone_from,
        "purdue_zone_to": purdue_zone_to,
    }
    stats.update(parse_stats)
    stats["nat_rules_created"] = 0
    if device_type == "unknown":
        # F-01: unrecognised input is rejected by the caller - do not leave
        # a phantom FirewallDevice (vendor "unknown") behind.
        return stats

    # MV-02: an ASA is not IOS (post-NAT, implicit security-level permits)
    from app.parsers import fw_interfaces as _fwi
    if device_type == "cisco_ios" and _fwi.is_asa(text):
        device_type = "cisco_asa"
        stats["device_type"] = device_type
    iface_info = _fwi.extract(text, device_type)

    fw_device: Optional["FirewallDevice"] = None
    if firewall_device_name:
        fw_device = get_or_create_firewall_device(
            db,
            name=firewall_device_name,
            vendor=device_type,
            source_file=source_file,
            purdue_zone_from=purdue_zone_from,
            purdue_zone_to=purdue_zone_to,
        )
        stats["firewall_device_id"] = fw_device.id
        # Re-ingest replaces this device's rules and NAT rows.  Scoped by
        # device_type so a FortiGate ingest that shares the FirewallDevice
        # name is never touched (this path writes firewall_id too, MV-05).
        if device_type != "unknown":
            db.query(FirewallRule).filter(
                FirewallRule.firewall_device_id == fw_device.id,
                FirewallRule.device_type != "fortigate",
            ).delete(synchronize_session="fetch")
            db.query(NatRule).filter(
                NatRule.firewall_device_id == fw_device.id,
                (NatRule.device_type != "fortigate") | NatRule.device_type.is_(None),
            ).delete(synchronize_session="fetch")
    # MV-01: the firewall and its interfaces, like a FortiGate upload
    fw_row = None
    if fw_device is not None and device_type != "unknown":
        fw_device.vendor = device_type           # ASA vs IOS decides the NAT mode
    if fw_device is not None and iface_info and iface_info.get("interfaces"):
        try:
            fw_row = _fwi.sync_firewall(db, fw_device, device_type, iface_info, source_file)
        except _fwi.NameTakenByFortiGate as exc:
            # the rules are stored (with no Firewall row); the FortiGate of
            # that name keeps its interfaces and the operator's labels
            stats["interfaces_skipped"] = str(exc)
            log.warning("%s", exc)
        else:
            stats["firewall_id"] = fw_row.id
            stats["interfaces"] = len(iface_info["interfaces"])
            implicit = _fwi.implicit_rules(iface_info)
            if implicit:
                parsed_rules = list(parsed_rules) + implicit
                stats["implicit_rules"] = len(implicit)
    elif fw_device is not None and fw_device.firewall_id is not None:
        # an ACL-only paste of a device whose interfaces were uploaded
        # before: the rules stay attached to that firewall
        fw_row = db.get(Firewall, fw_device.firewall_id)
        if fw_row is not None:
            stats["firewall_id"] = fw_row.id

    for seq, rule in enumerate(parsed_rules):
        db.add(FirewallRule(
            # MV-05: the firewall's name, not the rule / ACL name
            device_name=firewall_device_name or rule["device_name"],
            device_type=device_type,
            source_file=source_file,
            firewall_device_id=fw_device.id if fw_device else None,
            firewall_id=fw_row.id if fw_row is not None else None,
            policy_id=_clip(rule.get("policy_id"), 32),
            policy_name=_clip(rule.get("policy_name"), 255),
            src=rule["src"],
            dst=rule["dst"],
            protocol=rule["protocol"],
            dst_port=rule["dst_port"],
            action=rule["action"],
            raw_line=rule["raw_line"],
            src_zone=rule.get("src_zone"),
            dst_zone=rule.get("dst_zone"),
            # Evaluation position of the SOURCE rule (first-match-wins);
            # rows expanded from one rule/ACE share the same value.
            rule_order=rule.get("rule_order", seq),
            enabled=rule.get("enabled", True),
        ))
        stats["rules_created"] += 1
        if stats["rules_created"] % 5000 == 0:
            db.flush()      # B-08: flushed rows drop out of memory (weak identity map)

    nat_stats = _new_stats()
    nat_rows = parse_nat_config(text, device_type, nat_stats)
    if nat_stats.get("nat_lines_rejected"):
        stats["nat_lines_rejected"] = nat_stats["nat_lines_rejected"]
        stats.setdefault("reject_reasons", [])
        for r in nat_stats.get("reject_reasons", []):
            if r not in stats["reject_reasons"] and len(stats["reject_reasons"]) < 2 * MAX_REJECT_SAMPLES:
                stats["reject_reasons"].append(r)
    # B-13: rows keep their configured order (PAN-OS / pfSense NAT is
    # first-match in rule order too).
    for _nat_seq, nat in enumerate(nat_rows, start=1):
        db.add(NatRule(
            firewall_device_id=fw_device.id if fw_device else None,
            firewall_id=fw_row.id if fw_row is not None else None,
            device_name=firewall_device_name,
            device_type=device_type,
            nat_type=nat["nat_type"],
            name=_clip(nat.get("name"), 255),
            policy_id=nat.get("policy_id"),
            protocol=_clip(nat.get("protocol"), 16),
            src_intf=nat.get("src_intf"),
            orig_src=nat.get("orig_src"),
            ext_ip=nat.get("ext_ip"),
            ext_port=_clip(nat.get("ext_port"), 255),
            mapped_ip=nat.get("mapped_ip"),
            mapped_port=_clip(nat.get("mapped_port"), 255),
            enabled=nat.get("enabled", True),
            source_file=source_file,
            raw=nat.get("raw"),
            sequence=nat.get("sequence", _nat_seq),
            nat_exempt=bool(nat.get("nat_exempt", False)),
        ))
        stats["nat_rules_created"] += 1

    db.commit()
    return stats
