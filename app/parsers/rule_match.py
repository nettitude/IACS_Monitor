"""
Shared rule-matching primitives for reachability.py and rule_shadow.py.

Ports are represented as a normalised tuple of inclusive ``(lo, hi)`` ranges
instead of Python sets of ints, so ``gt 1023`` costs one tuple rather than a
64 k-element set (T3-41) and range arithmetic (contain / overlap / subtract /
intersect) is exact.

Accepted FirewallRule.dst_port forms
------------------------------------
Canonical (emitted by the parsers going forward):
    "any" | "22" | "80,443" | "1-1024" | "80,443,1000-2000"
Legacy rows still in the DB:
    "eq 22", "range 1 1024", "gt 1023", "lt 1024", "neq 23",
    "['502', '102']"  (Python list repr),
    "502:1024-65535"  (FortiOS dst[:src] portrange - the part after ':' is
                       the SOURCE port range and is ignored),
    "80 443"          (whitespace-separated FortiOS portranges)
Unresolvable (never treated as "any"):
    "unknown:NAME", "alias:NAME", "unresolved:NAME", or anything else that
    does not parse -> ``Unresolved``.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional, Union

ANY = "any"
MAX_PORT = 65535

PortRanges = tuple  # tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Unresolved:
    """A rule field that references an object we could not expand."""
    raw: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"unresolved({self.raw})"


PortSpec = Union[str, PortRanges, Unresolved]
ProtoSpec = Union[str, frozenset, Unresolved]

_UNRESOLVED_PREFIXES = ("unknown:", "alias:", "unresolved:", "cycle:", "group:", "object:",
                        "too-large:")
_ANY_TOKENS = {"", "any", "all", "*", "none"}  # "none" = no port restriction (e.g. icmp)

_EQ_RE = re.compile(r"^eq\s+(\d+)$", re.I)
_NEQ_RE = re.compile(r"^neq\s+(\d+)$", re.I)
_RANGE_RE = re.compile(r"^range\s+(\d+)\s+(\d+)$", re.I)
_GT_RE = re.compile(r"^gt\s+(\d+)$", re.I)
_LT_RE = re.compile(r"^lt\s+(\d+)$", re.I)
_TOKEN_RE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")


# ---------------------------------------------------------------------------
# Port ranges
# ---------------------------------------------------------------------------

def normalize_ranges(ranges) -> PortRanges:
    """Sort, clamp and merge overlapping / adjacent ranges."""
    cleaned = []
    for lo, hi in ranges:
        lo, hi = max(0, int(lo)), min(MAX_PORT, int(hi))
        if lo > hi:
            lo, hi = hi, lo
        cleaned.append((lo, hi))
    cleaned.sort()
    merged: list[list[int]] = []
    for lo, hi in cleaned:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return tuple((a, b) for a, b in merged)


FULL_RANGE: PortRanges = ((0, MAX_PORT),)


def _parse_port_token(tok: str) -> Optional[tuple[int, int]]:
    tok = tok.strip().strip("'\"").strip()
    if not tok:
        return None
    # FortiOS "dst[-hi]:src[-hi]" - keep only the destination part.
    if ":" in tok:
        tok = tok.split(":", 1)[0].strip()
    m = _TOKEN_RE.match(tok)
    if not m:
        raise ValueError(tok)
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) is not None else lo
    if lo > MAX_PORT or hi > MAX_PORT:
        raise ValueError(tok)
    return (min(lo, hi), max(lo, hi))


def parse_ports(port_str: Optional[str]) -> PortSpec:
    """Parse a FirewallRule.dst_port value into ANY, ranges or Unresolved."""
    if port_str is None:
        return ANY
    s = str(port_str).strip()
    low = s.lower()
    if low in _ANY_TOKENS:
        return ANY
    if low.startswith(_UNRESOLVED_PREFIXES):
        return Unresolved(s)

    m = _EQ_RE.match(s)
    if m:
        p = int(m.group(1))
        return normalize_ranges([(p, p)]) if p <= MAX_PORT else Unresolved(s)
    m = _NEQ_RE.match(s)
    if m:
        p = int(m.group(1))
        parts = []
        if p > 0:
            parts.append((0, p - 1))
        if p < MAX_PORT:
            parts.append((p + 1, MAX_PORT))
        return normalize_ranges(parts)
    m = _RANGE_RE.match(s)
    if m:
        return normalize_ranges([(int(m.group(1)), int(m.group(2)))])
    m = _GT_RE.match(s)
    if m:
        p = int(m.group(1))
        return normalize_ranges([(p + 1, MAX_PORT)]) if p < MAX_PORT else Unresolved(s)
    m = _LT_RE.match(s)
    if m:
        p = int(m.group(1))
        return normalize_ranges([(0, p - 1)]) if p > 0 else Unresolved(s)

    # Python list repr: "['502', '102']"
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]

    tokens = [t for t in re.split(r"[,\s]+", s) if t.strip().strip("'\"")]
    if not tokens:
        return ANY
    ranges = []
    for tok in tokens:
        t = tok.strip().strip("'\"")
        if t.lower() in _ANY_TOKENS:
            return ANY
        if t.lower().startswith(_UNRESOLVED_PREFIXES):
            return Unresolved(str(port_str).strip())
        try:
            r = _parse_port_token(t)
        except ValueError:
            return Unresolved(str(port_str).strip())
        if r:
            ranges.append(r)
    if not ranges:
        return ANY
    ranges = normalize_ranges(ranges)
    if ranges == FULL_RANGE:
        return ANY
    return ranges


def _as_ranges(p: PortSpec) -> PortRanges:
    return FULL_RANGE if p == ANY else p


def port_in(port: int, spec: PortSpec) -> Optional[bool]:
    """True/False, or None if spec is Unresolved."""
    if isinstance(spec, Unresolved):
        return None
    if spec == ANY:
        return True
    return any(lo <= port <= hi for lo, hi in spec)


def ports_contain(outer: PortSpec, inner: PortSpec) -> Optional[bool]:
    """True if every port of ``inner`` is in ``outer``."""
    if isinstance(outer, Unresolved) or isinstance(inner, Unresolved):
        return None
    if outer == ANY:
        return True
    if inner == ANY:
        return False
    return not ranges_subtract(inner, outer)


def ports_overlap(a: PortSpec, b: PortSpec) -> Optional[bool]:
    if isinstance(a, Unresolved) or isinstance(b, Unresolved):
        return None
    if a == ANY or b == ANY:
        return True
    return bool(ranges_intersect(a, b))


def ranges_intersect(a: PortSpec, b: PortSpec) -> PortRanges:
    a, b = _as_ranges(a), _as_ranges(b)
    out = []
    for alo, ahi in a:
        for blo, bhi in b:
            lo, hi = max(alo, blo), min(ahi, bhi)
            if lo <= hi:
                out.append((lo, hi))
    return normalize_ranges(out)


def ranges_subtract(a: PortSpec, b: PortSpec) -> PortRanges:
    """Ports in ``a`` that are not in ``b``."""
    cur = list(_as_ranges(a))
    for blo, bhi in _as_ranges(b):
        nxt = []
        for lo, hi in cur:
            if bhi < lo or blo > hi:
                nxt.append((lo, hi))
                continue
            if lo < blo:
                nxt.append((lo, blo - 1))
            if hi > bhi:
                nxt.append((bhi + 1, hi))
        cur = nxt
    return normalize_ranges(cur)


def format_ports(spec: PortSpec) -> str:
    if isinstance(spec, Unresolved):
        return spec.raw
    if spec == ANY:
        return "any"
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in spec)


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------

_PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "132": "sctp"}
PORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})


def parse_protocols(proto: Optional[str]) -> ProtoSpec:
    if proto is None:
        return ANY
    s = str(proto).strip().lower()
    if s in ("", "any", "ip", "all", "ipv4", "ipv6", "0"):
        return ANY
    if s == "unknown" or s.startswith(_UNRESOLVED_PREFIXES):
        return Unresolved(str(proto))
    toks = [t for t in re.split(r"[,/\s|+_]+|(?<=tcp)-(?=udp)", s) if t]
    out = set()
    for t in toks:
        if t in ("any", "ip"):
            return ANY
        out.add(_PROTO_NUM.get(t, t))
    return frozenset(out) if out else ANY


def protos_contain(outer: ProtoSpec, inner: ProtoSpec) -> Optional[bool]:
    if isinstance(outer, Unresolved) or isinstance(inner, Unresolved):
        return None
    if outer == ANY:
        return True
    if inner == ANY:
        return False
    return inner <= outer


def protos_overlap(a: ProtoSpec, b: ProtoSpec) -> Optional[bool]:
    if isinstance(a, Unresolved) or isinstance(b, Unresolved):
        return None
    if a == ANY or b == ANY:
        return True
    return bool(a & b)


def protos_intersect(a: ProtoSpec, b: ProtoSpec):
    if a == ANY:
        return b
    if b == ANY:
        return a
    return frozenset(a & b)


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AddrRange:
    """An inclusive, non-CIDR-aligned address range (``range:a-b`` objects,
    T3-35).  Kept as integers so containment / overlap are exact instead of
    collapsing to a covering (or, before T3-35, an UNDER-covering) supernet.
    Supports ``ip in rng`` like an ip_network."""
    version: int
    lo: int
    hi: int

    def _ip(self, n: int):
        return ipaddress.IPv4Address(n) if self.version == 4 else ipaddress.IPv6Address(n)

    @property
    def networks(self) -> list:
        """Exact CIDR decomposition (ipaddress.summarize_address_range)."""
        return list(ipaddress.summarize_address_range(self._ip(self.lo), self._ip(self.hi)))

    def __contains__(self, ip) -> bool:
        try:
            a = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
                else ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return a.version == self.version and self.lo <= int(a) <= self.hi

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self._ip(self.lo)}-{self._ip(self.hi)}"


@dataclass(frozen=True)
class AddrSet:
    """A multi-address field ("10.0.0.1,10.0.0.2", "10.0.0.1 10.0.0.2",
    "['10.0.0.0/24', 'range:10.1.0.1-10.1.0.9']") parsed as a SET of
    networks / ranges (N-05) - previously the whole field was unresolved.
    Members may mix IPv4 and IPv6; the families stay disjoint (F-07)."""
    members: tuple

    @property
    def versions(self) -> frozenset:
        return frozenset(m.version for m in self.members)

    def __contains__(self, ip) -> bool:
        return bool(ip_in_addr(str(ip), self))

    def __str__(self) -> str:  # pragma: no cover - trivial
        return ",".join(format_addr(m) for m in self.members)


AddrSpec = Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network, AddrRange, AddrSet, Unresolved]


def _cisco_wildcard_to_network(ip_str: str, wildcard_str: str):
    """('10.0.1.0', '0.0.0.255') -> 10.0.1.0/24.  Non-contiguous masks raise
    ValueError (caller treats the address as unresolvable)."""
    wildcard_int = int(ipaddress.IPv4Address(wildcard_str))
    netmask_int = (~wildcard_int) & 0xFFFFFFFF
    netmask_str = str(ipaddress.IPv4Address(netmask_int))
    return ipaddress.ip_network(f"{ip_str}/{netmask_str}", strict=False)


def _is_wildcard_mask(tok: str) -> bool:
    """True for a contiguous Cisco wildcard mask (0.0.0.255, 0.0.0.0, ...)."""
    try:
        w = int(ipaddress.IPv4Address(tok))
    except ValueError:
        return False
    # contiguous wildcard = low-order ones only: w+1 is a power of two
    return (w & (w + 1)) == 0


def _is_ipv4(tok: str) -> bool:
    try:
        ipaddress.IPv4Address(tok)
        return True
    except ValueError:
        return False


def _parse_range(body: str):
    """"a-b" -> ip_network when the range is exactly one CIDR, else AddrRange."""
    a, b = body.split("-", 1)
    lo, hi = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
    if lo.version != hi.version:
        raise ValueError("mixed-version range")
    if int(lo) > int(hi):
        lo, hi = hi, lo
    cidrs = list(ipaddress.summarize_address_range(lo, hi))
    if len(cidrs) == 1:
        return cidrs[0]
    return AddrRange(lo.version, int(lo), int(hi))


def _parse_single(s: str):
    """One address token -> "any" | ip_network | AddrRange | None."""
    if not s:
        return None
    if s.lower() in ("any", "all", "*"):
        return "any"
    if s.lower() == "any4":
        return ipaddress.ip_network("0.0.0.0/0")
    if s.lower() == "any6":
        return ipaddress.ip_network("::/0")
    if s.startswith("network:"):
        return None
    if s.startswith("range:"):
        try:
            return _parse_range(s[len("range:"):])
        except (ValueError, IndexError):
            return None
    if s.startswith("host "):
        try:
            return ipaddress.ip_network(s.split(None, 1)[1].strip(), strict=False)
        except ValueError:
            return None
    if "/" in s:
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
    if "-" in s and ":" not in s and " " not in s:
        # bare "a-b" IPv4 range (FortiOS iprange text without the prefix)
        try:
            return _parse_range(s)
        except (ValueError, IndexError):
            pass
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _split_multi(s: str) -> list:
    body = s.strip()
    if body.startswith("[") and body.endswith("]"):
        body = body[1:-1]
    toks = [t.strip().strip("'\"").strip() for t in re.split(r"[,;\s]+", body)]
    return [t for t in toks if t]


def parse_address_spec(addr_str: Optional[str]):
    """
    Resolve a FirewallRule.src/dst string into "any", an ip_network, an
    :class:`AddrRange`, an :class:`AddrSet`, or None if it cannot be
    resolved (named object that was never expanded, pfSense
    ``network:<alias>``, unrecognised text).

    Accepted: "any", "a.b.c.d/nn", IPv6 CIDRs / addresses, "host a.b.c.d",
    bare IP, Cisco "ip wildcard", "range:a-b" (FortiOS iprange objects;
    exact, T3-35), and comma / semicolon / whitespace separated LISTS of
    any of those (N-05).  A two-token "ip mask" is a Cisco wildcard only
    when the second token is a contiguous wildcard mask; otherwise the two
    tokens are a two-address list.  A list with any unresolvable member is
    unresolvable as a whole; a list containing "any" is "any".
    This is the single address parser; topology_diff re-exports it.
    """
    if not addr_str:
        return None
    s = str(addr_str).strip()
    single = _parse_single(s)
    if single is not None:
        return single
    if s.startswith(("network:", "host ")):
        return None
    toks = _split_multi(s)
    if len(toks) == 2 and "/" not in toks[0] and _is_ipv4(toks[0]) and _is_ipv4(toks[1]):
        # AU full review C9: "a.b.c.d 255.255.255.255" is a /32 netmask
        # (ASA / pfSense), not the Cisco "match everything" wildcard - that
        # one is only ever written with 0.0.0.0 as the address.
        if _is_wildcard_mask(toks[1]) and not (toks[1] == "255.255.255.255" and toks[0] != "0.0.0.0"):
            return _cisco_wildcard_to_network(toks[0], toks[1])
        if toks[1].startswith("0."):
            return None  # non-contiguous wildcard mask: not representable
        try:  # "ip netmask" (ASA / pfSense style)
            if int(ipaddress.IPv4Address(toks[1])) >> 31:
                return ipaddress.ip_network(f"{toks[0]}/{toks[1]}", strict=False)
        except ValueError:
            pass
    if len(toks) < 2:
        return None
    members = []
    for t in toks:
        sp = _parse_single(t)
        if sp is None:
            return None
        if sp == "any":
            return "any"
        members.append(sp)
    return _make_set(members)


def _make_set(members):
    """Normalise a member list: dedupe, collapse to a single spec if one."""
    out = []
    for m in members:
        if m not in out:
            out.append(m)
    if len(out) == 1:
        return out[0]
    return AddrSet(tuple(sorted(out, key=lambda m: addr_bounds(m))))


def parse_address(addr: Optional[str], v6_default_is_any: Optional[bool] = None) -> AddrSpec:
    """
    Parse FirewallRule.src/dst into ANY, an ip_network, an AddrRange, an
    AddrSet or Unresolved.

    F-07: address families are always disjoint.  "any"/"all"/"*" is ANY and
    matches BOTH families; "0.0.0.0/0" ("any4") is the whole IPv4 space
    and "::/0" ("any6") the whole IPv6 space - an IPv6 rule never matches an
    IPv4 flow and vice versa.  ``v6_default_is_any`` is accepted for
    backward compatibility and ignored.  Use :func:`is_family_wide` to ask
    "does this cover a whole family".
    """
    if addr is None:
        return Unresolved("")
    s = str(addr).strip()
    if s.lower() in ("any", "all", "*"):
        return ANY
    spec = parse_address_spec(s)
    if spec is None:
        return Unresolved(s)
    if spec == "any":
        return ANY
    return spec


def addr_bounds(spec) -> tuple:
    """(version, lo_int, hi_int) for an ip_network or AddrRange (for an
    AddrSet: the covering bounds of its lowest family - use
    :func:`addr_intervals` for exact work)."""
    if isinstance(spec, AddrRange):
        return spec.version, spec.lo, spec.hi
    if isinstance(spec, AddrSet):
        iv = addr_intervals(spec)
        v = min(iv)
        return v, iv[v][0][0], iv[v][-1][1]
    return spec.version, int(spec.network_address), int(spec.broadcast_address)


def _merge(ivals):
    ivals = sorted(ivals)
    out: list = []
    for lo, hi in ivals:
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((a, b) for a, b in out)


def addr_intervals(spec) -> dict:
    """{version: ((lo, hi), ...)} merged, for network / range / set specs."""
    members = spec.members if isinstance(spec, AddrSet) else (spec,)
    by_v: dict = {}
    for m in members:
        if isinstance(m, AddrRange):
            v, lo, hi = m.version, m.lo, m.hi
        else:
            v, lo, hi = m.version, int(m.network_address), int(m.broadcast_address)
        by_v.setdefault(v, []).append((lo, hi))
    return {v: _merge(iv) for v, iv in by_v.items()}


_FAMILY_MAX = {4: (1 << 32) - 1, 6: (1 << 128) - 1}


def is_family_wide(spec, version: Optional[int] = None) -> bool:
    """True for ANY, or a spec covering an entire address family
    (0.0.0.0/0, ::/0) - of ``version`` when given."""
    if spec == ANY:
        return True
    if isinstance(spec, (Unresolved, str)) or spec is None:
        return False
    for v, iv in addr_intervals(spec).items():
        if version is not None and v != version:
            continue
        if iv and iv[0] == (0, _FAMILY_MAX[v]):
            return True
    return False


def addr_versions(spec) -> Optional[frozenset]:
    """Families a resolved spec covers (None for ANY / unresolved)."""
    if spec == ANY or isinstance(spec, Unresolved) or spec is None:
        return None
    return frozenset(addr_intervals(spec))


def addr_contains(outer: AddrSpec, inner: AddrSpec) -> Optional[bool]:
    """True if every address in ``inner`` is in ``outer``.  Different IP
    versions are disjoint (never raises TypeError).  Exact for ranges and
    address sets."""
    if isinstance(outer, Unresolved) or isinstance(inner, Unresolved):
        return None
    if outer == ANY:
        return True
    if inner == ANY:
        return False
    o = addr_intervals(outer)
    for v, ivals in addr_intervals(inner).items():
        ov = o.get(v, ())
        for lo, hi in ivals:
            if not any(olo <= lo and hi <= ohi for olo, ohi in ov):
                return False
    return True


def addr_overlaps(a: AddrSpec, b: AddrSpec) -> Optional[bool]:
    if isinstance(a, Unresolved) or isinstance(b, Unresolved):
        return None
    if a == ANY or b == ANY:
        return True
    ai, bi = addr_intervals(a), addr_intervals(b)
    for v, iv in ai.items():
        for alo, ahi in iv:
            for blo, bhi in bi.get(v, ()):
                if alo <= bhi and blo <= ahi:
                    return True
    return False


def _spec_from_intervals(by_v: dict):
    members = []
    for v, ivals in by_v.items():
        cls = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
        for lo, hi in ivals:
            cidrs = list(ipaddress.summarize_address_range(cls(lo), cls(hi)))
            members.append(cidrs[0] if len(cidrs) == 1 else AddrRange(v, lo, hi))
    if not members:
        return None
    return _make_set(members)


def addr_intersect(a: AddrSpec, b: AddrSpec):
    """Intersection of two specs: ANY / network / range / set, or None when
    empty.  An Unresolved operand is returned unchanged (cannot narrow)."""
    if isinstance(a, Unresolved):
        return a
    if isinstance(b, Unresolved):
        return b
    if a == ANY:
        return b
    if b == ANY:
        return a
    ai, bi = addr_intervals(a), addr_intervals(b)
    out: dict = {}
    for v, iv in ai.items():
        for alo, ahi in iv:
            for blo, bhi in bi.get(v, ()):
                lo, hi = max(alo, blo), min(ahi, bhi)
                if lo <= hi:
                    out.setdefault(v, []).append((lo, hi))
    return _spec_from_intervals({v: _merge(iv) for v, iv in out.items()})


def addr_restrict_family(spec, version: Optional[int]):
    """Only the ``version`` part of ``spec`` (None if nothing remains)."""
    if version is None or spec == ANY or isinstance(spec, Unresolved):
        return spec
    iv = addr_intervals(spec)
    return _spec_from_intervals({version: iv[version]}) if version in iv else None


_FAMILY_WIDE = {4: ipaddress.ip_network("0.0.0.0/0"), 6: ipaddress.ip_network("::/0")}


def narrow_rule_family(src, dst) -> tuple:
    """A rule's two address sides together determine its family: "any" on
    one side paired with an IPv4-only (IPv6-only) other side can only ever
    match IPv4 (IPv6) packets.  Returns (src, dst) with such an "any"
    replaced by the family-wide network, so containment between rules is
    family-exact (F-07).  Other specs are returned unchanged."""
    sv, dv = addr_versions(src), addr_versions(dst)
    if src == ANY and dv is not None and len(dv) == 1:
        src = _FAMILY_WIDE[next(iter(dv))]
    elif dst == ANY and sv is not None and len(sv) == 1:
        dst = _FAMILY_WIDE[next(iter(sv))]
    return src, dst


def addr_equal(a: AddrSpec, b: AddrSpec) -> bool:
    """Semantic equality ("10.1.0.0/24" == "10.1.0.0 0.0.0.255")."""
    if isinstance(a, Unresolved) or isinstance(b, Unresolved):
        return isinstance(a, Unresolved) and isinstance(b, Unresolved) and a.raw.lower() == b.raw.lower()
    if a == ANY or b == ANY:
        return a == b
    return addr_intervals(a) == addr_intervals(b)


def ip_in_addr(ip: str, spec: AddrSpec) -> Optional[bool]:
    """True/False for a concrete IP string (v4 or v6), None if spec is
    Unresolved or the IP does not parse.  Cross-version -> False."""
    if isinstance(spec, Unresolved):
        return None
    if spec == ANY:
        return True
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    n = int(a)
    return any(lo <= n <= hi for lo, hi in addr_intervals(spec).get(a.version, ()))


def ip_version(ip: Optional[str]) -> Optional[int]:
    """4 / 6 for a parseable IP string, else None."""
    if not ip:
        return None
    try:
        return ipaddress.ip_address(str(ip).strip()).version
    except ValueError:
        return None


#: Address tokens that name an external / internet source or destination
#: (FortiGuard ISDB entries, IPv4 and IPv6 - N-25).  They are address SETS
#: that cannot be expanded offline: parse_address() reports them Unresolved,
#: so a rule using one never silently matches or drops out (A-04), and
#: callers can flag the rule as external/internet with is_external_addr_token.
EXTERNAL_ADDR_PREFIXES = ("internet-service:", "internet-service6:", "fqdn:", "wildcard-fqdn:")
#: DR-02: an FQDN under one of these suffixes names an inside host, not the internet.
_INTERNAL_FQDN_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home.arpa",
                           ".localdomain", ".in-addr.arpa")


def is_external_addr_token(value) -> bool:
    """True for an ``internet-service[6]:<name>`` address token, or an
    ``fqdn:`` / ``wildcard-fqdn:`` token naming a public DNS name (DR-02:
    FortiOS FQDN address objects; a name under an internal suffix such as
    ``.local`` / ``.corp`` is not external)."""
    if not isinstance(value, str) or not value.startswith(EXTERNAL_ADDR_PREFIXES):
        return False
    if value.startswith(("fqdn:", "wildcard-fqdn:")):
        name = value.split(":", 1)[1].strip().lower().rstrip(".")
        if not name or "." not in name or name.endswith(_INTERNAL_FQDN_SUFFIXES):
            return False
    return True


def format_addr(spec) -> str:
    """Human-readable form of a parsed address spec."""
    if spec is None:
        return "none"
    if isinstance(spec, Unresolved):
        return spec.raw
    if spec == ANY:
        return "any"
    if isinstance(spec, AddrSet):
        return ",".join(format_addr(m) for m in spec.members)
    if isinstance(spec, AddrRange):
        return f"range:{spec}"
    return str(spec)


# ---------------------------------------------------------------------------
# Services (protocol + dst ports)
# ---------------------------------------------------------------------------

def format_services(protos: ProtoSpec, ports: PortSpec) -> list[str]:
    """Human-readable service strings, e.g. ["tcp/443"], ["any"], ["icmp"]."""
    if isinstance(protos, Unresolved):
        return [f"unresolved:{protos.raw}/{format_ports(ports)}"]
    p = format_ports(ports)
    if isinstance(ports, Unresolved):
        p = f"unresolved:{ports.raw}" if not ports.raw.lower().startswith(
            ("unresolved:", "unknown:", "alias:")) else ports.raw
    if protos == ANY:
        return ["any"] if ports == ANY else [f"any/{p}"]
    out = []
    for proto in sorted(protos):
        if proto in PORT_PROTOCOLS:
            out.append(f"{proto}/{p}" if ports != ANY else f"{proto}/any")
        else:
            out.append(proto)
    return out


# ---------------------------------------------------------------------------
# B-07: FortiOS zones (FirewallZoneDef) - implemented once in
# app.parsers.fortios_zones; re-exported here for existing callers.
# ---------------------------------------------------------------------------

from app.parsers.fortios_zones import (  # noqa: E402,F401  (re-exported)
    ANY_ZONE_TOKENS, ZoneDefIndex, expand_zone_tokens, load_zone_defs,
    zone_lookup, zone_tokens,
)
