"""
Firewall rule shadow / redundancy analysis.

Identifies rules within a single firewall device's policy list that are
either completely or partially eclipsed by an earlier rule — meaning the
shadowed rule can never (or only sometimes) be reached, regardless of
observed traffic.

SHADOW TYPES
------------
  full_shadow    — Rule B is completely eclipsed by rule A: every packet
                   that would match B is already matched by A first.  B can
                   never fire.  This is unambiguous dead code.

  partial_shadow — Rule A covers a strict subset of B's traffic.  Some
                   packets will still reach B, but the overlap means A's
                   action silently overrides B's for that subset.  Dangerous
                   when A=permit and B=deny (or vice versa): the intent of
                   one rule is silently defeated for the overlapping traffic.

  duplicate      — A and B match the same traffic AND have the same action.
                   One is redundant; B (lower priority) can never add value.

  exception      — (T3-38) A is strictly NARROWER than B with the opposite
                   action, e.g. ``permit 10.0.0.5/32`` before
                   ``deny 10.0.0.0/24``.  This is the normal, intended
                   carve-out pattern, not a silent override, so it is NOT
                   reported in ``shadows`` and never becomes a Finding; it is
                   listed in the separate informational ``exceptions`` list.

SEVERITY (T3-38) — every shadow dict carries ``severity`` and generated
Findings use it (instead of the single CHECK_TYPE_REFERENCE default):
  full_shadow, deny hidden by an earlier permit   → high   (the deny is ineffective)
  full_shadow, permit hidden by an earlier deny   → medium (dead permit)
  partial_shadow, deny partly overridden by permit→ medium
  partial_shadow, permit partly hidden by deny    → low
  duplicate                                       → low

ZONES (T3-38) — src_zone / dst_zone are treated as SETS of interface/zone
names ("port1,port2", "port1 port2", "['a','b']"); "any"/"all"/NULL/empty
is the universe.  An earlier rule on "any" or "port1,port2" covers a later
rule on "port1"; rules whose zone sets are disjoint never shadow each other.

EVALUATION RULES
----------------
  - Rules are sorted by rule_order ASC (FortiOS policy_id, Cisco ACL line
    number, or positional ingest order).  NULL rule_order rules sort LAST
    and are treated as low-priority.
  - Only rules from the SAME device (same firewall_device_id, or same
    device_name when firewall_device_id is NULL) are compared against each
    other.  Inter-device shadowing is a reachability question, not a shadow
    question.
  - Address/port/protocol parsing uses app.parsers.rule_match (canonical
    "80,443,1000-2000" port lists plus legacy forms, port ranges instead of
    int sets; IPv4 vs IPv6 networks are disjoint (F-07): 0.0.0.0/0 is all of
    IPv4, ::/0 all of IPv6, "any" both; address lists parse as sets).  Unresolvable rules (named
    objects, PAN-OS address groups not expanded) cannot be checked for
    superset relationships — they are returned in a separate
    ``unanalysed_rules`` list rather than silently skipped or falsely flagged.
  - Protocol matching: when rule A's protocol is "any", it is a superset of
    every protocol in rule B (including "any").  If rule A's protocol is
    "unknown" (an unresolved PAN-OS service object), the relationship cannot
    be determined → reported in unanalysed_rules.

LIMITATIONS
-----------
  - B-07: FortiOS zone names (FirewallZoneDef: `config system zone`,
    SD-WAN zones) are expanded to their member interfaces before the set
    comparison; an empty zone matches no interface.  A zone whose
    membership could not be parsed is compared by name (other vendors'
    zone names are always compared by name).
  - Cisco ACLs: a named ACL applied to multiple interfaces can have rules
    that appear to shadow each other in this analysis but are actually
    applied independently per interface.  Since the current parser stores
    one rule_order sequence per ACL name, the analysis is still correct at
    the ACL level.

UNION COVERAGE (A-31)
---------------------
  A later rule that no single earlier rule covers, but that the UNION of
  earlier rules covers (e.g. permit 10.0.0.0/25 + permit 10.0.0.128/25
  before deny 10.0.0.0/24), is reported as ONE full_shadow (or duplicate,
  when every covering rule has the same action) with ``union_coverage``
  True and every covering rule in ``shadowing_rules`` (``shadowing_rule``
  is the first); the per-rule partial shadows for that rule are dropped.
  Only earlier rules whose zone sets contain the later rule's take part.
  Coverage is exact over src x dst x port x protocol (box subtraction,
  capped at 4096 pieces -> "not covered", never a false full shadow).
  Rows sharing a rule_order are expansions of one logical rule and are
  never compared with each other.

COMPLEXITY
----------
  Earlier rules are indexed by coarse address blocks (IPv4 /16, IPv6 /32)
  of their src and dst sides; a later rule is compared only with earlier
  rules sharing a block on its narrow side plus the "wide" ones.  Worst
  case (every rule wide on both sides) is still O(n^2); typical 5 000-rule
  policies take seconds.
"""
import ipaddress
import logging
import re
from typing import Optional

from sqlalchemy.orm import Session as DBSession, joinedload

from app.models import FirewallDevice, FirewallRule
from app.parsers import rule_match as rm
from app.parsers.site_scope import current_site, scope_module

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Address / port superset helpers
#
# Specs come from app.parsers.rule_match: rm.ANY, an ip_network, a tuple of
# (lo, hi) port ranges, or rm.Unresolved.  ``None`` is also accepted as
# "unresolvable" for backward compatibility.  Networks of different IP
# versions are disjoint (T1-33: subnet_of() used to raise TypeError).
# ---------------------------------------------------------------------------

def _unres(x) -> bool:
    return x is None or isinstance(x, rm.Unresolved)


def _addr_is_superset_or_equal(a_spec, b_spec) -> Optional[bool]:
    """True if every IP matching b_spec also matches a_spec; None if unresolvable."""
    if _unres(a_spec) or _unres(b_spec):
        return None
    return rm.addr_contains(a_spec, b_spec)


def _addr_overlaps(a_spec, b_spec) -> Optional[bool]:
    """True if the two address specs share at least one address."""
    if _unres(a_spec) or _unres(b_spec):
        return None
    return rm.addr_overlaps(a_spec, b_spec)


def _port_overlaps(a_port, b_port) -> Optional[bool]:
    """Returns True if the two port specs share at least one port."""
    if _unres(a_port) or _unres(b_port):
        return None
    return rm.ports_overlap(a_port, b_port)


def _port_is_superset_or_equal(a_port, b_port) -> Optional[bool]:
    """True if every port in b_port is also in a_port; None if unresolvable."""
    if _unres(a_port) or _unres(b_port):
        return None
    return rm.ports_contain(a_port, b_port)


def _protocol_is_superset_or_equal(a_proto: Optional[str], b_proto: Optional[str]) -> Optional[bool]:
    """
    Returns True  if a_proto covers everything b_proto covers.
    Returns None  if either is "unknown" (unresolved service object).
    """
    return rm.protos_contain(rm.parse_protocols(a_proto), rm.parse_protocols(b_proto))


def _protocol_overlaps(a_proto: Optional[str], b_proto: Optional[str]) -> Optional[bool]:
    return rm.protos_overlap(rm.parse_protocols(a_proto), rm.parse_protocols(b_proto))


# ---------------------------------------------------------------------------
# Zone context comparison (FortiGate / PAN-OS)
# ---------------------------------------------------------------------------

_ANY_ZONE_TOKENS = {"any", "all", "*"}
ZONE_ANY = None  # universe


def parse_zones(zone: Optional[str]):
    """Zone field -> frozenset of lower-cased names, or ZONE_ANY (None) for
    the universe ("any"/"all"/NULL/empty).

    C-05: split on the comma that separates srcintf / dstintf list elements,
    not on whitespace - an interface / zone name may contain spaces ("IT
    Zone"), and shattering it produced spurious token overlap (e.g. "IT Zone"
    and "OT Zone" both yielding "zone") and so false shadow findings."""
    if zone is None:
        return ZONE_ANY
    toks = {t.strip().strip("'\"[]").lower() for t in str(zone).split(",")}
    toks.discard("")
    if not toks or toks & _ANY_ZONE_TOKENS:
        return ZONE_ANY
    return frozenset(toks)


def _zones_contain(outer, inner) -> bool:
    if outer is ZONE_ANY:
        return True
    if inner is ZONE_ANY:
        return False
    return inner <= outer


def _zones_overlap(a, b) -> bool:
    if a is ZONE_ANY or b is ZONE_ANY:
        return True
    return bool(a & b)


def _zones_match(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """True if the two rules' zone contexts can see the same packet
    (src and dst zone sets both overlap; "any"/NULL = every zone)."""
    return (_zones_overlap(parse_zones(rule_a.src_zone), parse_zones(rule_b.src_zone))
            and _zones_overlap(parse_zones(rule_a.dst_zone), parse_zones(rule_b.dst_zone)))


_PERMIT_ACTIONS = {"permit", "allow", "accept", "pass"}


def _is_permit(action: Optional[str]) -> bool:
    return (action or "").strip().lower() in _PERMIT_ACTIONS


def _shadow_severity(shadow_type: str, earlier_permit: bool, later_permit: bool) -> str:
    if shadow_type == "duplicate":
        return "low"
    if shadow_type == "full_shadow":
        # deny hidden by an earlier permit: the deny never takes effect
        return "high" if earlier_permit and not later_permit else "medium"
    if shadow_type == "partial_shadow":
        return "medium" if earlier_permit and not later_permit else "low"
    return "info"


# ---------------------------------------------------------------------------
# Per-rule parsed representation (extends ParsedRule with zone + order)
# ---------------------------------------------------------------------------


def _pl(rule) -> str:
    """Display identity of a rule: policy id (or row id), plus its VDOM when
    it has one (N-24: ids are only unique within a VDOM)."""
    base = str(rule.policy_id or rule.id)
    vd = getattr(rule, "vdom", None)
    return f"{base} (vdom {vd})" if vd is not None else base


def _pl_d(rule_dict: dict) -> str:
    base = str(rule_dict.get("policy_id") or rule_dict.get("rule_id"))
    vd = rule_dict.get("vdom")
    return f"{base} (vdom {vd})" if vd is not None else base


class _AnalysedRule:
    """Wraps a FirewallRule with pre-parsed specs and an effective order."""

    def __init__(self, rule: FirewallRule, effective_order: int,
                 zone_defs: Optional[dict] = None):
        self.rule = rule
        self.effective_order = effective_order
        # F-07: 0.0.0.0/0 and ::/0 cover one address family each (T3-38
        # treated them as "any"); "any" next to a single-family side is
        # narrowed to that family so v4 and v6 rules never shadow each other.
        self.src, self.dst = rm.narrow_rule_family(rm.parse_address(rule.src),
                                                   rm.parse_address(rule.dst))
        self.port = rm.parse_ports(rule.dst_port)
        self._proto = (rule.protocol or "any").lower().strip()
        self.protos = rm.parse_protocols(self._proto)
        self.src_zones = parse_zones(rule.src_zone)
        self.dst_zones = parse_zones(rule.dst_zone)
        if zone_defs:
            # B-07: FortiOS zone names -> their member interfaces, so a zone
            # and an interface (or two zones) are compared by membership.
            zmap = zone_defs.get((rule.firewall_id, getattr(rule, "vdom", None)))
            if zmap:
                self.src_zones, _ = rm.expand_zone_tokens(self.src_zones, zmap)
                self.dst_zones, _ = rm.expand_zone_tokens(self.dst_zones, zmap)
        self.permit = _is_permit(rule.action)
        # H-10: identity-based rule (user groups) - None = any user
        ident = getattr(rule, "src_identity", None)
        self.identity = (frozenset(x.strip().lower() for x in str(ident).split(",") if x.strip())
                         if ident else None)

    def identity_covers(self, other: "_AnalysedRule") -> bool:
        """This rule's users include every user ``other`` matches (an
        IP-only rule covers everyone; an identity rule never covers an IP-only
        one or one for other groups)."""
        if self.identity is None:
            return True
        return other.identity is not None and other.identity <= self.identity

    @property
    def is_analysable(self) -> bool:
        """All specs must be resolvable AND protocol must not be "unknown"."""
        return (
            not _unres(self.src)
            and not _unres(self.dst)
            and not _unres(self.port)
            and not isinstance(self.protos, rm.Unresolved)
        )

    def prepare(self):
        """A-31: pre-compute the geometric form used by the union-coverage
        check and the coarse address buckets used by the candidate index."""
        self.src_iv = _addr_ivals(self.src)
        self.dst_iv = _addr_ivals(self.dst)
        self.port_iv = rm.FULL_RANGE if self.port == rm.ANY else tuple(self.port)
        self.proto_set = _P_ANY if self.protos == rm.ANY else (False, frozenset(self.protos))
        self.src_buckets = _buckets(self.src_iv)
        self.dst_buckets = _buckets(self.dst_iv)

    def _rule_summary(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "device_name": self.rule.device_name,
            "firewall_device_id": self.rule.firewall_device_id,
            "policy_id": self.rule.policy_id,
            "vdom": getattr(self.rule, "vdom", None),
            "policy_name": self.rule.policy_name,
            "rule_order": self.rule.rule_order,
            "effective_order": self.effective_order,
            "action": self.rule.action,
            "src": self.rule.src,
            "dst": self.rule.dst,
            "protocol": self.rule.protocol,
            "dst_port": self.rule.dst_port,
            "src_zone": self.rule.src_zone,
            "dst_zone": self.rule.dst_zone,
        }


# ---------------------------------------------------------------------------
# Shadow check between two rules
# ---------------------------------------------------------------------------

def _check_shadow(earlier: _AnalysedRule, later: _AnalysedRule) -> Optional[dict]:
    """
    Check whether ``earlier`` shadows ``later``.

    Returns a finding dict if a shadow relationship is found, or None.
    Both rules must be analysable and share zone context (caller checks).
    """
    if not (_zones_overlap(earlier.src_zones, later.src_zones)
            and _zones_overlap(earlier.dst_zones, later.dst_zones)):
        return None
    # H-10: rules for different user groups match different sessions - an
    # earlier rule only shadows a later one whose users it covers
    if not earlier.identity_covers(later):
        return None
    src_sup = _addr_is_superset_or_equal(earlier.src, later.src)
    dst_sup = _addr_is_superset_or_equal(earlier.dst, later.dst)
    port_sup = _port_is_superset_or_equal(earlier.port, later.port)
    proto_sup = rm.protos_contain(earlier.protos, later.protos)
    zone_sup = (_zones_contain(earlier.src_zones, later.src_zones)
                and _zones_contain(earlier.dst_zones, later.dst_zones))

    # Any None means we can't determine the relationship
    if None in (src_sup, dst_sup, port_sup, proto_sup):
        return None
    same_action = earlier.permit == later.permit

    if src_sup and dst_sup and port_sup and proto_sup and zone_sup:
        # earlier is a superset of later in all dimensions
        if same_action:
            shadow_type = "duplicate"
            description = (
                f"Rule {_pl(later.rule)} is a duplicate of "
                f"rule {_pl(earlier.rule)}: identical traffic "
                f"match and same action='{earlier.rule.action}'. The later rule can "
                f"never fire."
            )
        else:
            shadow_type = "full_shadow"
            description = (
                f"Rule {_pl(later.rule)} (action={later.rule.action}) "
                f"is fully shadowed by rule {_pl(earlier.rule)} "
                f"(action={earlier.rule.action}): the earlier rule matches a superset of "
                f"the later rule's traffic. The later rule can never fire."
            )
        return {
            "shadow_type": shadow_type,
            "severity": _shadow_severity(shadow_type, earlier.permit, later.permit),
            "description": description,
            "shadowing_rule": earlier._rule_summary(),
            "shadowed_rule": later._rule_summary(),
            "action_conflict": not same_action,
        }

    # Check for partial shadow: earlier covers SOME but not all of later's traffic
    # A partial shadow exists when there is any overlap, i.e. at least one
    # dimension where earlier is a superset and no dimension where they
    # are completely disjoint.
    #
    # Disjoint detection: if src/dst/port/proto sets are mutually exclusive,
    # no packet can match both — not a shadow at all.
    # We detect disjoint via the inverse: if b's spec is NOT a superset of a
    # AND a's spec is NOT a superset of b for a dimension, they may overlap
    # or be disjoint.  Full disjoint detection (e.g. two non-overlapping
    # CIDRs) would require a different test; for now we flag partial shadow
    # only when all dimensions have at least a superset-or-equal relationship
    # in at least one direction.
    #
    # Simplified partial-shadow rule used here:
    #   At least one of (src, dst, port, proto) has earlier ⊇ later (True),
    #   AND at least one has earlier ⊄ later (False),
    #   AND we cannot confirm disjoint in any dimension.
    #
    # This catches the common dangerous case: permit any → deny host X where
    # the permit precedes the deny (src is superset: any ⊇ host X, but port
    # may differ, so not a full shadow — still a partial shadow worth flagging
    # when actions differ).

    any_superset = src_sup or dst_sup or port_sup or proto_sup
    any_not_superset = not (src_sup and dst_sup and port_sup and proto_sup and zone_sup)

    # Before declaring a partial shadow, verify actual overlap exists
    # in EVERY dimension.  Two completely disjoint rules (e.g. different /24
    # subnets) would pass the superset tests above but have zero packets in
    # common — that is NOT a shadow.  An overlap is required in all four
    # dimensions simultaneously for the partial shadow to be real.
    if any_superset and any_not_superset and not same_action:
        src_overlaps = _addr_overlaps(earlier.src, later.src)
        dst_overlaps = _addr_overlaps(earlier.dst, later.dst)
        port_overlaps = _port_overlaps(earlier.port, later.port)
        # Protocol overlap: "any" overlaps with everything; else must match
        proto_overlaps = rm.protos_overlap(earlier.protos, later.protos)
        if not all(x is True for x in (src_overlaps, dst_overlaps, port_overlaps, proto_overlaps)):
            # Rules are disjoint in at least one dimension — no shadow possible
            return None

        # Exception pattern (T3-38): the earlier rule is entirely INSIDE the
        # later one (narrower in every dimension) with the opposite action -
        # "permit 10.0.0.5/32; deny 10.0.0.0/24".  That is the intended way
        # to carve an exception out of a broader rule, not a silent override.
        inner_sub = (
            rm.addr_contains(later.src, earlier.src) is True
            and rm.addr_contains(later.dst, earlier.dst) is True
            and rm.ports_contain(later.port, earlier.port) is True
            and rm.protos_contain(later.protos, earlier.protos) is True
            and _zones_contain(later.src_zones, earlier.src_zones)
            and _zones_contain(later.dst_zones, earlier.dst_zones)
        )
        if inner_sub:
            return {
                "shadow_type": "exception",
                "severity": "info",
                "description": (
                    f"Rule {_pl(earlier.rule)} "
                    f"(action={earlier.rule.action}) is a narrower exception carved out "
                    f"of rule {_pl(later.rule)} "
                    f"(action={later.rule.action}). This is the normal exception "
                    f"pattern and is not a shadow."
                ),
                "shadowing_rule": earlier._rule_summary(),
                "shadowed_rule": later._rule_summary(),
                "action_conflict": True,
            }

        # Only flag action-conflicting partial shadows — same-action partials
        # are not dangerous, just slightly inefficient (the later rule still
        # fires for traffic that doesn't match the earlier one).
        return {
            "shadow_type": "partial_shadow",
            "severity": _shadow_severity("partial_shadow", earlier.permit, later.permit),
            "description": (
                f"Rule {_pl(later.rule)} "
                f"(action={later.rule.action}) is partially shadowed by rule "
                f"{_pl(earlier.rule)} "
                f"(action={earlier.rule.action}): the earlier rule's traffic match "
                f"overlaps with the later rule's match in at least one dimension "
                f"(src_superset={src_sup}, dst_superset={dst_sup}, "
                f"port_superset={port_sup}, proto_superset={proto_sup}). "
                f"Traffic in the overlap is governed by the earlier rule's action, "
                f"silently overriding the later rule's intent for that subset."
            ),
            "shadowing_rule": earlier._rule_summary(),
            "shadowed_rule": later._rule_summary(),
            "action_conflict": True,
            "overlap_dimensions": {
                "src": src_sup,
                "dst": dst_sup,
                "port": port_sup,
                "protocol": proto_sup,
            },
        }

    return None



# ---------------------------------------------------------------------------
# A-31: geometric (box) representation for union coverage + candidate index
#
# A rule is a box over four dimensions: src addresses, dst addresses,
# dst ports, protocols.  Addresses of both families live on ONE integer line
# (IPv6 shifted past the IPv4 space) so a dimension is a sorted tuple of
# disjoint closed intervals; protocols are (negated, frozenset) so "any"
# and "any except tcp" are representable.  Subtracting a box from a box
# yields at most four boxes, so the union of the earlier rules covering a
# later rule can be computed by repeated subtraction (capped, see
# _UNION_PIECE_CAP - when the cap is hit the result is "not covered",
# never a false full shadow).
# ---------------------------------------------------------------------------

_V6_OFF = 1 << 33
_V4_MAX = (1 << 32) - 1
_ANY_ADDR = ((0, _V4_MAX), (_V6_OFF, _V6_OFF + (1 << 128) - 1))
_P_ANY = (True, frozenset())
_UNION_PIECE_CAP = 4096
_BUCKET_MAX = 16          # a side touching more coarse blocks is "wide"


def _addr_ivals(spec) -> tuple:
    if spec == rm.ANY:
        return _ANY_ADDR
    out = []
    for v, iv in rm.addr_intervals(spec).items():
        off = 0 if v == 4 else _V6_OFF
        out += [(lo + off, hi + off) for lo, hi in iv]
    return tuple(sorted(out))


def _buckets(ivals) -> Optional[frozenset]:
    """Coarse blocks (IPv4 /16, IPv6 /32) an address side touches, or None
    when it touches more than _BUCKET_MAX (indexed as "wide")."""
    keys = set()
    for lo, hi in ivals:
        if lo >= _V6_OFF:
            a, b, tag = (lo - _V6_OFF) >> 96, (hi - _V6_OFF) >> 96, 6
        else:
            a, b, tag = lo >> 16, hi >> 16, 4
        if b - a + len(keys) >= _BUCKET_MAX:
            return None
        keys.update((tag, k) for k in range(a, b + 1))
    return frozenset(keys)


def _iv_inter(a, b) -> tuple:
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def _iv_sub(a, b) -> tuple:
    out = []
    for lo, hi in a:
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return tuple(out)


def _p_inter(a, b):
    (na, sa), (nb, sb) = a, b
    if na and nb:
        return (True, sa | sb)
    if na:
        return (False, sb - sa)
    if nb:
        return (False, sa - sb)
    return (False, sa & sb)


def _p_sub(a, b):
    return _p_inter(a, (not b[0], b[1]))


def _p_empty(p) -> bool:
    return not p[0] and not p[1]


_DIM_OPS = ((_iv_inter, _iv_sub, lambda x: not x),) * 3 + ((_p_inter, _p_sub, _p_empty),)


def _box(ar) -> tuple:
    return (ar.src_iv, ar.dst_iv, ar.port_iv, ar.proto_set)


def _box_overlaps(a, b) -> bool:
    return all(not empty(inter(x, y)) for (inter, _s, empty), x, y in zip(_DIM_OPS, a, b))


def _box_subtract(r, c) -> list:
    """r minus c as a list of disjoint boxes (<= 4)."""
    if not _box_overlaps(r, c):
        return [r]
    out, cur = [], list(r)
    for i, (inter, sub, empty) in enumerate(_DIM_OPS):
        rest = sub(cur[i], c[i])
        if not empty(rest):
            piece = list(cur)
            piece[i] = rest
            out.append(tuple(piece))
        cur[i] = inter(cur[i], c[i])
    return out


def _union_covers(target, cutters) -> Optional[list]:
    """Indices of the cutters that together cover ``target`` (in order),
    or None if the union does not cover it (or the piece cap is hit)."""
    region, used = [target], []
    for k, c in enumerate(cutters):
        nxt, hit = [], False
        for r in region:
            parts = _box_subtract(r, c)
            if len(parts) != 1 or parts[0] is not r:
                hit = True
            nxt += parts
        if hit:
            used.append(k)
        region = nxt
        if not region:
            return used
        if len(region) > _UNION_PIECE_CAP:
            return None
    return None


def _same_logical_rule(a: "_AnalysedRule", b: "_AnalysedRule") -> bool:
    """Rows sharing a rule_order are expansions of ONE logical rule (e.g. a
    multi-service policy stored as several rows) - never compared."""
    return a.rule.rule_order is not None and a.rule.rule_order == b.rule.rule_order


def _union_finding(later: "_AnalysedRule", covering: list) -> dict:
    conflict = any(c.permit != later.permit for c in covering)
    if conflict:
        shadow_type = "full_shadow"
        severity = ("high" if not later.permit and any(c.permit for c in covering)
                    else "medium")
    else:
        shadow_type = "duplicate"
        severity = "low"
    ids = ", ".join(str(_pl(c.rule)) for c in covering)
    return {
        "shadow_type": shadow_type,
        "severity": severity,
        "description": (
            f"Rule {_pl(later.rule)} (action={later.rule.action}) "
            f"can never fire: the UNION of earlier rules {ids} matches all of its "
            f"traffic, although no single earlier rule does."
        ),
        "shadowing_rule": covering[0]._rule_summary(),
        "shadowing_rules": [c._rule_summary() for c in covering],
        "shadowed_rule": later._rule_summary(),
        "action_conflict": conflict,
        "union_coverage": True,
    }

# ---------------------------------------------------------------------------
# Per-device analysis
# ---------------------------------------------------------------------------

def _analyse_group(rules: list[FirewallRule], include_partial: bool,
                   zone_defs: Optional[dict] = None):
    """Analyse one device's policy list.
    Returns (shadows, unanalysed, n_analysed, exceptions)."""
    shadows: list[dict] = []
    exceptions: list[dict] = []
    unanalysed: list[dict] = []
    # Sort by rule_order ASC (nulls last = lowest priority)
    sorted_rules = sorted(
        rules,
        key=lambda r: (r.rule_order is None, r.rule_order if r.rule_order is not None else 0),
    )

    analysed: list[_AnalysedRule] = []
    for seq, rule in enumerate(sorted_rules):
        ar = _AnalysedRule(rule, effective_order=seq, zone_defs=zone_defs)
        if ar.is_analysable:
            analysed.append(ar)
        else:
            unanalysed.append({
                "rule_id": rule.id,
                "device_name": rule.device_name,
                "firewall_device_id": rule.firewall_device_id,
                "policy_id": rule.policy_id,
                "vdom": getattr(rule, "vdom", None),
                "src": rule.src,
                "dst": rule.dst,
                "protocol": rule.protocol,
                "dst_port": rule.dst_port,
                "reason": "src, dst, protocol or dst_port contains an unresolvable named object",
            })

    # A-31: candidate index.  Earlier rules are bucketed by the coarse
    # address blocks of their src and dst sides; a later rule only meets
    # earlier rules sharing a block on its narrow side (plus the "wide"
    # ones), which are the only ones that can overlap it.
    for ar in analysed:
        ar.prepare()
    src_idx: dict = {}
    dst_idx: dict = {}
    src_wide: list = []
    dst_wide: list = []
    for i, later in enumerate(analysed):
        if later.src_buckets is not None:
            cand = set(src_wide)
            for b in later.src_buckets:
                cand.update(src_idx.get(b, ()))
        elif later.dst_buckets is not None:
            cand = set(dst_wide)
            for b in later.dst_buckets:
                cand.update(dst_idx.get(b, ()))
        else:
            cand = range(i)
        lbox = _box(later)
        pending: list = []
        cutters: list = []
        single_cover = False
        for j in sorted(cand):
            earlier = analysed[j]
            if _same_logical_rule(earlier, later):
                continue
            ebox = _box(earlier)
            if not _box_overlaps(ebox, lbox):
                continue
            if (_zones_contain(earlier.src_zones, later.src_zones)
                    and _zones_contain(earlier.dst_zones, later.dst_zones)
                    and earlier.identity_covers(later)):
                cutters.append(earlier)
            finding = _check_shadow(earlier, later)
            if finding is None:
                continue
            st = finding["shadow_type"]
            if st == "exception":
                exceptions.append(finding)
                continue
            if st in ("full_shadow", "duplicate"):
                single_cover = True
            pending.append(finding)
        if not single_cover and len(cutters) >= 2:
            used = _union_covers(lbox, [_box(c) for c in cutters])
            if used is not None:
                # One full shadow replaces the per-rule partial shadows.
                pending = [_union_finding(later, [cutters[k] for k in used])]
        for finding in pending:
            if finding["shadow_type"] == "partial_shadow" and not include_partial:
                continue
            shadows.append(finding)
        # index this rule for the rules after it
        if later.src_buckets is None:
            src_wide.append(i)
        else:
            for b in later.src_buckets:
                src_idx.setdefault(b, []).append(i)
        if later.dst_buckets is None:
            dst_wide.append(i)
        else:
            for b in later.dst_buckets:
                dst_idx.setdefault(b, []).append(i)
    return shadows, unanalysed, len(analysed), exceptions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_shadowed_rules(
    db: DBSession,
    device_name: Optional[str] = None,
    firewall_device_id: Optional[int] = None,
    include_partial: bool = True,
    generate_findings: bool = False,
) -> dict:
    """
    Analyse the FirewallRule table for shadow / redundancy relationships.

    Parameters
    ----------
    device_name         Filter to one device by name (device_name column).
    firewall_device_id  Filter to one FirewallDevice by id (more precise).
    include_partial     Include partial shadows (action-conflicting overlaps).
                        True by default; set False for full-shadow/duplicate only.
    generate_findings   Write Finding rows for each shadow found (uses the
                        'shadow_rule' check_name already in CHECK_TYPE_REFERENCE).

    Returns
    -------
    {
        "shadows":           [shadow dicts (each with "severity"), by device then order],
        "exceptions":        [narrower opposite-action rules before a broader
                              rule - intended carve-outs, info only, no Finding],
        "unanalysed_rules":  [rules skipped due to unresolvable specs],
        "rules_analysed":    int,
        "rules_unanalysed":  int,
        "devices_analysed":  int,
        "findings_created":  int,   # 0 unless generate_findings=True
        "devices_failed":    [{"group", "error"}],  # devices skipped after an error
    }
    """
    # Disabled rules enforce nothing: they can neither shadow nor be shadowed
    # (they are flagged separately by review_disabled_rules).
    query = db.query(FirewallRule).filter(FirewallRule.enabled.is_(True))
    if firewall_device_id is not None:
        query = query.filter(FirewallRule.firewall_device_id == firewall_device_id)
    elif device_name is not None:
        query = query.filter(FirewallRule.device_name == device_name)

    all_rules = query.all()

    # Group rules by their owning device.
    # Priority: firewall_device_id → device_name (for legacy rules without a
    # FirewallDevice row).  Each group is one policy list with first-match ordering.
    # N-24: a FortiGate VDOM is its own policy list (ids and order are per
    # VDOM), so the VDOM is part of the group key (3rd element, NULL = none).
    groups: dict[tuple, list[FirewallRule]] = {}
    for rule in all_rules:
        vdom = getattr(rule, "vdom", None)
        if rule.firewall_device_id is not None:
            key = ("device_id", rule.firewall_device_id, vdom)
        else:
            key = ("device_name", rule.device_name or "unknown", vdom)
        groups.setdefault(key, []).append(rule)

    shadows = []
    exceptions: list[dict] = []
    unanalysed = []
    total_analysed = 0
    total_unanalysed = 0
    devices_analysed = len({k[:2] for k in groups})

    devices_failed: list[dict] = []
    zone_defs = rm.load_zone_defs(db, {r.firewall_id for r in all_rules
                                       if r.firewall_id is not None})
    for group_key, rules in groups.items():
        # T1-33: one malformed device must not abort analysis of all others.
        try:
            g_shadows, g_unanalysed, g_analysed, g_exceptions = _analyse_group(
                rules, include_partial, zone_defs)
        except Exception as exc:
            log.exception("Shadow analysis failed for %s=%s", group_key[0], group_key[1])
            devices_failed.append({
                "group": f"{group_key[0]}:{group_key[1]}"
                         + (f"/vdom:{group_key[2]}" if group_key[2] is not None else ""),
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        shadows.extend(g_shadows)
        exceptions.extend(g_exceptions)
        unanalysed.extend(g_unanalysed)
        total_analysed += g_analysed
        total_unanalysed += len(g_unanalysed)

    # Optionally write Finding rows
    findings_created = 0
    if generate_findings and shadows:
        from datetime import datetime, timezone
        from app.models import Finding, CHECK_TYPE_REFERENCE

        sr, checklist_id, default_severity, category = CHECK_TYPE_REFERENCE["shadow_rule"]
        now = datetime.now(timezone.utc)

        for s in shadows:
            sr_rule = s["shadowed_rule"]
            sh_rule = s["shadowing_rule"]
            source_ref = f"shadow:{sh_rule['rule_id']}:{sr_rule['rule_id']}"
            # T3-38: severity depends on the shadow type / action direction
            severity = s.get("severity") or default_severity

            # Check for ANY existing row with this source_ref, not only
            # open/acknowledged.  If we only skip open+acknowledged, a "closed"
            # finding will cause an IntegrityError on the unique constraint.
            # Re-open a closed finding instead of inserting a duplicate.
            existing = db.query(Finding).filter(
                Finding.source_ref == source_ref,
            ).first()
            if existing:
                if existing.status == "closed":
                    from datetime import datetime, timezone as _tz
                    existing.status = "open"
                    existing.severity = severity
                    existing.updated_at = datetime.now(_tz.utc)
                    findings_created += 1
                continue

            f = Finding(
                category=category,
                check_name="shadow_rule",
                severity=severity,
                status="open",
                isa62443_sr=sr,
                checklist_id=checklist_id,
                title=(
                    f"[{s['shadow_type'].replace('_', ' ').title()}] "
                    f"Rule {_pl_d(sr_rule)} shadowed by "
                    f"rule {_pl_d(sh_rule)} "
                    f"on {sr_rule.get('device_name') or 'unknown device'}"
                ),
                detail={
                    "shadow_type": s["shadow_type"],
                    "severity_reason": s["shadow_type"] + (
                        ": deny ineffective (hidden by earlier permit)"
                        if s["shadow_type"] != "duplicate"
                        and _is_permit(sh_rule.get("action")) and not _is_permit(sr_rule.get("action"))
                        else ""),
                    "action_conflict": s.get("action_conflict", False),
                    "shadowing_rule": sh_rule,
                    "shadowed_rule": sr_rule,
                    "description": s["description"],
                },
                device_name=sr_rule.get("device_name"),
                source_ref=source_ref,
                created_at=now,
                updated_at=now,
                site_id=current_site(db),
            )
            db.add(f)
            findings_created += 1

        if findings_created:
            db.commit()

    return {
        "shadows": shadows,
        "exceptions": exceptions,   # T3-38: intended carve-outs, informational only
        "unanalysed_rules": unanalysed,
        "rules_analysed": total_analysed,
        "rules_unanalysed": total_unanalysed,
        "devices_analysed": devices_analysed,
        "findings_created": findings_created,
        "devices_failed": devices_failed,
    }


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("find_",))
