"""
Cross-level reachability analysis.

Determines which Purdue-level zones can communicate with each other through
the chain of boundary-tagged firewalls, and (optionally) traces the specific
permit/deny path for a given source host IP and destination IP or Purdue
level.

REACHABILITY MODEL
------------------
Each enforcement point sits on the boundary between two Purdue levels.  It is
either
  - a FirewallDevice with purdue_zone_from / purdue_zone_to set, or
  - a FirewallDevice whose linked Firewall (firewall_id) has
    purdue_level_ingress / purdue_level_egress set, or
  - a Firewall with ingress/egress levels and no FirewallDevice row at all
    (rules found via FirewallRule.firewall_id).
  - a "multi-leg" firewall: no explicit boundary, but its FirewallInterfaces
    carry >=2 distinct purdue_levels -> one enforcement point per unordered
    level pair (explicit boundaries always win).  Rules on a multi-leg box
    apply to a crossing only if their src/dst side resolves exactly to the
    entering/exiting leg (or is undetermined), and a path never crosses the
    same physical firewall twice.

  nodes  = Purdue levels {0, 1, 2, 3, 3.5, 4, 5} (app.purdue.VALID_LEVELS;
           3.5 = industrial DMZ, a node of its own: a 3-leg firewall with
           L1 / L3.5 / L4 legs, or a chain L4 -[FW]- L3.5 -[FW]- L3, are
           modelled exactly like any other level pair)
  edges  = enforcement points
  permit/deny on an edge = the device's ruleset evaluated in rule_order
  (first-match-wins) for the traffic AND the traversal direction.

IMPLICIT DENY (T1-30)
---------------------
Every supported vendor (FortiOS, PAN-OS, Cisco ACL, pfSense) ends its policy
with an implicit deny.  A device that HAS rules loaded but none of them match
is therefore "deny" with reason_code "implicit_deny".  A device with ZERO
rules loaded is "no_policy" (config not ingested - we don't know).

RULE DIRECTION (T1-32)
----------------------
Each rule's src/dst side is mapped to Purdue level(s):
  1. src_zone / dst_zone (comma/space separated lists allowed, "any" = both)
     matched against FirewallInterface name / alias / zone_label on the same
     firewall_id, a FortiOS zone (FirewallZoneDef of the rule's firewall and
     VDOM, B-07: `config system zone` / SD-WAN zone -> member interfaces),
     or a legacy FirewallZone zone_name whose member interfaces map to a
     FirewallInterface with a purdue_level.  An empty zone matches nothing;
     a zone whose membership could not be parsed makes the rule "uncertain"
     (reported unknown when it could change the result, never denied);
  2. otherwise the src/dst CIDR contained in an interface subnet
     (network_cidr / ip_cidr) with a known purdue_level;
  3. legacy devices (no linked Firewall): FirewallZone subnets / classified
     hosts covered by the rule's addresses (N-05);
  4. otherwise undetermined -> the rule applies in both directions.
A rule applies to a crossing A->B only if its src side is compatible with A's
side of the boundary and its dst side with B's.
FortiOS intrazone (B-07): a crossing whose ingress and egress interfaces are
all members of ONE zone with `set intrazone allow` is permitted when no
policy matches it (an explicit zone->zone policy is evaluated first);
when only some interface pairs are, the implicit deny becomes "unknown".
Intrazone deny (the default) needs a zone->zone policy like any crossing.
NAT order (B-13): NAT rows are evaluated in (sequence, id) order, first
match wins; a central-snat `nat disable` exemption that matches stops the
lookup without translating.

VERDICTS
--------
Per device ("decision"):  "permit" | "deny" | "partial" | "unknown" | "no_policy"
Per boundary / path / cell:
  - "permitted"  - all (any-service) traffic is permitted
  - "partial"    - only specific services / hosts are permitted; see
                   ``permitted_services`` (e.g. ["tcp/443"]) and, per device,
                   ``permitted_scopes``
  - "denied"     - nothing is permitted (explicit or implicit deny)
  - "unknown"    - an unresolvable object could change the result
  - "no_policy"  - no enforcement point / no rules ingested on the boundary

Level-pair queries without port/protocol: rules are walked in order; an
any-service/any-host permit reached before any any-service deny makes the
device "permit" (specific-service denies before it are listed in
``denied_services``); specific permits followed by a deny (explicit or
implicit) make it "partial".  With a port/protocol query, first-match
semantics apply and a rule matches only if its protocol set and port ranges
actually contain the queried ones.

Port parsing lives in app/parsers/rule_match.py (canonical "80,443,1000-2000"
plus legacy forms).  Unresolved service objects ("unknown:NAME",
"alias:NAME", "too-large:GRP", ...) are listed in ``unresolved_rules`` and
make the device "unknown" whenever they could change the outcome (A-04:
fail-unknown, never fail-closed or fail-open).  IPv6 rules never match IPv4 queries and do not stop
evaluation.

MULTI-FIREWALL CHAINING
-----------------------
Several firewalls on the same boundary are ALTERNATIVES (a flow crosses one
of them) unless the operator declared them in series - a paired group, a
confirmed inside -> outside link, or a confirmed upstream chain (MP-01):
declared series boxes are AND-ed.  For a host query the alternatives a
flow cannot cross (no labelled interface network of the box holds either
address while another box's does; or a captured carrier MAC names another
box) are left out.  A path is the AND of its hops; a level pair takes the
most permissive path.

LIMITATIONS
-----------
- Named address objects that were not expanded make a device "unknown" when
  they could change the outcome.
- "partial" results are intersected across hops on host scopes AND services
  (N-05); the surviving pieces are reported as ``permitted_scopes``.
- Addresses: IPv4 and IPv6 are disjoint families; "any" matches both
  (F-07).  Level-pair queries without IPs evaluate one family (IPv4 by
  default).  Address lists ("a,b" / "a b") are address sets.
- NAT (F-05): NatRule rows are applied on host queries (see
  _NAT_POLICY_MATCH for the per-vendor pre/post-NAT policy assumption).
  Level-pair queries (no IPs) translate permitted host scopes through each
  hop's SNAT / DNAT before intersecting downstream (A-06); inexact
  translations over-approximate to "partial", never "denied".  On pre-NAT
  vendors a rule's VIP destination takes the mapped address's level for
  direction inference (A-05).
- NAT-aware level-pair cells (N-25): an unrestricted source / destination
  scope is translated too (reported under its ORIGINAL addresses, with
  ``translated_scopes`` giving the far-side view); central-snat protocol /
  dst-addr limits narrow the translated copy.  An interface-mode SNAT
  ("interface:<name>") resolves to that FirewallInterface's address when
  known.  Cells and paths carry ``nat_dependent`` / ``nat_notes`` when an
  enabled NAT row on the path could not be applied exactly (unknown
  interface address, unresolved ippool, translation covering only part of
  the scope, address-family translation).
- Address-family translation (VIP46 / VIP64, policy46 / policy64 pools,
  N-25): a cross-family policy row cannot match a level-pair query, so a
  "denied" that only such a row could have turned into a permit - or a deny
  that lies beyond an applicable family-translating NAT - is reported
  "unknown" (NAT-dependent), never "denied".  With concrete host addresses
  the translation is applied hop by hop as for any DNAT.
- VDOMs (N-24): a firewall's rules are evaluated per VDOM (policy ids and
  order are per VDOM) and the VDOM results OR-ed; inter-VDOM links are not
  followed.  Central-snat assumptions are documented on
  forti_config_parser._central_snat_rows.
- Legacy FirewallDevice rows without a linked Firewall derive rule direction
  from FirewallZone subnets (level = classified hosts inside) or from the
  levels of classified hosts the rule's own addresses cover (N-05) before
  falling back to "applies both ways".
- Intra-level traffic is not modelled.
"""
import ipaddress
import itertools
import logging
from collections import defaultdict
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.models import (
    Firewall,
    FirewallDevice,
    FirewallInterface,
    FirewallRule,
    FirewallZone,
    Host,
    NatRule,
)
from app.parsers import fortios_zones as fz
from app.parsers import rule_match as rm
from app.purdue import VALID_LEVELS
from app.parsers.site_scope import scope_module

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_PURDUE_LEVELS = list(VALID_LEVELS)
# B-07: a rule side naming a FortiOS zone whose membership is unknown
_SIDE_UNKNOWN = frozenset({"__unknown_zone__"})
_PERMIT_ACTIONS = {"permit", "allow", "accept", "pass"}
_ANY_ZONE_TOKENS = fz.ANY_ZONE_TOKENS

# A permitted "piece" is (src_scope, dst_scope, protocols, ports); scopes
# are rule_match address specs (rm.ANY = unrestricted).  Pieces are
# intersected hop by hop so a path's verdict reflects the hosts AND services
# that can traverse every hop (N-05), not just the services.
_SVC_ANY = (rm.ANY, rm.ANY, rm.ANY, rm.ANY)


def _normalize_boundary(a: int, b: int) -> tuple[int, int]:
    """Canonical (lo, hi) boundary key."""
    return (min(a, b), max(a, b))


class _EnforcementPoint:
    """A FirewallDevice or Firewall acting on one Purdue boundary."""

    def __init__(self, *, id, name, vendor, zone_from, zone_to, hostname,
                 mgmt_ip, firewall_id, firewall_device_id, source,
                 physical=None, multi_leg=False, interface_levels=None, vdom=None,
                 series_group=None):
        self.id = id
        self.name = name
        self.vendor = vendor
        self.purdue_zone_from = zone_from
        self.purdue_zone_to = zone_to
        self.device_hostname = hostname
        self.mgmt_ip = mgmt_ip
        self.firewall_id = firewall_id
        self.firewall_device_id = firewall_device_id
        self.source = source
        # Identity of the physical box: a multi-leg firewall yields one
        # enforcement point per level pair, all sharing this key.
        self.physical = physical if physical is not None else ("ep", id(self))
        self.multi_leg = multi_leg
        self.interface_levels = sorted(interface_levels or [])
        # LS-02: a routing switch is an ALTERNATIVE path on a boundary it
        # shares with a firewall (a flow crosses one or the other), not one
        # more device in series.
        self.parallel = (vendor or "") == "cisco_l3_switch"
        # VD-01: a FortiGate VDOM is its own enforcement point (its rules
        # only); two VDOMs joined by an inter-VDOM link are IN SERIES on a
        # boundary that spans them.  None = the whole firewall.
        self.vdom = vdom
        # EPs of one box sharing a series_group are AND-ed (in series); the
        # groups of a box are alternatives (OR-ed).  None = the box's only group.
        self.series_group = series_group
        # MP-01: boxes of one boundary are in series only when DECLARED so
        # (paired group, confirmed inside -> outside link, confirmed
        # upstream chain): such boxes share a series_key.  Boxes with no
        # declared relation are ALTERNATIVES - a flow crosses one of them.
        # None = this box only (set by _Context._load).
        self.series_key = None

    @property
    def boundary(self) -> tuple[int, int]:
        return _normalize_boundary(self.purdue_zone_from, self.purdue_zone_to)


def _rule_dict(rule: FirewallRule) -> dict:
    return {
        "rule_id": rule.id,
        "device_name": rule.device_name,
        "firewall_device_id": rule.firewall_device_id,
        "policy_id": rule.policy_id,
        "vdom": getattr(rule, "vdom", None),
        # N-25: src/dst is an ISDB internet-service[6] set = external/internet
        "external_internet": any(rm.is_external_addr_token(x) for x in (rule.src, rule.dst)),
        "policy_name": rule.policy_name,
        "action": rule.action,
        "src": rule.src,
        "dst": rule.dst,
        "protocol": rule.protocol,
        "dst_port": rule.dst_port,
        "rule_order": rule.rule_order,
        "src_zone": rule.src_zone,
        "dst_zone": rule.dst_zone,
    }


def _fw_device_dict(dev) -> dict:
    return {
        "id": dev.id,
        "name": dev.name,
        "vendor": dev.vendor,
        "purdue_zone_from": dev.purdue_zone_from,
        "purdue_zone_to": dev.purdue_zone_to,
        "device_hostname": dev.device_hostname,
        "mgmt_ip": getattr(dev, "mgmt_ip", None),
        "firewall_id": getattr(dev, "firewall_id", None),
        "source": getattr(dev, "source", "firewall_device"),
        "multi_leg": getattr(dev, "multi_leg", False),
        "routing_switch": getattr(dev, "parallel", False),
        "vdom": getattr(dev, "vdom", None),
        "interface_levels": getattr(dev, "interface_levels", []),
    }


def _rule_sort_key(r: FirewallRule):
    return (r.rule_order is None, r.rule_order if r.rule_order is not None else 0, r.id or 0)


# ---------------------------------------------------------------------------
# Verdict algebra
# ---------------------------------------------------------------------------

class _Verdict:
    """Internal verdict: decision + permitted service pieces.

    ``denies`` (MP-10): the device's full-address specific denies as
    (protos, ports) pieces, so a permit on another hop can have them
    subtracted (FW-A permits 443,502; FW-B denies 502 then permits any:
    the path permits 443 only).  ``denied_services`` is their text."""

    __slots__ = ("decision", "services", "denied_services", "denies", "uncertain")

    def __init__(self, decision: str, services=None, denied_services=None, denies=None,
                 uncertain: bool = False):
        self.decision = decision  # permitted|denied|partial|unknown|no_policy
        self.services = list(services or [])
        self.denied_services = list(denied_services or [])
        self.denies = list(denies or [])
        # MP-25: a partial verdict that is the OR of a partial and an UNKNOWN
        # alternative - the service list is a lower bound, not definitive
        self.uncertain = uncertain

    def service_strings(self) -> list[str]:
        if self.decision == "permitted":
            return ["any"]
        if self.decision != "partial":
            return []
        return _dedupe(s for pc in self.services for s in rm.format_services(pc[2], pc[3]))

    def scopes(self) -> list[dict]:
        """Host scopes x services that are permitted (partial verdicts)."""
        if self.decision == "permitted":
            return [{"src": "any", "dst": "any", "services": ["any"]}]
        if self.decision != "partial":
            return []
        out = []
        for src, dst, p, x in self.services:
            d = {"src": rm.format_addr(src), "dst": rm.format_addr(dst),
                 "services": rm.format_services(p, x)}
            if d not in out:
                out.append(d)
        return out


def _dedupe(items) -> list:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _intersect_service(a, b):
    """Intersect two permitted pieces (src, dst, protos, ports); None if the
    intersection is empty (disjoint hosts OR services)."""
    sa, da, pa, xa = a
    sb, db_, pb, xb = b
    src = rm.addr_intersect(sa, sb)
    if src is None:
        return None
    dst = rm.addr_intersect(da, db_)
    if dst is None:
        return None
    if isinstance(pa, rm.Unresolved) or isinstance(xa, rm.Unresolved):
        return (src, dst, pa, xa)
    if isinstance(pb, rm.Unresolved) or isinstance(xb, rm.Unresolved):
        return (src, dst, pb, xb)
    p = rm.protos_intersect(pa, pb)
    if p != rm.ANY and not p:
        return None
    if xa == rm.ANY:
        x = xb
    elif xb == rm.ANY:
        x = xa
    else:
        x = rm.ranges_intersect(xa, xb)
        if not x:
            return None
    return (src, dst, p, x)


_DEVICE_TO_VERDICT = {"permit": "permitted", "deny": "denied"}


def _subtract_denies(pieces: list, denies: list) -> list:
    """MP-10: remove the services a specific deny (protos, ports) blocks
    from every permitted piece.  A deny applies to a piece when its
    protocols cover the piece's protocols (then the ports are subtracted);
    a deny narrower than the piece's protocols cannot be expressed as a
    piece and is left to ``denied_services`` (text) as before."""
    if not denies:
        return pieces
    out = []
    for piece in pieces:
        s, d, p, x = piece
        if isinstance(x, rm.Unresolved) or isinstance(p, rm.Unresolved):
            out.append(piece)
            continue
        cur_x = x
        blocked = False
        for dp, dx in denies:
            if isinstance(dx, rm.Unresolved) or isinstance(dp, rm.Unresolved):
                continue
            if not rm.protos_contain(dp, p):
                continue
            nx = rm.ranges_subtract(cur_x, dx)
            if not nx:
                blocked = True
                break
            cur_x = rm.ANY if nx == rm.FULL_RANGE else nx
        if blocked:
            continue
        out.append(piece if cur_x == x else (s, d, p, cur_x))
    return out


def _combine_verdicts(verdicts: list[_Verdict]) -> _Verdict:
    """AND semantics (devices on one boundary, or hops on one path).

    Any deny -> denied; any unknown -> unknown; any no_policy -> no_policy;
    all permit -> permitted; otherwise partial with the intersection of the
    permitted pieces - host scopes AND services (N-05) - so two firewalls
    that each permit a different host set yield "denied" (empty
    intersection), not "partial".  MP-10: the specific denies of every hop
    are subtracted from the result (a permit-any hop behind a deny tcp/502
    still blocks 502 on the whole path).
    """
    decisions = [v.decision for v in verdicts]
    denied = _dedupe(s for v in verdicts for s in v.denied_services)
    denies = _dedupe(dn for v in verdicts for dn in v.denies)
    if not decisions:
        return _Verdict("no_policy")
    if "denied" in decisions:
        return _Verdict("denied", denied_services=denied)
    if "unknown" in decisions:
        return _Verdict("unknown", denied_services=denied)
    if "no_policy" in decisions:
        return _Verdict("no_policy", denied_services=denied)
    if all(d == "permitted" for d in decisions):
        return _Verdict("permitted", [_SVC_ANY], denied, denies)
    cur = [_SVC_ANY]
    for v in verdicts:
        if v.decision == "permitted":
            continue
        nxt = []
        seen: set = set()          # C-10: O(1) piece dedupe (hashable pieces)
        for a in cur:
            for b in v.services:
                r = _intersect_service(a, b)
                if r is not None and r not in seen:
                    seen.add(r)
                    nxt.append(r)
        cur = nxt
    cur = _subtract_denies(cur, denies)
    if not cur:
        return _Verdict("denied", denied_services=denied)
    return _Verdict("partial", cur, denied, denies)


def _union_verdicts(verdicts: list[_Verdict]) -> _Verdict:
    """OR semantics across alternative paths (most permissive wins).  MP-10:
    the denied services are kept - those every alternative denies as
    pieces (still subtractable), the rest as text."""
    decisions = [v.decision for v in verdicts]
    if "permitted" in decisions:
        return _Verdict("permitted", [_SVC_ANY], _common_denied_text(verdicts),
                        _common_denies(verdicts))
    if "partial" in decisions:
        svcs = []
        seen: set = set()          # C-10: O(1) piece dedupe (hashable pieces)
        for v in verdicts:
            if v.decision == "partial":
                for s in v.services:
                    if s not in seen:
                        seen.add(s)
                        svcs.append(s)
        return _Verdict("partial", svcs, _common_denied_text(verdicts), _common_denies(verdicts),
                        uncertain="unknown" in decisions or any(getattr(v, "uncertain", False)
                                                                for v in verdicts))
    if decisions and all(d == "denied" for d in decisions):
        return _Verdict("denied")
    if "unknown" in decisions:
        return _Verdict("unknown")
    return _Verdict("no_policy")


def _common_denied_text(verdicts: list) -> list:
    """Denied-service text common to every alternative."""
    common = None
    for v in verdicts:
        mine = set(v.denied_services)
        common = mine if common is None else common & mine
        if not common:
            return []
    return sorted(common or [])


def _common_denies(verdicts: list) -> list:
    """Deny pieces present on EVERY alternative (an OR of paths only blocks
    what all of them block)."""
    if not verdicts:
        return []
    common = None
    for v in verdicts:
        mine = set(v.denies)
        common = mine if common is None else common & mine
        if not common:
            return []
    return sorted(common, key=repr)


def _combine_decisions(decisions: list[str]) -> str:
    """Back-compat wrapper: combine plain decision strings (AND semantics).

    "no_match" (legacy value) is an implicit deny.
    """
    norm = []
    for d in decisions:
        d = {"no_match": "denied"}.get(d, d)
        d = _DEVICE_TO_VERDICT.get(d, d)
        norm.append(_Verdict(d, [_SVC_ANY] if d == "partial" else None))
    return _combine_verdicts(norm).decision


# ---------------------------------------------------------------------------
# NAT (F-05)
# ---------------------------------------------------------------------------
#
# Which destination a vendor's security policy is matched against for
# destination-NAT'd (VIP / port-forward) traffic:
#
#   FortiOS  "post": a policy whose destination is a VIP matches the VIP's
#            MAPPED address (the config parser resolves VIP policies to the
#            mapped address), and the service is the mapped port.
#   PAN-OS   "pre":  security policy uses the PRE-NAT (original) destination
#            address and service with the POST-NAT zone; zones/levels are
#            taken from the real destination here anyway.
#   pfSense  "post": port forwards are applied before the filter, so filter
#            rules see the translated destination address and port.
#   Cisco ASA (8.3+) "post": ACLs reference the real (mapped) address.
#   Cisco IOS "pre": an inbound ACL on the outside interface is evaluated
#            before NAT outside->inside translation.
#   anything else: "post".
#
# Source NAT is applied after a firewall's own policy (every vendor matches
# the ORIGINAL source); downstream hops see the translated source.
_NAT_POLICY_MATCH = {
    "fortigate": "post", "fortios": "post", "forti": "post",
    "panos": "pre", "pan-os": "pre", "palo_alto": "pre", "paloalto": "pre",
    "pfsense": "post", "opnsense": "post",
    "cisco_asa": "post", "asa": "post",
    "cisco_ios": "pre", "cisco": "pre", "ios": "pre",
}


def _nat_policy_mode(vendor: Optional[str]) -> str:
    v = (vendor or "").strip().lower()
    if v in _NAT_POLICY_MATCH:
        return _NAT_POLICY_MATCH[v]
    # MV-02: parser device types (panos_xml / panos_set, cisco_asa_*, ...)
    if v.startswith(("pan", "palo")):
        return "pre"
    if v.startswith(("cisco_asa", "asa", "ftd")):
        return "post"
    if v.startswith("cisco"):
        return "pre"
    return "post"


def _first_ip(spec) -> Optional[tuple]:
    """(version, lo, hi) of the first interval of a resolved spec."""
    if spec == rm.ANY or isinstance(spec, rm.Unresolved) or spec is None:
        return None
    iv = rm.addr_intervals(spec)
    v = min(iv)
    lo, hi = iv[v][0]
    return v, lo, hi


def _ip_str(v: int, n: int) -> str:
    return str(ipaddress.IPv4Address(n) if v == 4 else ipaddress.IPv6Address(n))


def _map_ip(ip: str, frm, to) -> Optional[str]:
    """Translate ``ip`` (inside ``frm``) into ``to``: offset mapping when
    both are one same-sized block, otherwise the first address of ``to``."""
    f, t = _first_ip(frm), _first_ip(to)
    if t is None:
        return None
    tv, tlo, thi = t
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if f is not None and f[0] == a.version == tv and (f[2] - f[1]) == (thi - tlo) \
            and f[1] <= int(a) <= f[2]:
        return _ip_str(tv, tlo + int(a) - f[1])
    return _ip_str(tv, tlo)


def _map_port(port: Optional[int], frm, to) -> Optional[int]:
    if port is None or to == rm.ANY or isinstance(to, rm.Unresolved):
        return port
    if frm != rm.ANY and not isinstance(frm, rm.Unresolved) and len(frm) == 1 and len(to) == 1:
        (flo, fhi), (tlo, thi) = frm[0], to[0]
        if fhi - flo == thi - tlo and flo <= port <= fhi:
            return tlo + port - flo
    return to[0][0]


_XFAM_KINDS = frozenset({"vip46", "vip64", "policy46-nat", "policy64-nat"})


def _nat_order_key(row) -> tuple:
    """B-13: NAT evaluation order - (sequence, id), rows without a sequence
    last (portable: PostgreSQL and SQLite disagree on NULL ordering)."""
    seq = getattr(row, "sequence", None)
    rid = getattr(row, "id", None)
    return (seq is None, seq if seq is not None else 0, rid if rid is not None else 0)


class _Nat:
    """A parsed NatRule row.

    ``mapped_text`` overrides row.mapped_ip (an SNAT "interface:<name>"
    resolved to that interface's address, N-25).  ``cross_family`` marks an
    address-family translation (VIP46 / VIP64 / policy46 / policy64 pool):
    the translated address is of the OTHER family than the original."""

    def __init__(self, row, mapped_text: Optional[str] = None):
        self.row = row
        self.kind = (row.nat_type or "").strip().lower()
        self.protos = rm.parse_protocols(row.protocol)
        self.ext = rm.parse_address(row.ext_ip) if row.ext_ip else None
        self.ext_ports = rm.parse_ports(row.ext_port)
        # C-04: central-snat orig-port limit (SNAT only).  ANY = no port limit.
        self.orig_ports = rm.parse_ports(getattr(row, "orig_port", None))
        mt = mapped_text if mapped_text is not None else row.mapped_ip
        self.mapped = rm.parse_address(mt) if mt else None
        self.mapped_ports = rm.parse_ports(row.mapped_port)
        self.orig_src = rm.parse_address(row.orig_src or "any")
        self.orig_dst = rm.parse_address(getattr(row, "orig_dst", None) or "any")
        self.vdom = getattr(row, "vdom", None)
        self.nat_kind = getattr(row, "nat_kind", None)
        self.policy_ids = [x.strip() for x in str(row.policy_id).split(",") if x.strip()] \
            if row.policy_id else []
        # B-13: exemption entry (central-snat `nat disable`): a match means
        # "no translation, stop" (first-match).
        self.exempt = bool(getattr(row, "nat_exempt", False)) and self.kind == "snat"
        self.sequence = getattr(row, "sequence", None)
        self.cross_family = self._cross_family()

    def _cross_family(self) -> bool:
        if self.exempt:
            return False
        if self.nat_kind in _XFAM_KINDS:
            return True
        frm = self.ext if self.kind == "dnat" else self.orig_src
        a, b = rm.addr_versions(frm), rm.addr_versions(self.mapped)
        return bool(a and b and a != b)

    def client_families(self) -> Optional[frozenset]:
        """Address families of the flows this translation takes in (None =
        either)."""
        frm = self.ext if self.kind == "dnat" else self.orig_src
        v = rm.addr_versions(frm)
        if v:
            return v
        if self.nat_kind in ("vip46", "policy46-nat"):
            return frozenset({4})
        if self.nat_kind in ("vip64", "policy64-nat"):
            return frozenset({6})
        return None

    def unusable_reason(self) -> Optional[str]:
        """Why this row cannot be applied to a concrete flow (None = usable)."""
        if self.usable:
            return None
        if self.kind == "dnat":
            return "external or mapped address is not a concrete IP"
        if self.kind == "snat":
            if isinstance(self.orig_src, rm.Unresolved):
                return "original source is an unresolved object"
            m = str(self.row.mapped_ip or "")
            if m.startswith("interface:"):
                return f"translated to the address of {m[10:]} (interface address unknown)"
            if m.startswith("pool:"):
                return f"ippool {m[5:]} not found in the config"
            return "translated source is not a concrete IP"
        return f"unsupported nat_type {self.row.nat_type!r}"

    def policy_ok(self, permit_keys: set) -> bool:
        """SNAT bound to policies: only applies when one of them permitted
        the flow ((vdom, policy_id) identity, N-24)."""
        if not self.policy_ids:
            return True
        return any((self.vdom, pid) in permit_keys for pid in self.policy_ids)

    @property
    def usable(self) -> bool:
        if self.kind == "dnat":
            return _first_ip(self.ext) is not None and _first_ip(self.mapped) is not None
        if self.exempt:
            return not isinstance(self.orig_src, rm.Unresolved)
        if self.kind == "snat":
            return _first_ip(self.mapped) is not None and not isinstance(self.orig_src, rm.Unresolved)
        return False

    def _proto_ok(self, protos) -> bool:
        if isinstance(self.protos, rm.Unresolved):
            return False
        return rm.protos_overlap(self.protos, protos) is not False

    def match_dnat(self, dst_ip, port, protos) -> Optional[tuple]:
        """(mapped_ip, mapped_port) when a flow to dst_ip[:port] hits this VIP."""
        if self.kind != "dnat" or not dst_ip or not self._proto_ok(protos):
            return None
        if not rm.ip_in_addr(dst_ip, self.ext):
            return None
        if port is not None and self.ext_ports != rm.ANY:
            if not rm.port_in(port, self.ext_ports):
                return None
        new_ip = _map_ip(dst_ip, self.ext, self.mapped)
        if new_ip is None:
            return None
        return new_ip, _map_port(port, self.ext_ports, self.mapped_ports)

    def reverse_dnat(self, dst_ip, port, protos) -> Optional[tuple]:
        """(ext_ip, ext_port) for a flow OBSERVED to the mapped address -
        only when the mapping is reversible (single host / same-size)."""
        if self.kind != "dnat" or not dst_ip or not self._proto_ok(protos):
            return None
        if not rm.ip_in_addr(dst_ip, self.mapped):
            return None
        if port is not None and self.mapped_ports != rm.ANY and not rm.port_in(port, self.mapped_ports):
            return None
        old_ip = _map_ip(dst_ip, self.mapped, self.ext)
        if old_ip is None:
            return None
        return old_ip, _map_port(port, self.mapped_ports, self.ext_ports)

    def snat_matches(self, src_ip, dst_ip=None, protos=None, port=None) -> bool:
        """Does a flow from ``src_ip`` hit this SNAT / exemption entry?"""
        if self.kind != "snat" or not src_ip:
            return False
        if protos is not None and not self._proto_ok(protos):
            return False  # central-snat protocol limit
        # C-04: central-snat orig-port limit.  Only applied when the flow has a
        # concrete port AND the entry restricts ports - so an exemption limited
        # to tcp/80 does NOT exempt a tcp/443 flow.  A portless query never
        # narrows here (the over-approximation note on exemptions: never a
        # false deny from a port we don't know).
        if port is not None and self.orig_ports != rm.ANY \
                and not isinstance(self.orig_ports, rm.Unresolved) \
                and rm.port_in(port, self.orig_ports) is False:
            return False
        if not rm.ip_in_addr(src_ip, self.orig_src):
            return False
        if dst_ip and self.orig_dst != rm.ANY and rm.ip_in_addr(dst_ip, self.orig_dst) is False:
            return False  # central-snat dst-addr limit
        return True

    def match_snat(self, src_ip, dst_ip=None, protos=None, port=None) -> Optional[str]:
        """Translated source for a matching flow (None: no match, or an
        exemption entry - see snat_matches)."""
        if self.exempt or not self.snat_matches(src_ip, dst_ip, protos, port):
            return None
        return _map_ip(src_ip, self.orig_src if self.orig_src != rm.ANY else None, self.mapped)

    def ref(self, ep) -> dict:
        r = self.row
        return {"nat_rule_id": r.id, "name": r.name, "policy_id": r.policy_id,
                "nat_kind": self.nat_kind, "vdom": self.vdom,
                "cross_family": self.cross_family, "exempt": self.exempt,
                "sequence": self.sequence,
                "firewall": ep.name, "firewall_id": ep.firewall_id,
                "firewall_device_id": ep.firewall_device_id}


# ---------------------------------------------------------------------------
# Analysis context (loaded once per public call)
# ---------------------------------------------------------------------------

class _Context:
    def __init__(self, db: DBSession):
        # LS-03: the firewall / routing switch that carried the flow being
        # evaluated (router MAC on its frames), set per flow by topology_diff.
        self.carrier_fw_id: Optional[int] = None
        self.db = db
        self.boundary_map: dict[tuple[int, int], list[_EnforcementPoint]] = {}
        self._rules: dict[int, list[FirewallRule]] = {}
        self._iface_names: dict[int, dict[str, set[int]]] = defaultdict(dict)
        # C-09: exact interface NAMES only (not alias / zone_label), so a
        # srcintf/dstintf token is resolved against zone defs and real
        # interface names before an interface alias that happens to equal a
        # zone name.
        self._iface_exact: dict[int, dict[str, set[int]]] = defaultdict(dict)
        # MP-09: names / aliases / zone_labels of interfaces that EXIST on the
        # firewall but carry no level (wan1, SD-WAN members, tunnels,
        # loopbacks, mgmt).  A rule side naming one is "another leg" on a
        # multi-leg box - never this crossing - and uncertain on an explicit
        # two-level boundary.
        self._iface_unlabelled: dict[int, set[str]] = defaultdict(set)
        self._unlabelled_sides: set = set()     # (id(ep), zone_str) seen by _zone_levels
        self._iface_unlabelled_names: dict[int, set[str]] = defaultdict(set)   # display names
        # MP-12: firewalls whose upload boundary and interface labels disagree
        self.label_conflicts: list[dict] = []
        self._iface_subnets: dict[int, list] = defaultdict(list)
        self._zones_by_device: dict[str, dict[str, list[str]]] = defaultdict(dict)
        # B-07: FortiOS zone definitions per (firewall_id, vdom):
        #   zone name (lower) -> {"members": [iface lower], "resolved": bool,
        #                         "intrazone": "allow" | "deny" | None}
        self._zone_defs: dict[tuple, dict[str, dict]] = defaultdict(dict)
        # leveled interfaces per firewall: [(name lower, level)] (intrazone)
        self._leveled_ifaces: dict[int, list] = defaultdict(list)
        self._fw_by_name: dict[str, int] = {}
        self._eval_cache: dict = {}        # bounded - see _cache_put (AU C7)
        # T3-41: parsed rule specs / direction results cached for the whole
        # compute call (rules are no longer re-parsed per level pair / path).
        self._parsed: dict[int, tuple] = {}
        self._side_cache: dict = {}
        # F-05: NAT rows per firewall / firewall device
        self._nat_by_fw: dict[int, list] = defaultdict(list)
        self._nat_by_dev: dict[int, list] = defaultdict(list)
        self._nat_all: list = []
        self._nat_meta: dict = {}        # level-pair path key -> translation summary (N-25)
        # N-25: enabled NAT rows that cannot be applied to a concrete flow
        # (kept so level-pair cells can be flagged "NAT-dependent")
        self._nat_unusable_by_fw: dict[int, list] = defaultdict(list)
        self._nat_unusable_by_dev: dict[int, list] = defaultdict(list)
        self._nat_unusable: list = []
        self._vendor_by_fw: dict[int, str] = {}
        # N-05: legacy (no linked Firewall) direction inference
        self._legacy_maps: dict = {}
        self._host_levels: Optional[list] = None
        self._host_level_by_ip: dict = {}
        self.flat_edges: list[dict] = []
        self._load()
        self._load_nat()

    # -- loading -----------------------------------------------------------
    def _load(self):
        db = self.db
        # HA clusters (operator-declared): the non-primary members run the
        # primary's configuration and are not separate enforcement points -
        # traffic passes ONE member.  ha_config_drift reports differences.
        from app.parsers.firewall_groups import ha_secondary_ids
        try:
            self.ha_secondary = ha_secondary_ids(db)
        except Exception:      # never let grouping break the analysis
            log.warning("HA cluster lookup failed", exc_info=True)
            self.ha_secondary = set()
        firewalls = {fw.id: fw for fw in db.query(Firewall).all()
                     if fw.id not in self.ha_secondary}
        devices = db.query(FirewallDevice).all()
        for fw in firewalls.values():
            for n in (fw.name, fw.device_name):
                if n:
                    self._fw_by_name.setdefault(n.lower(), fw.id)

        # Interfaces with an operator-assigned Purdue level (direction + legs)
        ifaces = db.query(FirewallInterface).filter(
            FirewallInterface.purdue_level.isnot(None)
        ).all()
        # VD-03: inter-VDOM link interfaces are internal - never a leg, never
        # a zone with a level of its own.  (links / peer VDOM levels below)
        vlinks = _vdom_links(db, set(firewalls))
        link_names = {(fw_id, n) for fw_id, pairs in vlinks.items() for a, b in pairs for n in (a, b)}
        ifaces = [i for i in ifaces if (i.firewall_id, (i.name or "").strip().lower()) not in link_names]
        levels_by_fw: dict[int, set[int]] = defaultdict(set)
        levels_by_vdom: dict[tuple, set[int]] = defaultdict(set)   # (fw_id, vdom) -> levels
        for iface in ifaces:
            levels_by_fw[iface.firewall_id].add(iface.purdue_level)
            levels_by_vdom[(iface.firewall_id, iface.vdom)].add(iface.purdue_level)
        self._vdom_of_iface = {(i.firewall_id, (i.name or "").strip().lower()): i.vdom
                               for i in db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                                                 FirewallInterface.vdom)}
        self.vdom_levels = {}
        for (fw_id, vd), lv in levels_by_vdom.items():
            if vd is not None:
                self.vdom_levels.setdefault(fw_id, {})[vd] = set(lv)

        eps: list[_EnforcementPoint] = []
        linked_fw_ids = set()

        def _add_vdoms(kind, obj_id, fw_id, **kw) -> bool:
            """VD-01: a firewall whose labelled interfaces sit in two or more
            VDOMs.  Each VDOM with two or more labelled levels is an
            enforcement point per level pair (its own rules only, series
            group = the VDOM); every pair of labelled VDOMs connected over
            the inter-VDOM link graph - directly or through transit VDOMs
            that carry no labelled interface (AU full review C2) - gets, per
            (level of A, level of B), one EP for EVERY VDOM on the chain,
            in series (group = the chain).  Groups of one box are
            alternatives (C3: a level both VDOMs own is reachable inside
            one VDOM OR over the link).  Returns False when nothing could
            be built (C1: the caller then falls back to the whole-firewall
            model instead of dropping the firewall)."""
            per = self.vdom_levels.get(fw_id) or {}
            if len(per) < 2:
                return False
            links = vlinks.get(fw_id, [])
            adj: dict[str, set] = defaultdict(set)
            for a, b in links:
                va, vb = self._vdom_of_iface.get((fw_id, a)), self._vdom_of_iface.get((fw_id, b))
                if va and vb and va != vb:
                    adj[va].add(vb)
                    adj[vb].add(va)
            built = 0
            for vd, lv in per.items():
                legs = sorted(lv)
                for lo, hi in itertools.combinations(legs, 2):
                    eps.append(_EnforcementPoint(
                        zone_from=hi, zone_to=lo, source="firewall_interfaces",
                        physical=(kind, obj_id, vd), multi_leg=True, interface_levels=legs,
                        vdom=vd, series_group=(kind, obj_id, vd), **kw))
                    built += 1

            def _chain(src, dst):
                """Shortest VDOM chain src..dst over the links (BFS), else None."""
                prev = {src: None}
                todo = [src]
                while todo:
                    cur = todo.pop(0)
                    if cur == dst:
                        out, x = [], dst
                        while x is not None:
                            out.append(x)
                            x = prev[x]
                        return out[::-1]
                    for nxt in sorted(adj.get(cur, ())):
                        if nxt not in prev:
                            prev[nxt] = cur
                            todo.append(nxt)
                return None

            labelled = sorted(per)
            for i, va in enumerate(labelled):
                for vb in labelled[i + 1:]:
                    chain = _chain(va, vb)
                    if not chain:
                        continue
                    group = (kind, obj_id, "chain") + tuple(chain)
                    for la in per[va]:
                        for lb in per[vb]:
                            if la == lb:
                                continue
                            for vd in chain:
                                eps.append(_EnforcementPoint(
                                    zone_from=max(la, lb), zone_to=min(la, lb),
                                    source="firewall_interfaces", physical=(kind, obj_id, vd),
                                    multi_leg=True, interface_levels=sorted(per.get(vd, ())),
                                    vdom=vd, series_group=group, **kw))
                                built += 1
            return built > 0

        def _add(kind, obj_id, zf, zt, source, **kw):
            """One EP for an explicit boundary, or one per level pair for a
            multi-leg firewall (no explicit boundary, >=2 interface levels)."""
            fw_id = kw["firewall_id"]
            if fw_id is not None and _add_vdoms(kind, obj_id, fw_id, **kw):
                return
            legs = sorted(levels_by_fw.get(fw_id, set())) if fw_id is not None else []
            # H-11 / P-01: the explicit two-level boundary (upload parameter)
            # is the firewall's crossing while its interfaces say nothing
            # more.  Once the operator has labelled an interface at another
            # level (a DMZ leg, a VPN tunnel, or a second OT leg such as an L1
            # controller network beside the L2 one) that label wins: one EP
            # per labelled level pair - the boundary's own two levels stay in
            # the set (AU full review C8: labelling only the OT legs must not
            # drop the IT side of a declared 4 -> 1 firewall).
            extra = set(legs) - {zf, zt} if zf is not None and zt is not None else set()
            if zf is not None and zt is not None and not extra:
                eps.append(_EnforcementPoint(zone_from=zf, zone_to=zt, source=source,
                                             physical=(kind, obj_id), **kw))
                return
            if zf is not None and zt is not None:
                # MP-12: the interfaces are the physical truth.  A boundary
                # level BEYOND the labelled range is the unlabelled far leg
                # (C8) and is kept; one INSIDE the range would be a phantom
                # leg between real legs (4->3 device with 4 / 2 interfaces:
                # no L3 leg exists) and is dropped - both are reported.
                lab = set(legs)
                kept, dropped = set(), set()
                if len(lab) >= 2:
                    lo_l, hi_l = min(lab), max(lab)
                    for z in {zf, zt} - lab:
                        (dropped if lo_l < z < hi_l else kept).add(z)
                else:
                    kept = {zf, zt} - lab
                conflict = {zf, zt} - lab
                if conflict:
                    self.label_conflicts.append({
                        "firewall_id": fw_id, "firewall_device_id": kw.get("firewall_device_id"),
                        "firewall": kw.get("name"),
                        "boundary": [min(zf, zt), max(zf, zt)], "boundary_source": source,
                        "interface_levels": sorted(lab),
                        "ignored_levels": sorted(dropped), "assumed_levels": sorted(kept),
                        "detail": (f"upload boundary L{min(zf, zt):g}↔L{max(zf, zt):g} vs "
                                   f"interface levels {'/'.join(f'L{x:g}' for x in sorted(lab))}"
                                   + (f"; L{'/L'.join(f'{x:g}' for x in sorted(dropped))} lies between "
                                      "labelled legs and is ignored (no such interface)" if dropped else "")
                                   + (f"; L{'/L'.join(f'{x:g}' for x in sorted(kept))} assumed to be an "
                                      "unlabelled leg" if kept else "")),
                    })
                legs = sorted(lab | kept)
            if len(legs) < 2:
                return
            for lo, hi in itertools.combinations(legs, 2):
                eps.append(_EnforcementPoint(
                    zone_from=hi, zone_to=lo, source="firewall_interfaces",
                    physical=(kind, obj_id), multi_leg=True, interface_levels=legs, **kw,
                ))

        for dev in devices:
            fw_id = dev.firewall_id
            if fw_id is None:
                for n in (dev.name, dev.device_hostname):
                    if n and n.lower() in self._fw_by_name:
                        fw_id = self._fw_by_name[n.lower()]
                        break
            if fw_id is not None and fw_id in self.ha_secondary:
                continue          # HA member: the cluster primary represents it
            if fw_id is not None:
                linked_fw_ids.add(fw_id)
            zf, zt, source = dev.purdue_zone_from, dev.purdue_zone_to, "firewall_device"
            if (zf is None or zt is None) and fw_id in firewalls:
                fw = firewalls[fw_id]
                if fw.purdue_level_ingress is not None and fw.purdue_level_egress is not None:
                    zf, zt, source = fw.purdue_level_ingress, fw.purdue_level_egress, "firewall"
            if zf is None or zt is None:
                zf = zt = None
            _add("dev", dev.id, zf, zt, source,
                 id=dev.id, name=dev.name, vendor=dev.vendor,
                 hostname=dev.device_hostname, mgmt_ip=dev.mgmt_ip, firewall_id=fw_id,
                 firewall_device_id=dev.id)
        for fw in firewalls.values():
            if fw.id in linked_fw_ids:
                continue
            zf, zt = fw.purdue_level_ingress, fw.purdue_level_egress
            if zf is None or zt is None:
                zf = zt = None
            _add("fw", fw.id, zf, zt, "firewall",
                 id=None, name=fw.name, vendor=fw.vendor,
                 hostname=fw.device_name, mgmt_ip=None, firewall_id=fw.id,
                 firewall_device_id=None)

        bmap: dict[tuple[int, int], list[_EnforcementPoint]] = defaultdict(list)
        for ep in eps:
            bmap[ep.boundary].append(ep)
        self.boundary_map = dict(bmap)
        # MP-03: firewalls / devices that carry rules but built no
        # enforcement point - they are NOT in the model and every verdict
        # that passes where they sit is unverified.
        self.unplaced_firewalls: list[dict] = []
        try:
            self.unplaced_firewalls = self._find_unplaced(db, eps, firewalls, devices, levels_by_fw)
        except Exception:  # never let the notice break the analysis
            log.warning("unplaced-firewall lookup failed", exc_info=True)
        # MP-04: declared paired groups whose members are not placed on one
        # level pair, or have no confirmed link between them
        self.paired_group_warnings: list[dict] = []
        try:
            from app.parsers.firewall_groups import paired_group_warnings
            self.paired_group_warnings = paired_group_warnings(db)
        except Exception:  # never let the notice break the analysis
            log.warning("paired-group health lookup failed", exc_info=True)
        self.series_basis: dict = {}
        try:
            self._assign_series_keys(eps)
        except Exception:  # never let the topology relation break the analysis
            log.warning("series relation lookup failed", exc_info=True)
        try:
            self.flat_edges = _infer_flat_edges(self.boundary_map, ifaces,
                                                self._all_host_levels())
        except Exception:  # never let inference break the analysis
            log.warning("flat-segment inference failed", exc_info=True)
            self.flat_edges = []

        dev_ids = {ep.firewall_device_id for ep in eps if ep.firewall_device_id is not None}
        fw_ids = {ep.firewall_id for ep in eps if ep.firewall_id is not None}
        rules: list[FirewallRule] = []
        if dev_ids:
            rules += db.query(FirewallRule).filter(
                FirewallRule.firewall_device_id.in_(dev_ids), FirewallRule.enabled.is_(True)).all()
        if fw_ids:
            rules += db.query(FirewallRule).filter(
                FirewallRule.firewall_id.in_(fw_ids), FirewallRule.enabled.is_(True)).all()
        by_dev, by_fw = defaultdict(dict), defaultdict(dict)
        for r in rules:
            if r.firewall_device_id is not None:
                by_dev[r.firewall_device_id][r.id] = r
            if r.firewall_id is not None:
                by_fw[r.firewall_id][r.id] = r
        for ep in eps:
            merged = {}
            if ep.firewall_device_id is not None:
                merged.update(by_dev.get(ep.firewall_device_id, {}))
            if ep.firewall_id is not None:
                for rid, r in by_fw.get(ep.firewall_id, {}).items():
                    # A rule tagged with a DIFFERENT device belongs to that device
                    if r.firewall_device_id in (None, ep.firewall_device_id):
                        merged[rid] = r
            if ep.vdom is not None:             # VD-01: this VDOM's policies only
                merged = {rid: r for rid, r in merged.items() if getattr(r, "vdom", None) == ep.vdom}
            self._rules[id(ep)] = sorted(merged.values(), key=_rule_sort_key)

        # Interface / zone maps for direction resolution
        if fw_ids:
            # VD-03: an inter-VDOM link interface stands for everything on
            # the other side of the link: its level set is the peer VDOM's
            # labelled levels (transitively over further links).
            for fw_id, names_lv in _link_levels(vlinks, self._vdom_of_iface, self.vdom_levels).items():
                if fw_id not in fw_ids:
                    continue
                for name, lv in names_lv.items():
                    self._iface_names[fw_id].setdefault(name, set()).update(lv)
                    self._iface_exact[fw_id].setdefault(name, set()).update(lv)
            for iface in db.query(FirewallInterface).filter(
                    FirewallInterface.purdue_level.is_(None),
                    FirewallInterface.firewall_id.in_(sorted(fw_ids))):
                if (iface.firewall_id, (iface.name or "").strip().lower()) in link_names:
                    continue
                for label in (iface.name, iface.alias, iface.zone_label):
                    if label and label.strip():
                        self._iface_unlabelled[iface.firewall_id].add(label.strip().lower())
                if iface.name and (iface.iface_type or "") not in ("loopback", "tunnel") \
                        and not getattr(iface, "is_mgmt_only", False):
                    self._iface_unlabelled_names[iface.firewall_id].add(iface.name.strip())
            for iface in ifaces:
                if iface.firewall_id not in fw_ids:
                    continue
                names = self._iface_names[iface.firewall_id]
                if iface.name and iface.name.strip():
                    self._leveled_ifaces[iface.firewall_id].append(
                        (iface.name.strip().lower(), iface.purdue_level))
                    self._iface_exact[iface.firewall_id].setdefault(
                        iface.name.strip().lower(), set()).add(iface.purdue_level)
                for label in (iface.name, iface.alias, iface.zone_label):
                    if label and label.strip():
                        names.setdefault(label.strip().lower(), set()).add(iface.purdue_level)
                for cidr in (iface.network_cidr, iface.ip_cidr):
                    if not cidr:
                        continue
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    if net.prefixlen == 0 or (net.version == 4 and net.prefixlen == 32):
                        continue
                    self._iface_subnets[iface.firewall_id].append((net, iface.purdue_level))
                    break
            try:
                for z in db.query(FirewallZone).all():
                    if not z.zone_name or not z.interface_name:
                        continue
                    key = (z.device_name or "").lower()
                    self._zones_by_device[key].setdefault(
                        z.zone_name.strip().lower(), []
                    ).append(z.interface_name.strip().lower())
            except Exception:  # pragma: no cover - table missing in old DBs
                log.debug("FirewallZone lookup failed", exc_info=True)
            for key, zmap in fz.load_zone_defs(db, fw_ids).items():
                self._zone_defs[key].update(zmap)

    @staticmethod
    def _find_unplaced(db, eps, firewalls, devices, levels_by_fw) -> list[dict]:
        """MP-03: every firewall (and device without a firewall) that has
        enabled rules but no enforcement point, with why."""
        placed_fw = {ep.firewall_id for ep in eps if ep.firewall_id is not None}
        placed_dev = {ep.firewall_device_id for ep in eps if ep.firewall_device_id is not None}
        fw_rules: dict = defaultdict(int)
        dev_rules: dict = defaultdict(int)
        for fid, did, n in db.query(FirewallRule.firewall_id, FirewallRule.firewall_device_id,
                                    func.count(FirewallRule.id)) \
                .filter(FirewallRule.enabled.is_(True)) \
                .group_by(FirewallRule.firewall_id, FirewallRule.firewall_device_id):
            if fid is not None:
                fw_rules[fid] += n
            elif did is not None:
                dev_rules[did] += n
        dev_by_fw: dict = {}
        for dev in devices:
            if dev.firewall_id is not None:
                dev_by_fw.setdefault(dev.firewall_id, dev)
        out = []
        for fw in firewalls.values():
            if fw.id in placed_fw:
                continue
            n = fw_rules.get(fw.id, 0)
            dev = dev_by_fw.get(fw.id)
            if dev is not None:
                n += dev_rules.get(dev.id, 0)
            if not n:
                continue
            legs = sorted(levels_by_fw.get(fw.id, set()))
            ifaces = db.query(FirewallInterface).filter(
                FirewallInterface.firewall_id == fw.id, FirewallInterface.purdue_level.is_(None)) \
                .order_by(FirewallInterface.name).all()
            unl = [i.name for i in ifaces if (i.iface_type or "") not in ("loopback", "tunnel")
                   and not getattr(i, "is_mgmt_only", False)]
            # MP-25: labels on an HA SECONDARY only - the cluster's primary
            # represents it and carries none, so the cluster has no EP
            sec_labels = []
            if fw.ha_group_id is not None:
                for m_id, m_name, lv in db.query(Firewall.id, Firewall.name, FirewallInterface.purdue_level) \
                        .join(FirewallInterface, FirewallInterface.firewall_id == Firewall.id) \
                        .filter(Firewall.ha_group_id == fw.ha_group_id, Firewall.id != fw.id,
                                FirewallInterface.purdue_level.isnot(None)):
                    sec_labels.append((m_name, lv))
            if len(legs) == 1:
                reason = f"only one Purdue level labelled (L{legs[0]:g}); a crossing needs two"
            elif sec_labels:
                names = sorted({n for n, _lv in sec_labels})
                reason = (f"interface levels are on the HA secondary ({', '.join(names)}) only; "
                          f"the cluster primary {fw.name} carries none - label the primary")
            else:
                reason = "no interface Purdue levels and no boundary"
            out.append({"firewall_id": fw.id, "firewall_device_id": dev.id if dev is not None else None,
                        "firewall": fw.name or fw.device_name, "vendor": fw.vendor,
                        "rule_count": n, "labelled_levels": legs,
                        "unlabelled_interfaces": unl, "reason": reason})
        for dev in devices:
            if dev.id in placed_dev or dev.firewall_id is not None:
                continue
            n = dev_rules.get(dev.id, 0)
            if not n:
                continue
            out.append({"firewall_id": None, "firewall_device_id": dev.id,
                        "firewall": dev.name or dev.device_hostname, "vendor": dev.vendor,
                        "rule_count": n, "labelled_levels": [], "unlabelled_interfaces": [],
                        "reason": "no Purdue boundary on the device"})
        out.sort(key=lambda d: (d["firewall"] or ""))
        return out

    def _assign_series_keys(self, eps: list) -> None:
        """MP-01: the declared "in series" relation between distinct boxes.
        Two firewalls are in series when the operator put them in one
        paired group, confirmed a link from an INSIDE-side interface of one
        to an OUTSIDE-side interface of the other (the transit segment of a
        serial pair), or confirmed one as the upstream of the other.  HA
        members are already folded into their primary.  Everything else on
        a boundary is an alternative.  ``series_basis`` records why, per
        series set, for the API / UI."""
        db = self.db
        parent: dict[int, int] = {}
        basis: dict[int, set] = defaultdict(set)

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b, why):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb
            basis[find(a)].add(why)

        fw_ids = {ep.firewall_id for ep in eps if ep.firewall_id is not None}
        if not fw_ids:
            return
        try:
            from app.models import FirewallGroup
            from app.parsers.firewall_groups import KIND_PAIRED
            for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_PAIRED).all():
                members = [f.id for f in db.query(Firewall.id).filter(Firewall.paired_group_id == g.id)
                           if f.id in fw_ids]
                for m in members[1:]:
                    union(members[0], m, f"paired group {g.name or g.id}")
        except Exception:
            log.debug("paired group lookup failed", exc_info=True)
        for fw in db.query(Firewall).filter(Firewall.upstream_firewall_id.isnot(None),
                                            Firewall.topology_confirmed.is_(True)):
            if fw.id in fw_ids and fw.upstream_firewall_id in fw_ids:
                union(fw.id, fw.upstream_firewall_id, "confirmed upstream chain")
        ifaces = {i.id: i for i in db.query(FirewallInterface).filter(
            FirewallInterface.firewall_id.in_(fw_ids), FirewallInterface.connects_to_interface_id.isnot(None))}
        for i in ifaces.values():
            peer = ifaces.get(i.connects_to_interface_id)
            if peer is None or peer.firewall_id == i.firewall_id:
                continue
            sides = {(i.side or "").lower(), (peer.side or "").lower()}
            if sides == {"inside", "outside"}:
                union(i.firewall_id, peer.firewall_id, "confirmed inside→outside link")
        # merge the basis sets of unions that happened under an older root
        merged: dict[int, set] = defaultdict(set)
        for r, why in basis.items():
            merged[find(r)] |= why
        roots = defaultdict(set)
        for fid in fw_ids:
            roots[find(fid)].add(fid)
        for ep in eps:
            if ep.firewall_id is None:
                continue
            r = find(ep.firewall_id)
            if len(roots[r]) >= 2:
                ep.series_key = ("series", r)
                self.series_basis[("series", r)] = sorted(merged.get(r, ()))

    def rules_for(self, ep: _EnforcementPoint) -> list[FirewallRule]:
        return self._rules.get(id(ep), [])

    # -- NAT (F-05) --------------------------------------------------------
    def _load_nat(self):
        try:
            # B-13: configured order (sequence, then id) - SNAT / DNAT are
            # evaluated first-match in this order.
            rows = (self.db.query(NatRule).filter(NatRule.enabled.is_(True))
                    .order_by(NatRule.sequence, NatRule.id).all())
            rows.sort(key=_nat_order_key)
        except Exception:  # pragma: no cover - table missing in old DBs
            log.debug("NatRule lookup failed", exc_info=True)
            return
        for fw in self.db.query(Firewall.id, Firewall.vendor).all():
            self._vendor_by_fw[fw.id] = fw.vendor
        # N-25: an interface-mode SNAT ("interface:<name>") translates to that
        # interface's address - concrete when the firewall's interface is known.
        iface_ip: dict = {}
        try:
            for fi in self.db.query(FirewallInterface).all():
                if fi.ip_address and fi.name:
                    iface_ip[(fi.firewall_id, fi.name.strip().lower())] = fi.ip_address
        except Exception:  # pragma: no cover - table missing in old DBs
            log.debug("FirewallInterface lookup failed", exc_info=True)
        for row in rows:
            mapped_text = None
            m = str(row.mapped_ip or "")
            if row.nat_type == "snat" and m.startswith("interface:"):
                names = [x.strip().lower() for x in m[10:].split(",") if x.strip()]
                ips = {iface_ip.get((row.firewall_id, nm)) for nm in names}
                if len(names) == 1 and None not in ips:
                    try:
                        a = ipaddress.ip_address(next(iter(ips)))
                        mapped_text = f"{a}/{a.max_prefixlen}"
                    except ValueError:
                        mapped_text = None
            n = _Nat(row, mapped_text)
            if not n.usable:
                self._nat_unusable.append(n)
                if row.firewall_id is not None:
                    self._nat_unusable_by_fw[row.firewall_id].append(n)
                if row.firewall_device_id is not None:
                    self._nat_unusable_by_dev[row.firewall_device_id].append(n)
                continue
            self._nat_all.append(n)
            if row.firewall_id is not None:
                self._nat_by_fw[row.firewall_id].append(n)
            if row.firewall_device_id is not None:
                self._nat_by_dev[row.firewall_device_id].append(n)

    @property
    def has_nat(self) -> bool:
        return bool(self._nat_all)

    def unusable_nats_for(self, ep) -> list:
        """Enabled NAT rows of ``ep``'s firewall that cannot be applied (N-25)."""
        out, seen = [], set()
        cands = []
        if ep.firewall_device_id is not None:
            cands += self._nat_unusable_by_dev.get(ep.firewall_device_id, [])
        if ep.firewall_id is not None:
            cands += [n for n in self._nat_unusable_by_fw.get(ep.firewall_id, [])
                      if n.row.firewall_device_id in (None, ep.firewall_device_id)]
        for n in cands:
            if n.row.id not in seen:
                seen.add(n.row.id)
                out.append(n)
        return out

    def nats_for(self, ep) -> list:
        """Usable NAT rows of ``ep``'s firewall in configured order (B-13:
        (sequence, id) - first match wins)."""
        out, seen = [], set()
        cands = []
        if ep.firewall_device_id is not None:
            cands += self._nat_by_dev.get(ep.firewall_device_id, [])
        if ep.firewall_id is not None:
            cands += [n for n in self._nat_by_fw.get(ep.firewall_id, [])
                      if n.row.firewall_device_id in (None, ep.firewall_device_id)]
        for n in cands:
            if n.row.id not in seen:
                seen.add(n.row.id)
                out.append(n)
        out.sort(key=lambda n: _nat_order_key(n.row))
        return out

    def nat_policy_mode(self, ep, nat=None) -> str:
        """'pre' or 'post': which destination the vendor's policy matches
        for DNAT'd traffic (see _NAT_POLICY_MATCH)."""
        vendor = (ep.vendor or (nat.row.device_type if nat is not None else None)
                  or self._vendor_by_fw.get(ep.firewall_id) or "")
        return _nat_policy_mode(vendor)

    def subnet_level(self, ip: Optional[str]):
        """Level of the labelled firewall interface network(s) holding ``ip``
        (one common level, else None) - the level of an address that is no
        known host (a VIP's mapped address, a downstream VIP)."""
        try:
            a = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return None
        best = None
        for nets in self._iface_subnets.values():
            for net, lv in nets:
                if lv is None or net.version != a.version or a not in net:
                    continue
                if best is None or net.prefixlen > best[0]:
                    best = (net.prefixlen, lv)
        return best[1] if best else None

    def host_level(self, ip: Optional[str]) -> Optional[int]:
        if not ip:
            return None
        if ip not in self._host_level_by_ip:
            h = self.db.query(Host.purdue_level).filter(
                Host.ip == ip, Host.purdue_level.isnot(None)).first()
            self._host_level_by_ip[ip] = h[0] if h else None
        return self._host_level_by_ip[ip]

    def dnat_target(self, dst_ip, port, protos) -> Optional[tuple]:
        """(nat, mapped_ip, mapped_port) for the first DNAT on ANY firewall
        whose external address matches - used to find the real destination
        (and its Purdue level) of a flow addressed to a VIP."""
        first, chain = None, []
        cur_ip, cur_port = dst_ip, port
        # P-03: a VIP may map onto another firewall's VIP (double NAT) -
        # follow the chain (bounded) to the real destination.
        for _ in range(4):
            hit = None
            for n in self._nat_all:
                if n.kind == "dnat" and n not in chain:
                    m = n.match_dnat(cur_ip, cur_port, protos)
                    if m is not None:
                        hit = (n,) + m
                        break
            if hit is None:
                break
            chain.append(hit[0])
            first = first or hit[0]
            cur_ip, cur_port = hit[1], hit[2]
        if first is None:
            return None
        self.last_dnat_chain = chain
        return first, cur_ip, cur_port

    # -- legacy direction inference (N-05) --------------------------------
    def _all_host_levels(self) -> list:
        if self._host_levels is None:
            out = []
            for ip, lv in self.db.query(Host.ip, Host.purdue_level).filter(
                    Host.ip.isnot(None), Host.purdue_level.isnot(None)):
                try:
                    out.append((ipaddress.ip_address(ip), lv))
                except ValueError:
                    continue
            self._host_levels = out
        return self._host_levels

    def _levels_of_hosts_in(self, spec) -> Optional[set[int]]:
        if spec == rm.ANY or isinstance(spec, rm.Unresolved) or spec is None:
            return None
        if rm.is_family_wide(spec):
            return None
        ivals = rm.addr_intervals(spec)
        levels = {lv for a, lv in self._all_host_levels()
                  if any(lo <= int(a) <= hi for lo, hi in ivals.get(a.version, ()))}
        return levels or None

    def _legacy_map(self, ep) -> dict:
        """{"names": {zone/interface name: levels}, "subnets": [(net, levels)]}
        for a FirewallDevice with no linked Firewall, from its FirewallZone
        rows (matched on device name / hostname).  Each zone subnet's level
        is inferred from the classified hosts inside it, clamped to the
        device's boundary sides when the boundary is known."""
        key = id(ep)
        if key in self._legacy_maps:
            return self._legacy_maps[key]
        names: dict[str, set[int]] = {}
        subnets: list = []
        lo, hi = ep.boundary if ep.purdue_zone_from is not None else (None, None)
        zones = []
        try:
            wanted = {n.lower() for n in (ep.name, ep.device_hostname) if n}
            if wanted:
                zones = [z for z in self.db.query(FirewallZone).all()
                         if (z.device_name or "").lower() in wanted]
        except Exception:  # pragma: no cover
            log.debug("FirewallZone lookup failed", exc_info=True)
        for z in zones:
            if not z.ip_cidr:
                continue
            try:
                net = ipaddress.ip_network(z.ip_cidr, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                continue
            levels = self._levels_of_hosts_in(net)
            if not levels:
                continue
            if lo is not None:
                levels = {lv for lv in levels if lv <= lo or lv >= hi} or None
                if not levels:
                    continue
            subnets.append((net, levels))
            for label in (z.zone_name, z.interface_name):
                if label and label.strip():
                    names.setdefault(label.strip().lower(), set()).update(levels)
        m = {"names": names, "subnets": subnets}
        self._legacy_maps[key] = m
        return m

    def _legacy_side_levels(self, ep, zone_str, addr) -> Optional[set[int]]:
        m = self._legacy_map(ep)
        if zone_str and m["names"]:
            # C-05: comma-separated list; keep whole (possibly spaced) names.
            toks = [t.strip().strip("'\"[]").lower() for t in str(zone_str).split(",")]
            toks = [t for t in toks if t]
            if toks and not any(t in _ANY_ZONE_TOKENS for t in toks):
                levels: set[int] = set()
                for t in toks:
                    lv = m["names"].get(t)
                    if not lv:
                        levels = set()
                        break
                    levels |= lv
                if levels:
                    return levels
        spec = rm.parse_address(addr)
        if spec == rm.ANY or isinstance(spec, rm.Unresolved):
            return None
        best = None
        for net, levels in m["subnets"]:
            if rm.addr_contains(net, spec):
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, levels)
        if best:
            return set(best[1])
        # last resort: the classified hosts the rule's own address covers
        return self._levels_of_hosts_in(spec)

    def parsed(self, rule) -> tuple:
        """(src_spec, dst_spec, protos, ports) parsed once per rule."""
        key = id(rule) if rule.id is None else rule.id
        p = self._parsed.get(key)
        if p is None:
            p = (rm.parse_address(rule.src, v6_default_is_any=False),
                 rm.parse_address(rule.dst, v6_default_is_any=False),
                 rm.parse_protocols(rule.protocol),
                 rm.parse_ports(rule.dst_port))
            self._parsed[key] = p
        return p

    # -- direction ---------------------------------------------------------
    def _zone_map_for(self, ep: _EnforcementPoint) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for n in (ep.name, ep.device_hostname):
            if n:
                for zname, members in self._zones_by_device.get(n.lower(), {}).items():
                    out.setdefault(zname, []).extend(members)
        return out

    def zone_def(self, fw_id, vdom, name: str) -> Optional[dict]:
        """B-07: the FortiOS zone ``name`` of (firewall, vdom), or None."""
        if fw_id is None or not name:
            return None
        return self._zone_defs.get((fw_id, vdom), {}).get(name.strip().lower())

    def _zone_levels(self, ep, fw_id, zone_str: Optional[str], vdom=None):
        """Purdue levels of a rule side's interface / zone list.  None =
        undetermined (applies both ways); ``_SIDE_UNKNOWN`` = it names a
        FortiOS zone whose membership could not be parsed (B-07: the rule
        is treated as uncertain); an empty set = only empty zones (the rule
        matches no interface)."""
        if not zone_str or fw_id is None:
            return None
        # C-05: split on the comma that separates srcintf / dstintf list
        # elements (names may contain spaces, e.g. "OT Zone") and match each
        # WHOLE name - never a whitespace-shattered fragment.
        tokens = [t.strip().strip("'\"[]").lower() for t in str(zone_str).split(",")]
        tokens = [t for t in tokens if t]
        if not tokens or any(t in _ANY_ZONE_TOKENS for t in tokens):
            return None
        names = self._iface_names.get(fw_id, {})          # name + alias + zone_label
        exact = self._iface_exact.get(fw_id, {})          # interface NAME only
        unlabelled = self._iface_unlabelled.get(fw_id, set())
        zmap = self._zone_defs.get((fw_id, vdom))
        legacy = None
        levels: set[int] = set()
        matched_any = False
        other_leg = False          # MP-09: names a known interface without a level

        def _known(m) -> Optional[bool]:
            """True: a known unlabelled interface (another leg / uncertain);
            None: nothing known by that name."""
            return True if m in unlabelled else None

        for tok in tokens:
            # C-09: a FortiOS zone definition wins over an interface whose
            # ALIAS equals the zone name, and over the legacy FirewallZone map.
            z = fz.zone_lookup(zmap, tok)
            if z is not None:
                zmembers, zresolved = z
                if not zresolved:
                    return _SIDE_UNKNOWN       # B-07: membership unknown
                for m in zmembers:
                    mlv = names.get(m)
                    if not mlv:
                        if _known(m):
                            other_leg = True   # MP-09: member exists, no level
                            continue
                        return None
                    levels |= mlv
                    matched_any = True
                continue
            lv = exact.get(tok)                 # exact interface name
            if lv:
                levels |= lv
                matched_any = True
                continue
            lv = names.get(tok)                 # interface alias / zone_label
            if lv:
                levels |= lv
                matched_any = True
                continue
            if _known(tok):
                other_leg = True                # MP-09: interface exists, no level
                continue
            if legacy is None:
                legacy = self._zone_map_for(ep)
            members = legacy.get(tok)
            if not members:
                return None
            for m in members:
                mlv = names.get(m)
                if not mlv:
                    if _known(m):
                        other_leg = True
                        continue
                    return None
                levels |= mlv
                matched_any = True
        if other_leg:
            if not ep.multi_leg and not names:
                # D-11: an explicit boundary with NO labelled interface at all
                # - every rule applies both ways and the rows say
                # direction_unverified (the twins use the boundary, MP-15)
                return None
            self._unlabelled_sides.add((id(ep), zone_str))
            if not ep.multi_leg:
                # an explicit two-level boundary with other interfaces
                # labelled: the unlabelled one may be either end - uncertain,
                # never silently "any leg"
                return _SIDE_UNKNOWN
            if not levels:
                return frozenset()    # only other legs: never this crossing
            return levels             # the labelled legs it also names
        if not matched_any:
            return frozenset()        # only empty zones: matches no interface
        return levels or None

    def _addr_levels(self, fw_id, addr: Optional[str]) -> Optional[set[int]]:
        if fw_id is None:
            return None
        spec = rm.parse_address(addr, v6_default_is_any=False)
        if spec == rm.ANY or isinstance(spec, rm.Unresolved):
            return None
        best = None
        for net, level in self._iface_subnets.get(fw_id, []):
            if rm.addr_contains(net, spec):
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, level)
        return {best[1]} if best else None

    def side_levels(self, ep, rule, which: str) -> Optional[set[int]]:
        key = (id(ep), id(rule), which)
        if key in self._side_cache:
            return self._side_cache[key]
        lv = self._side_levels(ep, rule, which)
        self._side_cache[key] = lv
        return lv

    def _side_levels(self, ep, rule, which: str) -> Optional[set[int]]:
        fw_id = ep.firewall_id if ep.firewall_id is not None else rule.firewall_id
        zone = rule.src_zone if which == "src" else rule.dst_zone
        addr = rule.src if which == "src" else rule.dst
        if fw_id is None:
            # N-05: legacy FirewallDevice with no linked Firewall - infer from
            # FirewallZone subnets / classified hosts before falling back to
            # "both directions".
            if ep.multi_leg or ep.purdue_zone_from is None:
                return None
            return self._legacy_side_levels(ep, zone, addr)
        lv = self._zone_levels(ep, fw_id, zone, getattr(rule, "vdom", None))
        if lv is _SIDE_UNKNOWN:
            return lv
        if lv is None:
            lv = self._addr_levels(fw_id, addr)
            if which == "dst":
                lv = self._prenat_dst_levels(ep, fw_id, addr, lv)
        return lv

    def _prenat_dst_levels(self, ep, fw_id, addr, lv):
        """A-05: on a pre-NAT vendor (_NAT_POLICY_MATCH "pre") a security
        rule for DNAT'd traffic names the EXTERNAL (VIP) address, which lies
        in the outside interface subnet.  Its real destination - and so the
        direction it governs - is the mapped address.  A dst wholly inside a
        DNAT ext_ip takes the mapped address's level(s); one that merely
        overlaps an ext_ip gets them added (and None, i.e. both directions,
        when the mapped level is not known)."""
        if lv is None or not self.has_nat:
            return lv
        spec = rm.parse_address(addr, v6_default_is_any=False)
        if spec == rm.ANY or isinstance(spec, rm.Unresolved):
            return lv
        out, replaced = set(lv), False
        for n in self.nats_for(ep):
            if n.kind != "dnat" or self.nat_policy_mode(ep, n) != "pre":
                continue
            if not rm.addr_overlaps(n.ext, spec):
                continue
            mlv = self._spec_levels(fw_id, n.mapped)
            if mlv is None:
                return None  # direction undeterminable -> applies both ways
            if rm.addr_contains(n.ext, spec) and not replaced:
                out, replaced = set(), True
            out |= mlv
        return out or None

    def _spec_levels(self, fw_id, spec) -> Optional[set[int]]:
        """Purdue level(s) of a parsed address spec: interface subnet, else
        classified hosts inside it."""
        best = None
        for net, level in self._iface_subnets.get(fw_id, []):
            if rm.addr_contains(net, spec):
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, level)
        if best:
            return {best[1]}
        return self._levels_of_hosts_in(spec)

    def direction_unverified(self, ep, rule) -> bool:
        """D-11: True when NEITHER side of the rule resolves to a Purdue level
        (no labelled interface, zone or classified host behind it), so
        rule_applies() answered True for both directions by default rather
        than from evidence.  Rows built from such a rule may show the
        reverse of the real direction."""
        if str(getattr(rule, "policy_id", "") or "").startswith("implicit:route:"):
            return False      # RS-04: a switch routes both ways - no direction to verify
        try:
            sl, dl = self.side_levels(ep, rule, "src"), self.side_levels(ep, rule, "dst")
        except Exception:
            return True
        return sl is None and dl is None

    def rule_applies(self, ep, rule, from_level, to_level):
        """True / False, or "uncertain" when a side names a FortiOS zone
        whose membership is unknown (B-07) and the other side does not
        exclude the crossing."""
        if from_level is None or to_level is None:
            return True
        lo, hi = ep.boundary

        def side(x):
            if x >= hi:
                return "hi"
            if x <= lo:
                return "lo"
            return None

        def compatible(levels, entering):
            if levels is None or levels is _SIDE_UNKNOWN:
                return True
            if not levels:
                return False          # empty zone: no interface to match
            if ep.multi_leg:
                # One box, many legs: the rule's side must be exactly this leg.
                return entering in levels
            target = side(entering)
            if target is None:
                return True
            return any(side(x) in (None, target) for x in levels)

        sl, dl = self.side_levels(ep, rule, "src"), self.side_levels(ep, rule, "dst")
        if not (compatible(sl, from_level) and compatible(dl, to_level)):
            return False
        if sl is _SIDE_UNKNOWN or dl is _SIDE_UNKNOWN:
            return "uncertain"
        return True

    def intrazone_state(self, ep, from_level, to_level, vdom) -> Optional[str]:
        """B-07: is this crossing traffic between members of ONE FortiOS zone
        with ``set intrazone allow``?  "allow" - every (ingress, egress)
        interface pair on the two sides is in the same allow-zone;
        "maybe" - only some pairs are; None - none (or not determinable).
        Intrazone deny (the default) needs no special handling: such traffic
        needs a zone->zone policy, which the level mapping already finds."""
        fw_id = ep.firewall_id
        if fw_id is None or from_level is None or to_level is None:
            return None
        zmap = self._zone_defs.get((fw_id, vdom))
        if not zmap:
            return None
        allow_of: dict = {}
        for zname, zd in zmap.items():
            if zd.get("intrazone") == "allow" and zd["resolved"]:
                for m in zd["members"]:
                    allow_of[m] = zname
        if not allow_of:
            return None
        lo, hi = ep.boundary

        def on_side(lv, target):
            if ep.multi_leg:
                return lv == target
            if target >= hi:
                return lv >= hi
            if target <= lo:
                return lv <= lo
            return False

        ifs = self._leveled_ifaces.get(fw_id, [])
        ing = [n for n, lv in ifs if on_side(lv, from_level)]
        egr = [n for n, lv in ifs if on_side(lv, to_level)]
        pairs = [(i, e) for i in ing for e in egr if i != e]
        if not pairs:
            return None
        hits = [allow_of.get(i) is not None and allow_of.get(i) == allow_of.get(e)
                for i, e in pairs]
        if all(hits):
            return "allow"
        return "maybe" if any(hits) else None


# ---------------------------------------------------------------------------
# Per-device evaluation
# ---------------------------------------------------------------------------

def _addr_coverage(rule_addr, ip: Optional[str], family: Optional[int] = None) -> str:
    """'full' | 'partial' (restricted hosts, no IP in query) | 'none' | 'uncertain'.

    ``rule_addr`` is a raw string or an already-parsed rule_match spec.
    F-07: without a concrete IP the query's address ``family`` decides -
    a rule with no address of that family is 'none', one covering the whole
    family (0.0.0.0/0 for IPv4, ::/0 for IPv6, or "any") is 'full'."""
    spec = rule_addr
    if spec is None or isinstance(spec, str) and spec != rm.ANY:
        spec = rm.parse_address(rule_addr)
    if isinstance(spec, rm.Unresolved):
        return "uncertain"
    if spec == rm.ANY:
        return "full"
    if not ip:
        if family is not None:
            vers = rm.addr_versions(spec) or frozenset()
            if family not in vers:
                return "none"
            if rm.is_family_wide(spec, family):
                return "full"
        return "partial"
    r = rm.ip_in_addr(ip, spec)
    if r is None:
        return "uncertain"
    return "full" if r else "none"


def _scope_piece(spec, ip, cov, family):
    """The host scope a permit contributes for one side: unrestricted when
    the side is fully covered (or the query names a concrete IP), else the
    rule's own address restricted to the query family."""
    if cov == "full" or ip:
        return rm.ANY
    narrowed = rm.addr_restrict_family(spec, family)
    return narrowed if narrowed is not None else spec


def _service_coverage(rp, rports, qp, qport):
    """Returns (coverage, effective_protos, effective_ports)."""
    if isinstance(rp, rm.Unresolved) or isinstance(rports, rm.Unresolved):
        return "unresolved", rp, rports
    # Protocol
    if qp == rm.ANY:
        pcov = "full" if rp == rm.ANY else "partial"
    elif rm.protos_contain(rp, qp):
        pcov = "full"
    elif rm.protos_overlap(rp, qp):
        pcov = "partial"
    else:
        return "none", None, None
    eff_p = rm.protos_intersect(rp, qp)
    # Port
    if qport is None:
        xcov = "full" if rports == rm.ANY else "partial"
        eff_x = rports
    else:
        if eff_p != rm.ANY and not (eff_p & rm.PORT_PROTOCOLS):
            return "none", None, None  # icmp etc. has no ports
        if not rm.port_in(qport, rports):
            return "none", None, None
        xcov = "full"
        eff_x = ((qport, qport),)
    cov = "full" if pcov == "full" and xcov == "full" else "partial"
    return cov, eff_p, eff_x


def _is_permit(rule) -> bool:
    return (rule.action or "").strip().lower() in _PERMIT_ACTIONS


def _rule_label(rule) -> str:
    vd = getattr(rule, "vdom", None)
    base = str(rule.policy_id or rule.id)
    return f"{base} (vdom {vd})" if vd is not None else base


def _is_cross_family_rule(src_spec, dst_spec) -> bool:
    """A rule whose src and dst are single, DIFFERENT address families - a
    policy46 / policy64 row (N-25): it exists because a VIP46 / VIP64 (or
    pool) translates the family."""
    sv, dv = rm.addr_versions(src_spec), rm.addr_versions(dst_spec)
    return bool(sv and dv and len(sv) == 1 and len(dv) == 1 and sv != dv)


def _evaluate_device(ctx: _Context, ep, q: dict, from_level, to_level):
    """Returns (public_dict, _Verdict).

    N-24: a firewall with several VDOMs keeps one rule list per VDOM (policy
    ids and ordering are per VDOM).  Each VDOM is evaluated separately and
    the results are OR-ed (most permissive wins, like alternative paths):
    a flow traverses the VDOM that owns its ingress interface, and which
    one that is cannot be told here.  Inter-VDOM links are not followed."""
    rules = ctx.rules_for(ep)
    by_vdom: dict = {}
    for r in rules:
        by_vdom.setdefault(getattr(r, "vdom", None), []).append(r)
    if len(by_vdom) <= 1:
        return _evaluate_device_rules(ctx, ep, q, from_level, to_level, rules)
    results = [(vd, *_evaluate_device_rules(ctx, ep, q, from_level, to_level, grp))
               for vd, grp in by_vdom.items()]
    uv = _union_verdicts([v for _vd, _d, v in results])
    want = {"permitted": "permit", "denied": "deny"}.get(uv.decision, uv.decision)
    chosen = next((d for _vd, d, _v in results if d.get("decision") == want), results[0][1])
    out = dict(chosen)
    out["vdoms"] = [{"vdom": vd, "decision": d.get("decision")} for vd, d, _v in results]
    out["permitted_scopes"] = [sc for _vd, d, _v in results for sc in d.get("permitted_scopes") or []]
    out["unresolved_rules"] = [u for _vd, d, _v in results for u in d.get("unresolved_rules") or []]
    out["rules_evaluated"] = sum(d.get("rules_evaluated", 0) for _vd, d, _v in results)
    out["rules_skipped_direction"] = sum(d.get("rules_skipped_direction", 0) for _vd, d, _v in results)
    su = [x for _vd, d, _v in results for x in d.get("rules_skipped_unlabelled") or []]
    if su:
        out["rules_skipped_unlabelled"] = su[:20]
    xf = [x for _vd, d, _v in results for x in d.get("cross_family_rules") or []]
    if xf:
        out["cross_family_rules"] = xf
        out["nat_dependent"] = True
    if want != chosen.get("decision") or uv.decision in ("partial", "unknown"):
        out["decision"] = want
        out["permitted_services"] = uv.service_strings()
        out["reason"] = (f"Evaluated per VDOM ({', '.join(str(vd) for vd, _d, _v in results)}); "
                         f"most permissive VDOM result: {want}")
    return out, uv


def _evaluate_device_rules(ctx: _Context, ep, q: dict, from_level, to_level, rules):
    """One rule list (one VDOM, or a firewall without VDOMs) - see
    _evaluate_device.  Cross-family (policy46 / policy64) rules cannot be
    matched by a level-pair query: when one could permit the flow and the
    plain evaluation says "denied", the result is "unknown" (NAT-dependent),
    never a wrong "denied"."""
    base, v = _evaluate_device_core(ctx, ep, q, from_level, to_level, rules)
    xh = base.pop("_xfam", None)
    if xh:
        base["cross_family_rules"] = [dict(_rule_dict(r), permit=p) for r, p in xh][:20]
        base["nat_dependent"] = True
        if v.decision == "denied" and any(p for _r, p in xh):
            base.update(
                decision="unknown", reason_code="cross_family_nat", implicit_deny=False,
                reason=("Only an address-family translating rule (policy46 / policy64, "
                        "VIP46 / VIP64) may permit this flow; without concrete addresses "
                        "to translate the result depends on NAT"))
            v = _Verdict("unknown")
    return base, v


def _evaluate_device_core(ctx: _Context, ep, q: dict, from_level, to_level, rules):
    base = {
        "firewall_device": _fw_device_dict(ep),
        "matching_rule": None,
        "implicit_deny": False,
        "permitted_services": [],
        "denied_services": [],
        "permitted_scopes": [],
        "unresolved_rules": [],
        "rules_evaluated": 0,
        "rules_skipped_direction": 0,
        "direction": {"from_level": from_level, "to_level": to_level},
        "direction_unverified": [],   # D-11: permit rule ids applied without level evidence
    }
    if not rules:
        base.update(decision="no_policy", reason_code="no_rules_loaded",
                    reason="No rules loaded for this device (config not ingested)")
        return base, _Verdict("no_policy")

    qp, qport = q["protos"], q["port"]
    fam = q.get("family")
    permits: list[dict] = []          # {"svc": (src, dst, p, x), "rule": rule, "restricted": bool}
    partial_denies: list[tuple] = []  # (protos, ports, rule) — full-address, specific-service
    uncertain: list[tuple] = []       # (rule, is_permit)
    xfam_hits: list[tuple] = []       # (rule, is_permit): cross-family rules, level-pair query
    evaluated = skipped = 0
    skipped_unlabelled: list = []     # MP-09: rules on an unlabelled leg (not this crossing)
    terminal = None

    for rule in rules:
        dir_uncertain = False
        try:
            applies = ctx.rule_applies(ep, rule, from_level, to_level)
            if not applies:
                skipped += 1
                unl = [z for z in (rule.src_zone, rule.dst_zone)
                       if z and (id(ep), z) in ctx._unlabelled_sides]
                if unl and _is_permit(rule) and len(skipped_unlabelled) < 20:
                    skipped_unlabelled.append({**_rule_dict(rule), "unlabelled": unl})
                continue
            dir_uncertain = applies == "uncertain"
        except Exception:  # never let a malformed row abort the analysis
            log.warning("direction check failed for rule %s", rule.id, exc_info=True)
        evaluated += 1
        permit = _is_permit(rule)
        src_spec, dst_spec, rp, rports = ctx.parsed(rule)
        if (q["src_ip"] is None or q["dst_ip"] is None) and _is_cross_family_rule(src_spec, dst_spec):
            # N-25: a policy46 / policy64 row has no address of the query family
            # on its far side; with a side left open we cannot tell what the
            # translation maps to, so note it instead of silently skipping it.
            if _addr_coverage(src_spec, q["src_ip"], fam) != "none":
                xfam_hits.append((rule, permit))
            continue
        src_cov = _addr_coverage(src_spec, q["src_ip"], fam)
        dst_cov = _addr_coverage(dst_spec, q["dst_ip"], fam)
        if "none" in (src_cov, dst_cov):
            continue
        svc_cov, eff_p, eff_x = _service_coverage(rp, rports, qp, qport)
        if svc_cov == "none":
            continue
        if dir_uncertain:
            # B-07: the rule names a FortiOS zone whose member interfaces are
            # unknown - whether it governs this direction cannot be told.
            uncertain.append((rule, permit))
            unl = [z for z in (rule.src_zone, rule.dst_zone)
                   if z and (id(ep), z) in ctx._unlabelled_sides]
            base["unresolved_rules"].append({
                **_rule_dict(rule), "unresolved": "zone",
                "note": (f"names interface(s) without a Purdue level ({', '.join(unl)}) - "
                         "cannot determine whether the rule applies to this direction; "
                         "label the interface" if unl else
                         "zone membership unresolved (e.g. SD-WAN zone) - cannot "
                         "determine whether the rule applies to this direction"),
            })
            continue
        # A-04: fail-unknown.  A rule whose match against the query cannot be
        # decided (unresolved address / service / protocol object) never
        # silently drops out of the evaluation: it is recorded as uncertain so
        # an implicit/explicit deny it might precede, or a permit it might
        # shadow, yields "unknown" rather than "denied"/"permitted".
        if svc_cov == "unresolved":
            base["unresolved_rules"].append({
                **_rule_dict(rule),
                "unresolved": ("address+service" if "uncertain" in (src_cov, dst_cov)
                               else "service"),
                "note": ("unresolved service object - cannot determine whether it "
                         "matches the queried port" if qport is not None else
                         "unresolved service object - permits an unknown service"
                         if permit else
                         "unresolved service object - denies an unknown service"),
            })
            if qport is None and permit and "uncertain" not in (src_cov, dst_cov):
                # Something (an unknown service) is definitely permitted.
                permits.append({"svc": (_scope_piece(src_spec, q["src_ip"], src_cov, fam),
                                        _scope_piece(dst_spec, q["dst_ip"], dst_cov, fam),
                                        rp, rports), "rule": rule,
                                "restricted": src_cov != "full" or dst_cov != "full",
                                "after_unc_deny": bool(uncertain and any(not p for _, p in uncertain))})
            else:
                uncertain.append((rule, permit))
            continue
        if "uncertain" in (src_cov, dst_cov):
            uncertain.append((rule, permit))
            base["unresolved_rules"].append({
                **_rule_dict(rule), "unresolved": "address",
                "note": "unresolvable address object - cannot determine match",
            })
            continue

        addr_full = src_cov == "full" and dst_cov == "full"
        if addr_full and svc_cov == "full":
            terminal = rule
            break
        if permit:
            x = eff_x
            if not isinstance(x, rm.Unresolved):
                for dp, dx, _r in partial_denies:
                    if rm.protos_contain(dp, eff_p) and not isinstance(dx, rm.Unresolved):
                        x = rm.ranges_subtract(x, dx)
                        if not x:
                            break
                if not x:
                    continue  # fully blocked by earlier specific denies
                if x == rm.FULL_RANGE:
                    x = rm.ANY
            permits.append({"svc": (_scope_piece(src_spec, q["src_ip"], src_cov, fam),
                                    _scope_piece(dst_spec, q["dst_ip"], dst_cov, fam),
                                    eff_p, x),
                            "rule": rule, "restricted": not addr_full,
                            "after_unc_deny": any(not p for _, p in uncertain)})
        elif addr_full:
            partial_denies.append((eff_p, eff_x, rule))

    base["rules_evaluated"] = evaluated
    base["rules_skipped_direction"] = skipped
    if skipped_unlabelled:
        # MP-09: permits that name an interface without a level were taken
        # as "another leg" of this box; if that interface is really one end
        # of this crossing they are missing from the verdict
        base["rules_skipped_unlabelled"] = skipped_unlabelled
    if xfam_hits:
        base["_xfam"] = xfam_hits
    denied_strs = _dedupe(s for p, x, _ in partial_denies for s in rm.format_services(p, x))
    deny_pieces = _dedupe((p, x) for p, x, _ in partial_denies
                          if not isinstance(p, rm.Unresolved) and not isinstance(x, rm.Unresolved))
    # MP-10: the same denies in a JSON form for the access-path enumeration
    base["denied_pieces"] = [{"protos": sorted(p) if p != rm.ANY else "any",
                              "ports": list(rm._as_ranges(x)) if x != rm.ANY else "any"}
                             for p, x in deny_pieces]
    # C-10: dedupe permitted pieces via a hashable set, not O(n) `in` on a
    # list of tuples-of-ipaddress-objects (quadratic at tens of thousands of
    # rows).  Pieces are fully hashable (ip_network / AddrRange / AddrSet /
    # frozenset / port-range tuples), so set membership is identical to the
    # previous list membership but O(1).
    services = []
    _seen_svc: set = set()
    for pm in permits:
        s = pm["svc"]
        if s not in _seen_svc:
            _seen_svc.add(s)
            services.append(s)
    unverified = []
    for r in list(pm["rule"] for pm in permits) + ([terminal] if terminal is not None else []):
        if _is_permit(r) and r.id not in unverified and ctx.direction_unverified(ep, r):
            unverified.append(r.id)
    base["direction_unverified"] = unverified
    base["permitted_scopes"] = [
        {"services": rm.format_services(*pm["svc"][2:]), "src": pm["rule"].src,
         "dst": pm["rule"].dst, "host_restricted": pm["restricted"],
         "rule_id": pm["rule"].id, "policy_id": pm["rule"].policy_id,
         "vdom": getattr(pm["rule"], "vdom", None),
         "external_internet": any(rm.is_external_addr_token(x) for x in (pm["rule"].src, pm["rule"].dst))}
        for pm in permits
    ]
    unc_permit = any(p for _, p in uncertain)
    unc_deny = any(not p for _, p in uncertain)

    def _partial(reason, implicit, matching=None):
        if any(pm.get("after_unc_deny") for pm in permits):
            # A-04: an earlier deny with an unresolvable object may block
            # these permits - we cannot say what is permitted.
            base.update(decision="unknown", reason_code="unresolved_match",
                        matching_rule=matching,
                        reason=("Specific permits follow a deny rule that uses an "
                                "unresolvable object"))
            return base, _Verdict("unknown")
        v = _Verdict("partial", services, denied_strs, deny_pieces)
        base.update(decision="partial", reason_code="partial_services",
                    implicit_deny=implicit, matching_rule=matching,
                    permitted_services=v.service_strings(), reason=reason)
        return base, v

    if terminal is not None:
        rd = _rule_dict(terminal)
        if _is_permit(terminal):
            if unc_deny:
                base.update(decision="unknown", reason_code="unresolved_match", matching_rule=rd,
                            reason=(f"Permit rule {_rule_label(terminal)} matches, but an earlier "
                                    f"deny rule uses an unresolvable object"))
                return base, _Verdict("unknown")
            base.update(decision="permit", reason_code="matched_rule", matching_rule=rd,
                        permitted_services=["any"], denied_services=denied_strs,
                        reason=f"Matched permit rule {_rule_label(terminal)}"
                               + (f" (earlier rules deny {', '.join(denied_strs)})" if denied_strs else ""))
            return base, _Verdict("permitted", [_SVC_ANY], denied_strs, deny_pieces)
        # explicit deny
        if permits:
            return _partial(
                f"Only specific services/hosts are permitted before deny rule "
                f"{_rule_label(terminal)}", False, rd)
        if unc_permit:
            base.update(decision="unknown", reason_code="unresolved_match", matching_rule=rd,
                        reason=(f"Deny rule {_rule_label(terminal)} matches, but an earlier "
                                f"permit rule uses an unresolvable object"))
            return base, _Verdict("unknown")
        base.update(decision="deny", reason_code="matched_rule", matching_rule=rd,
                    reason=f"Matched deny rule {_rule_label(terminal)}")
        return base, _Verdict("denied")

    # No terminal rule: vendor implicit deny at the end of the policy.
    # B-07: FortiOS `set intrazone allow` - traffic between two member
    # interfaces of one zone is accepted when no policy matches it.
    vdom = getattr(rules[0], "vdom", None) if rules else None
    intra = ctx.intrazone_state(ep, from_level, to_level, vdom)
    if intra == "allow":
        if unc_deny:
            base.update(decision="unknown", reason_code="unresolved_match",
                        reason=("Intrazone traffic is allowed by the zone, but a deny "
                                "rule uses an unresolvable object"))
            return base, _Verdict("unknown")
        base.update(decision="permit", reason_code="intrazone_allow",
                    permitted_services=["any"], denied_services=denied_strs,
                    reason=("No policy matches; both sides are member interfaces of one "
                            "zone with intrazone allow")
                           + (f" (earlier rules deny {', '.join(denied_strs)})" if denied_strs else ""))
        return base, _Verdict("permitted", [_SVC_ANY], denied_strs, deny_pieces)
    if intra == "maybe":
        base.update(decision="unknown", reason_code="intrazone_partial",
                    reason=("No policy matches this traffic, but some interface pairs of "
                            "this crossing are members of one zone with intrazone allow "
                            "(accepted without a policy) - cannot tell which pair the "
                            "traffic uses"))
        return base, _Verdict("unknown")
    if permits:
        return _partial("Only specific services/hosts are permitted; everything else "
                        "hits the implicit deny", True)
    if unc_permit:
        base.update(decision="unknown", reason_code="unresolved_match",
                    reason="No rule definitely matched; a permit rule uses an "
                           "unresolvable object")
        return base, _Verdict("unknown")
    base.update(decision="deny", reason_code="implicit_deny", implicit_deny=True,
                reason=(f"Implicit deny: none of the {len(rules)} loaded rules match "
                        f"this traffic/direction (vendor default-deny)"))
    return base, _Verdict("denied")


def _make_query(src_ip, dst_ip, dst_port, protocol, ip_version: Optional[int] = None) -> dict:
    """Traffic query.  ``family`` (4 / 6) comes from the IPs; level-pair
    queries without IPs evaluate ``ip_version`` (default IPv4, F-07)."""
    protos = rm.parse_protocols(protocol) if protocol else rm.ANY
    if isinstance(protos, rm.Unresolved):
        protos = rm.ANY
    port = None
    if dst_port is not None:
        try:
            port = int(dst_port)
        except (TypeError, ValueError):
            port = None
    family = rm.ip_version(src_ip) or rm.ip_version(dst_ip) or (ip_version if ip_version in (4, 6) else 4)
    return {"src_ip": src_ip, "dst_ip": dst_ip, "port": port, "protos": protos, "family": family}


def _qkey(q) -> tuple:
    return (q["src_ip"], q["dst_ip"], q["port"], q["protos"], q.get("family"))


def _hop_eps(ctx, boundary, exclude=None) -> list:
    """The enforcement points a flow over ``boundary`` is judged against, in
    boundary order.  LS-03: with a known carrier (the router MAC on the
    captured frames, ctx.carrier_fw_id) and both a routing switch and a
    firewall on the boundary, only the device that carried it.  MP-02:
    ``exclude`` (physical box keys) drops boxes this path already crossed."""
    eps = list(ctx.boundary_map[boundary])
    if exclude:
        eps = [ep for ep in eps if getattr(ep, "physical", ("obj", id(ep))) not in exclude]
    carrier = getattr(ctx, "carrier_fw_id", None)
    par = [ep for ep in eps if getattr(ep, "parallel", False)]
    if carrier is None or not par or len(par) == len(eps):
        return eps
    if carrier in {ep.firewall_id for ep in par}:
        return [ep for ep in par if ep.firewall_id == carrier]
    if carrier in {ep.firewall_id for ep in eps if ep not in par}:
        return [ep for ep in eps if ep not in par]
    return eps


def hop_alternatives(eps: list) -> list:
    """The ways a flow can cross one boundary, as lists of EP INDEXES into
    ``eps`` (the order _hop_eps returns).  Algebra: EPs of one box that
    share a series_group are in series; a box's groups are alternatives;
    series boxes are in series (one choice of group per box, every
    combination); a routing switch (parallel) is an alternative of its own
    beside the series boxes (LS-02).  Every alternative must be permitted
    end to end for the flow to pass that way."""
    boxes: dict = {}
    par_alts = []
    order = []
    for i, ep in enumerate(eps):
        if getattr(ep, "parallel", False):
            par_alts.append([i])
            continue
        box = tuple(ep.physical[:2]) if isinstance(ep.physical, tuple) else ("ep", id(ep))
        if box not in boxes:
            boxes[box] = {}
            order.append(box)
        boxes[box].setdefault(getattr(ep, "series_group", None), []).append(i)
    if not boxes:
        return par_alts
    # MP-01: boxes are in series only within a declared series set
    # (series_key); series sets are alternatives of each other.
    sets: dict = {}
    set_order = []
    for box in order:
        ep0 = eps[boxes[box][next(iter(boxes[box]))][0]]
        skey = getattr(ep0, "series_key", None) or ("box", box)
        if skey not in sets:
            sets[skey] = []
            set_order.append(skey)
        sets[skey].append(box)
    out = []
    for skey in set_order:
        combos = [[]]
        for box in sets[skey]:
            groups = list(boxes[box].values())
            combos = [c + g for c in combos for g in groups]
        out += combos
    return out + par_alts


_EVAL_CACHE_MAX = 20000


def _cache_put(ctx, key, value) -> None:
    """AU full review C7: the per-context evaluation cache is keyed by the
    concrete query (host addresses and ports), so a long-lived context fed
    every observed flow grew without bound.  Drop the oldest half once the
    cap is reached (dict order is insertion order)."""
    c = ctx._eval_cache
    if len(c) >= _EVAL_CACHE_MAX:
        for k in list(c)[: _EVAL_CACHE_MAX // 2]:
            del c[k]
    c[key] = value


def _arrangement(eps: list, alts: list) -> str:
    """How the boxes of one hop relate: "single" (one box), "series" (one
    alternative of several boxes), "parallel" (several alternatives of one
    box each) or "mixed"."""
    boxes = {tuple(ep.physical[:2]) if isinstance(ep.physical, tuple) else ("ep", id(ep)) for ep in eps}
    if len(boxes) <= 1:
        return "single"
    multi = [a for a in alts if len({tuple(eps[i].physical[:2]) for i in a}) > 1]
    if len(alts) <= 1:
        return "series"
    return "mixed" if multi else "parallel"


def _box_contains(ctx, ep, ips) -> Optional[int]:
    """How many of ``ips`` fall inside the box's labelled interface networks
    (0..len(ips)); None when the box has no usable network (no evidence
    either way)."""
    nets = ctx._iface_subnets.get(ep.firewall_id) if ep.firewall_id is not None else None
    if not nets:
        return None
    n = 0
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            continue
        if any(net.version == a.version and a in net for net, _lv in nets):
            n += 1
    return n


def _select_alternatives(ctx, eps: list, alts: list, q: dict, ep_queries=None) -> tuple:
    """MP-01: with several alternatives on a hop, keep the ones a concrete
    flow can actually cross.

    1. Carrier (LS-03): the router MAC seen on the frames names the box -
       only alternatives containing it.
    2. Placement: for a host query, every alternative is scored by how many
       of the flow's addresses its boxes' labelled interface networks hold
       (both endpoints beat one, one beats none); alternatives scoring below
       the best are dropped.  Alternatives whose boxes have no networks are
       kept (no evidence either way).
    Level-pair queries (no addresses) keep every alternative.  Returns
    (alternatives, placement note or None)."""
    if len(alts) <= 1:
        return alts, None
    carrier = getattr(ctx, "carrier_fw_id", None)
    if carrier is not None:
        keep = [a for a in alts if any(eps[i].firewall_id == carrier for i in a)]
        if keep and len(keep) < len(alts):
            return keep, {"basis": "carrier", "dropped": _alt_names(eps, [a for a in alts if a not in keep])}
    ips = list(dict.fromkeys(x for x in (q.get("src_ip"), q.get("dst_ip")) if x))
    if ep_queries:
        for eq in ep_queries.values():
            ips += [x for x in (eq.get("src_ip"), eq.get("dst_ip")) if x and x not in ips]
    if not ips:
        return alts, None
    score = []
    for a in alts:
        counts = [c for c in (_box_contains(ctx, eps[i], ips) for i in a) if c is not None]
        score.append(max(counts) if counts else None)
    known = [v for v in score if v is not None]
    if known and max(known) > 0 and min(known) < max(known):
        best = max(known)
        keep = [a for a, v in zip(alts, score) if v is None or v == best]
        return keep, {"basis": "interface networks",
                      "dropped": _alt_names(eps, [a for a, v in zip(alts, score) if v is not None and v != best])}
    return alts, None


def _alt_names(eps: list, alts: list) -> list:
    return [" + ".join(dict.fromkeys(eps[i].name or "?" for i in a)) for a in alts]


def _evaluate_hop(ctx: _Context, boundary, from_level, to_level, q,
                  ep_queries: Optional[dict] = None, exclude=None) -> tuple[dict, _Verdict]:
    """``ep_queries`` ({id(ep): query}) overrides the query per enforcement
    point - used when NAT makes devices on one boundary see different
    addresses (F-05).  ``exclude`` (MP-02): physical boxes already crossed
    on this path, left out of the hop."""
    epk = tuple(sorted((k, _qkey(v)) for k, v in ep_queries.items())) if ep_queries else None
    carrier = getattr(ctx, "carrier_fw_id", None)
    exclude = frozenset(exclude or ())
    key = (boundary, from_level, to_level, _qkey(q), epk, carrier, exclude)
    if key in ctx._eval_cache:
        return ctx._eval_cache[key]
    evals, verdicts = [], []
    eps = _hop_eps(ctx, boundary, exclude)
    for ep in eps:
        eq = (ep_queries or {}).get(id(ep), q)
        try:
            d, v = _evaluate_device(ctx, ep, eq, from_level, to_level)
        except Exception as exc:
            log.exception("reachability evaluation failed for %s", ep.name)
            d = {"firewall_device": _fw_device_dict(ep), "decision": "unknown",
                 "reason_code": "error", "reason": f"Evaluation error: {exc}",
                 "matching_rule": None}
            v = _Verdict("unknown")
        evals.append(d)
        verdicts.append(v)
    alts = hop_alternatives(eps)
    arrangement = _arrangement(eps, alts)      # of the boundary, before any selection
    alts, placement = _select_alternatives(ctx, eps, alts, q, ep_queries)
    if placement:
        # MP-01: a box this flow cannot cross keeps its evaluation for the
        # record, but is marked so the UI does not read its deny as the hop's
        in_play = {i for a in alts for i in a}
        for i, d in enumerate(evals):
            if i not in in_play:
                d["not_on_path"] = placement["basis"]
    alt_verdicts = [_combine_verdicts([verdicts[i] for i in alt]) for alt in alts] or [_combine_verdicts([])]
    bv = _union_verdicts(alt_verdicts) if len(alt_verdicts) > 1 else alt_verdicts[0]
    hop = {
        "boundary": f"{boundary[0]}↔{boundary[1]}",
        "zone_lo": boundary[0],
        "zone_hi": boundary[1],
        "from_level": from_level,
        "to_level": to_level,
        "enforcement_points": evals,
        "alternatives": alts,
        "arrangement": arrangement,
        "placement": placement,
        "already_crossed": sorted({ep.name or "?" for ep in ctx.boundary_map[boundary] if ep not in eps})
        if exclude else [],
        "boundary_decision": bv.decision,
        "permitted_services": bv.service_strings(),
        "denied_services": bv.denied_services,
    }
    _cache_put(ctx, key, (hop, bv))
    return hop, bv


def _evaluate_path(ctx, path_boundaries, src_level, q,
                   start_snat=None) -> tuple[list[dict], _Verdict]:
    """Walk a path hop by hop.  With NAT rows loaded and a concrete
    destination (F-05) the flow is translated as it goes: a DNAT on a hop's
    firewall turns ext_ip[:port] into mapped_ip[:mapped_port] (policy
    evaluated on the pre- or post-NAT destination per vendor, see
    _NAT_POLICY_MATCH) and later hops see the mapped destination; an SNAT
    applied by a hop that permits the flow changes the source seen by later
    hops.  Each hop carries ``nat`` (list of translations applied there).
    ``start_snat`` (a _Nat) forces that SNAT at its firewall - used when an
    observed session's source is already the translated address."""
    hops, verdicts = [], []
    current = src_level
    cur = q
    nat_on = ctx.has_nat and (q.get("dst_ip") or q.get("src_ip") or start_snat is not None)
    entries = getattr(path_boundaries, "entries", None)
    excludes = getattr(path_boundaries, "excludes", None)
    for i, boundary in enumerate(path_boundaries):
        if entries:
            current = entries[i]  # A-25: may have arrived over a flat hop
        excl = excludes[i] if excludes and i < len(excludes) else frozenset()
        nxt = boundary[1] if current == boundary[0] else boundary[0]
        if not nat_on:
            hop, v = _evaluate_hop(ctx, boundary, current, nxt, cur, exclude=excl)
        else:
            hop, v, cur, start_snat = _evaluate_hop_nat(ctx, boundary, current, nxt, cur, start_snat, excl)
        hops.append(hop)
        verdicts.append(v)
        current = nxt
        if v.decision == "denied":
            break
    if not nat_on and ctx.has_nat:
        # A-06: level-pair query (no IPs) - carry the permitted host scopes
        # through each hop's SNAT / DNAT before intersecting downstream.
        final = _combine_path_scoped_nat(ctx, path_boundaries, hops, verdicts)
    else:
        final = _combine_verdicts(verdicts)
    final = _xfam_downgrade(ctx, path_boundaries, hops, final, q)
    return hops, _flat_downgrade(path_boundaries, final, ctx)


def _xfam_applicable(n, q) -> bool:
    """Could this cross-family translation take the queried flow in?"""
    fams = n.client_families()
    if fams is not None and q.get("family") not in fams:
        return False
    if n.kind == "dnat":
        return not (q.get("dst_ip") and rm.ip_in_addr(q["dst_ip"], n.ext) is False)
    return not (q.get("src_ip") and rm.ip_in_addr(q["src_ip"], n.orig_src) is False)


def _xfam_downgrade(ctx, path_boundaries, hops, verdict, q) -> "_Verdict":
    """N-25: a VIP46 / VIP64 / policy46-64 pool translates the address family
    mid-path.  Hops AFTER it see the other family, but the scope algebra (and
    a level-pair query) evaluates them in the query's family, where they
    would deny for want of rules of that family.  So a "denied" verdict that
    lies beyond an applicable, un-applied cross-family translation is
    reported "unknown" (NAT-dependent) instead of a wrong "blocked"."""
    if verdict.decision != "denied" or not ctx.has_nat or len(hops) < 2:
        return verdict
    applied = {e.get("nat_rule_id") for h in hops for e in h.get("nat", [])}
    for i, boundary in enumerate(path_boundaries[:len(hops) - 1]):
        for ep in ctx.boundary_map[boundary]:
            for n in ctx.nats_for(ep):
                if n.cross_family and n.row.id not in applied and _xfam_applicable(n, q):
                    return _Verdict("unknown", denied_services=verdict.denied_services)
    return verdict


def _path_nat_annotation(ctx, path_boundaries, hops, q) -> dict:
    """NAT summary of one evaluated path (N-25), for matrix cells / path
    results.  ``nat_dependent`` is True when the verdict depends on a
    translation that could not be applied exactly: enabled NAT rows on the
    path's firewalls with no concrete translated address (interface-mode
    SNAT of an unknown interface, unresolved pool, ...), address-family
    translations, or a translation applied by over-approximation.
    ``translated_scopes`` are the permitted scopes as seen on the far side
    when level-pair translation was applied with concrete addresses."""
    notes, seen = [], set()

    def _ref(n, reason):
        r = n.row
        return {"nat_rule_id": r.id, "name": r.name, "type": n.kind, "nat_kind": n.nat_kind,
                "vdom": n.vdom, "reason": reason}

    excludes = getattr(path_boundaries, "excludes", None)
    for i, boundary in enumerate(path_boundaries):
        for ep in _hop_eps(ctx, boundary, excludes[i] if excludes and i < len(excludes) else None) \
                if boundary in ctx.boundary_map else []:
            for n in ctx.nats_for(ep):
                if n.cross_family and n.row.id not in seen and _xfam_applicable(n, q):
                    seen.add(n.row.id)
                    notes.append(_ref(n, "address-family translation (IPv4<->IPv6): the "
                                         "far side of this firewall is evaluated in the "
                                         "other family"))
            for n in ctx.unusable_nats_for(ep):
                if n.row.id not in seen:
                    seen.add(n.row.id)
                    notes.append(_ref(n, n.unusable_reason() or "not applicable"))
    key = ("nat_path", tuple(path_boundaries), tuple(id(h) for h in hops),
           tuple(getattr(path_boundaries, "excludes", None) or ()))
    meta = ctx._nat_meta.get(key)
    translated = []
    if meta and meta["touched"]:
        if not meta["exact"]:
            notes.append({"nat_rule_id": None, "name": None, "type": None, "nat_kind": None,
                          "vdom": None,
                          "reason": "translation matches only part of the permitted scope; "
                                    "reported as partial (over-approximation)"})
        for src, dst, p, x in meta["translated"]:
            d = {"src": rm.format_addr(src), "dst": rm.format_addr(dst),
                 "services": rm.format_services(p, x)}
            if d not in translated:
                translated.append(d)
    return {"nat_dependent": bool(notes), "nat_notes": notes[:20],
            "nat_notes_total": len(notes), "translated_scopes": translated}


def _translate_ports(x, n):
    """Ports of a DNAT'd piece after translation (exact offset when both
    sides are one same-sized range, otherwise the mapped ports)."""
    if n.ext_ports == rm.ANY and n.mapped_ports == rm.ANY:
        return x, True
    if n.mapped_ports == rm.ANY or isinstance(n.mapped_ports, rm.Unresolved):
        return x, False
    if (x != rm.ANY and not isinstance(x, rm.Unresolved) and n.ext_ports != rm.ANY
            and not isinstance(n.ext_ports, rm.Unresolved)
            and len(n.ext_ports) == 1 and len(n.mapped_ports) == 1):
        (flo, fhi), (tlo, thi) = n.ext_ports[0], n.mapped_ports[0]
        if fhi - flo == thi - tlo and all(flo <= a and b <= fhi for a, b in x):
            return rm.normalize_ranges([(a - flo + tlo, b - flo + tlo) for a, b in x]), True
    return n.mapped_ports, False


def _nat_pieces(ctx, eps, hop, pairs, phase):
    """Apply the translations of one hop's firewalls to the running scope
    pairs [(orig_piece, cur_piece)].  ``phase`` "pre": DNATs of post-NAT
    vendors (their policy already names the mapped destination, so the
    flow must be translated BEFORE intersecting); "post": DNATs of pre-NAT
    vendors and SNATs (applied after the policy).  A piece wholly inside
    the NAT's match is replaced; one that only overlaps is kept AND a
    translated copy added (over-approximation - never a false deny).
    Returns (pairs, translated_any, exact)."""
    out, changed, exact = list(pairs), False, True
    evs = hop["enforcement_points"]
    for ep, ev in zip(eps, evs):
        # B-13: first-match SNAT per firewall.  flags[i] for out[i]:
        #   0 open - later SNAT entries may still match it;
        #   1 done - an earlier entry (translation or `nat disable`
        #     exemption) matched it wholly: no later entry is consulted;
        #   2 partly exempted - an earlier exemption matched part of it, so a
        #     later translation keeps the untranslated piece too
        #     (over-approximation, never a false deny).
        flags = [0] * len(out)
        for n in ctx.nats_for(ep):
            if n.cross_family:
                # N-25: an address-family translation cannot be carried through the
                # (single-family) scope algebra; _xfam_downgrade makes a later "denied"
                # NAT-dependent ("unknown") instead.
                continue
            if n.kind == "dnat":
                mode = ctx.nat_policy_mode(ep, n)
                if (mode == "pre") != (phase == "post"):
                    continue
            elif n.kind == "snat":
                if phase != "post":
                    continue
                if not n.policy_ok(_ep_permit_policy_ids(ev)):
                    continue
            else:
                continue
            nxt, nflags = [], []

            def _emit(pair, flag):
                nxt.append(pair)
                nflags.append(flag)

            for (orig, cur), flag in zip(out, flags):
                src, dst, p, x = cur
                if n.kind == "snat":
                    if flag == 1:
                        _emit((orig, cur), 1)
                        continue
                    if src != rm.ANY and not rm.addr_overlaps(n.orig_src, src):
                        _emit((orig, cur), flag)
                        continue
                    if n.orig_dst != rm.ANY and dst != rm.ANY and not isinstance(dst, rm.Unresolved) \
                            and rm.addr_overlaps(n.orig_dst, dst) is False:
                        _emit((orig, cur), flag)   # central-snat dst-addr limit: not this flow
                        continue
                    if isinstance(p, rm.Unresolved) or (
                            not isinstance(n.protos, rm.Unresolved) and p != rm.ANY
                            and not n._proto_ok(p)):
                        _emit((orig, cur), flag)   # central-snat protocol limit: not this flow
                        continue
                    # C-04: central-snat orig-port limit.  A port-restricted
                    # entry only applies to flows whose ports it covers; one
                    # that covers only part of the piece's ports makes the
                    # match non-whole (partial, never a false deny).
                    port_limited = n.orig_ports != rm.ANY and not isinstance(n.orig_ports, rm.Unresolved)
                    if port_limited and not isinstance(x, rm.Unresolved) \
                            and rm.ports_overlap(x, n.orig_ports) is False:
                        _emit((orig, cur), flag)   # central-snat orig-port limit: not this flow
                        continue
                    port_whole = (not port_limited) or (
                        not isinstance(x, rm.Unresolved) and rm.ports_contain(n.orig_ports, x) is True)
                    pi = p if (n.protos == rm.ANY or isinstance(n.protos, rm.Unresolved)) \
                        else rm.protos_intersect(p, n.protos)
                    proto_whole = n.protos == rm.ANY or rm.protos_contain(n.protos, p) is True
                    whole = (src != rm.ANY or n.orig_src == rm.ANY) \
                        and rm.addr_contains(n.orig_src, src) is True and proto_whole and port_whole and (
                            n.orig_dst == rm.ANY or rm.addr_contains(n.orig_dst, dst) is True)
                    if n.exempt:
                        # `nat disable`: the matched flows keep their source and
                        # no later entry translates them.
                        _emit((orig, cur), 1 if whole else 2)
                        if not whole:
                            exact, changed = False, True
                        continue
                    if src == rm.ANY and n.orig_src != rm.ANY:
                        # N-25: an unrestricted source scope (the hop permits any
                        # source).  Keep it (the sources outside orig_src, and an
                        # over-approximation of the rest) AND add the orig_src hosts
                        # translated, reported under their ORIGINAL addresses.  A
                        # downstream hop that is itself unrestricted subsumes the
                        # translated piece again (see _subsume), so permissive paths
                        # stay "permitted".
                        o_src = rm.addr_intersect(orig[0], n.orig_src)
                        _emit((orig, cur), flag)
                        if o_src is not None:
                            _emit(((o_src, orig[1], pi, orig[3]), (n.mapped, dst, pi, x)), 1)
                            changed = True
                        continue
                    ndst = dst if n.orig_dst == rm.ANY else rm.addr_intersect(dst, n.orig_dst)
                    new = (n.mapped, ndst, pi, x)
                    if whole and flag == 0:
                        _emit(((orig[0],) + orig[1:], new), 1)
                    else:
                        # the translation covers only part of this piece (protocol /
                        # destination limit, part of the sources, or part of it was
                        # exempted by an earlier entry): keep the piece AND a
                        # translated copy limited to what the NAT matches
                        odst = orig[1] if n.orig_dst == rm.ANY else rm.addr_intersect(orig[1], n.orig_dst)
                        _emit((orig, cur), flag)
                        _emit(((orig[0], odst, pi, orig[3]), new), 1)
                        exact = False
                    changed = True
                else:
                    if dst == rm.ANY and n.ext is not None and not isinstance(p, rm.Unresolved) \
                            and n._proto_ok(p) and not isinstance(x, rm.Unresolved) \
                            and rm.ports_overlap(x, n.ext_ports) is not False:
                        # N-25: unrestricted destination scope: keep it, add the VIP's
                        # external address translated to the mapped one (original
                        # address reported); subsumed again by an unrestricted hop.
                        o_dst = rm.addr_intersect(orig[1], n.ext)
                        _emit((orig, cur), flag)
                        if o_dst is not None:
                            nx, _ok = _translate_ports(x, n)
                            _emit(((orig[0], o_dst) + orig[2:], (src, n.mapped, p, nx)), flag)
                            changed = True
                        continue
                    if dst == rm.ANY or not rm.addr_overlaps(n.ext, dst):
                        _emit((orig, cur), flag)
                        continue
                    if (not isinstance(p, rm.Unresolved) and not n._proto_ok(p)) or (
                            not isinstance(x, rm.Unresolved)
                            and rm.ports_overlap(x, n.ext_ports) is False):
                        _emit((orig, cur), flag)
                        continue
                    nx, ok = _translate_ports(x, n)
                    new = (src, n.mapped, p, nx)
                    if rm.addr_contains(n.ext, dst) and ok:
                        _emit((orig, new), flag)
                    else:
                        _emit((orig, cur), flag)
                        _emit((orig, new), flag)
                        exact = False
                    changed = True
            out, flags = nxt, nflags
    return out, changed, exact


def _piece_contains(a, b) -> bool:
    """Piece ``a`` covers every host and service of piece ``b``."""
    for ia, ib in ((a[0], b[0]), (a[1], b[1])):
        if rm.addr_contains(ia, ib) is not True:
            return False
    if rm.protos_contain(a[2], b[2]) is not True:
        return False
    if a[3] == rm.ANY:
        return True
    return b[3] != rm.ANY and rm.ports_contain(a[3], b[3]) is True


def _subsume(pieces: list) -> list:
    """Drop permitted pieces that another piece already covers."""
    out = []
    for i, a in enumerate(pieces):
        if any(j != i and _piece_contains(b, a) and (not _piece_contains(a, b) or j < i)
               for j, b in enumerate(pieces)):
            continue
        out.append(a)
    return out


def _combine_path_scoped_nat(ctx, path_boundaries, hops, verdicts) -> _Verdict:
    """AND of a path's hops (like _combine_verdicts) where the permitted
    pieces are translated by each hop's NAT before meeting the next hop
    (A-06).  Reported scopes keep the ORIGINAL (pre-translation) addresses.
    Falls back to _combine_verdicts when no translation touches the path."""
    plain = _combine_verdicts(verdicts)
    if plain.decision in ("unknown", "no_policy") or len(verdicts) < 2 and plain.decision != "denied":
        return plain
    decisions = [v.decision for v in verdicts]
    if any(d in ("unknown", "no_policy") for d in decisions) or len(verdicts) < len(path_boundaries):
        return plain
    key = ("nat_path", tuple(path_boundaries), tuple(id(h) for h in hops),
           tuple(getattr(path_boundaries, "excludes", None) or ()))
    if key in ctx._eval_cache:
        return ctx._eval_cache[key]
    if any(d == "denied" for d in decisions):
        _cache_put(ctx, key, plain)
        return plain
    pairs = [(_SVC_ANY, _SVC_ANY)]
    touched, exact = False, True
    excludes = getattr(path_boundaries, "excludes", None)
    for i, (boundary, hop, v) in enumerate(zip(path_boundaries, hops, verdicts)):
        eps = _hop_eps(ctx, boundary, excludes[i] if excludes and i < len(excludes) else None)
        pairs, ch, ex = _nat_pieces(ctx, eps, hop, pairs, "pre")
        touched, exact = touched or ch, exact and ex
        if v.decision != "permitted":
            nxt = []
            seen_pairs: set = set()   # C-10: O(1) dedupe of hashable piece pairs
            for orig, cur in pairs:
                for b in v.services:
                    r = _intersect_service(cur, b)
                    if r is None:
                        continue
                    o = _intersect_service(orig, (rm.ANY, rm.ANY, r[2], r[3]))
                    if o is None:
                        continue
                    if cur[0] == orig[0]:
                        o = (r[0],) + o[1:]
                    if cur[1] == orig[1]:
                        o = (o[0], r[1]) + o[2:]
                    if (o, r) not in seen_pairs:
                        seen_pairs.add((o, r))
                        nxt.append((o, r))
            pairs = nxt
        pairs, ch, ex = _nat_pieces(ctx, eps, hop, pairs, "post")
        touched, exact = touched or ch, exact and ex
        if not pairs:
            break
    ctx._nat_meta[key] = {"touched": touched, "exact": exact,
                          "translated": [cur for _o, cur in pairs]}
    if not touched:
        res = plain
    elif not pairs:
        res = _Verdict("denied", denied_services=plain.denied_services)
    else:
        svcs = _subsume(_dedupe(o for o, _ in pairs))
        if svcs == [_SVC_ANY] and exact:
            res = _Verdict("permitted", [_SVC_ANY], plain.denied_services)
        else:
            res = _Verdict("partial", svcs, plain.denied_services)
    _cache_put(ctx, key, res)
    return res


def _ep_permit_policy_ids(hop_ep: dict) -> set:
    """{(vdom, policy_id)} of the policies that permitted the flow at one
    enforcement point (N-24: policy identity includes the VDOM)."""
    ids = set()
    mr = hop_ep.get("matching_rule")
    if hop_ep.get("decision") == "permit" and mr:
        ids.add((mr.get("vdom"), str(mr.get("policy_id"))))
    if hop_ep.get("decision") == "partial":
        for sc in hop_ep.get("permitted_scopes") or []:
            ids.add((sc.get("vdom"), str(sc.get("policy_id"))))
    return ids


def _evaluate_hop_nat(ctx, boundary, from_level, to_level, q, start_snat, exclude=None):
    eps = _hop_eps(ctx, boundary, exclude) if exclude else ctx.boundary_map[boundary]
    events = []
    post = q
    dn_ep = None
    for ep in eps:
        for n in ctx.nats_for(ep):
            m = n.match_dnat(q.get("dst_ip"), q.get("port"), q["protos"])
            if m is None:
                continue
            new_ip, new_port = m
            post = dict(q, dst_ip=new_ip, port=new_port)
            mode = ctx.nat_policy_mode(ep, n)
            events.append(dict(n.ref(ep), type="dnat",
                               original={"dst_ip": q.get("dst_ip"), "dst_port": q.get("port")},
                               translated={"dst_ip": new_ip, "dst_port": new_port},
                               policy_evaluated_on="pre_nat" if mode == "pre" else "post_nat"))
            dn_ep = ep
            break
        if dn_ep is not None:
            break
    ep_queries = None
    if dn_ep is not None:
        ep_queries = {}
        for ep in eps:
            if ep is dn_ep:
                ep_queries[id(ep)] = q if ctx.nat_policy_mode(ep) == "pre" else post
            else:
                ep_queries[id(ep)] = post
    hop, v = _evaluate_hop(ctx, boundary, from_level, to_level, post if dn_ep else q, ep_queries,
                           exclude=exclude)
    out_q = post
    if v.decision in ("permitted", "partial"):
        done = False
        for ep, ev in zip(_hop_eps(ctx, boundary, exclude), hop["enforcement_points"]):
            # B-13: SNAT entries in configured order, first match wins; a
            # matching exemption (`nat disable`) means no translation.
            for n in ctx.nats_for(ep):
                if n.kind != "snat":
                    continue
                forced = start_snat is not None and n.row.id == start_snat.row.id
                if not forced:
                    if not n.policy_ok(_ep_permit_policy_ids(ev)):
                        continue
                    if n.exempt:
                        if n.snat_matches(out_q.get("src_ip"), out_q.get("dst_ip"),
                                          out_q.get("protos"), out_q.get("port")):
                            events.append(dict(n.ref(ep), type="snat_exempt",
                                               original={"src_ip": out_q.get("src_ip")},
                                               translated={"src_ip": out_q.get("src_ip")}))
                            done = True
                            break
                        continue
                    new_src = n.match_snat(out_q.get("src_ip"), out_q.get("dst_ip"),
                                           out_q.get("protos"), out_q.get("port"))
                else:
                    new_src = _map_ip(out_q.get("src_ip") or "", None, n.mapped) \
                        if out_q.get("src_ip") else _ip_str(*_first_ip(n.mapped)[:2])
                if not new_src:
                    continue
                events.append(dict(n.ref(ep), type="snat",
                                   original={"src_ip": out_q.get("src_ip")},
                                   translated={"src_ip": new_src}))
                out_q = dict(out_q, src_ip=new_src)
                if forced:
                    start_snat = None
                done = True
                break
            if done:
                break
    hop = dict(hop, nat=events)
    return hop, v, out_q, start_snat


def _nat_start_variants(ctx, path_boundaries, q) -> list:
    """Alternative starting points for a flow OBSERVED with already
    translated addresses (topology diff): a destination equal to a DNAT's
    mapped address on a firewall of this path is un-translated to the
    external address (so pre-NAT vendors and upstream hops see what they
    really saw); a source equal to an SNAT's translated address starts as
    an unknown original source and is re-translated at that firewall.
    Returns [(query, start_snat)]."""
    if not ctx.has_nat:
        return []
    eps = [ep for b in path_boundaries for ep in ctx.boundary_map.get(b, [])]
    out = []
    for ep in eps:
        for n in ctx.nats_for(ep):
            if n.kind == "dnat":
                if any(x.match_dnat(q.get("dst_ip"), q.get("port"), q["protos"])
                       for e2 in eps for x in ctx.nats_for(e2) if x.kind == "dnat"):
                    continue  # observed pre-NAT already: forward NAT handles it
                r = n.reverse_dnat(q.get("dst_ip"), q.get("port"), q["protos"])
                if r is not None:
                    out.append((dict(q, dst_ip=r[0], port=r[1]), None))
            elif n.kind == "snat" and not n.exempt and q.get("src_ip") \
                    and rm.ip_in_addr(q["src_ip"], n.mapped):
                out.append((dict(q, src_ip=None), n))
    return out


def _vdom_links(db: DBSession, fw_ids: set) -> dict:
    """{firewall_id: [(iface_a, iface_b)]} - inter-VDOM link interface pairs
    (FortiOS ``set type vdom-link`` / npu-vlink; names ``<link>0`` /
    ``<link>1``, else the two ends of one /30 or /31), lower-cased."""
    out: dict = defaultdict(list)
    if not fw_ids:
        return out
    rows = db.query(FirewallInterface).filter(
        FirewallInterface.firewall_id.in_(list(fw_ids)),
        FirewallInterface.iface_type.in_(["vdom-link", "npu-vlink", "vdom_link"])).all()
    by_fw: dict = defaultdict(list)
    for r in rows:
        by_fw[r.firewall_id].append(r)
    for fw_id, ifs in by_fw.items():
        used = set()
        names = {(i.name or "").strip().lower(): i for i in ifs}
        for n, i in names.items():
            if n in used or not n[-1:].isdigit():
                continue
            base, d = n[:-1], n[-1]
            peer = base + ("1" if d == "0" else "0" if d == "1" else "")
            if peer in names and peer not in used and peer != n:
                out[fw_id].append((n, peer))
                used |= {n, peer}
        rest = [i for i in ifs if (i.name or "").strip().lower() not in used]
        for k, a in enumerate(rest):
            for b in rest[k + 1:]:
                na, nb = (a.name or "").strip().lower(), (b.name or "").strip().lower()
                if na in used or nb in used or not a.network_cidr or a.network_cidr != b.network_cidr:
                    continue
                out[fw_id].append((na, nb))
                used |= {na, nb}
    return out


def _link_levels(vlinks: dict, vdom_of: dict, vdom_levels: dict) -> dict:
    """{fw_id: {link iface name: levels}} - each end of an inter-VDOM link
    carries the labelled levels of the VDOM(s) reachable through it."""
    out: dict = {}
    for fw_id, pairs in vlinks.items():
        per = vdom_levels.get(fw_id) or {}
        for a, b in pairs:
            for name, start in ((a, vdom_of.get((fw_id, b))), (b, vdom_of.get((fw_id, a)))):
                own = vdom_of.get((fw_id, name))
                reach, todo = set(), [start] if start else []
                while todo:
                    vd = todo.pop()
                    if vd in reach:
                        continue
                    reach.add(vd)
                    for x, y in pairs:
                        for p, q in ((x, y), (y, x)):
                            if vdom_of.get((fw_id, p)) == vd:
                                nxt = vdom_of.get((fw_id, q))
                                if nxt and nxt != own:
                                    todo.append(nxt)
                lv = set()
                for vd in reach:
                    lv |= per.get(vd, set())
                if lv:
                    out.setdefault(fw_id, {})[name] = lv
    return out


def vdom_link_levels(db: DBSession) -> dict:
    """Public form of _link_levels for other modules: {fw_id: {link iface
    (lower): levels of the VDOM(s) on the other side}}."""
    fw_ids = {i for (i,) in db.query(Firewall.id)}
    vlinks = _vdom_links(db, fw_ids)
    if not vlinks:
        return {}
    vdom_of = {(i.firewall_id, (i.name or "").strip().lower()): i.vdom
               for i in db.query(FirewallInterface.firewall_id, FirewallInterface.name, FirewallInterface.vdom)}
    link_names = {(fw_id, n) for fw_id, pairs in vlinks.items() for a, b in pairs for n in (a, b)}
    vdom_levels: dict = {}
    for i in db.query(FirewallInterface).filter(FirewallInterface.purdue_level.isnot(None)):
        if (i.firewall_id, (i.name or "").strip().lower()) in link_names or i.vdom is None:
            continue
        vdom_levels.setdefault(i.firewall_id, {}).setdefault(i.vdom, set()).add(i.purdue_level)
    return _link_levels(vlinks, vdom_of, vdom_levels)


def _load_boundary_devices(db: DBSession) -> dict:
    """{(lo, hi): [enforcement point, ...]} — kept for callers/tests."""
    return _Context(db).boundary_map


class _Path(list):
    """A path: the ordered boundaries it crosses (a plain list for callers),
    plus ``entries`` (the level each boundary is entered from) and ``flat``
    (inferred unfirewalled hops it relies on, A-25)."""

    def __init__(self, boundaries, entries=None, flat=None, excludes=None):
        super().__init__(boundaries)
        self.entries = entries
        self.flat = flat or []
        # MP-02: per hop, the physical boxes already crossed earlier on this
        # path (their enforcement points are left out of that hop)
        self.excludes = excludes or [frozenset()] * len(boundaries)
        self.flat_note = None      # MP-03: why the verdict was downgraded, if it was


def _infer_flat_edges(boundary_map: dict, ifaces, host_levels) -> list[dict]:
    """A-25: unfirewalled adjacency between Purdue levels.

    Rule: levels are first grouped into components connected by firewall
    boundaries.  Components are then joined (Kruskal-style, a flat edge is
    only ever added between two components with NO firewall path between
    them, so a flat edge can never short-circuit a modelled firewall):

      1. "subnet" evidence first - hosts of level X inside a firewall
         interface subnet whose operator-assigned level is Z (they share a
         segment) => X ~ Z;
      2. otherwise the closest pair of levels by Purdue distance
         ("nearest"; ties broken toward the lower levels).

    An edge is ``ambiguous`` when another candidate of the same priority
    joins the same two components through different levels.  Without any
    firewall boundary no edge is inferred, and (MP-03) only levels that
    have hosts, a boundary or a labelled interface take part."""
    if not boundary_map:
        return []
    # MP-03: only levels with evidence of existing at this site - hosts,
    # a firewall boundary or a labelled interface - take part; no edge is
    # invented into an empty level.
    levels = {lv for _ip, lv in host_levels}
    for lo, hi in boundary_map:
        levels |= {lo, hi}
    for iface in ifaces or []:
        if iface.purdue_level is not None:
            levels.add(iface.purdue_level)
    parent = {lv: lv for lv in levels}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for lo, hi in boundary_map:
        if lo != hi:
            parent[find(lo)] = find(hi)

    evidence = set()
    nets = []
    for iface in ifaces or []:
        if iface.purdue_level is None or not iface.network_cidr:
            continue
        try:
            nets.append((ipaddress.ip_network(iface.network_cidr, strict=False),
                         iface.purdue_level))
        except ValueError:
            continue
    if nets:
        for ip, lv in host_levels:
            for net, z in nets:
                if lv != z and ip.version == net.version and ip in net:
                    evidence.add((min(lv, z), max(lv, z)))
    cands = []
    for a, b in itertools.combinations(sorted(levels), 2):
        basis = "subnet" if (a, b) in evidence else "nearest"
        cands.append(((0 if basis == "subnet" else 1, b - a), a, b, basis))
    cands.sort(key=lambda c: (c[0], c[1], c[2]))
    out = []
    for prio, a, b, basis in cands:
        ra, rb = find(a), find(b)
        if ra == rb:
            continue
        ambiguous = any(
            p2 == prio and (a2, b2) != (a, b) and {find(a2), find(b2)} == {ra, rb}
            for p2, a2, b2, _ in cands)
        parent[ra] = rb
        out.append({"a": a, "b": b, "basis": basis, "ambiguous": ambiguous})
    return out


def _path_between_levels(
    boundary_map: dict,
    src_level: int,
    dst_level: int,
    max_hops: int = len(VALID_LEVELS) - 1,
    flat_edges: Optional[list] = None,
) -> list[list[tuple[int, int]]]:
    """
    Find all simple paths (as ordered boundary sequences) from src_level to
    dst_level.  Purdue levels have at most 7 nodes (0-5 and 3.5) so BFS is
    always fast.

    A path never crosses the same physical firewall twice: a multi-leg
    firewall appears on every pair of its legs, so 4→1 crosses it once
    directly rather than 4→3→1 through itself.  MP-02: when a later hop
    holds a box already crossed, that box is left out of the hop (the
    path's ``excludes``) rather than the whole path being dropped; only a
    hop with no box left is a dead end.

    ``flat_edges`` (A-25, _Context.flat_edges) adds inferred unfirewalled
    adjacency: such a step crosses no boundary, but a path must still cross
    at least one firewall (a firewall-free path is "no enforcement point").
    Paths are _Path lists carrying ``entries`` / ``flat``.
    """
    if src_level == dst_level:
        return [[]]

    adjacency: dict = defaultdict(set)
    for lo, hi in boundary_map:
        if lo == hi:
            continue
        adjacency[lo].add((hi, None))
        adjacency[hi].add((lo, None))
    for fe in flat_edges or []:
        adjacency[fe["a"]].add((fe["b"], id(fe)))
        adjacency[fe["b"]].add((fe["a"], id(fe)))
    flat_by_id = {id(fe): fe for fe in flat_edges or []}

    paths = []
    max_steps = max_hops + len(flat_edges or [])
    # (level, boundaries, entries, flat edges used, visited)
    queue = [(src_level, [], [], [], {src_level})]
    while queue:
        current, path, entries, flats, visited = queue.pop(0)
        if current == dst_level:
            if path:
                paths.append(_Path(path, entries, [
                    {**flat_by_id[f]} for f in flats]))
            continue
        if len(path) + len(flats) >= max_steps:
            continue
        for neighbor, flat in sorted(adjacency.get(current, set()),
                                     key=lambda t: (t[0], t[1] is not None)):
            if neighbor in visited:
                continue
            if flat is not None:
                queue.append((neighbor, path, entries, flats + [flat], visited | {neighbor}))
                continue
            boundary = _normalize_boundary(current, neighbor)
            if boundary in boundary_map:
                queue.append((neighbor, path + [boundary], entries + [current], flats,
                              visited | {neighbor}))

    def _with_excludes(path):
        """The path with per-hop exclusions of boxes crossed earlier, or
        None when some hop has no box left."""
        seen: set = set()
        excludes = []
        for b in path:
            boxes = {getattr(ep, "physical", ("obj", id(ep))) for ep in boundary_map[b]}
            again = boxes & seen
            if again == boxes:
                return None
            excludes.append(frozenset(again))
            seen |= boxes
        path.excludes = excludes
        return path

    return [p for p in map(_with_excludes, paths) if p is not None]


def _unplaced_suffix(ctx) -> str:
    """MP-03: "; FW-X, FW-Y carry rules but are not placed in the model"."""
    names = [u["firewall"] or "?" for u in (getattr(ctx, "unplaced_firewalls", None) or [])]
    if not names:
        return ""
    return ("; " + ", ".join(names[:5]) + (f" (+{len(names) - 5})" if len(names) > 5 else "")
            + (" carries" if len(names) == 1 else " carry")
            + " rules but " + ("is" if len(names) == 1 else "are") + " not placed in the model")


def _path_string(path, src_level, hops, dst_level, src_ip=None, dst_ip=None) -> str:
    """The path as text.  Firewall hops are ``[lo↔hi]``; an inferred
    unfirewalled hop (A-25) is printed as ``~ L3 (inferred)`` so it is never
    hidden (MP-03); boundaries after an early deny (not evaluated) are
    printed as ``[lo↔hi]`` too."""
    def lv(x, ip=None):
        if ip:
            return f"Level {x:g} ({ip})"
        return f"{x:g}" if src_ip is None and dst_ip is None else f"Level {x:g}"
    entries = getattr(path, "entries", None) or []
    boundaries = list(path) if path is not None else [(h.get("zone_lo"), h.get("zone_hi")) for h in hops]
    bits = [lv(src_level, src_ip)]
    current = src_level
    for i, b in enumerate(boundaries):
        entry = entries[i] if i < len(entries) else current
        if entry != current:
            bits.append(f"~ {lv(entry)} (inferred, no firewall)")
            current = entry
        if i < len(hops):
            h = hops[i]
            bits.append(f"[{h['boundary']}]")
            current = h["to_level"] if h.get("to_level") is not None else current
        else:
            lo, hi = b
            bits.append(f"[{lo:g}↔{hi:g}]")
            current = hi if current == lo else lo
    if current != dst_level and getattr(path, "flat", None):
        bits.append(f"~ {lv(dst_level, dst_ip)} (inferred, no firewall)")
    else:
        bits.append(lv(dst_level, dst_ip))
    return " → ".join(bits)


def _flat_downgrade(path, verdict: "_Verdict", ctx=None) -> "_Verdict":
    """A-25: a path that relies on an inferred flat hop without subnet
    evidence (or an ambiguous one) is never reported "denied" - whether the
    flow really meets that firewall is a guess, so the answer is "unknown".
    MP-03: when the site has firewalls that carry rules but built no
    enforcement point, ANY verdict over an inferred hop is "unknown" - the
    unplaced firewall may sit exactly on that hop, and a flow it denies must
    not come back permitted.  The reason is left on ``path.flat_note``."""
    flats = getattr(path, "flat", None) or []
    try:
        path.flat_note = None
    except AttributeError:
        pass
    if not flats or verdict.decision in ("unknown", "no_policy"):
        return verdict
    guessed = [f for f in flats if f["ambiguous"] or f["basis"] != "subnet"]
    unplaced = [u["firewall"] or "?" for u in (getattr(ctx, "unplaced_firewalls", None) or [])]
    if unplaced:
        note = ("relies on an inferred unfirewalled hop " + ", ".join(
            f"L{f['a']:g}~L{f['b']:g}" for f in flats) + " while " + ", ".join(unplaced[:5])
            + (" carries" if len(unplaced) == 1 else " carry")
            + " rules but " + ("is" if len(unplaced) == 1 else "are") + " not placed in the model")
    elif verdict.decision == "denied" and guessed:
        note = ("relies on an inferred unfirewalled hop " + ", ".join(
            f"L{f['a']:g}~L{f['b']:g}" for f in guessed)
            + " with no segment evidence, so the deny may not apply to this flow")
    else:
        return verdict
    try:
        path.flat_note = note
    except AttributeError:
        pass
    return _Verdict("unknown")


# ---------------------------------------------------------------------------
# Public API: level-to-level matrix
# ---------------------------------------------------------------------------

def compute_reachability(
    db: DBSession,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    src_level: Optional[int] = None,
    dst_level: Optional[int] = None,
    ip_version: Optional[int] = None,
) -> dict:
    """
    Compute the reachability matrix for all ordered pairs of Purdue levels.

    When src_ip / dst_ip are provided, the rule evaluation is for that
    specific host pair rather than generic "any to any".  src_level /
    dst_level filter the returned cells (post-build).  Without IPs the
    matrix is for ``ip_version`` traffic (4 by default, 6 for IPv6; F-07):
    rules of the other family neither permit nor deny it.

    Each path additionally carries ``permitted_scopes`` - the host scopes x
    services that survive EVERY hop (N-05) - and its hops carry ``nat``
    (translations applied; only for host queries, F-05).

    Returns:
    {
        "matrix": {
            "3→4": {
                "src_level": 3, "dst_level": 4,
                "overall": "permitted" | "partial" | "denied" | "unknown" | "no_policy",
                "permitted_services": [...],   # ["any"] / ["tcp/443", ...] / []
                "denied_services": [...],      # specific denies before a broad permit
                "paths": [ {path, hops, path_decision, permitted_services,
                            denied_services}, ...],
            },
        },
        "enforcement_points": [{boundary, zone_lo, zone_hi, devices, rule_count}],
        "levels_with_hosts": [...],
        "traffic_filter": {...},
    }
    """
    _filter_src_level = src_level
    _filter_dst_level = dst_level

    ctx = _Context(db)
    boundary_map = ctx.boundary_map
    q = _make_query(src_ip, dst_ip, dst_port, protocol, ip_version)

    host_levels = [
        row[0]
        for row in db.query(Host.purdue_level)
        .filter(Host.purdue_level.isnot(None))
        .distinct()
        .all()
    ]

    enforcement_points = []
    for (lo, hi), eps in sorted(boundary_map.items()):
        alts = hop_alternatives(eps)
        series_sets = []
        for a in alts:
            names = list(dict.fromkeys(d.name or "?" for i in a for d in [eps[i]]))
            key = getattr(eps[a[0]], "series_key", None) if a else None
            series_sets.append({"devices": names,
                                "basis": ctx.series_basis.get(key, []) if len(names) > 1 else []})
        enforcement_points.append({
            "boundary": f"{lo}↔{hi}",
            "zone_lo": lo,
            "zone_hi": hi,
            "devices": [_fw_device_dict(d) for d in eps],
            "rule_count": sum(len(ctx.rules_for(d)) for d in eps),
            # MP-01: how the boxes relate - alternatives (a flow crosses one
            # of them) vs declared series sets
            "arrangement": _arrangement(eps, alts),
            "alternatives": series_sets,
            # MP-09: routed interfaces of these boxes that carry no level -
            # rules on them are not judged on any crossing
            "unlabelled_interfaces": sorted({n for d in eps if d.firewall_id is not None
                                             for n in ctx._iface_unlabelled_names.get(d.firewall_id, ())}),
        })

    matrix = {}
    all_levels = sorted(set(_PURDUE_LEVELS) | set(host_levels))
    # MP-08: downhill (IT -> OT) cells first, deepest crossing first (5->0,
    # 5->1, ..., 4->0, ...), then the upward cells.  The access-path
    # enumeration walks the matrix in this order under a row budget, so a
    # truncated list loses the least important rows last.
    no_fw_data = _no_firewall_data(db)       # FO-08
    cell_order = sorted(itertools.permutations(all_levels, 2),
                        key=lambda p: (0 if p[0] > p[1] else 1, -p[0], p[1]))
    for s_lvl, d_lvl in cell_order:
        if _filter_src_level is not None and s_lvl != _filter_src_level:
            continue
        if _filter_dst_level is not None and d_lvl != _filter_dst_level:
            continue
        paths = _path_between_levels(boundary_map, s_lvl, d_lvl, flat_edges=ctx.flat_edges)
        if not paths:
            matrix[f"{s_lvl}→{d_lvl}"] = {
                "src_level": s_lvl,
                "dst_level": d_lvl,
                "overall": "no_policy",
                # FO-08: no enforcement point at all = unfiltered as far as
                # the app knows ("no policy" never means blocked)
                "unfiltered": no_fw_data,
                "reason": ("No firewall data loaded: no enforcement point - unfiltered as far as the "
                           "app knows" if no_fw_data else
                           "No firewall enforcement point exists on any path between these levels")
                + _unplaced_suffix(ctx),
                "permitted_services": [],
                "denied_services": [],
                "paths": [],
                "nat_dependent": False,
                "nat_notes": [],
            }
            continue

        path_results, verdicts, nat_notes = [], [], []
        for path_boundaries in paths:
            hops, pv = _evaluate_path(ctx, path_boundaries, s_lvl, q)
            verdicts.append(pv)
            ann = _path_nat_annotation(ctx, path_boundaries, hops, q) if ctx.has_nat or ctx._nat_unusable else {
                "nat_dependent": False, "nat_notes": [], "nat_notes_total": 0, "translated_scopes": []}
            nat_notes += [n for n in ann["nat_notes"] if n not in nat_notes]
            path_results.append({
                **ann,
                "path": _path_string(path_boundaries, s_lvl, hops, d_lvl),
                "hops": hops,
                "path_decision": pv.decision,
                "inferred_hop_note": getattr(path_boundaries, "flat_note", None),
                "permitted_services": pv.service_strings(),
                "permitted_scopes": pv.scopes(),
                "denied_services": pv.denied_services,
                "nat": [e for h in hops for e in h.get("nat", [])],
                "inferred_adjacency": list(getattr(path_boundaries, "flat", []) or []),
            })

        ov = _union_verdicts(verdicts)
        matrix[f"{s_lvl}→{d_lvl}"] = {
            "src_level": s_lvl,
            "dst_level": d_lvl,
            "overall": ov.decision,
            "permitted_services": ov.service_strings(),
            "denied_services": ov.denied_services,
            # MP-25: a partial that is the OR of a partial and an unknown
            # path - the service list is a lower bound
            "uncertain": bool(getattr(ov, "uncertain", False)),
            "paths": path_results,
            # N-25: the verdict depends on a NAT that could not be applied
            # exactly (see each path's nat_notes)
            "nat_dependent": any(pr["nat_dependent"] for pr in path_results),
            "nat_notes": nat_notes[:20],
        }

    return {
        "matrix": matrix,
        "enforcement_points": enforcement_points,
        # FO-08
        "no_enforcement_note": (None if not no_fw_data else
                                "No firewall data loaded: there is no enforcement point, so traffic "
                                "between levels is unfiltered as far as the app knows. A \"no policy\" "
                                "cell means no firewall, not blocked."),
        "unplaced_firewalls": list(ctx.unplaced_firewalls),
        "paired_group_warnings": list(ctx.paired_group_warnings),
        "label_conflicts": list(ctx.label_conflicts),
        "levels_with_hosts": sorted(host_levels),
        "traffic_filter": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "src_level": _filter_src_level,
            "dst_level": _filter_dst_level,
            "ip_version": q["family"],
        },
    }


# ---------------------------------------------------------------------------
# Public API: host-specific path analysis
# ---------------------------------------------------------------------------

def compute_path(
    db: DBSession,
    src_ip: str,
    dst_ip: Optional[str] = None,
    dst_level: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> dict:
    """Public entry point; see _compute_path_inner. Guarantees that a DNAT
    resolution of dst_ip is reported in ``nat_destination`` on EVERY return
    path - including the early no_policy / intra_level / unknown results,
    which previously dropped it."""
    holder: dict = {}
    res = _compute_path_inner(db, src_ip, dst_ip, dst_level, dst_port, protocol, _nat_out=holder)
    if res.get("nat_destination") is None and holder.get("nat_destination") is not None:
        res["nat_destination"] = holder["nat_destination"]
    return res


def _compute_path_inner(
    db: DBSession,
    src_ip: str,
    dst_ip: Optional[str] = None,
    dst_level: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    _nat_out: Optional[dict] = None,
) -> dict:
    """
    Trace the specific policy path for traffic from ``src_ip`` to
    ``dst_ip`` (or all hosts in ``dst_level``).

    Returns:
    {
        "src_ip", "src_host", "src_level", "dst_ip", "dst_host", "dst_level",
        "overall": "permitted" | "partial" | "denied" | "unknown" | "no_policy"
                   | "intra_level",
        "permitted_services": [...], "denied_services": [...],
        "hops": [...], "path": str, "error": str | None,
        "permitted_scopes": [...],      # host scopes x services across all hops
        "nat": [...],                   # translations applied along the path
        "nat_destination": {...} | None # dst_ip was a DNAT external address
    }

    IPv4 and IPv6 addresses are both accepted (F-07).  F-05: when dst_ip is
    a DNAT external address (VIP / port forward) of a firewall and is not a
    known host with a level, the destination level is that of the mapped
    host; translations are applied hop by hop (see _evaluate_path).
    """
    src_ip = _canon_ip(src_ip)
    dst_ip = _canon_ip(dst_ip)
    src_host = _find_host(db, src_ip)
    src_level = src_host.purdue_level if src_host else None

    dst_host = None
    resolved_dst_level = dst_level
    ctx = None
    nat_destination = None
    if dst_ip:
        dst_host = _find_host(db, dst_ip)
        ctx = _Context(db)
        pq = _make_query(src_ip, dst_ip, dst_port, protocol)
        # A VIP external address is the firewall's, not a host: the level is
        # that of the real (mapped) destination, through every VIP in the
        # chain (P-03 / P-04), even when a host row for it carries a level.
        tgt = ctx.dnat_target(dst_ip, pq["port"], pq["protos"]) if ctx.has_nat else None
        if tgt is not None:
            n, mapped_ip, mapped_port = tgt
            mlevel = ctx.host_level(mapped_ip)
            if mlevel is None:
                mlevel = ctx.subnet_level(mapped_ip)
            chain = getattr(ctx, "last_dnat_chain", [n])
            nat_destination = {"nat_rule_id": n.row.id, "name": n.row.name,
                               "ext_ip": dst_ip, "mapped_ip": mapped_ip,
                               "mapped_port": mapped_port, "mapped_level": mlevel,
                               "chain": [{"nat_rule_id": c.row.id, "name": c.row.name,
                                          "firewall_id": c.row.firewall_id,
                                          "ext_ip": c.row.ext_ip, "mapped_ip": c.row.mapped_ip}
                                         for c in chain]}
            if _nat_out is not None:
                _nat_out["nat_destination"] = nat_destination
            if mlevel is not None and dst_level is None:
                resolved_dst_level = mlevel
                if dst_host is not None and dst_host.purdue_level is not None:
                    dst_host = None     # the VIP's own (inferred) level is not used
        if dst_host:
            if dst_host.purdue_level is not None:
                resolved_dst_level = dst_host.purdue_level
        elif resolved_dst_level is None:
            return _path_result(
                src_ip, src_host, src_level, dst_ip, dst_host, None, "unknown",
                error=(f"dst_ip {dst_ip!r} not found in host table and "
                       f"dst_level not provided — cannot determine destination Purdue level"),
            )

    if src_level is None:
        return _path_result(
            src_ip, src_host, None, dst_ip, dst_host, resolved_dst_level, "unknown",
            error=(f"src_ip {src_ip!r} has no Purdue level assigned — "
                   f"cannot determine which boundaries to traverse"),
        )

    if resolved_dst_level is None:
        return _path_result(src_ip, src_host, src_level, dst_ip, dst_host, None, "unknown",
                            error="Cannot determine destination Purdue level")

    if src_level == resolved_dst_level:
        # MP-16: two legs of ONE firewall at the same level (two L3 subnets
        # on port2 / port3) are still a policy crossing - evaluate it.
        ctx = ctx or _Context(db)
        same = _same_level_path(ctx, src_ip, dst_ip, src_level,
                                _make_query(src_ip, dst_ip, dst_port, protocol)) if dst_ip else None
        if same is not None:
            res = _path_result(src_ip, src_host, src_level, dst_ip, dst_host, resolved_dst_level,
                               same["overall"], hops=same["hops"], path=same["path"])
            res["permitted_services"] = same["permitted_services"]
            res["denied_services"] = same["denied_services"]
            res["same_level_crossing"] = same["crossing"]
            res["unplaced_firewalls"] = list(ctx.unplaced_firewalls)
            res["paired_group_warnings"] = list(ctx.paired_group_warnings)
            res["label_conflicts"] = list(ctx.label_conflicts)
            return res
        return _path_result(
            src_ip, src_host, src_level, dst_ip, dst_host, resolved_dst_level, "intra_level",
            path=(f"Level {src_level} → Level {resolved_dst_level} "
                  f"(same level, no firewall leg between the two hosts - not evaluated)"),
        )

    ctx = ctx or _Context(db)
    paths = _path_between_levels(ctx.boundary_map, src_level, resolved_dst_level,
                                  flat_edges=ctx.flat_edges)
    if not paths:
        # FO-08: say what "no policy" means here - no firewall at all is
        # unfiltered; two hosts on one capture segment talk MAC to MAC
        same_seg = None
        if src_host is not None and dst_host is not None:
            from app.parsers.segments import capture_networks, same_capture_segment
            if same_capture_segment(db)(src_host, dst_host):
                same_seg = next((dom for n, _c, _g, dom in capture_networks(db)
                                 if src_host.ip and _ip_in(src_host.ip, n)), None)
        no_ep = not ctx.boundary_map and _no_firewall_data(db)
        if same_seg:
            note = (f"same L2 segment {same_seg} (from the capture): no enforcement point between "
                    "the two hosts - unfiltered")
        elif no_ep:
            note = "no firewall data loaded: no enforcement point - unfiltered as far as the app knows"
        else:
            note = "no enforcement points" + _unplaced_suffix(ctx)
        res = _path_result(
            src_ip, src_host, src_level, dst_ip, dst_host, resolved_dst_level, "no_policy",
            path=f"Level {src_level} → Level {resolved_dst_level} ({note})",
        )
        res["unfiltered"] = bool(same_seg or no_ep)
        res["same_segment"] = same_seg
        if same_seg or no_ep:
            res["path_note"] = note[0].upper() + note[1:] + "."
        res["unplaced_firewalls"] = list(ctx.unplaced_firewalls)
        res["paired_group_warnings"] = list(ctx.paired_group_warnings)
        res["label_conflicts"] = list(ctx.label_conflicts)
        return res

    q = _make_query(src_ip, dst_ip, dst_port, protocol)
    # A-8: evaluate ALL paths and return the most permissive result.  MP-17:
    # among equally permissive paths the one whose firewalls hold the
    # queried addresses (interface networks) wins, every path is reported
    # in ``paths_evaluated`` / ``alternatives``, and the result says it is
    # the most permissive of N - an upper bound, not a determination of
    # which path the packets take.
    rank = {"permitted": 4, "partial": 3, "unknown": 2, "no_policy": 1, "denied": 0}
    evaluated = []
    ips = [x for x in (q.get("src_ip"), q.get("dst_ip")) if x]
    for candidate in paths:
        hops, v = _evaluate_path(ctx, candidate, src_level, q)
        placed = 0
        for h in hops:
            for e in h.get("enforcement_points") or []:
                fid = (e.get("firewall_device") or {}).get("firewall_id")
                nets = ctx._iface_subnets.get(fid) if fid is not None else None
                if nets and not e.get("not_on_path"):
                    for ip in ips:
                        try:
                            a = ipaddress.ip_address(ip)
                        except ValueError:
                            continue
                        if any(n.version == a.version and a in n for n, _lv in nets):
                            placed += 1
        evaluated.append((candidate, hops, v, placed))
    evaluated.sort(key=lambda t: (-rank.get(t[2].decision, 0), -t[3]))
    best_path, best_hops, best_v, best_placed = evaluated[0]

    path_str = _path_string(best_path, src_level, best_hops, resolved_dst_level, src_ip, dst_ip)
    res = _path_result(src_ip, src_host, src_level, dst_ip, dst_host, resolved_dst_level,
                       best_v.decision, hops=best_hops, path=path_str)
    res["paths_evaluated"] = len(evaluated)
    res["alternatives"] = [
        {"path": _path_string(c, src_level, h, resolved_dst_level), "decision": v.decision,
         "permitted_services": v.service_strings(),
         "firewalls": list(dict.fromkeys((e.get("firewall_device") or {}).get("name") or "?"
                                         for hp in h for e in hp.get("enforcement_points") or []
                                         if not e.get("not_on_path"))),
         "placement_evidence": pl, "chosen": c is best_path}
        for c, h, v, pl in evaluated]
    if len(evaluated) > 1:
        same = sum(1 for _c, _h, v, _p in evaluated if v.decision == best_v.decision)
        res["path_note"] = (f"most permissive of {len(evaluated)} level paths"
                            + (f" ({same} with this verdict; the one whose firewalls hold the "
                               "queried addresses is shown)" if same > 1 and best_placed else
                               f" ({same} with this verdict)" if same > 1 else "")
                            + "; an upper bound - which path the packets take depends on routing")
    else:
        res["path_note"] = None
    res["permitted_services"] = best_v.service_strings()
    res["permitted_scopes"] = best_v.scopes()
    res["denied_services"] = best_v.denied_services
    res["nat"] = [e for h in best_hops for e in h.get("nat", [])]
    res.update(_path_nat_annotation(ctx, best_path, best_hops, q)
               if ctx.has_nat or ctx._nat_unusable else
               {"nat_dependent": False, "nat_notes": [], "nat_notes_total": 0,
                "translated_scopes": []})
    res["nat_destination"] = nat_destination
    res["inferred_adjacency"] = list(getattr(best_path, "flat", []) or [])
    res["inferred_hop_note"] = getattr(best_path, "flat_note", None)
    res["unplaced_firewalls"] = list(ctx.unplaced_firewalls)
    res["paired_group_warnings"] = list(ctx.paired_group_warnings)
    res["label_conflicts"] = list(ctx.label_conflicts)
    return res


def _same_level_path(ctx: _Context, src_ip: str, dst_ip: str, level, q: dict) -> Optional[dict]:
    """MP-16: when ``src_ip`` and ``dst_ip`` sit on two DIFFERENT labelled
    interface networks of one firewall at the same level, evaluate that
    firewall's policies for the crossing between those two legs (rules
    whose src / dst zone names the ingress / egress interface, or any).
    None when no firewall separates the two hosts that way."""
    try:
        a, b = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    except ValueError:
        return None
    ifaces = ctx.db.query(FirewallInterface).filter(
        FirewallInterface.purdue_level == level, FirewallInterface.network_cidr.isnot(None)).all()
    by_fw: dict = defaultdict(list)
    for i in ifaces:
        try:
            net = ipaddress.ip_network(i.network_cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or (net.version == 4 and net.prefixlen == 32):
            continue
        by_fw[i.firewall_id].append((net, i))
    best = None
    for fw_id, nets in by_fw.items():
        src_if = max((n_i for n_i in nets if n_i[0].version == a.version and a in n_i[0]),
                     key=lambda t: t[0].prefixlen, default=None)
        dst_if = max((n_i for n_i in nets if n_i[0].version == b.version and b in n_i[0]),
                     key=lambda t: t[0].prefixlen, default=None)
        if src_if is None or dst_if is None or src_if[1].id == dst_if[1].id:
            continue
        best = (fw_id, src_if[1], dst_if[1])
        break
    if best is None:
        return None
    fw_id, src_if, dst_if = best
    ep = next((e for eps in ctx.boundary_map.values() for e in eps if e.firewall_id == fw_id), None)
    rules = list(ctx.rules_for(ep)) if ep is not None else sorted(
        ctx.db.query(FirewallRule).filter(FirewallRule.firewall_id == fw_id,
                                          FirewallRule.enabled.is_(True)).all(), key=_rule_sort_key)
    if ep is None:
        fw = ctx.db.get(Firewall, fw_id)
        ep = _EnforcementPoint(zone_from=level, zone_to=level, source="firewall_interfaces",
                               physical=("fw", fw_id), multi_leg=True, interface_levels=[level],
                               id=None, name=fw.name if fw else None, vendor=fw.vendor if fw else None,
                               hostname=fw.device_name if fw else None, mgmt_ip=None,
                               firewall_id=fw_id, firewall_device_id=None)

    def names(iface) -> set:
        return {x.strip().lower() for x in (iface.name, iface.alias, iface.zone_label) if x and x.strip()}
    ingress, egress = names(src_if), names(dst_if)
    zmap = ctx._zone_defs.get((fw_id, None)) or {}

    def side_ok(zone_value, want: set) -> bool:
        toks = fz.zone_tokens(zone_value)
        if toks is None:
            return True                       # any
        for t in toks:
            if t in want:
                return True
            z = fz.zone_lookup(zmap, t)
            if z is not None:
                members, resolved = z
                if not resolved or set(members) & want:
                    return True
        return False
    leg_rules = [r for r in rules if side_ok(r.src_zone, ingress) and side_ok(r.dst_zone, egress)]
    base, v = _evaluate_device_core(ctx, ep, q, level, level, leg_rules)
    base.pop("_xfam", None)
    hop = {
        "boundary": f"{level:g}↔{level:g}",
        "zone_lo": level, "zone_hi": level, "from_level": level, "to_level": level,
        "enforcement_points": [base],
        "alternatives": [[0]], "arrangement": "single", "placement": None, "already_crossed": [],
        "boundary_decision": v.decision,
        "permitted_services": v.service_strings(),
        "denied_services": v.denied_services,
        "same_level": {"firewall": ep.name, "ingress": src_if.name, "egress": dst_if.name},
    }
    crossing = {"firewall": ep.name, "firewall_id": fw_id, "level": level,
                "ingress": src_if.name, "egress": dst_if.name, "rules_considered": len(leg_rules)}
    return {"overall": v.decision, "hops": [hop],
            "permitted_services": v.service_strings(), "denied_services": v.denied_services,
            "crossing": crossing,
            "path": (f"Level {level:g} ({src_ip}) → [{level:g}↔{level:g} {ep.name} "
                     f"{src_if.name}→{dst_if.name}] → Level {level:g} ({dst_ip})")}


def _canon_ip(ip: Optional[str]) -> Optional[str]:
    """Canonical text for an IPv4/IPv6 address (IPv6 compressed form);
    unparseable input is returned stripped and unchanged."""
    if ip is None:
        return None
    s = str(ip).strip()
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def _find_host(db: DBSession, ip: Optional[str]) -> Optional[Host]:
    if not ip:
        return None
    h = db.query(Host).filter(Host.ip == ip).first()
    if h is None and ":" in ip:
        # IPv6 stored in a non-canonical (e.g. exploded / upper-case) form
        try:
            want = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for cand in db.query(Host).filter(Host.ip.like("%:%")):
            try:
                if ipaddress.ip_address(cand.ip) == want:
                    return cand
            except ValueError:
                continue
    return h


def _no_firewall_data(db) -> bool:
    """FO-08: the site has no firewall at all (not even an unplaced one)."""
    from app.models import Firewall
    try:
        return db.query(Firewall.id).first() is None
    except Exception:          # pragma: no cover
        return False


def _ip_in(ip, net) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == net.version and a in net


def _path_result(src_ip, src_host, src_level, dst_ip, dst_host, dst_level, overall,
                 hops=None, path="unknown", error=None) -> dict:
    return {
        "src_ip": src_ip,
        "src_host": _host_dict(src_host),
        "src_level": src_level,
        "dst_ip": dst_ip,
        "dst_host": _host_dict(dst_host),
        "dst_level": dst_level,
        "overall": overall,
        "permitted_services": [],
        "denied_services": [],
        "hops": hops or [],
        "path": path,
        "error": error,
        "permitted_scopes": [],
        "nat": [],
        "nat_dependent": False,
        "nat_notes": [],
        "translated_scopes": [],
        "nat_destination": None,
        "inferred_adjacency": [],
        "inferred_hop_note": None,
        "unplaced_firewalls": [],
        "paired_group_warnings": [],
        "label_conflicts": [],
        "paths_evaluated": 1 if hops else 0,
        "alternatives": [],
        "path_note": None,
    }


def _host_dict(host: Optional[Host]) -> Optional[dict]:
    if host is None:
        return None
    return {
        "id": host.id,
        "ip_address": host.ip,
        "hostname": host.hostname,
        "mac_address": host.mac,
        "purdue_level": host.purdue_level,
        "device_type": host.device_type,
        "vendor": host.vendor,
    }


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("compute_",))
