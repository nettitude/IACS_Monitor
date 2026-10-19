"""
Observed-vs-configured topology diff.

Compares what's actually happening on the network (NetworkSession rows,
from pcap/ARP) against what the firewall configs say is *allowed*
(FirewallRule rows with action="permit"), and surfaces two kinds of
finding:

    unexpected_traffic  - an observed session with no matching permit
                          rule. Either a misconfiguration, a rule that
                          was since removed, or traffic riding on a
                          broader "any" rule somewhere the parser
                          couldn't resolve (see limitations below) -
                          worth a human's attention either way.
    unused_rules        - a permit rule that never matched any observed
                          session. A firewall hygiene finding (attack
                          surface reduction candidate) - though "never
                          observed in this capture" isn't the same as
                          "never used ever"; it only means not used
                          during whatever traffic was actually ingested.

PATH-AWARE POLICY EVALUATION (T3-34)
  A session is evaluated the same way reachability.py evaluates traffic:
  when both hosts have a purdue_level and at least one chain of
  enforcement points connects the two levels, EVERY hop on a path must
  permit the flow, each device's rules are walked in rule_order
  (first-match-wins), explicit deny rules count, and a device whose rules
  do not match ends in the vendor implicit deny.  The session is
  "explained" if at least one path permits it.  So a multi-hop L1->L3
  flow across the 1<->2 and 2<->3 firewalls is only explained if BOTH
  permit it - a permit on the 2<->3 box no longer explains a flow the
  1<->2 box denies.

  A flow that was OBSERVED although the policy denies it (earlier
  explicit deny, or implicit deny) is reported in unexpected_traffic with
  reason_code "explicit_deny" / "implicit_deny" and policy_mismatch=True
  for explicit denies: the traffic got through despite a deny, i.e. the
  ingested config is not what is enforced (or there is a bypass).

  Sessions without Purdue levels on both hosts, intra-level sessions, and
  crossings with no enforcement point (or whose enforcement points have
  no rules loaded) fall back to a per-device first-match evaluation over
  the devices that PLAUSIBLY CARRY the flow (A-24): a firewall whose
  interface subnets (FirewallInterface network_cidr / ip_cidr) contain
  the session's src or dst IP, or whose first matching rule names the
  flow's addresses specifically (src or dst not "any" / 0.0.0.0/0).  The
  session is explained if one such device's FIRST matching rule is a
  permit; an "any -> any" permit on an unrelated firewall explains
  nothing.  When no device plausibly carries the flow the session stays in
  unexpected_traffic with reason_code "no_enforcement_point_known"
  (policy_mismatch False; counted in sessions_no_enforcement_point) - it
  is kept there rather than in a separate list because consumers treat
  unexpected_traffic as "observed traffic no known policy explains", which
  this is; the distinct reason_code lets them filter or downgrade it.

SCOPE / LIMITATIONS (read before treating a finding as a fact rather
than a lead worth checking):

  - Only "any"/bare-IP/CIDR/`host <ip>`/Cisco wildcard-mask/IP-range
    address specs are resolved. Named objects that were never expanded at
    parse time - pfSense `network:<alias>` interface aliases, unresolved
    PAN-OS service/address objects - can't be matched at all. Rules
    containing one are reported separately in `unresolvable_rules` rather
    than silently treated as either a match or a non-match, since guessing
    either way would corrupt the other two lists.
    IP range objects (stored as "range:x.x.x.x-y.y.y.y" by
    forti_config_parser) are matched exactly (numeric lo/hi bounds in
    rule_match.AddrRange - T3-35), not collapsed to a supernet.
  - Only sessions where BOTH hosts have an IP address are considered.
    PROFINET sessions are MAC-only (no IP layer at all - see
    profinet_analyzer.py) and firewall rules are fundamentally an
    IP-layer concept, so PROFINET traffic is out of scope for this diff
    entirely rather than being falsely flagged as "unexpected" for a
    reason that has nothing to do with policy.
  - Matching is directional: a rule's `src` is checked against the
    session's initiating host and `dst` against the session's
    destination host, matching how firewall rules are actually written
    (permit traffic *from* src *to* dst). A session observed in the
    "wrong" direction relative to how a rule was written won't match
    that rule, which is correct behavior, not a bug - stateful firewalls
    return traffic for an established connection without a separate
    rule, so only the connection-initiating direction should need one.
  - EVERY session of the analysed site is evaluated (B-06): the sessions
    are read in keyset-paginated batches of SESSION_BATCH rows (ordered by
    id) so memory stays bounded by the batch, not the table. Only an
    explicit ``session_limit`` argument caps the evaluation; the result
    then reports sessions_total / sessions_evaluated / sessions_truncated
    so a partial analysis is never presented as complete (T3-41).
  - unused_rules lists permit rules that were never the FIRST match on a
    permitted path/device (a permit shadowed by an earlier permit is
    therefore "unused" - it never decides anything).

NAT (F-05)
  Sessions are evaluated through reachability's NAT-aware path walk:
  a session to a DNAT external address (VIP) is evaluated - and its
  destination level taken - as a flow to the mapped host; a session
  observed with the already-translated (mapped) destination, or with an
  SNAT'd source, is additionally evaluated from its un-translated form, so
  e.g. an internet client -> VIP-mapped server session is explained by a
  PAN-OS rule written against the pre-NAT address as well as by a FortiOS
  rule written against the VIP.  Per-vendor pre/post-NAT policy matching:
  see reachability._NAT_POLICY_MATCH.

RULE USAGE (F-10)
  The permit rule(s) that decided each explained session - on the ONE
  path evaluation the flow is taken to have used (A-24: most permissive,
  as-observed before NAT variants, first path first), the first-match
  permit of each enforcement point on it; not alternative paths, NAT
  variants or later permitted scopes - get
  FirewallRule.last_matched = max(existing, session.last_seen).  A permit
  rule is NOT listed in unused_rules while its last_matched (from this diff
  or from firewall logs) is within IACS_UNUSED_RULE_DAYS days (default
  90); every unused entry reports ``last_matched``.  The writes are
  flushed; they are committed here only when the session had no other
  pending changes and is not inside a savepoint (the caller's transaction
  otherwise owns the commit).
"""
import ipaddress
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from sqlalchemy.orm import Session as DBSession, joinedload

from app.models import FirewallInterface, FirewallRule, FirewallZone, Host, NetworkSession
from app.parsers import reachability as _reach
from app.parsers import rule_match as rm
# Single address parser lives in rule_match (re-exported for callers/tests).
from app.parsers.rule_match import parse_address_spec, AddrRange  # noqa: F401
from app.parsers.site_scope import scope_module

log = logging.getLogger(__name__)

AddressSpec = Union[str, "ipaddress.IPv4Network", AddrRange, None]  # "any" | network | range | None
PortSpec = Union[str, set, None]  # "any" | set of ints | None (unresolvable)

# B-06: page size of the keyset-paginated session scan (NOT a cap).
SESSION_BATCH = 5_000
# Kept for callers that referenced the old cap; no longer applied by default.
SESSION_LIMIT = None
DEFAULT_UNUSED_RULE_DAYS = 90


def unused_rule_days() -> int:
    """IACS_UNUSED_RULE_DAYS (default 90; invalid / negative -> default)."""
    try:
        v = int(os.environ.get("IACS_UNUSED_RULE_DAYS", DEFAULT_UNUSED_RULE_DAYS))
        return v if v >= 0 else DEFAULT_UNUSED_RULE_DAYS
    except (TypeError, ValueError):
        return DEFAULT_UNUSED_RULE_DAYS


def _aware(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def parse_port_spec(port_str: Optional[str]) -> PortSpec:
    """
    Back-compat view of rule_match.parse_ports: "any", a set of port ints,
    or None if unresolvable.  Internal matching uses the range tuples from
    rule_match directly (no 64k-element sets).
    """
    spec = rm.parse_ports(port_str)
    if isinstance(spec, rm.Unresolved):
        return None
    if spec == rm.ANY:
        return "any"
    out: set = set()
    for lo, hi in spec:
        out.update(range(lo, hi + 1))
    return out


class ParsedRule:
    """A FirewallRule with its address/port/protocol specs pre-resolved once
    (via rule_match), rather than re-parsing for every session."""

    def __init__(self, rule: FirewallRule):
        self.rule = rule
        self.src = rm.parse_address(rule.src, v6_default_is_any=False)
        self.dst = rm.parse_address(rule.dst, v6_default_is_any=False)
        self.port = rm.parse_ports(rule.dst_port)
        self.protos = rm.parse_protocols(rule.protocol)
        self.permit = (rule.action or "").strip().lower() in _reach._PERMIT_ACTIONS

    @property
    def is_resolvable(self) -> bool:
        return not any(isinstance(x, rm.Unresolved)
                       for x in (self.src, self.dst, self.port, self.protos))

    def matches_flow(self, src_ip: str, dst_ip: str, dst_port, transport) -> bool:
        """Assumes is_resolvable."""
        if not rm.ip_in_addr(src_ip, self.src) or not rm.ip_in_addr(dst_ip, self.dst):
            return False
        if self.protos != rm.ANY:
            if not transport or transport.lower() not in self.protos:
                return False
        if self.port == rm.ANY:
            return True
        if dst_port is None:
            return False
        return bool(rm.port_in(int(dst_port), self.port))

    def matches(self, session: NetworkSession) -> bool:
        return self.matches_flow(session.src_host.ip, session.dst_host.ip,
                                 session.dst_port, session.transport)


def _device_key(rule: FirewallRule):
    """Policy-list identity: the device, plus (N-24) its VDOM - a FortiGate
    VDOM is its own first-match list and policy ids repeat across VDOMs."""
    vdom = getattr(rule, "vdom", None)
    if rule.firewall_device_id is not None:
        return ("dev", rule.firewall_device_id, vdom)
    if rule.firewall_id is not None:
        return ("fw", rule.firewall_id, vdom)
    return ("name", rule.device_name or "unknown", vdom)


def _rule_ref(rule: FirewallRule) -> dict:
    return {
        "rule_id": rule.id,
        "policy_id": rule.policy_id,
        "vdom": getattr(rule, "vdom", None),
        "device_name": rule.device_name,
        "firewall_device_id": rule.firewall_device_id,
        "action": rule.action,
        "src": rule.src,
        "dst": rule.dst,
        "protocol": rule.protocol,
        "dst_port": rule.dst_port,
        "rule_order": rule.rule_order,
    }


class _Carriers:
    """A-24: which firewalls plausibly carry a flow.  A firewall carries it
    when one of its interfaces' subnets contains the session's src or dst
    IP (FirewallInterface network_cidr / ip_cidr on the device's linked
    Firewall)."""

    def __init__(self, db: DBSession):
        self._nets: dict = defaultdict(list)
        self._named: dict = defaultdict(list)     # fw_id -> [(net, iface name lower)]
        self.fw_ips: set = set()                  # H-04: every firewall interface address
        try:
            for (ip,) in db.query(FirewallInterface.ip_address).filter(
                    FirewallInterface.ip_address.isnot(None)):
                self.fw_ips.add(str(ip).strip())
        except Exception:  # pragma: no cover
            log.debug("FirewallInterface address lookup failed", exc_info=True)
        try:
            for fid, name, net_cidr, ip_cidr in db.query(FirewallInterface.firewall_id,
                                                         FirewallInterface.name,
                                                         FirewallInterface.network_cidr,
                                                         FirewallInterface.ip_cidr):
                for cidr in (net_cidr, ip_cidr):
                    if not cidr:
                        continue
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    if net.prefixlen == 0 or net.prefixlen == net.max_prefixlen:
                        continue
                    self._nets[fid].append(net)
                    if name:
                        self._named[fid].append((net, name.strip().lower()))
                    break
        except Exception:  # pragma: no cover - table missing in old DBs
            log.debug("FirewallInterface lookup failed", exc_info=True)
        # B-07: FortiOS zones, so a zone-based policy only matches flows on
        # its member interfaces
        self._zones = rm.load_zone_defs(db)
        self._iface_names: dict = defaultdict(set)   # fw_id -> every interface name
        self._legacy_zones: dict = defaultdict(dict)  # device lower -> zone -> {iface}
        try:
            for fid, name in db.query(FirewallInterface.firewall_id, FirewallInterface.name):
                if name:
                    self._iface_names[fid].add(name.strip().lower())
            for dev, iface, zone in db.query(FirewallZone.device_name,
                                             FirewallZone.interface_name,
                                             FirewallZone.zone_name):
                if dev and iface and zone:
                    self._legacy_zones[dev.strip().lower()].setdefault(
                        zone.strip().lower(), set()).add(iface.strip().lower())
        except Exception:  # pragma: no cover - table missing in old DBs
            log.debug("FirewallZone lookup failed", exc_info=True)

    def _iface_of(self, fw_id, ip) -> Optional[str]:
        """The interface whose connected subnet holds ``ip`` (longest
        prefix), or None when not directly connected / unknown."""
        try:
            a = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return None
        best = None
        for net, name in self._named.get(fw_id, ()):
            if a.version == net.version and a in net:
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, name)
        return best[1] if best else None

    def interfaces_ok(self, rule, src_ip, dst_ip) -> Optional[bool]:
        """B-07: can this FortiOS rule's srcintf / dstintf (zones expanded to
        member interfaces) see the flow?  False when the flow's ingress /
        egress interface (directly connected subnet of src / dst) is known
        and not in the rule's set; None when a named zone's membership is
        unresolved; True otherwise (incl. undeterminable interfaces).
        Other vendors' zone fields are not interface names: always True."""
        fw_id = rule.firewall_id
        if fw_id is None or (rule.device_type or "").lower() != "fortigate":
            return True
        zmap = self._zones.get((fw_id, getattr(rule, "vdom", None)))
        known_ifaces = self._iface_names.get(fw_id, set())
        legacy = self._legacy_zones.get((rule.device_name or "").strip().lower(), {})
        uncertain = False
        for zone, ip in ((rule.src_zone, src_ip), (rule.dst_zone, dst_ip)):
            names, resolved = rm.expand_zone_tokens(rm.zone_tokens(zone), zmap)
            if names is None:
                continue
            if not resolved:
                uncertain = True
                continue
            # interface-attribute zones (`set zone X` on the interface) -> members
            expanded = set()
            for n in names:
                if n in known_ifaces:
                    expanded.add(n)
                elif n in legacy:
                    expanded |= legacy[n]
                else:
                    expanded = None        # a name we cannot place: undeterminable
                    break
            if expanded is None:
                continue
            iface = self._iface_of(fw_id, ip)
            if iface is not None and iface not in expanded:
                return False
        return None if uncertain else True

    def same_segment(self, src_ip, dst_ip) -> bool:
        """Both addresses inside ONE connected subnet of some firewall
        interface: the flow is switched inside that segment and no firewall
        sees it (e.g. a remote-access gateway -> jump host in the DMZ)."""
        try:
            a, b = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
        except (TypeError, ValueError):
            return False
        for nets in self._nets.values():
            for n in nets:
                if a.version == n.version == b.version and a in n and b in n:
                    return True
        return False

    def carries(self, fw_id, src_ip, dst_ip) -> bool:
        nets = self._nets.get(fw_id)
        if not nets:
            return False
        for ip in (src_ip, dst_ip):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(a.version == n.version and a in n for n in nets):
                return True
        return False


def _group_fw_id(rules) -> Optional[int]:
    for pr in rules:
        r = pr.rule
        if r.firewall_id is not None:
            return r.firewall_id
        if r.firewall_device is not None and r.firewall_device.firewall_id is not None:
            return r.firewall_device.firewall_id
    return None


def _names_flow(pr: "ParsedRule") -> bool:
    """The rule names the flow's addresses explicitly: src or dst is a
    specific (not "any" / family-wide) spec - it matched, so it contains
    the session IP on that side."""
    return not rm.is_family_wide(pr.src) or not rm.is_family_wide(pr.dst)


def _first_match_global(groups: dict, src_ip, dst_ip, dst_port, transport,
                        carriers: Optional[_Carriers] = None, fw_ids: Optional[dict] = None):
    """Per-device first-match fallback (no Purdue path applies).

    A-24: only firewalls that plausibly carry the flow take part - the
    firewall's interfaces contain the src/dst IP, or its first matching
    rule names the flow's addresses specifically.  An "any -> any" permit
    on an unrelated firewall no longer explains a session.  Returns
    (explained, permit_rules, deny_rules, enforcement_known)."""
    permits, denies = [], []
    known = False
    for key, rules in groups.items():
        carried = bool(carriers and carriers.carries((fw_ids or {}).get(key), src_ip, dst_ip))
        known = known or carried
        for pr in rules:
            if pr.matches_flow(src_ip, dst_ip, dst_port, transport):
                # B-07: a zone / interface-bound FortiOS policy does not see a
                # flow on other interfaces - keep scanning (first match).
                ok = carriers.interfaces_ok(pr.rule, src_ip, dst_ip) if carriers else True
                if ok is False:
                    continue
                if ok is None:
                    # zone membership unknown: this rule may or may not be the
                    # first match - neither a permit nor a deny is claimed
                    known = True
                    break
                if carriers is None or carried or _names_flow(pr):
                    known = True
                    (permits if pr.permit else denies).append(pr.rule)
                break
    return bool(permits), permits, denies, known


def first_matches(db: DBSession, flows) -> dict:
    """G5: {(src_ip, dst_ip, port, transport): [{device, policy_id, policy_name,
    action}]} - per firewall / routing switch, the first enabled rule that
    matches the flow, for devices that plausibly carry it (an interface
    holds an endpoint, or the rule names the flow's addresses, or the
    device routes for the site - a switch's implicit route)."""
    from app.models import Firewall
    rules = db.query(FirewallRule).filter(FirewallRule.enabled.is_(True)) \
        .options(joinedload(FirewallRule.firewall_device)).all()
    rules.sort(key=_reach._rule_sort_key)
    groups: dict = defaultdict(list)
    for pr in (ParsedRule(r) for r in rules):
        if pr.is_resolvable:
            groups[_device_key(pr.rule)].append(pr)
    fw_ids = {k: _group_fw_id(v) for k, v in groups.items()}
    names = {f.id: f.name for f in db.query(Firewall)}
    carriers = _Carriers(db)
    out: dict = {}
    for flow in dict.fromkeys(flows):
        src_ip, dst_ip, port, transport = flow
        hits = []
        for key, prs in groups.items():
            fid = fw_ids.get(key)
            carried = carriers.carries(fid, src_ip, dst_ip)
            for pr in prs:
                if not pr.matches_flow(src_ip, dst_ip, port, transport):
                    continue
                if carriers.interfaces_ok(pr.rule, src_ip, dst_ip) is False:
                    continue
                route = str(pr.rule.policy_id or "").startswith("implicit:route:")
                if carried or _names_flow(pr) or route:
                    hits.append({"device": names.get(fid) or pr.rule.device_name, "policy_id": pr.rule.policy_id,
                                 "policy_name": pr.rule.policy_name, "action": pr.rule.action,
                                 "rule_id": pr.rule.id})
                break
        out[flow] = hits
    return out


def _path_attempts(ctx, paths, q):
    """(path, query, start_snat) evaluations: each path as observed plus its
    NAT un-translated variants (F-05)."""
    for path in paths:
        yield path, q, None
        for vq, snat in _reach._nat_start_variants(ctx, path, q):
            yield path, vq, snat


_RANK = {"permitted": 3, "partial": 2}


def _evaluate_session_paths(ctx, paths, src_level, q):
    """Path-aware evaluation (same algebra as reachability).  Returns
    (verdict_decision, deciding_permit_rule_ids, deny_info, nat_events).

    A-24: the deciding rules come from ONE evaluation - the path the flow
    is taken to have used: the most permissive attempt, preferring the
    as-observed query over NAT un-translated variants, then path order.
    On it, each hop's deciding rule is the first-match permit of every
    enforcement point (matching_rule for "permit", the first permitted
    scope for "partial")."""
    verdicts, best, deny_info = [], None, None
    for n, (path, pq, snat) in enumerate(_path_attempts(ctx, paths, q)):
        hops, v = _reach._evaluate_path(ctx, path, src_level, pq, start_snat=snat)
        verdicts.append(v)
        if v.decision in _RANK:
            score = (_RANK[v.decision], snat is None and pq is q, -n)
            if best is None or score > best[0]:
                best = (score, hops)
        elif v.decision == "denied" and deny_info is None:
            for h in hops:
                for ep in h["enforcement_points"]:
                    if ep.get("decision") == "deny":
                        deny_info = {
                            "reason_code": ep.get("reason_code"),
                            "boundary": h["boundary"],
                            "firewall_device_name": ep["firewall_device"].get("name"),
                            "firewall_device_id": ep["firewall_device"].get("id"),
                            "blocking_rule": ep.get("matching_rule"),
                        }
                        break
                if deny_info:
                    break
    matched: set = set()
    best_hops = best[1] if best else None
    for h in best_hops or []:
        for ep in h["enforcement_points"]:
            mr = ep.get("matching_rule")
            if ep.get("decision") == "permit" and mr:
                matched.add(mr["rule_id"])
            elif ep.get("decision") == "partial":
                for sc in ep.get("permitted_scopes") or []:
                    if sc.get("rule_id") is not None:
                        matched.add(sc["rule_id"])
                        break
    nat = [e for h in (best_hops or []) for e in h.get("nat", [])]
    return _reach._union_verdicts(verdicts).decision, matched, deny_info, nat


def _iter_session_batches(db: DBSession, batch_size: int, limit: Optional[int]):
    """B-06: yield lists of session rows ordered by id, keyset-paginated
    (``id > last_id``) so every session is visited with bounded memory.
    Stops after ``limit`` rows when a limit is given."""
    batch_size = max(1, int(batch_size))
    last_id = None
    remaining = limit
    while remaining is None or remaining > 0:
        n = batch_size if remaining is None else min(batch_size, remaining)
        q = db.query(NetworkSession.id, NetworkSession.dst_port, NetworkSession.protocol,
                     NetworkSession.transport, NetworkSession.src_host_id,
                     NetworkSession.dst_host_id, NetworkSession.last_seen,
                     NetworkSession.carrier_mac)
        if last_id is not None:
            q = q.filter(NetworkSession.id > last_id)
        rows = q.order_by(NetworkSession.id).limit(n).all()
        if not rows:
            return
        yield rows
        if remaining is not None:
            remaining -= len(rows)
        if len(rows) < n:
            return
        last_id = rows[-1].id


def compute_diff(db: DBSession, session_limit: Optional[int] = None,
                 batch_size: Optional[int] = None) -> dict:
    """
    Compare observed NetworkSession traffic against the configured firewall
    policy (see module docstring for the evaluation model).

    Returns:
        {
            "unexpected_traffic": [session summaries the policy does not permit;
                                   each has reason_code "explicit_deny" |
                                   "implicit_deny" | "no_matching_permit" |
                                   "unresolved_rule" | "no_enforcement_point_known", policy_mismatch, path_evaluated],
            "unused_rules":        [permit rules never the deciding match],
            "unresolvable_rules":  [permit rules that couldn't be parsed],
            "sessions_considered": int,
            "sessions_skipped_no_ip": int,
            "sessions_total": int,          # all NetworkSession rows (in scope)
            "sessions_evaluated": int,      # rows actually read and evaluated
            "sessions_truncated": bool,     # True only if session_limit cut the scan
            "session_limit": int | None,    # None = all sessions (default)
            "truncated": bool,              # alias of sessions_truncated
            "purdue_boundary_scoping": bool,  # any session evaluated along a path
            "sessions_path_evaluated": int,
        }
    """
    all_rules = (
        db.query(FirewallRule)
        .filter(FirewallRule.enabled.is_(True))
        .options(joinedload(FirewallRule.firewall_device))
        .all()
    )
    all_rules.sort(key=_reach._rule_sort_key)
    parsed = [ParsedRule(r) for r in all_rules]
    permit_parsed = [pr for pr in parsed if pr.permit]
    resolvable_permits = [pr for pr in permit_parsed if pr.is_resolvable]
    unresolvable_permits = [pr for pr in permit_parsed if not pr.is_resolvable]

    # Fallback pool: per-device ordered rulesets (unresolvable rules skipped -
    # they can neither confirm nor refute a match).
    groups: dict = defaultdict(list)
    for pr in parsed:
        if pr.is_resolvable:
            groups[_device_key(pr.rule)].append(pr)

    fw_ids = {k: _group_fw_id(v) for k, v in groups.items()}
    carriers = _Carriers(db)
    ctx = _reach._Context(db)
    # LS-03: router MAC -> the firewall / routing switch it belongs to
    try:
        from app.parsers.l3_switch import router_macs as _router_macs
        rmacs = _router_macs(db)
    except Exception:  # never fail the diff over carrier lookup
        log.warning("topology diff: router MAC lookup failed", exc_info=True)
        rmacs = {}
    paths_cache: dict = {}
    from app.parsers.l3_switch import external_level_fn, routing_switch_ids
    ext_level = external_level_fn(db)
    ctx.routing_switch_ids = routing_switch_ids(db)

    matched_rule_ids: set[int] = set()
    unexpected_traffic: list[dict] = []
    sessions_considered = 0
    sessions_skipped_no_ip = 0
    sessions_path_evaluated = 0
    sessions_no_enforcement_point = 0
    flow_cache: dict = {}
    rule_last_seen: dict = {}
    clean_before = not (db.new or db.dirty or db.deleted)

    sessions_total = db.query(NetworkSession).count()
    sessions_evaluated = 0
    hosts: dict[int, tuple] = {}

    def _batches():
        nonlocal sessions_evaluated
        for batch in _iter_session_batches(
                db, batch_size or SESSION_BATCH, session_limit):
            missing = list(({r.src_host_id for r in batch} | {r.dst_host_id for r in batch})
                           - hosts.keys())
            for i in range(0, len(missing), 900):
                for h in db.query(Host.id, Host.ip, Host.purdue_level).filter(
                        Host.id.in_(missing[i:i + 900])):
                    hosts[h.id] = (h.ip, ext_level(h.ip, h.purdue_level))
            sessions_evaluated += len(batch)
            yield from batch

    for row in _batches():
        src = hosts.get(row.src_host_id)
        dst = hosts.get(row.dst_host_id)
        if not src or not dst or not src[0] or not dst[0]:
            sessions_skipped_no_ip += 1
            continue
        sessions_considered += 1
        (src_ip, src_level), (dst_ip, dst_level) = src, dst
        cfw = rmacs.get(row.carrier_mac) if rmacs and row.carrier_mac else None
        key = (src_ip, dst_ip, row.dst_port, (row.transport or "").lower(), src_level, dst_level, cfw)
        res = flow_cache.get(key)
        if res is None:
            ctx.carrier_fw_id = cfw
            try:
                res = _evaluate_flow(ctx, groups, paths_cache, src_ip, dst_ip, row.dst_port,
                                     row.transport, src_level, dst_level,
                                     carriers=carriers, fw_ids=fw_ids)
            finally:
                ctx.carrier_fw_id = None
            if cfw is not None:
                res[2].setdefault("carried_by_firewall_id", cfw)
            flow_cache[key] = res
        explained, matched, info = res
        matched_rule_ids |= matched
        seen_at = _aware(row.last_seen)
        if seen_at is not None:
            for rid in matched:
                prev = rule_last_seen.get(rid)
                if prev is None or seen_at > prev:
                    rule_last_seen[rid] = seen_at
        if info.get("path_evaluated"):
            sessions_path_evaluated += 1
        if not explained:
            if info.get("reason_code") == "no_enforcement_point_known":
                sessions_no_enforcement_point += 1
            entry = {
                "session_id": row.id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": row.dst_port,
                "protocol": row.protocol,
                "transport": row.transport,
                "src_purdue_level": src_level,
                "dst_purdue_level": dst_level,
            }
            entry.update(info)
            unexpected_traffic.append(entry)

    def _dev_attr(pr, attr):
        return getattr(pr.rule.firewall_device, attr) if pr.rule.firewall_device else None

    # F-10: record the deciding rules' last match (max with existing values,
    # which may come from firewall logs).
    by_id = {pr.rule.id: pr.rule for pr in parsed}
    updated = 0
    for rid, seen_at in rule_last_seen.items():
        rule = by_id.get(rid)
        if rule is None:
            continue
        prev = _aware(rule.last_matched)
        if prev is None or seen_at > prev:
            rule.last_matched = seen_at
            updated += 1
    if updated:
        try:
            if db.in_nested_transaction():
                # inside a review SAVEPOINT (B11): a failed flush must roll
                # back this bookkeeping only, never the whole review run
                with db.begin_nested():
                    db.flush()
            else:
                db.flush()
                if clean_before:
                    db.commit()
        except Exception:  # never fail the diff over bookkeeping
            log.warning("topology diff: could not persist last_matched", exc_info=True)
            if not db.in_nested_transaction():
                db.rollback()

    days = unused_rule_days()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    def _recently_used(rule) -> bool:
        lm = _aware(rule.last_matched)
        return lm is not None and lm >= cutoff

    unused_rules = [
        {
            "rule_id": pr.rule.id,
            "device_name": pr.rule.device_name,
            "firewall_device_id": pr.rule.firewall_device_id,
            "firewall_device_name": _dev_attr(pr, "name"),
            "purdue_zone_from": _dev_attr(pr, "purdue_zone_from"),
            "purdue_zone_to": _dev_attr(pr, "purdue_zone_to"),
            "src": pr.rule.src,
            "dst": pr.rule.dst,
            "protocol": pr.rule.protocol,
            "dst_port": pr.rule.dst_port,
            "last_matched": _aware(pr.rule.last_matched).isoformat() if pr.rule.last_matched else None,
        }
        for pr in resolvable_permits
        if pr.rule.id not in matched_rule_ids and not _recently_used(pr.rule)
    ]
    unresolvable_rules_out = [
        {
            "rule_id": pr.rule.id,
            "device_name": pr.rule.device_name,
            "firewall_device_id": pr.rule.firewall_device_id,
            "firewall_device_name": _dev_attr(pr, "name"),
            "src": pr.rule.src,
            "dst": pr.rule.dst,
            "protocol": pr.rule.protocol,
            "dst_port": pr.rule.dst_port,
            "reason": "src, dst, protocol or dst_port references an object this parser couldn't resolve",
        }
        for pr in unresolvable_permits
    ]

    truncated = sessions_total > sessions_evaluated
    if truncated:
        log.warning("topology diff: evaluated %d of %d sessions (limit %s)",
                    sessions_evaluated, sessions_total, session_limit)
    return {
        "unexpected_traffic": unexpected_traffic,
        "unused_rules": unused_rules,
        "unresolvable_rules": unresolvable_rules_out,
        "sessions_considered": sessions_considered,
        "sessions_skipped_no_ip": sessions_skipped_no_ip,
        "sessions_total": sessions_total,
        "sessions_evaluated": sessions_evaluated,
        "sessions_truncated": truncated,
        "truncated": truncated,
        "session_limit": session_limit,
        "purdue_boundary_scoping": sessions_path_evaluated > 0,
        "sessions_path_evaluated": sessions_path_evaluated,
        "sessions_no_enforcement_point": sessions_no_enforcement_point,
        # C-08: number of enabled firewall rules loaded. Zero means there is no
        # firewall policy to evaluate sessions against, so every flow trivially
        # has "no matching permit" - a data-completeness gap, not a per-flow
        # violation. review_session_no_permitting_rule uses this to mark the
        # review incomplete instead of emitting a finding per session.
        "firewall_rules_total": len(all_rules),
        "unused_rule_days": days,
        "rules_last_matched_updated": updated,
    }


def _external(ip) -> bool:
    try:
        import ipaddress as _ipa
        return _ipa.ip_address(str(ip)).is_global
    except ValueError:
        return False


def _evaluate_flow(ctx, groups, paths_cache, src_ip, dst_ip, dst_port, transport,
                   src_level, dst_level, carriers=None, fw_ids=None):
    """Returns (explained, matched_permit_rule_ids, info_dict)."""
    nat_dst = None
    if ctx.has_nat:
        q0 = _reach._make_query(src_ip, dst_ip, dst_port, transport)
        tgt = ctx.dnat_target(dst_ip, q0["port"], q0["protos"])
        if tgt is not None:
            n, mapped_ip, mapped_port = tgt
            nat_dst = (mapped_ip, mapped_port)
            if dst_level is None:
                dst_level = ctx.host_level(mapped_ip)
    if carriers is not None and nat_dst is None and str(dst_ip) in carriers.fw_ips:
        # H-04: traffic TO a firewall (VPN login, the device's own admin
        # interface) is local-in - no forwarding policy governs it.
        return True, set(), {"path_evaluated": False, "boundary_scoped": False,
                             "reason_code": "local_in"}
    if src_level is not None and dst_level is not None and src_level != dst_level:
        pk = (src_level, dst_level)
        if pk not in paths_cache:
            paths_cache[pk] = _reach._path_between_levels(
                ctx.boundary_map, src_level, dst_level, flat_edges=ctx.flat_edges)
        paths = paths_cache[pk]
        if paths:
            q = _reach._make_query(src_ip, dst_ip, dst_port, transport)
            decision, matched, deny_info, nat = _evaluate_session_paths(ctx, paths, src_level, q)
            if decision != "no_policy":
                info = {
                    "path_evaluated": True,
                    "boundary_scoped": True,
                    "purdue_zone_from": min(src_level, dst_level),
                    "purdue_zone_to": max(src_level, dst_level),
                    "policy_decision": decision,
                }
                if nat:
                    info["nat"] = nat
                if decision in ("permitted", "partial"):
                    return True, matched, info
                if decision == "denied":
                    di = deny_info or {}
                    rc = di.get("reason_code")
                    info.update(
                        reason_code="explicit_deny" if rc == "matched_rule" else "implicit_deny",
                        policy_mismatch=rc == "matched_rule",
                        denied_at=di or None,
                        blocking_rule=di.get("blocking_rule"),
                    )
                else:  # unknown
                    info.update(reason_code="unresolved_rule", policy_mismatch=False)
                return False, set(), info

    if carriers is not None and nat_dst is None and carriers.same_segment(src_ip, dst_ip):
        # Switched inside one firewall-connected segment: no firewall policy
        # applies, so the flow is neither permitted nor denied by one - it
        # is not "traffic the policy does not explain".
        return True, set(), {"path_evaluated": False, "boundary_scoped": False,
                             "reason_code": "intra_segment"}
    cfw = getattr(ctx, "carrier_fw_id", None)
    serial = None
    if cfw is not None and fw_ids:
        # LS-03: only the device that carried the frames can explain them
        own = {k: v for k, v in groups.items() if fw_ids.get(k) == cfw}
        switches = getattr(ctx, "routing_switch_ids", set()) or set()
        if own and cfw in switches and (_external(src_ip) or _external(dst_ip)):
            # RS-03: a routing switch hands Internet traffic to a firewall -
            # the flow crosses both, in series; each one's permit counts
            serial = {k: v for k, v in groups.items()
                      if fw_ids.get(k) != cfw and fw_ids.get(k) not in switches}
        groups = own or groups
    explained, permits, denies, known = _first_match_global(
        groups, src_ip, dst_ip, dst_port, transport, carriers, fw_ids)
    if serial:
        e2, p2, d2, k2 = _first_match_global(serial, src_ip, dst_ip, dst_port, transport, carriers, fw_ids)
        if k2 or e2 or d2:
            explained = explained and e2
            permits = permits + p2 if explained else []
            denies = denies + d2
            known = known or k2
    if not explained and nat_dst is not None:
        # post-NAT vendors match the mapped destination (F-05)
        e2, p2, _d2, k2 = _first_match_global(
            groups, src_ip, nat_dst[0], nat_dst[1] if nat_dst[1] is not None else dst_port,
            transport, carriers, fw_ids)
        known = known or k2
        if e2:
            explained, permits = True, p2
    info = {"path_evaluated": False, "boundary_scoped": False}
    if explained:
        return True, {r.id for r in permits}, info
    if denies:
        info.update(reason_code="explicit_deny", policy_mismatch=True,
                    blocking_rule=_rule_ref(denies[0]))
    elif not known and groups:
        info.update(reason_code="no_enforcement_point_known", policy_mismatch=False,
                    reason=("No firewall is known to carry this flow (no interface "
                            "subnet contains either IP and no rule names its addresses)"))
    else:
        info.update(reason_code="no_matching_permit", policy_mismatch=False)
    return False, set(), info


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("compute_",))
