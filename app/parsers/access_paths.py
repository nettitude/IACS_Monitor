"""
Access-path enumeration (docs/access-path-review.md, phases 1-2).

A single, direction-aware enumeration of **every permitted communication path**
between Purdue levels/zones, with the exact permitting policy chain and a set of
62443-oriented flags per row.  The enumeration is config-only: it builds on the
existing reachability engine (``app.parsers.reachability``) and never
re-implements permit/deny logic — every verdict and every per-hop
``matching_rule`` is taken straight from ``compute_reachability``.

What phase 1 covers
-------------------
* Single-chain **down** paths (src level > dst level) and **up** paths
  (src level < dst level), including multi-firewall chains: a path that crosses
  ``L4 –[FW1]– L3.5 –[FW2]– L2`` is ONE row whose ``chain`` lists each hop, and
  it is emitted only when every hop permits it (the engine already AND-s hops).
* The flag taxonomy from the design doc's table (see ``_compute_flags``).
* ``boundary_only`` (default True): only cross-Purdue-level paths.  With it
  False an extra pass surfaces intra-zone / same-level permits (direction
  ``"same"``) using the engine's own level resolver.
* A per-call row budget (``IACS_MAX_ACCESS_PATH_ROWS``, falling back to the
  shared ``IACS_MAX_RULE_ROWS_PER_INGEST``): when exceeded the enumeration
  stops and the envelope's ``truncated`` flag is set — it never runs unbounded
  on a permissive firewall.

Phase 2 (traffic overlay + composed conduits)
---------------------------------------------
* ``traffic`` = {status, sessions, last_seen, rule_hits, rule_hits_since,
  last_matched[, capture_window]}.  Sessions (``NetworkSession``, read in
  batches) are oriented with traffic_findings.canonical_flow and placed by
  client / server host level; each distinct flow goes to exactly ONE row, the
  first candidate in the engine's first-match order whose scopes and service
  accept it.  Rule hits are FAZ / syslog traffic events attributed per rule
  the way app.parsers.rule_hits does, reported separately.
  Status ``seen`` / ``not_seen`` (the site has a capture or hits, none on
  this path - "not seen in the capture window", never "unused": a capture
  is a sample, and "unused rule" is the time-based ``unused_policy``
  finding) / ``no_capture`` (nothing to judge by) / ``partial`` (composed,
  one leg seen).
* ``unmatched_observed``: crossing flows that no permitted row explains,
  with direction-aware flags.
* ``direction: "composed"`` / ``conduit_through_dmz``: two permitted rows
  joined through ONE specific pivot host (never an any / all scope), IT side
  down to OT through a level between them.  Informational; never
  it_ot_bypass.  Seen only when both legs are.

Phase 3 (classification)
------------------------
* Every row / flow carries a stable ``tag_key`` (see "classification tags"
  below) and the stored ``access_path_tag`` fields; ``classify_access_paths``
  validates and upserts tags.  Tags whose key matches no current row are
  returned as ``orphaned_tags``.

Not here: the review UI and the report section (wave 2).

Site isolation: the whole call runs scoped to one site (``analysis_site``), so
no row can ever reference another site's policies.
"""
from __future__ import annotations

import ipaddress

import logging
import re
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.parsers.common import env_int

from app.models import ACCESS_PATH_CLASSIFICATIONS, AccessPathHop, AccessPathTag, FirewallInterface, FirewallRule
from app.parsers import rule_match as rm
from app.parsers.reachability import (
    _Context, _SIDE_UNKNOWN, _intersect_service, _is_permit, _subtract_denies, compute_reachability,
)
from app.parsers.site_scope import analysis_site
from app.purdue import (
    DMZ_LEVEL, is_deep_ot, is_dmz, is_it, is_it_side, is_ot, level_distance,
)

log = logging.getLogger(__name__)

# Row budget.  A dedicated knob, falling back to the shared per-ingest rule-row
# budget so operators have one number to reason about (docs/access-path-review).
_DEFAULT_MAX_ACCESS_PATH_ROWS = 20_000


def _max_rows() -> int:
    from app.parsers.common import max_rule_rows_per_ingest
    import os
    if os.environ.get("IACS_MAX_ACCESS_PATH_ROWS"):
        return env_int("IACS_MAX_ACCESS_PATH_ROWS", _DEFAULT_MAX_ACCESS_PATH_ROWS)
    # No dedicated knob set: use the smaller of our default and the shared
    # per-ingest budget, so a tightened ingest budget also tightens this.
    return min(_DEFAULT_MAX_ACCESS_PATH_ROWS, max_rule_rows_per_ingest())


# ---------------------------------------------------------------------------
# Flag taxonomy constants.
#
# alert_engine's insecure / industrial port tables are defined *inside* its
# check functions (not importable), so they are restated here with a note.
# The Purdue level predicates ARE imported from app.purdue (the one source of
# truth alert_engine itself uses) so the level tables are never duplicated.
# ---------------------------------------------------------------------------

# Cleartext protocols (flag cleartext_protocol = rule_cleartext_protocol, 3.5)
# and management protocols (flag mgmt_protocol = rule_mgmt_protocol, 5.1/5.2):
# the same two tables the findings use (owner 2026-10-12: separate findings;
# Telnet / SNMP v1/v2c are in both, so they carry both flags).  Replaces the
# single insecure_protocol flag.
from app.parsers.alert_engine import (  # noqa: E402
    _CLEARTEXT_PROTO_PORTS as CLEARTEXT_PORTS, _MGMT_PROTO_PORTS as MGMT_PORTS,
)

# Industrial / OT protocols (mirrors alert_engine's industrial proto_map in
# check_unauthorized_industrial_writes).
INDUSTRIAL_PORTS: dict[int, str] = {
    502: "Modbus/TCP", 20000: "DNP3", 44818: "EtherNet/IP", 102: "S7comm",
}

_ANY_SCOPE_TOKENS = frozenset({"all", "any", "*", "0.0.0.0/0", "::/0", ""})


_FULL_RANGE = (0, 65535)


def _is_any_scope(scope: Optional[str]) -> bool:
    return scope is None or str(scope).strip().lower() in _ANY_SCOPE_TOKENS


_PORT_RE = re.compile(r"(\d+)(?:-(\d+))?")


def _service_ports(services) -> tuple[list[tuple[int, int]], bool]:
    """Parse the engine's formatted service strings (e.g. ``"tcp/443"``,
    ``"udp/53,67"``, ``"tcp/1000-2000"``, ``"any"``, ``"icmp"``) into
    ``(ranges, covers_all)``.  ``covers_all`` is True when any service is
    all-ports (``"any"`` / ``".../any"``) or an unresolved object (fail-open
    for flagging: an unknown service might carry a dangerous port)."""
    ranges: list[tuple[int, int]] = []
    covers_all = False
    for s in services or []:
        s = str(s).strip().lower()
        if not s:
            continue
        if s == "any":
            covers_all = True
            continue
        if s.startswith("unresolved:") or "unresolved:" in s or "unknown:" in s:
            covers_all = True
            continue
        port_part = s.split("/", 1)[1] if "/" in s else None
        if port_part is None:
            # bare protocol such as "icmp" — no port semantics
            continue
        if port_part == "any":
            covers_all = True
            continue
        for tok in port_part.split(","):
            m = _PORT_RE.search(tok)
            if not m:
                continue
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            if lo <= hi:
                ranges.append((lo, hi))
    return ranges, covers_all


def _ports_matched(ranges: list[tuple[int, int]], table: dict[int, str]) -> dict[int, str]:
    """Entries of ``table`` whose port overlaps any range (same semantics as
    alert_engine._ports_matched)."""
    return {p: name for p, name in sorted(table.items())
            if any(lo <= p <= hi for lo, hi in ranges)}


def _direction(src_level, dst_level) -> str:
    """down = higher→lower (src level > dst level); up = lower→higher;
    same = equal levels (only surfaced when boundary_only is False)."""
    if src_level is None or dst_level is None:
        return "up"  # defensive; cells always carry both levels
    if src_level > dst_level:
        return "down"
    if src_level < dst_level:
        return "up"
    return "same"


def _permitting_eps(hop: dict) -> list[dict]:
    """Enforcement points on one hop that permit the flow (permit / partial)."""
    return [ep for ep in hop.get("enforcement_points", [])
            if ep.get("decision") in ("permit", "partial")]


def _hop_alternatives_permitted(hop: dict) -> list:
    """The hop's crossing alternatives (reachability.hop_alternatives: index
    lists into enforcement_points) whose EVERY enforcement point permits.
    Hops from older engine results carry no ``alternatives``: then the
    series set of all non-switch devices plus each switch on its own."""
    eps = hop.get("enforcement_points", [])
    alts = hop.get("alternatives")
    if alts is None:
        ser = [i for i, ep in enumerate(eps) if not (ep.get("firewall_device") or {}).get("routing_switch")]
        alts = ([ser] if ser else []) + [[i] for i, ep in enumerate(eps)
                                         if (ep.get("firewall_device") or {}).get("routing_switch")]
    return [alt for alt in alts
            if alt and all(eps[i].get("decision") in ("permit", "partial") for i in alt)]


def _stage_sets(hops: list[dict], rules_by_id: dict) -> list[list[list[dict]]]:
    """Stage lists of one engine path: one per combination of permitted
    crossing alternatives of the hops (AU full review C4: an alternative
    counts only when every device in it permits - a denying device is never
    dropped from a series set)."""
    import itertools
    per_hop = []
    for hop in hops:
        eps = hop.get("enforcement_points", [])
        alts = _hop_alternatives_permitted(hop)
        if not alts:
            return []
        per_hop.append([[_ep_candidates(eps[i], rules_by_id) for i in alt] for alt in alts])
    return [[st for alt in combo for st in alt] for combo in itertools.product(*per_hop)]


import contextvars as _cv

# owner 2026-10-19: {(firewall_id, tunnel interface lower): remote-side AddrSpec} for the enumeration
_TUNNEL_SELECTORS: _cv.ContextVar = _cv.ContextVar("iasc_tunnel_selectors", default=None)


def tunnel_selector_map(db) -> dict:
    """The remote-side selectors of every site-to-site tunnel interface, as one
    address spec per (firewall_id, interface name lower); empty when none.

    owner 2026-11-09: a FortiOS zone whose members are ALL tunnel interfaces with
    usable selectors is keyed too (the union of its members' remote selectors, no
    local bound) - a policy that names the zone instead of the tunnel is bounded
    the same way.  A zone that mixes a tunnel with a LAN interface is not: the
    traffic may enter on the LAN member and nothing bounds it."""
    from app.models import FirewallInterface, FirewallZoneDef
    out: dict = {}
    raw_remotes: dict = {}          # (firewall_id, interface lower) -> the remote selector strings
    for i in db.query(FirewallInterface).filter(FirewallInterface.tunnel_info.isnot(None)):
        info = i.tunnel_info if isinstance(i.tunnel_info, dict) else {}
        sels = info.get("selectors") or []
        remotes = [s.get("remote") for s in sels if s.get("remote") and s.get("remote") != "0.0.0.0/0"]
        if not remotes or any(s.get("remote") == "0.0.0.0/0" for s in sels):
            continue
        # the local side bounds the other end only for dial-up tunnels (split-include); a site-to-site
        # local selector may be a pre-NAT address (VIP) and must not narrow a post-NAT policy
        locals_ = [s.get("local") for s in sels if s.get("local") and s.get("local") != "0.0.0.0/0"] if info.get("dynamic") else []
        try:
            out[(i.firewall_id, str(i.name).lower())] = (
                rm.parse_address(",".join(remotes), v6_default_is_any=False),
                rm.parse_address(",".join(locals_), v6_default_is_any=False) if locals_ and len(locals_) == len(sels) else None)
            raw_remotes[(i.firewall_id, str(i.name).lower())] = list(remotes)
        except Exception:      # noqa: BLE001
            continue
    if not raw_remotes:
        return out
    for zd in db.query(FirewallZoneDef).filter(FirewallZoneDef.kind == "zone"):
        fw_id, zone = zd.firewall_id, str(zd.name).lower()
        members = [str(m).strip('"').lower() for m in (zd.members or []) if str(m).strip()]
        if (fw_id, zone) in out or not members or zd.members_resolved is False:
            continue                                     # an interface of that name wins; unresolved = unknown
        keys = [(fw_id, m) for m in members]
        if not all(k in raw_remotes for k in keys):
            continue                                     # a member without selectors: unbounded zone
        remotes = sorted({r for k in keys for r in raw_remotes[k]})
        try:
            out[(fw_id, zone)] = (rm.parse_address(",".join(remotes), v6_default_is_any=False), None)
        except Exception:      # noqa: BLE001
            continue
    return out


def _narrow_by_selectors(rule, piece: tuple) -> tuple:
    """(piece, narrowed) - the rule's source / destination intersected with the
    remote-side selectors of the tunnel interface it names (empty -> None)."""
    sel = _TUNNEL_SELECTORS.get()
    if not sel:
        return piece, False
    src, dst, protos, ports = piece

    def _cut(spec, bound):
        """spec ∩ bound - left alone when the two share no address family (an
        IPv6 policy on a tunnel with IPv4 selectors is not "nothing", it is
        unbounded by them) or when the spec is unresolved."""
        if spec is None or bound is None:
            return spec
        fam_s, fam_b = rm.addr_versions(spec), rm.addr_versions(bound)
        if fam_s is not None and fam_b is not None and not (fam_s & fam_b):
            return spec
        return rm.addr_intersect(spec, bound)
    for side, zone in ((0, rule.src_zone), (1, rule.dst_zone)):
        for tok in str(zone or "").split(","):
            entry = sel.get((rule.firewall_id, tok.strip().lower()))
            if entry is None:
                continue
            remote, local = entry
            if side == 0:
                src = _cut(src, remote)
                if local is not None:
                    dst = _cut(dst, local)
            else:
                dst = _cut(dst, remote)
                if local is not None:
                    src = _cut(src, local)
    # the flag means "narrowed": set only when a side actually changed (audit 2026-10-19)
    narrowed = (src, dst) != (piece[0], piece[1])
    return (src, dst, protos, ports), narrowed


def _rule_piece(rule) -> tuple:
    """(src, dst, protos, ports) of a stored FirewallRule, parsed exactly as
    the reachability engine parses it (_Context.parsed)."""
    return (rm.parse_address(rule.src, v6_default_is_any=False),
            rm.parse_address(rule.dst, v6_default_is_any=False),
            rm.parse_protocols(rule.protocol),
            rm.parse_ports(rule.dst_port))


def _policy_from_rule(rule, fw: dict) -> dict:
    """Policy identity from the STORED FirewallRule (policy_name = `set name`)."""
    return {
        "firewall_device_id": rule.firewall_device_id if rule.firewall_device_id is not None
        else fw.get("id"),
        "firewall_name": fw.get("name") or rule.device_name,
        "vdom": getattr(rule, "vdom", None),
        "policy_id": rule.policy_id,
        "policy_name": rule.policy_name,
        "action": rule.action,
        "src_zone": rule.src_zone,
        "dst_zone": rule.dst_zone,
        "src": rule.src,
        "dst": rule.dst,
        "external_internet": any(rm.is_external_addr_token(x) for x in (rule.src, rule.dst)),
        "rule_id": rule.id,
        "firewall_id": rule.firewall_id,
        **dict(zip(("_piece", "_selector_narrowed"), _narrow_by_selectors(rule, _rule_piece(rule)))),
        # engine evaluation order (rule_order, id) = first-match priority
        "_prio": (rule.rule_order is None, rule.rule_order or 0, rule.id or 0),
    }


def _ep_candidates(ep: dict, rules_by_id: dict) -> list[dict]:
    """The PERMIT policies through which one enforcement point lets the flow
    pass — one candidate per permitting rule.

    * decision "permit": the engine's ``matching_rule`` is the terminal permit
      (or None for a FortiOS intrazone-allow, which has no policy).
    * decision "partial": the permits are the engine's ``permitted_scopes``
      entries (one per permit rule).  The ep's ``matching_rule`` here is the
      TERMINAL rule that ended evaluation - typically the explicit DENY that
      follows the specific permits - so it must never be attributed.

    Every candidate is re-checked to be a permit rule; a deny never appears.
    """
    fw = ep.get("firewall_device") or {}
    out: list[dict] = []
    unverified = set(ep.get("direction_unverified") or ())
    # MP-10: the device's specific denies in front of its permits, as pieces
    # every candidate of this enforcement point carries
    denies = _deny_pieces(ep.get("denied_pieces"))
    if ep.get("decision") == "permit":
        mr = ep.get("matching_rule")
        if mr is None:
            out.append({"firewall_device_id": fw.get("id"), "firewall_name": fw.get("name"),
                        "vdom": None, "policy_id": None, "policy_name": None,
                        "action": "intrazone_allow", "src_zone": None, "dst_zone": None,
                        "src": "any", "dst": "any", "external_internet": False,
                        "rule_id": None, "firewall_id": fw.get("firewall_id"),
                        "_piece": (rm.ANY, rm.ANY, rm.ANY, rm.ANY),
                        "_denies": denies,
                        "_prio": (True, 1 << 30, 1 << 30)})
            return out
        # G-04: narrower permits evaluated BEFORE the terminal permit (an
        # "any" rule further down) match their traffic first; they are the
        # engine's permitted_scopes.  Without them every flow would be
        # attributed to the broad rule.
        seen_ids: set = set()
        for sc in ep.get("permitted_scopes") or []:
            rid = sc.get("rule_id")
            if rid in seen_ids or rid == mr.get("rule_id"):
                continue
            seen_ids.add(rid)
            early = rules_by_id.get(rid)
            if early is not None and _is_permit(early):
                out.append({**_policy_from_rule(early, fw), "_dir_unverified": early.id in unverified,
                            "_denies": denies})
        rule = rules_by_id.get(mr.get("rule_id"))
        if rule is not None and _is_permit(rule):
            out.append({**_policy_from_rule(rule, fw), "_dir_unverified": rule.id in unverified,
                        "_denies": denies})
        return out
    seen: set = set()
    for sc in ep.get("permitted_scopes") or []:
        rid = sc.get("rule_id")
        if rid in seen:
            continue
        seen.add(rid)
        rule = rules_by_id.get(rid)
        if rule is not None and _is_permit(rule):
            out.append({**_policy_from_rule(rule, fw), "_dir_unverified": rule.id in unverified,
                        "_denies": denies})
    return out


def _deny_pieces(items) -> list:
    """The engine's ``denied_pieces`` back into (protos, ports) pieces."""
    out = []
    for d in items or []:
        protos = rm.ANY if d.get("protos") == "any" else frozenset(d.get("protos") or ())
        ports = rm.ANY if d.get("ports") == "any" else rm.normalize_ranges(
            [tuple(x) for x in (d.get("ports") or [])])
        out.append((protos, ports))
    return out


def _is_any_piece(piece: tuple) -> bool:
    """Does a single policy permit any-source, any-destination or any-service?"""
    src, dst, p, x = piece

    def wide(a):
        return a == rm.ANY or (not isinstance(a, rm.Unresolved) and a is not None
                               and rm.is_family_wide(a))
    return wide(src) or wide(dst) or (p == rm.ANY and x == rm.ANY)


def _chain_entry(pol: dict) -> dict:
    """One hop of a row's chain.  MP-22: carries the policy's own src / dst /
    service and whether it is an any -> any / any-service policy, so the
    evidence shows where the chain is broad and where it is narrow."""
    piece = pol.get("_piece")
    services = None
    if piece is not None:
        try:
            services = rm.format_services(piece[2], piece[3])
        except Exception:
            services = None
    return {
        "rule_id": pol.get("rule_id"),
        "firewall_id": pol.get("firewall_id"),
        "firewall_device_id": pol["firewall_device_id"],
        "firewall_name": pol["firewall_name"],
        "vdom": pol["vdom"],
        "policy_id": pol["policy_id"],
        "policy_name": pol["policy_name"],
        "action": pol["action"],
        "src": pol.get("src"),
        "dst": pol.get("dst"),
        "service": services,
        "any_policy": _is_any_piece(piece) if piece is not None else None,
    }


def _marked_chain(chain: list) -> list:
    _mark_chain_breadth(chain)
    return chain


def _mark_chain_breadth(chain: list) -> None:
    """MP-22: mark the narrowest hop(s) of a chain - the policy that scopes
    the traffic (the recommended change point) - and the broad ones."""
    if not chain:
        return
    def width(h):
        piece_w = 0
        for key in ("src", "dst"):
            v = h.get(key)
            try:
                spec = rm.parse_address(v, v6_default_is_any=False) if v else rm.ANY
            except Exception:
                spec = rm.ANY
            if spec == rm.ANY or isinstance(spec, rm.Unresolved):
                piece_w += 1 << 40
            else:
                try:
                    piece_w += sum(hi - lo + 1 for rs in rm.addr_intervals(spec).values() for lo, hi in rs)
                except Exception:
                    piece_w += 1 << 40
        svc = h.get("service") or []
        piece_w += (1 << 40) if (not svc or "any" in svc) else len(svc)
        return piece_w
    ws = [width(h) for h in chain]
    narrowest = min(ws)
    for h, w in zip(chain, ws):
        h["narrowest"] = w == narrowest


def _spec_may_be_public(spec) -> bool:
    """The address spec includes (or may include) globally routable
    addresses: any / family-wide, or a member that is not private."""
    import ipaddress as _ip
    if spec is None or isinstance(spec, rm.Unresolved):
        return False
    if spec == rm.ANY or rm.is_family_wide(spec):
        return True
    for v, ivs in rm.addr_intervals(spec).items():
        cls = _ip.IPv4Address if v == 4 else _ip.IPv6Address
        for lo, hi in ivs:
            if not (cls(lo).is_private and cls(hi).is_private):
                return True
    return False


def _site_has_dmz(db, reach: Optional[dict] = None) -> bool:
    """The bound site has an industrial DMZ: an enforcement point touches
    L3.5.  MP-12: decided from the engine's boundaries when ``reach`` is
    given, so a boundary L3.5 that the interface labels contradict (a
    phantom DMZ leg) does not switch on site-wide dmz_bypass flagging."""
    if reach is not None:
        return any(DMZ_LEVEL in (e.get("zone_lo"), e.get("zone_hi"))
                   for e in reach.get("enforcement_points") or [])
    from app.models import Firewall, FirewallDevice, FirewallInterface
    if db.query(FirewallInterface.id).join(Firewall, Firewall.id == FirewallInterface.firewall_id) \
            .filter(FirewallInterface.purdue_level == DMZ_LEVEL).first():
        return True
    return db.query(FirewallDevice.id).filter(
        (FirewallDevice.purdue_zone_from == DMZ_LEVEL) | (FirewallDevice.purdue_zone_to == DMZ_LEVEL)).first() is not None


def _compute_flags(*, src_level, dst_level, direction: str, traversed: set,
                   n_hops: int, ranges, covers_all: bool,
                   any_policy: bool, external_internet: bool,
                   dst_public: bool = False, has_dmz: bool = False) -> list[str]:
    """The design-doc flag taxonomy for one cross-boundary row.

    Level predicates come from app.purdue (is_ot / is_deep_ot / is_it /
    is_it_side / DMZ_LEVEL) — the same semantics alert_engine's
    review_rule_it_ot_bypass / check_ot_internet_egress classify crossings by.
    """
    flags: list[str] = []
    eff = [_FULL_RANGE] if covers_all else list(ranges)

    # permit_any — a policy OF THIS ROW has any-source, any-dest or
    # any-service (never inherited from another policy of the same cell).
    if any_policy:
        flags.append("permit_any")

    # it_ot_bypass — downhill IT→OT crossing with no session break.
    # Mirrors review_rule_it_ot_bypass: IT-side (≥L3, incl. the DMZ itself) →
    # deep-OT (≤L1), or enterprise (≥L4) → L2.  Routing THROUGH the DMZ
    # firewalls does not make it compliant: a direct row keeps the same
    # source and destination end to end, so nothing in the DMZ terminates the
    # session.  Only a composed row (leg 1 ends on a DMZ host, leg 2 starts
    # from it - direction "composed", never evaluated here) is exempt.
    if direction == "down":
        deep_hit = is_it_side(src_level) and is_deep_ot(dst_level)
        l2_hit = is_it(src_level) and dst_level == 2
        if deep_hit or l2_hit:
            flags.append("it_ot_bypass")

    # ot_egress_external — OT zone → IT / internet / external scope.
    if is_ot(src_level) and (is_it(dst_level) or external_internet):
        flags.append("ot_egress_external")

    # internet_egress (H-13) — an OT zone, site operations (L3) included,
    # can open sessions to the internet: the destination is an IT-side / L5
    # leg whose scope includes public addresses, or an internet-service.
    internet = (src_level is not None and src_level <= 3 and direction == "up"
                and ((is_it(dst_level) and dst_public) or external_internet))
    if internet:
        flags.append("internet_egress")

    # dmz_bypass (H-14) — the site HAS an industrial DMZ, yet the row joins
    # the IT side / internet / remote users (L4-L5) and site operations (L3)
    # directly, in either direction, without terminating on a DMZ host
    # (composed rows - the sanctioned pattern - are never evaluated here).
    if has_dmz and not internet and (
            (direction == "down" and is_it(src_level) and dst_level == 3)
            or (direction == "up" and src_level == 3 and is_it(dst_level))):
        flags.append("dmz_bypass")

    # ot_upward_skip — uphill crossing that skips a Purdue tier.  Mirrors
    # it_ot_bypass (G-02): deep OT (L0/L1) reaching the IT side (L3 and up,
    # incl. the DMZ), or L2 reaching enterprise (L4/L5), in ONE routed
    # session - passing every boundary's firewall does not break the session.
    # Also when a boundary on the way has no enforcement point at all (fewer
    # hops than Purdue steps).  Composed rows are never evaluated here.
    up_mirror = (is_deep_ot(src_level) and is_it_side(dst_level)) or \
        (src_level == 2 and is_it(dst_level))
    tier_gap = bool(n_hops) and level_distance(src_level, dst_level) > n_hops
    if direction == "up" and (up_mirror or (is_ot(src_level) and tier_gap)):
        # an OT source only: a DMZ / site host going straight out (e.g. a
        # remote-access gateway to the internet) is not an OT upward skip
        flags.append("ot_upward_skip")

    # cleartext_protocol / mgmt_protocol — across a zone boundary (both for
    # a cleartext management protocol such as Telnet or SNMP v1/v2c).
    if _ports_matched(eff, CLEARTEXT_PORTS):
        flags.append("cleartext_protocol")
    if _ports_matched(eff, MGMT_PORTS):
        flags.append("mgmt_protocol")

    # industrial_proto_out_of_zone — Modbus/DNP3/S7/EtherNet-IP permitted with
    # an endpoint outside the OT zones (L0–L2).
    if _ports_matched(eff, INDUSTRIAL_PORTS) and not (is_ot(src_level) and is_ot(dst_level)):
        flags.append("industrial_proto_out_of_zone")

    return flags


def _initiation(src_level, dst_level, direction: str, src_zone) -> dict:
    """Best-effort connection-initiation descriptor (62443 conduit semantics):
    the policy's source zone opens the connection; a less-trusted lower zone
    opening *into* a higher zone (``lower_to_higher``) is called out distinctly
    from the reverse."""
    toward = ("lower_to_higher" if direction == "up"
              else "higher_to_lower" if direction == "down" else "intra_zone")
    return {"level": src_level, "zone": src_zone, "initiates": toward}


def _row(*, src, dst, service, protocol, direction, chain, flags, initiation):
    return {
        "src": src,
        "dst": dst,
        "service": service,
        "protocol": protocol,
        "direction": direction,
        "chain": chain,
        "flags": flags,
        "initiation": initiation,
        # Filled by apply_overlay (sessions + rule hits); null only when the
        # caller asks for the config-only enumeration (overlay=False).
        "traffic": None,
    }


def _empty_counts() -> dict:
    return {"total": 0,
            "by_direction": {"down": 0, "up": 0, "composed": 0, "same": 0},
            "by_flag": {},
            "by_traffic": {"seen": 0, "not_seen": 0, "no_capture": 0, "partial": 0},
            "by_classification": {c: 0 for c in ACCESS_PATH_CLASSIFICATIONS},
            "by_reach": {"reaches": 0, "prefix": 0, "dead_end": 0},     # MP-07
            "report_include": 0}


def count_rows(paths: list[dict]) -> dict:
    """Counts envelope ({total, by_direction, by_flag}) for a row list.
    Exposed so the endpoint can recount after ``flagged_only`` filtering."""
    counts = _empty_counts()
    counts["total"] = len(paths)
    for p in paths:
        counts["by_direction"][p["direction"]] = counts["by_direction"].get(p["direction"], 0) + 1
        rc = p.get("reach") or "reaches"
        counts["by_reach"][rc] = counts["by_reach"].get(rc, 0) + 1
        for f in p["flags"]:
            counts["by_flag"][f] = counts["by_flag"].get(f, 0) + 1
        tr = p.get("traffic")
        if tr:
            counts["by_traffic"][tr["status"]] = counts["by_traffic"].get(tr["status"], 0) + 1
        cls = p.get("classification")
        if cls:
            counts["by_classification"][cls] = counts["by_classification"].get(cls, 0) + 1
        if p.get("report_include"):
            counts["report_include"] += 1
    return counts


def report_lines(res: dict) -> list[tuple[dict, str]]:
    """The lines the compliance report prints for one ``_enumerate`` result,
    as ``(item, kind)`` with kind ``path`` | ``composed`` | ``unexplained``.

    THE single definition of "in the report": generate_report.py prints
    exactly these, and GET /access-paths ``counts.report_include`` (the
    console's "Generate report (N lines)") is their number.  Rows / composed
    conduits / unexplained flows whose effective report_include is true;
    intra-zone rows (hidden in the review screen by default) only when the
    reviewer explicitly included them (stored tag, not the row default)."""
    tags = res.get("tags") or {}
    out: list[tuple[dict, str]] = []
    for row in res["paths"]:
        if not row.get("report_include"):
            continue
        if row["direction"] == "same":
            t = tags.get(row.get("tag_key"))
            if t is None or t.report_include is not True:
                continue
        out.append((row, "composed" if row["direction"] == "composed" else "path"))
    for flow in res["unmatched"].get("all_flows") or []:
        if flow.get("report_include"):
            out.append((flow, "unexplained"))
    return out


def report_line_counts(res: dict) -> dict:
    """``{report_include, report_include_by_kind: {path, composed,
    unexplained}}`` for one ``_enumerate`` result (see report_lines)."""
    by_kind = {"path": 0, "composed": 0, "unexplained": 0}
    for _item, kind in report_lines(res):
        by_kind[kind] += 1
    return {"report_include": sum(by_kind.values()), "report_include_by_kind": by_kind}


def enumerate_access_paths(
    db: DBSession,
    site_id: int,
    *,
    direction: str = "all",
    boundary_only: bool = True,
    overlay: bool = True,
    include_unmatched: bool = True,
    unmatched_cap: int = 500,
) -> dict:
    """Enumerate every permitted access path of one site, with the traffic
    overlay and the operator's classification tags merged in.

    Parameters
    ----------
    db, site_id
        The whole call runs scoped to ``site_id`` (``analysis_site``), so no
        row references another site's policies or tags.
    direction
        ``"all"`` | ``"down"`` | ``"up"``.  Composed / intra-zone rows appear
        only under ``"all"``.  Applied after the overlay, so a hidden row's
        traffic never looks unexplained.
    boundary_only
        True (default): only cross-Purdue-level paths.  False also lists
        intra-zone / same-level permits (direction ``"same"``).
    overlay
        False = config-only (``traffic`` null, no unexplained flows).
    include_unmatched, unmatched_cap
        Include up to ``unmatched_cap`` unexplained observed flows.

    Returns ``{"paths", "truncated", "counts", "capture_window",
    "orphaned_tags", "orphaned_incomplete", ["unmatched_observed",
    "unmatched_total", "unmatched_sessions", "unmatched_capped",
    "unmatched_incomplete"]}`` - see docs/access-path-review.md, "API".
    """
    if direction not in ("all", "down", "up"):
        raise ValueError(f"direction must be 'all', 'down' or 'up'; got {direction!r}")
    with analysis_site(db, site_id):
        res = _enumerate(db, overlay=overlay, unmatched_cap=unmatched_cap)
    report_counts = report_line_counts(res)
    paths = res["paths"]
    flows = res["unmatched"]["flows"]
    if boundary_only:
        paths = [p for p in paths if p["direction"] != "same"]
    if direction != "all":
        paths = [p for p in paths if p["direction"] == direction]
        flows = [f for f in flows if f["direction"] == direction]
    paths = [_public(p) for p in paths]
    truncated = res["truncated_visible"] if boundary_only else res["truncated"]
    out = {"paths": paths, "truncated": truncated, "counts": count_rows(paths),
           "unlabelled_firewalls": res["unlabelled_firewalls"],
           "unplaced_firewalls": res.get("unplaced_firewalls") or [],
           "paired_group_warnings": res.get("paired_group_warnings") or [],
           "label_conflicts": res.get("label_conflicts") or [],
           "composition_notes": res.get("composition_notes") or [],
           "capture_window": res["unmatched"]["capture_window"],
           "orphaned_tags": res["orphaned"],
           # a truncated enumeration may have dropped the row a tag belongs to
           "orphaned_incomplete": res["truncated"]}
    out["counts"]["orphaned"] = len(res["orphaned"])
    # what the report prints for the whole site, whatever the filters
    out["report_counts"] = report_counts
    out["counts"].update(report_counts)
    if overlay and include_unmatched:
        u = res["unmatched"]
        out["unmatched_observed"] = flows
        out["unmatched_total"] = u["total"]
        out["unmatched_sessions"] = u["sessions"]
        out["unmatched_capped"] = u["capped"]
        # rows missing from a truncated enumeration make their traffic look
        # unexplained: say so instead of over-reporting silently.
        out["unmatched_incomplete"] = res["truncated"]
        out["counts"]["unmatched_total"] = u["total"]
    return out


def _public(row: dict) -> dict:
    """A row without its internal (``_``-prefixed) working fields."""
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _walk_stages(stages, nat=None):
    """Yield ``(combo, piece)`` for every choice of one policy per stage whose
    host scopes AND services all intersect, in ``itertools.product`` order
    (see _walk_stages_nat; ``nat`` = a NatIndex)."""
    for combo, piece, _ev in _walk_stages_nat(stages, nat):
        yield combo, piece


def _walk_stages_nat(stages, nat=None):
    """Yield ``(combo, piece, nat_events)``.

    Depth-first with the running intersection: a branch dies as soon as the
    scopes stop overlapping, so a chain of N firewalls costs roughly the
    number of *surviving* paths instead of the product of every stage's
    policy count (10 stages x ~15 policies each never finished).

    P-02 / P-03: with a NatIndex the walk translates between firewalls - a
    policy's source NAT replaces the source the next firewall sees, and the
    next firewall's VIP replaces a destination inside its external address
    (FortiOS-style "post" vendors before their policies are matched, "pre"
    vendors after).  The yielded piece keeps the ORIGINAL source (who really
    connects) and the FINAL destination; nat_events lists the translations
    and the VIPs the chosen policies publish."""
    n = len(stages)
    chosen: list = []

    def fw_of(i):
        return stages[i][0].get("firewall_id") if stages[i] else None

    def rec(i, piece, orig_src, events):
        if i == n:
            yield tuple(chosen), (piece if orig_src is None else
                                  (orig_src, piece[1], piece[2], piece[3])), events
            return
        cur, evs = piece, events
        if nat and i > 0:
            d = nat.apply_dnat(fw_of(i), cur[1], cur[3], mode="post")
            if d is not None:
                cur, evs = (cur[0], d[0], cur[2], d[1]), evs + [d[2]]
        for pol in stages[i]:
            nxt = _intersect_service(cur, pol["_piece"])
            if nxt is None:
                continue
            if pol.get("_denies"):
                # MP-10: a specific deny in front of this permit (deny tcp/502,
                # permit any) blocks those services for the whole chain
                left = _subtract_denies([nxt], pol["_denies"])
                if not left:
                    continue
                nxt = left[0]
            o, ev2 = orig_src, evs
            if nat:
                ev2 = ev2 + [e for e in nat.published_by(pol) if e not in ev2]
                s_ = nat.apply_snat(pol, nxt[0])
                if s_ is not None:
                    o = o if o is not None else nxt[0]
                    nxt, ev2 = (s_[0], nxt[1], nxt[2], nxt[3]), ev2 + [s_[1]]
                d = nat.apply_dnat(pol.get("firewall_id"), nxt[1], nxt[3], mode="pre")
                if d is not None:
                    nxt, ev2 = (nxt[0], d[0], nxt[2], d[1]), ev2 + [d[2]]
            chosen.append(pol)
            yield from rec(i + 1, nxt, o, ev2)
            chosen.pop()

    yield from rec(0, (rm.ANY, rm.ANY, rm.ANY, rm.ANY), None, [])


def _enumerate(db: DBSession, *, overlay: bool = True, unmatched_cap: int = 500) -> dict:
    """``_enumerate_rows`` with the tunnel-selector map bound for the duration
    of the call and reset afterwards (the scheduler thread must not keep one
    site's map for the next; audit 2026-10-19)."""
    tok = _TUNNEL_SELECTORS.set(tunnel_selector_map(db) or None)      # owner 2026-10-19
    try:
        return _enumerate_rows(db, overlay=overlay, unmatched_cap=unmatched_cap)
    finally:
        _TUNNEL_SELECTORS.reset(tok)


def _enumerate_rows(db: DBSession, *, overlay: bool = True, unmatched_cap: int = 500) -> dict:
    """Every row of the bound site (all directions, intra-zone rows
    included), overlay applied, tag keys assigned and tags merged.  Rows
    keep their internal ``_`` fields.  Must run inside ``analysis_site``.

    Returns {"paths", "unmatched": apply_overlay result, "truncated",
    "truncated_visible" (budget hit before the hidden intra-zone pass),
    "orphaned", "tags": {tag_key: AccessPathTag}, "index": {tag_key: row or
    flow}}."""
    budget = _max_rows()
    paths: list[dict] = []
    truncated = False
    unverified_fws: set = set()     # D-11: firewalls whose rules lacked level evidence

    # ---- cross-boundary enumeration: build straight on the engine -----
    reach = compute_reachability(db)
    has_dmz = _site_has_dmz(db, reach)
    matrix = reach.get("matrix", {})
    unplaced = list(reach.get("unplaced_firewalls") or [])     # MP-03
    group_warnings = list(reach.get("paired_group_warnings") or [])   # MP-04
    label_conflicts = list(reach.get("label_conflicts") or [])         # MP-12
    from app.parsers.nat_paths import NatIndex
    try:
        nat = NatIndex.build(db) or None
    except Exception:      # never let NAT annotation break the enumeration
        log.warning("NAT index failed", exc_info=True)
        nat = None
    host_levels = _host_level_map(db)
    iface_nets = _iface_nets(db)          # MP-06
    # Stored FirewallRule rows (site-scoped by the binding above): policy
    # identity / `set name` / action come from here, never from a cell.
    rules_by_id = {r.id: r for r in db.query(FirewallRule).all()}
    for cell in matrix.values():
        if truncated:
            break
        # P-03: with NAT on the site a cell can read "denied" only because
        # the engine intersected the hops' scopes untranslated (FG-L3 names
        # a downstream VIP, FG-L2 its mapped host); the NAT-aware walk below
        # decides those paths.
        nat_retry = bool(nat) and cell.get("overall") == "denied"
        if cell.get("overall") not in ("permitted", "partial") and not nat_retry:
            continue
        s_lvl, d_lvl = cell.get("src_level"), cell.get("dst_level")
        dirn = _direction(s_lvl, d_lvl)
        if dirn == "same":
            continue  # cross-level matrix never yields these; defensive
        for path in cell.get("paths", []):
            if path.get("path_decision") not in ("permitted", "partial") and not (
                    nat and path.get("path_decision") == "denied"
                    and path.get("hops") and all(_hop_alternatives_permitted(h) for h in path["hops"])):
                continue
            # Config-only: only paths that cross REAL firewall boundaries.
            # The engine's A-25 flat-edge inference fabricates unfirewalled
            # adjacency between levels (over-approximation for the matrix);
            # a path relying on it is not a concrete policy path, so skip it.
            if path.get("inferred_adjacency"):
                continue
            hops = path.get("hops", [])
            if not hops:
                continue
            # Stages = permitting enforcement points in hop order (several
            # devices on one boundary are AND-ed, so each is a stage).  LS-02:
            # a routing switch beside them is an ALTERNATIVE: each variant of
            # the path is enumerated on its own.
            for stages in _stage_sets(hops, rules_by_id):
                if not stages or any(not c for c in stages):
                    continue
                traversed = {s_lvl, d_lvl}
                for hop in hops:
                    traversed.add(hop.get("from_level"))
                    traversed.add(hop.get("to_level"))

                # One row per (permitting policy per stage) x resolved service:
                # a combination survives only if its policies' host scopes AND
                # services intersect (the engine's own piece algebra).
                for combo, piece, nat_events in _walk_stages_nat(stages, nat):
                    if _src_elsewhere(piece[0], s_lvl, host_levels, iface_nets):
                        continue        # P-10 / MP-06: the source lives at another level
                    services = rm.format_services(piece[2], piece[3])
                    ranges, covers_all = _service_ports(services)
                    src_pol, dst_pol = combo[0], combo[-1]
                    flags = _compute_flags(
                        src_level=s_lvl, dst_level=d_lvl, direction=dirn,
                        traversed=traversed, n_hops=len(hops),
                        ranges=ranges, covers_all=covers_all,
                        # G-04: judged on what the whole chain lets through (the
                        # intersection), not on one permissive policy inside it
                        any_policy=_is_any_piece(piece),
                        external_internet=dst_pol.get("external_internet", False),
                        # RS-04: a routing switch's implicit route delivers only
                        # into its own SVI networks (private) - not the Internet
                        dst_public=_spec_may_be_public(piece[1]) and not str(
                            dst_pol.get("policy_id") or "").startswith("implicit:route:"),
                        has_dmz=has_dmz,
                    )
                    # G-04: the scope the CHAIN lets through (intersection of every
                    # policy's source / destination), not the first / last
                    # policy's own text; that text is kept as policy_scope when it
                    # is broader.
                    src_scope, dst_scope = _scope_text(piece[0]), _scope_text(piece[1])
                    row = _row(
                        src={"level": s_lvl, "zone": src_pol.get("src_zone"),
                             "scope": src_scope or src_pol.get("src")},
                        dst={"level": d_lvl, "zone": dst_pol.get("dst_zone"),
                             "scope": dst_scope or dst_pol.get("dst")},
                        service=list(services),
                        protocol=_protocols_of(services),
                        direction=dirn,
                        chain=_marked_chain([_chain_entry(p) for p in combo]),
                        flags=flags,
                        initiation=_initiation(s_lvl, d_lvl, dirn, src_pol.get("src_zone")),
                    )
                    if any(p.get("_selector_narrowed") for p in combo):
                        # owner 2026-10-19: the tunnel's phase 2 selectors bound what can cross it
                        row["flags"].append("tunnel_selector")
                    if any(p.get("_dir_unverified") for p in combo):
                        # D-11: at least one policy's direction rests on no level
                        # evidence; the row may be the reverse of reality.
                        row["flags"].append("direction_unverified")
                        for p in combo:
                            if p.get("_dir_unverified") and p.get("firewall_id") is not None:
                                unverified_fws.add(p["firewall_id"])
                    for side, pol_text in (("src", src_pol.get("src")), ("dst", dst_pol.get("dst"))):
                        if pol_text and row[side]["scope"] != pol_text:
                            row[side]["policy_scope"] = pol_text
                    if nat_events:
                        # P-09: the translations on the way (VIP published by a
                        # policy, a downstream VIP, source NAT)
                        row["nat"] = nat_events
                        if any(e["type"] == "dnat" for e in nat_events):
                            row["flags"].append("nat_published")
                        if any(e["type"] == "snat" for e in nat_events):
                            row["flags"].append("source_nat")
                    row["_piece"] = piece
                    row["_prio"] = tuple(p["_prio"] for p in combo)
                    row["_any"] = [_is_any_piece(piece)]
                    paths.append(row)
                    if len(paths) >= budget:
                        truncated = True
                        break
                if truncated:
                    break
            if truncated:
                break

    # G-04: several policy combinations can let EXACTLY the same traffic
    # through (same effective scopes and services through the same
    # firewalls).  A firewall applies the first matching policy, so for that
    # traffic only the earliest policy of each firewall ever matches: keep
    # that row and list the shadowed combinations on it.
    paths[:] = _first_match_rows(paths)

    # ---- phase 2: composed DMZ conduits (joined through a specific host)
    composition_notes: list = []
    if not truncated:
        hops = [{"id": h.id, "from_ip": h.from_ip, "to_ip": h.to_ip,
                 "service": h.service, "note": h.note}
                for h in db.query(AccessPathHop).order_by(AccessPathHop.id).all()]
        truncated = _compose_conduits(paths, budget, hops, composition_notes) or truncated
    truncated_visible = truncated

    # ---- intra-zone / same-level permits: always computed (hidden unless
    # boundary_only=False) so their tags never look orphaned; last, so
    # they cannot use up the budget of the cross-boundary rows.
    if not truncated:
        truncated = _emit_intrazone(db, paths, budget) or truncated

    # ---- phase 2: traffic overlay + unexplained observed flows ----------
    unmatched = {"flows": [], "all_flows": [], "total": 0, "sessions": 0,
                 "capped": False, "capture_window": {"first": None, "last": None}}
    if overlay:
        unmatched = apply_overlay(db, paths, unmatched_cap=unmatched_cap)

    # ---- MP-07: prefix / dead-end rows ------------------------------------
    # A cross-boundary row whose destination scope lives BEYOND the level it
    # reaches delivers nothing there: a longer row continues it ("prefix")
    # or the next boundary drops it ("dead_end").  Such a row is marked,
    # loses the flags that judge it against the level it does not reach,
    # and is left out of the report by default (the longer row - or the
    # dead_end_permit finding - carries the case).
    from app.parsers.chain_findings import _egress_nets, classify_reach
    try:
        reach = classify_reach(paths, host_levels, iface_nets, _egress_nets(db))
    except Exception:  # never let the classification break the enumeration
        log.warning("reach classification failed", exc_info=True)
        reach = {}
    for row in paths:
        rc = reach.get(id(row), "reaches")
        row["reach"] = rc
        if rc in ("prefix", "dead_end"):
            row["flags_at_reached_level"] = [f for f in row["flags"] if f in _LEVEL_FLAGS]
            row["flags"] = [f for f in row["flags"] if f not in _LEVEL_FLAGS]

    # SF-6: a side naming several interfaces is labelled per interface with its level
    try:
        _annotate_zone_parts(db, paths)
    except Exception:  # cosmetic - never break the enumeration
        log.warning("zone part labelling failed", exc_info=True)
    # roll-up keys: rows differing only in the destination (or source) host
    # share a key, so the review screen and the report print one line each
    try:
        from app.parsers.access_path_groups import annotate as _annotate_groups
        _annotate_groups(paths)
    except Exception:  # cosmetic - never break the enumeration
        log.warning("group key annotation failed", exc_info=True)

    # ---- phase 3: stable tag keys + stored classifications --------------
    index = _assign_tag_keys(paths, unmatched["all_flows"])
    tags = {t.tag_key: t for t in db.query(AccessPathTag).all()}
    for key, item in index.items():
        _merge_tag(item, tags.get(key))
    orphaned = [_tag_dict(t) for k, t in sorted(tags.items()) if k not in index]

    return {"paths": paths, "unmatched": unmatched, "truncated": truncated,
            "truncated_visible": truncated_visible, "orphaned": orphaned,
            "tags": tags, "index": index,
            "unlabelled_firewalls": _unlabelled_firewalls(db, unverified_fws),
            # MP-03: firewalls with rules that built no enforcement point -
            # no row here passes through them, so the list is incomplete
            # wherever they sit
            "unplaced_firewalls": unplaced,
            "paired_group_warnings": group_warnings,
            "label_conflicts": label_conflicts,
            # MP-21: leg pairs that overlap on a network, not a host
            "composition_notes": composition_notes}


def zone_parts(levels_by_iface: dict, fw_id, zone_text) -> Optional[list]:
    """SF-6: [{"name", "level"}] for a policy side naming two or more
    interfaces / zones ("port1,port2"), each with its labelled level (None
    when unlabelled); None for a single name."""
    from app.parsers import fortios_zones as _fz
    toks = _fz.zone_list(zone_text)
    if len(toks) < 2:
        return None
    parts = [{"name": t, "level": levels_by_iface.get((fw_id, t.casefold()))} for t in toks]
    return sorted(parts, key=lambda p: (p["level"] is None, p["level"] if p["level"] is not None else 0, p["name"]))


def _iface_level_map(db) -> dict:
    from app.models import Firewall, FirewallInterface
    from app.parsers.site_scope import current_site
    q = db.query(FirewallInterface.firewall_id, FirewallInterface.name, FirewallInterface.alias,
                 FirewallInterface.purdue_level).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
    sid = current_site(db)
    if sid is not None:
        q = q.filter(Firewall.site_id == sid)
    out = {}
    for fw_id, name, alias, lvl in q:
        for n in (name, alias):
            if n:
                out.setdefault((fw_id, n.casefold()), float(lvl) if lvl is not None else None)
    return out


def _annotate_zone_parts(db, paths: list) -> None:
    levels = None
    for row in paths:
        chain = row.get("chain") or []
        for side, hop in (("src", chain[0] if chain else None), ("dst", chain[-1] if chain else None)):
            d = row.get(side)
            if not isinstance(d, dict) or not d.get("zone") or "," not in str(d["zone"]):
                continue
            if levels is None:
                levels = _iface_level_map(db)
            parts = zone_parts(levels, (hop or {}).get("firewall_id"), d["zone"])
            if parts:
                d["zone_parts"] = parts


def _host_level_map(db) -> dict:
    from app.models import Host
    from app.parsers.remote_access import canon_ip
    out = {}
    for ip, lv in db.query(Host.ip, Host.purdue_level).filter(
            Host.ip.isnot(None), Host.purdue_level.isnot(None)):
        out[canon_ip(ip)] = lv
    return out


def _iface_nets(db) -> list:
    """(parsed network, level) of every labelled firewall interface of the
    bound site - where an address scope really lives (MP-06)."""
    from app.models import FirewallInterface
    out = []
    for cidr, lv in db.query(FirewallInterface.network_cidr, FirewallInterface.purdue_level).filter(
            FirewallInterface.network_cidr.isnot(None), FirewallInterface.purdue_level.isnot(None)):
        try:
            net = rm.parse_address(cidr)
        except Exception:
            continue
        if net == rm.ANY or isinstance(net, rm.Unresolved):
            continue
        out.append((net, lv))
    return out


def _scope_level(spec, host_levels: dict, nets: list):
    """The Purdue level an address scope actually lives at: a single known
    host's level, else the level of the most specific labelled interface
    network that contains the WHOLE scope, else None (MP-06: a network
    scope is placed like a host, so an upstream policy's `10.4.0.0/24`
    source is never reported as an L3 / L3.5 / L2 source)."""
    if spec is None or spec == rm.ANY or isinstance(spec, rm.Unresolved):
        return None
    ip = _single_host(spec)
    if ip is not None and host_levels:
        from app.parsers.remote_access import canon_ip
        hl = host_levels.get(canon_ip(ip))
        if hl is not None:
            return hl
    best = None
    for net, lv in nets or ():
        try:
            if rm.addr_contains(net, spec) is True:
                size = getattr(net, "num_addresses", None)
                if best is None or (size is not None and size < best[0]):
                    best = (size if size is not None else 1 << 128, lv)
        except Exception:
            continue
    return best[1] if best else None


def _src_elsewhere(src, level, host_levels: dict, nets: Optional[list] = None) -> bool:
    """P-10 / MP-06: the chain's source scope lives at a level that is not
    the row's source level - one host with a known level, or a network
    inside a labelled interface network of another level (an any-source
    upstream policy intersected with a downstream policy naming the
    upstream network): not a path that starts at ``level``."""
    if level is None:
        return False
    sl = _scope_level(src, host_levels, nets)
    return sl is not None and sl != level


def _unlabelled_firewalls(db: DBSession, fw_ids: set) -> list[dict]:
    """D-11 notice material: for each firewall whose rules were applied
    without level evidence, the routed interfaces that carry no Purdue level
    (label them with POST /topology/set-interface-side or the console)."""
    if not fw_ids:
        return []
    from app.models import Firewall, FirewallInterface
    out = []
    for fw in db.query(Firewall).filter(Firewall.id.in_(sorted(fw_ids))).order_by(Firewall.id):
        ifaces = (db.query(FirewallInterface)
                  .filter(FirewallInterface.firewall_id == fw.id,
                          FirewallInterface.purdue_level.is_(None))
                  .order_by(FirewallInterface.name).all())
        names = [i.name for i in ifaces
                 if (i.iface_type or "") not in ("loopback", "tunnel") and not getattr(i, "is_mgmt_only", False)]
        out.append({"firewall_id": fw.id, "firewall": fw.name or fw.device_name,
                    "unlabelled_interfaces": names})
    return out


def _first_match_rows(rows: list[dict]) -> list[dict]:
    """Collapse cross-boundary rows with identical effective traffic (G-04).

    Identity: direction, both levels, both effective scopes, services and
    the firewall of each stage.  The kept row is the one whose policies come
    first in rule order (``_prio``, compared stage by stage); the others are
    recorded in ``shadowed_by_first_match`` (their policy labels) - for this
    traffic those policies never match."""
    out: list[dict] = []
    seen: dict = {}
    for r in rows:
        if r.get("direction") not in ("down", "up"):
            out.append(r)
            continue
        ident = (r["direction"], r["src"].get("level"), r["dst"].get("level"),
                 r["src"].get("scope"), r["dst"].get("scope"), tuple(r.get("service") or ()),
                 tuple((c.get("firewall_id"), c.get("firewall_device_id"), c.get("firewall_name"))
                       for c in r.get("chain") or []))
        k = seen.get(ident)
        if k is None:
            seen[ident] = len(out)
            out.append(r)
            continue
        keep = out[k]
        win, lose = (r, keep) if tuple(r.get("_prio") or ()) < tuple(keep.get("_prio") or ()) else (keep, r)
        shadowed = list(keep.get("shadowed_by_first_match") or []) + list(r.get("shadowed_by_first_match") or [])
        shadowed.append(" + ".join(f"{c.get('firewall_name') or '?'} #{c.get('policy_id')}"
                                   + (f" {c['policy_name']}" if c.get("policy_name") else "")
                                   for c in lose.get("chain") or []))
        win["shadowed_by_first_match"] = shadowed
        # a flag either row carries stays visible (e.g. cleartext_protocol on both)
        win["flags"] = list(dict.fromkeys(list(win.get("flags") or [])
                                          + [f for f in lose.get("flags") or [] if f == "direction_unverified"]))
        out[k] = win
    return out


def _scope_text(spec) -> Optional[str]:
    """Display / identity text of an intersected address spec ("any" for
    ANY), None when it cannot be rendered (fall back to the policy text)."""
    try:
        if spec is None or isinstance(spec, rm.Unresolved):
            return None
        return rm.format_addr(spec)
    except Exception:
        return None


def _protocols_of(services) -> list[str]:
    """Transport/protocol tokens carried by the engine's service strings."""
    out: list[str] = []
    for s in services or []:
        s = str(s).strip().lower()
        if not s or s == "any":
            if s == "any":
                out.append("any")
            continue
        proto = s.split("/", 1)[0]
        if proto and proto not in out:
            out.append(proto)
    return out


def _emit_intrazone(db: DBSession, paths: list[dict], budget: int) -> bool:
    """Append intra-zone / same-level permit rows (direction ``"same"``).

    Uses the reachability engine's own level resolver (``_Context``) to decide
    which permit rules have their src and dst on the SAME single Purdue level —
    no permit/deny logic is re-implemented.  Returns True if the budget was hit.
    """
    try:
        ctx = _Context(db)
    except Exception:  # pragma: no cover - never let this pass abort the call
        log.warning("access_paths intra-zone pass: _Context build failed", exc_info=True)
        return False
    seen: set = set()
    for eps in ctx.boundary_map.values():
        for ep in eps:
            for rule in ctx.rules_for(ep):
                if rule.id in seen or not _is_permit(rule):
                    continue
                try:
                    sl = ctx.side_levels(ep, rule, "src")
                    dl = ctx.side_levels(ep, rule, "dst")
                except Exception:
                    log.warning("access_paths: intra-zone level resolution failed for "
                                "rule %s; row skipped", rule.id, exc_info=True)
                    continue
                if sl is _SIDE_UNKNOWN or dl is _SIDE_UNKNOWN:
                    continue
                if not sl or not dl or len(sl) != 1 or sl != dl:
                    continue
                seen.add(rule.id)
                lvl = next(iter(sl))
                covers_all = _is_any_scope(rule.dst_port) or not rule.dst_port
                fw = ep.name
                svc = f"{(rule.protocol or 'any')}/{rule.dst_port or 'any'}"
                flags = ["permit_any"] if (
                    covers_all or _is_any_scope(rule.src) or _is_any_scope(rule.dst)) else []
                paths.append(_row(
                    src={"level": lvl, "zone": rule.src_zone, "scope": rule.src},
                    dst={"level": lvl, "zone": rule.dst_zone, "scope": rule.dst},
                    service=[svc],
                    protocol=[(rule.protocol or "any").strip().lower()],
                    direction="same",
                    chain=[{
                        "rule_id": rule.id,
                        "firewall_id": rule.firewall_id,
                        "firewall_device_id": rule.firewall_device_id,
                        "firewall_name": fw,
                        "vdom": getattr(rule, "vdom", None),
                        "policy_id": rule.policy_id,
                        "policy_name": rule.policy_name,
                        "action": rule.action,
                    }],
                    flags=flags,
                    initiation=_initiation(lvl, lvl, "same", rule.src_zone),
                ))
                piece = _rule_piece(rule)
                paths[-1]["_piece"] = piece
                paths[-1]["_prio"] = ((rule.rule_order is None, rule.rule_order or 0, rule.id or 0),)
                paths[-1]["_any"] = [_is_any_piece(piece)]
                if len(paths) >= budget:
                    return True
    return False


# ---------------------------------------------------------------------------
# Phase 2: composed DMZ conduits
# ---------------------------------------------------------------------------

_DEFAULT_MAX_COMPOSED_ROWS = 2_000


def _max_composed() -> int:
    return env_int("IACS_MAX_COMPOSED_ROWS", _DEFAULT_MAX_COMPOSED_ROWS)


def _specific(spec) -> bool:
    """A concrete, non-wildcard address scope (never any / all / 0.0.0.0/0 /
    an unresolved object)."""
    if spec is None or spec == rm.ANY or isinstance(spec, rm.Unresolved):
        return False
    try:
        return not rm.is_family_wide(spec)
    except Exception:
        return False


def _single_host(spec) -> Optional[str]:
    """The one address ``spec`` covers, or None when it covers zero / many."""
    if not _specific(spec):
        return None
    try:
        iv = rm.addr_intervals(spec)
    except Exception:
        return None
    found = [(v, lo, hi) for v, ranges in iv.items() for lo, hi in ranges]
    if len(found) != 1 or found[0][1] != found[0][2]:
        return None
    v, lo, _ = found[0]
    return str(ipaddress.IPv4Address(lo) if v == 4 else ipaddress.IPv6Address(lo))


def _compose_conduits(paths: list[dict], budget: int, hops=(), notes: Optional[list] = None,
                      max_legs: int = 3) -> bool:
    """Append ``direction: "composed"`` rows: leg 1 delivers to a pivot host,
    leg 2 leaves from the SAME host, the pivot sits strictly between the two
    legs' levels (typically the L3.5 DMZ) and the end-to-end path runs from
    the IT side (>= L3) down to OT (<= L2).

    Only a specific host pivots: leg 1's destination and leg 2's source must
    both be concrete scopes whose intersection is exactly one address, so an
    ``all`` / any scope never combines everything.  Informational: legitimate
    DMZ designs look exactly like this, so it_ot_bypass is never set.

    ``hops`` are the operator-declared segment hops (``access_path_hop``:
    ``{"id", "from_ip", "to_ip", "service", "note"}``).  A hop joins leg 1
    ending on ``from_ip`` (e.g. a remote-access gateway) with leg 2 leaving
    from ``to_ip`` (e.g. a jumpbox) in the same segment, where no firewall
    sees the step between them.  Such rows carry ``hop`` and the
    ``declared_hop`` flag; a pair of legs already joined through one shared
    host never also gets a hop row.
    MP-21: a composed row can itself be leg 1 of a further composition
    (vendor -> gateway -> L3 server -> PLC), up to ``max_legs`` legs; a pair
    of legs that overlap on a NETWORK rather than one host (a /24 pivot on
    both legs) is recorded in ``notes`` (why nothing was composed - declare
    a hop to join them).
    Returns True when the row budget was hit."""
    legs = [r for r in paths if r.get("_piece") is not None
            and r["direction"] in ("down", "up")]
    by_src: dict = {}
    for r in legs:
        by_src.setdefault(r["src"]["level"], []).append(r)
    noted: set = set()
    hop_specs = []
    for h in hops or ():
        try:
            hop_specs.append((h, rm.parse_address(h["from_ip"]), rm.parse_address(h["to_ip"])))
        except Exception:
            continue
    cap = _max_composed()
    made = 0

    def hop_ends(piece_side, idx):
        """Hop indexes whose from_ip (idx 1) / to_ip (idx 2) is the single
        host ``piece_side`` covers.  Depends on one leg only, so it is
        memoised per leg instead of being recomputed per leg pair."""
        out = set()
        for k, spec in enumerate(hop_specs):
            if _single_host(rm.addr_intersect(piece_side, spec[idx])) == spec[0]["from_ip" if idx == 1 else "to_ip"]:
                out.add(k)
        return out

    def build(leg1, leg2, a, piv, b, pivot_ip, hop=None):
        ranges, covers_all = _service_ports(leg2["service"])
        # H-08: a pivot on a DMZ host is the sanctioned conduit; a pivot on
        # any other host (an L3 server reached by RDP from IT) is a session
        # break outside the DMZ
        flags = ["conduit_through_dmz" if is_dmz(piv) else "pivot_outside_dmz"] + (
            [] if hop is None else ["declared_hop"]) + [
            f for f in _compute_flags(
                src_level=a, dst_level=b, direction="composed",
                traversed={a, piv, b}, n_hops=len(leg1["chain"]) + len(leg2["chain"]),
                ranges=ranges, covers_all=covers_all,
                any_policy=any(leg1.get("_any", [])) or any(leg2.get("_any", [])),
                external_internet=False)
            if f != "it_ot_bypass"]
        if "direction_unverified" in leg1["flags"] or "direction_unverified" in leg2["flags"]:
            flags.append("direction_unverified")      # D-11: inherited from a leg
        row = _row(
            src=dict(leg1["src"]), dst=dict(leg2["dst"]),
            service=list(leg2["service"]), protocol=list(leg2["protocol"]),
            direction="composed",
            chain=[dict(c) for c in leg1["chain"]] + [dict(c) for c in leg2["chain"]],
            flags=flags,
            initiation=_initiation(a, b, "down", leg1["src"].get("zone")),
        )
        row["pivot"] = {"ip": pivot_ip, "level": piv}
        row["pivots"] = list(leg1.get("pivots") or []) + [row["pivot"]]
        if hop is not None:
            row["hop"] = {"id": hop.get("id"), "from_ip": hop["from_ip"], "to_ip": hop["to_ip"],
                          "service": hop.get("service"), "note": hop.get("note")}
        prior = leg1.get("legs") or [
            {"src": dict(leg1["src"]), "dst": dict(leg1["dst"]), "service": list(leg1["service"]),
             "policy_ids": [c["policy_id"] for c in leg1["chain"]]}]
        row["legs"] = list(prior) + [
            {"src": dict(leg2["src"]), "dst": dict(leg2["dst"]), "service": list(leg2["service"]),
             "policy_ids": [c["policy_id"] for c in leg2["chain"]]}]
        # base (non-composed) legs, flattened: the overlay reads each one's traffic
        row["_legs"] = tuple(leg1.get("_legs") or (leg1,)) + (leg2,)
        # MP-21: the composed row can be leg 1 of a longer composition
        p1, p2 = leg1["_piece"], leg2["_piece"]
        row["_piece"] = (p1[0], p2[1], p2[2], p2[3])
        row["_any"] = list(leg1.get("_any", [])) + list(leg2.get("_any", []))
        return row

    leg1_hops: dict = {}      # id(leg1) -> hop indexes ending on its dst
    leg2_hops: dict = {}      # id(leg2) -> hop indexes starting at its src

    def _note(leg1, leg2, d1, s2):
        if notes is None or len(notes) >= 20:
            return
        key = (id(leg1), id(leg2))
        if key in noted:
            return
        noted.add(key)
        from app.parsers.access_path_findings import allowed_by
        notes.append({
            "leg1": allowed_by(leg1), "leg2": allowed_by(leg2),
            "leg1_dst": rm.format_addr(d1), "leg2_src": rm.format_addr(s2),
            "pivot_level": leg1["dst"]["level"],
            "reason": "the legs overlap on a network, not on one host: nothing is composed "
                      "(declare a hop between the gateway and the jump host to join them)"})

    def _join(leg1, leg2, a, piv, b):
        """Pivot candidates [(pivot ip, hop or None)] joining the two legs."""
        d1, s2 = leg1["_piece"][1], leg2["_piece"][0]
        if not (_specific(d1) and _specific(s2)):
            return []
        host = _single_host(rm.addr_intersect(d1, s2))
        candidates = []
        if host is not None:
            candidates.append((host, None))
        elif hop_specs:
            k1 = leg1_hops.get(id(leg1))
            if k1 is None:
                k1 = leg1_hops[id(leg1)] = hop_ends(d1, 1)
            if k1:
                k2 = leg2_hops.get(id(leg2))
                if k2 is None:
                    k2 = leg2_hops[id(leg2)] = hop_ends(s2, 2)
                for k in sorted(k1 & k2):
                    h = hop_specs[k][0]
                    candidates.append((h["from_ip"], h))
        if not candidates and rm.addr_overlaps(d1, s2) is True:
            _note(leg1, leg2, d1, s2)
        return candidates

    firsts = list(legs)
    for depth in range(max_legs - 1):
        partial_rows = []          # compositions that end above OT: next pass's leg 1
        for leg1 in firsts:
            piv = leg1["dst"]["level"]
            a = leg1["src"]["level"]
            if not is_it_side(a) or piv is None:
                continue
            for leg2 in by_src.get(piv, ()):
                b = leg2["dst"]["level"]
                if b is None or not (b < piv < a):
                    continue
                ends_in_ot = is_ot(b)
                if not ends_in_ot and depth >= max_legs - 2:
                    continue          # no further pass to finish it
                for pivot_ip, hop in _join(leg1, leg2, a, piv, b):
                    row = build(leg1, leg2, a, piv, b, pivot_ip, hop)
                    if ends_in_ot:
                        paths.append(row)
                        made += 1
                        if len(paths) >= budget:
                            return True
                        if made >= cap:
                            log.info("access_paths: composed conduit cap %d reached", cap)
                            return False
                    else:
                        partial_rows.append(row)
        if not partial_rows:
            break
        firsts = partial_rows
    return False


# ---------------------------------------------------------------------------
# Phase 2: traffic overlay
# ---------------------------------------------------------------------------

_SESSION_BATCH = 10_000
_WIDE_PORT_SPAN = 256      # port sets wider than this are matched by range


def _iso(ts):
    return ts.isoformat() if ts is not None else None


def _later(a, b):
    if a is None:
        return b
    if b is None:
        return a
    try:
        return b if b > a else a
    except TypeError:  # naive vs aware: compare as naive UTC
        return b if b.replace(tzinfo=None) > a.replace(tzinfo=None) else a


def _earlier(a, b):
    if a is None or b is None:
        return None
    try:
        return a if a < b else b
    except TypeError:
        return a if a.replace(tzinfo=None) < b.replace(tzinfo=None) else b


class _RowIndex:
    """Candidate rows indexed by (src_level, dst_level) then server port, each
    candidate list in first-match priority order (the engine's rule order),
    so one flow lookup is a short scan - never sessions x rows."""

    def __init__(self, rows: list[dict]):
        self._exact: dict = {}
        self._wide: dict = {}
        self._cache: dict = {}
        for i, r in enumerate(rows):
            piece = r.get("_piece")
            if piece is None or r["direction"] == "composed":
                continue
            key = (r["src"]["level"], r["dst"]["level"])
            ports = piece[3]
            entry = (r.get("_prio") or (), i, r)
            if ports == rm.ANY or isinstance(ports, rm.Unresolved) or \
                    sum(hi - lo + 1 for lo, hi in ports) > _WIDE_PORT_SPAN:
                self._wide.setdefault(key, []).append(entry)
            else:
                ex = self._exact.setdefault(key, {})
                for lo, hi in ports:
                    for port in range(lo, hi + 1):
                        ex.setdefault(port, []).append(entry)

    def candidates(self, cl, sl, port) -> list:
        k = (cl, sl, port)
        c = self._cache.get(k)
        if c is None:
            c = list(self._wide.get((cl, sl), ()))
            if port is not None:
                c += self._exact.get((cl, sl), {}).get(port, ())
            c.sort(key=lambda e: (e[0], e[1]))
            c = [e[2] for e in c]
            self._cache[k] = c
        return c


def _row_accepts(row, client_ip, server_ip, port, transport) -> bool:
    src, dst, protos, ports = row["_piece"]
    if protos != rm.ANY and not isinstance(protos, rm.Unresolved):
        if (transport or "").lower() not in protos:
            return False
    if ports != rm.ANY and not isinstance(ports, rm.Unresolved):
        if port is None or not rm.port_in(port, ports):
            return False
    if rm.ip_in_addr(client_ip, src) is not True:
        return False
    return rm.ip_in_addr(server_ip, dst) is True


def _rule_hit_stats(db) -> tuple[dict, dict, dict, set, dict]:
    """({rule_id: allowed-event count}, {rule_id: earliest counted event ts},
    {rule_id: last event ts / stored last_matched}, {firewall keys with ANY
    hit evidence}, {rule_id: firewall key}) from FAZ / syslog traffic events,
    attributed to rules exactly as app.parsers.rule_hits does (policy id /
    name per vendor, device scoping, ASA first-match), plus every rule's
    stored ``last_matched``."""
    from app.models import FortiAnalyzerEvent
    from app.parsers import rule_hits as rh

    rule_fw: dict = {}
    hits: dict = {}
    first: dict = {}
    last: dict = {}
    fw_with_hits: set = set()
    for rid, fw_id, fd_id, lm in db.query(FirewallRule.id, FirewallRule.firewall_id,
                                          FirewallRule.firewall_device_id,
                                          FirewallRule.last_matched):
        key = ("fw", fw_id) if fw_id is not None else ("dev", fd_id)
        rule_fw[rid] = key
        if lm is not None:
            last[rid] = lm
            fw_with_hits.add(key)
    q = db.query(FortiAnalyzerEvent).filter(FortiAnalyzerEvent.log_type == "traffic")
    if db.query(q.exists()).scalar():
        idx = rh._RuleIndex(db, {"fortinet", "cisco_asa", "pfsense", "panos"})
        stats = {"first_match_evaluations": 0}
        for ev in q.yield_per(2_000):
            action = (ev.action or "").lower()
            if action in rh.ALLOW_ACTIONS:
                allowed = True
            elif action in rh.DENY_ACTIONS:
                allowed = False
            else:
                continue
            fam = rh._event_family(ev)
            if fam is None:
                continue
            rows = rh._candidates(idx, ev, fam, stats)
            if not rows:
                continue
            rows = [r for r in rows if rh._rule_is_permit(r) == allowed]
            if fam != "cisco_asa" and len(rows) > 1:
                rows = [r for r in rows if rh.tuple_match(r, ev) is True] or rows
            ts = ev.event_time or ev.received_at
            for r in rows:
                fw_with_hits.add(rule_fw.get(r.id, ("fw", r.firewall_id)))
                if allowed:
                    hits[r.id] = hits.get(r.id, 0) + 1
                    last[r.id] = _later(last.get(r.id), ts)
                    first[r.id] = ts if first.get(r.id) is None else _earlier(first[r.id], ts)
    return hits, first, last, fw_with_hits, rule_fw


def apply_overlay(db, paths: list[dict], *, unmatched_cap: int = 500) -> dict:
    """Fill every row's ``traffic`` and collect unexplained crossing flows.

    Sessions are read in batches (column tuples, ``yield_per``), oriented
    with traffic_findings.canonical_flow (client -> server, server port), and
    placed by the client / server host levels.  Each distinct flow is
    attributed to exactly ONE row: the first candidate, in the engine's
    first-match order, whose scopes / service accept it - overlapping
    policies never double-count.  Must run inside the site scope.

    A capture is a sample, so a path with no matching session is
    ``not_seen`` (in the capture window), never "unused"; "unused rule" is
    reserved for the time-based ``unused_policy`` finding.

    Returns {"flows": [first ``unmatched_cap`` unexplained flows],
    "all_flows": [every unexplained flow], "total", "sessions", "capped",
    "capture_window": {"first", "last"}}.
    """
    from app.models import Host, NetworkSession
    from app.parsers.alert_engine import _is_public_ip
    from app.parsers.traffic_findings import canonical_flow

    from app.parsers.l3_switch import external_level_fn
    _ext = external_level_fn(db)          # RS-04: public, unclassified -> L5
    hosts = {hid: (ip, _ext(ip, lv)) for hid, ip, lv in
             db.query(Host.id, Host.ip, Host.purdue_level)}
    # MP-01: labelled interface networks per firewall - a flow is credited
    # to a row through a firewall that holds one of its endpoints before a
    # row through a firewall that provably holds neither (parallel boxes on
    # one boundary each yield a row).
    fw_nets: dict = {}
    for fid, cidr in db.query(FirewallInterface.firewall_id, FirewallInterface.network_cidr).filter(
            FirewallInterface.purdue_level.isnot(None), FirewallInterface.network_cidr.isnot(None)):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen and not (net.version == 4 and net.prefixlen == 32):
            fw_nets.setdefault(fid, []).append(net)

    def _placed(row, client_ip, server_ip):
        """How many of the flow's endpoints the row's firewalls hold (0..2);
        None when none of them has a labelled network."""
        best = None
        for c in row["chain"]:
            nets = fw_nets.get(c.get("firewall_id"))
            if not nets:
                continue
            n = 0
            for ip in (client_ip, server_ip):
                try:
                    a = ipaddress.ip_address(ip)
                except (TypeError, ValueError):
                    continue
                if any(x.version == a.version and a in x for x in nets):
                    n += 1
            best = n if best is None else max(best, n)
        return best
    index = _RowIndex(paths)
    flow_row: dict = {}                  # flow key -> row position | -1 | -2
    row_sessions: dict = {}
    row_last: dict = {}
    unmatched: dict = {}                 # flow key -> [sessions, last_seen]
    pos = {id(r): i for i, r in enumerate(paths)}
    any_sessions = False
    win_first = win_last = None

    # LS-03: the router MAC on a session's frames names the device that
    # carried it; only rows through that device are credited.
    try:
        from app.parsers.l3_switch import router_macs as _router_macs
        rmacs = _router_macs(db)
    except Exception:      # never let carrier lookup break the overlay
        log.warning("router MAC lookup failed", exc_info=True)
        rmacs = {}
    q = db.query(NetworkSession.src_host_id, NetworkSession.dst_host_id,
                 NetworkSession.src_port, NetworkSession.dst_port,
                 NetworkSession.transport, NetworkSession.first_seen,
                 NetworkSession.last_seen, NetworkSession.carrier_mac)
    for sh, dh, sp, dp, transport, first, seen, cmac in q.yield_per(_SESSION_BATCH):
        any_sessions = True
        f0 = first or seen
        if f0 is not None:
            win_first = f0 if win_first is None else _earlier(win_first, f0)
        win_last = _later(win_last, seen or first)
        client, server, port = canonical_flow(sh, sp, dh, dp)
        cfw = rmacs.get(cmac) if cmac and rmacs else None
        key = (client, server, port, transport, cfw)
        target = flow_row.get(key)
        if target is None:
            c, s = hosts.get(client), hosts.get(server)
            target = -2                  # not placeable (unknown host / level)
            if c and s and c[1] is not None and s[1] is not None and c[0] and s[0]:
                target = -1
                cands = list(index.candidates(c[1], s[1], port))
                if cfw is not None:
                    # only rows through the device that carried the frames;
                    # none -> the flow is unexplained (not credited elsewhere)
                    cands = [r for r in cands if any(x.get("firewall_id") == cfw for x in r["chain"])]
                accepting = [row for row in cands if _row_accepts(row, c[0], s[0], port, transport)]
                if len(accepting) > 1:
                    placed = [(row, _placed(row, c[0], s[0])) for row in accepting]
                    known = [v for _r, v in placed if v is not None]
                    if known and max(known) > 0 and min(known) < max(known):
                        accepting = [row for row, v in placed if v is None or v == max(known)]
                if accepting:
                    target = pos[id(accepting[0])]
                if target == -1 and c[1] == s[1]:
                    target = -2          # intra-level: not a boundary crossing
            flow_row[key] = target
        if target >= 0:
            row_sessions[target] = row_sessions.get(target, 0) + 1
            row_last[target] = _later(row_last.get(target), seen)
        elif target == -1:
            u = unmatched.setdefault(key[:4], [0, None])
            u[0] += 1
            u[1] = _later(u[1], seen)

    window = {"first": _iso(win_first), "last": _iso(win_last)}
    hits, hit_first, last_hit, fw_with_hits, rule_fw = _rule_hit_stats(db)

    def _traffic(i, row):
        rids = [c.get("rule_id") for c in row["chain"] if c.get("rule_id") is not None]
        hop_hits = [hits.get(r, 0) for r in rids]
        rule_hits = min(hop_hits) if hop_hits else 0
        lm = since = None
        if rids and all(last_hit.get(r) is not None for r in rids):
            lm = last_hit[rids[0]]
            for r in rids[1:]:
                lm = _earlier(lm, last_hit[r])
        if rule_hits and all(hit_first.get(r) is not None for r in rids):
            # every hop has counted hits since the LATEST of their first hits
            since = hit_first[rids[0]]
            for r in rids[1:]:
                since = _later(since, hit_first[r])
        sessions = row_sessions.get(i, 0)
        has_data = any_sessions or any(rule_fw.get(r) in fw_with_hits for r in rids)
        status = ("seen" if sessions > 0 or rule_hits > 0
                  else "not_seen" if has_data else "no_capture")
        out = {"status": status, "sessions": sessions, "last_seen": _iso(row_last.get(i)),
               "rule_hits": rule_hits, "rule_hits_since": _iso(since),
               "last_matched": _iso(lm)}
        if status == "not_seen":
            out["capture_window"] = dict(window)
        return out

    for i, row in enumerate(paths):
        if row["direction"] != "composed":
            row["traffic"] = _traffic(i, row)
    for row in paths:
        if row["direction"] == "composed":
            legs = [leg["traffic"] for leg in row["_legs"]]
            st = [leg["status"] for leg in legs]
            if all(x == "seen" for x in st):
                status = "seen"
            elif "seen" in st:
                status = "partial"
            elif all(x == "no_capture" for x in st):
                status = "no_capture"
            else:
                status = "not_seen"
            row["traffic"] = {
                "status": status,
                "sessions": min(leg["sessions"] for leg in legs) if status == "seen" else 0,
                "last_seen": None, "rule_hits": None, "rule_hits_since": None,
                "last_matched": None, "by_leg": legs,
            }
            if status in ("not_seen", "partial"):
                row["traffic"]["capture_window"] = dict(window)

    flows = []
    for (client, server, port, transport), (n, seen) in unmatched.items():
        (cip, cl), (sip, sl) = hosts[client], hosts[server]
        dirn = _direction(cl, sl)
        flows.append({
            "client": {"ip": cip, "level": cl},
            "server": {"ip": sip, "level": sl, "port": port},
            "transport": transport,
            "direction": dirn,
            "sessions": n,
            "last_seen": _iso(seen),
            "flags": _compute_flags(
                src_level=cl, dst_level=sl, direction=dirn, traversed={cl, sl},
                n_hops=1, ranges=[(port, port)] if port is not None else [],
                covers_all=False, any_policy=False,
                external_internet=_is_public_ip(sip)),
        })
    flows.sort(key=lambda f: (-f["sessions"], f["client"]["ip"], f["server"]["ip"],
                              f["server"]["port"] or 0))
    return {"flows": flows[:unmatched_cap], "all_flows": flows, "total": len(flows),
            "sessions": sum(f["sessions"] for f in flows),
            "capped": len(flows) > unmatched_cap, "capture_window": window}


# ---------------------------------------------------------------------------
# Phase 3: classification tags (access_path_tag)
# ---------------------------------------------------------------------------
#
# tag_key is a row's identity across config re-ingest: firewall NAME, VDOM,
# policy id and a hash of what the row permits - never a DB row id - so a
# re-uploaded config, or a firewall deleted and added again under the same
# name, keeps its classifications.
#
#   path / same  p:{firewall}:{vdom|-}:{policy_id}:{sha1(src|dst|service|direction)[:16]}
#                src / dst = "L{level}/{zone}/{scope}"; a multi-firewall chain
#                is keyed on its FIRST hop and the later hops' policy keys are
#                appended to the hashed text (so two chains sharing a first
#                hop never collide).
#   composed     c:{sha1(leg 1 policy keys|leg 2 policy keys|pivot ip|services)[:16]}
#   unexplained  u:{sha1(client ip|server ip|proto|port)[:16]}

import hashlib  # noqa: E402

from app.models import ACCESS_PATH_TAG_KINDS  # noqa: E402,F401  (re-exported)

NOTE_MAX = 2000
CLASSIFIED_BY_MAX = 128
CLASSIFY_MAX_ITEMS = 500
_SUPPRESSING = ("reviewed_ok", "exception")


def _h16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def _policy_key(hop: dict) -> str:
    return f"{hop.get('firewall_name') or ''}:{hop.get('vdom') or '-'}:{hop.get('policy_id') or ''}"


def _side(d: dict) -> str:
    return f"L{d.get('level')}/{d.get('zone') or ''}/{d.get('scope') or ''}"


def tag_key_for_path(row: dict) -> str:
    """tag_key of a single-chain (or intra-zone) row."""
    chain = row["chain"]
    text = "|".join([_side(row["src"]), _side(row["dst"]), ",".join(row["service"]),
                     row["direction"]])
    if len(chain) > 1:
        text += "|" + "|".join(_policy_key(h) for h in chain[1:])
    first = chain[0]
    return (f"p:{first.get('firewall_name') or ''}:{first.get('vdom') or '-'}:"
            f"{first.get('policy_id') or ''}:{_h16(text)}")


def tag_key_for_composed(row: dict) -> str:
    """tag_key of a composed conduit row (needs its internal ``_legs``)."""
    legs = list(row["_legs"])
    # two legs: the historical identity (keys of existing classifications
    # survive); more legs (MP-21): every leg's policies and every pivot
    text = "|".join([";".join(_policy_key(h) for h in leg["chain"]) for leg in legs]
                    + ([row["pivot"]["ip"]] if len(legs) == 2 else
                       [",".join(p["ip"] for p in row.get("pivots") or [row["pivot"]])])
                    + [",".join(row["service"])]
                    + ([f"hop:{row['hop']['to_ip']}"] if row.get("hop") else []))
    return f"c:{_h16(text)}"


def tag_key_for_flow(flow: dict) -> str:
    """tag_key of an unexplained observed flow."""
    port = flow["server"].get("port")
    text = "|".join([str(flow["client"]["ip"]), str(flow["server"]["ip"]),
                     str(flow.get("transport") or ""), "" if port is None else str(port)])
    return f"u:{_h16(text)}"


def _assign_tag_keys(paths: list[dict], flows: list[dict]) -> dict:
    """Set ``tag_key`` (and the internal ``_kind``) on every row and flow;
    returns {tag_key: row or flow}.  A key that would repeat (two rows with
    identical identity text - not expected) gets a ``~n`` suffix in
    enumeration order so every row stays addressable."""
    index: dict = {}

    def put(item, key, kind):
        if key in index:
            n = 2
            while f"{key}~{n}" in index:
                n += 1
            key = f"{key}~{n}"
        item["tag_key"] = key
        item["_kind"] = kind
        index[key] = item

    for row in paths:
        if row["direction"] == "composed":
            put(row, tag_key_for_composed(row), "composed")
        else:
            put(row, tag_key_for_path(row), "path")
    for flow in flows:
        put(flow, tag_key_for_flow(flow), "unexplained")
    return index


#: MP-07: flags that judge a row against the level it reaches - meaningless
#: on a prefix / dead-end row (its traffic does not stop at that level).
_LEVEL_FLAGS = frozenset({"it_ot_bypass", "dmz_bypass", "ot_upward_skip", "internet_egress",
                          "ot_egress_external", "industrial_proto_out_of_zone",
                          "pivot_outside_dmz", "conduit_through_dmz"})


def report_include_default(flags, classification: str, reach: str = "reaches") -> bool:
    """Default report inclusion: the row carries at least one flag, the
    operator has not cleared it (reviewed_ok / exception), and (MP-07) it
    really delivers to its destination level (not a prefix / dead end)."""
    return bool(flags) and classification not in _SUPPRESSING and reach not in ("prefix", "dead_end")


def _merge_tag(item: dict, tag) -> None:
    cls = tag.classification if tag is not None else "unclassified"
    default = report_include_default(item.get("flags"), cls, item.get("reach", "reaches"))
    stored = tag.report_include if tag is not None else None
    item["classification"] = cls
    item["note"] = tag.note if tag is not None else None
    item["classified_by"] = tag.classified_by if tag is not None else None
    item["classified_at"] = _iso(tag.classified_at) if tag is not None else None
    item["report_include_default"] = default
    item["report_include"] = default if stored is None else bool(stored)


def _tag_dict(tag) -> dict:
    """A stored tag as returned in ``orphaned_tags``."""
    return {"tag_key": tag.tag_key, "kind": tag.kind,
            "firewall_device_id": tag.firewall_device_id, "vdom": tag.vdom,
            "policy_id": tag.policy_id, "classification": tag.classification,
            "report_include": tag.report_include, "note": tag.note,
            "classified_by": tag.classified_by, "classified_at": _iso(tag.classified_at),
            "updated_at": _iso(tag.updated_at)}


class ClassifyError(ValueError):
    """Invalid POST /access-paths/classify request (HTTP 422); nothing is stored."""


_UNSET = object()


def _validate_items(items) -> list[dict]:
    if not isinstance(items, list) or not items:
        raise ClassifyError("items must be a non-empty list")
    if len(items) > CLASSIFY_MAX_ITEMS:
        raise ClassifyError(f"at most {CLASSIFY_MAX_ITEMS} items per request; got {len(items)}")
    out, seen = [], set()
    for n, it in enumerate(items):
        if not isinstance(it, dict):
            raise ClassifyError(f"items[{n}] must be an object")
        unknown = set(it) - {"tag_key", "classification", "report_include", "note",
                             "classified_by"}
        if unknown:
            raise ClassifyError(f"items[{n}]: unknown field(s) {sorted(unknown)}")
        key = it.get("tag_key")
        if not isinstance(key, str) or not key:
            raise ClassifyError(f"items[{n}].tag_key is required")
        if key in seen:
            raise ClassifyError(f"items[{n}].tag_key {key!r} is listed twice")
        seen.add(key)
        cls = it.get("classification", _UNSET)
        if cls is not _UNSET and cls not in ACCESS_PATH_CLASSIFICATIONS:
            raise ClassifyError(f"items[{n}].classification must be one of "
                                f"{', '.join(ACCESS_PATH_CLASSIFICATIONS)}; got {cls!r}")
        ri = it.get("report_include", _UNSET)
        if ri is not _UNSET and ri is not None and not isinstance(ri, bool):
            raise ClassifyError(f"items[{n}].report_include must be true, false or null")
        note = it.get("note", _UNSET)
        if note is not _UNSET and note is not None:
            if not isinstance(note, str) or len(note) > NOTE_MAX:
                raise ClassifyError(f"items[{n}].note must be a string of at most "
                                    f"{NOTE_MAX} characters")
        by = it.get("classified_by", _UNSET)
        if by is not _UNSET and by is not None:
            if not isinstance(by, str) or len(by) > CLASSIFIED_BY_MAX:
                raise ClassifyError(f"items[{n}].classified_by must be a string of at most "
                                    f"{CLASSIFIED_BY_MAX} characters")
        out.append({"tag_key": key, "classification": cls, "report_include": ri,
                    "note": note, "classified_by": by})
    return out


def _descriptive(item: dict) -> dict:
    """firewall_device_id / vdom / policy_id copied onto a tag (descriptive)."""
    chain = item.get("chain") or []
    if not chain:
        return {"firewall_device_id": None, "vdom": None, "policy_id": None}
    h = chain[0]
    return {"firewall_device_id": h.get("firewall_device_id"), "vdom": h.get("vdom"),
            "policy_id": h.get("policy_id")}


def classify_access_paths(db: DBSession, site_id: int, items) -> dict:
    """Validate and upsert classification ``items`` for one site; flushes
    but does NOT commit (the caller commits, then calls
    access_path_findings.sync_findings_for_tags).

    Every tag_key must belong to the site's CURRENT enumeration (paths,
    composed rows, intra-zone rows, unexplained flows); otherwise
    ClassifyError and nothing is written.  ``report_include: null`` resets
    to the row's default; an omitted field is left unchanged.

    Returns {"items": [the updated rows / flows, in request order, in the
    GET shape], "tag_keys": [...], "report_counts": report_line_counts()
    after the update}.
    """
    clean = _validate_items(items)
    with analysis_site(db, site_id):
        res = _enumerate(db, overlay=True, unmatched_cap=0)
        index, tags = res["index"], res["tags"]
        unknown = [it["tag_key"] for it in clean if it["tag_key"] not in index]
        if unknown:
            raise ClassifyError(
                "unknown tag_key(s) for this site (not in its current access-path "
                f"enumeration): {', '.join(unknown[:20])}"
                + (f" (+{len(unknown) - 20} more)" if len(unknown) > 20 else ""))
        now = utcnow_for_tags()
        for it in clean:
            key = it["tag_key"]
            item = index[key]
            tag = tags.get(key)
            if tag is None:
                tag = AccessPathTag(site_id=site_id, tag_key=key, kind=item["_kind"],
                                    classification="unclassified")
                db.add(tag)
                tags[key] = tag
            for f, v in _descriptive(item).items():
                setattr(tag, f, v)
            if it["classification"] is not _UNSET:
                tag.classification = it["classification"]
                tag.classified_at = now
            if it["report_include"] is not _UNSET:
                tag.report_include = it["report_include"]
            if it["note"] is not _UNSET:
                tag.note = it["note"] or None
            if it["classified_by"] is not _UNSET:
                tag.classified_by = it["classified_by"] or None
            tag.updated_at = now
            _merge_tag(item, tag)
        db.flush()
        report_counts = report_line_counts(res)
    return {"items": [_public(index[it["tag_key"]]) for it in clean],
            "tag_keys": [it["tag_key"] for it in clean],
            "report_counts": report_counts}


def utcnow_for_tags():
    """Timestamp source for tag writes (separate so tests can pin it)."""
    from app.models import utcnow
    return utcnow()
