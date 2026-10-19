"""
Cross-Firewall Findings — ISA/IEC 62443 policy-gap analysis across confirmed
topology links.

When two or more firewall configs have been ingested and at least one
``connects_to_interface_id`` link has been confirmed by the operator, this
module compares the rule sets of the connected firewalls and generates
``Finding`` records for policy gaps, missing deny-all boundaries, and
asymmetric rules that leave the inter-FW conduit under-protected.

Check catalogue
---------------
Each check has a stable ``check_name`` so re-runs are idempotent (existing
open findings with the same ``source_ref`` are skipped rather than
duplicated).

  cross_fw_missing_deny_all
      One side of a confirmed link has no explicit ``action=deny`` rule for
      traffic crossing the interface.  ISA 62443 SR 5.1 — boundary protection.

  cross_fw_asymmetric_permit
      A permit rule exists on firewall A for traffic src→dst across the link,
      but no equivalent permit exists on firewall B for return traffic.  This
      makes the link permeable in one direction only — a sign of misconfigured
      or copy-paste policy.  ISA 62443 SR 5.2 — use control.

  cross_fw_any_any_permit
      A rule with src="any" AND dst="any" AND action="permit" exists on an
      interface that faces another firewall (outside-facing interface in a
      multi-FW topology). This effectively disables the boundary.
      ISA 62443 SR 5.1 RE1 — explicit deny.

  cross_fw_no_rules
      A firewall that appears in a confirmed topology link has zero
      ``FirewallRule`` rows at all.  The config was parsed but no policy was
      found — the firewall may be in pass-through mode or the parser missed
      the policy block.  ISA 62443 SR 5.1 — boundary protection.

  cross_fw_same_permit_both_sides
      The same source/destination/port/protocol combination is explicitly
      permitted on BOTH firewalls for the same conduit.  This is expected for
      a permitted flow, so this check emits only an INFO finding to remind
      operators to confirm the rule is intentional on both ends.

Auto-resolve (B-24)
-------------------
``run_cross_fw_checks`` re-derives the complete finding set of every
confirmed link on each run, so after the run every OPEN cross_fw_* finding
whose ``source_ref`` was not re-produced is closed ("Auto-resolved: ..."),
like alert_engine's periodic reviews (F-04): acknowledged findings are never
touched, and a rule the run could NOT evaluate (asymmetric / any-any check:
an address / service object that does not resolve) keeps its finding open.
Findings of a link that is no longer confirmed close too (the condition is
defined on confirmed links only).  IACS_AUTO_RESOLVE=false disables it.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models import (
    Finding,
    Firewall,
    FirewallInterface,
    FirewallRule,
)
from app.parsers import fortios_zones as fz
from app.parsers import rule_match as rm
from app.parsers.site_scope import current_site, scope_module

log = logging.getLogger(__name__)

# ISA/IEC 62443 references
_SR_BOUNDARY   = "SR 5.1"
_SR_BOUNDARY_E = "SR 5.1 RE1"
_SR_USE_CTL    = "SR 5.2"

# Normalised "any" values from FortiGate parser
_ANY_VALUES = {"any", "all", "0.0.0.0/0", ""}


def _is_any(val: Optional[str]) -> bool:
    if not val or val.strip().lower() in _ANY_VALUES:
        return True
    # "all", 0.0.0.0/0, ::/0 - a whole address family counts as "any" for the
    # any-any permit check (F-07: the spec itself stays family-specific).
    return rm.is_family_wide(rm.parse_address(val))


def _is_permit(rule: FirewallRule) -> bool:
    return (rule.action or "").strip().lower() in {"permit", "allow", "accept", "pass"}


def _is_deny(rule: FirewallRule) -> bool:
    return (rule.action or "").strip().lower() in {"deny", "drop", "reject", "block"}


def _service_is_any(rule: FirewallRule) -> bool:
    """Protocol any AND destination port any (T3-39: a udp/53 rule is not
    an any-any rule)."""
    return (rm.parse_protocols(rule.protocol) == rm.ANY
            and rm.parse_ports(rule.dst_port) == rm.ANY)


_ZONE_ANY_TOKENS = fz.ANY_ZONE_TOKENS


def _zone_tokens(zone: Optional[str]):
    """Zone field -> set of lower-cased names, or None for any/unset."""
    toks = fz.zone_tokens(zone)
    return None if toks is None else set(toks)


def _side(rule: FirewallRule, attr: str, zone_defs) -> tuple:
    """B-07: (interface names | None = any, resolved) of a rule side, FortiOS
    zone names expanded to member interfaces (shared helper).  resolved
    False = it names a zone of unknown membership."""
    if zone_defs is None:
        return _zone_tokens(getattr(rule, attr)), True
    return zone_defs.expand_rule(rule, attr)


class _GroupIface:
    """MP-04: stand-in for the (unconfirmed) transit interface of a paired
    group member - every rule that can touch ANY of the member's interfaces
    is compared.  Quacks like a FirewallInterface for the per-link checks."""

    def __init__(self, fw: Firewall, ifaces: list):
        self.id = None
        self.firewall_id = fw.id
        self.name = f"{fw.name} (paired group, link not confirmed)"
        self.zone_label = self.alias = self.side = None
        self.network_cidr = self.ip_cidr = None
        self.purdue_level = None
        self._ids: set[str] = set()
        for i in ifaces:
            self._ids |= _iface_identifiers(i)


def _iface_identifiers(iface) -> set[str]:
    """Every label a rule may use for this interface: name, zone_label,
    alias, side (T3-39: a deny naming "port2" must match even when the
    interface also has a zone_label)."""
    if isinstance(iface, _GroupIface):
        return set(iface._ids)
    out = set()
    for v in (iface.name, iface.zone_label, iface.alias, iface.side):
        if v and v.strip():
            out.add(v.strip().lower())
    return out


def _rule_touches_iface(rule: FirewallRule, ids: set[str], zone_defs=None) -> bool:
    """True if the rule can apply to traffic crossing the interface: its src
    zone or its dst zone names the interface (directly or as a member of a
    FortiOS zone, B-07) or is unset/"any".  A zone of unknown membership may
    contain the interface (conservative: it touches)."""
    sz, s_ok = _side(rule, "src_zone", zone_defs)
    dz, d_ok = _side(rule, "dst_zone", zone_defs)
    ingress = sz is None or bool(sz & ids) or not s_ok   # arriving on the link
    egress = dz is None or bool(dz & ids) or not d_ok    # leaving via the link
    return ingress or egress


def _zone_defs_for(db: DBSession, zone_defs, *fws) -> "fz.ZoneDefIndex":
    if zone_defs is not None:
        return zone_defs
    return fz.ZoneDefIndex(db, [f.id for f in fws if f is not None])


# Vendors whose policy ends in an implicit deny-all (T3-39): FortiOS,
# PAN-OS (interzone-default deny), Cisco IOS/ASA/FTD ACLs, pfSense.
_IMPLICIT_DENY_MARKERS = ("forti", "cisco", "asa", "ftd", "ios", "pan", "palo", "pfsense")


def _has_implicit_deny(fw: Firewall, rules: list[FirewallRule]) -> bool:
    # fw.vendor is authoritative; rule device_type only when vendor is unset
    candidates = [fw.vendor] if (fw.vendor or "").strip() else [r.device_type for r in rules[:5]]
    for v in candidates:
        v = (v or "").strip().lower()
        if v and any(m in v for m in _IMPLICIT_DENY_MARKERS):
            return True
    return False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _source_ref(check: str, fw_a_id: int, fw_b_id: int, extra: str = "",
                directional: bool = False) -> str:
    """Stable, unique reference for deduplication.

    Both firewall ids are always part of it: "<a>><b>" (ordered as given)
    for a finding about one side of the pair - a rule / interface of
    ``fw_a_id`` relative to its peer ``fw_b_id`` - and "<min>-<max>"
    (canonical) only for a finding that is symmetric in the pair.  Rule
    findings add ``_rule_ref`` (VDOM + policy id) in ``extra``: FW-A and
    FW-B both having a policy 1 must not merge into one finding."""
    pair = (f"{fw_a_id}>{fw_b_id}" if directional
            else f"{min(fw_a_id, fw_b_id)}-{max(fw_a_id, fw_b_id)}")
    ref = f"{check}:{pair}" + (f":{extra}" if extra else "")
    if len(ref) > _SOURCE_REF_MAX:
        # Finding.source_ref is String(255) (PostgreSQL enforces it): a long
        # raw-line rule identifier is replaced by its digest
        digest = hashlib.sha1(extra.encode("utf-8", "replace")).hexdigest()
        ref = f"{check}:{pair}:sha1={digest}"
    return ref


_SOURCE_REF_MAX = 255


def _rule_ref(rule: FirewallRule) -> str:
    """VDOM + rule identifier of a rule for a source_ref.  The policy id
    (else the raw line, else the row id) - not the row id first, which
    changes on every config re-upload (rules are replaced) and would
    close and re-open the finding, losing its acknowledgement."""
    vdom = getattr(rule, "vdom", None)
    rid = rule.policy_id or rule.raw_line or str(rule.id)
    return f"vd={vdom if vdom is not None else '-'}:rule={rid}"


# B-24: Session.info key holding, while run_cross_fw_checks runs, the
# source_refs produced (new, reopened or already open) or deliberately kept
# (rule not evaluable) this run - everything else open is auto-resolved.
_SEEN_KEY = "cross_fw.seen_refs"
CROSS_FW_CHECKS = ("cross_fw_no_rules", "cross_fw_missing_deny_all",
                   "cross_fw_any_any_permit", "cross_fw_asymmetric_permit")


def _mark_seen(db: DBSession, ref: Optional[str]) -> None:
    seen = db.info.get(_SEEN_KEY)
    if seen is not None and ref:
        seen.add(ref)


def _upsert_finding(db: DBSession, **kwargs) -> Optional[Finding]:
    """
    Insert or reopen a Finding for the given ``source_ref``.

    Behaviour:
    - No existing row with this source_ref → insert a new open finding.
    - Existing open/acknowledged row → skip (return None; caller counts as skipped).
    - Existing closed/resolved row → reopen it (update status to 'open', refresh
      timestamps and text fields).  This avoids hitting the unique constraint on
      source_ref that would cause an IntegrityError if we naively inserted a
      duplicate.
    """
    ref = kwargs.get("source_ref")
    _mark_seen(db, ref)
    if ref:
        rows = (db.query(Finding).filter(Finding.source_ref == ref)
                .order_by(Finding.id.desc()).all())
        if any(r.status != "closed" for r in rows):
            # Already open or acknowledged — deduplicate, count as skipped
            return None
        if rows:
            # Reopen the most recent closed finding rather than creating a
            # duplicate.  B-16: a re-opened finding is nobody's yet - stale
            # acknowledgement and closed_at are cleared.
            existing = rows[0]
            existing.status = "open"
            existing.updated_at = _utcnow()
            existing.acknowledged_by = None
            existing.acknowledged_at = None
            existing.closed_at = None
            for field in ("severity", "title", "detail", "category",
                          "isa62443_sr", "device_name"):
                if field in kwargs:
                    setattr(existing, field, kwargs[field])
            return existing  # return the reopened finding so _record() counts it

    kwargs.setdefault("site_id", current_site(db))
    finding = Finding(created_at=_utcnow(), updated_at=_utcnow(), **kwargs)
    db.add(finding)
    # Production sessions run with autoflush off: without this flush a second
    # row of the same policy (same source_ref - one policy expands to several
    # src/dst rows) is not seen by the lookup above and the commit fails on
    # the (site_id, source_ref) unique constraint.
    db.flush()
    return finding


# ─────────────────────────────────────── per-link checks ──────────────────────

def _check_no_rules(
    db: DBSession,
    fw: Firewall,
    peer_fw: Firewall,
    iface: FirewallInterface,
) -> list[Finding]:
    """Emit a finding if ``fw`` has no ENABLED FirewallRule rows (a config
    whose only rules are disabled enforces nothing either)."""
    rule_count = (
        db.query(FirewallRule)
        .filter(FirewallRule.firewall_id == fw.id, FirewallRule.enabled.is_(True))
        .count()
    )
    if rule_count > 0:
        return []

    f = _upsert_finding(
        db,
        category="config_review",
        check_name="cross_fw_no_rules",
        severity="high",
        isa62443_sr=_SR_BOUNDARY,
        title=f"No firewall rules found on '{fw.name}' (linked to '{peer_fw.name}')",
        detail={
            "firewall_id":   fw.id,
            "firewall_name": fw.name,
            "peer_fw_id":    peer_fw.id,
            "peer_fw_name":  peer_fw.name,
            "interface":     iface.name,
            "note": (
                "The config was ingested but zero policy rules were parsed. "
                "The firewall may be in pass-through mode, or the policy "
                "block was missing from the uploaded config file."
            ),
        },
        device_name=fw.name,
        # Per-firewall key (not per-pair): if FW-A is linked to B, C, D the root
        # cause is the same — FW-A has no rules. A pair-based key would create
        # three separate findings for the same gap.
        source_ref=f"cross_fw_no_rules:{fw.id}",
    )
    # None = skipped (duplicate); sentinel preserved so _record() counts correctly
    return [f]


def _check_missing_deny_all(
    db: DBSession,
    fw: Firewall,
    peer_fw: Firewall,
    iface: FirewallInterface,
    rules: list[FirewallRule],
    zone_defs=None,
) -> list[Finding]:
    """
    Emit a finding if there is no explicit deny rule on this interface's
    zone pair in ``fw``'s rule set.  FortiGate has an implicit deny-all at
    the bottom of every policy list, so this check is informational for FG
    but HIGH for other vendors that don't have that default.
    """
    iface_zone = iface.zone_label or iface.name
    # T3-39: a deny may name the interface by name, zone_label, alias or side
    # (and zone fields may be lists "port1,port2").  A NULL zone is NOT a
    # match here (an unzoned ACL rule is not evidence of a boundary deny);
    # only an explicit "any" is a catch-all.
    iface_ids = _iface_identifiers(iface)
    zone_defs = _zone_defs_for(db, zone_defs, fw)

    def _zone_matches(rule: FirewallRule, attr: str) -> bool:
        # B-07: a deny naming a FortiOS zone matches its member interfaces;
        # a zone of unknown membership is not evidence of a boundary deny,
        # an empty zone matches nothing.
        raw = getattr(rule, attr)
        if raw is None or not str(raw).strip(" ,'\"[]"):
            return False                  # NULL / blank: not a catch-all
        toks, _ok = _side(rule, attr, zone_defs)
        return toks is None or bool(toks & iface_ids)

    deny_rules = [
        r for r in rules
        if _is_deny(r) and (_zone_matches(r, "src_zone") or _zone_matches(r, "dst_zone"))
    ]

    if deny_rules:
        return []

    # Vendors with an implicit deny-all at the bottom of every policy list
    # (FortiOS, PAN-OS, Cisco IOS/ASA/FTD, pfSense).  For these a missing
    # explicit deny is INFO: traffic is still dropped, the gap is only
    # auditability.  Unknown/other vendors stay HIGH.
    has_implicit_deny = _has_implicit_deny(fw, rules)
    severity = "info" if has_implicit_deny else "high"
    note = (
        f"{fw.vendor or 'This vendor'} enforces an implicit deny-all at the end "
        f"of each policy list; this finding is informational (the boundary relies "
        f"on the implicit deny) — consider adding an explicit deny to make the "
        f"intent visible in the config and auditable."
        if has_implicit_deny
        else (
            "No explicit deny rule found for traffic arriving on this interface. "
            "Without an explicit deny, traffic may be forwarded by default."
        )
    )

    f = _upsert_finding(
        db,
        category="config_review",
        check_name="cross_fw_missing_deny_all",
        severity=severity,
        isa62443_sr=_SR_BOUNDARY_E,
        checklist_id="5.1",
        title=(
            f"No explicit deny-all on '{fw.name}' interface '{iface.name}' "
            f"(cross-FW link to '{peer_fw.name}')"
        ),
        detail={
            "firewall_id":      fw.id,
            "firewall_name":    fw.name,
            "peer_fw_id":       peer_fw.id,
            "peer_fw_name":     peer_fw.name,
            "interface":        iface.name,
            "interface_zone":   iface_zone,
            "vendor":           fw.vendor,
            "note":             note,
        },
        device_name=fw.name,
        # Directional (fw>peer) so both FWs having an interface with the
        # same name (e.g. both have "wan1") cannot collide.
        source_ref=_source_ref("cross_fw_missing_deny_all", fw.id, peer_fw.id,
                               iface.name, directional=True),
    )
    return [f]


def _check_any_any_permit(
    db: DBSession,
    fw: Firewall,
    peer_fw: Firewall,
    iface: FirewallInterface,
    rules: list[FirewallRule],
    zone_defs=None,
) -> list[Finding]:
    """
    Emit a CRITICAL finding for any permit-any-any rule on a cross-FW
    interface.  This effectively disables boundary protection.

    T3-39: "any-any" means src any AND dst any AND service any (protocol
    and port), on a rule that can apply to this interface (its zones name
    the interface, or are unset/"any").
    """
    findings = []
    iface_ids = _iface_identifiers(iface)
    zone_defs = _zone_defs_for(db, zone_defs, fw)
    for rule in rules:
        if not _is_permit(rule):
            continue
        if not _rule_touches_iface(rule, iface_ids, zone_defs):
            continue
        # fw>peer + VDOM + policy id: ids repeat across VDOMs (N-24) and
        # across the two firewalls of the pair
        ref = _source_ref("cross_fw_any_any_permit", fw.id, peer_fw.id,
                          _rule_ref(rule), directional=True)
        if any(isinstance(rm.parse_address(v or "any"), rm.Unresolved) for v in (rule.src, rule.dst)):
            # B-24: cannot tell whether it is any-any - keep a prior finding open
            _mark_seen(db, ref)
            continue
        if _is_any(rule.src) and _is_any(rule.dst) and _service_is_any(rule):
            f = _upsert_finding(
                db,
                category="config_review",
                check_name="cross_fw_any_any_permit",
                severity="critical",
                isa62443_sr=_SR_BOUNDARY_E,
                checklist_id="5.1",
                title=(
                    f"Permit ANY→ANY rule on cross-FW interface '{iface.name}' "
                    f"of '{fw.name}' (linked to '{peer_fw.name}')"
                ),
                detail={
                    "firewall_id":   fw.id,
                    "firewall_name": fw.name,
                    "peer_fw_id":    peer_fw.id,
                    "peer_fw_name":  peer_fw.name,
                    "interface":     iface.name,
                    "policy_id":     rule.policy_id,
                    "vdom":          getattr(rule, "vdom", None),
                    "policy_name":   rule.policy_name,
                    "src":           rule.src,
                    "dst":           rule.dst,
                    "action":        rule.action,
                    "raw_line":      rule.raw_line,
                },
                device_name=fw.name,
                rule_id=rule.id,
                source_ref=ref,
            )
            findings.append(f)  # None = skipped duplicate; _record() counts it
    return findings


def _normalize_rule_key(rule: FirewallRule) -> tuple:
    """
    Parsed (src, dst, protocols, ports) via rule_match, so textual variants
    of the same scope ("10.1.0.0/24" vs "10.1.0.0 0.0.0.255", "eq 502" vs
    "502") compare equal (T3-39).
    """
    src, dst = rm.narrow_rule_family(rm.parse_address(rule.src or "any"),
                                     rm.parse_address(rule.dst or "any"))
    return (
        src,
        dst,
        rm.parse_protocols(rule.protocol),
        rm.parse_ports(rule.dst_port),
    )


def _key_resolvable(key: tuple) -> bool:
    return not any(isinstance(x, rm.Unresolved) for x in key)


def _covers(outer: tuple, inner: tuple) -> bool:
    """outer permit scope ⊇ inner permit scope."""
    return (rm.addr_contains(outer[0], inner[0]) is True
            and rm.addr_contains(outer[1], inner[1]) is True
            and rm.protos_contain(outer[2], inner[2]) is True
            and rm.ports_contain(outer[3], inner[3]) is True)


def _fw_levels(db: DBSession, fw: Firewall) -> frozenset:
    """The Purdue levels a firewall's labelled interfaces touch (its boundary),
    falling back to purdue_level_ingress / egress.  Empty = unknown."""
    lv = {r[0] for r in db.query(FirewallInterface.purdue_level)
          .filter(FirewallInterface.firewall_id == fw.id,
                  FirewallInterface.purdue_level.isnot(None)).distinct()}
    if not lv and fw.purdue_level_ingress is not None and fw.purdue_level_egress is not None:
        lv = {fw.purdue_level_ingress, fw.purdue_level_egress}
    return frozenset(lv)


def _transit_interfaces(db: DBSession, fw_a: Firewall, fw_b: Firewall):
    """MP-04: the two routed interfaces of fw_a / fw_b that share one IP
    network (the unconfirmed transit link of a paired group), or (None,
    None)."""
    import ipaddress
    nets_a = []
    for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_a.id,
                                                FirewallInterface.network_cidr.isnot(None)):
        try:
            nets_a.append((ipaddress.ip_network(i.network_cidr, strict=False), i))
        except ValueError:
            continue
    for j in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_b.id,
                                                FirewallInterface.network_cidr.isnot(None)):
        try:
            nj = ipaddress.ip_network(j.network_cidr, strict=False)
        except ValueError:
            continue
        for na, i in nets_a:
            if na == nj and na.prefixlen < (32 if na.version == 4 else 128):
                return i, j
    return None, None


def _serial_pair(db: DBSession, fw_a: Firewall, fw_b: Firewall) -> Optional[bool]:
    """D-06: do the two linked firewalls enforce the SAME boundary (a serial
    / redundant pair every crossing passes through both of), so that a permit
    on one must have a counterpart on the other?  False when they are two
    different boundaries' firewalls sharing a segment (e.g. the DMZ switch):
    most of one firewall's permits never reach the other.  None = unknown
    (no level labels on either side)."""
    from app.parsers.firewall_groups import confirmed_pair
    decided = confirmed_pair(db, fw_a, fw_b)
    if decided is not None:
        return decided         # an operator-confirmed paired firewall decides
    la, lb = _fw_levels(db, fw_a), _fw_levels(db, fw_b)
    if not la or not lb:
        return None
    return la == lb


def _terminates_on_link(key: tuple, iface_a: FirewallInterface, iface_b: FirewallInterface) -> bool:
    """D-06: the permit's destination lies inside the link segment itself
    (a host between the two firewalls), so the traffic never transits the
    peer and the peer needs no counterpart rule."""
    nets = []
    for iface in (iface_a, iface_b):
        for cidr in (iface.network_cidr, iface.ip_cidr):
            if cidr:
                try:
                    nets.append(rm.parse_address(cidr))
                except Exception:
                    continue
    dst = key[1]
    if dst == rm.ANY or isinstance(dst, rm.Unresolved):
        return False
    return any(rm.addr_contains(n, dst) is True for n in nets
               if n is not rm.ANY and not isinstance(n, rm.Unresolved))


def _check_asymmetric_permits(
    db: DBSession,
    fw_a: Firewall,
    fw_b: Firewall,
    iface_a: FirewallInterface,
    iface_b: FirewallInterface,
    rules_a: list[FirewallRule],
    rules_b: list[FirewallRule],
    zone_defs=None,
    serial: Optional[bool] = None,
) -> list[Finding]:
    """
    For each permit on fw_a that applies to the LINK interface iface_a,
    check whether fw_b has a permit on iface_b whose (normalised) scope
    covers it, in either orientation.  Flag cases where fw_a allows
    something fw_b doesn't permit — the conduit is one-directional.

    T3-39: addresses/ports are normalised via rule_match (so equivalent
    notations match and a broader peer permit counts), and only rules whose
    zones can apply to the link interfaces are compared - not the whole
    ruleset of each firewall.  Rules with unresolvable objects are skipped
    (cannot be compared either way).
    """
    findings = []
    if serial is None:
        serial = _serial_pair(db, fw_a, fw_b)
    if serial is False:
        # D-06: two boundaries' firewalls sharing a segment - a permit on one
        # is not expected on the other.  (no-rules / deny-all / any-any still
        # run per firewall.)
        log.debug("cross_fw_checks: %s <-> %s cross different boundaries; asymmetric "
                  "permit check skipped", fw_a.name, fw_b.name)
        return findings
    ids_a, ids_b = _iface_identifiers(iface_a), _iface_identifiers(iface_b)
    zone_defs = _zone_defs_for(db, zone_defs, fw_a, fw_b)

    peer_keys: list[tuple] = []
    for r in rules_b:
        if _is_permit(r) and _rule_touches_iface(r, ids_b, zone_defs):
            k = _normalize_rule_key(r)
            if _key_resolvable(k):
                peer_keys.append(k)
                peer_keys.append((k[1], k[0], k[2], k[3]))   # return direction

    for rule in rules_a:
        if not _is_permit(rule):
            continue
        if not _rule_touches_iface(rule, ids_a, zone_defs):
            continue
        if _is_any(rule.src) and _is_any(rule.dst):
            continue  # already flagged by any_any check
        # directional (a>b: a permit of fw_a missing on fw_b) + VDOM + policy
        # id + service, so fw_a's and fw_b's same-numbered policies differ
        ref = _source_ref(
            "cross_fw_asymmetric_permit", fw_a.id, fw_b.id,
            f"{_rule_ref(rule)}:{(rule.dst_port or 'any').strip().lower()}:"
            f"{(rule.protocol or 'any').strip().lower()}",
            directional=True)
        key = _normalize_rule_key(rule)
        if not _key_resolvable(key):
            # B-24: not comparable this run - keep a prior finding open
            _mark_seen(db, ref)
            continue
        if _terminates_on_link(key, iface_a, iface_b):
            continue      # D-06: destination sits between the two firewalls
        if not any(_covers(pk, key) for pk in peer_keys):
            f = _upsert_finding(
                db,
                category="config_review",
                check_name="cross_fw_asymmetric_permit",
                severity="medium",
                isa62443_sr=_SR_USE_CTL,
                checklist_id="5.2",
                title=(
                    f"Asymmetric permit: '{fw_a.name}' allows "
                    f"{rule.src or 'any'}→{rule.dst or 'any'} "
                    f"port {rule.dst_port or 'any'}/{rule.protocol or 'any'} "
                    f"but '{fw_b.name}' has no matching permit"
                ),
                detail={
                    "fw_a_id":       fw_a.id,
                    "fw_a_name":     fw_a.name,
                    "fw_b_id":       fw_b.id,
                    "fw_b_name":     fw_b.name,
                    "iface_a":       iface_a.name,
                    "iface_b":       iface_b.name,
                    "rule_a_policy": rule.policy_id,
                    "rule_a_vdom":   getattr(rule, "vdom", None),
                    "rule_a_name":   rule.policy_name,
                    "src":           rule.src,
                    "dst":           rule.dst,
                    "port":          rule.dst_port,
                    "protocol":      rule.protocol,
                    "action":        rule.action,
                },
                device_name=fw_a.name,
                rule_id=rule.id,
                source_ref=ref,
            )
            findings.append(f)  # None = skipped duplicate; _record() counts it

    return findings


# ─────────────────────────────────────── entry point ──────────────────────────

def run_cross_fw_checks(db: DBSession) -> dict:
    """
    Run all cross-firewall policy checks and persist ``Finding`` rows.

    Only confirmed links (``FirewallInterface.connects_to_interface_id`` is
    set) and confirmed shared segments (``FirewallInterface.segment``, every
    pair of members on different firewalls, D-07) are analysed; unconfirmed
    proposals are ignored.

    Returns a summary dict::

        {
            "links_analysed": int,
            "findings_created": int,
            "findings_skipped": int,      # already existed (open/ack)
            "by_check": {check_name: int, ...},
        }

    ``auto_resolved`` counts open cross_fw_* findings closed because this
    run no longer produced them (B-24, see the module docstring).

    The caller is responsible for ``db.commit()``.
    """
    seen: set = set()
    db.info[_SEEN_KEY] = seen
    try:
        out = _run_cross_fw_checks(db)
    finally:
        db.info.pop(_SEEN_KEY, None)
    from app.parsers.alert_engine import auto_resolve_enabled
    out["auto_resolved"] = _auto_resolve(db, seen) if auto_resolve_enabled() else 0
    return out


def _auto_resolve(db: DBSession, seen: set) -> int:
    """B-24: close OPEN, unacknowledged cross_fw_* findings (of the analysed
    site - the query is site-scoped) whose source_ref this run did not
    re-produce or keep.  Returns the number closed."""
    now = _utcnow()
    note = f"Auto-resolved: condition no longer detected by run_cross_fw_checks on {now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    closed = 0
    for f in (db.query(Finding)
              .filter(Finding.check_name.in_(CROSS_FW_CHECKS),
                      Finding.status == "open",
                      Finding.acknowledged_by.is_(None),
                      Finding.source_ref.isnot(None))):
        if f.source_ref in seen:
            continue
        f.status = "closed"
        f.closed_at = now
        f.updated_at = now
        f.notes = ((f.notes + " | ") if f.notes else "")[:2048 - len(note) - 3] + note
        closed += 1
    if closed:
        log.info("cross_fw_checks: auto-resolved %d finding(s) no longer detected", closed)
    return closed


def _run_cross_fw_checks(db: DBSession) -> dict:
    # Collect all confirmed cross-FW pairs (deduplicated)
    confirmed_pairs: list[tuple[FirewallInterface, FirewallInterface]] = []
    seen_pairs: set[frozenset] = set()

    all_ifaces = (
        db.query(FirewallInterface)
        .filter(FirewallInterface.connects_to_interface_id.isnot(None))
        .all()
    )

    for iface_a in all_ifaces:
        iface_b = db.get(FirewallInterface, iface_a.connects_to_interface_id)
        if iface_b is None:
            continue
        if iface_a.firewall_id == iface_b.firewall_id:
            continue   # same-FW self-link — shouldn't exist, but guard
        pair_key = frozenset({iface_a.id, iface_b.id})
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)
        confirmed_pairs.append((iface_a, iface_b))

    # D-07: members of a confirmed shared segment are pairwise linked
    seg_ifaces = (db.query(FirewallInterface)
                  .filter(FirewallInterface.segment.isnot(None))
                  .order_by(FirewallInterface.segment, FirewallInterface.id).all())
    by_seg: dict[str, list[FirewallInterface]] = {}
    for i in seg_ifaces:
        by_seg.setdefault(i.segment, []).append(i)
    for members in by_seg.values():
        for ix, a in enumerate(members):
            for b in members[ix + 1:]:
                if a.firewall_id == b.firewall_id:
                    continue
                pair_key = frozenset({a.id, b.id})
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                confirmed_pairs.append((a, b))

    # MP-04: members of a declared paired group with NO confirmed link or
    # shared segment between them are still one boundary in series, so they
    # are compared too - over the transit interfaces when the two share an
    # IP network, otherwise over their whole rulesets.
    from app.parsers.firewall_groups import KIND_PAIRED, _members, ha_secondary_ids
    from app.models import FirewallGroup
    linked_fw_pairs = {frozenset({a.firewall_id, b.firewall_id}) for a, b in confirmed_pairs}
    unlinked_pairs = 0
    _secondary = ha_secondary_ids(db)
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_PAIRED).order_by(FirewallGroup.id):
        units = [m for m in _members(db, g) if m.id not in _secondary]
        for ix, a in enumerate(units):
            for b in units[ix + 1:]:
                if frozenset({a.id, b.id}) in linked_fw_pairs:
                    continue
                ia, ib = _transit_interfaces(db, a, b)
                if ia is None:
                    ifs_a = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == a.id).all()
                    ifs_b = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == b.id).all()
                    ia, ib = _GroupIface(a, ifs_a), _GroupIface(b, ifs_b)
                confirmed_pairs.append((ia, ib))
                linked_fw_pairs.add(frozenset({a.id, b.id}))
                unlinked_pairs += 1

    log.info("cross_fw_checks: %d confirmed link(s) to analyse (%d shared segment(s), "
             "%d unlinked paired-group pair(s))", len(confirmed_pairs), len(by_seg), unlinked_pairs)
    # B-07: FortiOS zone definitions, loaded once (shared helper)
    zone_defs = fz.ZoneDefIndex(db, {i.firewall_id for p in confirmed_pairs for i in p})

    by_check: dict[str, int] = {}
    total_created = 0
    total_skipped = 0
    skipped_links = 0          # D-06: links between different boundaries' firewalls

    def _record(findings: list):
        nonlocal total_created, total_skipped
        for f in findings:
            if f is None:
                total_skipped += 1
            else:
                by_check[f.check_name] = by_check.get(f.check_name, 0) + 1
                total_created += 1

    from app.parsers.firewall_groups import ha_secondary_ids
    ha_secondary = ha_secondary_ids(db)
    for iface_a, iface_b in confirmed_pairs:
        fw_a = db.get(Firewall, iface_a.firewall_id)
        fw_b = db.get(Firewall, iface_b.firewall_id)
        if not fw_a or not fw_b:
            continue
        if fw_a.id in ha_secondary or fw_b.id in ha_secondary:
            continue      # HA member: compared with its primary by ha_config_drift
        if fw_a.ha_group_id is not None and fw_a.ha_group_id == fw_b.ha_group_id:
            continue      # two members of one HA cluster are one firewall

        rules_a = (
            db.query(FirewallRule)
            .filter(FirewallRule.firewall_id == fw_a.id, FirewallRule.enabled.is_(True))
            .all()
        )
        rules_b = (
            db.query(FirewallRule)
            .filter(FirewallRule.firewall_id == fw_b.id, FirewallRule.enabled.is_(True))
            .all()
        )

        # ---- no-rules check (per FW, not per pair)
        _record(_check_no_rules(db, fw_a, fw_b, iface_a))
        _record(_check_no_rules(db, fw_b, fw_a, iface_b))

        # ---- missing deny-all
        _record(_check_missing_deny_all(db, fw_a, fw_b, iface_a, rules_a, zone_defs))
        _record(_check_missing_deny_all(db, fw_b, fw_a, iface_b, rules_b, zone_defs))

        # ---- any-any permit
        _record(_check_any_any_permit(db, fw_a, fw_b, iface_a, rules_a, zone_defs))
        _record(_check_any_any_permit(db, fw_b, fw_a, iface_b, rules_b, zone_defs))

        # ---- asymmetric permits (both directions; serial pairs only, D-06)
        serial = _serial_pair(db, fw_a, fw_b)
        if serial is False:
            skipped_links += 1
        _record(_check_asymmetric_permits(db, fw_a, fw_b, iface_a, iface_b, rules_a, rules_b, zone_defs, serial=serial))
        _record(_check_asymmetric_permits(db, fw_b, fw_a, iface_b, iface_a, rules_b, rules_a, zone_defs, serial=serial))

    log.info(
        "cross_fw_checks done: %d created, %d skipped; by_check=%s",
        total_created, total_skipped, by_check,
    )
    return {
        "links_analysed":  len(confirmed_pairs),
        "paired_unlinked": unlinked_pairs,
        "asymmetric_skipped_links": skipped_links,
        "findings_created": total_created,
        "findings_skipped": total_skipped,
        "by_check":         by_check,
    }


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("run_",))
