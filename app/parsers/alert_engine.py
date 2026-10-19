"""
Alert engine: 62443-tagged findings from FortiAnalyzer events and
periodic baseline comparison.

REAL-TIME CHECKS (run against each new FortiAnalyzerEvent immediately):
  Any single event matching these conditions = potential incident.
  Each produces one Finding row with isa62443_sr, checklist_id,
  check_name, severity, and detail (evidence).

PERIODIC REVIEWS (run on demand or on a schedule, compare against baseline):
  These compare the current state of NetworkSession / FirewallRule data
  against the active Baseline's ApprovedCommsEntry set and produce
  Finding rows with category="periodic_review".

All finding-generation is idempotent by content hash, stored in
Finding.source_ref: two identical events within the same review period
don't generate two identical open findings (a new one is only skipped
if an *open* finding with the same check + key evidence already exists -
if the prior one was closed or acknowledged, a fresh occurrence still
gets a new finding, since "it happened again after being resolved" is
meaningful and shouldn't be silently suppressed). This prevents alert
storms from repeated log delivery without hiding genuinely separate
incidents.

This module previously wrote to a separate `Alert` model, entirely
disconnected from `Finding` (which forti_config_parser.py and
traffic_findings.py already wrote to) - two complete, parallel alerting
systems, neither aware of the other, and the dashboard built against
`Finding` was blind to everything this module produced. `Alert` has
been removed; this module now writes `Finding` rows like every other
check-producing module in the project, tagged with `check_name` (see
CHECK_TYPE_REFERENCE in models.py) to identify which specific check
fired, since Finding.category alone (config_review/real_time/
periodic_review) is too coarse for that.

FINDINGS LIFECYCLE (F-04): a dedup hit on an OPEN finding is a re-detection:
the finding's last_seen and occurrence_count are bumped and its detail
evidence refreshed (severity/title change only by escalation). After a
periodic review that is listed in _AUTO_RESOLVE_CHECKS succeeds with a
complete evaluation, its open findings that were not re-produced in that run
are closed ("Auto-resolved: ..." note). Acknowledged and real_time findings
are never auto-closed; IACS_AUTO_RESOLVE=false switches auto-resolve off.

FAILURE ISOLATION (T3-16 / T3-17): every real-time check in evaluate_event()
(one shared savepoint first, per-check savepoints only after a failure,
N-17) and every review in run_periodic_reviews() runs inside its own SAVEPOINT
(Session.begin_nested). On PostgreSQL a single failed statement aborts the
whole transaction; the savepoint confines that to the failing check, whose
partial writes are rolled back while earlier and later checks (and the
caller's commit) proceed. The escalation counter (escalation_count) is
restored to its pre-check value when a check's savepoint is rolled back.

PHASE-6 RULE TWINS - ONE FINDING PER LOGICAL RULE (T3-19): FirewallRule rows
are an expansion of a logical policy (FortiOS: src x dst x service rows that
share policy_id; Cisco/pfSense/PAN-OS: rows sharing raw_line). The review_rule_*
checks evaluate every row but group the hits by logical rule (same key as
review_disabled_rules) and emit one finding per logical rule per check, with
the union of the rows' Purdue levels and ports. Dedup is on the stable
rule_key (policy_id or sha1(raw_line), plus firewall / device identity) - NOT
on firewall_rule_id - so a config re-ingest (which recreates rows with new
ids) does not duplicate the set. The rows' ids are kept in evidence under
"firewall_rule_ids" (not part of the dedup key). Open findings written by the
older per-row scheme are closed as superseded when their rule's new
per-logical-rule finding exists (never deleted).

OVERLAPPING RULE-TWIN FINDINGS (T3-20): one permissive rule (e.g. IT -> L1
Telnet) legitimately trips several twins - insecure protocol (3.5),
cleartext credentials (8.3), management from wrong zone (5.1) and IT/OT
bypass (2.1/2.2). They map to DIFFERENT checklist rows, each of which an
auditor must be able to close independently, so they are deliberately kept
as separate findings rather than merged. To make the overlap visible, each
twin finding carries evidence "related_checks" (the other twin check_names
that fired for the same logical rule in the same run; not part of the dedup
key), and titles start with a check-specific prefix so the four are clearly
distinguishable in lists.
"""
import bisect
import hashlib
import ipaddress
import logging
import re
import threading
import traceback
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

log = logging.getLogger(__name__)

from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession, joinedload, aliased

from app.parsers import remote_access as ra
from app.parsers import fortios_zones as _fz
from app.parsers.site_scope import analysis_site, current_site, scope_module
# C-01: shared flow canonicaliser (client, server, server_port) - keeps pcap
# and FAZ findings for one logical flow on a single identity. traffic_findings
# imports from this module only lazily (inside functions), so this top-level
# import introduces no cycle.
from app.parsers.traffic_findings import canonical_flow

from app.models import (
    ApprovedCommsEntry, ApprovedHost, Attestation, Baseline,
    FirewallInterface, FirewallRule, FirewallZone, FortiAnalyzerEvent, Finding, Host, MacTableEntry,
    NetworkSession, ProtocolDetail, SwitchInterface, SwitchVlan,
    CHECK_TYPE_REFERENCE, real_host_clause,
)
from app.purdue import (
    fmt_level, is_deep_ot, is_dmz, is_it, is_it_side, is_ot, sorted_levels,
)

# Purdue level semantics used by the checks below (F-08; vocabulary and the
# full rationale in app/purdue.py):
#   * "OT" = L0-L2 (is_ot), "deep OT" = L0-L1 (is_deep_ot).
#   * "IT side" = L3 and above (is_it_side) - unchanged from the pre-F-08
#     ``level >= 3`` tests.  The industrial DMZ (L3.5) sits above L3, so it
#     is on the IT side for every IT->OT / bypass / crossing check: a DMZ
#     host reaching L1 directly still skips L3 and L2.
#   * "Different zone" = a different level (``!=``), never ``abs(a-b) >= 1``
#     - L3 and L3.5 are different zones half a unit apart.
#   * Exception - management / remote access FROM the DMZ into L0-L2: a jump
#     host in the industrial DMZ is the sanctioned ISA/IEC 62443 remote-access
#     path (enterprise -> DMZ jump host -> OT), so mgmt_access_from_wrong_zone
#     and rule_mgmt_wrong_zone report DMZ-only sources one severity step lower
#     (evidence "dmz_source": true) and say so.  They still fire: the jump
#     host should be in the baseline (ApprovedHost role jump_host) and the
#     rule scoped to it.  Enterprise / internet / L3 sources keep the
#     original severity.
_SEVERITY_STEP_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}

# Ports/services considered "internet egress" for OT (check 3.7, 9.11, 9.12)
_INTERNET_EGRESS_PORTS = {
    53, 80, 443, 8080, 8443,   # DNS, HTTP, HTTPS
    123,                         # NTP
    20, 21,                      # FTP (software updates via FTP)
    25, 587, 465,                # SMTP
}
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_REMOTE_ACCESS_APPS = {
    "teamviewer", "anydesk", "vnc", "logmein", "gotomypc",
    "splashtop", "netmanage", "connectwise", "bomgar", "screenconnect",
    "zoho assist", "rustdesk",
}

_LOG_SILENCE_THRESHOLD_MINUTES = 30

# Module-level counter for unknown check_name values passed to _make_finding().
# Incremented each time a check_name is not in CHECK_TYPE_REFERENCE so typos
# can be detected via monitoring or log analysis without crashing.
_unknown_check_name_count: dict[str, int] = {}


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ULA = ipaddress.ip_network("fc00::/7")
# Documentation ranges (RFC 5737 / RFC 3849). ipaddress counts them as
# "private", but they are the conventional stand-in for INTERNET hosts in
# examples, sample data and lab captures. Treated as public/external: calling
# them internal would silently suppress egress / remote-access findings
# (false negative), while treating them as public can only raise one.
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _is_doc(addr) -> bool:
    return any(addr.version == n.version and addr in n for n in _DOC_NETS)


def _parse_ip(ip_str: Optional[str]):
    """ipaddress object for ``ip_str`` (IPv4-mapped IPv6 unwrapped to IPv4;
    a zone suffix ``%eth0`` dropped), or None when absent / unparseable."""
    if not ip_str:
        return None
    try:
        addr = ipaddress.ip_address(str(ip_str).strip().split("%", 1)[0])
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr


def _is_internal_ip(ip_str: Optional[str]) -> bool:
    """B-20: address of an internal (non-internet) network, IPv4 or IPv6:
    RFC 1918 / other IANA private ranges (ipaddress.is_private), carrier-grade
    NAT 100.64.0.0/10, link-local (169.254/16, fe80::/10) and IPv6 ULA
    fc00::/7. Replaces the old RFC1918-only test, under which OT addressed
    from IPv6 / ULA / CGNAT / link-local was never evaluated."""
    addr = _parse_ip(ip_str)
    if addr is None or _is_doc(addr):
        return False
    if addr.is_private or addr.is_link_local:
        return True
    if addr.version == 4:
        return addr in _CGNAT
    return addr in _ULA


def _is_public_ip(ip_str: Optional[str]) -> bool:
    """B-20: a globally routable unicast (internet) address: is_global and
    not multicast / reserved / unspecified / loopback (so link-local, CGNAT
    and ULA destinations are no longer called 'public')."""
    addr = _parse_ip(ip_str)
    if addr is None:
        return False
    if _is_doc(addr):
        return True
    return bool(addr.is_global and not (addr.is_multicast or addr.is_reserved
                                        or addr.is_unspecified or addr.is_loopback))


def _is_rfc1918(ip_str: Optional[str]) -> bool:
    """Deprecated alias (B-20): internal-address test, see _is_internal_ip."""
    return _is_internal_ip(ip_str)


def _different_region(a: str, b: str) -> bool:
    """Subnet-heuristic helper: different /16 (IPv4) or /48 (IPv6) block,
    or different address families."""
    x, y = _parse_ip(a), _parse_ip(b)
    if x is None or y is None:
        return False
    if x.version != y.version:
        return True
    plen = 16 if x.version == 4 else 48
    return (ipaddress.ip_network(f"{x}/{plen}", strict=False)
            != ipaddress.ip_network(f"{y}/{plen}", strict=False))


def _active_baseline(db: DBSession) -> Optional[Baseline]:
    return db.query(Baseline).filter(Baseline.is_active == True).order_by(Baseline.created_at.desc()).first()


# B-05: actions that mean "the firewall permitted this traffic". Real-time
# checks must treat session-END / session-START logs as permitted too: with
# FortiGate (and ASA teardown -> "close", PAN-OS end logs) many sessions are
# only ever logged as close / timeout / client-rst / server-rst, so an
# accept-only test silently never raised IT/OT bypass etc. Deny-class actions
# (deny, drop, block, reject, reset, reset-*, dns, perf-stats, ...) are
# deliberately NOT here. Duplicate accept+close logs for one flow collapse into
# ONE finding because the action is not part of the dedup key (_dedup_key).
_PERMITTED_ACTIONS = frozenset({
    "accept", "allow", "allowed", "permit", "permitted", "pass", "est-allowed",
    "close", "closed", "timeout", "client-rst", "server-rst", "start",
    "ip-conn", "session-end", "session-close", "end",
})


def _is_permitted(action) -> bool:
    """True when ``action`` denotes permitted traffic (incl. session end logs).

    Case/whitespace-insensitive; also accepts FortiOS composite values such as
    ``"accept: session close"`` / ``"allow: ..."`` via their leading verb.
    """
    a = str(action or "").strip().lower()
    if not a:
        return False
    if a in _PERMITTED_ACTIONS:
        return True
    head = a.split(":", 1)[0].strip()
    return head in _PERMITTED_ACTIONS and ":" in a


def _dedup_key(check_name: str, evidence: dict) -> str:
    """Produce a stable hash of (check_name, key evidence fields) for
    deduplication - stored in Finding.source_ref, matched by plain
    string equality. The previous version of this dedup stored the same
    hash inside Alert.evidence (a JSON column) and matched it via a
    JSON-path query (`Alert.evidence["_dedup"].as_string()`), which
    this environment had no way to verify actually works correctly
    against SQLite - no live database was available to test it against.
    Finding.source_ref is a plain indexed string column matched with
    `==`, avoiding that uncertainty entirely, and is the same mechanism
    already tested and working in traffic_findings.py.

    Key coverage:
      Real-time checks use src_ip / dst_ip / dst_port / policy_id.
      Periodic review checks use a broader set of fields so that each
      distinct entity (device, rule, session) gets its own dedup slot
      rather than all findings for a check colliding on None values.

      Field mapping by check_name:
        review_unknown_devices  → ip, mac
        review_ip_conflicts     → ip
        review_shadow_rules     → policy_id_a, policy_id_b
        review_unused_policies  → rule_id
        review_misplaced_devices → src_ip
        review_cleartext_creds  → src_ip, dst_ip, dst_port
        review_cleartext_protocol / smbv1_legacy → src_ip, dst_ip, dst_port
        review_mgmt_protocols   → src_ip, dst_ip, dst_port
        review_ot_it_dependency → src_ip, dst_ip, dst_port
        conduit_matrix_drift    → src_ip, dst_ip, dst_port
    """
    # Collect every distinguishing field present in the evidence dict.
    # Fields not present for a given check resolve to None and don't
    # contribute distinguishing power, which is fine — the check_name
    # prefix already namespaces collisions across check types.
    sig = "|".join([
        check_name,
        str(evidence.get("src_ip")),
        str(evidence.get("dst_ip")),
        str(evidence.get("dst_port")),
        str(evidence.get("policy_id")),
        # periodic review extras
        str(evidence.get("ip")),           # unknown_device, ip_conflict, firmware_not_documented
        str(evidence.get("mac")),          # unknown_device
        str(evidence.get("rule_id")),      # unused_policy
        str(evidence.get("policy_id_a")), # shadow_rule
        str(evidence.get("policy_id_b")), # shadow_rule
        # real-time extras
        str(evidence.get("device_name")), # fw_config_change (distinct per firewall)
        str(evidence.get("window_hour")), # scanning_denied (one finding per src/hour)
        # VLAN topology checks — each finding is per-host or per-conduit pair
        str(evidence.get("host_ip")),      # vlan_zone_mismatch (one finding per mismatched host)
        str(evidence.get("host_mac")),     # vlan_zone_mismatch (MAC-only hosts have no IP)
        str(evidence.get("vlan_id")),      # vlan_zone_mismatch, ghost_vlan
        str(evidence.get("switch_device")), # ghost_vlan (one finding per VLAN per switch)
        str(evidence.get("ot_interface")), # intervlan_routing_unchecked (one per conduit pair)
        str(evidence.get("it_interface")), # intervlan_routing_unchecked
        str(evidence.get("firewall_id")), # intervlan_routing_unchecked (multi-FW disambiguation)
        # Phase 6: rule-based twin checks — one finding per (rule, check_name)
        str(evidence.get("firewall_rule_id")), # rule_cleartext_protocol, rule_cleartext_creds, etc.
        str(evidence.get("src_zone")),     # rule-based: zone pair disambiguates conduit
        str(evidence.get("dst_zone")),     # rule-based: zone pair disambiguates conduit
    ])
    # T3-21: rule_conduit_drift is evaluated against a specific baseline, so a
    # finding raised against baseline A must not suppress the same drift
    # against baseline B. Appended only when present so that the hash of
    # every other check (which never carries baseline_id) is unchanged and
    # existing open findings keep deduplicating across the upgrade.
    if evidence.get("baseline_id") is not None:
        sig += "|baseline=" + str(evidence.get("baseline_id"))
    # disabled_rule: stable identity of a logical rule that survives config
    # re-ingest (which recreates FirewallRule rows with new ids). Appended
    # only when present, for the same hash-stability reason as baseline_id.
    if evidence.get("rule_key") is not None:
        sig += "|rule=" + str(evidence.get("rule_key"))
    # N-15: baseline drift is per (src, dst, dst_port, transport) flow.
    # Appended only when present (hash stability of every other check).
    if evidence.get("flow_transport") is not None:
        sig += "|transport=" + str(evidence.get("flow_transport"))
    if evidence.get("kind") is not None:          # ha_system_error: per subtype (B2)
        sig += "|kind=" + str(evidence.get("kind"))
    # A-12: shadow_rule identity = logical rule_key of BOTH rules (rule_key
    # above carries "<key_a>><key_b>"); A-14: per-signature / per-app /
    # per-day identities. Each appended only when present (hash stability).
    if evidence.get("ips_attack") is not None:
        sig += "|attack=" + str(evidence.get("ips_attack"))
    if evidence.get("ra_app") is not None:
        sig += "|app=" + str(evidence.get("ra_app"))
    if evidence.get("window_day") is not None:
        sig += "|day=" + str(evidence.get("window_day"))
    # C-14: auth_failure dedup is per (src_ip, user, device, hour) - the
    # docstring always said so, but `user` was never hashed, so alice and bob
    # failing from one IP in one hour collapsed to a single finding (and
    # _redetected then overwrote the first user). Appended only when present so
    # every other check's hash is unchanged (no other check feeds `user` into
    # its dedup evidence - auth_from_non_admin_host / fw_config_change pass an
    # explicit dedup_evidence that omits it).
    if evidence.get("user") is not None:
        sig += "|user=" + str(evidence.get("user"))
    # C-11: ha_failover passes {site_device_id, to_serial, window_hour} but the
    # dedup only ever hashed window_hour, collapsing SA->SB and SB->SA (and two
    # different clusters) in one hour to a single finding. Hash the identifying
    # fields it actually supplies. Appended only when present (no other check
    # carries these in its dedup evidence) so all other hashes are unchanged.
    if evidence.get("site_device_id") is not None:
        sig += "|sdev=" + str(evidence.get("site_device_id"))
    if evidence.get("to_serial") is not None:
        sig += "|toserial=" + str(evidence.get("to_serial"))
    return hashlib.sha1(sig.encode()).hexdigest()[:16]


# Severity ordering used for escalation of an already-open finding (T1-11).
_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

# Key in Session.info where _make_finding counts escalations of existing open
# findings. Escalations are deliberately NOT returned from _make_finding (it
# returns None for them, as for any suppressed duplicate) so that every caller
# that counts non-None results as "new findings" stays correct; callers that
# want the escalation count read it from here (see run_periodic_reviews).
_ESCALATION_COUNTER_KEY = "alert_engine.escalations"


def _severity_rank(sev: Optional[str]) -> int:
    return _SEVERITY_RANK.get((sev or "").lower(), -1)


def escalation_count(db: DBSession) -> int:
    """Number of open findings escalated through this session so far."""
    return int(db.info.get(_ESCALATION_COUNTER_KEY, 0))


# F-04: Session.info key holding the set of dedup keys (source_ref) produced
# by _make_finding while a periodic review runs (new findings AND re-detected
# open ones). Only populated while a review is being tracked
# (run_periodic_reviews sets it to a fresh set per review); None otherwise so
# bulk real-time ingest does not accumulate it.
_SEEN_KEY = "alert_engine.seen_refs"
_RUN_FINDINGS_KEY = "alert_engine.run_findings"   # dedup -> Finding handled this run (B6)
_RESTATE_KEY = "alert_engine.restate"   # FO-09: dedup -> [open Finding, run severity, run title]
_HA_SECONDARY_RULES_KEY = "alert_engine.ha_secondary_rule_ids"
# F-04: set by a review (via _mark_incomplete) when its evaluation this run
# was partial (required data absent, input truncated by a row limit, ...);
# auto-resolve is then skipped for that review.
_INCOMPLETE_KEY = "alert_engine.incomplete"


# B-06: Session.info key: {label: rows_not_evaluated} recorded by a review
# whose input was capped (exposed per review in last_review_info()
# ["truncated"]). Reviews paginate fully (_keyset) wherever cost is linear,
# so this normally stays empty.
_TRUNCATED_KEY = "alert_engine.truncated"
# B-20: per-review count of sessions/hosts skipped because a Purdue level is
# unknown (last_review_info()["skipped_unknown_level"]) and the IPs involved
# (auto-resolve keeps findings concerning them; it is NOT disabled for the
# whole check - see _count_unknown_level).
_SKIPPED_UNKNOWN_KEY = "alert_engine.skipped_unknown_level"
_UNKNOWN_HOSTS_KEY = "alert_engine.unknown_level_hosts"
# B-06: page size of keyset-paginated review scans (_keyset). Not a cap.
_PAGE_SIZE = 5_000


def _mark_incomplete(db: DBSession, reason: str) -> None:
    """Tell run_periodic_reviews that the running review did not evaluate
    its complete input this run, so its unreproduced findings must not be
    auto-resolved."""
    if db.info.get(_SEEN_KEY) is not None:
        db.info[_INCOMPLETE_KEY] = reason


def _limit_hit(db: DBSession, rows: list, limit: int, label: str) -> list:
    """Mark the running review incomplete when a row-limited query was
    truncated (len(rows) reached the limit). Returns rows unchanged."""
    if len(rows) >= limit:
        _mark_incomplete(db, f"{label}: input truncated at {limit} rows")
        _record_truncation(db, label, None)
    return rows


def _record_truncation(db: DBSession, label: str, skipped: Optional[int]) -> None:
    """B-06: surface a capped review input (rows not evaluated; None when
    unknown) in last_review_info()["truncated"]."""
    if db.info.get(_SEEN_KEY) is not None:
        db.info.setdefault(_TRUNCATED_KEY, {})[label] = skipped


# A-09: Session.info key holding, while a review runs, the identities
# (rule_key, firewall_id, device_name) of logical firewall rules the review
# could NOT fully evaluate this run (a relevant rule side unresolvable to
# Purdue levels, unparseable ports, object the diff could not resolve...).
# Auto-resolve skips open findings of those rules - scoped per finding, so
# one junk rule does not disable auto-resolve for the whole check, while a
# live finding is never closed just because its rule became unresolvable.
_UNEVALUATED_KEY = "alert_engine.unevaluated_rules"


def _rule_identity(rule_key, firewall_id, device_name) -> tuple:
    return (None if rule_key is None else str(rule_key), firewall_id, device_name)


def _mark_rule_unevaluated(db: DBSession, rule_key, firewall_id, device_name) -> None:
    """A-09: the running review could not fully evaluate this logical rule;
    its open findings must not be auto-resolved this run."""
    s = db.info.get(_UNEVALUATED_KEY)
    if s is not None:
        s.add(_rule_identity(rule_key, firewall_id, device_name))


def _apply_restatements(db: DBSession, restate: dict) -> int:
    """FO-09: after a complete periodic review, an open finding that was
    re-detected takes the title and severity THIS run gave it (the highest
    occurrence of the run): a reclassified host changes both.  Raising was
    already done on the fly (_escalate_if_higher); this only lowers severity
    and refreshes the title.  Returns how many findings changed."""
    n = 0
    for f, sev, title in restate.values():
        changed = False
        if _severity_rank(sev) < _severity_rank(f.severity):
            f.severity = sev
            changed = True
        if _severity_rank(sev) <= _severity_rank(f.severity) and title and f.title != title:
            f.title = title[:512]
            changed = True
        if changed:
            f.updated_at = datetime.now(timezone.utc)
            n += 1
    return n


def _redetected(existing: Finding, detail: dict) -> None:
    """F-04: an open finding's condition was detected again - bump
    last_seen / occurrence_count and refresh its evidence. Severity and
    title follow the escalation rules (_escalate_if_higher) and, after a
    complete periodic review, the run's own verdict (FO-09,
    _apply_restatements)."""
    existing.last_seen = datetime.now(timezone.utc)
    existing.occurrence_count = int(existing.occurrence_count or 1) + 1
    # C-14: MERGE rather than overwrite. A straight replace erased any key the
    # prior evidence carried that this occurrence's dict happens to omit (e.g.
    # the "description" the finding was created with, or a user recorded on a
    # path that no longer re-supplies it), which the UI/report display. Newer
    # values still win for shared keys, so this never staleness-locks a field.
    if isinstance(existing.detail, dict) and isinstance(detail, dict):
        merged = {**existing.detail, **detail}
    else:
        merged = detail
    if existing.detail != merged:
        existing.detail = merged  # reassign: plain JSON column, no mutation tracking


# Detail keys written by app.parsers.access_path_findings (Access Review
# confirmations / acceptances, docs/access-path-review.md phase 4). An
# evidence refresh never drops them; "manual" findings (raised from a
# classification) are owned by _review_access_path_classifications.
ACCESS_REVIEW_DETAIL_KEYS = (
    "manual", "access_path_tag", "manual_confirmed", "access_review_confirmations",
    "reviewer_note", "classified_by", "acknowledged_via_tag", "access_review_ack_note",
)


# Statuses that make a finding "active" for dedup: an ACKNOWLEDGED finding
# is owned by a person (risk accepted / being handled), so a persisting
# condition must update it - not spawn a fresh open duplicate every review
# run. Only CLOSED findings let a recurrence open a new finding.
from app.models import ACTIVE_FINDING_STATUSES as _ACTIVE_STATUSES   # open / acknowledged / false_positive (SF)


def _find_open(db: DBSession, dedup: str) -> Optional[Finding]:
    """The active (open or acknowledged) finding for a dedup key, preferring
    an open one if both exist."""
    rows = db.query(Finding).filter(
        Finding.source_ref == dedup,
        Finding.status.in_(_ACTIVE_STATUSES),
    ).all()
    if not rows:
        return None
    rows.sort(key=lambda f: (f.status != "open", f.id))
    return rows[0]


def _already_open(db: DBSession, dedup: str) -> bool:
    return _find_open(db, dedup) is not None


def _escalate_if_higher(
    db: DBSession,
    existing: Finding,
    severity: str,
    title: str,
    detail: dict,
) -> bool:
    """T1-11: raise an open finding's severity when a new occurrence of the
    same condition is more severe (e.g. traffic now confirms a policy gap).

    Only severity, title and detail change; id, created_at, status,
    source_ref and lifecycle fields are preserved. updated_at is bumped.
    Equal or lower severity leaves the finding untouched. Returns True if
    the finding was escalated.
    """
    if _severity_rank(severity) <= _severity_rank(existing.severity):
        return False
    old = existing.severity
    old_detail = existing.detail if isinstance(existing.detail, dict) else {}
    # Access Review (docs/access-path-review.md phase 4): keep the reviewer's
    # confirmation / acceptance markers across the evidence refresh.
    kept = {k: old_detail[k] for k in ACCESS_REVIEW_DETAIL_KEYS if k in old_detail}
    accepted = existing.status == "acknowledged" and bool(old_detail.get("acknowledged_via_tag"))
    existing.severity = severity
    existing.title = title
    existing.detail = {**detail, **kept} if isinstance(detail, dict) else detail
    existing.updated_at = datetime.now(timezone.utc)
    if accepted:
        # Accepted (exception / reviewed OK) in Access Review: the reviewer
        # accepted this policy, so a severity change does not undo it.
        stamp = existing.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        note = (f"{stamp}: severity escalated {old} -> {severity}; kept acknowledged "
                f"(accepted in Access Review).")
        existing.notes = (f"{existing.notes}\n{note}" if existing.notes else note)[:2048]
    elif existing.status == "false_positive":
        # SF: the operator judged the condition itself a false positive; a
        # severity change does not make it real.  Recorded, never re-opened.
        stamp = existing.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        note = f"{stamp}: severity escalated {old} -> {severity}; kept as false positive."
        existing.notes = (f"{existing.notes}\n{note}" if existing.notes else note)[:2048]
    elif existing.status == "acknowledged":
        # The acknowledgement covered a less severe condition: put it back in
        # front of a person. Safe w.r.t. the open-only unique index because
        # dedup never lets an open twin exist alongside an active finding.
        existing.status = "open"
        # B-16 parity (routes status route, cross_fw_findings._upsert_finding):
        # a re-opened finding is nobody's yet - drop the stale acknowledgement.
        existing.acknowledged_by = None
        existing.acknowledged_at = None
        existing.closed_at = None
        stamp = existing.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        reopen = f"Re-opened {stamp}: severity escalated {old} -> {severity} after acknowledgement."
        existing.notes = f"{existing.notes}\n{reopen}" if existing.notes else reopen
    db.info[_ESCALATION_COUNTER_KEY] = escalation_count(db) + 1
    log.info(
        "_make_finding: escalated open finding id=%s (%s) %s -> %s: %s",
        existing.id, existing.check_name, old, severity, title,
    )
    return True


def _make_finding(
    db: DBSession,
    check_name: str,
    title: str,
    detail_text: str,
    evidence: dict,
    forti_event_id: Optional[int] = None,
    session_id: Optional[int] = None,
    firewall_rule_id: Optional[int] = None,
    device_name: Optional[str] = None,
    severity: Optional[str] = None,
    dedup_evidence: Optional[dict] = None,
    _open_cache: Optional[dict] = None,
    legacy_dedup_evidence: Optional[dict] = None,
) -> Optional[Finding]:
    """Create a Finding for a check occurrence, deduplicated against OPEN
    findings with the same dedup key.

    Returns the new Finding, or None when no new row was created: unknown
    check_name, an open duplicate already exists (in which case that open
    finding is escalated in place if this occurrence is more severe - see
    _escalate_if_higher / escalation_count), or a concurrent insert won the
    race for the open slot.

    Recurrence (T1-10): Finding.source_ref is unique only among open
    findings (partial index ux_findings_source_ref_open), so when the prior
    finding for this condition was closed or acknowledged a fresh open
    finding is inserted with the same source_ref.

    dedup_evidence: when given, the dedup hash is computed from it instead of
    `evidence` (which is still stored whole in detail). Lets a check keep
    display-only fields (zones, raw ports, row ids) out of its identity.

    _open_cache: optional {source_ref: open Finding} preloaded by the caller
    for this check_name (Phase-6 batch path, T3-18). When given it replaces
    the per-finding _find_open query and is kept up to date on insert.

    legacy_dedup_evidence: dedup evidence under the check's PREVIOUS key
    scheme (A-12/A-14 re-keyed checks). When no active finding exists under
    the new key but one exists under the legacy key, that finding is
    re-keyed in place (source_ref updated) and treated as re-detected, so
    an upgrade never leaves a permanent old/new duplicate pair open.
    """
    # Guard against check_names produced by forti_config_parser (and any
    # future check) that aren't registered in CHECK_TYPE_REFERENCE. An
    # unregistered name would raise KeyError, crashing the entire ingest
    # request. Log a warning and skip rather than crash.
    if check_name not in CHECK_TYPE_REFERENCE:
        # Track unknown check_names in a module-level counter so monitoring
        # can detect typos that silently produce zero findings.
        _unknown_check_name_count[check_name] = (
            _unknown_check_name_count.get(check_name, 0) + 1
        )
        log.warning(
            "_make_finding: unknown check_name %r (seen %d time(s)) — add it to "
            "CHECK_TYPE_REFERENCE in models.py. Skipping finding: %s",
            check_name, _unknown_check_name_count[check_name], title,
        )
        return None
    sr_ref, checklist_id, default_severity, category = CHECK_TYPE_REFERENCE[check_name]
    # HA clusters: during a periodic run a finding about a non-primary
    # member's rule duplicates the primary's (one configuration); the member
    # is compared with the primary by ha_config_drift instead.
    _ha_rules = db.info.get(_HA_SECONDARY_RULES_KEY)
    if _ha_rules and firewall_rule_id is not None and firewall_rule_id in _ha_rules:
        return None
    # Allow callers to override the default severity from CHECK_TYPE_REFERENCE
    # when context (e.g. Purdue level of the source host) warrants a different
    # classification. Fall back to the registered default when not provided.
    effective_severity = severity if severity is not None else default_severity
    dedup = _dedup_key(check_name, evidence if dedup_evidence is None else dedup_evidence)
    detail = {"description": detail_text, **evidence}
    seen = db.info.get(_SEEN_KEY)
    if seen is not None:
        prior = db.info.get(_RUN_FINDINGS_KEY, {}).get(dedup)
        if prior is not None:
            restate = db.info.get(_RESTATE_KEY)
            rec = restate.get(dedup) if restate is not None else None
            if rec is not None and _severity_rank(effective_severity) > _severity_rank(rec[1]):
                rec[1], rec[2] = effective_severity, title
            # AU full review B6: the same condition reported again IN THIS RUN
            # (one finding per flow, many sessions): no query, no extra
            # occurrence - only a higher severity still escalates it.
            if _severity_rank(effective_severity) > _severity_rank(prior.severity):
                _escalate_if_higher(db, prior, effective_severity, title, detail)
            return None
        seen.add(dedup)  # F-04: re-produced this run (new or re-detected)

    # Dedup applies to ALL categories (real_time and periodic_review alike).
    if _open_cache is not None:
        existing = _open_cache.get(dedup)
        if existing is not None and existing.status not in _ACTIVE_STATUSES:
            existing = None
    else:
        existing = _find_open(db, dedup)
    if existing is None and legacy_dedup_evidence is not None:
        legacy = _dedup_key(check_name, legacy_dedup_evidence)
        if legacy != dedup:
            old = _find_open(db, legacy)
            if old is not None and old.check_name == check_name:
                old.source_ref = dedup  # adopt: re-key the pre-upgrade finding
                if _open_cache is not None:
                    _open_cache[dedup] = old
                existing = old
    if existing is not None:
        restate = db.info.get(_RESTATE_KEY)
        if restate is not None:
            # FO-09: remember what THIS run says (highest occurrence wins);
            # applied when the review completes (_apply_restatements)
            restate[dedup] = [existing, effective_severity, title]
        if _severity_rank(effective_severity) < _severity_rank(existing.severity) \
                and isinstance(detail, dict) and "severity_reason" in detail:
            # the finding keeps its (higher) severity: keep the reason that set it
            detail = {k: v for k, v in detail.items() if k != "severity_reason"}
        _redetected(existing, detail)
        _escalate_if_higher(db, existing, effective_severity, title, detail)
        if db.info.get(_RUN_FINDINGS_KEY) is not None:
            db.info[_RUN_FINDINGS_KEY][dedup] = existing
        return None

    finding = Finding(
        category=category,
        check_name=check_name,
        isa62443_sr=sr_ref,
        checklist_id=checklist_id,
        severity=effective_severity,
        title=title,
        detail=detail,
        device_name=device_name,
        forti_event_id=forti_event_id,
        session_id=session_id,
        rule_id=firewall_rule_id,
        source_ref=dedup,
        # Multi-site: the analysed site (None = unscoped legacy run; the
        # flush listener then derives it from the rule/session/event).
        site_id=current_site(db),
    )
    # Use a savepoint so an IntegrityError on this one finding does not roll
    # back the entire ambient transaction (which may hold previously flushed
    # findings from earlier checks in the same run_periodic_reviews pass).
    sp = db.begin_nested()
    try:
        db.add(finding)
        sp.commit()
    except IntegrityError:
        # With the partial unique index (open findings only) the only way to
        # get here is a concurrent writer inserting the same OPEN finding
        # between our _find_open() and this insert. Roll back only this
        # savepoint and try to apply any escalation to the winner's row.
        sp.rollback()
        log.warning(
            "_make_finding: concurrent duplicate open finding source_ref=%s "
            "(%s), skipped insert: %s",
            dedup, check_name, title,
        )
        winner = _find_open(db, dedup)
        if winner is not None:
            if _open_cache is not None:
                _open_cache[dedup] = winner
            _redetected(winner, detail)
            _escalate_if_higher(db, winner, effective_severity, title, detail)
        return None
    if _open_cache is not None:
        _open_cache[dedup] = finding
    if db.info.get(_RUN_FINDINGS_KEY) is not None:
        db.info[_RUN_FINDINGS_KEY][dedup] = finding
    return finding


# ---------------------------------------------------------------------------
# 11 REAL-TIME CHECKS
# ---------------------------------------------------------------------------

def _bypass_kind(a, b) -> Optional[str]:
    """A-11: classify a direct (accepted) exchange between Purdue levels a
    and b (either direction) as an IT/OT layer bypass.

      "deep_ot"  one side L3+ (L3, L3.5, L4, L5) and the other L0-L1 - the
                 historical rule; severity unchanged (critical for events /
                 sessions).
      "l2"       one side enterprise/internet (L4-L5) and the other L2:
                 traffic that skips BOTH the site-operations (L3) and the
                 industrial-DMZ (L3.5) layers of the 62443 conduit model.
                 Severity "high" (one step below deep-OT: L2 supervisory
                 hosts are not the field devices themselves).
      None       not a bypass. Notably L3 / L3.5 <-> L2 is NOT a bypass:
                 L3 -> L2 is the adjacent conduit and DMZ (L3.5) -> L2 is the
                 sanctioned remote-access / jump-host path, governed by the
                 management / remote-access checks (mgmt_access_*,
                 remote_access_bypass, rule_mgmt_wrong_zone), not by bypass.
    """
    if (is_it_side(a) and is_deep_ot(b)) or (is_it_side(b) and is_deep_ot(a)):
        return "deep_ot"
    if (is_it(a) and is_ot(b)) or (is_it(b) and is_ot(a)):
        return "l2"
    return None


def check_it_ot_bypass(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 5.1 RE2, SR 5.2 / 2.1, 2.2 — Direct IT↔OT sessions bypassing DMZ.

    Two detection paths, in order of confidence:

    1. Purdue-level check (preferred): if both hosts exist in the database
       with Purdue levels assigned, fires when one end is Level 3+ (IT/
       operations) and the other is Level 1 or below (basic control / field),
       or (A-11) one end is Level 4+ (enterprise / internet) and the other
       is Level 2 - skipping both L3 and the L3.5 DMZ; that case is "high"
       instead of the check's default "critical". See _bypass_kind.

    2. Subnet heuristic fallback (when Purdue levels are unavailable):
       fires when src and dst are in *different* /16 (IPv6: /48) private
       blocks (_different_region) - medium, with a note that it needs
       confirmation. Different /16 blocks on a typical segmented network
       indicate different zones. This is explicitly a heuristic - it can false-positive on a
       flat network where OT and IT share a /8 with adjacent /24s, and it
       won't catch a bypass through a host with an unclassified level. The
       finding's detail flags which path fired and what the confidence is,
       so a reviewer knows whether Purdue classification data would be
       needed to confirm it.

    The fallback exists because the Purdue-level path silently produces
    nothing if the hosts haven't been ingested with classification data -
    first-run scenarios would surface zero findings from the most important
    check in the table. A heuristic finding that needs human confirmation
    is more useful than no finding at all.
    """
    if ev.log_type != "traffic" or not _is_permitted(ev.action):
        return None
    if not ev.src_ip or not ev.dst_ip:
        return None
    if not (_is_internal_ip(ev.src_ip) and _is_internal_ip(ev.dst_ip)):
        return None

    src_host = db.query(Host).filter(Host.ip == ev.src_ip).first()
    dst_host = db.query(Host).filter(Host.ip == ev.dst_ip).first()

    # --- Path 1: Purdue-level check (definitive) ---
    if src_host and dst_host:
        sl, dl = src_host.purdue_level, dst_host.purdue_level
        if sl is not None and dl is not None:
            kind = _bypass_kind(sl, dl)
            if kind is not None:
                return _make_finding(
                    db, "it_ot_bypass",
                    f"Direct IT↔OT session: {ev.src_ip} ({fmt_level(sl)}) → {ev.dst_ip} ({fmt_level(dl)})",
                    f"Traffic allowed directly between Level {sl} and Level {dl} without "
                    f"traversing the intermediate Purdue zones"
                    f"{'' if is_dmz(sl) or is_dmz(dl) else ' (DMZ / site operations)'}. "
                    f"Policy: {ev.policy_name or ev.policy_id}",
                    {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                     "policy_id": ev.policy_id, "src_level": sl, "dst_level": dl,
                     "detection": "purdue_level"},
                    forti_event_id=ev.id, device_name=ev.device_name,
                    severity=None if kind == "deep_ot" else "high",
                )
            return None  # both hosts classified but not a violation

    # --- Path 2: Subnet heuristic fallback ---
    # Only runs when one or both hosts lack Purdue classification, so this
    # doesn't double-fire when level data exists.
    try:
        # Different /16 (IPv4) or /48 (IPv6) block = clearly different
        # network regions (B-20: IPv6 / ULA handled, not split on ".").
        if _different_region(ev.src_ip, ev.dst_ip):
            plen = "/16" if ":" not in ev.src_ip else "/48"
            return _make_finding(
                db, "it_ot_bypass",
                f"Possible IT↔OT bypass (subnet heuristic): {ev.src_ip} → {ev.dst_ip}",
                f"Traffic between hosts in different {plen} subnets ({ev.src_ip} "
                f"and {ev.dst_ip}) was allowed. Purdue classification "
                f"data is not available for one or both hosts - this finding is heuristic "
                f"and requires manual confirmation. Ingest pcap/ARP data and run /classify "
                f"to enable definitive detection.",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                 "policy_id": ev.policy_id, "detection": "subnet_heuristic",
                 "src_classified": src_host is not None and src_host.purdue_level is not None,
                 "dst_classified": dst_host is not None and dst_host.purdue_level is not None,
                 "severity_reason": "Medium: subnet heuristic without Purdue levels - needs confirmation "
                                    "(critical once both hosts are classified and the crossing is real)."},
                forti_event_id=ev.id, device_name=ev.device_name,
                severity="medium",
            )
    except (IndexError, AttributeError):
        pass

    return None


def check_ot_internet_egress(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 5.1 RE2 / 3.7, 9.11, 9.12 — OT device reaching internet
    (including DNS, NTP, update services).

    Fires on any internal → public (globally routable) allowed session
    (B-20: IPv4/IPv6; internal = private / CGNAT / link-local / ULA).

    Severity depends on classification confidence:
    - critical: source is a confirmed L0-L2 OT host (Purdue level known)
    - high:     source host exists in the database but has no Purdue level
    - medium:   source IP has never been ingested at all

    The lower-severity variants still produce findings because "I don't
    know whether this is an OT device" is the wrong reason to suppress
    a finding about something reaching the internet from an OT-adjacent
    network segment. An unknown host on an OT network VLAN reaching the
    internet is exactly what 3.7 wants flagged.
    """
    if ev.log_type != "traffic" or not _is_permitted(ev.action):
        return None
    if not ev.src_ip or not ev.dst_ip:
        return None
    if not _is_internal_ip(ev.src_ip) or not _is_public_ip(ev.dst_ip):
        return None

    src_host = db.query(Host).filter(Host.ip == ev.src_ip).first()

    if src_host and src_host.purdue_level is not None:
        # H-13: site operations (L3) is OT too - no direct internet access
        if src_host.purdue_level > 3:
            return None  # confirmed IT host (L3.5 DMZ and up) - internet access is expected
        severity = "critical" if src_host.purdue_level <= 2 else "high"
        level_desc = f"{fmt_level(src_host.purdue_level)} OT device"
        classification_note = None
    elif src_host:
        severity = "high"
        level_desc = "host with no Purdue classification"
        classification_note = ("Source host is known but not yet Purdue-classified. "
                               "Run /classify after ingesting pcap/ARP data to confirm level.")
    else:
        severity = "medium"
        level_desc = "unrecognised host"
        classification_note = ("Source IP has not been seen in any pcap/ARP ingest. "
                               "Ingest network capture data to identify this host.")

    detail: dict = {
        "src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
        "service": ev.service, "policy_id": ev.policy_id, "severity_basis": severity,
    }
    if classification_note:
        detail["classification_note"] = classification_note

    return _make_finding(
        db, "ot_internet_egress",
        f"OT-network internet egress: {ev.src_ip} ({level_desc}) → {ev.dst_ip}:{ev.dst_port}",
        f"Host on OT-adjacent network is reaching an internet destination. "
        f"Service: {ev.service}. Policy: {ev.policy_name or ev.policy_id}.",
        detail,
        forti_event_id=ev.id, device_name=ev.device_name,
        severity=severity,
    )


def check_remote_access_bypass(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 1.13 / 4.1 — Remote access reaching a host other than the approved
    jump host(s) / remote-access gateway, or landing directly in a control zone.

    Previous implementation only checked destination ports 3389/22/23.
    FortiGate SSL-VPN tunnels terminate on port 443 (web mode) or a
    custom SSLVPN port, and IPsec shows up as ESP (protocol 50, ports
    500/4500) - neither appeared in the old port list, so those paths
    were completely invisible to this check.

    Detection paths in order of specificity:

    1. FortiGate VPN event logs (definitive): SSL-VPN / IPsec tunnel
       establishment landing anywhere but a jump host or a remote-access
       gateway.

    2. Traffic to known remote-access ports from non-RFC1918 source
       (RDP 3389, SSH 22, Telnet 23, HTTPS 443 from external, IPsec
       500/4500) to a host that is neither a jump host nor a gateway.
       2b: a gateway is declared but the external source reached a jump
       host directly (bypassing the gateway).

    3. Traffic landing directly in OT/control zones: any allowed session
       from a non-RFC1918 source to a Level 0-2 host, regardless of
       port, unless the destination is a jump host.

    Jump hosts and gateways are the same product-neutral labels the session
    fallback uses (app.parsers.remote_access: approved-host roles
    ``jump_host`` / ``remote_access_gateway``, ``Host.device_type`` /
    ``Host.role``).  Addresses are compared in canonical form.  Paths 2 and 3
    need at least one jump host; path 1 always fires.
    """
    if not ev.src_ip or not ev.dst_ip:
        return None

    jump_hosts = ra.jump_host_ips(db)
    gateways = ra.gateway_ips(db)
    dst = ra.canon_ip(ev.dst_ip)
    sanctioned = jump_hosts | gateways

    # Path 1: FortiGate VPN event (SSL-VPN tunnel up / IPsec SA established)
    if ev.log_type == "event" and ev.subtype in ("vpn", "ssl-vpn", "ipsec"):
        # Fire if the tunnel is landing somewhere other than a documented jump
        # host / gateway, or if we can't verify that at all
        if dst not in sanctioned:
            return _make_finding(
                db, "remote_access_bypass",
                f"VPN session not terminating on jump host: {ev.src_ip} → {ev.dst_ip}",
                f"VPN tunnel ({ev.subtype}) from {ev.src_ip} established to {ev.dst_ip}, "
                f"which is not an approved jump host or remote-access gateway "
                f"({', '.join(sorted(sanctioned)) if sanctioned else 'none defined'}). "
                f"All remote access should terminate in the DMZ at a jump host (check 4.1).",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
                 "vpn_type": ev.subtype, "policy_id": ev.policy_id,
                 "approved_jump_hosts": sorted(jump_hosts),
                 "gateways": sorted(gateways),
                 "detection": "vpn_event"},
                forti_event_id=ev.id, device_name=ev.device_name,
            )
        return None  # VPN to approved jump host / gateway - correct behaviour

    if ev.log_type != "traffic" or not _is_permitted(ev.action):
        return None

    src_external = _is_public_ip(ev.src_ip)

    # Path 2: Traffic to remote-access ports from external source
    RA_PORTS = {3389, 22, 23, 500, 4500}
    port_match = ev.dst_port in RA_PORTS
    # Port 443 only if from external (avoid flagging internal HTTPS)
    if ev.dst_port == 443 and src_external:
        port_match = True

    if port_match and src_external and jump_hosts:
        if gateways and dst in jump_hosts and dst not in gateways:
            # Path 2b: straight to the jump host although a gateway is declared
            return _make_finding(
                db, "remote_access_bypass",
                f"Remote access to jump host {ev.dst_ip}:{ev.dst_port} bypasses the "
                f"remote-access gateway",
                f"External source {ev.src_ip} reached jump host {ev.dst_ip} on port "
                f"{ev.dst_port} directly, but a remote-access gateway "
                f"({', '.join(sorted(gateways))}) is declared for this site. External "
                f"sessions must enter through the gateway, which authenticates and "
                f"records them, and reach the jump host from there (SR 1.13).",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                 "approved_jump_hosts": sorted(jump_hosts), "gateways": sorted(gateways),
                 "policy_id": ev.policy_id,
                 "detection": "external_to_jump_host_bypassing_gateway"},
                forti_event_id=ev.id, device_name=ev.device_name,
                severity="high",
            )
        if dst not in sanctioned:
            return _make_finding(
                db, "remote_access_bypass",
                f"Remote access direct to {ev.dst_ip}:{ev.dst_port} (not jump host)",
                f"Remote access protocol (port {ev.dst_port}) from external source {ev.src_ip} "
                f"reached a host other than the approved jump host(s) / gateway(s): "
                f"{', '.join(sorted(sanctioned))}.",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                 "approved_jump_hosts": sorted(jump_hosts), "gateways": sorted(gateways),
                 "policy_id": ev.policy_id,
                 "detection": "external_port_match"},
                forti_event_id=ev.id, device_name=ev.device_name,
            )

    # Path 3: Any external traffic landing directly on an OT host (L0-L2)
    if src_external and dst not in jump_hosts:
        dst_host = db.query(Host).filter(Host.ip == ev.dst_ip).first()
        if dst_host and dst_host.purdue_level is not None and dst_host.purdue_level <= 2:
            return _make_finding(
                db, "remote_access_bypass",
                f"External traffic direct to OT device: {ev.src_ip} → {ev.dst_ip}:{ev.dst_port} "
                f"({fmt_level(dst_host.purdue_level)})",
                f"Traffic from public source {ev.src_ip} landed directly on "
                f"a Level {dst_host.purdue_level} OT device {ev.dst_ip} rather than "
                f"terminating at a jump host in the DMZ.",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                 "dst_level": dst_host.purdue_level, "policy_id": ev.policy_id,
                 "detection": "external_to_ot_direct"},
                forti_event_id=ev.id, device_name=ev.device_name,
            )
    return None


def check_remote_access_app(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    NET 3.1 / 4.5 — Unauthorized remote access application detected
    (TeamViewer, AnyDesk, VNC, etc.).
    """
    if not ev.app:
        return None
    app_lower = ev.app.lower()
    for ra_app in _REMOTE_ACCESS_APPS:
        if ra_app in app_lower:
            return _make_finding(
                db, "remote_access_app",
                f"Remote access application detected: {ev.app} from {ev.src_ip} → {ev.dst_ip}",
                f"Unauthorized remote access tool '{ev.app}' was detected on the network. "
                f"Action: {ev.action}. Policy: {ev.policy_name or ev.policy_id}.",
                {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "app": ev.app,
                 "action": ev.action, "policy_id": ev.policy_id},
                forti_event_id=ev.id, device_name=ev.device_name,
                # A-14: one finding per application, not per (src, dst, policy).
                dedup_evidence={"src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
                                "policy_id": ev.policy_id, "ra_app": app_lower},
                legacy_dedup_evidence={"src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
                                       "policy_id": ev.policy_id},
            )
    return None


# FortiOS 7.x admin login events (owner 2026-10-13: "fix the auth failure check"):
# type=event subtype=system action="login" status="success|failed", logid
# 0100032001 (success) / 0100032002 (failed).  The outcome is in status=, not action=.
_FORTI_ADMIN_LOGIN_LOGIDS = {"0100032001": "success", "0100032002": "failed",
                             "32001": "success", "32002": "failed"}
_LOGIN_FAILED = ("failed", "failure", "blocked")


def _login_outcome(ev: FortiAnalyzerEvent) -> Optional[str]:
    """"failed" / "success" for a login event, None for anything else.

    Two shapes: subtype login / authentication with the outcome in action=
    (CEF, older FortiOS, the other vendors' parsers), and FortiOS 7.x
    subtype system with action="login" and the outcome in status= (or
    implied by the admin-login logid)."""
    if ev.log_type != "event":
        return None
    if ev.subtype in ("login", "authentication"):
        if ev.action in _LOGIN_FAILED:
            return "failed"
        if _is_permitted(ev.action) or ev.action == "success":
            return "success"
        return None
    raw = ev.raw_fields if isinstance(ev.raw_fields, dict) else {}
    by_logid = _FORTI_ADMIN_LOGIN_LOGIDS.get(str(raw.get("logid") or "").strip())
    if ev.action != "login" and by_logid is None:
        return None
    status = str(raw.get("status") or "").strip().lower()
    if status in _LOGIN_FAILED:
        return "failed"
    if status == "success":
        return "success"
    return by_logid


def check_auth_failure(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 1.11, 2.8 / 5.1, 9.5 — Admin login failures or logins from
    non-admin hosts.  Login events in either shape (see _login_outcome).
    """
    outcome = _login_outcome(ev)
    if outcome is None:
        return None
    if outcome == "failed":
        # window_hour limits dedup to one open finding per hour per
        # (src_ip, user, device). Without it the dedup key is permanent
        # and a second attack hours later would be silently suppressed.
        window_hour = ev.received_at.strftime("%Y-%m-%dT%H") if ev.received_at else "unknown"
        return _make_finding(
            db, "auth_failure",
            f"Authentication failure: {ev.user or ev.src_user or 'unknown'} from {ev.src_ip}",
            f"Failed login to {ev.device_name}. User: {ev.user or ev.src_user}. "
            f"Source: {ev.src_ip}.",
            {"src_ip": ev.src_ip, "user": ev.user or ev.src_user,
             "device_name": ev.device_name, "window_hour": window_hour},
            forti_event_id=ev.id, device_name=ev.device_name,
            # C-14: user is part of the identity (per the docstring above), so
            # two different users failing from one IP in one hour are distinct
            # findings instead of one that keeps overwriting whose login failed.
            dedup_evidence={"src_ip": ev.src_ip, "user": ev.user or ev.src_user,
                            "device_name": ev.device_name, "window_hour": window_hour},
        )
    # Login from a non-admin host — distinct check_name to avoid dedup collision
    # with the auth_failure path above (different root cause, different alert type).
    # Approved admin sources: baseline admin_ws / jump_host entries (IP or
    # CIDR) plus the declared management networks, trusted management hosts
    # and hosts on management VLANs (app.parsers.mgmt_networks).
    if outcome == "success" and ev.src_ip:
        from app.parsers.mgmt_networks import build_context as _mgmt_ctx
        with analysis_site(db, getattr(ev, "site_id", None)):
            mctx = _mgmt_ctx(db)
        # firewall admin login: management sources only (not engineering)
        admin_ips = [str(n) for n, _d, p in mctx.nets if p == "management"][:50]
        if mctx.has_mgmt_sources and not mctx.is_admin_ip(ev.src_ip):
            ts = ev.received_at or datetime.now(timezone.utc)
            window_day = ts.strftime("%Y-%m-%d")
            return _make_finding(
                db, "auth_from_non_admin_host",
                f"Admin login from non-admin host: {ev.src_ip}",
                f"Successful login from {ev.src_ip} which is not in the approved admin "
                f"workstation list ({', '.join(sorted(admin_ips))}).",
                {"src_ip": ev.src_ip, "user": ev.user or ev.src_user,
                 "approved_admin_hosts": sorted(admin_ips),
                 "device_name": ev.device_name, "window_day": window_day},
                forti_event_id=ev.id, device_name=ev.device_name,
                # A-14: per (source, target device, UTC day) - the old key
                # (src_ip only) suppressed every later login forever.
                dedup_evidence={"src_ip": ev.src_ip, "device_name": ev.device_name,
                                "window_day": window_day},
                legacy_dedup_evidence={"src_ip": ev.src_ip},
            )
    return None


# A-15: whole-word matching (substring matching fired on "addr", "address",
# "settings", "attempt", "fan" in "fanout", ...).
_CONFIG_CHANGE_RE = re.compile(
    r"\b(?:changed?|changes|edit(?:ed)?|add(?:ed)?|delete[d]?|modif(?:y|ied)|set)\b")
# FortiOS structured markers of a configuration change: logids
# 0100044544-0100044547 ("Path/Object/Attribute configured"), cfg* fields.
_FORTI_CONFIG_LOGIDS = {"0100044544", "0100044545", "0100044546", "0100044547",
                        "44544", "44545", "44546", "44547"}
_FORTI_CONFIG_ACTIONS = {"add", "edit", "delete", "set", "unset", "move",
                         "rename", "clone", "modify", "change"}
# AU full review B2: phrases, not single words - "temp" / "ha" / "fan" as
# whole words matched policy names such as TEMP-Allow-Vendor in a config-
# change event.  Matched against logdesc / msg only, never policy names.
_HA_SYSTEM_RE = re.compile(
    r"(?:\bha (?:failover|member|cluster|heartbeat|sync|state)\b|\bfailover\b|\bhigh-availability\b|"
    r"\bcpu usage\b|\bmem(?:ory)? usage\b|\bdisk usage\b|\bsystem error\b|\bhardware (?:error|failure)\b|"
    r"\bpower (?:supply|failure|loss)\b|\bpsu\b|\bfan (?:failure|speed|error)\b|\btemperature\b|"
    r"\boverheat(?:ing|ed)?\b|\bconserve mode\b|\bslave became master\b|\bmaster became slave\b)")
_HA_SUBTYPES = {"ha", "system-error", "hardware"}


def _event_tokens_text(ev: FortiAnalyzerEvent) -> str:
    """Lower-cased text of the event's raw field VALUES plus raw message,
    for whole-word keyword matching (field names like 'srcaddr' excluded)."""
    rf = ev.raw_fields if isinstance(ev.raw_fields, dict) else {}
    parts = [str(v) for v in rf.values() if v is not None]
    if not rf and ev.raw_fields:
        parts.append(str(ev.raw_fields))
    if ev.raw_message:
        parts.append(ev.raw_message)
    return " ".join(parts).lower()


def _is_config_change_event(ev: FortiAnalyzerEvent) -> bool:
    rf = ev.raw_fields if isinstance(ev.raw_fields, dict) else {}
    logid = str(rf.get("logid") or "").strip()
    if logid in _FORTI_CONFIG_LOGIDS:
        return True
    if any(rf.get(k) for k in ("cfgpath", "cfgobj", "cfgattr", "cfgtid")):
        return True
    if (ev.action or "").strip().lower() in _FORTI_CONFIG_ACTIONS:
        return True
    return bool(_CONFIG_CHANGE_RE.search(_event_tokens_text(ev)))


def _is_ha_system_event(ev: FortiAnalyzerEvent) -> bool:
    if (ev.subtype or "").strip().lower() in _HA_SUBTYPES:
        return True
    rf = ev.raw_fields if isinstance(ev.raw_fields, dict) else {}
    text = " ".join(str(rf.get(k) or "") for k in ("logdesc", "msg", "reason", "status")).lower()
    if not text and ev.raw_message and not rf:
        text = ev.raw_message.lower()
    return bool(_HA_SYSTEM_RE.search(text))


def check_fw_config_change(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """SR 2.8, SR 2.12 / 6.2 — Firewall configuration change.
    (SR 2.12 = audit log protection; SR 7.6 was incorrect — that is a
    change-control SPE requirement, not an audit-log SR.) (P4-M8)
    """
    if ev.log_type != "event":
        return None
    if ev.subtype not in ("config", "system"):
        return None
    if not _is_config_change_event(ev):
        return None
    return _make_finding(
        db, "fw_config_change",
        f"Firewall config change on {ev.device_name} by {ev.user or 'unknown'}",
        f"Configuration modification detected. User: {ev.user}. "
        f"Action: {ev.action}. Raw: {ev.raw_message[:200] if ev.raw_message else ''}",
        {"device_name": ev.device_name, "user": ev.user, "action": ev.action,
         # window_hour gives one open finding per firewall per hour of change activity;
         # a single audit session may generate many config events but shouldn't flood
         # the finding table.
         "window_hour": ev.received_at.strftime("%Y-%m-%dT%H") if ev.received_at else "unknown"},
        forti_event_id=ev.id, device_name=ev.device_name,
        # C-14: this check's identity has always been (device, hour) - `user`
        # and `action` are display-only. Pin the dedup evidence explicitly so
        # the new `user` hashing in _dedup_key does NOT silently split this
        # check per user (the key stays byte-identical to its prior value).
        dedup_evidence={"device_name": ev.device_name,
                        "window_hour": ev.received_at.strftime("%Y-%m-%dT%H")
                        if ev.received_at else "unknown"},
    )


_IPS_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    "info": "info", "information": "info", "informational": "info",
    "warning": "medium", "notice": "low", "alert": "critical", "emergency": "critical",
    "error": "high",
}


def _ips_severity(sev: Optional[str]) -> Optional[str]:
    """A-14: map an IPS event's severity onto the finding scale; None (use
    the CHECK_TYPE_REFERENCE default) when absent or unrecognised."""
    return _IPS_SEVERITY_MAP.get((sev or "").strip().lower())


def check_ips_ot_conduit(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """SR 6.2 / 3.12 — IPS events on OT conduits.

    FortiGate IPS logs arrive as log_type "ips" (CEF, classified by
    forti_parser) or, from key=value syslog / FortiAnalyzer, as
    type=utm subtype=ips - both are accepted.
    """
    lt = (ev.log_type or "").lower()
    st = (ev.subtype or "").lower()
    if not (lt == "ips" or (lt == "utm" and st == "ips")):
        return None
    return _make_finding(
        db, "ips_ot_conduit",
        f"IPS event on OT conduit: {ev.attack_name or 'unknown'} {ev.src_ip} → {ev.dst_ip}",
        f"IPS signature triggered on traffic crossing an OT conduit. "
        f"Attack: {ev.attack_name}. Severity: {ev.severity}. Policy: {ev.policy_name or ev.policy_id}.",
        {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "attack_name": ev.attack_name,
         "severity": ev.severity, "policy_id": ev.policy_id},
        forti_event_id=ev.id, device_name=ev.device_name,
        # A-14: severity follows the IPS event's own severity when known.
        severity=_ips_severity(ev.severity),
        # A-14: distinct signatures between the same hosts are distinct findings.
        dedup_evidence={"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "policy_id": ev.policy_id,
                        "ips_attack": ev.attack_name or ""},
        legacy_dedup_evidence={"src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
                               "policy_id": ev.policy_id},
    )


def check_unauth_ot_write(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 2.1, SR 3.5 / 8.4 — Industrial write/program ops from unapproved hosts.
    Detects via traffic-log port matching (fires even without a pcap capture).
    The complementary check in traffic_findings.py fires from actually-decoded
    ProtocolDetail write operations (more precise, requires a pcap).

    FAIL-OPEN DESIGN: if no ApprovedHost baseline has been loaded for
    engineering_ws/hmi roles, every OT protocol session is flagged. This
    matches traffic_findings.py's approach and is the right default: a
    silent pass when nothing is approved would produce a clean findings
    list that looks like verification but is actually nothing being checked.
    The finding's detail says plainly when this is why it fired.

    Previously this check returned None when no baseline existed, meaning
    the first thing a reviewer would see after a first-run ingest is zero
    findings from the most important OT-integrity check - opposite of
    what you want.
    """
    if ev.log_type != "traffic" or ev.dst_port not in {502, 20000, 44818, 102}:
        return None
    if not _is_permitted(ev.action):
        return None
    if not ev.src_ip:
        return None

    proto_map = {502: "Modbus/TCP", 20000: "DNP3", 44818: "EtherNet/IP", 102: "S7comm"}
    proto_name = proto_map.get(ev.dst_port, str(ev.dst_port))

    # Declared engineering sources (engineering networks / VLANs / trusted
    # engineering workstations) are approved alongside the baseline's
    # engineering_ws / hmi entries (app.parsers.mgmt_networks).
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    with analysis_site(db, getattr(ev, "site_id", None)):
        mctx = _mgmt_ctx(db)
    if mctx.is_engineering_ip(ev.src_ip):
        return None
    baseline = _active_baseline(db)
    if not baseline and not mctx.has_eng_sources:
        # Fail-open: flag everything, note why
        return _make_finding(
            db, "unauth_ot_write",
            f"OT protocol session - no baseline to validate: {ev.src_ip} → {ev.dst_ip}:{ev.dst_port} ({proto_name})",
            f"Host {ev.src_ip} is communicating on {proto_name} but no approved "
            f"engineering-workstation/HMI baseline has been loaded. All OT protocol "
            f"sessions are flagged until a baseline is available. "
            f"Load one via /ingest/baseline/approved-hosts.",
            {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
             "protocol": proto_name, "policy_id": ev.policy_id,
             "baseline_loaded": False},
            forti_event_id=ev.id, device_name=ev.device_name,
        )

    approved_ips = {
        h.ip for h in db.query(ApprovedHost).filter(
            ApprovedHost.baseline_id == baseline.id,
            ApprovedHost.role.in_(["engineering_ws", "hmi"]),
        ).all() if h.ip
    } if baseline else set()
    # declared engineering sources (the baseline's own rows are already above)
    approved_ips |= {str(n) for n, d, p in mctx.nets
                     if p == "engineering" and not d.startswith("baseline ")}

    if not approved_ips:
        # Baseline exists but no engineering_ws/hmi roles defined - still fail-open
        return _make_finding(
            db, "unauth_ot_write",
            f"OT protocol session - baseline has no engineering WS/HMI entries: "
            f"{ev.src_ip} → {ev.dst_ip}:{ev.dst_port} ({proto_name})",
            f"Host {ev.src_ip} is communicating on {proto_name} but the active baseline "
            f"contains no hosts with role engineering_ws or hmi. "
            f"Add approved hosts via /ingest/baseline/approved-hosts.",
            {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
             "protocol": proto_name, "policy_id": ev.policy_id,
             "baseline_loaded": True, "approved_engineering_hosts": 0},
            forti_event_id=ev.id, device_name=ev.device_name,
        )

    if ev.src_ip not in approved_ips and not _ip_in_any(ev.src_ip, approved_ips):
        return _make_finding(
            db, "unauth_ot_write",
            f"Unapproved host on OT protocol: {ev.src_ip} → {ev.dst_ip}:{ev.dst_port} ({proto_name})",
            f"Host {ev.src_ip} is not in the approved engineering workstation/HMI list, nor in a "
            f"declared engineering network, but is communicating with an OT device on "
            f"{proto_name}. Approved sources: {', '.join(sorted(approved_ips))}. If it is an "
            f"engineering workstation, add it as one (Findings > Fix).",
            {"src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
             "protocol": proto_name, "approved_hosts": sorted(approved_ips),
             "policy_id": ev.policy_id, "baseline_loaded": True},
            forti_event_id=ev.id, device_name=ev.device_name,
        )
    return None


def _ip_in_any(ip, entries) -> bool:
    """``ip`` inside any of the IP / CIDR ``entries`` (malformed ones skipped)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    for e in entries:
        try:
            net = ipaddress.ip_network(str(e).strip(), strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            return True
    return False


def check_scanning_denied(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 6.2, SR 7.1 / 8.8 — Scanning or anomalous traffic volumes.

    REPLACED APPROACH: the original check filtered on keywords like "scan"
    or "anomaly" in the FortiGate event subtype / raw fields. Those terms
    only appear when FortiGate's own DoS anomaly detection has already
    classified the traffic as a scan - at which point you already know
    about it through FortiGate's own alerting. That made this check
    effectively dead code on all normal FortiGate configurations.

    NEW APPROACH - two complementary paths:

    1. FortiGate anomaly events (real-time, definitive): the original
       keyword check is kept as a fast path for events that FortiGate has
       already classified as anomalous (scan/flood/sweep). These are high-
       confidence and can be acted on immediately.

    2. Sliding-window deny counter (real-time, heuristic): counts denied
       traffic events from the same source IP within a 5-minute window.
       A source generating > SCAN_DENY_THRESHOLD denials within that window
       is flagged. This catches port scans and host sweeps that FortiGate's
       own anomaly detection hasn't classified, which is the common case.
       Uses the FortiAnalyzerEvent table as the window store.

    The periodic review `review_denied_trends` is the third path - it
    aggregates the full FortiAnalyzerEvent history for pattern analysis
    across longer time windows (days/weeks), separate from this real-time
    check.
    """
    if ev.log_type not in ("traffic", "utm", "ips"):
        return None
    if ev.action not in ("deny", "blocked", "drop", "reset"):
        return None
    if not ev.src_ip:
        return None

    # T3-15: every time reference is the EVENT's own log timestamp
    # (event_time), falling back to received_at (DB insert time) only when the
    # log carried no parseable timestamp. Keying on received_at put hours of
    # denies from an uploaded historical log file into one 5-minute window
    # (they were all inserted within seconds) and raised false scan findings.
    _ev_ts = ev.event_time or ev.received_at

    # Path 1: FortiGate has already classified this as anomalous (fast path)
    subtypes = str(ev.subtype or "").lower()
    raw = str(ev.raw_fields).lower()
    if any(w in subtypes + raw for w in ("scan", "anomaly", "flood", "sweep", "dos")):
        # Dedup key: one Finding per source IP per (event) hour across anomaly events
        event_hour = _ev_ts.strftime("%Y-%m-%dT%H") if _ev_ts else "unknown"
        return _make_finding(
            db, "scanning_denied",
            f"FortiGate anomaly event from {ev.src_ip}",
            f"FortiGate classified traffic from {ev.src_ip} as anomalous. "
            f"Subtype: {ev.subtype}. Target: {ev.dst_ip}:{ev.dst_port}.",
            {"src_ip": ev.src_ip,
             "window_hour": event_hour,
             "subtype": ev.subtype,
             "detection": "fortigate_anomaly_event"},
            forti_event_id=ev.id, device_name=ev.device_name,
        )

    # Path 2: sliding-window deny counter
    SCAN_DENY_THRESHOLD = 20       # denials from one source in the window
    SCAN_WINDOW_MINUTES = 5

    window_start = _ev_ts - timedelta(minutes=SCAN_WINDOW_MINUTES) if _ev_ts else None

    if window_start:
        # Single COUNT(*) aggregate. The window is bounded on the same
        # "event time, else insert time" expression used for _ev_ts, so a
        # historical file is windowed by when its events happened, and rows
        # without a log timestamp still count by insert time. (P4-M1, T3-15)
        from sqlalchemy import func as sa_func
        ts_col = sa_func.coalesce(FortiAnalyzerEvent.event_time, FortiAnalyzerEvent.received_at)
        recent_deny_count = db.query(sa_func.count(FortiAnalyzerEvent.id)).filter(
            FortiAnalyzerEvent.src_ip == ev.src_ip,
            FortiAnalyzerEvent.action.in_(["deny", "blocked", "drop", "reset"]),
            ts_col >= window_start,
            ts_col <= _ev_ts,
        ).scalar()

        if recent_deny_count >= SCAN_DENY_THRESHOLD:
            # Dedup key: one Finding per source IP per hour so a storm of
            # 100 denied events from one scanner doesn't produce 100 rows.
            # window_hour is hour-truncated ISO string from the EVENT timestamp,
            # e.g. "2026-09-27T14". Using _ev_ts (not window_start) ensures
            # two events spanning a 5-min boundary within the same clock-hour share
            # the same dedup slot rather than landing in adjacent hours.
            window_hour = _ev_ts.strftime("%Y-%m-%dT%H") if _ev_ts else "unknown"
            return _make_finding(
                db, "scanning_denied",
                f"Scanning detected: {ev.src_ip} ({recent_deny_count} denials in {SCAN_WINDOW_MINUTES} min)",
                f"Source {ev.src_ip} generated {recent_deny_count} denied connections within "
                f"{SCAN_WINDOW_MINUTES} minutes (threshold: {SCAN_DENY_THRESHOLD}). "
                f"Most recent target: {ev.dst_ip}:{ev.dst_port}.",
                {"src_ip": ev.src_ip,
                 "window_hour": window_hour,
                 "deny_count_in_window": recent_deny_count,
                 "window_minutes": SCAN_WINDOW_MINUTES,
                 "threshold": SCAN_DENY_THRESHOLD,
                 "detection": "sliding_window_count"},
                forti_event_id=ev.id, device_name=ev.device_name,
            )
    return None


_LOG_SILENCE_RE = re.compile(
    r"\blog stopped\b|\bconnection lost\b|\bdevice offline\b|\bno logs?\b"
    r"|\blogd\b"                                   # the logging daemon (not logdesc)
    r"|\blogging (?:has been |was |is )?(?:stopped|disabled|turned off)\b"
    r"|\b(?:disable[sd]?|stopped) logging\b"
)


def check_log_silence(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """
    SR 6.1, SR 2.9 / 6.3 — Log volume dropping to zero per device.
    FortiAnalyzer can generate a "logd" event with action "dropped" or
    a device-offline event when a managed device stops sending logs.
    (SR 6.1 = security audit logging; SR 2.10 was incorrect — that is
    audit non-repudiation, not log-silence monitoring.) (P4-M9)
    """
    if ev.log_type != "event":
        return None
    # B-19: match on field VALUES (never key names - every FortiGate event log
    # carries a ``logdesc`` key, which contains the substring "logd") and use
    # word-boundary patterns, so ``logd`` only matches the logging daemon
    # itself, not ``logdesc`` / ``logdesc="..."`` or other words.
    rf = ev.raw_fields
    vals = [str(v) for v in rf.values()] if isinstance(rf, dict) else [str(rf or "")]
    kw = " ".join([ev.subtype or "", *vals]).lower()
    if not _LOG_SILENCE_RE.search(kw):
        return None
    return _make_finding(
        db, "log_silence",
        f"Log silence detected from {ev.device_name}",
        f"Device {ev.device_name} appears to have stopped sending logs. "
        f"Event: {ev.raw_message[:200] if ev.raw_message else ''}",
        {"device_name": ev.device_name},
        forti_event_id=ev.id, device_name=ev.device_name,
    )


def check_ha_system_error(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """SR 7.1, 7.2 / 7.4 — HA failover or system/hardware error."""
    if ev.log_type != "event":
        return None
    if not _is_ha_system_event(ev):
        return None
    return _make_finding(
        db, "ha_system_error",
        f"HA or system error on {ev.device_name}",
        f"High-availability or system health event detected on {ev.device_name}. "
        f"Subtype: {ev.subtype}. Detail: {ev.raw_message[:200] if ev.raw_message else ''}",
        {"device_name": ev.device_name, "subtype": ev.subtype,
         # one finding per device, subtype and hour (B2: a device-only key
         # let one event swallow every later HA event of the device)
         "window_hour": ev.received_at.strftime("%Y-%m-%dT%H") if ev.received_at else "unknown",
         "kind": (ev.subtype or "system").strip().lower()},
        forti_event_id=ev.id, device_name=ev.device_name,
    )


def check_ha_failover(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[Finding]:
    """SR 7.1, 7.2 / 7.4 — HA failover detected (B-12).

    The device registry tracks which member of a registered HA cluster
    logged each event (app.site_devices.track_member_activity).  For an
    active-passive (a-p) cluster, a change of the ACTIVE member (traffic now
    logged by another member serial, or an FGCP "member state moved" log
    naming a new primary) raises one low finding per device, new primary
    and hour.  Active-active clusters (both members log traffic) never
    raise it.  Site-scoped: the device must belong to the event's site.
    """
    from app.site_devices import track_member_activity
    fo = track_member_activity(db, ev)
    if not fo:
        return None
    dev = fo["device"]
    at = fo["at"]
    window = at.strftime("%Y-%m-%dT%H") if at else "unknown"
    evidence = {"device_name": dev.device_name, "site_device_id": dev.id,
                "ha_mode": dev.ha_mode, "ha_group_name": dev.ha_group_name,
                "from_serial": fo["from_serial"], "to_serial": fo["to_serial"],
                "detected_via": fo["via"], "window_hour": window}
    return _make_finding(
        db, "ha_failover",
        f"HA failover detected on {dev.device_name}: {fo['from_serial']} -> {fo['to_serial']}",
        f"The active member of HA cluster {dev.device_name} (mode {dev.ha_mode}, group "
        f"{dev.ha_group_name or '-'}) changed from {fo['from_serial']} to {fo['to_serial']} "
        f"({'HA member state log' if fo['via'] == 'ha_state_log' else 'traffic now logged by the other member'}). "
        "Confirm the failover was planned or investigate why the primary failed.",
        evidence,
        forti_event_id=ev.id, device_name=dev.device_name,
        dedup_evidence={"site_device_id": dev.id, "to_serial": fo["to_serial"],
                        "window_hour": window},
    )


# ---------------------------------------------------------------------------
# REAL-TIME DISPATCH
# ---------------------------------------------------------------------------

def _event_site_id(ev: FortiAnalyzerEvent, db: DBSession) -> Optional[int]:
    """Site of a real-time event: its own site_id, else the ingest site
    bound to the session (pending, not yet flushed event)."""
    sid = getattr(ev, "site_id", None)
    if sid is None:
        from app.sites import current_ingest_site_id
        sid = current_ingest_site_id(db)
    return sid


def _event_scoped(fn):
    """Real-time check decorator: run inside the event's site scope so the
    check only sees that site's hosts / baselines / approved hosts / events."""
    import functools

    @functools.wraps(fn)
    def wrapper(ev, db, *a, **kw):
        with analysis_site(db, _event_site_id(ev, db)):
            return fn(ev, db, *a, **kw)
    return wrapper


for _n in ("check_it_ot_bypass", "check_ot_internet_egress", "check_remote_access_bypass",
           "check_remote_access_app", "check_auth_failure", "check_fw_config_change",
           "check_ips_ot_conduit", "check_unauth_ot_write", "check_scanning_denied",
           "check_log_silence", "check_ha_system_error"):
    globals()[_n] = _event_scoped(globals()[_n])
del _n

_RT_CHECKS = [
    check_it_ot_bypass,
    check_ot_internet_egress,
    check_remote_access_bypass,
    check_remote_access_app,
    check_auth_failure,
    check_fw_config_change,
    check_ips_ot_conduit,
    check_unauth_ot_write,
    check_scanning_denied,
    check_log_silence,
    check_ha_system_error,
    check_ha_failover,
]


def _run_isolated(db: DBSession, label: str, fn, *args, **kwargs) -> tuple[bool, object]:
    """Run fn(*args, **kwargs) inside a SAVEPOINT (T3-16/T3-17).

    Returns (True, result) on success. On any exception the savepoint is
    rolled back - discarding only this call's writes, and on PostgreSQL
    clearing the "current transaction is aborted" state so later work and
    the caller's commit still succeed - the escalation counter is restored to
    its value before the call (the escalated rows were rolled back too), the
    traceback is logged once, and (False, None) is returned.
    """
    before = db.info.get(_ESCALATION_COUNTER_KEY, 0)
    sp = db.begin_nested()
    try:
        result = fn(*args, **kwargs)
        sp.commit()  # flushes this call's pending writes inside the savepoint
        return True, result
    except Exception:
        try:
            sp.rollback()
        except Exception:  # pragma: no cover - session already unusable
            log.exception("%s: savepoint rollback failed", label)
        db.info[_ESCALATION_COUNTER_KEY] = before
        log.error("%s raised an exception (rolled back):\n%s", label, traceback.format_exc())
        return False, None


def evaluate_event(ev: FortiAnalyzerEvent, db: DBSession) -> list:
    """
    Run all real-time checks against one FortiAnalyzerEvent. Returns
    the list of Finding objects created (may be empty). Caller commits.

    Failure isolation (T3-16): a check that raises - including a database
    error, which on PostgreSQL would otherwise abort the whole transaction
    and make every later check and the caller's commit fail - rolls back
    only its own writes and is logged; the other checks still run and their
    findings are kept.

    N-17: the common (no-failure) path runs ALL checks inside ONE savepoint
    (2 statements per event instead of 2 x 11). Only if that savepoint
    fails is it rolled back - discarding every check's writes and restoring
    the escalation counter - and the checks re-run one by one, each in its
    own savepoint (_run_isolated), giving exactly the per-check isolation
    semantics above. Checks are pure functions of (event, database state),
    so the re-run reproduces the successful checks' findings.
    """
    with analysis_site(db, _event_site_id(ev, db)):
        return _evaluate_event(ev, db)


def _evaluate_event(ev: FortiAnalyzerEvent, db: DBSession) -> list:
    ev_id = getattr(ev, "id", "?")
    checks = list(_RT_CHECKS)
    before = db.info.get(_ESCALATION_COUNTER_KEY, 0)
    sp = db.begin_nested()
    try:
        alerts = [a for a in (fn(ev, db) for fn in checks) if a]
        sp.commit()
        return alerts
    except Exception as exc:
        try:
            sp.rollback()
        except Exception:  # pragma: no cover - session already unusable
            log.exception("evaluate_event: combined savepoint rollback failed (event id=%s)", ev_id)
        db.info[_ESCALATION_COUNTER_KEY] = before
        log.warning(
            "evaluate_event: a real-time check failed for event id=%s (%s); "
            "re-running the checks one savepoint each", ev_id, type(exc).__name__,
        )

    alerts = []
    for check_fn in checks:
        ok, alert = _run_isolated(
            db, f"Alert check {check_fn.__name__} (event id={ev_id})", check_fn, ev, db,
        )
        if ok and alert:
            alerts.append(alert)
    return alerts


# ---------------------------------------------------------------------------
# 5 PERIODIC REVIEW FUNCTIONS
# ---------------------------------------------------------------------------

def _approved_entry_matcher(e: ApprovedCommsEntry):
    """Pre-parse one ApprovedCommsEntry for session matching (N-15):
    (src spec, dst spec, port range or None=any, protocol tcp/udp/any).
    Returns None when either address is unresolvable (a named object the
    baseline import could not expand never approves anything)."""
    from app.parsers import rule_match as rm
    src = rm.parse_address(e.src)
    dst = rm.parse_address(e.dst)
    if isinstance(src, rm.Unresolved) or isinstance(dst, rm.Unresolved):
        return None
    proto = (e.protocol or "any").strip().lower() or "any"
    return src, dst, _approved_entry_range(e), proto


def _flow_approved(matchers: list, src_ip: str, dst_ip: str,
                   dst_port: Optional[int], transport: Optional[str]) -> bool:
    """True when some approved entry covers the observed flow: src IP in the
    entry's src, dst IP in its dst, dst_port within its range (entry
    dst_port None = any port; a session without a dst_port is only covered
    by an any-port entry) and protocol any or equal to the transport."""
    from app.parsers import rule_match as rm
    t = (transport or "").strip().lower()
    for src, dst, rng, proto in matchers:
        if proto not in ("any", "", "ip", "all") and proto != t:
            continue
        if rng is not None:
            if dst_port is None or not (rng[0] <= int(dst_port) <= rng[1]):
                continue
        if rm.ip_in_addr(src_ip, src) and rm.ip_in_addr(dst_ip, dst):
            return True
    return False


def review_conduit_matrix_drift(db: DBSession, _diff: Optional[dict] = None) -> list:
    """
    SR 5.2, ZCR 3 / 8.1, 8.2 — True session-vs-baseline drift (N-15).

    Compares observed NetworkSession traffic (src/dst host IP, dst_port,
    transport) against the ACTIVE baseline's ApprovedCommsEntry set: an
    entry covers a flow when the src/dst IPs fall inside its src/dst
    (CIDR, bare IP, range or any), the dst_port is within
    [dst_port, dst_port_end] (dst_port None = any port) and its protocol is
    "any" or equals the session transport. Every flow - one finding per
    (src_ip, dst_ip, dst_port, transport) per baseline - that no entry
    covers is drift from the approved communications matrix. Occurrence
    information (session count, packets, first/last seen) is in evidence.

    No active baseline, or an active baseline with no approved entries, =
    nothing to compare against: no findings, and the run is marked
    incomplete so open drift findings are not auto-resolved.

    ("SR 8.1, 8.2" was wrong — those numbers are checklist row IDs, not
    ISA/IEC 62443-3-3 SR numbers. The correct SRs are SR 5.2 and ZCR 3.) (P4-I1)

    The previous behaviour of this check (sessions with no permitting
    firewall rule, via topology_diff) is review_session_no_permitting_rule.
    _diff is accepted (and ignored) for call compatibility.
    """
    from sqlalchemy import func

    active = _active_baseline(db)
    if not active:
        _mark_incomplete(db, "no active baseline")
        return []
    entries = db.query(ApprovedCommsEntry).filter(
        ApprovedCommsEntry.baseline_id == active.id,
    ).all()
    if not entries:
        _mark_incomplete(db, "active baseline has no approved comms entries")
        return []
    matchers = [m for m in (_approved_entry_matcher(e) for e in entries) if m is not None]

    src_h = aliased(Host)
    dst_h = aliased(Host)
    flows = (
        db.query(
            src_h.ip, dst_h.ip, NetworkSession.dst_port, NetworkSession.transport,
            func.count(NetworkSession.id), func.sum(NetworkSession.packet_count),
            func.min(NetworkSession.first_seen), func.max(NetworkSession.last_seen),
            func.min(NetworkSession.id),
            func.min(NetworkSession.protocol), func.max(NetworkSession.protocol),
            func.min(src_h.purdue_level), func.min(dst_h.purdue_level),
            func.min(NetworkSession.src_port),   # C-01: representative src port
        )
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
        .filter(src_h.ip.isnot(None), dst_h.ip.isnot(None))
        .group_by(src_h.ip, dst_h.ip, NetworkSession.dst_port, NetworkSession.transport)
        .all()
    )
    if not flows:
        _mark_incomplete(db, "no observed sessions")
        return []

    def _iso(v):
        return v.isoformat() if isinstance(v, datetime) else v

    alerts = []
    for (src_ip, dst_ip, dst_port, transport, n_sess, packets, first_seen, last_seen,
         sample_id, proto_lo, proto_hi, src_lvl, dst_lvl, src_port_rep) in flows:
        # C-01: compare and key against the canonical (client, server,
        # server_port) identity. A capture of the return half of an approved
        # IT->OT:502 flow (or a mid-stream capture on an ephemeral port) would
        # otherwise be flagged as drift and keyed separately from the flow
        # itself; canonicalising collapses them onto one identity.
        c_ip, s_ip, s_port = canonical_flow(src_ip, src_port_rep, dst_ip, dst_port)
        if c_ip != src_ip:                        # orientation flipped
            src_lvl, dst_lvl = dst_lvl, src_lvl
        src_ip, dst_ip, dst_port = c_ip, s_ip, s_port
        if _flow_approved(matchers, src_ip, dst_ip, dst_port, transport):
            continue
        t = (transport or "").lower() or None
        protocols = sorted({p for p in (proto_lo, proto_hi) if p})
        port_txt = "any" if dst_port is None else dst_port
        evidence = {
            "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
            "transport": t, "protocol": ", ".join(protocols) or None,
            "src_purdue_level": src_lvl, "dst_purdue_level": dst_lvl,
            "session_count": int(n_sess or 0), "packet_count": int(packets or 0),
            "first_seen": _iso(first_seen), "last_seen": _iso(last_seen),
            "sample_session_id": sample_id,
            "baseline_id": active.id, "baseline_name": active.name,
            "approved_entries": len(entries),
        }
        alerts.append(_make_finding(
            db, "conduit_matrix_drift",
            f"Traffic outside approved comms matrix: {src_ip} → {dst_ip}:{port_txt}/{t or '?'}",
            f"Observed traffic {src_ip} → {dst_ip} on {t or 'unknown transport'} port "
            f"{port_txt} ({int(n_sess or 0)} session(s), {int(packets or 0)} packets, "
            f"last seen {_iso(last_seen)}) is not covered by any ApprovedCommsEntry of "
            f"active baseline #{active.id} '{active.name}'. Either the flow is an "
            f"undocumented requirement that must be added to the approved communications "
            f"matrix (ZCR 3) or it is unapproved cross-zone traffic (SR 5.2).",
            evidence,
            session_id=sample_id,
            dedup_evidence={"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                            "baseline_id": active.id, "flow_transport": t or "none"},
        ))
    return [a for a in alerts if a]


def review_session_no_permitting_rule(db: DBSession, _diff: Optional[dict] = None) -> list:
    """
    SR 5.2 / 8.1, 8.2 — Observed sessions the configured firewall policy
    does not permit (no permitting rule / explicit or implicit deny /
    unresolved rule), via topology_diff.compute_diff. This was
    review_conduit_matrix_drift's behaviour before N-15 moved that check to
    a true baseline comparison; kept under its own check_name.

    _diff: pre-computed topology diff (shared with review_unused_policies
    to avoid loading all NetworkSession rows twice per run_periodic_reviews).
    """
    from app.parsers.topology_diff import compute_diff
    diff = _diff if _diff is not None else compute_diff(db)
    if diff.get("sessions_truncated"):
        _mark_incomplete(db, "topology diff truncated the session set")
        _record_truncation(db, "topology diff sessions",
                           max(0, int(diff.get("sessions_total") or 0)
                               - int(diff.get("sessions_evaluated") or 0)))
    if not diff.get("sessions_considered"):
        _mark_incomplete(db, "no observed sessions")
    # C-08: with NO firewall policy loaded at all, every observed session is
    # trivially "no matching permit". Emitting a medium finding per flow is a
    # false-positive storm against a data gap, not a set of real violations.
    # Mark the review incomplete (so existing open findings are preserved, not
    # auto-resolved) and emit nothing per flow. Behaviour is unchanged once
    # >=1 rule exists. Done AFTER the truncation/no-session bookkeeping above so
    # those incomplete reasons are still surfaced. A pre-built _diff lacking the
    # key (older fixtures) is treated as "policy present" so their explicit
    # unexpected_traffic still reports.
    if "firewall_rules_total" in diff and not diff.get("firewall_rules_total"):
        _mark_incomplete(db, "no firewall policy loaded")
        return []
    alerts = []
    for session_summary in diff.get("unexpected_traffic", []):
        alerts.append(_make_finding(
            db, "session_no_permitting_rule",
            f"Traffic with no permitting firewall rule: {session_summary['src_ip']} → "
            f"{session_summary['dst_ip']}:{session_summary['dst_port']}",
            f"Observed session is not permitted by the configured firewall policy "
            f"(reason: {session_summary.get('reason_code', 'no_matching_permit')}). "
            f"Protocol: {session_summary.get('protocol')}.",
            session_summary,
            session_id=session_summary.get("session_id"),
        ))
    return [a for a in alerts if a]


def review_unused_policies(db: DBSession, _diff: Optional[dict] = None) -> list:
    """
    SR 3.8 / 3.8 — Firewall permit rules never matched by any observed
    session. These are candidates for removal.

    _diff: pre-computed topology diff (shared with review_session_no_permitting_rule).
    """
    from app.parsers.topology_diff import compute_diff
    diff = _diff if _diff is not None else compute_diff(db)
    if diff.get("sessions_truncated"):
        _mark_incomplete(db, "topology diff truncated the session set")
        _record_truncation(db, "topology diff sessions",
                           max(0, int(diff.get("sessions_total") or 0)
                               - int(diff.get("sessions_evaluated") or 0)))
    # AU full review B4: with no traffic evidence at all (no sessions and no
    # rule hit from the logs) EVERY permit is "unused" - a data gap, not a
    # finding storm (the C-08 rule of session_no_permitting_rule).
    if not int(diff.get("sessions_considered") or 0) and not db.query(FirewallRule.id).filter(
            FirewallRule.last_matched.isnot(None)).first():
        _mark_incomplete(db, "no observed sessions and no rule hits: policy use cannot be judged")
        return []
    unused = {u.get("rule_id"): u for u in diff.get("unused_rules", []) if u.get("rule_id") is not None}
    # A-09: rows the diff could not resolve (named objects, unparseable
    # ports) were never evaluated for use - keep their logical rule's open
    # finding instead of letting auto-resolve close it.
    unresolvable = [u.get("rule_id") for u in diff.get("unresolvable_rules", [])
                    if u.get("rule_id") is not None]
    if unresolvable:
        for r in db.query(FirewallRule).filter(FirewallRule.id.in_(unresolvable)):
            fw_id, _fd, device, _ident = gk = _rule_group_key(r)
            _mark_rule_unevaluated(db, _group_rule_key(gk), fw_id, device)
    if not unused:
        return []

    # One finding per LOGICAL rule, keyed on a stable rule identity (same key
    # as the rule-twin and disabled-rule checks) so a config re-ingest - which
    # recreates FirewallRule rows with new ids - neither duplicates the
    # finding nor closes/reopens it (which used to drop acknowledgements).
    # A logical rule is unused only if NONE of its expanded rows matched.
    seed_rows = db.query(FirewallRule).filter(FirewallRule.id.in_(list(unused))).all()
    scopes = {(r.firewall_id, r.firewall_device_id, r.device_name) for r in seed_rows}
    groups: dict[tuple, list] = {}
    for fw_id, fd_id, dev in scopes:
        q = db.query(FirewallRule).filter(
            FirewallRule.enabled.is_(True),
            FirewallRule.action.in_(("permit", "allow", "accept")),
            (FirewallRule.firewall_id == fw_id) if fw_id is not None else FirewallRule.firewall_id.is_(None),
            (FirewallRule.firewall_device_id == fd_id) if fd_id is not None else FirewallRule.firewall_device_id.is_(None),
            (FirewallRule.device_name == dev) if dev is not None else FirewallRule.device_name.is_(None),
        )
        for r in q.order_by(FirewallRule.id):
            groups.setdefault(_rule_group_key(r), []).append(r)

    from app.parsers.nat_sessions import snat_rule_ids_seen
    nat_seen = snat_rule_ids_seen(db)
    alerts = []
    for key, rows in groups.items():
        if not all(r.id in unused for r in rows):
            continue  # some expansion of this rule did carry traffic
        if any(str(r.policy_id or "").startswith("implicit:") for r in rows):
            continue  # implicit permits (security levels / switch routing): own checks
        if nat_seen and any(r.id in nat_seen for r in rows):
            continue  # P-06: its source-NAT'd traffic is in the capture
        if any(getattr(r, "src_identity", None) for r in rows):
            # H-10: an identity-based rule (user groups) matches by user, which
            # a capture does not show - an earlier rule with the same addresses
            # for other users takes the session in the IP-only evaluation.
            continue
        first = rows[0]
        summaries = [unused[r.id] for r in rows]
        last_matched = max((u.get("last_matched") for u in summaries if u.get("last_matched")), default=None)
        evidence = {
            "rule_key":          _group_rule_key(key),
            "rule_id":           first.id,              # kept for UI links / old consumers
            "firewall_rule_ids": [r.id for r in rows],
            "expanded_rows":     len(rows),
            "firewall_id":       first.firewall_id,
            "firewall_device_id": first.firewall_device_id,
            "device_name":       first.device_name,
            "policy_id":         first.policy_id,
            "policy_name":       first.policy_name,
            "src":               _uniq_join(r.src for r in rows),
            "dst":               _uniq_join(r.dst for r in rows),
            "protocol":          _uniq_join(r.protocol for r in rows),
            "dst_port":          _uniq_join(r.dst_port for r in rows),
            "last_matched":      last_matched,
        }
        label = _group_label(rows)
        alerts.append(_make_finding(
            db, "unused_policy",
            f"Unused firewall rule: {label}",
            f"Permit rule {label} ({evidence['src']} → {evidence['dst']}:{evidence['dst_port']}) "
            f"has not been matched by observed traffic or rule-hit logs "
            f"{'since ' + str(last_matched) if last_matched else 'in the current dataset'}. "
            f"Review for removal.",
            evidence,
            firewall_rule_id=first.id,
            device_name=first.device_name,
            dedup_evidence=_group_dedup_evidence(key, rows),
        ))
    return [a for a in alerts if a]


def _flow_sessions(db: DBSession, filters: list, label: str = "",
                   join_src_host: bool = False):
    """A-17: one representative NetworkSession per distinct flow
    (src_host, dst_host, dst_port, transport), aggregated in SQL (GROUP BY),
    in deterministic order. The representative is the flow's lowest session id.

    B-06: EVERY flow is evaluated (the old 5 000-flow cap silently dropped
    the rest). Only the (rep_id, packets) integer pairs are held for all
    flows; the session objects are loaded and yielded in batches of 500.
    Yields (session, total_packets)."""
    q = db.query(
        func.min(NetworkSession.id).label("rep_id"),
        func.sum(NetworkSession.packet_count).label("pkts"),
    )
    if join_src_host:
        q = q.join(Host, Host.id == NetworkSession.src_host_id)
    grp = (NetworkSession.src_host_id, NetworkSession.dst_host_id,
           NetworkSession.dst_port, NetworkSession.transport)
    rows = [(r.rep_id, int(r.pkts or 0))
            for r in q.filter(*filters).group_by(*grp).order_by(*grp).all()]
    for i in range(0, len(rows), 500):
        chunk = rows[i:i + 500]
        by_id = {
            sess.id: sess
            for sess in (db.query(NetworkSession)
                         .filter(NetworkSession.id.in_([c[0] for c in chunk]))
                         .options(joinedload(NetworkSession.src_host),
                                  joinedload(NetworkSession.dst_host)))
        }
        for rep_id, pkts in chunk:
            if rep_id in by_id:
                yield by_id[rep_id], pkts


def review_denied_trends(db: DBSession) -> list:
    """
    SR 3.1 / 3.1 — Summarise denied-traffic patterns by source IP for
    human review. Produces info-level alerts that are more 'periodic
    report item' than 'incident', aggregating the raw deny events.

    Only considers events from the last DENIED_TRENDS_DAYS days to avoid
    loading the full event history on large deployments.
    """
    DENIED_TRENDS_DAYS = 90
    # Use tz-aware UTC to match the utcnow() helper in models.py, which
    # stores datetime.now(timezone.utc). Mixing naive and aware datetimes
    # causes a TypeError on comparison. datetime.utcnow() was used here
    # previously, which is naive and incompatible.
    cutoff = datetime.now(timezone.utc) - timedelta(days=DENIED_TRENDS_DAYS)

    # Cap at 10 000 rows to prevent loading the entire event history into
    # memory on busy deployments. The aggregation below still surfaces
    # the most active sources even with a partial load.
    # A-17: aggregate per (src_ip, dst_port) in SQL before the limit, in a
    # deterministic order, instead of loading the latest 10 000 raw events.
    rows = db.query(
        FortiAnalyzerEvent.src_ip, FortiAnalyzerEvent.dst_port,
        func.count(FortiAnalyzerEvent.id).label("n"),
        func.min(FortiAnalyzerEvent.device_name).label("dev"),
    ).filter(
        FortiAnalyzerEvent.action.in_(["deny", "blocked", "drop"]),
        FortiAnalyzerEvent.log_type == "traffic",
        FortiAnalyzerEvent.received_at >= cutoff,
        FortiAnalyzerEvent.src_ip.isnot(None),
    ).group_by(FortiAnalyzerEvent.src_ip, FortiAnalyzerEvent.dst_port).order_by(
        FortiAnalyzerEvent.src_ip, FortiAnalyzerEvent.dst_port,
    ).all()  # B-06: all groups (two small columns each; linear) - no silent cap

    by_src: dict = {}
    for r in rows:
        agg = by_src.setdefault(r.src_ip, {"n": 0, "ports": set(), "dev": r.dev})
        agg["n"] += int(r.n or 0)
        if r.dst_port:
            agg["ports"].add(r.dst_port)

    alerts = []
    for src_ip, agg in sorted(by_src.items(), key=lambda x: (-x[1]["n"], x[0])):
        events_n = agg["n"]
        if events_n < 5:
            continue
        dst_ports = sorted(agg["ports"])
        alerts.append(_make_finding(
            db, "denied_trend",
            f"Denied traffic trend: {src_ip} ({events_n} denies to {len(dst_ports)} ports)",
            f"Source {src_ip} generated {events_n} denied connections to ports: "
            f"{', '.join(str(p) for p in dst_ports[:20])}{'...' if len(dst_ports) > 20 else ''}. "
            f"Review for scanning, misconfiguration, or blocked legitimate traffic.",
            {"src_ip": src_ip, "deny_count": events_n, "dst_ports": dst_ports[:50]},
            device_name=agg["dev"],
        ))
    return [a for a in alerts if a]


# Cleartext protocols (cleartext_protocol / rule_cleartext_protocol, 3.5) and
# management protocols (mgmt_protocol / rule_mgmt_protocol, 5.1/5.2).  Owner:
# a cleartext management protocol (Telnet, SNMP v1/v2c) is in both lists, so it
# raises a finding in both checks.  HTTP/HTTPS are not in the management list:
# they are general web traffic, and HTTP is already a cleartext protocol.
_CLEARTEXT_PROTO_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 23: "Telnet", 25: "SMTP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    161: "SNMP-v1/v2", 162: "SNMP-trap",
}
_MGMT_PROTO_PORTS: dict[int, str] = {
    22: "SSH", 23: "Telnet", 161: "SNMP-v1/v2", 162: "SNMP-trap",
    3389: "RDP", 5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",
    8443: "HTTPS-alt",
}
# management protocols that are also cleartext: raise the management finding
_CLEARTEXT_MGMT_PORTS = frozenset(_CLEARTEXT_PROTO_PORTS) & frozenset(_MGMT_PROTO_PORTS)


def review_cleartext_protocols(db: DBSession) -> list:
    """
    SR 7.7, SR 4.1 / 3.5 — Sessions using cleartext protocols crossing zone
    boundaries (management ones included; review_mgmt_protocols reports
    those too).
    """
    _CLEARTEXT = _CLEARTEXT_PROTO_PORTS
    # A-17: one row per distinct flow, aggregated in SQL before the limit.
    flows = _flow_sessions(db, [
        NetworkSession.dst_port.in_(list(_CLEARTEXT.keys())),
        NetworkSession.protocol != "unknown",
    ], "cleartext-protocol flows")

    alerts = []
    for sess, flow_packets in flows:
        src = sess.src_host
        dst = sess.dst_host
        if not src or not dst:
            continue
        sl, dl = src.purdue_level, dst.purdue_level
        if sl is None or dl is None:
            # B-20: counted, not silent; SF-10: only the host whose level is
            # unknown is held from auto-resolve
            _count_unknown_level(db, *(h.ip for h, l in ((src, sl), (dst, dl)) if l is None))
            continue
        if sl == dl:
            continue  # same-level cleartext is less severe - skip for now (L3 vs L3.5 is a crossing)
        proto_name = _CLEARTEXT.get(sess.dst_port, str(sess.dst_port))
        alerts.append(_make_finding(
            db, "cleartext_protocol",
            f"Cleartext protocol {proto_name} crossing zones: {src.ip} ({fmt_level(sl)}) → {dst.ip}:{sess.dst_port} ({fmt_level(dl)})",
            f"Cleartext protocol {proto_name} (port {sess.dst_port}) is crossing zone boundaries "
            f"(Level {sl} to Level {dl}). Seen {flow_packets} times.",
            {"src_ip": src.ip, "dst_ip": dst.ip, "dst_port": sess.dst_port,
             "protocol_name": proto_name, "src_level": sl, "dst_level": dl,
             "packet_count": flow_packets},
            session_id=sess.id,
        ))

    from app.parsers.segments import ot_capture_segment_of
    ot_segment = ot_capture_segment_of(db)

    # ── SMBv1 detected from PCAP (packet-level evidence, higher confidence) ──
    # query ProtocolDetail rows written by pcap_parser when smb_analyzer
    # positively identified SMBv1 frames.  Join through NetworkSession to get
    # host info, then apply the same zone-crossing filter.
    # A-17: aggregate SMBv1 details per distinct flow in SQL (one
    # representative detail = lowest id) before the limit, ordered.
    grp = (NetworkSession.src_host_id, NetworkSession.dst_host_id,
           NetworkSession.dst_port, NetworkSession.transport)
    rep_rows = (
        db.query(func.min(ProtocolDetail.id).label("rep_id"))
        .join(NetworkSession, NetworkSession.id == ProtocolDetail.session_id)
        .filter(ProtocolDetail.protocol == "smb1")
        .group_by(*grp).order_by(*grp)
        .all()   # B-06: every SMBv1 flow (ids only; details hydrated in batches)
    )
    rep_ids = [r.rep_id for r in rep_rows]
    smb1_details = []
    for i in range(0, len(rep_ids), 500):
        smb1_details.extend(
            db.query(ProtocolDetail)
            .filter(ProtocolDetail.id.in_(rep_ids[i:i + 500]))
            .options(
                joinedload(ProtocolDetail.session).joinedload(NetworkSession.src_host),
                joinedload(ProtocolDetail.session).joinedload(NetworkSession.dst_host),
            ).all())
    smb1_details.sort(key=lambda d: d.id)
    seen_sessions: set[int] = set()  # deduplicate per session
    for detail in smb1_details:
        sess = detail.session
        if sess is None or sess.id in seen_sessions:
            continue
        seen_sessions.add(sess.id)
        src = sess.src_host
        dst = sess.dst_host
        if not src or not dst:
            continue
        sl, dl = src.purdue_level, dst.purdue_level
        cmd = detail.fields.get("command", "unknown") if detail.fields else "unknown"
        if sl is None or dl is None or sl == dl:
            # FO-05: SMBv1 is end-of-life whatever the zones - report it when
            # either end is OT (L0-L2) or on a capture segment holding OT devices
            seg = ot_segment(src) or ot_segment(dst)
            ot_end = any(lv is not None and lv <= 2 for lv in (sl, dl))
            if not (seg or ot_end):
                if sl is None or dl is None:
                    _count_unknown_level(db, *(h.ip for h, l in ((src, sl), (dst, dl)) if l is None))
                continue
            where = f"on OT segment {seg}" if seg else "inside an OT zone"
            alerts.append(_make_finding(
                db, "smbv1_legacy",
                f"SMBv1 (legacy EoL protocol) {where}: {src.ip} ({fmt_level(sl) if sl is not None else 'unclassified'})"
                f" → {dst.ip} ({fmt_level(dl) if dl is not None else 'unclassified'})",
                f"Packet-level inspection confirmed SMBv1 frames (\\xffSMB signature) on session "
                f"{src.ip}:{sess.src_port} → {dst.ip}:{sess.dst_port} {where}.  SMBv1 is end-of-life, "
                f"unpatched against MS17-010/EternalBlue, and should not be present in any OT "
                f"environment, zone crossing or not.  Command observed: {cmd}.  Disable SMBv1 via "
                f"Group Policy or registry (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
                {"src_ip": src.ip, "dst_ip": dst.ip, "src_port": sess.src_port, "dst_port": sess.dst_port,
                 "src_level": sl, "dst_level": dl, "ot_capture_segment": seg, "smb_command": cmd,
                 "packet_count": sess.packet_count},
                session_id=sess.id,
            ))
            continue
        alerts.append(_make_finding(
            db, "smbv1_legacy",
            f"SMBv1 (legacy EoL protocol) detected crossing zones: {src.ip} ({fmt_level(sl)}) → {dst.ip} ({fmt_level(dl)})",
            f"Packet-level inspection confirmed SMBv1 frames (\\xffSMB signature) on session "
            f"{src.ip}:{sess.src_port} → {dst.ip}:{sess.dst_port}.  "
            f"SMBv1 is end-of-life, unpatched against MS17-010/EternalBlue, and should not be "
            f"present in any OT environment.  Command observed: {cmd}.  "
            f"Disable SMBv1 via Group Policy or registry (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
            {"src_ip": src.ip, "dst_ip": dst.ip,
             "src_port": sess.src_port, "dst_port": sess.dst_port,
             "src_level": sl, "dst_level": dl,
             "smb_command": cmd,
             "packet_count": sess.packet_count},
            session_id=sess.id,
        ))

    return [a for a in alerts if a]


def review_mgmt_protocols(db: DBSession) -> list:
    """
    SR 1.3, SR 5.1 RE1, SR 4.1 / 5.1, 5.2 — Sessions using a management
    protocol (SSH, Telnet, SNMP, RDP, VNC, WinRM, HTTPS-alt) crossing zone
    boundaries.  Medium; high for a cleartext management protocol (Telnet,
    SNMP v1/v2c), which review_cleartext_protocols reports as well.
    """
    flows = _flow_sessions(db, [
        NetworkSession.dst_port.in_(list(_MGMT_PROTO_PORTS.keys())),
        NetworkSession.protocol != "unknown",
    ], "management-protocol flows")

    alerts = []
    for sess, flow_packets in flows:
        src = sess.src_host
        dst = sess.dst_host
        if not src or not dst:
            continue
        sl, dl = src.purdue_level, dst.purdue_level
        if sl is None or dl is None:
            _count_unknown_level(db, *(h.ip for h, l in ((src, sl), (dst, dl)) if l is None))
            continue
        if sl == dl:
            continue  # same as review_cleartext_protocols: only zone crossings
        proto_name = _MGMT_PROTO_PORTS.get(sess.dst_port, str(sess.dst_port))
        cleartext = sess.dst_port in _CLEARTEXT_MGMT_PORTS
        alerts.append(_make_finding(
            db, "mgmt_protocol",
            f"Management protocol {proto_name} crossing zones: {src.ip} ({fmt_level(sl)}) → {dst.ip}:{sess.dst_port} ({fmt_level(dl)})"
            + (" [cleartext]" if cleartext else ""),
            f"Management protocol {proto_name} (port {sess.dst_port}) is crossing zone boundaries "
            f"(Level {sl} to Level {dl}). Seen {flow_packets} times. Management access should come "
            f"only from a dedicated management zone, over an encrypted protocol."
            + (f" {proto_name} is cleartext: credentials and commands can be read on the wire."
               if cleartext else ""),
            {"src_ip": src.ip, "dst_ip": dst.ip, "dst_port": sess.dst_port,
             "protocol_name": proto_name, "src_level": sl, "dst_level": dl,
             "cleartext": cleartext, "packet_count": flow_packets},
            session_id=sess.id,
            severity="high" if cleartext else None,
        ))
    return [a for a in alerts if a]


def review_ot_it_dependencies(db: DBSession) -> list:
    """
    SR 7.3, 9.2 / 7.3, 9.2 — OT devices with active dependencies on
    IT services (AD, DNS, SMB, NTP).
    """
    _IT_SERVICE_PORTS = {
        53: "DNS", 88: "Kerberos/AD", 135: "RPC/AD",
        137: "NetBIOS/SMB", 139: "NetBIOS/SMB", 389: "LDAP/AD",
        445: "SMB", 464: "Kerberos/AD", 636: "LDAPS/AD", 123: "NTP",
    }
    # Filter at SQL level: only sessions from OT hosts (purdue_level ≤ 2).
    # Join through Host so the purdue_level predicate runs in the DB
    # rather than loading every IT-service session and filtering in Python.
    # A-17: one row per distinct flow, aggregated in SQL before the limit.
    flows = _flow_sessions(db, [
        NetworkSession.dst_port.in_(list(_IT_SERVICE_PORTS.keys())),
        Host.purdue_level <= 2,
        Host.purdue_level.isnot(None),
    ], "OT->IT service flows", join_src_host=True)

    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)
    alerts = []
    for sess, flow_packets in flows:
        src = sess.src_host
        if not src or src.purdue_level is None or src.purdue_level > 2:
            continue
        svc = _IT_SERVICE_PORTS.get(sess.dst_port, str(sess.dst_port))
        dst = sess.dst_host
        if dst is not None and mctx.is_ntp_flow(src.ip, sess.src_port, dst.ip, sess.dst_port):
            continue   # owner: the declared site NTP server is not an IT dependency
        # IO-13: a service on an OT host (L0-L3.5) is an OT dependency, not
        # an IT one; NTP keeps its own check
        if dst is not None and dst.purdue_level is not None and dst.purdue_level < 4 \
                and not _is_public_ip(dst.ip):
            continue
        alerts.append(_make_finding(
            db, "ot_it_dependency",
            f"OT device dependency on IT service: {src.ip} ({fmt_level(src.purdue_level)}) → {svc}",
            f"OT host {src.ip} (Level {src.purdue_level}) has an active session to IT service "
            f"{svc} (port {sess.dst_port}) on {dst.ip if dst else 'unknown'}. "
            f"Review whether this dependency is documented and whether the IT service has "
            f"appropriate OT resilience (SR 7.3: continuity of OT function without IT).",
            {"src_ip": src.ip, "dst_ip": dst.ip if dst else None, "dst_port": sess.dst_port,
             "service": svc, "src_level": src.purdue_level, "packet_count": flow_packets},
            session_id=sess.id,
        ))
    return [a for a in alerts if a]


def review_cleartext_credentials(db: DBSession) -> list:
    """
    SR 4.1, SR 3.1 / 8.3 — Cleartext credentials in traffic.
    Looks for NetworkSession rows where the protocol is Telnet, FTP, or
    unencrypted HTTP and the destination is a Level 0-2 host. These
    protocols transmit credentials in cleartext and are explicitly called
    out in checklist 8.3 as an OT-specific risk (operator authenticating
    to a PLC or HMI over Telnet, for example).

    Distinguishes from review_cleartext_protocols (3.5), which flags
    cleartext protocols crossing zone boundaries regardless of endpoint.
    This check specifically flags credential-exposure risk on OT devices.

    FO-07: a session on which the capture showed a cleartext LOGIN
    (NetworkSession.cleartext_auth - FTP / POP3 / IMAP / SMTP / telnet
    login, HTTP Basic auth, SNMPv1/v2c community) is reported as
    "Credentials observed in cleartext" for ANY destination, high (critical
    toward L0-L1).  The port-only rule stays for OT / unclassified
    destinations, medium ("cleartext protocol", no login seen).
    """
    _CLEARTEXT_CRED_PORTS = {
        21: "FTP", 23: "Telnet", 80: "HTTP",
        69: "TFTP",   # no auth but does transfer config/firmware
        110: "POP3", 143: "IMAP", 25: "SMTP",
    }
    # Push OT filter to SQL: only sessions destined for OT hosts (L0-2 or
    # unclassified). Avoids loading every cleartext session into memory.
    # B-06: keyset-paginated over every matching session (no silent cap).
    sessions = _keyset(
        db.query(NetworkSession)
        .join(NetworkSession.dst_host)
        .filter(
            NetworkSession.dst_port.in_(list(_CLEARTEXT_CRED_PORTS.keys())),
            # Include unclassified hosts (purdue_level IS NULL) so the Python
            # loop's dst_unclassified path is actually reachable.
            or_(Host.purdue_level <= 2, Host.purdue_level.is_(None)),
        )
        .options(
            joinedload(NetworkSession.src_host),
            joinedload(NetworkSession.dst_host),
        ),
        NetworkSession.id,
    )

    alerts = []
    # FO-07: logins the capture actually showed - any destination, the
    # gateway router included; high (critical toward L0-L1)
    observed_ids: set = set()
    snmp: dict = {}              # RS-10: (source, kind) -> sessions
    q_obs = (db.query(NetworkSession).filter(NetworkSession.cleartext_auth.isnot(None))
             .options(joinedload(NetworkSession.src_host), joinedload(NetworkSession.dst_host)))
    for sess in _keyset(q_obs, NetworkSession.id):
        src, dst = sess.src_host, sess.dst_host
        if not src or not dst:
            continue
        observed_ids.add(sess.id)
        kinds = sess.cleartext_auth
        if "snmp" in kinds.lower():
            snmp.setdefault((src.ip, kinds), []).append(sess)
            continue
        lvl = dst.purdue_level
        alerts.append(_make_finding(
            db, "cleartext_credentials",
            f"Credentials observed in cleartext: {kinds} {src.ip} → {dst.ip}:{sess.dst_port}",
            f"The capture shows a cleartext login ({kinds}) from {src.ip} to {dst.ip}:{sess.dst_port} "
            f"(Level {fmt_level(lvl) if lvl is not None else 'unknown'}): anyone on the path can read "
            f"the user name and password. The credential itself is not stored by the app. Replace the "
            f"protocol with an encrypted one (SFTP / SSH / HTTPS / SNMPv3) and change the exposed "
            f"credentials (SR 4.1, SR 3.1).",
            {"src_ip": src.ip, "dst_ip": dst.ip, "dst_port": sess.dst_port, "logins": kinds,
             "dst_level": lvl, "packet_count": sess.packet_count, "observed": True,
             "checklist_title": "Cleartext credentials in traffic",
             "severity_reason": ("Critical: credentials for an L0-L1 device were exposed."
                                 if lvl is not None and lvl <= 1 else
                                 "High: a login was captured in cleartext.")},
            session_id=sess.id,
            severity="critical" if lvl is not None and lvl <= 1 else "high",
            dedup_evidence={"src_ip": src.ip, "dst_ip": dst.ip, "dst_port": sess.dst_port, "observed": True},
        ))
    # RS-10: one poller sending its community to many devices is one
    # exposure - one finding per source and community kind, targets listed
    for (sip, kinds), group in sorted(snmp.items()):
        tg = sorted({(x.dst_host.ip, x.dst_port, x.dst_host.purdue_level) for x in group},
                    key=lambda t: (str(t[0]), t[1] or 0))
        deep = any(t[2] is not None and t[2] <= 1 for t in tg)
        names = [f"{ip}:{port}" for ip, port, _l in tg]
        alerts.append(_make_finding(
            db, "cleartext_credentials",
            (f"Credentials observed in cleartext: {kinds} {sip} → {names[0]}" if len(tg) == 1 else
             f"Credentials observed in cleartext: {kinds} from {sip} to {len(tg)} devices"
             f" ({', '.join(names[:3])}{' …' if len(names) > 3 else ''})"),
            f"The capture shows {sip} sending an SNMP community ({kinds}) in cleartext to {len(tg)} "
            f"device(s): {', '.join(names[:20])}{' …' if len(names) > 20 else ''}. Anyone on the path can "
            f"read the community and, if it is read-write, reconfigure every device that accepts it. The "
            f"community itself is not stored by the app. Move to SNMPv3 (authPriv) and change the "
            f"community on every listed device (SR 4.1, SR 1.5).",
            {"src_ip": sip, "logins": kinds, "observed": True, "grouped": True,
             "targets": [{"ip": ip, "port": port, "level": lv} for ip, port, lv in tg[:200]],
             "target_count": len(tg), "session_ids": [x.id for x in group][:200],
             "packet_count": sum(x.packet_count or 0 for x in group),
             "checklist_title": "Cleartext credentials in traffic",
             "severity_reason": ("Critical: the community reached L0-L1 devices." if deep else
                                 "High: a community was captured in cleartext.")},
            session_id=group[0].id,
            severity="critical" if deep else "high",
            dedup_evidence={"src_ip": sip, "logins": kinds, "observed": True, "grouped": True},
        ))
    for sess in sessions:
        if sess.id in observed_ids:
            continue           # reported above with the login it carried
        dst = sess.dst_host
        if not dst:
            continue
        # Flag if destination is a known OT device, or unclassified (fail visible)
        dst_is_ot = dst.purdue_level is not None and dst.purdue_level <= 2
        dst_unclassified = dst.purdue_level is None
        if not (dst_is_ot or dst_unclassified):
            continue
        proto_name = _CLEARTEXT_CRED_PORTS.get(sess.dst_port, str(sess.dst_port))
        src = sess.src_host
        detail: dict = {
            "src_ip": src.ip if src else None,
            "dst_ip": dst.ip,
            "dst_port": sess.dst_port,
            "protocol_name": proto_name,
            "dst_level": dst.purdue_level,
            "packet_count": sess.packet_count,
            "checklist_title": "Cleartext credentials in traffic",
        }
        if dst_unclassified:
            detail["classification_note"] = (
                "Destination host Purdue level unknown - may or may not be OT equipment. "
                "Run /classify after ingesting pcap/ARP data to confirm."
            )
        detail["severity_reason"] = ("Medium: a cleartext protocol by port; no login was seen in "
                                     "the capture (FO-07).")
        alerts.append(_make_finding(
            db, "cleartext_credentials",
            f"Cleartext protocol {proto_name} to OT-adjacent host "
            f"{dst.ip}:{sess.dst_port}",
            f"Cleartext protocol {proto_name} (port {sess.dst_port}) used toward "
            f"{dst.ip} (Level {dst.purdue_level if dst.purdue_level is not None else 'unknown'}). "
            f"Any credentials and data sent in such a session are visible on the wire; the capture "
            f"did not show a login on it.",
            detail,
            session_id=sess.id,
            severity="medium",
        ))
    return [a for a in alerts if a]


def _known_infrastructure(db: DBSession):
    """(firewall interface IPs, firewall port MACs seen on switches, VpnContext)."""
    from app.models import Firewall, FirewallInterface, MacTableEntry, SwitchInterface
    from app.parsers import vpn as _vpn
    ips = {str(ip).strip() for (ip,) in db.query(FirewallInterface.ip_address).join(
        Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
        FirewallInterface.ip_address.isnot(None))}
    names = set()
    for n, d in db.query(Firewall.name, Firewall.device_name):
        names |= {str(x).strip().lower() for x in (n, d) if x}
    ports = {(si.device_name, si.port_name) for si in db.query(SwitchInterface).filter(
        SwitchInterface.neighbor_device.isnot(None))
        if str(si.neighbor_device).strip().lower() in names}
    macs = set()
    if ports:
        for m in db.query(MacTableEntry):
            if (m.device_name, m.port_name) in ports and m.mac:
                macs.add(m.mac.lower())
    # LS-06 / LS-07: the MAC that answers for a firewall / switch interface
    # address (switch ARP table, capture) is that device's own MAC.
    if ips:
        il = list(ips)
        for i in range(0, len(il), 900):
            for (m,) in db.query(Host.mac).filter(Host.ip.in_(il[i:i + 900]), Host.mac.isnot(None)):
                macs.add(str(m).lower())
    # FO-10: the gateways a capture identified are infrastructure too
    for (m,) in db.query(Host.mac).filter(Host.classification_source == "capture_gateway",
                                          Host.mac.isnot(None)):
        macs.add(str(m).lower())
    from app.parsers.nat_sessions import known_vip_ips
    ips |= known_vip_ips(db)        # P-04: VIP external addresses are the firewall's
    return ips, macs, _vpn.VpnContext.build(db)


def review_unknown_devices(db: DBSession) -> list:
    """
    SR 7.8 / 8.6 — Unknown devices not in the asset inventory.
    Compares Host MAC addresses against ApprovedHost entries loaded
    via /ingest/baseline/asset-inventory - and the hosts approved on the
    Inventory page (owner 2026-10-14). Any Host with a MAC address that
    doesn't appear in the approved inventory is flagged.

    Requires an active Baseline with AssetInventory/ApprovedHost entries
    to be meaningful. Returns no findings (not an error) when no baseline
    exists - this is the correct behaviour since "nothing is approved yet"
    is not the same as "unknown devices found".
    """
    baseline = _active_baseline(db)
    if not baseline:
        # FO-03: no inventory - report the unidentified industrial clients
        # (fully evaluated, so not marked incomplete; they auto-resolve once
        # classified or once a baseline takes over)
        return _unidentified_ics_clients(db)

    # Single query for all approved hosts; partition into IP/MAC sets in Python
    # to avoid two identical queries against the same baseline_id.
    _all_approved = db.query(ApprovedHost).filter(
        ApprovedHost.baseline_id == baseline.id,
    ).all()
    approved_macs = {h.mac.lower() for h in _all_approved if h.mac}
    approved_ips  = {h.ip          for h in _all_approved if h.ip}
    if not approved_macs and not approved_ips:
        _mark_incomplete(db, "baseline has no approved hosts")
        return []
    # owner 2026-10-14: a host approved on the Inventory page is in the inventory too
    # (by address and by MAC, so the other addresses of an approved device count)
    page_ips, page_macs = _page_approved(db)
    approved_ips |= page_ips
    approved_macs |= page_macs

    infra_ips, infra_macs, vpn = _known_infrastructure(db)

    alerts = []
    # B-06: every host, paged; never the B-14 group marker (not a device).
    all_hosts = _keyset(db.query(Host).filter(real_host_clause()), Host.id)
    for host in all_hosts:
        mac_known = host.mac and host.mac.lower() in approved_macs
        ip_known = host.ip and host.ip in approved_ips
        # H-15: the firewalls' own interfaces (addresses from the configs, MACs
        # learned on the switch ports whose LLDP neighbour is a firewall) are
        # known infrastructure; SSL-VPN tunnel-pool addresses are remote users
        # (reported by the remote-access checks), not devices.
        if (host.ip and host.ip in infra_ips) or (host.mac and host.mac.lower() in infra_macs) \
                or (host.ip and vpn.is_pool_ip(host.ip)):
            continue
        if not mac_known and not ip_known:
            alerts.append(_make_finding(
                db, "unknown_device",
                f"Unknown device not in asset inventory: "
                f"{host.ip or 'no-ip'} / {host.mac or 'no-mac'}",
                f"Host {host.ip or host.mac} was observed on the network but does not "
                f"appear in the approved asset inventory (matched on neither IP nor MAC). "
                f"Vendor: {host.vendor or 'unknown'}. "
                f"Purdue level: {host.purdue_level if host.purdue_level is not None else 'unclassified'}.",
                {"ip": host.ip, "mac": host.mac, "vendor": host.vendor,
                 "purdue_level": host.purdue_level,
                 "checklist_title": "Unknown devices not in the asset inventory",
                 "sr_ref": "SR 7.8"},
            ))
    return [a for a in alerts if a]


#: SF-5: classification sources that carry no identity (a level at most)
_NO_IDENTITY_SOURCES = (None, "interface_label", "subnet_declared", "oui_hint", "protocol_client_hint")


def _across_firewall(db: DBSession, hosts: list) -> list:
    """SF-5: sessions or connection attempts of ``hosts`` to another firewall
    interface network (or the Internet) - traffic the firewall must carry."""
    from app.models import ConnectionAttempt, FirewallInterface, Firewall
    import ipaddress as _ip
    q = db.query(FirewallInterface.network_cidr).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
    sid = current_site(db)
    if sid is not None:
        q = q.filter(Firewall.site_id == sid)
    nets = []
    for (cidr,) in q:
        try:
            n = _ip.ip_network(cidr, strict=False) if cidr else None
        except ValueError:
            n = None
        if n is not None and n.prefixlen > 0:
            nets.append(n)
    nets.sort(key=lambda n: -n.prefixlen)

    def net(ip):
        try:
            a = _ip.ip_address(ip)
        except (ValueError, TypeError):
            return None
        return next((n for n in nets if n.version == a.version and a in n), None)
    out, seen = [], set()
    ids = [h.id for h in hosts]
    own = {h.ip: net(h.ip) for h in hosts}
    rows = []
    for d_ip, port, s_id in (db.query(Host.ip, NetworkSession.dst_port, NetworkSession.src_host_id)
                             .join(NetworkSession, NetworkSession.dst_host_id == Host.id)
                             .filter(NetworkSession.src_host_id.in_(ids))):
        src = next((h.ip for h in hosts if h.id == s_id), None)
        rows.append((src, d_ip, port, "session"))
    for a in db.query(ConnectionAttempt).filter(ConnectionAttempt.src_ip.in_(list(own)),
                                                ConnectionAttempt.dst_port.isnot(None)):
        rows.append((a.src_ip, a.dst_ip, a.dst_port, "attempt, " + (a.outcome or "dropped")))
    for src, d_ip, port, how in rows:
        mine = own.get(src)
        theirs = net(d_ip)
        if mine is None or (theirs is not None and theirs == mine):
            continue
        if theirs is None and not _is_public_ip(d_ip):
            continue
        k = (d_ip, port)
        if k in seen:
            continue
        seen.add(k)
        out.append({"ip": d_ip, "port": port, "how": how})
    return out


#: FO-03: industrial server ports - a host connecting TO one is a client
_ICS_CLIENT_PORTS = frozenset({502, 102, 44818, 20000, 2404, 4840, 34964, 1911, 18245, 20547})

#: FO-03: OUI vendor names of hobby / IoT boards - never a deliberate
#: industrial controller or HMI
_HOBBY_OUI_WORDS = ("raspberry", "espressif", "arduino", "particle industries", "seeed", "beagle",
                    "tuya", "sonoff", "itead", "shelly", "allterco", "pine64", "hardkernel", "friendlyelec")


def _page_approved(db: DBSession) -> tuple[set, set]:
    """Addresses and MACs of the hosts approved on the Inventory page
    (Host.approved True; 'unapproved / rogue' is False and stays reported) and of
    the hosts excluded from the inventory (owner 2026-10-14: the exclusion is a
    decision - the host was looked at and is not an asset to track)."""
    from sqlalchemy import or_ as _or
    ips, macs = set(), set()
    for ip, mac in db.query(Host.ip, Host.mac).filter(
            real_host_clause(), _or(Host.approved.is_(True), Host.inventory_excluded.is_(True))):
        if ip:
            ips.add(ip)
        if mac:
            macs.add(mac.lower())
    return ips, macs


def _unidentified_ics_clients(db: DBSession) -> list:
    """FO-03: with no asset inventory, an industrial-protocol CLIENT (a host
    that sent Modbus / S7 / CIP / DNP3 requests) nobody has identified is the
    capture-only signal of an unknown device: device type still
    ``ics_protocol_client_unclassified`` with no level, or a hobby / IoT
    board vendor acting as industrial client whatever its automatic label.
    Medium; high for a hobby / IoT vendor or when the host also reaches the
    Internet.  IO-04: a consumer / mobile device (phone, tablet - Apple,
    Samsung, Google ... OUIs) on the network is reported too (medium; high
    when it tried the Internet).  IO-12: one finding per MAC, listing its
    addresses.  A manually classified host is identified, and so is a host
    approved on the Inventory page (owner 2026-10-14)."""
    from sqlalchemy import or_
    from app.models import ConnectionAttempt
    from app.parsers.segments import CONSUMER_DEVICE_WORDS, vendor_matches
    alerts = []
    q = db.query(Host).filter(real_host_clause(), Host.ip.isnot(None),
                              or_(Host.classification_source.is_(None), Host.classification_source != "manual"))
    infra_ips, infra_macs, _vpn = _known_infrastructure(db)
    page_ips, page_macs = _page_approved(db)        # owner 2026-10-14: approved on the Inventory page
    groups: dict = {}
    for host in _keyset(q, Host.id):
        if host.ip in infra_ips or (host.mac and host.mac.lower() in infra_macs):
            continue
        if host.ip in page_ips or (host.mac and host.mac.lower() in page_macs):
            continue
        groups.setdefault((host.mac or f"ip:{host.ip}").lower(), []).append(host)
    for key, hosts in sorted(groups.items()):
        vendor = next((h.vendor for h in hosts if h.vendor), "") or ""
        hobby = any(w in vendor.lower() for w in _HOBBY_OUI_WORDS)
        consumer = vendor_matches(vendor, CONSUMER_DEVICE_WORDS)
        # RS G3 / SF-8a: a level taken from the subnet's zone or the interface
        # label does not identify the device
        unidentified = any(h.device_type == "ics_protocol_client_unclassified"
                           and (h.purdue_level is None
                                or h.classification_source in ("subnet_declared", "interface_label"))
                           for h in hosts)
        # SF-5: a host with no identity at all (no type, a level only from the
        # interface label / declared subnet) on a control network (L0-L2)
        bare = (all(h.device_type in (None, "ics_protocol_client_unclassified")
                    and h.classification_source in _NO_IDENTITY_SOURCES for h in hosts)
                and any(h.purdue_level is not None and float(h.purdue_level) <= 2 for h in hosts))
        if not (unidentified or hobby or consumer or bare):
            continue
        ids = [h.id for h in hosts]
        servers = (db.query(Host.ip, NetworkSession.dst_port, NetworkSession.protocol)
                   .join(NetworkSession, NetworkSession.dst_host_id == Host.id)
                   .filter(NetworkSession.src_host_id.in_(ids)).all())
        ics = sorted({f"{ip}:{port}" for ip, port, _proto in servers if port in _ICS_CLIENT_PORTS})
        internet = sorted({f"{ip}:{port}" for ip, port, _p in servers if _is_public_ip(ip)})
        tried = sorted({f"{a.dst_ip}:{a.dst_port}" for a in db.query(ConnectionAttempt).filter(
            ConnectionAttempt.src_ip.in_([h.ip for h in hosts])) if _is_public_ip(a.dst_ip)})
        crossing = []
        if not ics and not consumer:
            if bare:
                crossing = _across_firewall(db, hosts)
            if not crossing:
                continue
        addrs = sorted(h.ip for h in hosts)
        mac = hosts[0].mac
        why = []
        if hobby:
            why.append(f"its MAC belongs to {vendor} - a hobby / IoT board, not an industrial device")
        if consumer:
            why.append(f"its MAC belongs to {vendor} - a consumer / mobile device")
        if internet:
            why.append(f"it also reaches the Internet ({', '.join(internet[:3])})")
        if tried:
            why.append(f"it tried to reach the Internet ({', '.join(tried[:3])})")
        sev = "high" if (hobby or internet or (consumer and tried)) else None
        if crossing and not ics:
            mgmt = any(c["port"] in (21, 22, 23, 135, 139, 445, 3389, 5900, 5901, 5985, 5986) for c in crossing)
            if mgmt or tried:
                sev = "high"
                why.append("it tried management / file-sharing ports or the Internet")
            title = (f"Unidentified device on the control network reaching across the firewall: "
                     f"{', '.join(addrs)} / {mac or 'no-mac'}" + (f" ({vendor})" if vendor else ""))
            text = (f"Host {', '.join(addrs)} sits on a control network (Purdue "
                    f"L{float(hosts[0].purdue_level):g}, from {hosts[0].classification_source or 'no evidence'}) "
                    f"and nobody has identified it - no device type, not in any inventory - yet it opened sessions "
                    f"or attempts to other networks across the firewall: "
                    + ", ".join(f"{c['ip']}:{c['port']} ({c['how']})" for c in crossing[:6]) + ". ")
        elif ics:
            title = (f"Unidentified industrial client (no asset inventory): {', '.join(addrs)} / {mac or 'no-mac'}"
                     + (f" ({vendor})" if vendor else ""))
            text = (f"Host {', '.join(addrs)} sends industrial-protocol requests to {', '.join(ics[:5])} but "
                    f"nobody has identified it: there is no asset inventory to check it against and it is not "
                    f"classified (automatic label: {hosts[0].device_type or 'none'}). ")
        else:
            title = (f"Consumer device on the OT network (no asset inventory): {', '.join(addrs)} / {mac}"
                     + (f" ({vendor})" if vendor else ""))
            text = (f"Host {', '.join(addrs)} is a consumer / mobile device ({vendor}) on the network. ")
        alerts.append(_make_finding(
            db, "unknown_device", title,
            text + (("Also: " + "; ".join(why) + ". ") if why else "")
            + "Identify the device - classify it (Inventory or Host Topology: Classify) or load the asset inventory / approved "
              "host list - or remove it from the control network (SR 7.8).",
            {"ip": addrs[0], "addresses": addrs, "mac": mac, "vendor": vendor or None,
             "purdue_level": hosts[0].purdue_level, "device_type": hosts[0].device_type,
             "ics_servers": ics[:20], "internet": internet[:10], "internet_attempts": tried[:10],
             "hobby_vendor": hobby, "consumer_device": consumer, "basis": "capture only - no asset inventory",
             "across_firewall": crossing[:20],
             "severity_reason": ("High: " + "; ".join(why) + "." if sev else
                                 "Medium: an unidentified host on the control network."),
             "checklist_title": "Unknown devices not in the asset inventory", "sr_ref": "SR 7.8"},
            severity=sev, dedup_evidence={"rule_key": f"unidentified:{key}"},
        ))
    return [a for a in alerts if a]


def review_dead_default_gateways(db: DBSession) -> list:
    """IO-08: an address several hosts keep ARPing for and nobody ever
    claims - typically the default gateway configured on hosts of a network
    that has no router.  Anyone who takes that address becomes their router
    (man in the middle, exfiltration path).  Needs two or more requesting
    hosts, or three or more requests from one (a sweep asks once per address)."""
    from app.models import ConnectionAttempt
    by_target: dict = {}
    for a in db.query(ConnectionAttempt).filter(ConnectionAttempt.outcome == "arp_unanswered"):
        t = by_target.setdefault(a.dst_ip, {"sources": {}, "count": 0})
        t["sources"][a.src_ip] = t["sources"].get(a.src_ip, 0) + (a.count or 1)
        t["count"] += a.count or 1
    if not by_target:
        return []
    claimed = {ip for (ip,) in db.query(Host.ip).filter(Host.ip.in_(list(by_target)))}
    out = []
    for ip, t in sorted(by_target.items()):
        srcs = t["sources"]
        if ip in claimed or not (len(srcs) >= 2 or max(srcs.values()) >= 3):
            continue
        names = sorted(srcs)
        out.append(_make_finding(
            db, "dead_default_gateway",
            f"Address nobody answers, asked for by {len(names)} host(s): {ip} (dead default gateway?)",
            (f"{len(names)} host(s) ({', '.join(names[:10])}{' ...' if len(names) > 10 else ''}) sent "
             f"{t['count']} ARP request(s) for {ip}, and nothing ever answered. These hosts are configured "
             f"to send traffic through {ip} - usually a default gateway in a network that has no router. "
             f"Any device that takes {ip} becomes their router: a man-in-the-middle and a path out of the "
             f"network (SR 7.6, SR 5.1). Remove the gateway from the hosts' configuration (leave it empty "
             f"on an isolated network), or reserve the address on a device you control."),
            {"ip": ip, "requesting_hosts": names[:50], "requests": t["count"],
             "severity_reason": "Medium: misconfiguration that turns into a man-in-the-middle when the "
                                "address is taken."},
            dedup_evidence={"rule_key": f"dead_gateway:{ip}"},
        ))
    return [a for a in out if a]


def review_ip_conflicts(db: DBSession) -> list:
    """
    SR 7.8 / 8.7 — IP conflicts / duplicate addresses.
    Looks for Host rows where the same IP has been seen with more than
    one distinct MAC address. ARP table ingestion naturally surfaces
    this when a new device takes an old device's IP, or when a
    man-in-the-middle is ARP-poisoning the network.
    """
    from sqlalchemy import func
    # Find IPs with multiple distinct MACs
    results = (
        db.query(Host.ip, func.count(Host.mac.distinct()).label("mac_count"))
        .filter(Host.ip.isnot(None), Host.mac.isnot(None))
        .group_by(Host.ip)
        .having(func.count(Host.mac.distinct()) > 1)
        .all()
    )

    alerts = []
    for ip, mac_count in results:
        conflicting_hosts = db.query(Host).filter(Host.ip == ip).all()
        macs = [h.mac for h in conflicting_hosts if h.mac]
        alerts.append(_make_finding(
            db, "ip_conflict",
            f"IP conflict / duplicate address: {ip} seen with {mac_count} different MACs",
            f"IP address {ip} has been observed associated with {mac_count} distinct MAC "
            f"addresses: {', '.join(macs)}. This may indicate IP reuse after device replacement, "
            f"a misconfiguration, or ARP spoofing/MITM.",
            {"ip": ip, "mac_addresses": macs, "mac_count": mac_count,
             "checklist_title": "IP conflicts / duplicate addresses",
             "sr_ref": "SR 7.8"},
        ))
    return [a for a in alerts if a]


def _subnet_zone_mismatches(db: DBSession) -> list:
    """RS G3: a device whose own evidence (manual classification or
    protocol role) disagrees with the level the operator declared for its
    subnet - a PLC answering S7 in the VoIP subnet.  High across the OT /
    DMZ / IT boundary, medium two or more OT levels apart."""
    from app.parsers.subnet_zones import mismatches
    out = []
    for h, net, z, sev in mismatches(db):
        how = "set by the operator" if h.classification_source == "manual" else "inferred from its traffic"
        zone = f"'{z.zone_name}' " if z.zone_name else ""
        out.append(_make_finding(
            db, "misplaced_device",
            (f"Device does not match its zone: {h.ip} ({h.device_type or 'device'}, "
             f"{fmt_level(h.purdue_level)}) in subnet {net} - zone {zone}declared {fmt_level(z.purdue_level)}"),
            (f"Host {h.ip} is {h.device_type or 'a device'} at {fmt_level(h.purdue_level)} ({how}), but it sits "
             f"in subnet {net}, which the operator declared as zone {zone}at {fmt_level(z.purdue_level)}. Either the "
             f"device is in the wrong zone - move it to a subnet of its own level, behind the conduit that "
             f"zone needs - or the device or the zone declaration is wrong; correct whichever it is "
             f"(SR 5.1, SR 7.8; workbook row 2.7)."),
            {"ip": h.ip, "device_type": h.device_type, "purdue_level": h.purdue_level,
             "classification_source": h.classification_source, "ip_cidr": str(net),
             "zone_name": z.zone_name, "zone_level": z.purdue_level, "basis": "subnet zone declaration",
             "checklist_id": "2.7", "checklist_title": "No devices in the wrong zone",
             "severity_reason": ("High: the device and its zone are on different sides of the OT / DMZ / IT "
                                 "boundary." if sev == "high" else
                                 "Medium: two or more OT levels apart.")},
            severity=sev, dedup_evidence={"rule_key": f"zone_mismatch:{h.id}:{net}"},
        ))
    return out


def review_misplaced_devices(db: DBSession) -> list:
    """
    SR 5.1, SR 7.8 / 2.7 — No devices in the wrong zone.
    Cross-references the Host table (Purdue level + device_type from
    pcap/ARP classification) against the FirewallZone table (which zone
    each firewall interface is in, from FortiGate config ingestion).

    Flags OT-classified hosts (device_type contains plc, rtu, hmi, scada,
    dcs, ied, historian, or purdue_level <= 2) whose IP falls within a
    zone that has IT-zone naming (corp, enterprise, office, business, it,
    user) — a PLC on the corporate network, or an HMI in the user VLAN,
    is in the wrong zone.

    Requires BOTH:
    - pcap or ARP ingest (to populate Host with device_type/purdue_level)
    - FortiGate config ingest (to populate FirewallZone with ip_cidr)

    Returns no findings (not an error) when either dataset is absent.
    """
    import ipaddress as _ip

    _OT_DEVICE_KEYWORDS = {"plc", "rtu", "hmi", "scada", "dcs", "ied",
                            "historian", "controller", "slave", "master"}
    _IT_ZONE_KEYWORDS = {"corp", "enterprise", "office", "business",
                          "it", "user", "workstation", "desktop", "laptop"}

    alerts = _subnet_zone_mismatches(db)        # RS G3: operator subnet zones
    zones = db.query(FirewallZone).filter(FirewallZone.ip_cidr.isnot(None)).all()
    if not zones:
        from app.parsers.subnet_zones import declarations as _decl
        if not alerts and not _decl(db):
            _mark_incomplete(db, "no firewall zone data")
        return [a for a in alerts if a]

    # Build (network, zone_name) pairs for zone-membership lookups
    zone_nets = []
    for z in zones:
        try:
            net = _ip.ip_network(z.ip_cidr, strict=False)
            zone_nets.append((net, z.zone_name or "", z.device_name))
        except ValueError:
            continue

    # Find OT hosts (by device_type keyword OR confirmed Purdue level 0-2).
    # Apply purdue_level / device_type filter in SQL to avoid loading the
    # entire Host table when the DB is large.
    from sqlalchemy import func as _func_m1
    ot_hosts = []
    ot_candidates = 0
    for host in _keyset(
        db.query(Host)
        .filter(
            Host.ip.isnot(None),
            or_(
                Host.purdue_level <= 2,
                _func_m1.lower(Host.device_type).contains("plc"),
                _func_m1.lower(Host.device_type).contains("rtu"),
                _func_m1.lower(Host.device_type).contains("hmi"),
                _func_m1.lower(Host.device_type).contains("scada"),
                _func_m1.lower(Host.device_type).contains("dcs"),
                _func_m1.lower(Host.device_type).contains("ied"),
                _func_m1.lower(Host.device_type).contains("historian"),
                _func_m1.lower(Host.device_type).contains("controller"),
            ),
        ),
        Host.id,   # B-06: keyset-paginated, every candidate evaluated
    ):
        ot_candidates += 1
        dt = str(host.device_type or "").lower()
        is_ot_type = any(k in dt for k in _OT_DEVICE_KEYWORDS)
        is_ot_level = host.purdue_level is not None and host.purdue_level <= 2
        if is_ot_type or is_ot_level:
            ot_hosts.append(host)

    if not ot_hosts:
        return [a for a in alerts if a]

    for host in ot_hosts:
        try:
            addr = _ip.ip_address(host.ip)
        except ValueError:
            continue
        # Find which zone this host's IP falls in
        for net, zone_name, fw_device in zone_nets:
            if addr in net:
                # F-01: whole-token match - "it" in "UNIT1_CONTROL" /
                # "SECURITY" made OT zones look like IT zones.
                from app.parsers.common import name_has_keyword
                if name_has_keyword(zone_name, _IT_ZONE_KEYWORDS):
                    alerts.append(_make_finding(
                        db, "misplaced_device",
                        f"OT device in IT zone: {host.ip} "
                        f"({host.device_type or f'{fmt_level(host.purdue_level)}'}) "
                        f"in zone '{zone_name}' on {fw_device}",
                        f"Host {host.ip} is classified as OT equipment "
                        f"(device_type={host.device_type!r}, "
                        f"purdue_level={host.purdue_level}) but its IP falls within "
                        f"firewall zone '{zone_name}' on {fw_device}, which appears "
                        f"to be an IT zone based on its name. Verify this device is "
                        f"correctly zoned.",
                        {"src_ip": host.ip, "dst_ip": None,
                         "device_type": host.device_type,
                         "purdue_level": host.purdue_level,
                         "zone_name": zone_name,
                         "firewall_device": fw_device,
                         "ip_cidr": str(net),
                         "checklist_id": "2.7",
                         "checklist_title": "No devices in the wrong zone"},
                    ))
                break  # only report the first matching zone per host

    return [a for a in alerts if a]


def review_shadow_rules(db: DBSession) -> list:
    """
    SR 7.6 / 3.9 — Shadowed, redundant and conflicting rules identified.

    M-3 fix: delegates entirely to find_shadowed_rules() from rule_shadow.py,
    which uses proper CIDR superset analysis (parse_address_spec /
    parse_port_spec) instead of the old string-equality comparison.  This
    eliminates the duplicate shadow-detection code paths that previously existed
    in this module and in rule_shadow.py, which produced different results for
    the same firewall data.

    find_shadowed_rules() is called with generate_findings=False so that this
    function controls Finding creation through the standard _make_finding()
    path (dedup, source_ref, category tagging, CHECK_TYPE_REFERENCE lookup)
    rather than the direct Finding-insertion path in rule_shadow.py, which
    bypasses those controls.

    Shadow-type to finding-type mapping:
      duplicate       → finding_type "redundant"   (same traffic, same action)
      full_shadow     → finding_type "shadowed"    (superset, different action)
      partial_shadow  → finding_type "conflicting" (overlap, different actions)
    """
    from app.parsers.rule_shadow import find_shadowed_rules

    result = find_shadowed_rules(db, include_partial=True, generate_findings=False)
    shadows = result.get("shadows", [])
    # A-13: a device whose analysis raised produced no shadows this run -
    # its open findings must not be auto-resolved as "no longer detected".
    failed_devices = result.get("devices_failed") or []
    if failed_devices:
        _mark_incomplete(db, "shadow analysis failed for " + ", ".join(
            str(d.get("group")) for d in failed_devices[:10]))

    # A-12: resolve each side to its logical rule identity (same key as the
    # rule-twin / disabled-rule checks) so distinct pairs never share a key.
    rule_ids = {r.get("rule_id") for s in shadows
                for r in (s.get("shadowing_rule") or {}, s.get("shadowed_rule") or {})
                if r.get("rule_id") is not None}
    rows_by_id = {}
    ids = sorted(rule_ids)
    for i in range(0, len(ids), 500):
        for r in db.query(FirewallRule).filter(FirewallRule.id.in_(ids[i:i + 500])):
            rows_by_id[r.id] = r

    def _side_identity(summary: dict) -> tuple:
        row = rows_by_id.get(summary.get("rule_id"))
        if row is None:
            return (None, None, summary.get("device_name"),
                    summary.get("policy_id") or f"id:{summary.get('rule_id')}")
        key = _rule_group_key(row)
        return (key[0], key[1], key[2], _group_rule_key(key))

    alerts = []
    for s in shadows:
        shadow_type = s.get("shadow_type")
        sh_rule = s.get("shadowing_rule", {})   # the earlier, dominating rule
        sr_rule = s.get("shadowed_rule", {})     # the later, eclipsed rule
        dev = sr_rule.get("device_name") or sh_rule.get("device_name") or "unknown"

        pid_a = sh_rule.get("policy_id") or f"_id{sh_rule.get('rule_id', '?')}"
        pid_b = sr_rule.get("policy_id") or f"_id{sr_rule.get('rule_id', '?')}"
        # N-24: policy ids repeat across VDOMs - show the VDOM.  (The dedup
        # identity is rule_key below, built from the vdom-aware logical rule.)
        if sh_rule.get("vdom") is not None and sh_rule.get("policy_id"):
            pid_a = f"{pid_a} (vdom {sh_rule['vdom']})"
        if sr_rule.get("vdom") is not None and sr_rule.get("policy_id"):
            pid_b = f"{pid_b} (vdom {sr_rule['vdom']})"
        pname_a = sh_rule.get("policy_name") or "unnamed"
        pname_b = sr_rule.get("policy_name") or "unnamed"
        action_a = sh_rule.get("action", "?")
        action_b = sr_rule.get("action", "?")
        src = sh_rule.get("src", "?")
        dst = sh_rule.get("dst", "?")
        dst_port = sh_rule.get("dst_port", "any")
        rule_id_b = sr_rule.get("rule_id")

        if shadow_type == "duplicate":
            finding_type = "redundant"
            title = (
                f"Redundant rules on {dev}: "
                f"policy {pid_a} and {pid_b} have identical match criteria"
            )
            detail_text = (
                f"Policies {pid_a} ({pname_a}) and {pid_b} ({pname_b}) "
                f"on {dev} match the same traffic "
                f"({src} → {dst}:{dst_port}) "
                f"with the same action ({action_a}). "
                f"The later rule is redundant and can never fire."
            )
        elif shadow_type == "full_shadow":
            finding_type = "shadowed"
            title = (
                f"Shadowed rule on {dev}: "
                f"policy {pid_b} ({action_b}) fully shadowed by {pid_a} ({action_a})"
            )
            detail_text = (
                f"Policy {pid_b} ({pname_b}, action={action_b}) on {dev} "
                f"is fully shadowed by policy {pid_a} ({pname_a}, action={action_a}): "
                f"the earlier rule matches a superset of the later rule's traffic "
                f"({src} → {dst}:{dst_port}). The later rule can never fire. "
                f"If the intent was to override the earlier rule for a subset of traffic, "
                f"the rule order must be reversed."
            )
        elif shadow_type == "partial_shadow":
            finding_type = "conflicting"
            title = (
                f"Conflicting rules on {dev}: "
                f"policy {pid_a} ({action_a}) partially overrides {pid_b} ({action_b})"
            )
            detail_text = (
                f"Policies {pid_a} ({pname_a}, action={action_a}) and "
                f"{pid_b} ({pname_b}, action={action_b}) on {dev} have overlapping "
                f"traffic matches with conflicting actions. "
                f"Traffic in the overlap ({src} → {dst}:{dst_port}) is governed by "
                f"the earlier rule's action ({action_a}), silently overriding the "
                f"later rule's intent for that subset."
            )
        else:
            # Unexpected shadow_type — log and skip rather than crash
            log.warning("review_shadow_rules: unknown shadow_type %r for pair (%s, %s) on %s; skipping",
                        shadow_type, pid_a, pid_b, dev)
            continue

        evidence = {
            "policy_id_a": sh_rule.get("policy_id"),
            "policy_id_b": sr_rule.get("policy_id"),
            "vdom_a": sh_rule.get("vdom"),
            "vdom_b": sr_rule.get("vdom"),
            "rule_id_a": sh_rule.get("rule_id"),
            "rule_id_b": sr_rule.get("rule_id"),
            "action_a": action_a,
            "action_b": action_b,
            "src": src,
            "dst": dst,
            "dst_port": dst_port,
            "finding_type": finding_type,
            "shadow_type": shadow_type,
            "action_conflict": s.get("action_conflict", False),
        }
        if "overlap_dimensions" in s:
            evidence["overlap_dimensions"] = s["overlap_dimensions"]
        fw_a, _fd_a, dev_a, key_a = _side_identity(sh_rule)
        fw_b, _fd_b, dev_b, key_b = _side_identity(sr_rule)
        evidence["rule_key_a"] = key_a
        evidence["rule_key_b"] = key_b
        evidence["firewall_id"] = fw_b if fw_b is not None else fw_a
        dedup_evidence = {
            "policy_id_a": sh_rule.get("policy_id"),
            "policy_id_b": sr_rule.get("policy_id"),
            "device_name": dev,
            "firewall_id": evidence["firewall_id"],
            "rule_key": f"{key_a}>{key_b}",
        }

        alerts.append(_make_finding(
            db, "shadow_rule",
            title,
            detail_text,
            evidence,
            device_name=dev,
            firewall_rule_id=rule_id_b,
            # T3-38: severity by shadow type from rule_shadow (deny hidden by a
            # permit = high, dead permit = medium, duplicate = low, ...).
            severity=s.get("severity"),
            dedup_evidence=dedup_evidence,
            # Pre-A-12 key (policy ids + dst_port only): adopt such an open
            # finding instead of leaving it beside the re-keyed one.
            legacy_dedup_evidence={"policy_id_a": sh_rule.get("policy_id"),
                                   "policy_id_b": sr_rule.get("policy_id"),
                                   "dst_port": dst_port},
        ))

    return [a for a in alerts if a]


def review_historian_in_control_zone(db: DBSession) -> list:
    """
    SR 5.1, SR 7.8 / 2.3 — Historian server placed in control zone.

    Historian servers (role="historian") must sit at Level 3 (Site
    Operations) - they aggregate process data from controllers and should
    NOT be co-located with PLCs/RTUs at Level 1/2.  A historian in the
    control zone creates unnecessary attack surface between Level 1 and the
    data-collection path.

    Fires when Host.role=="historian" AND Host.purdue_level <= 2.
    Requires classify_hosts_by_lldp_role() to have run (role populated).
    """
    alerts = []
    historians = db.query(Host).filter(
        Host.role == "historian",
        Host.purdue_level.isnot(None),
        Host.purdue_level <= 2,
    ).all()
    for host in historians:
        alerts.append(_make_finding(
            db, "historian_in_control_zone",
            f"Historian server in control zone: {host.ip or host.mac} ({fmt_level(host.purdue_level)})",
            f"Host {host.ip or host.mac} is classified as a historian server (role={host.role!r}) "
            f"but sits at Purdue Level {host.purdue_level} (control/field layer). "
            f"Historians should be at Level 3 (Site Operations) — co-locating them in the "
            f"control zone extends the data-collection attack surface to Level 1/2 controllers. "
            f"Move this host's VLAN/segment to the Site Operations network.",
            {"ip": host.ip, "mac": host.mac, "role": host.role,
             "purdue_level": host.purdue_level,
             "role_source": host.role_source,
             "checklist_title": "Historian server placed in Site Operations zone, not control zone"},
        ))
    return [a for a in alerts if a]


_SIS_SOURCE_TYPES = ("engineering_workstation", "safety_plc", "safety_system", "sis")

# batch C (owner 2026-10-15): OUI vendor words of laptops / IT client hardware and
# USB-Ethernet adapters - transient devices when they show up on a control network.
_TRANSIENT_OUI_WORDS = ("dell", "lenovo", "hewlett packard", "hp inc", "asustek", "acer", "framework computer",
                        "lg electronics", "micro-star", "gigabyte", "razer", "asix electronics", "belkin",
                        "startech", "plugable", "cable matters", "anker", "ugreen", "fujitsu client", "vaio")
# (audit 2026-10-15: Realtek, Panasonic, Toshiba, TP-Link and D-Link OUIs sit in permanent OT
# equipment - HMIs, IPCs, PLCs, industrial switches - and are deliberately not listed)
_TRANSIENT_OUI_RE = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(w) for w in _TRANSIENT_OUI_WORDS) + r")(?![a-z0-9])")


def _transient_vendor(vendor) -> bool:
    return bool(vendor) and _TRANSIENT_OUI_RE.search(str(vendor).lower()) is not None


def review_switch_port_nac(db: DBSession) -> list:
    """
    SR 1.2 / 2.5 — FortiLink-managed or standalone FortiSwitch access ports without a
    port-security (802.1X) policy (owner 2026-10-19).  One finding per switch:
    medium when such a port sits on a VLAN labelled L0-L2, low otherwise.
    Uplinks, trunks and ports set down are left out.  A bound policy counts as
    protection whatever its content (open-auth / MAC-auth-bypass are not read
    from the stored rows).
    """
    rows = db.query(SwitchInterface).filter(or_(SwitchInterface.source_file.like("fortilink:%"),
                                                 SwitchInterface.source_file.like("fortiswitch:%")),
                                             SwitchInterface.mode == "access", SwitchInterface.uplink.is_(False)).all()
    if not rows:
        return []
    levels = {(v.device_name, str(v.vlan_id)): v.purdue_level for v in db.query(SwitchVlan)}
    by_sw: dict = {}
    for r in rows:
        if str(r.admin_status or "up").lower() == "down" or r.port_security_policy:
            continue
        lvl = levels.get((r.device_name, str(r.vlan or "")))
        by_sw.setdefault(r.device_name, []).append({"port": r.port_name, "vlan": r.vlan, "purdue_level": lvl,
                                                     "description": r.description})
    alerts = []
    for sw, ports in sorted(by_sw.items(), key=lambda kv: str(kv[0])):
        ot = [p for p in ports if isinstance(p["purdue_level"], (int, float)) and p["purdue_level"] <= 2]
        sev = "medium" if ot else "low"
        alerts.append(_make_finding(
            db, "switch_port_no_nac",
            f"FortiSwitch {sw}: {len(ports)} access port(s) without a port-security (802.1X) policy"
            + (f", {len(ot)} on OT VLANs" if ot else ""),
            f"{len(ports)} enabled access port(s) of FortiSwitch {sw} accept any device plugged in: no 802.1X / "
            f"MAC-authentication policy is bound to them" + (f"; {len(ot)} of them sit on VLANs labelled L0-L2" if ot else ""),
            {"switch_device": sw, "ports": ports[:60], "port_count": len(ports), "ot_ports": [p["port"] for p in ot][:60],
             "first_port": ports[0]["port"],
             "reason": "port-based NAC is the control that keeps a transient laptop or an unknown device off the control "
                       "network at the port; without it the transient-device and unknown-device findings are the only line",
             "checklist_title": "Switch port security / NAC on OT access ports"},
            device_name=sw, severity=sev, dedup_evidence={"switch_device": sw, "rule_key": f"nac:{sw}"}))
    return [a for a in alerts if a]


def review_switch_unused_ports(db: DBSession) -> list:
    """
    SR 7.7 — FortiLink-managed or standalone FortiSwitch access ports that are enabled but
    show no use: no description, no neighbour, no MAC ever seen on them
    (owner 2026-10-19).  One low finding per switch.
    """
    rows = db.query(SwitchInterface).filter(or_(SwitchInterface.source_file.like("fortilink:%"),
                                                 SwitchInterface.source_file.like("fortiswitch:%")),
                                             SwitchInterface.mode == "access", SwitchInterface.uplink.is_(False)).all()
    if not rows:
        return []
    used = {(m.device_name, m.port_name) for m in db.query(MacTableEntry.device_name, MacTableEntry.port_name).distinct()}
    by_sw: dict = {}
    for r in rows:
        if str(r.admin_status or "up").lower() == "down" or r.description or r.neighbor_device or (r.device_name, r.port_name) in used:
            continue
        by_sw.setdefault(r.device_name, []).append(r.port_name)
    alerts = []
    for sw, ports in sorted(by_sw.items(), key=lambda kv: str(kv[0])):
        alerts.append(_make_finding(
            db, "switch_unused_port_enabled",
            f"FortiSwitch {sw}: {len(ports)} enabled access port(s) with no use recorded",
            f"{len(ports)} access port(s) of FortiSwitch {sw} are up with no description, no neighbour and no MAC address "
            f"ever seen on them (MAC tables uploaded so far)",
            {"switch_device": sw, "ports": ports[:100], "port_count": len(ports),
             "first_port": ports[0]["port"] if isinstance(ports[0], dict) else ports[0],
             "reason": "an enabled, unused port is an open socket for anyone with physical access; shut it down "
                       "(set status down) or document what it is reserved for",
             "checklist_title": "Unused switch ports disabled"},
            device_name=sw, severity="low", dedup_evidence={"switch_device": sw, "rule_key": f"unused-ports:{sw}"}))
    return [a for a in alerts if a]


def review_transient_devices(db: DBSession) -> list:
    """
    NET-04 / UC-09 (2-1 NET 1.1, ZCR 3.4) - laptops, PCs and USB-Ethernet
    adapters (by OUI vendor) seen on a control network (L0-L2) that nobody
    identified: not manually classified, not in an inventory, not approved
    or excluded on the Inventory page.  One ``transient_device_in_ot_zone``
    per MAC listing its addresses; high when it sent industrial requests
    or used management ports, else medium.
    """
    from sqlalchemy import or_
    page_ips, page_macs = _page_approved(db)
    infra_ips, infra_macs, _vpn = _known_infrastructure(db)
    baseline = _active_baseline(db)
    inv_ips, inv_macs = set(), set()
    if baseline:
        for a in db.query(ApprovedHost).filter(ApprovedHost.baseline_id == baseline.id):
            if a.ip:
                inv_ips.add(a.ip)
            if a.mac:
                inv_macs.add(a.mac.lower())
    groups: dict = {}
    q = db.query(Host).filter(real_host_clause(), Host.mac.isnot(None), Host.vendor.isnot(None),
                              Host.purdue_level.isnot(None), Host.purdue_level <= 2,
                              or_(Host.classification_source.is_(None), Host.classification_source != "manual"),
                              Host.inventory_excluded.is_not(True))
    for h in _keyset(q, Host.id):
        if not _transient_vendor(h.vendor):
            continue
        mac = h.mac.lower()
        if mac in page_macs or mac in inv_macs or mac in infra_macs:
            continue
        if h.ip and (h.ip in page_ips or h.ip in inv_ips or h.ip in infra_ips):
            continue
        groups.setdefault(mac, []).append(h)
    alerts = []
    mgmt_ports = (21, 22, 23, 135, 139, 445, 3389, 5900, 5901, 5985, 5986)
    for mac, hosts in sorted(groups.items()):
        ids = [h.id for h in hosts]
        servers = (db.query(Host.ip, NetworkSession.dst_port)
                   .join(NetworkSession, NetworkSession.dst_host_id == Host.id)
                   .filter(NetworkSession.src_host_id.in_(ids)).all())
        ics = sorted({f"{ip}:{port}" for ip, port in servers if port in _ICS_CLIENT_PORTS})
        mgmt = sorted({f"{ip}:{port}" for ip, port in servers if port in mgmt_ports})
        addrs = sorted(h.ip for h in hosts if h.ip)
        vendor = hosts[0].vendor
        level = min(float(h.purdue_level) for h in hosts)
        sev = "high" if (ics or mgmt) else "medium"
        alerts.append(_make_finding(
            db, "transient_device_in_ot_zone",
            f"Transient / IT device on the control network: {', '.join(addrs) or mac} ({vendor})",
            f"The MAC {mac} belongs to {vendor} - laptop / PC / USB-Ethernet hardware - and sits at Purdue "
            f"L{level:g} with no identity (not classified by hand, not in any inventory, not approved). "
            + (f"It sends industrial-protocol requests to {', '.join(ics[:4])}. " if ics else "")
            + (f"It uses management ports on {', '.join(mgmt[:4])}. " if mgmt else "")
            + "Transient devices belong in their own zone (ZCR 3.4) or must be approved as engineering "
              "equipment in the inventory.",
            {"mac": mac, "addresses": addrs, "ip": addrs[0] if addrs else None, "vendor": vendor,
             "purdue_level": level, "ics_targets": ics[:10], "mgmt_targets": mgmt[:10],
             "checklist_title": "Transient and external-network device zones (ZCR 3.4 / 3.6)"},
            severity=sev, dedup_evidence={"mac": mac, "rule_key": f"transient:{mac}"},
        ))
    return [a for a in alerts if a]


def review_default_credentials(db: DBSession) -> list:
    """
    IAC-08 (3-3 SR 1.5, USER 1.12) - a cleartext login with a well-known
    default user / password pair, or an SNMP v1/v2c default community, was
    observed (the PCAP parser compared the values in the stream and kept
    only the kind).  One ``default_credentials_observed`` per client ->
    server:port, high.
    """
    src_h, dst_h = aliased(Host), aliased(Host)
    q = (db.query(NetworkSession, src_h, dst_h)
         .join(src_h, NetworkSession.src_host_id == src_h.id)
         .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
         .filter(NetworkSession.cleartext_auth.isnot(None),
                 or_(NetworkSession.cleartext_auth.like("%default credentials%"),
                     NetworkSession.cleartext_auth.like("%(default)%")))
         .order_by(NetworkSession.id))
    alerts, seen = [], set()
    for sess_row, src, dst in q:
        kinds = [k.strip() for k in (sess_row.cleartext_auth or "").split(",")
                 if "default credentials" in k or "(default)" in k]
        key = (src.ip or src.mac, dst.ip or dst.mac, sess_row.dst_port)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(_make_finding(
            db, "default_credentials_observed",
            f"Default credentials in use: {src.ip or src.mac} → {dst.ip or dst.mac}:{sess_row.dst_port} ({', '.join(kinds)})",
            f"{src.ip or src.mac} logged in to {dst.ip or dst.mac} on {sess_row.transport}/{sess_row.dst_port} with a "
            f"well-known default user / password pair or default SNMP community ({', '.join(kinds)}). Default "
            f"credentials are the first thing any attacker or worm tries; change them on the device and "
            f"replace the cleartext protocol where possible.",
            {"src_ip": src.ip, "dst_ip": dst.ip, "ip": dst.ip, "mac": dst.mac, "dst_port": sess_row.dst_port,
             "transport": sess_row.transport, "kinds": kinds,
             "checklist_title": "Default credentials changed (SR 1.5, USER 1.12)"},
            session_id=sess_row.id, severity="high",
            dedup_evidence={"src_ip": key[0], "dst_ip": key[1], "dst_port": key[2],
                            "rule_key": f"default-creds:{key[0]}>{key[1]}:{key[2]}"},
        ))
    return [a for a in alerts if a]


def review_weak_tls(db: DBSession) -> list:
    """
    DT-03 / DT-04 (3-3 SR 4.3, DATA 1.5) - a server negotiated SSLv3 / TLS
    1.0 / TLS 1.1 or spoke SSH-1 (ProtocolDetail rows written by the PCAP
    parser).  One ``weak_tls_observed`` per server:port, medium; high when a
    client from another Purdue level used it.
    """
    rows = (db.query(ProtocolDetail, NetworkSession)
            .join(NetworkSession, ProtocolDetail.session_id == NetworkSession.id)
            .filter(ProtocolDetail.protocol.in_(("tls", "ssh")))
            .order_by(ProtocolDetail.id).all())
    by_server: dict = {}
    for d, sess_row in rows:
        f = d.fields or {}
        if not f.get("weak"):
            continue
        key = (f.get("server_ip"), f.get("server_port"))
        e = by_server.setdefault(key, {"versions": set(), "clients": set(), "cross": False, "session_id": sess_row.id})
        e["versions"].add(str(f.get("version")))
        src = db.get(Host, sess_row.src_host_id)
        dst = db.get(Host, sess_row.dst_host_id)
        if src is not None and dst is not None:
            e["clients"].add(src.ip or src.mac or "?")
            if src.purdue_level is not None and dst.purdue_level is not None and src.purdue_level != dst.purdue_level:
                e["cross"] = True
    alerts = []
    for (sip, sp), e in sorted(by_server.items(), key=lambda kv: (str(kv[0][0]), kv[0][1] or 0)):
        vers = ", ".join(sorted(e["versions"]))
        alerts.append(_make_finding(
            db, "weak_tls_observed",
            f"Weak transport security on {sip}:{sp}: {vers}",
            f"The server {sip}:{sp} negotiated {vers} with {len(e['clients'])} client(s) "
            f"({', '.join(sorted(e['clients'])[:5])}). These versions have known downgrade and cipher "
            f"attacks; set the service to TLS 1.2+ (SSH-2) and update clients that cannot.",
            {"ip": sip, "dst_port": sp, "versions": sorted(e["versions"]), "clients": sorted(e["clients"])[:20],
             "cross_level": e["cross"], "checklist_title": "Cryptographic mechanisms (SR 4.3, DATA 1.5)"},
            session_id=e["session_id"], severity="high" if e["cross"] else "medium",
            dedup_evidence={"ip": str(sip), "dst_port": sp, "rule_key": f"weak-tls:{sip}:{sp}"},
        ))
    return [a for a in alerts if a]


def _wide_source_tokens(src: str, allowed_ips: set) -> list:
    """The comma-separated source tokens of a rule that are NOT one of the
    allowed single hosts: anything unresolvable, a network, a range, or a host
    outside ``allowed_ips``."""
    from app.parsers.rule_match import addr_contains, parse_address
    out = []
    for tok in (t.strip() for t in str(src or "").split(",")):
        if not tok:
            continue
        try:
            spec = parse_address(tok)
        except Exception:
            out.append(tok)
            continue
        narrow = any(addr_contains(parse_address(ip), spec) is True for ip in allowed_ips)
        if not narrow:
            out.append(tok)
    return out


def review_sis_isolation(db: DBSession) -> list:
    """
    NET 1.3 / 3-2 ZCR 3.3 - safety instrumented systems (SIS) in their own zone
    (evidence matrix NET-02, owner 2026-10-15).  SIS hosts = inventory hosts
    marked *Safety function* (Host.is_safety_function).  Raises
    ``sis_zone_not_isolated`` (one per cause, stable keys):
      * session - observed traffic into a SIS host from a host that is neither
        a safety host nor an engineering workstation (high);
      * rule - an enabled permit rule whose destination covers a SIS host and
        whose source is wider than named safety / engineering hosts (high);
      * subnet - a SIS host sharing its network (the firewall interface
        network, else the /24) with non-safety hosts (medium).
    """
    from app.parsers.rule_match import addr_contains, is_family_wide, parse_address
    sis = [h for h in db.query(Host).filter(real_host_clause(), Host.is_safety_function.is_(True)) if h.ip or h.mac]
    if not sis:
        return []
    alerts = []
    sis_ids = {h.id for h in sis}
    by_id = {h.id: h for h in sis}
    allowed = db.query(Host).filter(real_host_clause(), or_(
        Host.is_safety_function.is_(True), Host.device_type.in_(_SIS_SOURCE_TYPES))).all()
    allowed_ips = {h.ip for h in allowed if h.ip}
    allowed_ids = {h.id for h in allowed}
    # (a) sessions into SIS hosts
    src_h = aliased(Host)
    seen = set()
    q = (db.query(NetworkSession, src_h).join(src_h, NetworkSession.src_host_id == src_h.id)
         .filter(NetworkSession.dst_host_id.in_(sorted(sis_ids))).order_by(NetworkSession.id))
    for sess_row, src in q:
        if src.id in allowed_ids:
            continue
        dst = by_id.get(sess_row.dst_host_id)
        key = (src.ip or src.mac, dst.ip or dst.mac)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(_make_finding(
            db, "sis_zone_not_isolated",
            f"Safety system {dst.ip or dst.mac} reached from non-safety host {src.ip or src.mac}",
            f"A session from {src.ip or src.mac} ({src.device_type or 'unclassified'}, "
            f"{fmt_level(src.purdue_level) if src.purdue_level is not None else 'no level'}) to the safety "
            f"instrumented system {dst.ip or dst.mac} on {sess_row.transport}/{sess_row.dst_port} was observed. "
            f"Only the safety engineering workstation and other safety hosts should talk to the SIS; "
            f"any other source is a path from the control / IT side into the protection layer.",
            {"kind": "session", "ip": dst.ip, "mac": dst.mac, "src_ip": src.ip, "src_mac": src.mac, "dst_ip": dst.ip,
             "src_device_type": src.device_type, "dst_port": sess_row.dst_port, "transport": sess_row.transport,
             "protocol": sess_row.protocol,
             "checklist_title": "Safety system segmentation (NET 1.3, ZCR 3.3)"},
            session_id=sess_row.id, severity="high",
            dedup_evidence={"src_ip": key[0], "dst_ip": key[1], "rule_key": f"sis-session:{key[0]}>{key[1]}"},
        ))
    # (b) permit rules into SIS hosts from a wide source
    sis_specs = [(h, parse_address(h.ip)) for h in sis if h.ip]
    rules = db.query(FirewallRule).filter(FirewallRule.action == "permit", FirewallRule.enabled.is_not(False)).all()
    seen_rules = set()
    for r in rules:
        try:
            dst_spec = parse_address(r.dst)
        except Exception:
            continue
        # audit 2026-10-15: a "dst all" rule (every Internet-access policy) names no SIS host
        if is_family_wide(dst_spec):
            continue
        hit = [h for h, spec in sis_specs if addr_contains(dst_spec, spec) is True]
        if not hit:
            continue
        wide = _wide_source_tokens(r.src, allowed_ips)
        if not wide:
            continue
        # stable per logical rule (policy id + VDOM; else the rule's own addresses), not the row id
        logical = (f"{r.vdom or ''}:{r.policy_id}" if r.policy_id else f"{r.src}>{r.dst}:{r.dst_port or 'any'}")
        rkey = (str(r.device_name or r.firewall_id), logical)
        if rkey in seen_rules:
            continue
        seen_rules.add(rkey)
        alerts.append(_make_finding(
            db, "sis_zone_not_isolated",
            f"Policy {r.policy_id or r.id} on {r.device_name or 'firewall'} permits {', '.join(wide[:3])} into the safety system",
            f"Permit rule {r.policy_id or r.id} ({r.src} → {r.dst}:{r.dst_port or 'any'}) covers the safety "
            f"instrumented system(s) {', '.join(h.ip for h in hit[:5])} with a source that is not limited to the "
            f"named safety / engineering hosts. Restrict the source to the safety engineering workstation.",
            {"kind": "rule", "policy_id": r.policy_id, "firewall_id": r.firewall_id, "device_name": r.device_name,
             "src": r.src, "dst": r.dst, "dst_port": r.dst_port, "wide_sources": wide[:10],
             "sis_hosts": [h.ip for h in hit[:10]], "ip": hit[0].ip,
             "checklist_title": "Safety system segmentation (NET 1.3, ZCR 3.3)"},
            firewall_rule_id=r.id, device_name=r.device_name, severity="high",
            dedup_evidence={"device_name": rkey[0], "rule_key": f"sis-rule:{rkey[0]}:{rkey[1]}"},
        ))
    # (c) SIS hosts sharing a network with non-safety hosts
    nets = {}
    ifnets = []
    for (cidr,) in db.query(FirewallInterface.network_cidr).filter(FirewallInterface.network_cidr.isnot(None)):
        try:
            ifnets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    for h in sis:
        if not h.ip:
            continue
        try:
            a = ipaddress.ip_address(h.ip)
        except ValueError:
            continue
        net = next((n for n in ifnets if a in n), None) or ipaddress.ip_network(
            f"{h.ip}/{64 if a.version == 6 else 24}", strict=False)
        nets.setdefault(str(net), []).append(h)
    # every other real host once (audit 2026-10-15: not per network; inventory-excluded hosts -
    # scanners, broadcast / virtual addresses - do not count)
    candidates = []
    if nets:
        for h in db.query(Host).filter(real_host_clause(), Host.ip.isnot(None), Host.inventory_excluded.is_not(True)):
            if h.id in allowed_ids:
                continue
            try:
                candidates.append((ipaddress.ip_address(h.ip), h))
            except ValueError:
                continue
    for net_s, members in sorted(nets.items()):
        net = ipaddress.ip_network(net_s)
        others = [h for a, h in candidates if a.version == net.version and a in net]
        if not others:
            continue
        alerts.append(_make_finding(
            db, "sis_zone_not_isolated",
            f"Safety system(s) share network {net_s} with {len(others)} non-safety host(s)",
            f"The safety instrumented system(s) {', '.join(h.ip for h in members[:5])} sit on {net_s} together with "
            f"{', '.join(h.ip for h in others[:5])}{' …' if len(others) > 5 else ''}. A SIS needs its own zone "
            f"(interface / VLAN) so that only safety traffic reaches it.",
            {"kind": "subnet", "network": net_s, "sis_hosts": [h.ip for h in members[:10]],
             "other_hosts": [h.ip for h in others[:20]], "other_count": len(others), "ip": members[0].ip,
             "checklist_title": "Safety system segmentation (NET 1.3, ZCR 3.3)"},
            severity="medium", dedup_evidence={"ip": net_s, "rule_key": f"sis-subnet:{net_s}"},
        ))
    return [a for a in alerts if a]


def review_wireless_in_ot_zone(db: DBSession) -> list:
    """
    SR 7.7 / 2.6 — Wireless access point in OT/control zone.

    Any WAP/AP (role="ap") classified at Purdue Level 0-2 represents an
    uncontrolled wireless ingress point in the control network.  OT zones
    must not have wireless unless there is an explicit engineering
    justification and compensating controls.

    Fires when Host.role=="ap" AND Host.purdue_level <= 2.
    """
    alerts = []
    aps = db.query(Host).filter(
        Host.role == "ap",
        Host.purdue_level.isnot(None),
        Host.purdue_level <= 2,
    ).all()
    for host in aps:
        alerts.append(_make_finding(
            db, "wireless_in_ot_zone",
            f"Wireless AP in OT zone: {host.ip or host.mac} ({fmt_level(host.purdue_level)})",
            f"Host {host.ip or host.mac} is identified as a wireless access point "
            f"(role={host.role!r}, source={host.role_source!r}) at Purdue Level "
            f"{host.purdue_level}. Wireless in OT/control zones (Level 0-2) introduces "
            f"an uncontrolled RF attack surface. Wireless devices in these zones require "
            f"explicit risk acceptance and compensating controls (e.g. dedicated OT Wi-Fi "
            f"with device authentication).",
            {"ip": host.ip, "mac": host.mac, "role": host.role,
             "purdue_level": host.purdue_level,
             "role_source": host.role_source,
             "vendor": host.vendor,
             "checklist_title": "No wireless APs in OT/control zones"},
        ))
    # IO-04: consumer Wi-Fi / router gear seen in captures (no LLDP needed)
    import json as _json
    from app.models import PcapCapture
    from app.parsers.segments import CONSUMER_NET_WORDS, vendor_matches
    roles = {h.id for h in aps}
    gws, dhcp = set(), {}
    for (raw,) in db.query(PcapCapture.segment).filter(PcapCapture.segment.isnot(None)):
        try:
            seg = _json.loads(raw)
        except ValueError:
            continue
        gws |= {str(m).lower() for m in seg.get("gateway_macs") or []}
        for srv in seg.get("dhcp_servers") or []:
            if srv.get("mac"):
                dhcp[str(srv["mac"]).lower()] = srv
    seen_macs = set()
    for host in db.query(Host).filter(real_host_clause(), Host.mac.isnot(None)):
        mac = host.mac.lower()
        if host.id in roles or mac in seen_macs or not vendor_matches(host.vendor, CONSUMER_NET_WORDS):
            continue
        if host.classification_source == "manual" and host.device_type not in (None, "router"):
            continue
        seen_macs.add(mac)
        acts = []
        if mac in gws:
            acts.append("routes traffic for other hosts (gateway)")
        if mac in dhcp:
            acts.append(f"serves DHCP ({len(dhcp[mac].get('leases') or [])} lease(s))")
        alerts.append(_make_finding(
            db, "wireless_in_ot_zone",
            f"Consumer Wi-Fi / router equipment on the OT network: {host.ip or 'no-ip'} / {host.mac} ({host.vendor})",
            (f"{host.ip or host.mac} is consumer / SOHO network equipment ({host.vendor})"
             + (" that " + " and ".join(acts) if acts else "") + ". Such a device usually brings a wireless "
             "network with it: every phone or laptop that joins it is on the OT network, past any physical "
             "control. Remove it, or replace it with managed OT equipment and document the wireless link "
             "with its compensating controls (SR 7.7, workbook row 2.6)."),
            {"ip": host.ip, "mac": host.mac, "vendor": host.vendor, "gateway": mac in gws,
             "dhcp_server": mac in dhcp, "basis": "capture: consumer network gear OUI",
             "checklist_title": "No wireless APs in OT/control zones",
             "severity_reason": "High: consumer wireless / routing equipment on the control network."},
            severity="high", dedup_evidence={"rule_key": f"consumer_netgear:{mac}"},
        ))
    return [a for a in alerts if a]


def review_single_path_critical_devices(db: DBSession) -> list:
    """
    SR 7.7, SR 7.1 / 7.1 — Critical OT devices with a single network path.

    Checks whether PLCs, RTUs, and HMIs (role in plc/rtu/hmi/ied) have
    more than one SwitchInterface neighbor entry — i.e., appear on more
    than one switch port, which is the basic evidence of a redundant uplink.
    A host with only one switch port entry is a single point of failure.

    This is a structural check based on topology data, not traffic.  It
    can only work once switch config files have been ingested (SwitchInterface
    rows populated).  Returns no findings when no switch data is present —
    correct, since "no evidence" ≠ "single path confirmed".
    """
    from sqlalchemy import func

    _CRITICAL_ROLES = {"plc", "rtu", "hmi", "ied"}

    # Only run if switch topology data is available at all.
    if db.query(SwitchInterface).count() == 0:
        return []

    alerts = []
    critical_hosts = db.query(Host).filter(
        Host.role.in_(_CRITICAL_ROLES),
        Host.ip.isnot(None),
    ).all()

    for host in critical_hosts:
        # Count switch ports where this host is a neighbor (by IP or MAC).
        port_count = 0
        if host.ip:
            port_count = db.query(SwitchInterface).filter(
                SwitchInterface.neighbor_ip == host.ip
            ).count()
        if port_count == 0 and host.mac:
            # Try MAC match on neighbor_device (LLDP chassis-ID-as-MAC)
            port_count = db.query(SwitchInterface).filter(
                SwitchInterface.neighbor_device == host.mac
            ).count()

        if port_count == 0:
            continue  # not visible in switch topology - can't make determination

        if port_count == 1:
            alerts.append(_make_finding(
                db, "single_path_critical_device",
                f"Critical OT device with single network path: "
                f"{host.ip or host.mac} ({host.role})",
                f"Host {host.ip or host.mac} (role={host.role!r}, "
                f"purdue_level={host.purdue_level}) appears on only one switch port "
                f"in the topology data. A single network path is a single point of "
                f"failure for a critical OT device. Consider dual-homing or using a "
                f"ring topology (e.g. PROFINET MRP, RSTP) to provide redundancy.",
                {"ip": host.ip, "mac": host.mac, "role": host.role,
                 "purdue_level": host.purdue_level,
                 "switch_port_count": port_count,
                 "checklist_title": "Critical connections have redundant paths"},
            ))
    return [a for a in alerts if a]


def review_undocumented_lldp_devices(db: DBSession) -> list:
    """
    SR 7.8 / 7.7 — Devices visible in LLDP/CDP but absent from asset inventory.

    Complements review_unknown_devices (8.6 / SR 7.8) which compares Host
    MAC/IP against ApprovedHost.  This check is specifically for hosts
    where LLDP/CDP has given us a *role* (confirming they are active network
    participants) but no ApprovedHost entry exists for them — the combination
    of "we know what it is" and "it's not in the inventory" is a stronger
    finding than just "unknown MAC".

    Requires an active Baseline. Returns no findings when no baseline exists.
    """
    baseline = _active_baseline(db)
    if not baseline:
        _mark_incomplete(db, "no active baseline")
        return []

    approved_ips = {
        h.ip for h in db.query(ApprovedHost).filter(
            ApprovedHost.baseline_id == baseline.id,
        ).all() if h.ip
    }
    approved_macs = {
        h.mac.lower() for h in db.query(ApprovedHost).filter(
            ApprovedHost.baseline_id == baseline.id,
        ).all() if h.mac
    }
    if not approved_ips and not approved_macs:
        _mark_incomplete(db, "baseline has no approved hosts")
        return []

    alerts = []
    # Only flag hosts where we have a role from LLDP/CDP — these are
    # confirmed active devices, not just passive MAC table entries.
    lldp_hosts = db.query(Host).filter(
        Host.role.isnot(None),
        Host.role_source.in_(["lldp", "cdp"]),
    ).all()

    infra_ips, infra_macs, _vpn_ctx = _known_infrastructure(db)
    for host in lldp_hosts:
        # LS-07 (H-15): a firewall's / routing switch's own interface is
        # known infrastructure, not an undocumented device.
        if (host.ip and host.ip in infra_ips) or (host.mac and host.mac.lower() in infra_macs):
            continue
        ip_ok = host.ip and host.ip in approved_ips
        mac_ok = host.mac and host.mac.lower() in approved_macs
        if ip_ok or mac_ok:
            continue  # it's in the approved inventory

        alerts.append(_make_finding(
            db, "undocumented_lldp_device",
            f"LLDP-identified device not in asset inventory: "
            f"{host.ip or 'no-ip'} / {host.mac or 'no-mac'} ({host.role})",
            f"Host {host.ip or host.mac} has been identified as role={host.role!r} "
            f"via {host.role_source!r} neighbor discovery but does not appear in the "
            f"approved asset inventory (matched on neither IP nor MAC). "
            f"All OT devices should be documented in the asset inventory.",
            {"ip": host.ip, "mac": host.mac, "role": host.role,
             "role_source": host.role_source,
             "vendor": host.vendor,
             "purdue_level": host.purdue_level,
             "checklist_title": "Asset inventory complete and current"},
        ))
    return [a for a in alerts if a]


def review_mgmt_access_from_wrong_zone(db: DBSession) -> list:
    """
    SR 1.3, SR 5.1 RE1 / 5.1 — Management access only from approved management hosts.

    Looks for NetworkSession rows where:
    - dst_port is a management protocol (SSH/Telnet/HTTPS/RDP/SNMP)
    - dst_host.purdue_level <= 2 (OT device being managed)
    - src_host.ip is NOT in the set of approved admin_ws / jump_host IPs

    Requires: pcap ingest (NetworkSession), LLDP role classification (Host.purdue_level),
    and a baseline with at least one ApprovedHost row with role "admin_ws" or "jump_host".
    Returns empty (not an error) when any of these datasets is absent.
    """
    MGMT_PORTS = {22, 23, 443, 3389, 80, 8080, 8443, 161, 5900, 5901, 5985, 5986}  # SSH, Telnet, HTTPS, RDP, HTTP, SNMP, VNC, WinRM (SF-3)

    # Approved management sources: the active baseline's admin_ws / jump_host
    # entries (IP or CIDR) plus the declared management networks, trusted
    # management hosts and hosts on management VLANs.
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)
    if not mctx.has_sources:
        _mark_incomplete(db, "no approved management hosts or management networks")
        return []  # nothing declared yet - can't evaluate
    approved_mgmt_ips = [str(n) for n, _d, _p in mctx.nets]

    # Find sessions to OT management ports where destination is OT (L0-2).
    # Filter purdue_level at the SQL level to avoid loading all mgmt-port
    # sessions and then discarding IT-to-IT ones in Python.
    _dst_host_alias = aliased(Host)
    sessions = _keyset(   # B-06: every matching session, paged
        db.query(NetworkSession)
        .join(_dst_host_alias, NetworkSession.dst_host_id == _dst_host_alias.id)
        .filter(
            NetworkSession.dst_port.in_(list(MGMT_PORTS)),
            _dst_host_alias.purdue_level <= 2,
            _dst_host_alias.purdue_level.isnot(None),
        )
        .options(
            joinedload(NetworkSession.src_host),
            joinedload(NetworkSession.dst_host),
        ),
        NetworkSession.id,
    )

    alerts = []
    for sess in sessions:
        src = sess.src_host
        dst = sess.dst_host
        if not src or not dst:
            continue
        if dst.purdue_level is None or dst.purdue_level > 2:
            continue  # only care about management access TO OT equipment
        if mctx.is_admin_ip(src.ip, ot=True):
            continue  # legitimate - an approved management / engineering source (OT target)

        proto_label = {22: "SSH", 23: "Telnet", 443: "HTTPS", 3389: "RDP",
                       80: "HTTP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
                       161: "SNMP", 5900: "VNC", 5901: "VNC", 5985: "WinRM",
                       5986: "WinRM"}.get(sess.dst_port, f"port {sess.dst_port}")
        # F-08: from the industrial DMZ this is the sanctioned remote-access
        # path, most likely a jump host missing from the baseline - one
        # severity step lower than the same access from L3/L4/L5.
        dmz_source = is_dmz(src.purdue_level)
        base_sev = CHECK_TYPE_REFERENCE["mgmt_access_from_wrong_zone"][2]
        alerts.append(_make_finding(
            db, "mgmt_access_from_wrong_zone",
            f"Mgmt access from unapproved {'DMZ ' if dmz_source else ''}host: "
            f"{src.ip} → {dst.ip} ({proto_label})",
            f"Management protocol {proto_label} was observed from {src.ip} "
            f"({fmt_level(src.purdue_level) if src.purdue_level is not None else 'unclassified'}) to OT device "
            f"{dst.ip} (Purdue {fmt_level(dst.purdue_level)}). Source {src.ip} is not an "
            f"approved engineering workstation, admin workstation or jump host and is not "
            f"inside a declared engineering or management network or VLAN. "
            + (
                "The source is in the industrial DMZ (L3.5), the sanctioned location for "
                "remote-access jump hosts; if it is one, add it as a trusted management host "
                "(role jump_host) and restrict OT management to it. "
                if dmz_source else
                "Access to OT equipment should originate only from designated engineering "
                "workstations or management hosts (e.g. a jump host in the industrial DMZ); if "
                "it is an engineering workstation, add it as one (Findings > Fix) "
            )
            + "(ISA/IEC 62443 SR 5.1 RE1).",
            {"src_ip": src.ip, "dst_ip": dst.ip, "dst_port": sess.dst_port,
             "protocol_label": proto_label, "dst_purdue_level": dst.purdue_level,
             "src_purdue_level": src.purdue_level, "dmz_source": dmz_source,
             "approved_mgmt_sources_count": len(approved_mgmt_ips) + len(mctx.host_ips)},
            session_id=sess.id,
            severity=_SEVERITY_STEP_DOWN.get(base_sev, base_sev) if dmz_source else None,
        ))
    return [a for a in alerts if a]


def review_mgmt_access_not_restricted(db: DBSession) -> list:
    """
    SR 1.3, SR 5.1 / 2.5 — Management access to OT equipment restricted
    to a dedicated management zone (not reachable from general OT/IT subnets).

    Complements review_mgmt_access_from_wrong_zone (5.1): where 5.1 checks
    WHICH HOST initiated management access, this check asks whether the
    DESTINATION OT device is reachable from multiple distinct network zones.

    Flags OT devices (purdue_level <= 2) that received management-protocol
    sessions from more than one distinct src_host Purdue level — indicating
    that the device is reachable from multiple network segments, not locked
    down to a single management zone.
    """
    MGMT_PORTS = {22, 23, 443, 3389, 80, 8080, 8443, 5900, 5901, 5985, 5986}   # SF-3: + VNC, WinRM

    # B-06: keyset-paginated (memory bounded by one page; only the per-dst
    # level sets are accumulated) instead of a silent 10 000-row cap.
    sessions = _keyset(
        db.query(NetworkSession)
        .filter(NetworkSession.dst_port.in_(list(MGMT_PORTS)))
        .options(
            joinedload(NetworkSession.src_host),
            joinedload(NetworkSession.dst_host),
        ),
        NetworkSession.id,
    )

    # Declared management sources count as ONE zone ("management"), whatever
    # Purdue level they sit at: a device managed only from them is restricted.
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)

    # Collect (dst_host → set of src zones seen: Purdue level or "management")
    dst_src_levels: dict[int, set] = {}   # dst host id → set of src purdue levels
    dst_hosts: dict[int, object] = {}
    sess_by_dst: dict[int, int] = {}      # dst host id → one session id for evidence

    for sess in sessions:
        src = sess.src_host
        dst = sess.dst_host
        if not src or not dst:
            continue
        if dst.purdue_level is None or dst.purdue_level > 2:
            continue
        if mctx.is_admin_ip(src.ip, ot=True):
            dst_hosts[dst.id] = dst
            dst_src_levels.setdefault(dst.id, set()).add("management")
            sess_by_dst[dst.id] = sess.id
            continue
        if src.purdue_level is None:
            _count_unknown_level(db, src.ip, dst.ip)   # B-20: counted, not silent (B12: the finding is keyed on dst_ip)
            continue
        dst_hosts[dst.id] = dst
        dst_src_levels.setdefault(dst.id, set()).add(src.purdue_level)
        sess_by_dst[dst.id] = sess.id

    alerts = []
    for dst_id, src_levels in dst_src_levels.items():
        if len(src_levels) < 2:
            continue  # only reachable from one zone level — OK
        dst = dst_hosts[dst_id]
        levels = sorted(lv for lv in src_levels if lv != "management")
        from_mgmt = "management" in src_levels
        zones_txt = (_fmt_levels(set(levels)) if levels else "") + (
            (", " if levels else "") + "management network" if from_mgmt else "")
        alerts.append(_make_finding(
            db, "mgmt_access_not_restricted",
            f"OT device reachable from multiple zones: {dst.ip} "
            f"(mgmt sessions from {zones_txt})",
            f"OT device {dst.ip} (Purdue {fmt_level(dst.purdue_level)}) received management-protocol "
            f"connections from source hosts at Purdue levels {levels}"
            + (" and from the declared management network(s)" if from_mgmt else "") + ". "
            f"Management access to OT equipment should be restricted to a single "
            f"dedicated management zone; reachability from multiple levels indicates "
            f"the device is not properly isolated (ISA/IEC 62443 SR 1.3, SR 5.1). "
            f"If one of the sources is a management workstation, add it as a trusted "
            f"management host or declare its network a management network.",
            {"dst_ip": dst.ip, "dst_purdue_level": dst.purdue_level,
             "src_purdue_levels": levels, "from_management_network": from_mgmt,
             "zone_count": len(src_levels)},
            session_id=sess_by_dst.get(dst_id),
        ))
    return [a for a in alerts if a]


def review_no_path_redundancy(db: DBSession) -> list:
    """
    SR 7.1, SR 7.2 / 7.2 — Redundant network paths verified.

    Extends the single-path check (7.1) to cover infrastructure devices:
    flags switches and routers (role in {"switch", "router"}) that appear
    in the SwitchInterface neighbor table from only ONE direction — i.e.
    they have only a single upstream neighbor visible via LLDP/CDP, which
    indicates no redundant uplink to the core network.

    Additionally checks for any host that has already triggered a
    `single_path_critical_device` (7.1) finding AND has no corresponding
    HA configuration evidence — meaning redundancy hasn't been verified by
    any other means either.

    Returns empty when no LLDP/CDP data is present.
    """
    # --- Part 1: infrastructure devices with a single visible uplink ---
    INFRA_ROLES = {"switch", "router"}

    # All SwitchInterface rows that identify the device by IP
    all_ifaces = db.query(SwitchInterface).filter(
        SwitchInterface.neighbor_ip.isnot(None),
    ).all()
    if not all_ifaces:
        return []  # no topology data yet

    # Pre-load all hosts by IP to avoid N+1 queries
    all_hosts_by_ip: dict[str, object] = {
        h.ip: h for h in db.query(Host).filter(Host.ip.isnot(None)).all()
    }

    # Count DISTINCT upstream switch device_names per infrastructure device.
    # Each SwitchInterface row represents one switch port that sees this device
    # as a LLDP/CDP neighbor. The iface.device_name is the switch doing the
    # reporting. Counting distinct device_names gives the number of distinct
    # physical switches that see this device — i.e. the number of uplink paths.
    # Using port_name alone would double-count a switch with two ports to the
    # same upstream device. Using device_name gives us distinct upstream switches.
    from collections import defaultdict
    # Maps infra_host_ip → set of upstream switch device_names that see it
    upstream_switches: dict[str, set] = defaultdict(set)
    ip_to_host: dict[str, object] = {}

    for iface in all_ifaces:
        host = all_hosts_by_ip.get(iface.neighbor_ip)
        if host and host.role in INFRA_ROLES:
            # iface.device_name = the switch doing the reporting (the upstream)
            upstream_switches[host.ip].add(iface.device_name)
            ip_to_host[host.ip] = host

    # neighbor_count is now the number of distinct upstream switches visible
    neighbor_count = {ip: len(switches) for ip, switches in upstream_switches.items()}

    alerts = []
    for ip, count in neighbor_count.items():
        if count > 1:
            continue  # at least 2 uplinks visible — skip
        host = ip_to_host[ip]
        alerts.append(_make_finding(
            db, "no_path_redundancy_verified",
            f"Single uplink detected: {ip} ({host.role}) has only 1 visible LLDP/CDP neighbor",
            f"Infrastructure device {ip} (role={host.role!r}) has only one LLDP/CDP-visible "
            f"upstream neighbor. No redundant path has been verified by neighbor-discovery "
            f"data. A single path means any link failure causes loss of connectivity for "
            f"downstream OT devices (ISA/IEC 62443 SR 7.1, SR 7.2). "
            f"Verify physical redundancy or dual-homed uplinks.",
            {"ip": ip, "role": host.role, "visible_uplinks": count,
             "purdue_level": host.purdue_level},
        ))

    # --- Part 2: critical devices with an open 7.1 finding and no HA event ---
    # If review_single_path_critical_devices has already flagged a device, and
    # there's no ha_system_error finding for any device (which would imply HA
    # config is present), raise an additional 7.2 finding for that same device.
    open_71 = db.query(Finding).filter(
        Finding.check_name == "single_path_critical_device",
        Finding.status == "open",
    ).all()

    # ha_system_error findings store the affected host under evidence["device_name"]
    # (the FortiGate hostname that reported the HA error), not under "ip".
    # Collecting by "device_name" matches the `ip` lookup below because the
    # single_path_critical_device findings store their target in evidence["ip"],
    # which for network infrastructure devices IS the device name/IP used in
    # LLDP/CDP tables.  We therefore collect the device_name from HA findings
    # and suppress a single_path finding when the same device has HA evidence.
    ha_devices: set[str] = set(
        f.detail.get("device_name")
        for f in db.query(Finding).filter(
            Finding.check_name == "ha_system_error",
        ).all()
        if f.detail and f.detail.get("device_name")
    )

    for f in open_71:
        evidence = f.detail or {}
        ip = evidence.get("ip")
        if not ip or ip in ha_devices:
            continue  # HA is configured — redundancy may be present via other means
        alerts.append(_make_finding(
            db, "no_path_redundancy_verified",
            f"Path redundancy not verified: {ip} has single LLDP path and no HA evidence",
            f"Critical OT device {ip} has been flagged as single-path (7.1 finding open) "
            f"and no HA configuration evidence has been observed for any device in the "
            f"environment. Redundancy for this device has not been verified by any means "
            f"(ISA/IEC 62443 SR 7.2).",
            {"ip": ip, "single_path_finding_id": f.id, "ha_evidence": False},
        ))

    return [a for a in alerts if a]


def review_firmware_not_documented(db: DBSession) -> list:
    """
    SR 7.8, SR 2.2 / 7.8 — OT device firmware versions documented.

    For each OT-role host (plc, rtu, hmi, ied) that has at least one
    SwitchInterface row with a non-null neighbor_platform (CDP platform string,
    which often includes firmware/version info), checks whether the corresponding
    ApprovedHost entry has a notes field that appears to document a firmware
    or software version.

    A platform string without a documented version in the asset inventory
    is flagged as a low-severity finding — the platform IS known (CDP saw it)
    but the firmware version has not been formally documented.

    Returns empty when no CDP data or no active baseline is present.
    """
    OT_ROLES = {"plc", "rtu", "hmi", "ied", "scada_server", "historian"}
    VERSION_PATTERNS = ("fw", "ver", "v.", "rev", "release", "firmware", "software", "os:")

    active = _active_baseline(db)
    if not active:
        return []

    # Index approved hosts by IP for fast lookup
    approved_by_ip: dict[str, object] = {
        ah.ip: ah for ah in db.query(ApprovedHost).filter(
            ApprovedHost.baseline_id == active.id,
            ApprovedHost.ip.isnot(None),
        ).all()
    }

    # Find OT-role hosts with CDP platform data
    ot_hosts = db.query(Host).filter(
        Host.role.in_(list(OT_ROLES)),
        Host.ip.isnot(None),
    ).all()

    if not ot_hosts:
        return []

    # Bulk-load all CDP SwitchInterface rows for OT host IPs in one query to
    # avoid N+1 (one SELECT per host in the loop below).
    ot_ips = [h.ip for h in ot_hosts]
    all_cdp_ifaces = db.query(SwitchInterface).filter(
        SwitchInterface.neighbor_ip.in_(ot_ips),
        SwitchInterface.neighbor_platform.isnot(None),
    ).all()
    cdp_by_ip: dict = {}
    for iface in all_cdp_ifaces:
        cdp_by_ip.setdefault(iface.neighbor_ip, []).append(iface)

    alerts = []
    for host in ot_hosts:
        # Get CDP neighbor_platform strings for this host (already loaded)
        ifaces = cdp_by_ip.get(host.ip, [])
        if not ifaces:
            continue  # no CDP platform data — can't evaluate

        platform_str = ifaces[0].neighbor_platform  # use first CDP record

        # Check if there's an approved-inventory entry with firmware notes
        ah = approved_by_ip.get(host.ip)
        notes_lower = (ah.notes or "").lower() if ah else ""

        # Does the notes field look like it contains a firmware/version reference?
        has_version_doc = any(pat in notes_lower for pat in VERSION_PATTERNS)
        if has_version_doc:
            continue  # firmware version is documented

        alerts.append(_make_finding(
            db, "firmware_not_documented",
            f"Firmware version undocumented: {host.ip} ({host.role}) — CDP: {platform_str!r}",
            f"OT device {host.ip} (role={host.role!r}) is visible via CDP with platform "
            f"string {platform_str!r}. However, its firmware/software version has not been "
            f"documented in the asset inventory notes field. "
            f"ISA/IEC 62443 SR 7.8 requires firmware versions to be tracked and current. "
            f"Update the approved asset inventory entry for {host.ip} to include the "
            f"firmware version, or flag it for a firmware review.",
            {"ip": host.ip, "role": host.role, "cdp_platform": platform_str,
             "has_inventory_entry": ah is not None,
             "inventory_notes": ah.notes if ah else None},
        ))
    return [a for a in alerts if a]


def review_zone_documentation(db: DBSession) -> list:
    """
    CTR 1.1 – 1.6: Zone Documentation (attestation-backed).

    These six controls require a human reviewer to confirm that policy and
    design artifacts exist and have been approved.  Automated detection
    cannot substitute for that review, so each row is satisfied by a
    current Attestation record (is_current=True, attested_at < 365 days
    ago).  When no such record exists, a periodic_review Finding is opened.

    Attestations are managed via POST /attestation and the web form at
    GET /ui/attestation.
    """
    ZONE_DOC_ROWS = [
        ("1.1", "zone_doc_1_1", "Zone documentation control 1.1 missing current attestation: OT zones not formally defined/documented"),
        ("1.2", "zone_doc_1_2", "Zone documentation control 1.2 missing current attestation: zones not defined by risk/consequence"),
        ("1.3", "zone_doc_1_3", "Zone documentation control 1.3 missing current attestation: zone boundaries not confirmed enforced"),
        ("1.4", "zone_doc_1_4", "Zone documentation control 1.4 missing current attestation: communication conduits not documented"),
        ("1.5", "zone_doc_1_5", "Zone documentation control 1.5 missing current attestation: security requirements not defined per zone"),
        ("1.6", "zone_doc_1_6", "Zone documentation control 1.6 missing current attestation: zone documentation not reviewed/approved"),
    ]
    STALE_DAYS = 365
    # Use tz-aware UTC to match the utcnow() helper in models.py, which
    # stores datetime.now(timezone.utc). datetime.utcnow() is naive and
    # causes a TypeError when compared against tz-aware attested_at values.
    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)

    # Load all current, non-stale attestations in one query
    satisfied = set()
    atts = db.query(Attestation).filter(
        Attestation.is_current == True,
        Attestation.attested_at >= cutoff,
    ).all()
    for att in atts:
        satisfied.add(att.checklist_id)

    # Bulk-prefetch which row IDs have ANY attestation (regardless of staleness)
    # so the per-row stale-vs-never-attested discrimination below avoids issuing
    # one extra query per unsatisfied row. (P4-L6)
    all_attested_ids: set[str] = {
        row[0]
        for row in db.query(Attestation.checklist_id).distinct().all()
    }

    results = []
    for (row_id, check_name, title) in ZONE_DOC_ROWS:
        if row_id in satisfied:
            continue
        # Check if an older attestation exists (stale vs. never attested)
        has_old = row_id in all_attested_ids
        evidence = {
            "checklist_id": row_id,
            "reason": "attestation stale (> 365 days)" if has_old else "no attestation on record",
        }
        result = _make_finding(
            db,
            check_name=check_name,
            title=title,
            detail_text=(
                f"Checklist row {row_id} has no current attestation within "
                f"the last {STALE_DAYS} days. Submit an attestation at "
                "/ui/attestation to satisfy this control."
            ),
            evidence=evidence,
        )
        if result:
            results.append(result)
    return [r for r in results if r]


def review_ntp_sync(db: DBSession) -> list:
    """
    CTR 9.3: OT devices must sync NTP from a dedicated internal NTP server,
    not directly from the internet or FortiGuard.

    Two data sources are combined:

    SOURCE 1 — FortiGate config (authoritative for the firewall itself):
      The most recently ingested FortiGate config is queried via the
      FirewallRule table's device_name to locate which device name to check,
      then the parsed NTP settings are re-read from `dns_ntp` stored on the
      Finding detail of existing config findings, OR we query FortiAnalyzerEvent
      rows with the NTP-related config. In practice, we use the stored
      FortiGate config by importing the parser and re-extracting from whatever
      config text was most recently stored — but the config text itself is not
      stored in the DB. Instead we check for existing config_ntp_fortiguard
      or config_ntp_external findings (from forti_config_parser._config_findings)
      to determine the FortiGate's NTP state:
        - open finding "config_ntp_fortiguard" → FortiGate uses FortiGuard NTP
          (internet) → this check escalates it as a 9.3 violation.
        - open finding "config_ntp_external" → custom server but non-RFC1918 IP
          → escalate as 9.3 violation.
        - no such open findings → FortiGate NTP state is either clean or not yet
          reviewed (no config uploaded yet); skip the config-based sub-check.

    SOURCE 2 — pcap / NetworkSession (authoritative for OT endpoint behaviour):
      Query NetworkSession rows for UDP/123 (NTP) traffic where the src host
      is a known OT device (purdue_level ≤ 2).
        - src OT → dst public IP: OT device is syncing directly to internet NTP
          (ISA 62443 violation). Severity: medium.
        - src OT → dst RFC1918 IP: OT device is syncing to an internal NTP
          server. This is correct behaviour; no finding.
        - OT device with no NTP sessions at all: we can't confirm it is syncing
          at all. Severity: info ("unverifiable — no NTP traffic observed").

    All findings are deduplicated via _make_finding's content-hash mechanism.
    """
    results = []

    # ── Source 1: FortiGate config-level NTP findings ────────────────────────
    # The config_ntp_fortiguard finding (check_name="config_ntp_fortiguard",
    # checklist_id="6.4") is raised by forti_config_parser when
    # ntp_type == "fortiguard". For 9.3 we want to know if the FortiGate
    # itself (the zone border device) is using an internal NTP server, because
    # if the FortiGate is syncing from FortiGuard it needs internet egress that
    # OT-isolated networks should not have.
    config_ntp_open = db.query(Finding).filter(
        Finding.check_name == "config_ntp_fortiguard",
        Finding.status == "open",
    ).first()
    if config_ntp_open:
        evidence = {
            "source": "fortigate_config",
            "reason": "FortiGate NTP type is 'fortiguard' (internet cloud NTP)",
            "config_finding_id": config_ntp_open.id,
            "detail": "FortiGate syncing NTP from FortiGuard requires internet egress. "
                      "For OT-isolated networks, the firewall should sync from an "
                      "internal stratum-2 or GPS-disciplined NTP server.",
        }
        result = _make_finding(
            db,
            check_name="ntp_sync",
            title="FortiGate syncing NTP from FortiGuard (internet) — internal NTP server required",
            detail_text=(
                "Checklist 9.3: FortiGate config shows NTP type=fortiguard. "
                "The firewall should sync from a dedicated internal NTP server "
                "(RFC1918 address), not FortiGuard cloud. Configure a stratum-2 "
                "or GPS-disciplined NTP server on the OT network and update "
                "'config system ntp' to type=custom with that server's IP."
            ),
            evidence=evidence,
        )
        if result:
            results.append(result)

    # ── Source 2: pcap / NetworkSession — OT devices using NTP ───────────────
    # Collect all OT hosts (purdue_level ≤ 2) observed in the session data.
    # B-06: every OT host is evaluated, in keyset-paginated batches (the old
    # 5 000-host cap silently skipped the rest).
    # If there are no NTP sessions at all in the DB, it almost certainly
    # means no relevant traffic has been captured yet (or NTP traffic is
    # not in the capture window), not that every OT device is broken.
    # Emitting one "no NTP observed" finding per OT host floods the finding
    # list on a freshly-provisioned system.  Suppress the "unverifiable"
    # findings until at least one NTP session exists anywhere in the DB so
    # only genuinely missing-per-host cases are flagged.
    any_ntp_in_db = db.query(NetworkSession.id).filter(
        NetworkSession.dst_port == 123,
        NetworkSession.transport == "udp",
    ).first() is not None
    from collections import defaultdict
    # FO-11: NTP polls can be 17+ minutes apart - on a capture shorter than
    # IACS_NTP_MIN_CAPTURE_SECONDS (1 h) a device without NTP is not
    # evidence; those devices are rolled up in one informational finding
    span = None
    if any_ntp_in_db:
        from sqlalchemy import func as _f
        from app.parsers.common import as_utc
        sh = aliased(Host)
        lo, hi = (db.query(_f.min(NetworkSession.first_seen), _f.max(NetworkSession.last_seen))
                  .join(sh, NetworkSession.src_host_id == sh.id).one())
        if lo is not None and hi is not None:
            span = (as_utc(hi) - as_utc(lo)).total_seconds()
    short_capture = span is not None and span < _NTP_MIN_CAPTURE_SECONDS
    silent: list = []
    if not any_ntp_in_db:
        # IO-09: no NTP from ANY device during a long enough capture - the
        # network has no time source at all
        from sqlalchemy import func as _f2
        from app.parsers.common import as_utc as _au
        sh2 = aliased(Host)
        lo, hi = (db.query(_f2.min(NetworkSession.first_seen), _f2.max(NetworkSession.last_seen))
                  .join(sh2, NetworkSession.src_host_id == sh2.id).one())
        span2 = (_au(hi) - _au(lo)).total_seconds() if lo is not None and hi is not None else 0
        ptp = db.query(NetworkSession.id).filter(NetworkSession.dst_port.in_([319, 320])).first()
        ot = [ip for (ip,) in db.query(Host.ip).filter(Host.ip.isnot(None), Host.purdue_level <= 2).limit(50)]
        ics = ot or db.query(NetworkSession.id).filter(
            NetworkSession.dst_port.in_(list(_ICS_CLIENT_PORTS))).first() is not None
        if lo is not None and span2 > 0 and span2 >= _NTP_MIN_CAPTURE_SECONDS and ptp is None and ics:
            mins = int(round(span2 / 60.0))
            results.append(_make_finding(
                db, "ntp_sync",
                f"No time synchronisation observed in {mins} minutes of traffic (no NTP / PTP from any device)",
                f"Checklist 9.3: the captured traffic spans {mins} minutes and not one device sent NTP "
                f"(UDP/123) or PTP. NTP clients poll every 64 s to 17 min, so the network most likely has no "
                f"time source: controllers, HMIs and the historian drift apart, and their event timestamps "
                f"cannot be correlated in an investigation (SR 2.11). Provide an internal time source "
                f"(NTP server or GPS clock) and point every device at it."
                + (f" OT devices seen: {', '.join(ot[:10])}." if ot else ""),
                {"source": "pcap_network_session", "capture_seconds": int(span2), "ot_devices": ot[:50],
                 "threshold_seconds": _NTP_MIN_CAPTURE_SECONDS,
                 "severity_reason": "Medium: no time source in the network."},
                dedup_evidence={"rule_key": "ntp_none"},
            ))
    host_pages = _keyset(db.query(Host).filter(
        Host.purdue_level <= 2,
        Host.ip.isnot(None),
    ), Host.id) if any_ntp_in_db else iter(())
    while True:
        ot_hosts = []
        for h in host_pages:
            ot_hosts.append(h)
            if len(ot_hosts) >= 500:
                break
        if not ot_hosts:
            break
        ot_host_ids = [h.id for h in ot_hosts]

        # All NTP sessions where an OT device of this batch is the source
        ntp_sessions = (
            db.query(NetworkSession)
            .filter(
                NetworkSession.src_host_id.in_(ot_host_ids),
                NetworkSession.dst_port == 123,
                NetworkSession.transport == "udp",
            )
            .all()
        )

        # Bulk-load all destination hosts in one query (avoids N+1).
        dst_host_ids = {sess.dst_host_id for sess in ntp_sessions if sess.dst_host_id}
        dst_host_map: dict = {}
        if dst_host_ids:
            dst_host_map = {
                h.id: h
                for h in db.query(Host).filter(Host.id.in_(dst_host_ids)).all()
            }

        ot_ntp_dst: dict = defaultdict(list)
        for sess in ntp_sessions:
            dst_host = dst_host_map.get(sess.dst_host_id)
            if dst_host:
                ot_ntp_dst[sess.src_host_id].append(dst_host)

        for ot_host in ot_hosts:
            dst_hosts_seen = ot_ntp_dst.get(ot_host.id, [])

            if not dst_hosts_seen:
                # No NTP traffic observed for this specific OT device.
                # Only emit a finding when NTP traffic exists elsewhere in the
                # DB (proving the capture window includes NTP traffic for other
                # devices).  When no NTP sessions exist at all, the absence is
                # uninformative — the capture simply didn't include NTP — so
                # emitting one finding per OT host would flood the finding list
                # on a freshly-loaded system.
                if not any_ntp_in_db:
                    continue
                if short_capture:
                    silent.append(ot_host.ip)
                    continue
                evidence = {
                    "source": "pcap_network_session",
                    "ip": ot_host.ip,          # A-1: key must be "ip" for _dedup_key()
                    "ot_host_id": ot_host.id,
                    "purdue_level": ot_host.purdue_level,
                    "reason": "no NTP traffic (UDP/123) observed from this OT device — "
                              "cannot confirm it is syncing time at all",
                }
                result = _make_finding(
                    db,
                    check_name="ntp_sync",
                    title=f"OT device {ot_host.ip} — no NTP traffic observed (time sync unverifiable)",
                    detail_text=(
                        f"Checklist 9.3: No UDP/123 NTP sessions were observed from OT host "
                        f"{ot_host.ip} (Purdue level {ot_host.purdue_level}) in the captured "
                        f"traffic. This may mean NTP traffic is not in the capture window, "
                        f"or the device is not syncing time at all. Confirm that a dedicated "
                        f"internal NTP server is reachable from this device."
                    ),
                    evidence=evidence,
                )
                if result:
                    results.append(result)
            else:
                # Check each destination: flag any public (non-RFC1918) NTP server
                for dst_host in dst_hosts_seen:
                    if _is_public_ip(dst_host.ip):
                        evidence = {
                            "source": "pcap_network_session",
                            "ot_host_ip": ot_host.ip,
                            "ot_host_id": ot_host.id,
                            "purdue_level": ot_host.purdue_level,
                            "ntp_server_ip": dst_host.ip,
                            "reason": "OT device sending NTP (UDP/123) to a public (globally routable) IP",
                        }
                        result = _make_finding(
                            db,
                            check_name="ntp_sync",
                            title=(
                                f"OT device {ot_host.ip} syncing NTP directly to "
                                f"public IP {dst_host.ip}"
                            ),
                            detail_text=(
                                f"Checklist 9.3: OT host {ot_host.ip} (Purdue level "
                                f"{ot_host.purdue_level}) was observed sending NTP "
                                f"requests (UDP/123) to {dst_host.ip}, a public "
                                f"(non-RFC1918) address. OT devices must sync time from "
                                f"a dedicated internal NTP server. Reconfigure this device "
                                f"to use the site's internal NTP server."
                            ),
                            evidence=evidence,
                            # F-01: ot_host_ip / ntp_server_ip are not _dedup_key
                            # fields, so every public-NTP finding (and the
                            # FortiGate-config one) collapsed onto one all-None key.
                            dedup_evidence={"src_ip": ot_host.ip, "dst_ip": dst_host.ip,
                                            "dst_port": 123},
                        )
                        if result:
                            results.append(result)
                        # (RFC1918 NTP server = passing — no finding generated)

    if silent:
        mins = int(round(span / 60.0))
        results.append(_make_finding(
            db, "ntp_sync",
            f"Capture too short to judge time sync for {len(silent)} OT device(s) "
            f"({mins} min of traffic, no NTP seen from them)",
            f"Checklist 9.3: {len(silent)} OT device(s) sent no NTP (UDP/123) in the captured traffic "
            f"({', '.join(silent[:15])}{' ...' if len(silent) > 15 else ''}), but the capture spans only "
            f"{mins} minutes and NTP clients can poll 17 minutes or more apart, so the absence is no "
            f"evidence either way. Capture at least an hour, or check each device's time settings.",
            {"source": "pcap_network_session", "devices": silent[:100], "device_count": len(silent),
             "capture_seconds": int(span), "threshold_seconds": _NTP_MIN_CAPTURE_SECONDS},
            severity="info",
            dedup_evidence={"rule_key": "ntp_short_capture"},
        ))
    return [r for r in results if r]


# ---------------------------------------------------------------------------
# Phase 5: NetworkSession-based (pcap) counterparts of real-time FAZ checks
#
# These functions evaluate observed NetworkSession rows (5-tuple pcap data)
# and run as periodic reviews, producing category="periodic_review" findings
# via the session_* check_names registered in CHECK_TYPE_REFERENCE.
#
# B-04: they used to skip ENTIRELY whenever any FortiAnalyzerEvent of any
# type / device / site had arrived in the last 24 h - one unrelated event log
# silenced IT/OT bypass detection, and a bypass that never crosses the
# firewall (same-switch, rogue route) never reaches FAZ at all. They now
# ALWAYS run. Duplicates with the real-time FAZ finding are avoided per flow,
# never per review: a session finding is suppressed only when the SAME
# violation is already reported, i.e. BOTH
#   (a) an active (open/acknowledged) real-time counterpart finding exists in
#       the analysed site for the same flow (src_ip, dst_ip, dst_port), AND
#   (b) a permitted FAZ *traffic* event for that flow (same src/dst ip, dst
#       port, compatible transport) was received within the window.
# Requiring (a) guarantees no false negative: a FAZ event alone (denied, or
# one the real-time check did not flag, e.g. different classification at
# ingest time) never hides a pcap-observed violation. (b) keeps a stale
# real-time finding from masking fresh pcap evidence indefinitely.
# Site isolation comes from the analysis scope (site_scope) on every query.
# ---------------------------------------------------------------------------

_FAZ_RECENT_WINDOW_HOURS = 24   # FAZ traffic event recency for (b) above

# Management ports watched by session_mgmt_from_non_admin (check 5.5, 9.5)
_MGMT_PORTS = {22, 23, 3389, 5900, 5901, 5985, 5986, 8443}   # SF-3: + VNC

# Remote-access / RDP/SSH ports watched by session_remote_access_bypass (4.1)
_REMOTE_ACCESS_PORTS = {22, 23, 3389, 443, 500, 4500, 8443}

# Percentile threshold for scanning anomaly: flag sources whose distinct-dst-port
# count exceeds this multiple of the per-source average across the whole table.
_SCAN_VOLUME_MULTIPLIER = 5
#: FO-04: addresses a source must probe (mostly without a conversation) to be a sweep
from app.parsers.common import env_int as _env_int  # noqa: E402
_SCAN_SWEEP_HOSTS = _env_int("IACS_SCAN_SWEEP_HOSTS", 20)
#: FO-11: a capture shorter than this cannot show that a device does not sync time
_NTP_MIN_CAPTURE_SECONDS = _env_int("IACS_NTP_MIN_CAPTURE_SECONDS", 3600)

_SESSION_NOTE = ("observed in captured traffic (pcap) - whether the firewall "
                 "denied it is not visible from the session alone")


class _FazCoverage:
    """B-04: per-flow test 'is this session's violation already reported by
    the real-time FAZ counterpart?' (see the section comment above)."""

    def __init__(self, db: DBSession, rt_check: str, session_check: Optional[str] = None):
        self.db = db
        # B-24: the session check_name whose finding for a covered flow stays
        # open (the condition persists - it is just reported by FAZ now), so
        # auto-resolve does not close it.
        self.session_check = session_check
        self.cutoff = datetime.now(timezone.utc) - timedelta(hours=_FAZ_RECENT_WINDOW_HOURS)
        self.flows: set = set()
        for (detail,) in db.query(Finding.detail).filter(
                Finding.check_name == rt_check,
                Finding.category == "real_time",
                Finding.status.in_(_ACTIVE_STATUSES)):
            d = detail if isinstance(detail, dict) else {}
            if d.get("src_ip") and d.get("dst_ip"):
                # C-01: store the flow under its canonical (client, server,
                # server_port) identity so a pcap session captured in the
                # opposite orientation (or on a different ephemeral port) still
                # matches the real-time FAZ finding for the same logical flow.
                c_ip, s_ip, s_port = canonical_flow(
                    d["src_ip"], d.get("src_port"), d["dst_ip"], d.get("dst_port"))
                self.flows.add((c_ip, s_ip, s_port))
        self._cache: dict = {}
        self.suppressed = 0

    def covers(self, src_ip, src_port, dst_ip, dst_port, transport) -> bool:
        # C-01: compare on the canonical flow identity, not the raw capture
        # orientation, so one logical flow is one identity on both sides.
        c_ip, s_ip, s_port = canonical_flow(src_ip, src_port, dst_ip, dst_port)
        if (c_ip, s_ip, s_port) not in self.flows:
            return False
        key = (c_ip, s_ip, s_port, (transport or "").lower())
        hit = self._cache.get(key)
        if hit is None:
            q = self.db.query(FortiAnalyzerEvent.action, FortiAnalyzerEvent.protocol).filter(
                FortiAnalyzerEvent.log_type == "traffic",
                FortiAnalyzerEvent.src_ip == c_ip,
                FortiAnalyzerEvent.dst_ip == s_ip,
                # C-15: window on when the traffic HAPPENED (event_time),
                # falling back to received_at only when the log carried no
                # parseable timestamp. Keying on received_at let a bulk upload
                # of days-old FAZ events suppress a current pcap bypass finding.
                func.coalesce(FortiAnalyzerEvent.event_time,
                              FortiAnalyzerEvent.received_at) >= self.cutoff,
            )
            q = q.filter(FortiAnalyzerEvent.dst_port.is_(None) if s_port is None
                         else FortiAnalyzerEvent.dst_port == s_port)
            tr = key[3]
            hit = any(
                _is_permitted(action)
                and (not tr or not proto or str(proto).lower() == tr)
                for action, proto in q.limit(200)
            )
            self._cache[key] = hit
        if hit:
            self.suppressed += 1
            if self.session_check:
                # C-01: keep the SAME canonical identity the session finding is
                # keyed on, so auto-resolve recognises it as re-produced.
                _keep_seen(self.db, self.session_check,
                           {"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port})
        return hit


def _keep_seen(db: DBSession, check_name: str, evidence: dict) -> None:
    """B-24: count the finding `check_name` / `evidence` (its _dedup_key) as
    re-produced this run without creating or touching it - the review saw
    the condition but deliberately did not report it (e.g. a FAZ-covered
    flow), so auto-resolve must keep it."""
    seen = db.info.get(_SEEN_KEY)
    if seen is not None:
        seen.add(_dedup_key(check_name, evidence))


def _require_sessions(db: DBSession) -> bool:
    """B-24: True when the (site-scoped) NetworkSession table has rows;
    otherwise the running session review is marked incomplete (an empty
    table means no capture data, not that every condition was fixed)."""
    if db.query(NetworkSession.id).first() is None:
        _mark_incomplete(db, "no observed sessions")
        return False
    return True


def _count_unknown_level(db: DBSession, *ips) -> None:
    """B-20: a review skipped a session/host because a Purdue level is
    unknown. Counted per review (last_review_info "skipped_unknown_level");
    the IPs are remembered so auto-resolve keeps findings that concern them
    (their condition could not be re-evaluated) without disabling it for the
    whole check."""
    if db.info.get(_SEEN_KEY) is None:
        return
    db.info[_SKIPPED_UNKNOWN_KEY] = int(db.info.get(_SKIPPED_UNKNOWN_KEY, 0)) + 1
    hosts = db.info.setdefault(_UNKNOWN_HOSTS_KEY, set())
    hosts.update(ip for ip in ips if ip)


def _keyset(query, id_col, key=None, batch: Optional[int] = None):
    """B-06: iterate ``query`` completely in keyset-paginated pages ordered by
    ``id_col`` (``id_col > last``), so every row is evaluated with memory
    bounded by one page. ``key(row)`` extracts the id (default ``row.id``)."""
    size = max(1, int(batch or _PAGE_SIZE))
    key = key or (lambda r: r.id)
    last = None
    while True:
        q = query if last is None else query.filter(id_col > last)
        rows = q.order_by(id_col).limit(size).all()
        if not rows:
            return
        yield from rows
        if len(rows) < size:
            return
        last = key(rows[-1])


_LEVEL_NAMES = {0: "process", 1: "basic control", 2: "supervisory control", 3: "site operations",
                3.5: "industrial DMZ", 4: "enterprise", 5: "internet"}


def _bypass_wording(it_lvl, ot_lvl, ot_initiated: bool = False) -> dict:
    """RS-08: title / text pieces for a level-skipping exchange.  "IT" is
    used only for enterprise / internet (L4 and up); site operations (L3)
    and the DMZ (L3.5) are named as what they are.  SF-2: when the OT side
    opened the session (``ot_initiated``) the exchange is worded as the OT
    host reaching up (an HMI using the enterprise AD), not as IT reaching
    down."""
    hi, lo = float(it_lvl), float(ot_lvl)
    skipped = [l for l in (3.5, 3, 2) if lo < l < hi and not (l == 3.5 and hi < 4)]
    skips = ("skips " + " and ".join(fmt_level(l) for l in skipped)) if skipped else "skips a level"
    hi_name = _LEVEL_NAMES.get(hi if hi != int(hi) else int(hi), fmt_level(it_lvl))
    lo_name = _LEVEL_NAMES.get(int(lo), fmt_level(ot_lvl))
    if hi >= 4:
        hi_kind = "IT host" if hi == 4 else "internet host"
        title = "Direct IT-to-OT session"
    elif hi == 3.5:
        hi_kind = "industrial-DMZ host"
        title = "DMZ host straight to controllers" if lo <= 1 else "DMZ host straight to the control zone"
    else:
        hi_kind = f"{hi_name} host"
        title = "Level-skipping session"
    if ot_initiated:
        if hi >= 4:
            title = "OT host straight to IT" if lo <= 1 else "Control-zone host straight to IT"
        elif hi == 3.5:
            title = "Controller straight to the DMZ" if lo <= 1 else "Control-zone host straight to the DMZ"
        else:
            title = "Level-skipping session (OT host reaching up)"
        return {"title": title, "skips": f"{skips} ({lo_name} straight up to {hi_name})",
                "src_name": f"{lo_name} device", "dst_name": hi_kind,
                "why": f"{lo_name} ({fmt_level(ot_lvl)}) equipment opened a session directly to a "
                       f"{hi_name} ({fmt_level(it_lvl)}) host."}
    return {"title": title, "skips": f"{skips} ({hi_name} straight to {lo_name})",
            "src_name": hi_kind, "dst_name": f"{lo_name} device",
            "why": f"a {hi_name} ({fmt_level(it_lvl)}) host exchanged traffic directly with "
                   f"{lo_name} ({fmt_level(ot_lvl)}) equipment."}


def _engineering_session(a, b):
    """RS-08: (engineering workstation, target) when one side is a host the
    operator classified as an engineering workstation at L3 or below and the
    other side is L0-L2 equipment; else None."""
    for e, t in ((a, b), (b, a)):
        if (e.device_type == "engineering_workstation" and e.purdue_level is not None
                and float(e.purdue_level) <= 3 and t.purdue_level is not None
                and float(t.purdue_level) <= 2):
            return e, t
    return None


def _engineering_access_finding(db, ns, e_host, t_host):
    """RS-08: engineering access (row 8.4) from a classified engineering
    workstation that is not yet an approved engineering source."""
    name = e_host.hostname or e_host.ip
    port = ns.dst_port if ns.dst_host_id == t_host.id else ns.src_port
    return _make_finding(
        db,
        check_name="engineering_access_unapproved",
        title=(f"Engineering access to approve: engineering workstation {name} ({fmt_level(e_host.purdue_level)}) "
               f"→ {t_host.ip} ({fmt_level(t_host.purdue_level)}) port {port}"),
        detail_text=(
            f"Checklist 8.4 [observed sessions]: {e_host.ip} is classified as an engineering workstation "
            f"and worked on {t_host.ip} ({t_host.device_type or 'OT device'}, {fmt_level(t_host.purdue_level)}). "
            "Engineering access to controllers is expected from an approved engineering workstation, so this is "
            "not reported as a level-skipping bypass - but this workstation is not an approved engineering "
            "source yet. Approve it (Mgmt & Engineering: trusted host with purpose engineering, or the "
            "baseline's engineering_ws role) if it is the sanctioned engineering station; otherwise "
            "re-classify it. Program downloads and writes from it are reported separately."),
        evidence={"source": "network_session", "engineering_ws": e_host.ip, "target_ip": t_host.ip,
                  "target_purdue": t_host.purdue_level, "dst_port": port, "transport": ns.transport,
                  "severity_reason": "Medium: engineering access from a classified engineering workstation "
                                     "that has not been approved as an engineering source."},
        session_id=ns.id,
        dedup_evidence={"engineering_ws": e_host.ip, "target_ip": t_host.ip},
    )



def review_ns_it_ot_bypass(db: DBSession) -> list:
    """
    Session-based (pcap) counterpart of real-time "it_ot_bypass" (checks 2.1, 2.2).

    Flags NetworkSession rows where one endpoint is at Purdue Level >= 3 (IT)
    and the other is at Purdue Level <= 1 (field devices / basic control),
    indicating a direct IT-to-deep-OT session that bypasses the expected
    DMZ/conduit boundary - and (A-11) L4-L5 <-> L2 sessions, which skip L3
    and the DMZ (severity "high"; see _bypass_kind).

    Uses check_name "session_it_ot_bypass" (periodic_review, critical) so
    findings are separate from FAZ real-time "it_ot_bypass" findings.

    B-04: always runs; a session is skipped only when the same flow is
    already reported by an active real-time it_ot_bypass finding backed by a
    recent permitted FAZ traffic event (_FazCoverage). Sessions with an
    endpoint of unknown Purdue level are counted (B-20, _count_unknown_level).
    """
    results: list[Optional[Finding]] = []
    if not _require_sessions(db):
        return []
    cover = _FazCoverage(db, "it_ot_bypass", "session_it_ot_bypass")
    # FO-02: flows between two members of one capture segment (no router
    # between them) are rolled up in that segment's flat_control_segment
    from app.parsers.segments import same_capture_segment
    on_one_segment = same_capture_segment(db)
    from app.parsers.chain_findings import bypass_severity, _STEP_UP
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)
    src_h, dst_h = aliased(Host), aliased(Host)
    q = (
        db.query(NetworkSession, src_h, dst_h)
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
    )
    for ns, src_host, dst_host in _keyset(q, NetworkSession.id, key=lambda r: r[0].id):
        src_lvl = src_host.purdue_level
        dst_lvl = dst_host.purdue_level
        if src_lvl is None or dst_lvl is None:
            # B-20 / SF-10: only the host whose level is unknown is held from
            # auto-resolve - a finding between two known hosts is re-judged
            _count_unknown_level(db, *(h.ip for h, l in ((src_host, src_lvl), (dst_host, dst_lvl)) if l is None))
            continue
        # RS-08: an engineering workstation (classified as one, at site
        # operations or below) working on L0-L2 equipment is engineering
        # access - approved when it is a declared / baseline engineering
        # source, otherwise reported as access to approve, never as a bypass.
        ews = _engineering_session(src_host, dst_host) if _bypass_kind(src_lvl, dst_lvl) else None
        if ews is not None:
            e_host, t_host = ews
            if not mctx.is_engineering_ip(e_host.ip):
                r = _engineering_access_finding(db, ns, e_host, t_host)
                if r:
                    results.append(r)
            continue

        # Flag when one side is IT (>= 3) and the other is deep OT (<= 1),
        # both directions; A-11: also enterprise (L4-L5) <-> L2.
        kind = _bypass_kind(src_lvl, dst_lvl)
        if kind is None:
            continue
        if mctx.is_ntp_flow(src_host.ip, ns.src_port, dst_host.ip, ns.dst_port):
            continue   # owner: time sync with the declared site NTP server is allowed
        if cover.covers(src_host.ip, ns.src_port, dst_host.ip, ns.dst_port, ns.transport):
            continue   # same violation already reported by the FAZ finding
        if on_one_segment(src_host, dst_host):
            continue   # FO-02: reported under the segment's flat_control_segment
        # C-01: canonical (client, server, server_port) identity so the three
        # mid-stream captures of one logical flow (differing ephemeral ports /
        # orientation) dedup to a single finding and share the FAZ identity.
        c_ip, s_ip, s_port = canonical_flow(
            src_host.ip, ns.src_port, dst_host.ip, ns.dst_port)
        # SF-2: the initiator is the session's client (canonical flow), not
        # the higher-level side - an HMI opening LDAP to the enterprise AD is
        # the OT host reaching up, and is worded that way
        it_to_deep_ot = src_lvl > dst_lvl  # IT side is the source

        it_ip  = src_host.ip if it_to_deep_ot else dst_host.ip
        ot_ip  = dst_host.ip if it_to_deep_ot else src_host.ip
        it_lvl = src_lvl     if it_to_deep_ot else dst_lvl
        ot_lvl = dst_lvl     if it_to_deep_ot else src_lvl
        ot_initiated = c_ip == ot_ip

        from app.parsers.traffic_findings import _nat_evidence
        # RS-08: worded by level - "IT" only for L4 and up; severity from the
        # owner's (source band, destination band) table (MP-11), one step up
        # because the traffic was seen.
        sev, band, why_src = bypass_severity(it_lvl, ot_lvl)
        sev = _STEP_UP[sev]
        what = _bypass_wording(it_lvl, ot_lvl, ot_initiated=ot_initiated)
        evidence = {
            "source":        "network_session",
            "src_ip":        src_host.ip,
            "dst_ip":        dst_host.ip,
            "dst_port":      ns.dst_port,
            "transport":     ns.transport,
            **_nat_evidence(ns),
            "it_host_ip":    it_ip,
            "it_purdue":     it_lvl,
            "ot_host_ip":    ot_ip,
            "ot_purdue":     ot_lvl,
            "initiator":     c_ip,
            "direction":     "ot_to_it" if ot_initiated else "it_to_ot",
            "source_band":   band,
            "note":          _SESSION_NOTE,
            "severity_reason": (f"{sev.capitalize()}: {what['why']} {why_src} "
                                "Seen in the capture, so one step above the permitted-path severity."),
        }
        result = _make_finding(
            db,
            check_name="session_it_ot_bypass",
            title=(
                f"{what['title']} (observed traffic): {c_ip} ({fmt_level(src_lvl if c_ip == src_host.ip else dst_lvl)}) → "
                f"{s_ip} ({fmt_level(dst_lvl if s_ip == dst_host.ip else src_lvl)}) port {s_port} - {what['skips']}"
            ),
            detail_text=(
                f"Checklist 2.1/2.2 [observed sessions]: A network session was observed "
                f"directly connecting {what['src_name']} {c_ip} "
                f"to {what['dst_name']} {s_ip} on "
                f"{'TCP' if ns.transport == 'tcp' else ns.transport or 'unknown'}/{ns.dst_port}; "
                f"it {what['skips']}. Traffic between these levels should pass through the "
                f"intermediate zone's conduit (ISA/IEC 62443 SR 5.1 RE2, SR 5.2). "
                f"Verify this session is expected and that the traffic path passes "
                f"through the conduit firewall. Note: this is based on captured "
                f"traffic; a path that never crosses the firewall is invisible to "
                f"FortiAnalyzer, and deny-side enforcement cannot be confirmed here."
            ),
            evidence=evidence,
            session_id=ns.id,
            severity=sev,
            dedup_evidence={"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port},
        )
        if result:
            results.append(result)

    return [r for r in results if r]


def _review_suffix(rv) -> str:
    """Title suffix for an OT egress flow the operator reviewed on the
    External comms page (owner: an approval never closes it)."""
    if rv is None:
        return ""
    if rv.status == "remove":
        return " - marked for removal"
    return " - approved on External comms, still not allowed: OT must not reach the Internet directly"


def review_ns_ot_internet_egress(db: DBSession) -> list:
    """
    Session-based (pcap) counterpart of real-time "ot_internet_egress"
    (checks 3.7, 9.11, 9.12).

    Flags NetworkSession rows where a host in an OT zone (Purdue <= 3 - H-13: site operations is OT too) is the
    source and the destination IP is public (globally routable, B-20 - IPv4
    or IPv6; private / CGNAT / link-local / ULA destinations are internal).

    Severity is tiered by Purdue level of the OT source:
      - Purdue 0/1 (field devices, PLCs): critical
      - Purdue 2 (HMI / supervisory): high (default from CHECK_TYPE_REFERENCE)

    B-04: always runs (see _FazCoverage for per-flow dedup with the FAZ
    finding). Sessions to public destinations from a source of unknown
    Purdue level are counted (B-20).
    """
    results: list[Optional[Finding]] = []
    if not _require_sessions(db):
        return []
    cover = _FazCoverage(db, "ot_internet_egress", "session_ot_internet_egress")
    src_h, dst_h = aliased(Host), aliased(Host)
    q = (
        db.query(NetworkSession, src_h, dst_h)
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
        .filter(or_(src_h.purdue_level.is_(None), src_h.purdue_level <= 3))
    )
    from app.parsers.segments import ot_capture_segment_of
    from app.parsers import external_comms as _ec
    ot_segment = ot_capture_segment_of(db)
    dest_of = _ec.dest_key_fn(db)          # G5: name the destination
    revs = _ec.reviews(db)
    for ns, src_host, dst_host in _keyset(q, NetworkSession.id, key=lambda r: r[0].id):
        if not _is_public_ip(dst_host.ip):
            continue   # internal destination — not internet egress
        dkey, dname = dest_of(dst_host.ip)
        rv = _ec.review_for(revs, src_host.ip, dkey, dst_host.ip)
        # Owner (G4): no OT device may have direct Internet access - an
        # approval on the External comms page is recorded, never a pass.
        seg = None
        if src_host.purdue_level is None:
            # FO-05: an unclassified host on a capture segment holding L0-L2
            # devices is OT-adjacent (fail visible)
            seg = ot_segment(src_host)
            if seg is None:
                _count_unknown_level(db, src_host.ip)
                continue
        if cover.covers(src_host.ip, ns.src_port, dst_host.ip, ns.dst_port, ns.transport):
            continue
        c_ip, s_ip, s_port = canonical_flow(          # C-01: shared flow identity
            src_host.ip, ns.src_port, dst_host.ip, ns.dst_port)

        if seg is not None:
            # RS-12: a segment routed to the OT segment without a firewall is
            # one step removed - medium; on the OT segment itself - high
            via = "(routed to" in seg
            severity = "medium" if via else "high"
            lvl_txt = f"unclassified, on {'segment' if via else 'OT segment'} {seg}"
            lvl_long = (f"unclassified - on the capture segment {seg}, which no firewall separates from "
                        f"the L0-L2 devices" if via else
                        f"unclassified - on the capture segment {seg} with L0-L2 devices")
        else:
            # H-13: L3 (site operations) is OT for internet egress - medium;
            # RS-08: an engineering workstation programs the controllers, so
            # its Internet access is high whatever its level
            ews = src_host.device_type == "engineering_workstation"
            severity = ("critical" if src_host.purdue_level <= 1 else
                        "high" if src_host.purdue_level <= 2 or ews else "medium")
            lvl_txt = fmt_level(src_host.purdue_level) + (", engineering workstation" if ews else "")
            lvl_long = (f"Purdue Level {src_host.purdue_level}"
                        + (", an engineering workstation that programs the controllers" if ews else ""))

        evidence = {
            "source":        "network_session",
            "src_ip":        src_host.ip,
            "dst_ip":        dst_host.ip,
            "dst_port":      ns.dst_port,
            "transport":     ns.transport,
            "purdue_level":  src_host.purdue_level,
            "ot_capture_segment": seg,
            "note":          _SESSION_NOTE,
            "destination":   dkey if dname else None,
            "destination_name": dname,
            "review":        rv.status if rv is not None else None,
            "review_note":   rv.note if rv is not None else None,
        }
        if src_host.purdue_level is not None and src_host.device_type == "engineering_workstation":
            evidence["severity_reason"] = ("High: an engineering workstation reaches the Internet directly; "
                                           "it programs the controllers, so a compromise carries straight "
                                           "into L0-L1.")
        dest_txt = f"{dkey} ({dst_host.ip}:{ns.dst_port})" if dname else f"public IP {dst_host.ip}:{ns.dst_port}"
        result = _make_finding(
            db,
            check_name="session_ot_internet_egress",
            title=(
                f"OT host {src_host.ip} ({lvl_txt}) session to "
                f"{dest_txt} (observed traffic)" + _review_suffix(rv)
            ),
            detail_text=(
                f"Checklist 3.7 [observed sessions]: OT host {src_host.ip} "
                f"({lvl_long}) was observed initiating a "
                f"session to public (globally routable) IP {dst_host.ip} on port "
                f"{ns.dst_port}. OT zones (site operations, L3, included) must not have "
                f"direct internet access; "
                f"all external connectivity must route through an approved DMZ "
                f"proxy or historian (SR 5.1 RE2). "
                f"Note: based on captured traffic — whether it was blocked is unknown."
            ),
            evidence=evidence,
            severity=severity,
            session_id=ns.id,
            # G5: one finding per inside host and destination name (not per address)
            dedup_evidence=({"src_ip": src_host.ip, "dest": dkey, "dst_port": ns.dst_port} if dname else
                            {"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port}),
        )
        if result:
            results.append(result)

    # IO-07: attempts to public addresses that got no answer (unanswered UDP,
    # refused / unanswered TCP) - the host tried; nothing proves it got out
    from app.models import ConnectionAttempt
    att: dict = {}
    for a in db.query(ConnectionAttempt).filter(ConnectionAttempt.outcome != "arp_unanswered"):
        if _is_public_ip(a.dst_ip):
            k = (a.src_ip, a.dst_ip, a.dst_port, a.transport)
            att[k] = att.get(k, 0) + (a.count or 1)
    if att:
        hosts = {h.ip: h for h in db.query(Host).filter(Host.ip.in_(list({k[0] for k in att})))}
        for (sip, dip, dport, tr), cnt in sorted(att.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
            h = hosts.get(sip)
            if h is None:
                continue
            dkey, dname = dest_of(dip)
            rv = _ec.review_for(revs, sip, dkey, dip)
            seg = None
            if h.purdue_level is None:
                seg = ot_segment(h)
                if seg is None:
                    continue
            elif h.purdue_level > 3:
                continue
            if seg is not None:
                sev, lvl = "medium", f"unclassified, on OT segment {seg}"
            else:
                sev, lvl = ("medium" if h.purdue_level <= 2 else "low"), fmt_level(h.purdue_level)
            results.append(_make_finding(
                db, "session_ot_internet_egress",
                f"OT host {sip} ({lvl}) tried to reach public IP {dip}:{dport} (no answer seen)" + _review_suffix(rv),
                (f"Checklist 3.7 [connection attempts]: OT host {sip} sent {cnt} {tr} request(s) to public IP "
                 f"{dip} port {dport} and no answer was captured - the attempt most likely failed (no route, "
                 f"blocked or no Internet). The device is configured to use an Internet service (DNS, cloud, "
                 f"update or time server): remove that configuration, or the first time a path to the "
                 f"Internet appears the device will use it (SR 5.1)."),
                {"source": "connection_attempt", "src_ip": sip, "dst_ip": dip, "dst_port": dport,
                 "transport": tr, "requests": cnt, "purdue_level": h.purdue_level, "ot_capture_segment": seg,
                 "attempt": True,
                 "severity_reason": "Attempt only - no reply observed."},
                severity=sev,
                dedup_evidence={"src_ip": sip, "dst_ip": dip, "dst_port": dport, "attempt": True},
            ))

    return [r for r in results if r]


def review_ns_remote_access_bypass(db: DBSession) -> list:
    """
    Phase 5 fallback for real-time "remote_access_bypass" (check 4.1).

    Two paths — both run regardless of FAZ state:

    Path 2: External (public, B-20) source connecting to a host that is NOT
    an approved jump_host on remote-access-capable ports (22/23/3389/443/
    500/4500/8443). This indicates remote access that bypasses the DMZ
    jump-host requirement.

    Path 3: Any external source connecting directly to an OT host (Purdue
    ≤ 2), regardless of port. External direct-to-OT is always a critical
    finding.

    B-04: always runs; per-flow dedup with the real-time
    remote_access_bypass finding via _FazCoverage.
    """
    baseline = _active_baseline(db)
    approved_jump_ips: set[str] = set()
    if baseline:
        jump_hosts = (
            db.query(ApprovedHost)
            .filter(
                ApprovedHost.baseline_id == baseline.id,
                ApprovedHost.role == "jump_host",
                ApprovedHost.ip.isnot(None),
            )
            .all()
        )
        approved_jump_ips = {ra.canon_ip(h.ip) for h in jump_hosts if h.ip}
    # Product-neutral remote access (VPN concentrator, Teleport-style proxy,
    # RDP/SSH gateway): a host labelled jump host (device_type) counts as
    # approved, and a labelled gateway is the sanctioned external entry point.
    approved_jump_ips |= ra.jump_host_ips(db)
    gateway_ips = ra.gateway_ips(db)
    # H-03 / H-04: SSL-VPN - the firewalls that run it are the remote-access
    # gateway (a session TO them is a VPN login, local-in traffic), and the
    # tunnel-pool addresses are remote users inside the network.
    from app.parsers import vpn as _vpn
    vctx = _vpn.VpnContext.build(db)
    gateway_ips |= {ra.canon_ip(ip) for ip in vctx.fw_ips if vctx.is_gateway_ip(ip)}

    results: list[Optional[Finding]] = []

    if not _require_sessions(db):
        return []
    cover = _FazCoverage(db, "remote_access_bypass", "session_remote_access_bypass")
    src_h, dst_h = aliased(Host), aliased(Host)
    q = (
        db.query(NetworkSession, src_h, dst_h)
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
    )
    for ns, src_host, dst_host in _keyset(q, NetworkSession.id, key=lambda r: r[0].id):
        vpn_src = vctx.is_pool_ip(src_host.ip)
        if not _is_public_ip(src_host.ip) and not vpn_src:
            continue   # internal source (B-20: incl. CGNAT/link-local/ULA)
        if vctx.is_firewall_ip(dst_host.ip):
            continue   # H-04: local-in to a firewall (VPN login / the device itself)
        if cover.covers(src_host.ip, ns.src_port, dst_host.ip, ns.dst_port, ns.transport):
            continue
        c_ip, s_ip, s_port = canonical_flow(          # C-01: shared flow identity
            src_host.ip, ns.src_port, dst_host.ip, ns.dst_port)
        dst_c = ra.canon_ip(dst_host.ip)             # labels are canonical (E-01)
        who = (f"SSL-VPN user {src_host.ip} (tunnel pool)" if vpn_src
               else f"External host {src_host.ip}")

        # Path 3: external → OT host (Purdue ≤ 2), any port — always critical
        if dst_host.purdue_level is not None and dst_host.purdue_level <= 2:
            evidence = {
                "source":       "network_session",
                "src_ip":       src_host.ip,
                "dst_ip":       dst_host.ip,
                "dst_port":     ns.dst_port,
                "transport":    ns.transport,
                "ot_purdue":    dst_host.purdue_level,
                "path":         "vpn_to_ot" if vpn_src else "external_to_ot",
                "vpn_user":     vpn_src,
                "note":         _SESSION_NOTE,
            }
            result = _make_finding(
                db,
                check_name="session_remote_access_bypass",
                title=(
                    f"{who} direct session to OT "
                    f"{dst_host.ip} ({fmt_level(dst_host.purdue_level)}):{ns.dst_port}"
                ),
                detail_text=(
                    f"Checklist 4.1 [FAZ fallback — path 3]: {who} "
                    f"was observed connecting directly to OT host "
                    f"{dst_host.ip} (Purdue Level {dst_host.purdue_level}) on port "
                    f"{ns.dst_port}. All external access to OT must route through "
                    f"an approved jump host in the DMZ (SR 1.13). "
                    f"Note: FortiAnalyzer unavailable; whether blocked is unknown."
                ),
                evidence=evidence,
                severity="critical",
                session_id=ns.id,
                dedup_evidence={"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port},
            )
            if result:
                results.append(result)
            continue   # don't also emit path 2 for the same session

        # Path 2: external → non-jump-host on remote-access ports
        # Path 2b: a gateway is declared, but the external source reached a
        # jump host directly instead of through it.
        if (gateway_ips and not vpn_src and ns.dst_port in _REMOTE_ACCESS_PORTS
                and dst_c in approved_jump_ips and dst_c not in gateway_ips):
            result = _make_finding(
                db,
                check_name="session_remote_access_bypass",
                title=(
                    f"External remote access to jump host {dst_host.ip}:{ns.dst_port} "
                    f"from {src_host.ip} bypasses the remote-access gateway"
                ),
                detail_text=(
                    f"Checklist 4.1 [FAZ fallback — path 2b]: External host "
                    f"{src_host.ip} connected straight to jump host {dst_host.ip} on "
                    f"port {ns.dst_port}, but a remote-access gateway "
                    f"({', '.join(sorted(gateway_ips))}) is declared for this site. "
                    f"External sessions must enter through the gateway, which "
                    f"authenticates and records them, and reach the jump host from there "
                    f"(SR 1.13). Note: FortiAnalyzer unavailable; whether blocked is unknown."
                ),
                evidence={
                    "source":       "network_session",
                    "src_ip":       src_host.ip,
                    "dst_ip":       dst_host.ip,
                    "dst_port":     ns.dst_port,
                    "transport":    ns.transport,
                    "path":         "external_to_jump_host_bypassing_gateway",
                    "gateways":     sorted(gateway_ips),
                    "note":         _SESSION_NOTE,
                },
                severity="high",
                session_id=ns.id,
                dedup_evidence={"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port},
            )
            if result:
                results.append(result)
            continue

        # Path 2: external → non-jump-host on remote-access ports (a VPN
        # user: any port - every tunnel session is remote access)
        if ((vpn_src or ns.dst_port in _REMOTE_ACCESS_PORTS) and dst_c not in approved_jump_ips
                and dst_c not in gateway_ips):
            evidence = {
                "source":       "network_session",
                "src_ip":       src_host.ip,
                "dst_ip":       dst_host.ip,
                "dst_port":     ns.dst_port,
                "transport":    ns.transport,
                "path":         "vpn_to_non_jump_host" if vpn_src else "external_to_non_jump_host",
                "vpn_user":     vpn_src,
                "note":         _SESSION_NOTE,
            }
            result = _make_finding(
                db,
                check_name="session_remote_access_bypass",
                title=(
                    f"{'VPN' if vpn_src else 'External'} remote access to non-jump-host "
                    f"{dst_host.ip}:{ns.dst_port} from {src_host.ip}"
                ),
                detail_text=(
                    f"Checklist 4.1 [FAZ fallback — path 2]: {who} "
                    f"connected to {dst_host.ip} on port "
                    f"{ns.dst_port} (a remote-access session), but "
                    f"{dst_host.ip} is not in the approved jump-host list. "
                    f"All remote access must terminate at an approved jump host in "
                    f"the DMZ before reaching internal systems (SR 1.13). "
                    f"Note: FortiAnalyzer unavailable; whether blocked is unknown."
                ),
                evidence=evidence,
                session_id=ns.id,
                dedup_evidence={"src_ip": c_ip, "dst_ip": s_ip, "dst_port": s_port},
            )
            if result:
                results.append(result)

    return [r for r in results if r]


#: FO-06: remote-access tools by the server port they use on the Internet
#: (a session from an inside host to a public address on that port)
REMOTE_ACCESS_TOOL_PORTS: dict[int, str] = {
    5938: "TeamViewer", 7070: "AnyDesk", 6568: "AnyDesk",
    5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC", 5500: "VNC (reverse)",
    6783: "Splashtop", 6784: "Splashtop", 6785: "Splashtop",
    3389: "RDP", 8040: "RustDesk", 21115: "RustDesk", 21116: "RustDesk", 21117: "RustDesk",
    5650: "RemotePC", 8200: "GoToAssist", 1494: "Citrix ICA", 2598: "Citrix ICA",
}


def review_ns_remote_access_app(db: DBSession) -> list:
    """FO-06: a remote-access tool in captured traffic - a session between an
    inside host and a PUBLIC address on a well-known remote-access port
    (TeamViewer 5938, AnyDesk 7070 / 6568, VNC 5900-5903 / 5500, Splashtop
    6783-6785, RDP 3389, RustDesk, Citrix ICA ...) opened from the inside
    (inbound connections from the Internet are review_ns_remote_access_bypass's).  The
    pcap counterpart of the FortiAnalyzer application-control check
    ``remote_access_app``.  High; critical when the inside host also talks
    to L0-L1 devices (the tool is a door to the controllers)."""
    from sqlalchemy import or_
    if not _require_sessions(db):
        return []
    src_h, dst_h = aliased(Host), aliased(Host)
    ports = list(REMOTE_ACCESS_TOOL_PORTS)
    q = (db.query(NetworkSession, src_h, dst_h)
         .join(src_h, NetworkSession.src_host_id == src_h.id)
         .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
         .filter(or_(NetworkSession.dst_port.in_(ports), NetworkSession.src_port.in_(ports))))
    field_peers: dict = {}

    def _field_peers(h) -> list:
        if h.id not in field_peers:
            a, b = aliased(Host), aliased(Host)
            rows = (db.query(a.ip, b.ip, a.purdue_level, b.purdue_level)
                    .select_from(NetworkSession)
                    .join(a, NetworkSession.src_host_id == a.id)
                    .join(b, NetworkSession.dst_host_id == b.id)
                    .filter(or_(NetworkSession.src_host_id == h.id, NetworkSession.dst_host_id == h.id))
                    .limit(2000).all())
            peers = set()
            for aip, bip, al, bl in rows:
                pip, pl = (bip, bl) if aip == h.ip else (aip, al)
                if pl is not None and pl <= 1:
                    peers.add(pip)
            field_peers[h.id] = sorted(peers)
        return field_peers[h.id]

    results: list[Optional[Finding]] = []
    for ns, a, b in _keyset(q, NetworkSession.id, key=lambda r: r[0].id):
        if ns.dst_port in REMOTE_ACCESS_TOOL_PORTS and _is_public_ip(b.ip) and not _is_public_ip(a.ip):
            inside, outside, port, outbound = a, b, ns.dst_port, True
        elif ns.src_port in REMOTE_ACCESS_TOOL_PORTS and _is_public_ip(a.ip) and not _is_public_ip(b.ip):
            inside, outside, port, outbound = b, a, ns.src_port, True     # reply seen first
        else:
            # Internet -> inside is review_ns_remote_access_bypass's (an
            # approved jump host may legitimately accept it)
            continue
        tool = REMOTE_ACCESS_TOOL_PORTS[port]
        peers = _field_peers(inside)
        lvl = fmt_level(inside.purdue_level) if inside.purdue_level is not None else "unclassified"
        sev = "critical" if peers else None
        direction = (f"{inside.ip} ({lvl}) → {outside.ip}:{port}" if outbound
                     else f"{outside.ip} → {inside.ip}:{port} ({lvl})")
        results.append(_make_finding(
            db, "session_remote_access_app",
            f"Remote-access tool {tool} in captured traffic: {direction}",
            (f"Checklist 4.5 [observed sessions]: host {inside.ip} ({lvl}) "
             + (f"held a {tool} session to {outside.ip}:{port} on the Internet. " if outbound else
                f"accepted a {tool} connection from {outside.ip} on the Internet (port {port}). ")
             + "Remote-access tools bypass the DMZ jump host and every control on it: no MFA, no "
               "session recording, no approval (IEC 62443-2-1 NET 3.1, SR 1.13). "
             + (f"The host also talks to L0-L1 devices ({', '.join(peers[:5])}), so the tool is a door "
                "to the controllers. " if peers else "")
             + "Remove the tool, or route vendor access through the approved remote-access path. "
               "Identified by port only - confirm on the host."),
            {"source": "network_session", "src_ip": inside.ip, "dst_ip": outside.ip, "dst_port": port,
             "tool": tool, "direction": "outbound" if outbound else "inbound",
             "inside_level": inside.purdue_level, "field_peers": peers[:20],
             "severity_reason": ("Critical: the host also talks to L0-L1 devices." if peers else
                                 "High: an unapproved remote-access channel to the Internet.")},
            session_id=ns.id, severity=sev,
            dedup_evidence={"src_ip": inside.ip, "dst_ip": outside.ip, "dst_port": port},
        ))
    return [r for r in results if r]


_SWEEP_MGMT_PORTS = {22: "SSH", 23: "telnet", 3389: "RDP", 5900: "VNC", 5800: "VNC (web)", 161: "SNMP",
                     80: "HTTP admin", 443: "HTTPS admin", 8080: "HTTP admin", 2222: "SSH"}
_IOT_TYPE_WORDS = ("camera", "cctv", "nvr", "video", "recorder", "voip", "phone", "pbx", "printer",
                   "building", "iot", "badge", "access_control", "tv")


def _sweep_escalation(db, sip, targets, tports) -> list:
    """RS-09: reasons a host sweep is high - the scanner sits at a higher
    (less trusted) level than what it probed, it is IoT / CCTV / VoIP /
    consumer equipment, or it probed management ports (telnet, SSH, RDP,
    VNC, SNMP)."""
    from app.parsers.segments import CONSUMER_DEVICE_WORDS, CONSUMER_NET_WORDS, vendor_matches
    from app.parsers.subnet_zones import _CAMERA_VENDORS, _PHONE_VENDORS, _declared_for, declarations
    out = []
    src = db.query(Host).filter(Host.ip == sip).first()
    zone_of = _declared_for(declarations(db))

    def level_of(ip, host=None):
        if host is not None and host.purdue_level is not None:
            return float(host.purdue_level)
        z = zone_of(ip)
        return float(z[1].purdue_level) if z and z[1].purdue_level is not None else None

    src_lvl = level_of(sip, src)
    t_hosts = {h.ip: h for h in db.query(Host).filter(Host.ip.in_(list(targets)[:5000]))} if targets else {}
    t_lvls = [lv for lv in (level_of(ip, t_hosts.get(ip)) for ip in targets) if lv is not None]
    if src_lvl is not None and t_lvls and src_lvl > min(t_lvls):
        lo = min(t_lvls)
        out.append(f"the source ({fmt_level(src_lvl)}) probed {fmt_level(lo)} devices below its own level")
    dtype = (src.device_type or "").lower() if src is not None else ""
    vendor = (src.vendor or "") if src is not None else ""
    if any(w in dtype for w in _IOT_TYPE_WORDS):
        out.append(f"the source is {dtype.replace('_', ' ')} equipment, which has no reason to scan")
    elif vendor and (vendor_matches(vendor, _CAMERA_VENDORS) or vendor_matches(vendor, _PHONE_VENDORS)):
        out.append(f"the source is camera / phone equipment ({vendor}), which has no reason to scan")
    elif vendor and (vendor_matches(vendor, CONSUMER_NET_WORDS) or vendor_matches(vendor, CONSUMER_DEVICE_WORDS)):
        out.append(f"the source is consumer equipment ({vendor})")
    mg = [f"{_SWEEP_MGMT_PORTS[p]} ({p})" for p in tports if p in _SWEEP_MGMT_PORTS]
    if mg:
        out.append("management ports were probed: " + ", ".join(mg[:5]))
    return out



def review_ns_scanning_anomaly(db: DBSession) -> list:
    """
    Phase 5 degraded fallback for real-time "scanning_denied" (check 8.8).

    Without FAZ deny logs we have no direct visibility of scan attempts that
    were blocked.  Two capture heuristics:

    * vertical - a source whose distinct destination-port count (sessions
      plus FO-04 connection attempts) exceeds the average across all sources
      times _SCAN_VOLUME_MULTIPLIER (needs a threshold of 5+);
    * FO-04 horizontal sweep - a source that probed _SCAN_SWEEP_HOSTS or more
      addresses, most of them without a conversation (refused / unanswered
      TCP attempts, ARP requests nobody answered).  High when industrial
      ports were probed, else medium.

    B-04: always runs (no longer skipped when any FAZ event arrived; the
    FAZ counterpart sees different evidence, so both are kept).
    """
    from app.models import ConnectionAttempt
    from app.parsers.access_paths import INDUSTRIAL_PORTS

    src_h, dst_h = aliased(Host), aliased(Host)
    ports: dict = {}
    talked: dict = {}
    for sip, dip, port in (db.query(src_h.ip, dst_h.ip, NetworkSession.dst_port)
                           .join(src_h, NetworkSession.src_host_id == src_h.id)
                           .join(dst_h, NetworkSession.dst_host_id == dst_h.id)):
        if not sip:
            continue
        if port is not None:
            ports.setdefault(sip, set()).add(port)
        if dip:
            talked.setdefault(sip, set()).add(dip)
    probed: dict = {}
    for att in db.query(ConnectionAttempt):
        if att.dst_port is not None:
            ports.setdefault(att.src_ip, set()).add(att.dst_port)
        probed.setdefault(att.src_ip, []).append(att)

    if not ports and not probed:
        _mark_incomplete(db, "no observed sessions")   # B-24: no data, not "fixed"
        return []

    results: list[Optional[Finding]] = []
    counts = [len(v) for v in ports.values()]
    avg_count = sum(counts) / len(counts) if counts else 0
    threshold = avg_count * _SCAN_VOLUME_MULTIPLIER
    if threshold >= 5:            # else not enough data for a meaningful threshold
        for sip, pset in sorted(ports.items()):
            n = len(pset)
            if n <= threshold:
                continue
            evidence = {
                "source":           "network_session",
                "src_ip":           sip,
                "distinct_dst_ports": n,
                "threshold":        round(threshold, 1),
                "avg_dst_ports":    round(avg_count, 1),
                "note":             "observed in captured traffic - sessions and connection attempts",
            }
            result = _make_finding(
                db,
                check_name="session_scanning_anomaly",
                title=(f"Scanning anomaly: {sip} connected to {n} distinct ports "
                       f"(threshold {round(threshold, 0):.0f})"),
                detail_text=(
                    f"Checklist 8.8 [observed traffic]: Host {sip} reached or tried {n} distinct "
                    f"destination ports in the captured traffic (sessions and refused / unanswered "
                    f"attempts), {n / avg_count:.1f}× the average across all sources ({avg_count:.1f} "
                    f"ports). This may indicate scanning or broad reconnaissance behaviour "
                    f"(SR 6.2, SR 7.1). A scan a firewall dropped before the capture point is not "
                    f"visible here. Investigate this host's connectivity."),
                evidence=evidence,
            )
            if result:
                results.append(result)

    for sip, atts in sorted(probed.items()):
        failed = {a.dst_ip for a in atts if a.outcome in ("refused", "unanswered", "arp_unanswered")}
        targets = failed | {a.dst_ip for a in atts} | talked.get(sip, set())
        if len(targets) < _SCAN_SWEEP_HOSTS or len(failed) * 2 < len(targets):
            continue
        tports = sorted({a.dst_port for a in atts if a.dst_port is not None})
        ics = [p for p in tports if p in INDUSTRIAL_PORTS]
        silent = len({a.dst_ip for a in atts if a.outcome == "arp_unanswered"})
        refused = len({a.dst_ip for a in atts if a.outcome == "refused"})
        open_ = sorted({f"{a.dst_ip}:{a.dst_port}" for a in atts if a.outcome == "open"})
        mac = next((a.src_mac for a in atts if a.src_mac), None)
        port_txt = (f" on ports {', '.join(map(str, tports[:12]))}" if tports else "")
        # RS-09: who sweeps and what for decides the severity
        reasons = _sweep_escalation(db, sip, targets, tports)
        if ics:
            reasons.insert(0, "industrial ports were probed")
        result = _make_finding(
            db,
            check_name="session_scanning_anomaly",
            title=(f"Host sweep: {sip} probed {len(targets)} addresses{port_txt}"
                   + (" (industrial ports)" if ics else "")
                   + (f" - {reasons[1 if ics else 0]}" if len(reasons) > (1 if ics else 0) else "")),
            detail_text=(
                f"Checklist 8.8 [observed traffic]: Host {sip}{' (' + mac + ')' if mac else ''} probed "
                f"{len(targets)} addresses: {silent} never answered its ARP requests, {refused} refused "
                f"the connection, {len(open_)} open port(s) answered without any data following"
                + (f" ({', '.join(open_[:6])})" if open_ else "")
                + f". Probed ports: {', '.join(map(str, tports)) or 'none (ARP only)'}. "
                + (f"Industrial ports ({', '.join(INDUSTRIAL_PORTS[p] for p in ics)}) were probed: "
                   "someone is mapping the controllers. " if ics else "")
                + "Find out who runs the scan and why (SR 6.2, SR 7.1); a sanctioned asset discovery "
                  "should be scheduled, documented and done from an approved host."),
            evidence={"source": "connection_attempts", "src_ip": sip, "src_mac": mac,
                      "addresses_probed": len(targets), "arp_unanswered": silent, "refused": refused,
                      "open_probes": open_[:20], "ports": tports[:50], "industrial_ports": ics,
                      "threshold_hosts": _SCAN_SWEEP_HOSTS, "escalation": reasons,
                      "severity_reason": (("High: " + "; ".join(reasons) + ".") if reasons else
                                          "Medium: a sweep of the segment from a host at the same or a "
                                          "lower level, without industrial or management ports.")},
            severity="high" if reasons else None,
            dedup_evidence={"src_ip": sip, "kind": "sweep"},
        )
        if result:
            results.append(result)

    return [r for r in results if r]


def review_ns_mgmt_from_non_admin(db: DBSession) -> list:
    """
    Phase 5 degraded fallback for real-time "auth_failure" and
    "auth_from_non_admin_host" (checks 5.5, 9.5).

    Without FAZ authentication logs we cannot see actual failed login
    attempts.  Instead we flag sessions to management ports (SSH/Telnet/
    RDP/WinRM) that originate from hosts not in the approved admin_ws or
    jump_host baseline, which is network-visible evidence that management
    access may be coming from an unexpected host.

    This is degraded: we cannot distinguish successful from failed logins,
    and we cannot see password attempts — only that a session to a management
    port was established.

    B-04: always runs (no longer skipped when any FAZ event arrived; the
    FAZ counterpart sees different evidence, so both are kept).
    """

    # Approved admin sources: baseline admin_ws / jump_host (IP or CIDR) plus
    # declared management networks, trusted hosts and management-VLAN hosts.
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)
    approved_admin_ips = bool(mctx.has_sources)

    results: list[Optional[Finding]] = []
    if not _require_sessions(db):
        return []

    # Sessions to management ports only
    # C-20: one joined, keyset-paginated query instead of a session list
    # plus two host lookups per session.
    src_h, dst_h = aliased(Host), aliased(Host)
    q = (
        db.query(NetworkSession, src_h, dst_h)
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .outerjoin(dst_h, NetworkSession.dst_host_id == dst_h.id)
        .filter(NetworkSession.dst_port.in_(list(_MGMT_PORTS)))
    )

    for ns, src_host, dst_host in _keyset(q, NetworkSession.id, key=lambda r: r[0].id):
        # If no baseline exists, flag everything (fail-open design)
        # engineering sources count only toward OT equipment (L0-L2)
        if approved_admin_ips and mctx.is_admin_ip(
                src_host.ip, ot=bool(dst_host is not None and dst_host.purdue_level is not None
                                     and dst_host.purdue_level <= 2)):
            continue   # expected admin / engineering source

        # MV-10: remote access (L4+ / outside) to a declared jump host is the
        # sanctioned remote-access path; the remote-access checks judge it.
        if (dst_host is not None and mctx.is_jump_host(dst_host.ip, dst_host)
                and src_host.purdue_level is not None and src_host.purdue_level >= 4):
            continue

        dst_ip = dst_host.ip if dst_host else "unknown"

        evidence = {
            "source":          "network_session",
            "src_ip":          src_host.ip,
            "dst_ip":          dst_ip,
            "dst_port":        ns.dst_port,
            "transport":       ns.transport,
            "baseline_present": bool(approved_admin_ips),
            "note":            "observed in captured traffic - login outcome unknown",
        }
        no_baseline_note = (
            " No approved admin workstation, trusted management host or management "
            "network is declared - all management port sessions are flagged (fail-open)."
            if not approved_admin_ips else ""
        )
        result = _make_finding(
            db,
            check_name="session_mgmt_from_non_admin",
            title=(
                f"Management port session from non-admin host "
                f"{src_host.ip} → {dst_ip}:{ns.dst_port}"
            ),
            detail_text=(
                f"Checklist 5.5/9.5 [FAZ fallback — degraded]: Host {src_host.ip} "
                f"initiated a session to management port {ns.dst_port} "
                f"({'TCP' if ns.transport == 'tcp' else ns.transport or 'unknown'}) "
                f"on {dst_ip}, but {src_host.ip} is not in the approved "
                f"admin workstation or jump-host baseline (SR 1.11, SR 1.12, SR 2.1). "
                f"Verify that this access was authorised and originated from a "
                f"dedicated, hardened admin workstation.{no_baseline_note} "
                f"Note: FortiAnalyzer unavailable — the session was observed but "
                f"whether authentication succeeded is unknown."
            ),
            evidence=evidence,
        )
        if result:
            results.append(result)

    return [r for r in results if r]


def review_vlan_zone_mismatch(db: DBSession) -> list:
    """
    Phase 5 VLAN topology check: fires when a host's protocol-inferred
    Purdue level disagrees with the Purdue level that SwitchVlan propagated
    for the same VLAN (from keyword inference or firewall propagation).

    A mismatch here is a zone-integrity anomaly: either the host is behaving
    at a different Purdue level than its VLAN assignment suggests (likely
    misconfiguration or rogue traffic), or the VLAN naming/firewall assignment
    is wrong (documentation gap).  Either way, 62443-3-3 SR 5.1 RE2 / SR 5.2
    requires investigation.

    Checklist 2.7 (SR 5.1 RE2, SR 5.2).
    """
    results: list[Optional[Finding]] = []

    # Hosts that have both protocol-inferred classification AND a known VLAN
    candidates = db.query(Host).filter(
        Host.classification_source == "protocol_inferred",
        Host.purdue_level.isnot(None),
        Host.vlan.isnot(None),
    ).all()

    for host in candidates:
        # Resolve the SwitchVlan for this host's VLAN.
        # host.vlan is always stored as a string; for trunk ports it may be a
        # comma-separated list like "10,20-25,30".  Extract the first VLAN ID
        # (the primary VLAN) so trunk-mode hosts are still checked rather than
        # silently skipped.
        raw_vlan = (host.vlan or "").split(",")[0].split("-")[0].strip()
        try:
            vlan_id_int = int(raw_vlan)
        except (ValueError, TypeError):
            continue

        sv = (
            db.query(SwitchVlan)
            .filter(
                SwitchVlan.vlan_id == vlan_id_int,
                SwitchVlan.purdue_level.isnot(None),
                SwitchVlan.purdue_level_source.in_(
                    ["keyword_inferred", "firewall_propagated"]
                ),
            )
            .order_by(SwitchVlan.id)   # B-24: stable pick -> stable dedup key
            .first()
        )
        if sv is None:
            continue  # no VLAN-level evidence to compare against

        if sv.purdue_level == host.purdue_level:
            continue  # match — expected

        evidence = {
            "source":                  "vlan_topology",
            "host_ip":                 host.ip,
            "host_mac":                host.mac,
            "host_purdue_level":       host.purdue_level,
            "host_classification":     host.classification_source,
            "vlan_id":                 sv.vlan_id,
            "vlan_name":               sv.vlan_name,
            "vlan_purdue_level":       sv.purdue_level,
            "vlan_purdue_level_source": sv.purdue_level_source,
            "switch_device":           sv.device_name,
        }
        result = _make_finding(
            db,
            check_name="vlan_zone_mismatch",
            title=(
                f"VLAN zone mismatch: host {host.ip or host.mac} at Purdue {fmt_level(host.purdue_level)} "
                f"on VLAN {sv.vlan_id} ({sv.vlan_name or 'unnamed'}) assigned to {fmt_level(sv.purdue_level)}"
            ),
            detail_text=(
                f"Checklist 2.7 [VLAN zone integrity — SR 5.1 RE2, SR 5.2]: "
                f"Host {host.ip or host.mac} was classified as Purdue Level {host.purdue_level} "
                f"by protocol observation ({host.classification_source}), but it resides on "
                f"VLAN {sv.vlan_id} ({sv.vlan_name or 'unnamed'}) whose assigned Purdue level "
                f"is {sv.purdue_level} (source: {sv.purdue_level_source}). "
                f"Either the host is operating outside its intended zone, or the VLAN's "
                f"Purdue assignment is incorrect. Investigate to confirm correct zone placement "
                f"and update the baseline or VLAN documentation accordingly."
            ),
            evidence=evidence,
        )
        if result:
            results.append(result)

    return [r for r in results if r]


def review_ghost_vlans(db: DBSession) -> list:
    """
    Phase 5 VLAN topology check: fires when MAC address table entries exist
    for a VLAN that the switch marks as 'inactive' in its vlan brief output.

    An inactive VLAN with live MAC activity is a ghost VLAN — a strong indicator
    of:
      - A misconfigured port that is forwarding frames on a pruned VLAN
      - A rogue device injecting traffic on a VLAN that should be defunct
      - An unmanaged legacy segment still carrying traffic after a VLAN
        decommission was not fully completed

    Any of these is a zone-integrity concern under 62443-3-3 SR 6.2 (audit /
    anomaly detection).  Checklist 8.6.
    """
    results: list[Optional[Finding]] = []

    # All VLANs the switch reports as inactive (from show vlan brief)
    inactive_vlans = db.query(SwitchVlan).filter(
        SwitchVlan.status == "inactive",
    ).all()

    for sv in inactive_vlans:
        # Check if any MAC table entries reference this (device, vlan_id).
        # Always build a device-scoped query when device_name is known so that
        # mac_count and any_match reflect only THIS switch's MAC table — not
        # every switch that happens to have the same VLAN ID.  Falling back
        # to the unscoped query only when no device_name is set (MAC table
        # was ingested without a device name).
        mac_query_all = db.query(MacTableEntry).filter(
            MacTableEntry.vlan == str(sv.vlan_id),
        )
        if sv.device_name:
            mac_query = mac_query_all.filter(
                MacTableEntry.device_name == sv.device_name
            )
            any_match = mac_query.first()
            if not any_match:
                # Fall back to device_name=NULL rows (ingested without device context)
                any_match = mac_query_all.filter(
                    MacTableEntry.device_name.is_(None)
                ).first()
                if any_match:
                    mac_query = mac_query_all.filter(MacTableEntry.device_name.is_(None))
        else:
            mac_query = mac_query_all
            any_match = mac_query.first()

        if not any_match:
            continue  # no ghost — inactive VLAN is also silent

        # Count how many MACs were seen on this VLAN (device-scoped when possible)
        mac_count = mac_query.count()
        evidence = {
            "source":        "vlan_topology",
            "switch_device": sv.device_name,
            "vlan_id":       sv.vlan_id,
            "vlan_name":     sv.vlan_name,
            "vlan_status":   sv.status,
            "mac_count":     mac_count,
            "example_mac":   any_match.mac,
            "example_port":  any_match.port_name,
        }
        result = _make_finding(
            db,
            check_name="ghost_vlan",
            title=(
                f"Ghost VLAN: inactive VLAN {sv.vlan_id} "
                f"({sv.vlan_name or 'unnamed'}) on {sv.device_name or 'unknown switch'} "
                f"has {mac_count} MAC table {'entry' if mac_count == 1 else 'entries'}"
            ),
            detail_text=(
                f"Checklist 8.6 [Ghost VLAN — SR 6.2]: "
                f"VLAN {sv.vlan_id} ({sv.vlan_name or 'unnamed'}) on switch "
                f"{sv.device_name or 'unknown'} is marked 'inactive' in the VLAN table, "
                f"but {mac_count} MAC address table {'entry was' if mac_count == 1 else 'entries were'} "
                f"observed on it (example: {any_match.mac} on port {any_match.port_name}). "
                f"Traffic on an inactive VLAN indicates a misconfigured port, an incomplete "
                f"VLAN decommission, or a rogue device injecting traffic on a pruned segment. "
                f"Verify port {any_match.port_name} configuration and confirm whether VLAN "
                f"{sv.vlan_id} should be reactivated or fully pruned."
            ),
            evidence=evidence,
        )
        if result:
            results.append(result)

    return [r for r in results if r]


def review_intervlan_routing(db: DBSession) -> list:
    """
    Phase 5 VLAN topology check: fires when 802.1Q VLAN sub-interfaces on
    the same physical trunk span an IT/OT zone boundary but no explicit
    FirewallRule covers the conduit between them.

    When two sibling sub-interfaces (e.g. port3.10 at Purdue L2 and
    port3.20 at Purdue L3) share a parent trunk interface, the firewall is
    the SOLE enforcement point for inter-VLAN traffic.  If no FirewallRule
    with action="permit" exists for that zone pair in either direction, the
    firewall is either silently dropping traffic (no audit trail) or forwarding
    it without a logged policy — both are zone-isolation failures under
    62443-3-3 SR 5.1 RE2 and SR 5.2.

    Threshold: Purdue level distance >= 2 (e.g. L1↔L3, L2↔L4) is treated
    as an IT/OT crossing.  Distance of 1 (L2↔L3) is flagged when one side is
    <= 2 (OT) and the other is >= 3 (IT), because L2↔L3 is still the canonical
    OT→DMZ or OT→IT boundary in ISA-95/PERA.

    Checklist 2.1, 2.2 (SR 5.1 RE2, SR 5.2).
    """
    results: list[Optional[Finding]] = []

    # Collect all sub-interfaces that have both a parent and a purdue_level
    sub_ifaces = (
        db.query(FirewallInterface)
        .filter(
            FirewallInterface.parent_interface_id.isnot(None),
            FirewallInterface.purdue_level.isnot(None),
            FirewallInterface.name.isnot(None),
        )
        .all()
    )

    if not sub_ifaces:
        return results

    # Group siblings: (firewall_id, parent_interface_id) → list of sub-interfaces
    from collections import defaultdict
    sibling_groups: dict = defaultdict(list)
    for iface in sub_ifaces:
        key = (iface.firewall_id, iface.parent_interface_id)
        sibling_groups[key].append(iface)

    # Pre-load FirewallRule rows for the relevant firewall_ids so we don't
    # hit the DB once per pair — one query per firewall is far cheaper.
    firewall_ids = {fw_id for (fw_id, _) in sibling_groups.keys() if fw_id is not None}
    rules_by_fw: dict = {}
    zone_idx = _fz.ZoneDefIndex(db, firewall_ids)
    for fw_id in firewall_ids:
        fw_rules = (
            db.query(FirewallRule)
            .filter(
                FirewallRule.firewall_id == fw_id,
                FirewallRule.enabled.is_(True),
                FirewallRule.action == "permit",
                FirewallRule.src_zone.isnot(None),
                FirewallRule.dst_zone.isnot(None),
            )
            .all()
        )
        # Index as set of (src_iface, dst_iface) pairs for O(1) lookup.
        # B-07: FortiOS zone names expand to their member interfaces (shared
        # helper); a zone of unknown membership covers nothing (the finding
        # is kept - conservative), an empty zone covers nothing.
        pairs: set = set()
        for r in fw_rules:
            # (an unresolved zone keeps its own name, which names no
            # interface - so it covers nothing)
            src, _ = zone_idx.expand_rule(r, "src_zone")
            dst, _ = zone_idx.expand_rule(r, "dst_zone")
            if src is None or dst is None:
                continue        # "any" sides were never counted as coverage
            pairs.update((a, b) for a in src for b in dst)
        rules_by_fw[fw_id] = pairs

    def _is_it_ot_crossing(level_a: int, level_b: int) -> bool:
        """True when the two Purdue levels straddle the IT/OT boundary."""
        lo, hi = min(level_a, level_b), max(level_a, level_b)
        # Both sides OT (≤2) or both sides IT (≥3, incl. the L3.5 DMZ) — no
        # IT/OT boundary crossing
        if is_ot(hi) or is_it_side(lo):
            return False
        # lo is OT (≤2), hi is IT (≥3) — this IS a crossing
        return True

    # Examine every unordered pair within each sibling group
    for (fw_id, parent_id), siblings in sibling_groups.items():
        if len(siblings) < 2:
            continue  # a lone sub-interface has no sibling to cross into

        # Resolve the parent interface name for human-readable output
        parent_iface = db.get(FirewallInterface, parent_id) if parent_id else None
        parent_name = parent_iface.name if parent_iface else "unknown"
        fw_rules_set = rules_by_fw.get(fw_id, set())

        for i in range(len(siblings)):
            for j in range(i + 1, len(siblings)):
                a, b = siblings[i], siblings[j]
                if not _is_it_ot_crossing(a.purdue_level, b.purdue_level):
                    continue

                # Determine which is the OT side and which is IT
                ot_iface = a if a.purdue_level < b.purdue_level else b
                it_iface = b if a.purdue_level < b.purdue_level else a

                # Check both traffic directions: OT→IT and IT→OT
                ot_zone = ot_iface.name   # FortiGate zone = interface name
                it_zone = it_iface.name
                ot_key, it_key = (ot_zone or "").lower(), (it_zone or "").lower()
                covered_ot_to_it = (ot_key, it_key) in fw_rules_set
                covered_it_to_ot = (it_key, ot_key) in fw_rules_set

                if covered_ot_to_it and covered_it_to_ot:
                    continue  # both directions explicitly permitted — OK

                missing_directions = []
                if not covered_ot_to_it:
                    missing_directions.append(f"{ot_zone}→{it_zone} (OT→IT)")
                if not covered_it_to_ot:
                    missing_directions.append(f"{it_zone}→{ot_zone} (IT→OT)")

                evidence = {
                    "source":              "vlan_topology",
                    "firewall_id":         fw_id,
                    "parent_interface":    parent_name,
                    "ot_interface":        ot_iface.name,
                    "ot_vlan_id":          ot_iface.vlan_id,
                    "ot_purdue_level":     ot_iface.purdue_level,
                    "it_interface":        it_iface.name,
                    "it_vlan_id":          it_iface.vlan_id,
                    "it_purdue_level":     it_iface.purdue_level,
                    "missing_directions":  missing_directions,
                    "covered_ot_to_it":    covered_ot_to_it,
                    "covered_it_to_ot":    covered_it_to_ot,
                }

                result = _make_finding(
                    db,
                    check_name="intervlan_routing_unchecked",
                    title=(
                        f"Inter-VLAN routing unchecked: {ot_iface.name} ({fmt_level(ot_iface.purdue_level)}) ↔ "
                        f"{it_iface.name} ({fmt_level(it_iface.purdue_level)}) on trunk {parent_name} — "
                        f"no permit rule for: {', '.join(missing_directions)}"
                    ),
                    detail_text=(
                        f"Checklist 2.1/2.2 [Inter-VLAN zone isolation — SR 5.1 RE2, SR 5.2]: "
                        f"Sub-interfaces {ot_iface.name} (Purdue {fmt_level(ot_iface.purdue_level)}, "
                        f"VLAN {ot_iface.vlan_id or '?'}) and {it_iface.name} "
                        f"(Purdue {fmt_level(it_iface.purdue_level)}, VLAN {it_iface.vlan_id or '?'}) are "
                        f"802.1Q siblings on physical trunk {parent_name}.  The firewall is the only "
                        f"enforcement point for traffic between these VLANs.  "
                        f"No explicit permit FirewallRule was found for the following conduit "
                        f"{'direction' if len(missing_directions) == 1 else 'directions'}: "
                        f"{', '.join(missing_directions)}.  "
                        f"Without an auditable permit policy, inter-VLAN traffic either crosses "
                        f"without logging (implicit permit) or is silently dropped with no audit "
                        f"trail (implicit deny) — both violate SR 5.2 deny-by-default with logging.  "
                        f"Add explicit permit rules with logging enabled for all approved inter-VLAN "
                        f"conduits, or document that no cross-VLAN traffic is expected and confirm "
                        f"the implicit-deny behaviour is logged."
                    ),
                    evidence=evidence,
                )
                if result:
                    results.append(result)

    return [r for r in results if r]


# ---------------------------------------------------------------------------
# PHASE 6: FIREWALL-RULE-BASED TWIN CHECKS
#
# Each function below queries FirewallRule rows (parsed policy) for dangerous
# "permit" entries, then checks whether a matching NetworkSession row exists
# (i.e. traffic between hosts at the rule's resolved Purdue levels, on one of
# the matched ports). When such traffic is found the severity escalates and
# "confirmed_by_traffic": True is added to evidence; an already-open finding
# for the same rule is escalated in place by _make_finding (T1-11).
#
# Zone-to-Purdue resolution (T1-12) is done by _RuleZoneResolver, which maps
# each side of a rule (a FortiGate zone name, an interface list such as
# "port1,port2", or "any") to the SET of Purdue levels it covers. Port specs
# (T1-13) are parsed into (lo, hi) ranges by _parse_rule_ports, and each check
# tests OVERLAP between those ranges and its dangerous-port table.
# ---------------------------------------------------------------------------

_PORT_ANY: tuple[tuple[int, int], ...] = ((0, 65535),)

# Cisco IOS/ASA well-known port keywords, IANA service names, and FortiOS
# predefined service names (matched case-insensitively). Values are lists of
# inclusive (lo, hi) ranges.
_PORT_NAMES: dict[str, list[tuple[int, int]]] = {
    # Cisco / IANA keywords
    "echo": [(7, 7)], "discard": [(9, 9)], "daytime": [(13, 13)],
    "chargen": [(19, 19)], "ftp-data": [(20, 20)], "ftp": [(21, 21)],
    "ssh": [(22, 22)], "telnet": [(23, 23)], "smtp": [(25, 25)],
    "time": [(37, 37)], "nameserver": [(42, 42)], "whois": [(43, 43)],
    "tacacs": [(49, 49)], "domain": [(53, 53)], "dns": [(53, 53)],
    "bootps": [(67, 67)], "bootpc": [(68, 68)], "tftp": [(69, 69)],
    "gopher": [(70, 70)], "finger": [(79, 79)],
    "www": [(80, 80)], "http": [(80, 80)],
    "kerberos": [(88, 88)], "hostname": [(101, 101)],
    "iso-tsap": [(102, 102)], "s7": [(102, 102)], "s7comm": [(102, 102)],
    "pop2": [(109, 109)], "pop3": [(110, 110)], "sunrpc": [(111, 111)],
    "ident": [(113, 113)], "nntp": [(119, 119)], "ntp": [(123, 123)],
    "msrpc": [(135, 135)], "netbios-ns": [(137, 137)],
    "netbios-dgm": [(138, 138)], "netbios-ssn": [(139, 139)],
    "imap": [(143, 143)], "imap4": [(143, 143)],
    "snmp": [(161, 161)], "snmptrap": [(162, 162)], "snmp-trap": [(162, 162)],
    "xdmcp": [(177, 177)], "bgp": [(179, 179)], "irc": [(194, 194)],
    "dnsix": [(195, 195)], "ldap": [(389, 389)], "mobile-ip": [(434, 434)],
    "https": [(443, 443)], "cifs": [(445, 445)], "smb": [(445, 445)],
    "microsoft-ds": [(445, 445)], "pim-auto-rp": [(496, 496)],
    "isakmp": [(500, 500)], "ike": [(500, 500)], "modbus": [(502, 502)],
    "exec": [(512, 512)], "biff": [(512, 512)], "login": [(513, 513)],
    "cmd": [(514, 514)], "rsh": [(514, 514)], "syslog": [(514, 514)],
    "lpd": [(515, 515)], "talk": [(517, 517)], "rip": [(520, 520)],
    "uucp": [(540, 540)], "klogin": [(543, 543)], "kshell": [(544, 544)],
    "ldaps": [(636, 636)], "rtsp": [(554, 554)],
    "mssql": [(1433, 1433)], "ms-sql": [(1433, 1433)],
    "lotusnotes": [(1352, 1352)], "citrix-ica": [(1494, 1494)],
    "sqlnet": [(1521, 1521)], "radius": [(1645, 1645)],
    "radius-acct": [(1646, 1646)], "h323": [(1720, 1720)],
    "pptp": [(1723, 1723)], "iec-104": [(2404, 2404)], "iec104": [(2404, 2404)],
    "ctiqbe": [(2748, 2748)], "mysql": [(3306, 3306)],
    "rdp": [(3389, 3389)], "ms-wbt-server": [(3389, 3389)],
    "opc-ua": [(4840, 4840)], "sip": [(5060, 5060)], "aol": [(5190, 5190)],
    "secureid-udp": [(5510, 5510)], "vnc": [(5900, 5900)],
    "http-alt": [(8080, 8080)], "https-alt": [(8443, 8443)],
    "dnp3": [(20000, 20000)], "dnp": [(20000, 20000)],
    "enip": [(44818, 44818)], "ethernet-ip": [(44818, 44818)],
    "bacnet": [(47808, 47808)],
    # FortiOS predefined services (config firewall service custom defaults)
    "samba": [(139, 139)], "nfs": [(111, 111), (2049, 2049)],
    "ping": [], "all_icmp": [], "all_icmp6": [],  # ICMP: no port semantics
    "all": list(_PORT_ANY), "all_tcp": list(_PORT_ANY),
    "all_udp": list(_PORT_ANY),
}
_PORT_ANY_WORDS = {"", "any", "all", "*", "any/any", "0-65535", "1-65535"}
_CISCO_OPS = {"eq", "range", "gt", "lt", "neq"}
_ICMP_PROTOCOLS = {"icmp", "icmp6", "icmpv6", "ipv6-icmp", "1", "58"}


def _port_token(tok: str) -> Optional[list[tuple[int, int]]]:
    """One port token: number, lo-hi range, or service name → ranges."""
    tok = tok.strip().lower()
    if not tok:
        return None
    if tok in _PORT_NAMES:  # checked before "-" split: "ftp-data", "http-alt"
        return list(_PORT_NAMES[tok])
    if tok.isdigit():
        p = int(tok)
        return [(p, p)] if 0 <= p <= 65535 else None
    if "-" in tok:
        lo_s, _, hi_s = tok.partition("-")
        lo = _port_token(lo_s)
        hi = _port_token(hi_s)
        if lo and hi and len(lo) == 1 and len(hi) == 1:
            lo_p, hi_p = lo[0][0], hi[0][1]
            if lo_p <= hi_p:
                return [(lo_p, hi_p)]
    return None


def _parse_rule_ports(
    dst_port_str: Optional[str],
) -> Optional[list[tuple[int, int]]]:
    """Parse FirewallRule.dst_port text into inclusive (lo, hi) port ranges.

    Returns [(0, 65535)] (see _PORT_ANY) for "any"-style values and None
    when nothing in the value could be understood. Handles:
      - None / "" / "any" / "all"          → any
      - "22", "1-1024", "80,443", "80 443", "80,1000-2000"
      - Cisco operators: "eq 22", "eq telnet", "range 1 1024",
        "gt 1023", "lt 1024", "neq 53"
      - Cisco/IANA and FortiOS service names (case-insensitive), e.g.
        "www", "netbios-ssn", "HTTPS", "TELNET", "SAMBA"
      - legacy list junk "['502', '102']" (brackets/quotes stripped)
      - FortiOS "dst:src" ranges ("502:1024-65535" → dst part 502)
    Tokens that can't be parsed are logged at DEBUG and ignored when others
    in the same value parsed; if none parse the result is None.
    """
    if dst_port_str is None:
        return list(_PORT_ANY)
    s = str(dst_port_str).strip()
    s = re.sub(r"[\[\]\"'()]", " ", s).strip()
    if s.lower() in _PORT_ANY_WORDS:
        return list(_PORT_ANY)

    tokens = [t for t in re.split(r"[,\s;]+", s) if t]
    ranges: list[tuple[int, int]] = []
    bad: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()
        if tok in _CISCO_OPS:
            if tok == "range":
                a = _port_token(tokens[i + 1]) if i + 1 < len(tokens) else None
                b = _port_token(tokens[i + 2]) if i + 2 < len(tokens) else None
                if a and b and a[0][0] <= b[-1][1]:
                    ranges.append((a[0][0], b[-1][1]))
                else:
                    bad.append(" ".join(tokens[i:i + 3]))
                i += 3
                continue
            arg = _port_token(tokens[i + 1]) if i + 1 < len(tokens) else None
            if not arg or len(arg) != 1 or arg[0][0] != arg[0][1]:
                bad.append(" ".join(tokens[i:i + 2]))
                i += 2
                continue
            p = arg[0][0]
            if tok == "eq":
                ranges.append((p, p))
            elif tok == "gt":
                if p < 65535:
                    ranges.append((p + 1, 65535))
            elif tok == "lt":
                if p > 0:
                    ranges.append((0, p - 1))
            elif tok == "neq":
                if p > 0:
                    ranges.append((0, p - 1))
                if p < 65535:
                    ranges.append((p + 1, 65535))
            i += 2
            continue
        if tok in _PORT_ANY_WORDS:
            return list(_PORT_ANY)
        # FortiOS "dst:src" (e.g. "502:1024-65535") → destination part only
        dst_part = tok.split(":", 1)[0]
        parsed = _port_token(dst_part)
        if parsed is None:
            bad.append(tokens[i])
        else:
            ranges.extend(parsed)
        i += 1

    if bad:
        log.debug("_parse_rule_ports: unparseable token(s) %r in %r", bad, dst_port_str)
    if not ranges:
        return None
    return ranges


#: DR-04: transport of the single-transport well-known services in the
#: dangerous-port tables (a UDP-only rule never "permits Telnet").
_PORT_TRANSPORT = {
    20: "tcp", 21: "tcp", 22: "tcp", 23: "tcp", 25: "tcp", 80: "tcp", 110: "tcp",
    139: "tcp", 143: "tcp", 445: "tcp", 636: "tcp", 5985: "tcp", 5986: "tcp",
    69: "udp", 123: "udp", 137: "udp", 161: "udp", 162: "udp",
}


def _ports_matched(
    ranges: list[tuple[int, int]], table, rule: Optional[FirewallRule] = None,
) -> dict[int, str]:
    """Entries of a dangerous-port table whose port overlaps any range.
    ``table`` is {port: name} or a set of ports.  With ``rule``, a port whose
    service runs on the other transport than the rule's tcp/udp is skipped."""
    items = table.items() if isinstance(table, dict) else ((p, str(p)) for p in table)
    t = _rule_transport(rule) if rule is not None else None
    return {
        p: name for p, name in sorted(items)
        if any(lo <= p <= hi for lo, hi in ranges)
        and not (t and _PORT_TRANSPORT.get(p, t) != t)
    }


def _is_icmp_rule(rule: FirewallRule) -> bool:
    return (rule.protocol or "").strip().lower() in _ICMP_PROTOCOLS


def _rule_port_ranges(rule: FirewallRule) -> Optional[list[tuple[int, int]]]:
    """Port ranges for a port-based check, or None when the rule must be
    skipped (ICMP rule, port-0-only row, or unparseable dst_port)."""
    if _is_icmp_rule(rule):
        return None
    ranges = _parse_rule_ports(rule.dst_port)
    if ranges is None:
        log.debug(
            "Phase 6: rule id=%s policy=%s unparseable dst_port %r — skipped",
            rule.id, rule.policy_id, rule.dst_port,
        )
        return None
    if all(lo == 0 and hi == 0 for lo, hi in ranges):
        return None  # port-0 rows (ICMP/ip-proto rules stored without protocol)
    return ranges


def _rule_transport(rule: FirewallRule) -> Optional[str]:
    proto = (rule.protocol or "").strip().lower()
    if proto in ("tcp", "6"):
        return "tcp"
    if proto in ("udp", "17"):
        return "udp"
    return None


def _fmt_levels(levels) -> str:
    """{3, 3.5} -> "L3,3.5" (F-08: via app.purdue so 3.5 / 3 never print as 3.0)."""
    lv = sorted_levels(levels or ())
    return "L" + ",".join(fmt_level(l, prefix="") for l in lv) if lv else "L?"


def _fmt_ranges(ranges: list[tuple[int, int]], limit: int = 8) -> str:
    parts = [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges[:limit]]
    if len(ranges) > limit:
        parts.append(f"… (+{len(ranges) - limit} more)")
    return ",".join(parts)


def _split_zone_value(value: Optional[str]) -> list[str]:
    """A rule side (src_zone / dst_zone) as its list elements, case kept.

    MP-05 (C-05 parity with fortios_zones.zone_tokens): every parser joins
    srcintf / dstintf elements with a comma and a name may itself contain
    spaces ("OT Zone"), so the value is split on commas only - never on
    whitespace, which shattered such names into tokens that resolved to
    nothing (side unevaluated, no rule twin finding while the access-path
    row for the same policy was flagged)."""
    if value is None:
        return []
    out = []
    for t in str(value).split(","):
        t = t.strip().strip("'\"[]").strip()
        if t:
            out.append(t)
    return out


class _RuleZoneResolver:
    """Resolve a FirewallRule side (src_zone / dst_zone) to a set of Purdue
    levels (T1-12). Built once per run_periodic_reviews call from
    FirewallInterface, FirewallZone and Firewall rows.

    Resolution per token (zone value split on commas only - a name may contain
    spaces, MP-05):
      1. interface name / alias / zone_label on the rule's firewall
         (firewall_id, or the Firewall whose name/device_name equals the
         rule's device_name when firewall_id is None) → purdue_level;
         with no known firewall, a name that matches exactly one
         interface site-wide.
      1b. B-07: a FortiOS zone (FirewallZoneDef) of the rule's firewall and
         VDOM (app.parsers.fortios_zones) → its member interfaces' levels;
         unknown membership (or a member without a level) leaves the side
         incomplete, an empty zone matches nothing (a side of only empty
         zones resolves to no level and counts as fully evaluated).
      2. FirewallZone rows whose zone_name == token for the rule's device
         (device_name match against the rule / its Firewall row; if no
         device-specific match, a zone name used by exactly one device) →
         member interface_name(s) → their FirewallInterface level (same
         firewall, or site-wide when unambiguous).
    "any"/"all"/empty → every Purdue level present on the firewall's
    interfaces (every level on any firewall when the firewall is unknown).
    Unresolved tokens contribute nothing; an empty set means "unknown".
    NULL zones are treated as unknown (not "any").
    """

    _ANY = {"any", "all", "*"}

    def __init__(self, db: DBSession):
        from app.models import Firewall, FirewallDevice  # local: only used here
        # MP-14: the same maps as reachability, kept apart - exact interface
        # NAME -> levels, alias / zone_label -> levels - so a label on one
        # interface never overwrites another interface's real name, and a
        # label shared by two interfaces resolves to BOTH levels.
        self.exact_by_fw: dict[int, dict[str, set]] = {}
        self.labels_by_fw: dict[int, dict[str, set]] = {}
        # MP-09: names / labels of interfaces that exist on the firewall but
        # carry no level (wan1, SD-WAN members, tunnels, loopbacks, mgmt)
        self.known_by_fw: dict[int, set[str]] = {}
        self.side_by_fw: dict[int, dict[str, str]] = {}       # token -> inside / outside
        self.levels_by_fw: dict[int, set[int]] = {}
        self.all_levels: set[int] = set()
        # site-wide name → list of levels (None when that iface has no level)
        global_names: dict[str, list[Optional[int]]] = {}
        for iface in db.query(FirewallInterface).all():
            lvl = iface.purdue_level
            keys = {k.casefold() for k in (iface.name, iface.alias, iface.zone_label) if k}
            for k in keys:
                global_names.setdefault(k, []).append(lvl)
            if iface.side in ("inside", "outside"):
                sides = self.side_by_fw.setdefault(iface.firewall_id, {})
                for k in keys:
                    sides.setdefault(k, iface.side)
            if lvl is None:
                self.known_by_fw.setdefault(iface.firewall_id, set()).update(keys)
                continue
            if iface.name and iface.name.strip():
                self.exact_by_fw.setdefault(iface.firewall_id, {}).setdefault(
                    iface.name.strip().casefold(), set()).add(lvl)
            for k in (iface.name, iface.alias, iface.zone_label):
                if k and k.strip():
                    self.labels_by_fw.setdefault(iface.firewall_id, {}).setdefault(
                        k.strip().casefold(), set()).add(lvl)
            self.levels_by_fw.setdefault(iface.firewall_id, set()).add(lvl)
            self.all_levels.add(lvl)
        self.global_iface: dict[str, int] = {
            k: v[0] for k, v in global_names.items() if len(v) == 1 and v[0] is not None
        }
        # MP-15: the upload boundary (FirewallDevice purdue_zone_from / to,
        # else Firewall purdue_level_ingress / egress) of every firewall -
        # used only for a firewall with NO labelled interface at all.
        self.boundary_by_fw: dict[int, tuple] = {}
        self.boundary_used: set[int] = set()            # rule ids resolved from it
        self.unlabelled_hits: set[int] = set()          # rule ids naming an unlabelled iface
        fw_by_name: dict[str, int] = {}
        for fw in db.query(Firewall).all():
            for n in (fw.name, fw.device_name):
                if n:
                    fw_by_name.setdefault(n.casefold(), fw.id)
            if fw.purdue_level_ingress is not None and fw.purdue_level_egress is not None:
                self.boundary_by_fw[fw.id] = (min(fw.purdue_level_ingress, fw.purdue_level_egress),
                                              max(fw.purdue_level_ingress, fw.purdue_level_egress))
        for dev in db.query(FirewallDevice).all():
            if dev.purdue_zone_from is None or dev.purdue_zone_to is None:
                continue
            fw_id = dev.firewall_id
            if fw_id is None:
                for n in (dev.name, dev.device_hostname):
                    if n and n.casefold() in fw_by_name:
                        fw_id = fw_by_name[n.casefold()]
                        break
            if fw_id is not None:
                self.boundary_by_fw[fw_id] = (min(dev.purdue_zone_from, dev.purdue_zone_to),
                                              max(dev.purdue_zone_from, dev.purdue_zone_to))
        # VD-03: an inter-VDOM link interface stands for the levels of the
        # VDOM(s) on the other side of the link (same mapping as reachability)
        self.link_levels: dict[int, dict[str, set]] = {}
        try:
            from app.parsers.reachability import vdom_link_levels
            self.link_levels = vdom_link_levels(db)
        except Exception:                                # noqa: BLE001
            log.warning("inter-VDOM link levels failed", exc_info=True)

        self.fw_names: dict[int, set[str]] = {}
        self.fw_by_device: dict[str, set[int]] = {}
        for fw in db.query(Firewall).all():
            names = {n.casefold() for n in (fw.name, fw.device_name) if n}
            self.fw_names[fw.id] = names
            for n in names:
                self.fw_by_device.setdefault(n, set()).add(fw.id)

        # zone_name → device_name(casefold or None) → member interface names
        self.zones: dict[str, dict[Optional[str], list[str]]] = {}
        for z in db.query(FirewallZone).filter(FirewallZone.zone_name.isnot(None)).all():
            dev = z.device_name.casefold() if z.device_name else None
            self.zones.setdefault(z.zone_name.casefold(), {}).setdefault(dev, []).append(
                z.interface_name
            )

        # B-07: FortiOS zone definitions per (firewall, VDOM) - authoritative
        # over the legacy FirewallZone rows (shared helper, same semantics as
        # reachability: unknown membership -> unresolved, empty zone ->
        # matches nothing).
        self.zone_defs = _fz.ZoneDefIndex(db)

        self.sides_resolved = 0
        self.sides_unresolved = 0
        self.tokens_unresolved = 0

    def _firewall_for(self, rule: FirewallRule) -> Optional[int]:
        if rule.firewall_id is not None:
            return rule.firewall_id
        if rule.device_name:
            ids = self.fw_by_device.get(rule.device_name.casefold(), set())
            if len(ids) == 1:
                return next(iter(ids))
        return None

    def _iface_levels(self, fw_id: Optional[int], name: str) -> Optional[set]:
        """Levels of an interface named ``name`` on ``fw_id`` - exact name
        first, then alias / zone_label (MP-14, same order as reachability);
        None when nothing matches.  With no known firewall, a name that
        matches exactly one interface site-wide."""
        key = name.strip().casefold()
        if fw_id is not None:
            lv = self.exact_by_fw.get(fw_id, {}).get(key)
            if lv:
                return set(lv)
            lv = self.labels_by_fw.get(fw_id, {}).get(key)
            return set(lv) if lv else None
        lv = self.global_iface.get(key)
        return {lv} if lv is not None else None

    def _iface_level(self, fw_id: Optional[int], name: str) -> Optional[int]:
        """Single-level view of _iface_levels (legacy callers): the lowest."""
        lv = self._iface_levels(fw_id, name)
        return min(lv) if lv else None

    def is_known_unlabelled(self, fw_id: Optional[int], name: str) -> bool:
        """MP-09: ``name`` is an interface of ``fw_id`` that carries no level."""
        if fw_id is None:
            return False
        key = name.strip().casefold()
        return key in self.known_by_fw.get(fw_id, set()) and self._iface_levels(fw_id, name) is None

    def from_boundary(self, rules) -> bool:
        """MP-15: did any of these rows take its levels from the upload
        boundary rather than interface labels?"""
        return any(r.id in self.boundary_used for r in rules)

    def names_unlabelled(self, rules) -> bool:
        """MP-09: does any of these rows name a known interface without a level?"""
        return any(r.id in self.unlabelled_hits for r in rules)

    def _zone_members(self, rule: FirewallRule, fw_id: Optional[int], token: str) -> list[str]:
        by_dev = self.zones.get(token.casefold())
        if not by_dev:
            return []
        candidates: set[str] = set()
        if rule.device_name:
            candidates.add(rule.device_name.casefold())
        if fw_id is not None:
            candidates |= self.fw_names.get(fw_id, set())
        members: list[str] = []
        for dev, ifaces in by_dev.items():
            if dev is not None and dev in candidates:
                members.extend(ifaces)
        if members:
            return members
        # Legacy single-FW rows often lack a matching device_name; accept the
        # zone only when exactly one device defines it (unambiguous).
        if len(by_dev) == 1:
            return list(next(iter(by_dev.values())))
        return []

    def resolve(self, rule: FirewallRule, zone_value: Optional[str]) -> set[int]:
        return self.resolve_checked(rule, zone_value)[0]

    def names_link(self, rule: FirewallRule) -> bool:
        """VD-03: a side of ``rule`` is an inter-VDOM link interface."""
        fw_id = self._firewall_for(rule)
        links = self.link_levels.get(fw_id) if fw_id is not None else None
        if not links:
            return False
        for attr in ("src_zone", "dst_zone"):
            if any(t.casefold() in links for t in _fz.zone_tokens(getattr(rule, attr, None))):
                return True
        return False

    def matches_nothing(self, rule: FirewallRule) -> bool:
        """B-07: True when a side of ``rule`` names only EMPTY FortiOS zones
        (no interface) - the policy can match no traffic."""
        fw_id = self._firewall_for(rule)
        vdom = getattr(rule, "vdom", None)
        for attr in ("src_zone", "dst_zone"):
            toks = _fz.zone_tokens(getattr(rule, attr, None))
            if not toks:
                continue
            if all(self._iface_levels(fw_id, t) is None
                   and self.zone_defs.lookup(fw_id, vdom, t) == ([], True) for t in toks):
                return True
        return False

    def resolve_checked(
        self, rule: FirewallRule, zone_value: Optional[str]
    ) -> tuple[set[int], bool]:
        """(levels, complete). complete is False (A-09) when the side could
        not be fully resolved: NULL zone, empty level set, or at least one
        zone token that resolved to nothing (the side may cover levels we
        cannot see). Level-based checks must not treat such a side as
        "evaluated, no violation"."""
        fw_id = self._firewall_for(rule)
        unresolved = 0
        tokens = _split_zone_value(zone_value)
        boundary = self.boundary_by_fw.get(fw_id) if fw_id is not None else None
        # MP-15: a firewall with an upload boundary and NO labelled interface
        # takes its levels from the boundary (inside -> low side, outside ->
        # high side, unknown -> both); the twins step such findings down.
        use_boundary = boundary is not None and not self.levels_by_fw.get(fw_id)
        if zone_value is not None and (
            not tokens or any(t.casefold() in self._ANY for t in tokens)
        ):
            levels = set(self.levels_by_fw.get(fw_id, set())) if fw_id is not None \
                else set(self.all_levels)
            if not levels and use_boundary:
                levels = set(boundary)
                self.boundary_used.add(rule.id)
        else:
            levels = set()
            empty_zones = 0
            vdom = getattr(rule, "vdom", None)
            for tok in tokens:
                # MP-14: the reachability order - FortiOS zone definition,
                # exact interface name, inter-VDOM link, alias / zone_label,
                # legacy FirewallZone - so an alias never shadows a zone.
                zone = self.zone_defs.lookup(fw_id, vdom, tok)
                if zone is not None:
                    zmembers, zresolved = zone
                    if not zresolved:
                        unresolved += 1          # unknown membership
                    elif not zmembers:
                        empty_zones += 1         # empty zone: matches nothing
                    else:
                        z_lv = [self._iface_levels(fw_id, m) for m in zmembers]
                        for lv in z_lv:
                            if lv:
                                levels |= lv
                        if any(lv is None for lv in z_lv):
                            unresolved += 1      # a member without a level
                            if any(self.is_known_unlabelled(fw_id, m) for m in zmembers):
                                self.unlabelled_hits.add(rule.id)
                    continue
                lv = self.exact_by_fw.get(fw_id, {}).get(tok.casefold()) if fw_id is not None else None
                if lv:
                    levels |= lv
                    continue
                link = self.link_levels.get(fw_id, {}).get(tok.casefold()) if fw_id is not None else None
                if link:
                    levels |= link                       # VD-03: the peer VDOM's levels
                    continue
                lv = self._iface_levels(fw_id, tok)      # alias / zone_label (or site-wide)
                if lv:
                    levels |= lv
                    continue
                found = False
                for member in self._zone_members(rule, fw_id, tok):
                    m_lv = self._iface_levels(fw_id, member)
                    if m_lv:
                        levels |= m_lv
                        found = True
                if not found:
                    unresolved += 1
                    if self.is_known_unlabelled(fw_id, tok):
                        self.unlabelled_hits.add(rule.id)   # MP-09: known, no level
            if use_boundary and tokens and not levels and unresolved == len(tokens):
                # MP-15: nothing labelled on this firewall - the boundary
                # places the side; an interface's recorded side picks the end
                lo, hi = boundary
                for tok in tokens:
                    sd = self.side_by_fw.get(fw_id, {}).get(tok.casefold())
                    levels |= {lo} if sd == "inside" else {hi} if sd == "outside" else {lo, hi}
                unresolved = 0
                self.boundary_used.add(rule.id)
            self.tokens_unresolved += unresolved
            if unresolved:
                log.debug(
                    "Phase 6 zone resolver: rule id=%s fw=%s zone=%r — %d/%d "
                    "token(s) unresolved, levels=%s",
                    rule.id, fw_id, zone_value, unresolved, len(tokens), sorted(levels),
                )
            if tokens and not levels and not unresolved and empty_zones == len(tokens):
                # B-07: only empty zones - the side matches no interface; it
                # is fully evaluated (and can never violate anything).
                self.sides_resolved += 1
                return set(), True
        if levels:
            self.sides_resolved += 1
        else:
            self.sides_unresolved += 1
        return levels, bool(levels) and not unresolved and zone_value is not None


def _rule_zone_purdue(db: DBSession) -> _RuleZoneResolver:
    """Build the per-run zone→Purdue-level resolver (see _RuleZoneResolver)."""
    return _RuleZoneResolver(db)


def rules_not_judged(db: DBSession) -> dict:
    """MP-24: per firewall, the enabled permit policies whose src or dst side
    the rule twins could not resolve to Purdue levels (A-09: such a rule is
    not judged by rule_it_ot_bypass, rule_mgmt_wrong_zone, ... and its
    absence from the findings is not a pass), with why.  Site-scoped like
    the reviews.  Returns {"firewalls": [...], "total_rules", "not_judged"}."""
    resolver = _RuleZoneResolver(db)
    per: dict = {}
    total = 0
    for r in _permit_rules(db):
        if resolver.matches_nothing(r) or resolver.names_link(r):
            continue
        total += 1
        key = (r.firewall_id, r.device_name)
        entry = per.setdefault(key, {"firewall_id": r.firewall_id, "firewall": r.device_name,
                                     "rules_total": 0, "not_judged": 0, "policies": [],
                                     "reasons": {}, "_seen": set()})
        entry["rules_total"] += 1
        pid = r.policy_id or f"#{r.id}"
        if pid in entry["_seen"]:
            continue
        reasons = []
        for attr in ("src_zone", "dst_zone"):
            val = getattr(r, attr)
            levels, complete = resolver.resolve_checked(r, val)
            if complete:
                continue
            if val is None:
                reasons.append(f"{attr}: not set")
            elif resolver.names_unlabelled([r]):
                reasons.append(f"{attr} '{val}': interface without a Purdue level")
            elif not levels:
                reasons.append(f"{attr} '{val}': no interface or zone of that name")
            else:
                reasons.append(f"{attr} '{val}': part of the zone unresolved")
        if not reasons:
            continue
        entry["_seen"].add(pid)
        entry["not_judged"] += 1
        if len(entry["policies"]) < 20:
            entry["policies"].append({"policy_id": pid, "name": r.policy_name, "reasons": reasons})
        for why in reasons:
            attr = why.split(":", 1)[0].split(" ", 1)[0]
            k = attr + (": not set" if why.endswith("not set")
                        else ": unlabelled interface" if "without a Purdue level" in why
                        else ": unknown name" if "no interface or zone" in why
                        else ": partly resolved")
            entry["reasons"][k] = entry["reasons"].get(k, 0) + 1
    out = []
    for e in per.values():
        e.pop("_seen", None)
        if e["not_judged"]:
            out.append(e)
    out.sort(key=lambda e: (-e["not_judged"], e["firewall"] or ""))
    return {"firewalls": out, "total_rules": total,
            "not_judged": sum(e["not_judged"] for e in out)}


class _TrafficIndex:
    """Observed-traffic index for Phase-6 traffic confirmation (T3-18).

    Built with ONE grouped query per run: the DISTINCT set of
    (src host purdue_level, dst host purdue_level, transport, dst_port,
    src host ip, dst host ip) tuples present in NetworkSession (hosts without
    a Purdue level can never confirm and are excluded). Rule port ranges and
    (F-18) concrete rule src/dst addresses are then tested against it in
    Python, replacing the previous one EXISTS query per matching rule.
    Semantics are identical to the per-rule query in _rule_traffic_confirmed.
    """

    def __init__(self, db: DBSession):
        src_h = aliased(Host)
        dst_h = aliased(Host)
        rows = (
            db.query(src_h.purdue_level, dst_h.purdue_level,
                     NetworkSession.transport, NetworkSession.dst_port,
                     src_h.ip, dst_h.ip, NetworkSession.carrier_mac)
            .join(src_h, NetworkSession.src_host_id == src_h.id)
            .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
            .filter(src_h.purdue_level.isnot(None), dst_h.purdue_level.isnot(None))
            .distinct()
            .all()
        )
        acc: dict[tuple[int, int], dict[str, list]] = {}
        # F-18: per level pair, the concrete flows (transport, dst_port,
        # src ip, dst ip) for rules whose src/dst addresses are concrete.
        self._flows: dict[tuple[int, int], list[tuple]] = {}
        seen_flows: set = set()
        # LS-03: the device (firewall / routing switch) whose router MAC the
        # session's frames carried - a rule of ANOTHER device is not
        # confirmed by it.
        rmacs = {}
        if any(r[6] for r in rows):
            try:
                from app.parsers.l3_switch import router_macs as _router_macs
                rmacs = _router_macs(db)
            except Exception:                                # noqa: BLE001
                log.warning("router MAC lookup failed", exc_info=True)
        self.has_carriers = bool(rmacs)
        for s, d, t, p, sip, dip, cmac in rows:
            slot = acc.setdefault((s, d), {}).setdefault(t, [set(), False])
            if p is None:
                slot[1] = True
            else:
                slot[0].add(int(p))
            flow = (s, d, t, None if p is None else int(p), _ip_key(sip), _ip_key(dip),
                    rmacs.get(cmac) if cmac else None)
            if flow not in seen_flows:
                seen_flows.add(flow)
                self._flows.setdefault((s, d), []).append(flow[2:])
        # (src_lvl, dst_lvl) -> transport -> (sorted ports, port set, has NULL-port session)
        self._by_pair: dict[tuple[int, int], dict[str, tuple[list[int], set[int], bool]]] = {
            pair: {t: (sorted(ps), ps, has_null) for t, (ps, has_null) in by_t.items()}
            for pair, by_t in acc.items()
        }
        self.tuples = len(rows)

    def confirmed(
        self,
        src_levels: set[int],
        dst_levels: set[int],
        ports: Optional[list[int]] = None,
        port_ranges: Optional[list[tuple[int, int]]] = None,
        transport: Optional[str] = None,
        src_addr=None,
        dst_addr=None,
        firewall_id=None,
    ) -> bool:
        if not src_levels or not dst_levels:
            return False
        if ports is not None and not ports:
            return False
        if _addr_concrete(src_addr) or _addr_concrete(dst_addr):
            return self._confirmed_scoped(src_levels, dst_levels, ports, port_ranges,
                                          transport, src_addr, dst_addr, firewall_id)
        if firewall_id is not None and self.has_carriers:
            # LS-03: the cheap level / port lookup first; only a hit is
            # re-checked against the carriers of the matching flows.
            if not self.confirmed(src_levels, dst_levels, ports, port_ranges, transport):
                return False
            return self._confirmed_scoped(src_levels, dst_levels, ports, port_ranges,
                                          transport, src_addr, dst_addr, firewall_id)
        ranges = (
            None if port_ranges is None or list(port_ranges) == list(_PORT_ANY)
            else sorted(port_ranges)
        )
        wanted = sorted(set(ports)) if ports is not None else None
        for s in src_levels:
            for d in dst_levels:
                by_t = self._by_pair.get((s, d))
                if not by_t:
                    continue
                for t, (plist, pset, has_null) in by_t.items():
                    if transport in ("tcp", "udp") and t != transport:
                        continue
                    if wanted is None and ranges is None:
                        if plist or has_null:
                            return True
                    elif wanted is not None:
                        for p in wanted:
                            if p in pset and (
                                ranges is None or any(lo <= p <= hi for lo, hi in ranges)
                            ):
                                return True
                    else:
                        for lo, hi in ranges:
                            i = bisect.bisect_left(plist, lo)
                            if i < len(plist) and plist[i] <= hi:
                                return True
        return False

    def _confirmed_scoped(self, src_levels, dst_levels, ports, port_ranges,
                          transport, src_addr, dst_addr, firewall_id=None) -> bool:
        """F-18: like confirmed(), but the session's src/dst host IPs must
        also fall inside the rule's concrete src/dst addresses."""
        ranges = (
            None if port_ranges is None or list(port_ranges) == list(_PORT_ANY)
            else list(port_ranges)
        )
        wanted = set(ports) if ports is not None else None
        for s in src_levels:
            for d in dst_levels:
                for t, p, sip, dip, cfw in self._flows.get((s, d), ()):
                    if transport in ("tcp", "udp") and t != transport:
                        continue
                    if firewall_id is not None and cfw is not None and cfw != firewall_id:
                        continue        # LS-03: carried by another device
                    if wanted is not None and p not in wanted:
                        continue
                    if ranges is not None and (p is None or not any(lo <= p <= hi for lo, hi in ranges)):
                        continue
                    if _ip_key_in(sip, src_addr) and _ip_key_in(dip, dst_addr):
                        return True
        return False


def _ip_key(ip: Optional[str]) -> Optional[tuple[int, int]]:
    """(version, int) of an IP string, None if absent/unparseable."""
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    return a.version, int(a)


def _addr_concrete(spec) -> bool:
    """True for a concrete address spec (ip_network / AddrRange) - i.e.
    not None, "any" or Unresolved (those leave the side level-scoped only)."""
    from app.parsers import rule_match as rm
    return spec is not None and spec != rm.ANY and not isinstance(spec, rm.Unresolved)


def _ip_key_in(key: Optional[tuple[int, int]], spec) -> bool:
    if not _addr_concrete(spec):
        return True
    if key is None:
        return False
    from app.parsers import rule_match as rm
    v, lo, hi = rm.addr_bounds(spec)
    return key[0] == v and lo <= key[1] <= hi


def _rule_addr_specs(rule) -> tuple:
    """F-18: parsed (src, dst) address specs of a FirewallRule row
    (rule_match.parse_address: ANY / ip_network / AddrRange / Unresolved)."""
    from app.parsers import rule_match as rm
    if rule is None:
        return None, None
    return rm.parse_address(rule.src), rm.parse_address(rule.dst)


def _rule_traffic_confirmed(
    db: DBSession,
    src_levels: set[int],
    dst_levels: set[int],
    ports: Optional[list[int]] = None,
    port_ranges: Optional[list[tuple[int, int]]] = None,
    transport: Optional[str] = None,
    _traffic: Optional[_TrafficIndex] = None,
    src_addr=None,
    dst_addr=None,
) -> bool:
    """True when at least one NetworkSession matches the rule (T1-14):
    src host Purdue level in src_levels AND dst host level in dst_levels
    AND (transport matches, when the rule is tcp/udp) AND dst_port in
    `ports` / within `port_ranges` (either may be omitted; a (0, 65535)
    range means any port).

    With `_traffic` (a per-run _TrafficIndex, T3-18) this is a pure Python
    lookup; without it, one EXISTS query per call (standalone use).

    F-18: src_addr / dst_addr (rule_match address specs, see
    _rule_addr_specs) additionally require the session's src / dst host IP
    to fall inside the rule's address when that address is concrete (not
    any / unresolved).

    Conservative: an unresolved (empty) side never confirms, and a call
    with ports == [] (nothing matched) never confirms.
    """
    if not src_levels or not dst_levels:
        return False
    if ports is not None and not ports:
        return False
    if _traffic is not None:
        return _traffic.confirmed(src_levels, dst_levels, ports=ports,
                                  port_ranges=port_ranges, transport=transport,
                                  src_addr=src_addr, dst_addr=dst_addr)
    scoped = _addr_concrete(src_addr) or _addr_concrete(dst_addr)
    src_h = aliased(Host)
    dst_h = aliased(Host)
    q = (
        db.query(src_h.ip, dst_h.ip).select_from(NetworkSession) if scoped
        else db.query(NetworkSession.id)
    )
    q = (
        q
        .join(src_h, NetworkSession.src_host_id == src_h.id)
        .join(dst_h, NetworkSession.dst_host_id == dst_h.id)
        .filter(src_h.purdue_level.in_(sorted(src_levels)))
        .filter(dst_h.purdue_level.in_(sorted(dst_levels)))
    )
    if transport in ("tcp", "udp"):
        q = q.filter(NetworkSession.transport == transport)
    if ports is not None:
        q = q.filter(NetworkSession.dst_port.in_(sorted(set(ports))))
    if port_ranges is not None and list(port_ranges) != list(_PORT_ANY):
        q = q.filter(or_(*[
            NetworkSession.dst_port.between(lo, hi) for lo, hi in port_ranges
        ]))
    if scoped:
        return any(
            _ip_key_in(_ip_key(sip), src_addr) and _ip_key_in(_ip_key(dip), dst_addr)
            for sip, dip in q.distinct()
        )
    return bool(db.query(q.exists()).scalar())


def _rule_base_evidence(rule: FirewallRule, src_levels: set[int], dst_levels: set[int]) -> dict:
    # Per-row evidence (legacy shape, pre-T3-19). Kept for callers outside the
    # twin checks; the twins now use _group_evidence.
    return {
        "firewall_rule_id": rule.id,
        "firewall_id":      rule.firewall_id,
        "policy_id":        rule.policy_id,
        "device_name":      rule.device_name,
        "src_zone":         rule.src_zone,
        "dst_zone":         rule.dst_zone,
        "src":              rule.src,
        "dst":              rule.dst,
        "protocol":         rule.protocol,
        "dst_port":         rule.dst_port,
        "src_purdue_levels": sorted(src_levels),
        "dst_purdue_levels": sorted(dst_levels),
    }


def _permit_rules(db: DBSession, *required_zone_cols):
    """Enabled permit rules for the rule-twin checks.  Implicit permits (ASA
    security levels, L3 switch routing - policy_id ``implicit:``) are left to
    their own checks (rule_implicit_permit, switch_routes_between_zones)."""
    q = db.query(FirewallRule).filter(
        FirewallRule.enabled.is_(True),
        FirewallRule.action.in_(("permit", "allow", "accept")),
        ~FirewallRule.policy_id.like("implicit:%") | FirewallRule.policy_id.is_(None),
    )
    for col in required_zone_cols:
        q = q.filter(col.isnot(None))
    return q.order_by(FirewallRule.id).all()


def _describe_matches(matched: dict[int, str]) -> str:
    return ", ".join(f"{name} ({p})" for p, name in matched.items())


_TRAFFIC_OBSERVED = (
    "Matching traffic observed: NetworkSession data shows sessions between hosts "
    "at the rule's Purdue levels (inside the rule's src/dst addresses where those "
    "are concrete) on {ports}."
)


# --------------------------------------------------------------------------
# Phase-6 per-run context and logical-rule grouping (T3-18 / T3-19 / T3-20)
# --------------------------------------------------------------------------

def _rule_group_key(rule: FirewallRule) -> tuple:
    """Logical-rule identity shared with review_disabled_rules:
    (firewall_id, firewall_device_id, device_name, policy_id or sha1(raw_line))."""
    return _disabled_rule_group_key(rule)


def _group_rule_key(key: tuple) -> str:
    """Stable string identity of a logical rule (dedup field "rule_key").
    Survives config re-ingest: it never contains a FirewallRule row id
    unless the row has neither policy_id nor raw_line."""
    _fw_id, fw_dev_id, _device, ident = key
    return str(ident) if fw_dev_id is None else f"{ident}@fd{fw_dev_id}"


def _uniq_join(values) -> Optional[str]:
    vals = list(values)
    if all(v is None for v in vals):
        return None
    return ", ".join(dict.fromkeys("any" if v is None else str(v) for v in vals))


def _group_label(rows: list) -> str:
    first = rows[0]
    if first.policy_id:
        label = f"policy {first.policy_id}" + (
            f" (vdom {first.vdom})" if getattr(first, "vdom", None) is not None else "")
    else:
        label = (first.raw_line or f"rule {first.id}").strip().splitlines()[0][:80]
    return label + (f" on {first.device_name}" if first.device_name else "")


def _group_evidence(key: tuple, rows: list, src_levels: set[int], dst_levels: set[int]) -> dict:
    """Display evidence for one logical rule. Only the fields returned by
    _group_dedup_evidence form the dedup identity; everything here (row ids,
    zones, raw ports, levels, related_checks) is informational."""
    first = rows[0]
    return {
        "rule_key":          _group_rule_key(key),
        "firewall_rule_id":  first.id,                 # first matching row (link target)
        "firewall_rule_ids": [r.id for r in rows],     # every expanded row that matched
        "expanded_rows":     len(rows),
        "firewall_id":       first.firewall_id,
        "firewall_device_id": first.firewall_device_id,
        "policy_id":         first.policy_id,
        "vdom":              getattr(first, "vdom", None),
        "policy_name":       first.policy_name,
        "device_name":       first.device_name,
        "src_zone":          _uniq_join(r.src_zone for r in rows),
        "dst_zone":          _uniq_join(r.dst_zone for r in rows),
        "src":               _uniq_join(r.src for r in rows),
        "dst":               _uniq_join(r.dst for r in rows),
        "protocol":          _uniq_join(r.protocol for r in rows),
        "dst_port":          _uniq_join(r.dst_port for r in rows),
        "src_purdue_levels": sorted(src_levels),
        "dst_purdue_levels": sorted(dst_levels),
        "related_checks":    [],
    }


def _group_dedup_evidence(key: tuple, rows: list) -> dict:
    """Dedup identity of a twin finding: the logical rule, not its rows."""
    fw_id, _fw_dev_id, device, _ident = key
    return {
        "rule_key":    _group_rule_key(key),
        "firewall_id": fw_id,
        "device_name": device,
        "policy_id":   rows[0].policy_id,
    }


def _merge_ranges(ranges) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def _collect_hits(rows: list, row_eval) -> dict:
    """Evaluate row_eval(rule) for every row and merge the non-None results
    per logical rule: sets are unioned, dicts merged (sorted by key), lists
    concatenated, bools OR-ed. Each merged hit also carries "rows" (the
    matching rows, id order). Groups are ordered by their first matching row."""
    hits: dict[tuple, dict] = {}
    for rule in rows:
        h = row_eval(rule)
        if h is None:
            continue
        acc = hits.setdefault(_rule_group_key(rule), {"rows": []})
        acc["rows"].append(rule)
        for k, v in h.items():
            if isinstance(v, bool):
                acc[k] = acc.get(k, False) or v
            elif isinstance(v, set):
                acc.setdefault(k, set()).update(v)
            elif isinstance(v, dict):
                acc.setdefault(k, {}).update(v)
            elif isinstance(v, list):
                acc.setdefault(k, []).extend(v)
            else:
                acc.setdefault(k, v)
    for acc in hits.values():
        for k, v in list(acc.items()):
            if isinstance(v, dict):
                acc[k] = dict(sorted(v.items()))
    return hits


class _TwinRunContext:
    """Per-run state shared by the Phase-6 twin checks (T3-18/19/20).

    Holds the zone resolver, the lazily built _TrafficIndex, the enabled
    permit rows (one query per run instead of one per check), a per-check
    cache of open findings (one query per check instead of one _find_open
    per finding), the legacy per-row findings to supersede, and which checks
    fired for which logical rule (for evidence "related_checks").
    A standalone call to a twin check builds its own context.
    """

    def __init__(self, db: DBSession, resolver: Optional[_RuleZoneResolver] = None):
        self.db = db
        self.resolver = resolver if resolver is not None else _rule_zone_purdue(db)
        self._traffic: Optional[_TrafficIndex] = None
        self._rows: Optional[list] = None
        self._vpn_rule_ids: set = set()
        self._open: dict[str, dict[str, Finding]] = {}
        self._legacy: dict[str, dict] = {}
        self.fired: dict[str, dict[tuple, Finding]] = {}
        self._addr_specs: dict[int, tuple] = {}
        self._mctx = None

    @property
    def mctx(self):
        """The site's management / engineering / service declarations (built once per run)."""
        if self._mctx is None:
            from app.parsers.mgmt_networks import build_context as _mgmt_ctx
            self._mctx = _mgmt_ctx(self.db)
        return self._mctx

    @property
    def traffic(self) -> _TrafficIndex:
        if self._traffic is None:
            self._traffic = _TrafficIndex(self.db)
        return self._traffic

    def confirmed(self, src_levels, dst_levels, rule=None, **kw) -> bool:
        """Traffic confirmation via the per-run index. With `rule` (F-18) the
        session's host IPs must also fall inside the rule's concrete src/dst
        addresses (parsed once per row)."""
        if rule is not None:
            specs = self._addr_specs.get(rule.id)
            if specs is None:
                specs = self._addr_specs[rule.id] = _rule_addr_specs(rule)
            kw.setdefault("src_addr", specs[0])
            kw.setdefault("dst_addr", specs[1])
            if getattr(rule, "firewall_id", None) is not None:
                return self.traffic.confirmed(src_levels, dst_levels, firewall_id=rule.firewall_id, **kw)
        return _rule_traffic_confirmed(self.db, src_levels, dst_levels,
                                       _traffic=self.traffic, **kw)

    def permit_rows(self, *required_attrs: str, skip_vpn: bool = False) -> list:
        """Enabled permit rows (disabled rows are excluded - T1 rule), id order.
        ``skip_vpn`` (MP-23): leave out VPN-sourced policies - the level
        twins (IT/OT bypass, management zone, OT->IT dependency) do, because
        vpn_direct_to_ot already judges those policies (critical); the
        protocol twins (insecure protocol, cleartext credentials, conduit
        drift) still see them - a cleartext FTP over the VPN is its own
        finding."""
        if self._rows is None:
            # B-07: a policy whose side names only empty zones matches nothing.
            # VD-03: a policy with an inter-VDOM link on one side is one leg
            # of a crossing the OTHER VDOM also judges - the chain reviews
            # (series model) raise on the whole path; the twins skip the leg.
            self._rows = [r for r in _permit_rules(self.db)
                          if not self.resolver.matches_nothing(r) and not self.resolver.names_link(r)]
            try:
                from app.parsers.vpn import VpnContext
                vctx = VpnContext.build(self.db)
                self._vpn_rule_ids = {r.id for r in self._rows if vctx.is_vpn_rule(r)}
            except Exception:  # never let the VPN model break the twins
                log.warning("VPN context failed; twins judge VPN policies too", exc_info=True)
                self._vpn_rule_ids = set()
        rows = self._rows
        if skip_vpn and self._vpn_rule_ids:
            rows = [r for r in rows if r.id not in self._vpn_rule_ids]
        return [r for r in rows if all(getattr(r, a) is not None for a in required_attrs)]

    def open_cache(self, check_name: str) -> dict[str, Finding]:
        cache = self._open.get(check_name)
        if cache is None:
            cache = {
                f.source_ref: f for f in sorted(
                    self.db.query(Finding).filter(
                        Finding.check_name == check_name,
                        Finding.status.in_(_ACTIVE_STATUSES),
                        Finding.source_ref.isnot(None),
                    ),
                    key=lambda f: (f.status == "open", -f.id),  # open wins on duplicates
                )
            }
            self._open[check_name] = cache
        return cache

    def _legacy_index(self, check_name: str) -> dict:
        idx = self._legacy.get(check_name)
        if idx is None:
            by_row: dict[int, list[Finding]] = {}
            by_policy: dict[tuple, list[Finding]] = {}
            for f in self.open_cache(check_name).values():
                d = f.detail if isinstance(f.detail, dict) else {}
                if "rule_key" in d:
                    continue  # already per-logical-rule
                if d.get("firewall_rule_id") is not None:
                    by_row.setdefault(d["firewall_rule_id"], []).append(f)
                if d.get("policy_id") is not None:
                    by_policy.setdefault((d.get("device_name"), str(d["policy_id"])), []).append(f)
            idx = self._legacy[check_name] = {"by_row": by_row, "by_policy": by_policy}
        return idx

    def record(self, check_name: str, key: tuple, rows: list, target: Optional[Finding]) -> None:
        """Note that check_name fired for logical rule `key` (open finding
        `target`) and close open pre-T3-19 per-row findings it supersedes."""
        if target is None:
            return
        self.fired.setdefault(check_name, {})[key] = target
        idx = self._legacy_index(check_name)
        cands: dict[int, Finding] = {}
        for r in rows:
            for f in idx["by_row"].get(r.id, ()):
                cands[id(f)] = f
        first = rows[0]
        if first.policy_id is not None:
            for f in idx["by_policy"].get((first.device_name, str(first.policy_id)), ()):
                fw = (f.detail or {}).get("firewall_id")
                if fw is None or first.firewall_id is None or fw == first.firewall_id:
                    cands[id(f)] = f
        if not cands:
            return
        cache = self.open_cache(check_name)
        now = datetime.now(timezone.utc)
        for f in cands.values():
            if f is target or f.status != "open":
                continue
            f.status = "closed"
            f.closed_at = now
            note = (f"Superseded by finding #{target.id} (one finding per logical "
                    f"firewall rule, T3-19).")
            f.notes = ((f.notes + " | ") if f.notes else "")[:2048 - len(note)] + note
            if cache.get(f.source_ref) is f:
                del cache[f.source_ref]
            log.info("Phase 6: closed legacy per-row finding id=%s (%s) superseded by id=%s",
                     f.id, check_name, target.id)

    def unevaluated(self, rule: FirewallRule) -> None:
        """A-09: the running twin check could not fully evaluate `rule`, so
        its logical rule's open finding must survive auto-resolve."""
        fw_id, _fd, device, _ident = key = _rule_group_key(rule)
        _mark_rule_unevaluated(self.db, _group_rule_key(key), fw_id, device)

    def levels(self, rule: FirewallRule, zone_value: Optional[str]) -> set[int]:
        """resolver.resolve + A-09 bookkeeping: an incompletely resolved
        side marks the rule as not fully evaluated."""
        levels, complete = self.resolver.resolve_checked(rule, zone_value)
        if not complete:
            self.unevaluated(rule)
        return levels

    def ports(self, rule: FirewallRule) -> Optional[list[tuple[int, int]]]:
        """_rule_port_ranges + A-09: unparseable dst_port (not ICMP / port-0,
        which are legitimately port-less) marks the rule not evaluated."""
        ranges = _rule_port_ranges(rule)
        if ranges is None and not _is_icmp_rule(rule) and _parse_rule_ports(rule.dst_port) is None:
            self.unevaluated(rule)
        return ranges

    def permit_rows_tracked(self, *required_attrs: str, skip_vpn: bool = False) -> list:
        """permit_rows(*required_attrs), marking every enabled permit row
        that lacks a required zone (NULL = unknown, not "any") as not
        evaluated (A-09)."""
        rows = self.permit_rows(skip_vpn=skip_vpn)
        out = []
        for r in rows:
            if all(getattr(r, a) is not None for a in required_attrs):
                out.append(r)
            else:
                self.unevaluated(r)
        return out

    def discard(self, check_name: str) -> None:
        """Forget state of a check whose savepoint was rolled back."""
        self._open.pop(check_name, None)
        self._legacy.pop(check_name, None)
        self.fired.pop(check_name, None)

    def finalize_related(self) -> int:
        """Set evidence "related_checks" (T3-20) on every twin finding whose
        logical rule tripped other twin checks in this run. Returns the
        number of findings updated."""
        by_key: dict[tuple, dict[str, Finding]] = {}
        for check, groups in self.fired.items():
            for key, f in groups.items():
                by_key.setdefault(key, {})[check] = f
        updated = 0
        for checks in by_key.values():
            for check, f in checks.items():
                related = sorted(c for c in checks if c != check)
                d = dict(f.detail or {})
                if d.get("related_checks") != related:
                    d["related_checks"] = related
                    f.detail = d  # reassign: plain JSON column, no mutation tracking
                    updated += 1
        return updated


def _twin_ctx(db: DBSession, resolver: Optional[_RuleZoneResolver],
              ctx: Optional[_TwinRunContext]) -> _TwinRunContext:
    if ctx is not None:
        return ctx
    return _TwinRunContext(db, resolver)


def _emit_twin(
    ctx: _TwinRunContext,
    check_name: str,
    key: tuple,
    hit: dict,
    title: str,
    detail_text: str,
    severity: str,
    extra: dict,
    dedup_extra: Optional[dict] = None,
) -> Optional[Finding]:
    """One finding per logical rule per twin check (T3-19)."""
    rows = hit["rows"]
    evidence = {**_group_evidence(key, rows, hit["src_levels"], hit["dst_levels"]), **extra}
    resolver = getattr(ctx, "resolver", None)
    if resolver is not None and resolver.from_boundary(rows):
        # MP-15: levels came from the upload boundary, not interface labels -
        # the direction is unverified, so one severity step lower and said so
        evidence["level_source"] = "boundary"
        severity = _SEVERITY_STEP_DOWN.get(severity, severity)
        title = (title + " [levels from upload boundary, direction unverified]")[:512]
        detail_text += (" The firewall's interfaces carry no Purdue levels; the levels above "
                        "come from the boundary given at upload, so the direction of this rule "
                        "is unverified. Label the interfaces to confirm.")
    else:
        evidence["level_source"] = "labels"
    if resolver is not None and resolver.names_unlabelled(rows):
        evidence["names_unlabelled_interface"] = True       # MP-09
    if resolver is not None:
        title, detail_text = _label_multi_interface_sides(resolver, rows, title, detail_text, evidence)
    dedup_ev = _group_dedup_evidence(key, rows)
    if dedup_extra:
        dedup_ev.update(dedup_extra)
    cache = ctx.open_cache(check_name)
    f = _make_finding(
        ctx.db, check_name, title[:512], detail_text, evidence,
        firewall_rule_id=rows[0].id, device_name=rows[0].device_name,
        severity=severity, dedup_evidence=dedup_ev, _open_cache=cache,
    )
    target = f if f is not None else cache.get(_dedup_key(check_name, dedup_ev))
    ctx.record(check_name, key, rows, target)
    return f


def _label_multi_interface_sides(resolver, rows: list, title: str, text: str, evidence: dict):
    """SF-6: a policy side naming several interfaces ("port1,port2") is
    printed per interface with its level - "port1 (L1) + port2 (L3)" - not as
    one zone with one level; evidence gets ``src_zone_parts`` /
    ``dst_zone_parts``."""
    first = rows[0]
    for attr in ("src_zone", "dst_zone"):
        value = getattr(first, attr, None)
        toks = _fz.zone_list(value)
        if len(toks) < 2:
            continue
        parts = []
        for t in toks:
            lv = resolver.resolve(first, t)
            parts.append({"name": t, "levels": sorted_levels(lv) if lv else []})
        parts.sort(key=lambda p: (not p["levels"], float(p["levels"][0]) if p["levels"] else 0, p["name"]))
        label = " + ".join(f"{p['name']} ({_fmt_levels(p['levels']) if p['levels'] else 'no level'})" for p in parts)
        evidence[attr + "_parts"] = [{"name": p["name"], "levels": [float(x) for x in p["levels"]]} for p in parts]
        pat = re.compile(r"zone '" + re.escape(value) + r"' \((?:Purdue )?L[^)]*\)")
        title = pat.sub("zones " + label, title)
        text = pat.sub("zones " + label, text)
        for old in (f"'{value}'", value):
            title = title.replace(old, label)
            text = text.replace(old, label)
    return title, text


def _rows_phrase(rows: list) -> str:
    return (f" (logical rule expanded to {len(rows)} rows: ids "
            f"{', '.join(str(r.id) for r in rows[:10])}{'…' if len(rows) > 10 else ''})"
            if len(rows) > 1 else "")


def review_rule_cleartext_protocols(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_cleartext_protocols (SR 7.7, SR 4.1 / 3.5).

    Flags permit rules whose dst_port ranges overlap a cleartext protocol
    port (FTP, Telnet, HTTP, SNMP v1/v2, TFTP, …) across a zone boundary
    (src_zone ≠ dst_zone, or either side "any"). Fires without PCAP data; one
    finding per LOGICAL rule (T3-19) listing every matched port. Cleartext
    management protocols (Telnet, SNMP) are also reported by
    review_rule_mgmt_protocols.

    Severity escalates "medium" → "critical" when NetworkSession traffic
    between hosts at the rule's resolved src/dst levels is observed on one of
    the matched ports.
    """
    return _review_rule_zone_crossing_ports(
        db, _resolver, _ctx, "rule_cleartext_protocol", _CLEARTEXT_PROTO_PORTS)


def review_rule_mgmt_protocols(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_mgmt_protocols
    (SR 1.3, SR 5.1 RE1, SR 4.1 / 5.1, 5.2).

    Flags permit rules whose dst_port ranges overlap a management protocol
    port (SSH, Telnet, SNMP, RDP, VNC, WinRM, HTTPS-alt) across a zone
    boundary, whatever the levels or the declared management networks
    (review_rule_mgmt_wrong_zone judges those). One finding per LOGICAL rule
    (T3-19). Cleartext management protocols are also reported by
    review_rule_cleartext_protocols.

    Severity: "medium"; "high" when a cleartext management protocol (Telnet,
    SNMP v1/v2c) is permitted; "critical" when matching traffic is observed.
    """
    return _review_rule_zone_crossing_ports(
        db, _resolver, _ctx, "rule_mgmt_protocol", _MGMT_PROTO_PORTS)


def _review_rule_zone_crossing_ports(db, _resolver, _ctx, check: str,
                                     port_map: dict[int, str]) -> list:
    """Shared body of review_rule_cleartext_protocols / review_rule_mgmt_protocols:
    permit rules across a zone boundary whose ports overlap ``port_map``."""
    mgmt = check == "rule_mgmt_protocol"
    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        wildcard = any(
            t.casefold() in _RuleZoneResolver._ANY
            for t in _split_zone_value(rule.src_zone) + _split_zone_value(rule.dst_zone)
        )
        if rule.src_zone == rule.dst_zone and not wildcard:
            return None  # intra-zone cleartext is a separate posture issue
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        matched = _ports_matched(ranges, port_map, rule)
        if not matched:
            return None
        src_levels = ctx.resolver.resolve(rule, rule.src_zone)
        dst_levels = ctx.resolver.resolve(rule, rule.dst_zone)
        return {
            "src_levels": src_levels, "dst_levels": dst_levels, "matched": matched,
            "confirmed": ctx.confirmed(src_levels, dst_levels, ports=list(matched),
                                       transport=_rule_transport(rule), rule=rule),
        }

    alerts = []
    hits = _collect_hits(ctx.permit_rows_tracked("src_zone", "dst_zone"), row_eval)
    for key, hit in hits.items():
        rows, matched, confirmed = hit["rows"], hit["matched"], hit["confirmed"]
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        cleartext_mgmt = sorted(p for p in matched if p in _CLEARTEXT_MGMT_PORTS)
        if confirmed:
            severity = "critical"
        elif mgmt and cleartext_mgmt:
            severity = "high"
        else:
            severity = "medium"
        names = _describe_matches(matched)
        services = ", ".join(dict.fromkeys(matched.values()))
        if mgmt:
            title = f"Management protocol across zones: {services} permitted "
            why = ("Management access should come only from a dedicated management "
                   "zone, over an encrypted protocol (SR 1.3, SR 5.1 RE1, SR 4.1). "
                   + (f"{', '.join(dict.fromkeys(matched[p] for p in cleartext_mgmt))} "
                      f"{'is' if len(cleartext_mgmt) == 1 else 'are'} cleartext: "
                      f"credentials and commands can be read on the wire. "
                      if cleartext_mgmt else ""))
        else:
            title = f"Cleartext protocol across zones: {services} permitted "
            why = ("Cleartext protocols expose credentials and session data on the wire "
                   "and violate SR 7.7 / SR 4.1 (insecure services blocked or justified). ")
        alerts.append(_emit_twin(
            ctx, check, key, hit,
            title=(
                title + f"{ev['src_zone']} → {ev['dst_zone']} ({_group_label(rows)})"
                + (" [matching traffic observed]" if confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits {names} "
                f"(rule ports '{ev['dst_port'] or 'any'}') from zone '{ev['src_zone']}' to "
                f"zone '{ev['dst_zone']}'. " + why
                + (
                    _TRAFFIC_OBSERVED.format(ports=names)
                    if confirmed else
                    "No matching traffic observed yet; the rule represents a standing "
                    "policy risk regardless of whether traffic is currently flowing."
                )
            ),
            severity=severity,
            extra={
                "matched_ports": list(matched),
                "matched_services": list(matched.values()),
                "confirmed_by_traffic": confirmed,
                **({"cleartext_mgmt_ports": cleartext_mgmt} if mgmt else {}),
            },
        ))
    return [a for a in alerts if a]


def review_rule_cleartext_creds(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_cleartext_credentials (SR 4.1, SR 3.1 / 8.3).

    Flags permit rules whose ports overlap cleartext credential protocols
    (FTP, Telnet, HTTP, TFTP, POP3, IMAP, SMTP) into a destination zone that
    includes a Purdue level ≤ 2 (OT/control network). One finding per
    logical rule (T3-19).

    Severity escalates "high" → "critical" when traffic from the rule's
    source levels to an OT-level (≤ 2) destination is observed on a matched
    port.
    """
    _CLEARTEXT_CRED_PORTS: dict[int, str] = {
        21: "FTP", 23: "Telnet", 80: "HTTP",
        69: "TFTP", 110: "POP3", 143: "IMAP", 25: "SMTP",
    }
    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        matched = _ports_matched(ranges, _CLEARTEXT_CRED_PORTS, rule)
        if not matched:
            return None
        dst_levels = ctx.levels(rule, rule.dst_zone)
        ot_dst = {l for l in dst_levels if is_ot(l)}
        if not ot_dst:
            return None  # destination is not a known OT zone
        src_levels = ctx.resolver.resolve(rule, rule.src_zone)
        return {
            "src_levels": src_levels, "dst_levels": dst_levels, "ot_dst": ot_dst,
            "matched": matched,
            "confirmed": ctx.confirmed(src_levels, ot_dst, ports=list(matched),
                                       transport=_rule_transport(rule), rule=rule),
        }

    alerts = []
    for key, hit in _collect_hits(ctx.permit_rows_tracked("dst_zone"), row_eval).items():
        rows, matched, confirmed, ot_dst = hit["rows"], hit["matched"], hit["confirmed"], hit["ot_dst"]
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        severity = "critical" if confirmed else "high"
        names = _describe_matches(matched)
        alerts.append(_emit_twin(
            ctx, "rule_cleartext_creds", key, hit,
            title=(
                f"Cleartext credentials exposed to OT: {', '.join(matched.values())} "
                f"permitted into zone '{ev['dst_zone']}' ({_fmt_levels(ot_dst)}) "
                f"({_group_label(rows)})"
                + (" [matching traffic observed]" if confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits {names} to zone "
                f"'{ev['dst_zone']}' (Purdue {_fmt_levels(hit['dst_levels'])}). Cleartext "
                f"credential protocols to OT-zone hosts expose operator authentication to "
                f"interception and violate SR 4.1 (data confidentiality) and SR 3.1 (least "
                f"privilege). "
                + (
                    _TRAFFIC_OBSERVED.format(ports=names)
                    if confirmed else
                    "No matching traffic observed yet; the rule creates a standing "
                    "exposure risk that should be remediated regardless."
                )
            ),
            severity=severity,
            extra={
                "dst_ot_levels": sorted(ot_dst),
                "matched_ports": list(matched),
                "matched_services": list(matched.values()),
                "confirmed_by_traffic": confirmed,
            },
        ))
    return [a for a in alerts if a]


def review_rule_ot_it_dependency(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_ot_it_dependencies (SR 5.1 RE2, SR 1.1 / 7.3, 9.2).

    Flags permit rules whose source zone includes a Purdue level ≤ 2 (OT)
    and whose ports overlap IT services (DNS, AD/Kerberos, SMB, NTP). One
    finding per logical rule (T3-19).

    Severity escalates "low" → "medium" when OT-level sources are observed
    reaching the rule's destination levels on a matched port.
    """
    _IT_SERVICE_PORTS: dict[int, str] = {
        53: "DNS", 88: "Kerberos/AD", 135: "RPC/AD",
        137: "NetBIOS/SMB", 139: "NetBIOS/SMB", 389: "LDAP/AD",
        445: "SMB", 464: "Kerberos/AD", 636: "LDAPS/AD", 123: "NTP",
    }
    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        matched = _ports_matched(ranges, _IT_SERVICE_PORTS, rule)
        if not matched:
            return None
        if (set(matched.values()) == {"NTP"}
                and ctx.mctx.is_ntp_scope(rule.dst, [f"{_rule_transport(rule) or 'udp'}/123"])):
            return None  # owner: NTP to the declared site NTP server
        src_levels = ctx.levels(rule, rule.src_zone)
        ot_src = {l for l in src_levels if is_ot(l)}
        if not ot_src:
            return None  # source is not an OT zone
        dst_levels = ctx.resolver.resolve(rule, rule.dst_zone)
        return {
            "src_levels": src_levels, "dst_levels": dst_levels, "ot_src": ot_src,
            "matched": matched,
            "confirmed": ctx.confirmed(ot_src, dst_levels, ports=list(matched),
                                       transport=_rule_transport(rule), rule=rule),
        }

    alerts = []
    for key, hit in _collect_hits(ctx.permit_rows_tracked("src_zone", skip_vpn=True), row_eval).items():
        rows, matched, confirmed, ot_src = hit["rows"], hit["matched"], hit["confirmed"], hit["ot_src"]
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        severity = "medium" if confirmed else "low"
        names = _describe_matches(matched)
        services = ", ".join(dict.fromkeys(matched.values()))
        alerts.append(_emit_twin(
            ctx, "rule_ot_it_dependency", key, hit,
            title=(
                f"OT dependency on IT services: zone '{ev['src_zone']}' ({_fmt_levels(ot_src)}) "
                f"permitted to reach {services} ({_group_label(rows)})"
                + (" [matching traffic observed]" if confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits OT zone "
                f"'{ev['src_zone']}' (Purdue {_fmt_levels(hit['src_levels'])}) to reach IT "
                f"service(s) {names}. OT devices must not depend on IT infrastructure "
                f"services to maintain safe operation (SR 5.1 RE2, SR 1.1). If this "
                f"dependency is unavoidable, document the resilience measures in place and "
                f"ensure a local fallback (e.g. local DNS cache, NTP appliance). "
                + (
                    _TRAFFIC_OBSERVED.format(ports=names)
                    + " The dependency is in use, not theoretical."
                    if confirmed else
                    "No matching traffic observed yet; the rule creates a latent dependency "
                    "that should be reviewed against the autonomy requirement."
                )
            ),
            severity=severity,
            extra={
                "src_ot_levels": sorted(ot_src),
                "matched_ports": list(matched),
                "matched_services": list(dict.fromkeys(matched.values())),
                "confirmed_by_traffic": confirmed,
            },
        ))
    return [a for a in alerts if a]


def _external_dst_token(token: Optional[str]) -> Optional[str]:
    """The public destination a rule row names, or None: a public IPv4 / IPv6
    address or network (``8.8.8.8/32``, ``1.1.1.0/24``, ``2001:4860::/32``),
    an ``fqdn:`` / ``internet-service:`` token (DR-02).  ``any`` / private /
    unresolved tokens are not external by themselves."""
    if not token:
        return None
    t = token.strip()
    from app.parsers.rule_match import is_external_addr_token
    if is_external_addr_token(t):
        return t
    if t.startswith("range:"):
        t = t[6:].split("-", 1)[0]
    try:
        net = ipaddress.ip_network(t.split()[0], strict=False)
    except ValueError:
        return None
    if net.prefixlen == 0:
        return None
    probe = net.network_address if net.num_addresses == 1 else net.network_address + 1
    return token.strip() if _is_public_ip(str(probe)) else None


def review_rule_dns_external(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Owner (2026-10-11): one finding per enabled permit policy that lets any
    source reach an EXTERNAL DNS server (tcp / udp 53 to a public address, a
    public FQDN or an internet-service object) - checklist 9.11, SR 5.1 RE2 /
    SR 7.6, the policy-side counterpart of config_dns_external (which judges
    the firewall's own resolver).

    Not level-dependent: the destination decides.  Severity: high when the
    source zone holds an OT level (L0-L3: no OT device has direct Internet
    access), medium when the source level is unknown or DMZ, low when the
    source is enterprise only (L4 / L5); one step up when matching traffic
    was observed.  A row whose destination is ``any`` is not judged here -
    path_ot_internet_egress covers the egress chain.
    """
    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        ext = _external_dst_token(rule.dst)
        if ext is None:
            return None
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        matched = _ports_matched(ranges, {53: "DNS"}, rule)
        if not matched:
            return None
        src_levels, _complete = ctx.resolver.resolve_checked(rule, rule.src_zone)
        dst_levels = ctx.resolver.resolve(rule, rule.dst_zone)
        return {
            "src_levels": src_levels, "dst_levels": dst_levels,
            "external_dst": [ext], "matched": matched,
            "transports": [_rule_transport(rule) or "any"],
            "confirmed": ctx.confirmed({l for l in src_levels}, dst_levels, ports=[53],
                                       transport=_rule_transport(rule), rule=rule) if src_levels else False,
        }

    alerts = []
    for key, hit in _collect_hits(ctx.permit_rows(), row_eval).items():
        rows = hit["rows"]
        src_levels = set(hit["src_levels"])
        ot_src = {l for l in src_levels if l is not None and l <= 3}
        ev = _group_evidence(key, rows, src_levels, hit["dst_levels"])
        if ot_src:
            severity, band = "high", f"an OT zone ({_fmt_levels(ot_src)})"
        elif src_levels and all(l >= 4 for l in src_levels):
            severity, band = "low", f"the enterprise side ({_fmt_levels(src_levels)})"
        elif src_levels:
            severity, band = "medium", f"the DMZ ({_fmt_levels(src_levels)})"
        else:
            severity, band = "medium", "a zone of unknown level"
        if hit["confirmed"]:
            severity = {"low": "medium", "medium": "high", "high": "critical"}.get(severity, severity)
        dsts = list(dict.fromkeys(hit["external_dst"]))
        transports = sorted(set(hit["transports"]))
        alerts.append(_emit_twin(
            ctx, "rule_dns_external", key, hit,
            title=(f"External DNS permitted: zone '{ev['src_zone']}' to {', '.join(dsts[:4])}"
                   + (f" +{len(dsts) - 4} more" if len(dsts) > 4 else "")
                   + f" ({_group_label(rows)})" + (" [matching traffic observed]" if hit["confirmed"] else "")),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits {band} "
                f"('{ev['src_zone']}') to query DNS ({'/'.join(transports)} 53) at the external resolver"
                f"{'s' if len(dsts) > 1 else ''} {', '.join(dsts)}. Name resolution for the plant should "
                "come from internal resolvers (SR 5.1 RE2: no dependency on outside infrastructure; "
                "SR 7.6: controlled network configuration) - external DNS is an egress path, a "
                "dependency on the Internet and a channel that is rarely inspected. Point the hosts at "
                "an internal resolver (or the DMZ forwarder) and remove the public servers from the policy."
                + (" Matching traffic was observed: the external resolvers are in use."
                   if hit["confirmed"] else " No matching traffic observed yet.")
            ),
            severity=severity,
            extra={
                "external_destinations": dsts,
                "transports": transports,
                "src_ot_levels": sorted(ot_src),
                "confirmed_by_traffic": hit["confirmed"],
                "severity_reason": (f"high: the source zone holds OT levels {_fmt_levels(ot_src)} - no OT device "
                                    "should reach the Internet directly" if ot_src else
                                    "low: enterprise-side source only" if severity == "low" else
                                    "medium: source level unknown or DMZ")
                                   + (", one step up as the traffic was observed" if hit["confirmed"] else ""),
            },
        ))
    return [a for a in alerts if a]


def review_rule_mgmt_wrong_zone(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_mgmt_access_from_wrong_zone
    (SR 1.3, SR 5.1 RE1 / 5.1).

    Flags permit rules whose ports overlap management protocols (SSH,
    Telnet, HTTPS, RDP, HTTP, SNMP) from a source zone including a Purdue
    level ≥ 3 (IT) to a destination zone including a level ≤ 2 (OT). One
    finding per logical rule (T3-19).

    Severity escalates "medium" → "high" when IT-level → OT-level
    management traffic is observed on a matched port.
    """
    _MGMT_PORTS: dict[int, str] = {
        22: "SSH", 23: "Telnet", 443: "HTTPS", 3389: "RDP",
        80: "HTTP", 8080: "HTTP-alt", 8443: "HTTPS-alt", 161: "SNMP",
        5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",         # SF-3
    }
    ctx = _twin_ctx(db, _resolver, _ctx)
    # Declared management sources (app.parsers.mgmt_networks): a row whose
    # source is entirely inside management networks / trusted hosts, or whose
    # source zone is declared a management zone, is the sanctioned path.
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)

    def _from_mgmt(rule) -> bool:
        # the destination is OT (checked below), so engineering sources count
        if mctx.scope_is_mgmt(rule.src, ot=True):
            return True
        toks = [t.strip() for t in str(rule.src_zone or "").split(",") if t.strip()]
        return bool(toks) and all(mctx.name_class(rule.firewall_id, t, ot=True) is True for t in toks)

    def row_eval(rule):
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        matched = _ports_matched(ranges, _MGMT_PORTS, rule)
        if not matched:
            return None
        if _from_mgmt(rule):
            return None
        src_levels = ctx.levels(rule, rule.src_zone)
        dst_levels = ctx.levels(rule, rule.dst_zone)
        it_src = {l for l in src_levels if is_it_side(l)}
        ot_dst = {l for l in dst_levels if is_ot(l)}
        if not it_src or not ot_dst:
            return None
        return {
            "src_levels": src_levels, "dst_levels": dst_levels,
            "it_src": it_src, "ot_dst": ot_dst, "matched": matched,
            "confirmed": ctx.confirmed(it_src, ot_dst, ports=list(matched),
                                       transport=_rule_transport(rule), rule=rule),
        }

    alerts = []
    hits = _collect_hits(ctx.permit_rows_tracked("src_zone", "dst_zone", skip_vpn=True), row_eval)
    for key, hit in hits.items():
        rows, matched, confirmed = hit["rows"], hit["matched"], hit["confirmed"]
        it_src, ot_dst = hit["it_src"], hit["ot_dst"]
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        severity = "high" if confirmed else "medium"
        # F-08: DMZ-only source = the sanctioned jump-host remote-access path;
        # one step lower, and the text says so (see module-level note).
        dmz_source = all(is_dmz(lv) for lv in it_src)
        if dmz_source:
            severity = _SEVERITY_STEP_DOWN[severity]
        names = _describe_matches(matched)
        alerts.append(_emit_twin(
            ctx, "rule_mgmt_wrong_zone", key, hit,
            title=(
                f"Management access from {'DMZ' if dmz_source else 'non-management'} zone: "
                f"{', '.join(matched.values())} "
                f"from {'DMZ' if dmz_source else 'IT'} '{ev['src_zone']}' ({_fmt_levels(it_src)}) "
                f"to OT '{ev['dst_zone']}' "
                f"({_fmt_levels(ot_dst)}) ({_group_label(rows)})"
                + (" [matching traffic observed]" if confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits {names} from "
                f"IT-side zone '{ev['src_zone']}' (Purdue {_fmt_levels(hit['src_levels'])}) "
                f"to OT zone '{ev['dst_zone']}' (Purdue {_fmt_levels(hit['dst_levels'])}). "
                f"Management access to OT equipment must originate only from a dedicated "
                f"management zone (ISA/IEC 62443 SR 5.1 RE1, SR 1.3). "
                + (
                    "The source zone is the industrial DMZ (L3.5), the sanctioned location "
                    "for remote-access jump hosts: restrict the rule's source to the "
                    "approved jump host(s) and the services they need. "
                    if dmz_source else ""
                )
                + (
                    _TRAFFIC_OBSERVED.format(ports=names)
                    if confirmed else
                    "No matching traffic observed yet; the rule creates a standing "
                    "management-access risk from IT-side hosts."
                )
            ),
            severity=severity,
            extra={
                "src_it_levels": sorted(it_src),
                "dst_ot_levels": sorted(ot_dst),
                "dmz_source": dmz_source,
                "matched_ports": list(matched),
                "matched_services": list(matched.values()),
                "confirmed_by_traffic": confirmed,
            },
        ))
    return [a for a in alerts if a]


def review_rule_it_ot_bypass(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_ns_it_ot_bypass / check_it_ot_bypass
    (SR 5.1 RE2, SR 5.2 / 2.1, 2.2).

    Flags permit rules whose source zone includes a Purdue level ≥ 3
    (IT/enterprise) and whose destination zone includes a level ≤ 1 (field
    devices / basic control). Not port-based: any permitted service counts
    (ICMP rules included). A rule permitting direct IT-to-deep-OT traffic
    bypasses the required DMZ/conduit boundary regardless of observed
    traffic. One finding per logical rule (T3-19).

    Severity escalates "high" → "critical" when sessions from an IT-level
    (≥ 3) host to a deep-OT (≤ 1) host are observed within the rule's
    port ranges (and transport).

    A-11: a rule from an enterprise/internet zone (L4-L5) to an L2 zone
    also bypasses (it skips L3 and the L3.5 DMZ): "medium", "high" when
    matching traffic is observed. A rule hitting deep OT keeps the
    historical title/severity. DMZ (L3.5) -> L2 is not a bypass (sanctioned
    jump-host path, see review_rule_mgmt_wrong_zone).

    A-09: rules with a side that cannot be fully resolved to Purdue levels
    are recorded as not evaluated, so their open findings are not
    auto-resolved this run.
    """
    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        src_levels = ctx.levels(rule, rule.src_zone)
        dst_levels = ctx.levels(rule, rule.dst_zone)
        it_src = {l for l in src_levels if is_it_side(l)}
        deep_ot = {l for l in dst_levels if is_deep_ot(l)}
        # A-11: enterprise/internet (L4-L5) -> L2 also skips L3 and the DMZ.
        ent_src = {l for l in src_levels if is_it(l)}
        l2_dst = {l for l in dst_levels if is_ot(l) and not is_deep_ot(l)}
        deep_hit = bool(it_src and deep_ot)
        l2_hit = bool(ent_src and l2_dst)
        if not deep_hit and not l2_hit:
            return None
        if _is_icmp_rule(rule):
            ranges = None
        else:
            ranges = _parse_rule_ports(rule.dst_port)
        transport = _rule_transport(rule)

        def _conf(srcs, dsts) -> bool:
            # ICMP: no port semantics to match sessions against
            return ranges is not None and ctx.confirmed(
                srcs, dsts, port_ranges=ranges, transport=transport, rule=rule,
            )

        return {
            "src_levels": src_levels, "dst_levels": dst_levels,
            "it_src": it_src if deep_hit else set(),
            "deep_ot": deep_ot if deep_hit else set(),
            "ent_src": ent_src if l2_hit else set(),
            "l2_dst": l2_dst if l2_hit else set(),
            "port_ranges": list(ranges) if ranges else [],
            "confirmed": deep_hit and _conf(it_src, deep_ot),
            "confirmed_l2": l2_hit and _conf(ent_src, l2_dst),
        }

    alerts = []
    hits = _collect_hits(ctx.permit_rows_tracked("src_zone", "dst_zone", skip_vpn=True), row_eval)
    for key, hit in hits.items():
        rows = hit["rows"]
        it_src, deep_ot = hit["it_src"], hit["deep_ot"]
        ent_src, l2_dst = hit["ent_src"], hit["l2_dst"]
        ranges = _merge_ranges(hit["port_ranges"]) if hit["port_ranges"] else None
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        if deep_ot:
            # Historical case (unchanged title / severity / dedup identity).
            confirmed = hit["confirmed"]
            severity = "critical" if confirmed else "high"
            src_set, dst_set, dst_word = it_src, deep_ot, "deep-OT"
            src_word = "IT"
        else:
            # A-11: L4-L5 -> L2 only. One step below the deep-OT case.
            confirmed = hit["confirmed_l2"]
            severity = "high" if confirmed else "medium"
            src_set, dst_set, dst_word = ent_src, l2_dst, "OT"
            src_word = "enterprise"
        any_confirmed = hit["confirmed"] or hit["confirmed_l2"]
        bypassed = ("site operations (L3) and the industrial DMZ (L3.5)"
                    if not deep_ot else "at least one required inspection point")
        alerts.append(_emit_twin(
            ctx, "rule_it_ot_bypass", key, hit,
            title=(
                f"IT/OT boundary bypass: direct {src_word} '{ev['src_zone']}' "
                f"({_fmt_levels(src_set)}) → {dst_word} '{ev['dst_zone']}' "
                f"({_fmt_levels(dst_set)}) permitted ({_group_label(rows)})"
                + (" [matching traffic observed]" if any_confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits direct traffic "
                f"from {src_word} zone '{ev['src_zone']}' (Purdue {_fmt_levels(hit['src_levels'])}) to "
                f"{dst_word} zone '{ev['dst_zone']}' (Purdue {_fmt_levels(hit['dst_levels'])}). "
                f"The ISA/IEC 62443 Purdue model requires that all cross-level traffic "
                f"traverses a conduit at each boundary; a single rule spanning "
                f"{_fmt_levels(src_set)} to {_fmt_levels(dst_set)} skips {bypassed} "
                f"(SR 5.1 RE2, SR 5.2). "
                + (
                    "Matching traffic observed: NetworkSession data shows direct sessions "
                    f"from {src_word}-level to {dst_word}-level hosts within this rule's ports."
                    if any_confirmed else
                    "No matching traffic observed yet; the policy creates a standing "
                    "zone-isolation violation that must be remediated."
                )
            ),
            severity=severity,
            extra={
                "src_it_levels": sorted(it_src | ent_src),
                "dst_deep_ot_levels": sorted(deep_ot),
                "dst_ot_levels": sorted(deep_ot | l2_dst),
                "bypass_kind": "deep_ot" if deep_ot else "l2",
                "port_ranges": [list(r) for r in ranges] if ranges else None,
                "confirmed_by_traffic": any_confirmed,
            },
        ))
    return [a for a in alerts if a]


def _subtract_ranges(
    ranges: list[tuple[int, int]], covered: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """ranges minus the inclusive `covered` ranges (result sorted, merged)."""
    cov = _merge_ranges(covered)
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        cur = lo
        for clo, chi in cov:
            if chi < cur:
                continue
            if clo > hi:
                break
            if clo > cur:
                out.append((cur, clo - 1))
            cur = max(cur, chi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return _merge_ranges(out)


def _subtract_ports(
    ranges: list[tuple[int, int]], covered: set[int]
) -> list[tuple[int, int]]:
    """ranges minus the individual ports in `covered` (result sorted)."""
    return _subtract_ranges(ranges, [(p, p) for p in covered])


def _approved_entry_range(e: ApprovedCommsEntry) -> Optional[tuple[int, int]]:
    """Inclusive port range an ApprovedCommsEntry approves; None = any port.

    dst_port None → any; dst_port with dst_port_end → [dst_port, dst_port_end]
    (a reversed/garbage end is treated as the single port); dst_port alone →
    that single port."""
    if e.dst_port is None:
        return None
    lo = int(e.dst_port)
    end = getattr(e, "dst_port_end", None)
    hi = int(end) if end is not None and int(end) >= lo else lo
    return (lo, hi)


_ANY_PROTOCOLS = ("any", "", "ip", "all")


def _approved_coverage(
    entries: list, rule_transport: Optional[str], rule_conduit: Optional[str]
) -> tuple[bool, list[tuple[int, int]]]:
    """(covers_any_port, covered_ranges) of the baseline entries that apply
    to a rule with this transport/conduit (see review_rule_conduit_drift).

    A-10: an entry covers a (transport, port) only if its protocol is "any"
    (any/ip/all/empty) or equals the transport; ICMP / other IP-protocol
    entries never cover tcp/udp ports. rule_transport None (a transport-any
    rule) needs coverage for BOTH tcp and udp: the result is the
    intersection of the tcp and udp coverage (use _approved_coverage_by_transport
    to report per transport)."""
    if rule_transport is None:
        t_any, t_cov = _approved_coverage(entries, "tcp", rule_conduit)
        u_any, u_cov = _approved_coverage(entries, "udp", rule_conduit)
        if t_any and u_any:
            return True, []
        if t_any:
            return False, _merge_ranges(u_cov)
        if u_any:
            return False, _merge_ranges(t_cov)
        # intersection(T, U) = T - (full - U)
        not_u = _subtract_ranges(list(_PORT_ANY), u_cov)
        return False, _subtract_ranges(_merge_ranges(t_cov), not_u)
    covered: list[tuple[int, int]] = []
    for e in entries:
        e_conduit = (e.conduit or "").strip().casefold() or None
        if rule_conduit and e_conduit and rule_conduit != e_conduit:
            continue
        e_proto = (e.protocol or "any").strip().lower()
        if e_proto not in _ANY_PROTOCOLS and e_proto != rule_transport:
            continue
        rng = _approved_entry_range(e)
        if rng is None:
            return True, []
        covered.append(rng)
    return False, covered


def _rule_transports(rule: FirewallRule) -> tuple[str, ...]:
    """Transports a port-based permit rule allows: its own tcp/udp, or both
    for a transport-any rule (A-10)."""
    t = _rule_transport(rule)
    return (t,) if t else ("tcp", "udp")


def review_rule_conduit_drift(
    db: DBSession,
    _resolver: Optional[_RuleZoneResolver] = None,
    _ctx: Optional[_TwinRunContext] = None,
) -> list:
    """
    Phase 6 rule-based twin for review_conduit_matrix_drift (SR 5.2, ZCR 3 / 8.1, 8.2).

    Flags permit rules whose port ranges are not fully covered by the
    active baseline's ApprovedCommsEntry set. Matching is port-based (rule
    src/dst may be named objects), narrowed where both sides carry the
    information: an entry only covers a rule if their conduit names agree
    (when both are set) and the entry protocol is "any" or equals the rule
    transport (A-10: ICMP / other-protocol entries never cover tcp/udp
    ports; a transport-any rule must be covered for both tcp and udp, and
    evidence "uncovered_by_transport" lists the gaps per transport).
    An ApprovedCommsEntry with dst_port = None means "any port" and covers
    every port of the rules it applies to (T1-15); dst_port + dst_port_end
    approves that inclusive range. "any" / wide-range rules are evaluated
    (uncovered ranges are listed); ICMP / port-0 / unparseable rules are
    skipped. One finding per logical rule per baseline (T3-19).

    Severity escalates "medium" → "high" when traffic between hosts at the
    rule's resolved levels is observed on an uncovered port.
    """
    active = _active_baseline(db)
    if not active:
        _mark_incomplete(db, "no active baseline")
        return []  # no baseline = nothing to diff against

    entries = db.query(ApprovedCommsEntry).filter(
        ApprovedCommsEntry.baseline_id == active.id,
    ).all()
    if not entries:
        _mark_incomplete(db, "active baseline has no approved comms entries")
        return []  # no approved entries yet — baseline not configured

    ctx = _twin_ctx(db, _resolver, _ctx)

    def row_eval(rule):
        ranges = ctx.ports(rule)
        if ranges is None:
            return None
        rule_conduit = (rule.conduit or "").strip().casefold() or None
        # A-10: coverage per transport (a transport-any rule needs both).
        by_t: dict[str, list] = {}
        for t in _rule_transports(rule):
            covered_any, covered = _approved_coverage(entries, t, rule_conduit)
            if covered_any:
                continue
            unc = _subtract_ranges(ranges, covered)
            if unc:
                by_t[t] = unc
        if not by_t:
            return None  # every (transport, port) of this rule is approved
        uncovered = _merge_ranges(r for u in by_t.values() for r in u)
        src_levels = ctx.resolver.resolve(rule, rule.src_zone)
        dst_levels = ctx.resolver.resolve(rule, rule.dst_zone)
        return {
            "src_levels": src_levels, "dst_levels": dst_levels, "uncovered": uncovered,
            "uncovered_tx": [(t, lo, hi) for t, u in by_t.items() for lo, hi in u],
            "confirmed": any(
                ctx.confirmed(src_levels, dst_levels, port_ranges=u, transport=t, rule=rule)
                for t, u in by_t.items()
            ),
        }

    alerts = []
    for key, hit in _collect_hits(ctx.permit_rows(), row_eval).items():
        rows, confirmed = hit["rows"], hit["confirmed"]
        uncovered = _merge_ranges(hit["uncovered"])
        ev = _group_evidence(key, rows, hit["src_levels"], hit["dst_levels"])
        severity = "high" if confirmed else "medium"
        uncovered_txt = _fmt_ranges(uncovered)
        tx: dict[str, list] = {}
        for t, lo, hi in hit["uncovered_tx"]:
            tx.setdefault(t, []).append((lo, hi))
        by_t = {t: _fmt_ranges(_merge_ranges(u)) for t, u in sorted(tx.items())}
        alerts.append(_emit_twin(
            ctx, "rule_conduit_drift", key, hit,
            title=(
                f"Permit outside approved comms matrix: port(s) "
                f"{'; '.join(f'{t}/{r}' for t, r in by_t.items()) or uncovered_txt} "
                f"({_group_label(rows)})"
                + (" [matching traffic observed]" if confirmed else "")
            ),
            detail_text=(
                f"Firewall {_group_label(rows)}{_rows_phrase(rows)} permits traffic on port(s) "
                f"'{ev['dst_port'] or 'any'}' "
                + (f"from '{ev['src_zone']}' to '{ev['dst_zone']}' " if ev["src_zone"] else "")
                + f"but no ApprovedCommsEntry in baseline #{active.id} covers port(s) "
                f"{uncovered_txt}. The approved communications matrix (ZCR 3) should "
                f"document every permitted conduit; a permit rule with no corresponding "
                f"matrix entry indicates the rule was not reviewed as part of the conduit "
                f"design (SR 5.2). "
                + (
                    _TRAFFIC_OBSERVED.format(ports=f"uncovered port(s) {uncovered_txt}")
                    if confirmed else
                    "No matching traffic observed on the uncovered ports yet; the rule "
                    "represents an unreviewed policy entry regardless."
                )
            ),
            severity=severity,
            extra={
                "uncovered_ports": uncovered_txt,
                "uncovered_by_transport": by_t,
                "confirmed_by_traffic": confirmed,
                "baseline_id": active.id,
            },
            dedup_extra={"baseline_id": active.id},
        ))
    return [a for a in alerts if a]


# --------------------------------------------------------------------------
# Disabled rules (checklist 3.8 "Unused rules identified for removal", SR 7.7)
# --------------------------------------------------------------------------

def _disabled_rule_group_key(rule: FirewallRule) -> tuple:
    """Rows expanded from one logical rule share policy_id (FortiOS) or
    raw_line (Cisco/ASA, pfSense, PAN-OS, which carry no policy id)."""
    ident = rule.policy_id or hashlib.sha1((rule.raw_line or f"id:{rule.id}").encode()).hexdigest()[:12]
    if (rule.policy_id and rule.raw_line and str(rule.device_type or "").startswith("cisco")
            and not str(rule.policy_id).startswith("implicit:")):
        # MV-04: a Cisco ACE's policy_id is its POSITION in the ACL, which
        # moves when an entry is inserted above it.  Findings are keyed on
        # the ACL name and the ACE text instead, so acknowledgements survive
        # an insertion (the remark appended to raw_line is left out).
        ace = str(rule.raw_line).split("  ! remark:", 1)[0].strip()
        ident = f"{rule.policy_name or str(rule.policy_id).rsplit(':', 1)[0]}:" \
                f"{hashlib.sha1(ace.encode()).hexdigest()[:12]}"
    vdom = getattr(rule, "vdom", None)
    if vdom is not None and rule.policy_id:
        # N-24: a FortiOS policy id is unique only within its VDOM.  Rules with
        # no VDOM keep the plain id, so existing rule_keys stay stable.
        ident = f"{ident}@vd:{vdom}"
    return (rule.firewall_id, rule.firewall_device_id, rule.device_name, ident)


def _is_any(v: Optional[str]) -> bool:
    return str(v or "any").strip().lower() in ("any", "all", "0.0.0.0/0", "::/0", "any4")


def review_disabled_rules(db: DBSession, _resolver: Optional[_RuleZoneResolver] = None) -> list:
    """
    Flag administratively disabled firewall rules for removal
    (checklist 3.8 "Unused rules identified for removal", SR 7.7 Least
    functionality; 62443-2-1 configuration management).

    A disabled rule (FortiOS ``set status disable``, pfSense ``<disabled/>``,
    PAN-OS ``disabled yes``, Cisco ASA ``inactive``) enforces nothing today,
    but it is a legacy leftover that can be re-enabled without passing
    change review. Evidence comes straight from the parsed config, so no
    traffic or rule-hit logs are needed (unlike ``unused_policy``).

    One finding per LOGICAL rule (expanded rows are grouped), keyed on a
    stable rule identity so a config re-ingest does not duplicate it.

    Severity:
      low     default - the rule is inert.
      medium  when the rule is a PERMIT that would, if re-enabled, open
              IT→OT traffic (source zone includes Purdue ≥ 3 and destination
              zone includes ≤ 2), or is any-source / any-destination /
              any-service.
    """
    resolver = _resolver or _rule_zone_purdue(db)
    rows = (
        db.query(FirewallRule)
        .filter(FirewallRule.enabled.is_(False))
        .order_by(FirewallRule.id)
        .all()
    )
    groups: dict[tuple, list[FirewallRule]] = {}
    for r in rows:
        groups.setdefault(_disabled_rule_group_key(r), []).append(r)

    alerts = []
    for (fw_id, fw_dev_id, device, ident), members in groups.items():
        first = members[0]
        is_permit = str(first.action or "").lower() in ("permit", "allow", "accept")
        src_levels: set[int] = set()
        dst_levels: set[int] = set()
        it_to_ot = False
        any_any = False
        for r in members:
            sl = resolver.resolve(r, r.src_zone) if r.src_zone else set()
            dl = resolver.resolve(r, r.dst_zone) if r.dst_zone else set()
            src_levels |= sl
            dst_levels |= dl
            if any(is_it_side(l) for l in sl) and any(is_ot(l) for l in dl):
                it_to_ot = True
            if _is_any(r.src) and _is_any(r.dst) and _is_any(r.dst_port):
                any_any = True

        reasons = []
        if is_permit and it_to_ot:
            reasons.append("would permit IT→OT traffic if re-enabled")
        if is_permit and any_any:
            reasons.append("is an any-source/any-destination/any-service permit")
        severity = "medium" if reasons else "low"

        raw1 = (first.raw_line or f"rule {first.id}").strip().splitlines()[0][:120]
        if first.policy_id and str(first.device_type or "").startswith("cisco") and first.raw_line:
            # MV-04: an ACE is named by its ACL and line; its text says what it is
            label = f"ACE {first.policy_id} ({raw1})"
        elif first.policy_id:
            label = f"policy {first.policy_id}" + (f" '{first.policy_name}'" if first.policy_name else "")
        else:
            label = raw1
        evidence = {
            "rule_key":     ident,
            "firewall_id":  fw_id,
            "device_name":  device,
            "policy_id":    first.policy_id,
            "rule": {
                "policy_name":   first.policy_name,
                "device_type":   first.device_type,
                "action":        first.action,
                "src_zone":      first.src_zone,
                "dst_zone":      first.dst_zone,
                "rule_order":    first.rule_order,
                "expanded_rows": len(members),
                "firewall_rule_ids": [m.id for m in members],
                "raw_line":      (first.raw_line or "")[:500],
            },
            "src_purdue_levels": sorted(src_levels),
            "dst_purdue_levels": sorted(dst_levels),
            "severity_reasons": reasons,
        }
        alerts.append(_make_finding(
            db,
            check_name="disabled_rule",
            title=(
                f"Disabled {first.action or 'firewall'} rule should be removed: {label}"
                + (f" on {device}" if device else "")
                + (f" ({reasons[0]})" if reasons else "")
            ),
            detail_text=(
                f"{label} on {device or 'unknown device'} is present in the configuration "
                f"but administratively disabled. It enforces nothing today, but it is a "
                f"legacy leftover: it can be re-enabled without going through change "
                f"review, and it clutters rule-set reviews. Checklist 3.8 (unused rules "
                f"identified for removal) and ISA/IEC 62443-3-3 SR 7.7 (least "
                f"functionality) call for removing it, or documenting why it must stay. "
                + (f"Raised to medium because it {' and '.join(reasons)}." if reasons else "")
            ),
            evidence=evidence,
            device_name=device,
            severity=severity,
        ))
    return [a for a in alerts if a]


_RULE_TWIN_CHECKS = (
    review_rule_cleartext_protocols,
    review_rule_mgmt_protocols,
    review_rule_cleartext_creds,
    review_rule_ot_it_dependency,
    review_rule_dns_external,
    review_rule_mgmt_wrong_zone,
    review_rule_it_ot_bypass,
    review_rule_conduit_drift,
)
# review function name -> check_name it writes (used to discard per-run
# context state when a twin's savepoint is rolled back).
_TWIN_CHECK_NAME = {
    "review_rule_cleartext_protocols": "rule_cleartext_protocol",
    "review_rule_mgmt_protocols":     "rule_mgmt_protocol",
    "review_rule_cleartext_creds":    "rule_cleartext_creds",
    "review_rule_ot_it_dependency":   "rule_ot_it_dependency",
    "review_rule_dns_external":       "rule_dns_external",
    "review_rule_mgmt_wrong_zone":    "rule_mgmt_wrong_zone",
    "review_rule_it_ot_bypass":       "rule_it_ot_bypass",
    "review_rule_conduit_drift":      "rule_conduit_drift",
}

# Session.info key listing the reviews that failed (and were rolled back) in
# the most recent run_periodic_reviews call on that session. Kept out of the
# returned stats because callers sum stats.values() (app/main.py,
# POST /reviews/run).
_FAILED_REVIEWS_KEY = "alert_engine.failed_reviews"
# F-04: {review_name: findings auto-resolved} of the last run on the session.
_AUTO_RESOLVED_KEY = "alert_engine.auto_resolved"

# F-04 auto-resolve: reviews whose evaluation is complete each run (they
# re-derive every finding of their check_name(s) from the current data), and
# the check_names they own. After such a review SUCCEEDS without marking
# itself incomplete (_mark_incomplete: required data absent, e.g. no active
# baseline / no sessions / no zone data, or input truncated by a row limit),
# its OPEN periodic_review findings that were not re-produced this run are
# closed (minus per-finding exceptions: A-09 unevaluated rules, B-20 hosts of
# unknown Purdue level, B-24 FAZ-covered flows kept via _keep_seen).
#
# B-24 added (each re-derives its complete finding set every run):
#   review_ns_* (5)               always run since B-04 (the old "skipped
#                                 whenever FAZ is active" reason is gone);
#                                 full keyset scan of the site's sessions; a
#                                 flow suppressed because the FAZ real-time
#                                 finding covers it is kept open (_keep_seen);
#                                 empty session table -> incomplete
#   review_vlan_zone_mismatch / review_ghost_vlans / review_intervlan_routing
#                                 full scan of the current switch-VLAN / MAC /
#                                 sub-interface state each run; a zone of
#                                 unknown membership counts as "not covered"
#                                 (finding kept), so nothing is closed on a
#                                 guess
#
# Deliberately NOT listed (never auto-resolved), with the reason:
#   review_denied_trends          time-windowed report items (90-day window):
#                                 ageing out of the window is not "fixed"
#   review_single_path_critical_devices / review_no_path_redundancy
#                                 silently skip hosts whose paths they "can't
#                                 determine" (partial evaluation without a
#                                 per-finding marker)
#   review_firmware_not_documented
#                                 attestation/documentation workflow, human-owned
#   (review_zone_documentation IS listed - B5: it re-derives all six rows from
#    the attestation table on every run, so a row that is now attested closes)
#   review_ntp_sync               multi-source: the per-host "no NTP observed"
#                                 findings are suppressed (not re-evaluated)
#                                 whenever no NTP session exists at all, and
#                                 the config sub-check mirrors another finding
#                                 (config_ntp_fortiguard) - absence of output
#                                 does not mean the condition was fixed
# Not periodic reviews, so outside this table:
#   unauthorized_industrial_write traffic_findings.check_unauthorized_industrial_writes
#                                 (pcap ingest / POST /findings/scan-industrial-writes);
#                                 dedup per capture, lifecycle owned there
#   real_time checks              event-driven / one-shot (never auto-closed)
#   cross_fw_*                    cross_fw_findings.run_cross_fw_checks
#                                 auto-resolves its own findings (B-24)
#   config_* (forti_config_parser) per-config-ingest findings
_AUTO_RESOLVE_CHECKS: dict[str, tuple[str, ...]] = {
    "review_zone_documentation":         tuple(f"zone_doc_1_{i}" for i in range(1, 7)),
    "review_conduit_matrix_drift":       ("conduit_matrix_drift",),
    "review_session_no_permitting_rule": ("session_no_permitting_rule",),
    "review_unused_policies":            ("unused_policy",),
    "review_cleartext_protocols":        ("cleartext_protocol", "smbv1_legacy"),
    "review_mgmt_protocols":             ("mgmt_protocol",),
    "review_ot_it_dependencies":         ("ot_it_dependency",),
    "review_cleartext_credentials":      ("cleartext_credentials",),
    "review_unknown_devices":            ("unknown_device",),
    "review_ip_conflicts":               ("ip_conflict",),
    "review_misplaced_devices":          ("misplaced_device",),
    "review_shadow_rules":               ("shadow_rule",),
    "review_historian_in_control_zone":  ("historian_in_control_zone",),
    "review_wireless_in_ot_zone":        ("wireless_in_ot_zone",),
    "review_sis_isolation":              ("sis_zone_not_isolated",),
    "review_transient_devices":          ("transient_device_in_ot_zone",),
    "review_switch_port_nac":            ("switch_port_no_nac",),
    "review_switch_unused_ports":        ("switch_unused_port_enabled",),
    "review_default_credentials":        ("default_credentials_observed",),
    "review_weak_tls":                   ("weak_tls_observed",),
    "review_undocumented_lldp_devices":  ("undocumented_lldp_device",),
    "review_mgmt_access_from_wrong_zone": ("mgmt_access_from_wrong_zone",),
    "review_mgmt_access_not_restricted": ("mgmt_access_not_restricted",),
    "review_rule_cleartext_protocols":   ("rule_cleartext_protocol",),
    "review_rule_mgmt_protocols":        ("rule_mgmt_protocol",),
    "review_rule_cleartext_creds":       ("rule_cleartext_creds",),
    "review_rule_ot_it_dependency":      ("rule_ot_it_dependency",),
    "review_rule_dns_external":          ("rule_dns_external",),
    "review_rule_mgmt_wrong_zone":       ("rule_mgmt_wrong_zone",),
    "review_rule_it_ot_bypass":          ("rule_it_ot_bypass",),
    "review_rule_conduit_drift":         ("rule_conduit_drift",),
    "review_disabled_rules":             ("disabled_rule",),
    # B-24
    "review_ns_it_ot_bypass":            ("session_it_ot_bypass", "engineering_access_unapproved"),
    "review_ns_ot_internet_egress":      ("session_ot_internet_egress",),
    "review_ns_remote_access_bypass":    ("session_remote_access_bypass",),
    "review_ns_scanning_anomaly":        ("session_scanning_anomaly",),
    "review_ns_remote_access_app":       ("session_remote_access_app",),
    "review_ns_mgmt_from_non_admin":     ("session_mgmt_from_non_admin",),
    "review_vlan_zone_mismatch":         ("vlan_zone_mismatch",),
    "review_undocumented_conduits":      ("undocumented_conduit",),
    "review_multi_zone_membership":      ("host_in_multiple_zones", "network_in_multiple_zones"),
    "review_policies_spanning_conduits": ("policy_spans_multiple_conduits",),
    "review_blocked_cross_zone_attempts": ("blocked_cross_zone_attempts", "conduit_service_blocked"),
    "review_ghost_vlans":                ("ghost_vlan",),
    "review_intervlan_routing":          ("intervlan_routing_unchecked",),
    # Access Review (docs/access-path-review.md phase 4): re-derives every
    # classification-raised finding from the site's tags each run; marks
    # itself incomplete when the path enumeration is truncated.
    "_review_access_path_classifications": ("access_path_permissive",),
    # D-05: chain-aware twins, re-derived from the access-path rows each run
    "review_access_path_truncation":     ("access_path_enumeration_truncated",),
    "review_chain_it_ot_bypass":         ("chain_it_ot_bypass",),
    "review_chain_mgmt_wrong_zone":      ("chain_mgmt_wrong_zone",),
    "review_dead_end_permits":           ("dead_end_permit",),
    "review_chain_ot_upward_skip":       ("chain_ot_upward_skip",),
    "review_dmz_bypass":                 ("dmz_bypass",),
    "review_path_internet_egress":       ("path_ot_internet_egress",),
    "review_vpn_direct_to_ot":           ("vpn_direct_to_ot",),
    "review_nat_hides_source_into_ot":   ("nat_hides_source_into_ot",),
    "review_implicit_permits":           ("rule_implicit_permit",),
    "review_l3_switches":                ("switch_routes_between_zones", "switch_acl_wrong_direction",
                                          "switch_mgmt_svi_unrestricted", "switch_dual_gateway"),
    "review_flat_control_segments":      ("flat_control_segment",),
    "review_multi_homed_hosts":          ("multi_homed_host",),
    "review_rogue_dhcp_servers":         ("rogue_dhcp_server",),
    "review_dead_default_gateways":      ("dead_default_gateway",),
    "review_ha_config_drift":            ("ha_config_drift",),
    "review_paired_firewall_vendor_diversity": ("paired_firewall_vendor_diversity",),
}

_ACCESS_REVIEW_SYNC = "_review_access_path_classifications"


def _review_access_path_classifications(db: DBSession) -> list:
    """Access Review findings sync (docs/access-path-review.md phase 4):
    bring the findings of every ``access_path_tag`` of the reviewed site in
    line with its classification (app.parsers.access_path_findings), after
    the automatic checks so a new automatic finding is confirmed /
    acknowledged and findings follow config re-ingests.

    Owns ``access_path_permissive`` and the "manual" rule_it_ot_bypass
    findings: their dedup keys are recorded as seen, so auto-resolve closes
    only those whose tag no longer asks for them.  An unscoped (legacy) run
    syncs each site that has tags, each inside its own site scope."""
    from app.models import AccessPathTag
    from app.parsers import access_path_findings as apf

    sid = current_site(db)
    if sid is not None:
        site_ids = [sid]
    else:
        site_ids = sorted({r[0] for r in db.query(AccessPathTag.site_id).distinct()
                           if r[0] is not None})
    created: list = []
    seen = db.info.get(_SEEN_KEY)
    for s in site_ids:
        res = apf.sync_site_findings(db, s)
        created += res.get("_created", [])
        if seen is not None:
            seen.update(res.get("_refs", ()))
        if res.get("_incomplete"):
            _mark_incomplete(db, f"site {s}: access-path enumeration truncated")
        if any(res.get(k) for k in ("raised", "confirmed", "acknowledged", "reopened", "closed")):
            log.info("Access Review findings sync (site %s): %s", s,
                     {k: v for k, v in res.items() if not k.startswith("_")})
    return created


# F-17: summary of the most recent run_periodic_reviews call in this process
# (exposed by GET /diagnostics).
_last_review_info: dict = {}


# Multi-site: per-site copies of the bookkeeping above, keyed by site_id
# (None = unscoped all-data run), so a run for site B never overwrites what
# a caller wants to know about site A's last run on the same session.
_FAILED_BY_SITE_KEY = "alert_engine.failed_reviews_by_site"
_AUTO_RESOLVED_BY_SITE_KEY = "alert_engine.auto_resolved_by_site"
_last_review_info_by_site: dict = {}

_UNSET = object()


def failed_reviews(db: DBSession, site_id=_UNSET) -> list[str]:
    """Names of the reviews that raised (and were rolled back) in the last
    run_periodic_reviews call on this session (``site_id``: the last run
    for that site; None = the last unscoped run)."""
    if site_id is _UNSET:
        return list(db.info.get(_FAILED_REVIEWS_KEY, []))
    return list(db.info.get(_FAILED_BY_SITE_KEY, {}).get(site_id, []))


def auto_resolved_counts(db: DBSession, site_id=_UNSET) -> dict[str, int]:
    """{review_name: findings auto-resolved} for the last run_periodic_reviews
    call on this session (only reviews that closed at least one); per site
    when ``site_id`` is given."""
    if site_id is _UNSET:
        return dict(db.info.get(_AUTO_RESOLVED_KEY, {}))
    return dict(db.info.get(_AUTO_RESOLVED_BY_SITE_KEY, {}).get(site_id, {}))


# Reviews that are not auto-resolved (see the "Deliberately NOT listed" notes
# above) and the checks they evaluate - for the report's PASS / NOT EVALUATED.
_REVIEW_EXTRA_CHECKS: dict[str, tuple[str, ...]] = {
    "review_denied_trends":                ("denied_trend",),
    "review_single_path_critical_devices": ("single_path_critical_device",),
    "review_no_path_redundancy":           ("no_path_redundancy_verified",),
    "review_firmware_not_documented":      ("firmware_not_documented",),
    "review_ntp_sync":                     ("ntp_sync",),
}


def review_checks_map() -> dict[str, tuple[str, ...]]:
    """{review function name: check_names it evaluates} (auto-resolved reviews
    plus _REVIEW_EXTRA_CHECKS) - app.check_evaluations."""
    return {**_AUTO_RESOLVE_CHECKS, **_REVIEW_EXTRA_CHECKS}


def _record_evaluation(db: DBSession, review: str, ok: bool, incomplete) -> None:
    """Remember that `review` evaluated its checks now (report PASS / NOT
    EVALUATED); a failed or incomplete run is recorded as such.  Site-bound
    runs only."""
    checks = review_checks_map().get(review)
    site = current_site(db)
    if not checks or site is None:
        return
    from app.check_evaluations import record
    note = None if ok and not incomplete else ("review failed" if not ok else str(incomplete))
    when = datetime.now(timezone.utc)
    for c in checks:
        record(db, site, c, source=review, complete=ok and not incomplete, note=note, when=when)


def unknown_check_name_counts() -> dict[str, int]:
    """F-17: unregistered check_names passed to _make_finding (process-wide)."""
    return dict(_unknown_check_name_count)


def last_review_info(site_id=_UNSET) -> dict:
    """F-17: failed_reviews / escalations / auto_resolved of the last run
    (of the last run for ``site_id`` when given)."""
    src = _last_review_info if site_id is _UNSET else _last_review_info_by_site.get(site_id, {})
    return {k: (list(v) if isinstance(v, list) else dict(v) if isinstance(v, dict) else v)
            for k, v in src.items()}


def auto_resolve_enabled() -> bool:
    """IACS_AUTO_RESOLVE (default true); 0/false/no/off disables."""
    import os
    return os.environ.get("IACS_AUTO_RESOLVE", "true").strip().lower() not in (
        "0", "false", "no", "off", "")


def _auto_resolve(db: DBSession, review: str, check_names: tuple, seen: set,
                  unevaluated: Optional[set] = None,
                  unknown_hosts: Optional[set] = None) -> int:
    """Close OPEN periodic_review findings of `check_names` whose dedup key
    was not re-produced by `review` this run. Acknowledged findings (status
    "acknowledged" or acknowledged_by set) and real_time findings are never
    touched. Findings whose logical firewall rule (detail rule_key /
    firewall_id / device_name) is in `unevaluated` (A-09: the review could
    not fully evaluate that rule this run) are kept open, as are (B-20)
    findings whose src_ip / dst_ip is in `unknown_hosts` (the review skipped
    those hosts because a Purdue level is unknown). Returns the number
    closed."""
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    note = f"Auto-resolved: condition no longer detected by {review} on {stamp}"
    closed = 0
    q = db.query(Finding).filter(
        Finding.check_name.in_(list(check_names)),
        Finding.status == "open",
        Finding.category == "periodic_review",
        Finding.source_ref.isnot(None),
        Finding.acknowledged_by.is_(None),
    )
    for f in q:
        if f.source_ref in seen:
            continue
        d = f.detail if isinstance(f.detail, dict) else {}
        # Access Review: a finding raised from a reviewer's classification
        # ("manual") is owned by _review_access_path_classifications, never
        # by the automatic check that shares its check_name.
        if d.get("manual") and review != _ACCESS_REVIEW_SYNC:
            continue
        if unknown_hosts and (d.get("src_ip") in unknown_hosts
                              or d.get("dst_ip") in unknown_hosts):
            continue
        if unevaluated:
            if d.get("rule_key") is not None and _rule_identity(
                d.get("rule_key"), d.get("firewall_id"), d.get("device_name")
            ) in unevaluated:
                continue
        f.status = "closed"
        f.closed_at = now
        f.notes = ((f.notes + " | ") if f.notes else "")[:2048 - len(note) - 3] + note
        closed += 1
    if closed:
        log.info("Auto-resolved %d %s finding(s) no longer detected by %s",
                 closed, "/".join(check_names), review)
    return closed


# A-32: concurrent run_periodic_reviews guard. Two overlapping runs (the
# scheduler in main.py plus POST /reviews/run, or two API calls) used to
# interleave dedup/auto-resolve and could override each other's lifecycle
# changes. Guard, kept deliberately simple:
#   - process-wide: a non-blocking threading.Lock (covers the normal single
#     uvicorn process: scheduler thread + request threads);
#   - cross-process on PostgreSQL: pg_try_advisory_lock(_REVIEW_PG_LOCK_ID),
#     released in finally. SQLite deployments are single-process, so the
#     threading lock is the guard there (no DB marker row is needed).
# A caller that loses the race returns immediately with
# {"skipped_concurrent_run": 0} (int value: callers sum stats.values())
# and _review_run_skipped(db) is True.
_REVIEW_RUN_LOCK = threading.Lock()   # the unscoped (all-data) run
_REVIEW_PG_LOCK_ID = 0x1A5C_62443
_REVIEW_SKIPPED_KEY = "alert_engine.review_skipped"
REVIEW_SKIPPED_STAT = "skipped_concurrent_run"
# Multi-site: one lock per site, so two DIFFERENT sites may review
# concurrently while a second run for the SAME site is skipped. An unscoped
# all-data run (site_id=None, legacy) conflicts with every site run.
_SITE_LOCKS: dict[int, threading.Lock] = {}
_SITE_LOCKS_GUARD = threading.Lock()


def _acquire_review_lock(site_id: Optional[int]) -> Optional[threading.Lock]:
    """Non-blocking; the acquired lock, or None when a conflicting run holds it."""
    with _SITE_LOCKS_GUARD:
        if site_id is None:
            if any(lk.locked() for lk in _SITE_LOCKS.values()):
                return None
            return _REVIEW_RUN_LOCK if _REVIEW_RUN_LOCK.acquire(blocking=False) else None
        if _REVIEW_RUN_LOCK.locked():
            return None
        lk = _SITE_LOCKS.get(site_id)
        if lk is None:
            lk = _SITE_LOCKS[site_id] = threading.Lock()
        return lk if lk.acquire(blocking=False) else None


def _review_run_skipped(db: DBSession) -> bool:
    """True if the last run_periodic_reviews call on this session was
    skipped because another run was in progress (A-32)."""
    return bool(db.info.get(_REVIEW_SKIPPED_KEY))


def _pg_engine(db: DBSession):
    """The Engine behind ``db`` when it is PostgreSQL, else None."""
    try:
        bind = db.get_bind()
        if bind.dialect.name != "postgresql":
            return None
    except Exception:
        return None
    return getattr(bind, "engine", bind)


def _pg_lock_params(site_id: Optional[int]) -> dict:
    return {"k": _REVIEW_PG_LOCK_ID & 0x7FFFFFFF, "s": int(site_id or 0)}


def _pg_try_lock(db: DBSession, site_id: Optional[int] = None):
    """Cross-process review lock on PostgreSQL. Returns None on other
    dialects, False when another process holds the lock, else the DEDICATED
    Connection holding it (pass to _pg_unlock).

    B-10: the session-level advisory lock used to be taken on the request
    Session's connection; the run's db.commit() returned that connection to
    the pool, so pg_advisory_unlock ran on a different backend (no-op) and
    the lock leaked on the pooled connection - every later run for the site
    was then skipped. The lock now lives on a connection checked out from
    the engine for the whole run and released on that same connection.
    Two-key form (_REVIEW_PG_LOCK_ID, site_id); 0 = unscoped. Not an xact
    lock: the run commits more than once."""
    engine = _pg_engine(db)
    if engine is None:
        return None
    from sqlalchemy import text
    conn = engine.connect()
    try:
        got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k, :s)"),
                                _pg_lock_params(site_id)).scalar())
        conn.commit()  # end the autobegun txn; the session-level lock stays held
    except Exception:
        conn.close()
        raise
    if not got:
        conn.close()
        return False
    return conn


def _pg_unlock(conn, site_id: Optional[int] = None) -> None:
    """Release the advisory lock on the SAME connection that took it, then
    close it. If the unlock fails the connection is invalidated (its backend
    session ends, which releases every session-level lock) instead of being
    returned to the pool still holding the lock."""
    from sqlalchemy import text
    try:
        try:
            conn.execute(text("SELECT pg_advisory_unlock(:k, :s)"), _pg_lock_params(site_id))
            conn.commit()
        except Exception:
            log.exception("run_periodic_reviews: releasing advisory lock failed; "
                          "invalidating the lock connection")
            try:
                conn.invalidate()
            except Exception:
                log.exception("run_periodic_reviews: invalidating lock connection failed")
    finally:
        try:
            conn.close()
        except Exception:
            log.exception("run_periodic_reviews: closing lock connection failed")


def run_periodic_reviews(db: DBSession, site_id: Optional[int] = None,
                         only: Optional[Iterable[str]] = None) -> dict:
    """Run all periodic reviews (see _run_periodic_reviews), unless another
    run is already in progress - then return {REVIEW_SKIPPED_STAT: 0}
    immediately without touching findings (A-32).

    only: review function names to run (a targeted re-check, e.g. after a
    management-network declaration); None = every review.  A targeted run
    auto-resolves like a full one but does not replace the "last review run"
    information.

    site_id: review only that site's data (every query is scoped, findings
    are created in / auto-resolved within that site only, the run lock and
    the failed/auto-resolved bookkeeping are per site). None = legacy
    unscoped run over all data."""
    db.info[_REVIEW_SKIPPED_KEY] = False
    sid = None if site_id is None else int(site_id)
    lock = _acquire_review_lock(sid)
    if lock is None:
        log.warning("run_periodic_reviews(site_id=%s): another run is in progress in "
                    "this process; skipped", sid)
        db.info[_REVIEW_SKIPPED_KEY] = True
        return {REVIEW_SKIPPED_STAT: 0}
    try:
        pg = _pg_try_lock(db, sid)
        if pg is False:
            log.warning("run_periodic_reviews(site_id=%s): another process holds the "
                        "review lock; skipped", sid)
            db.info[_REVIEW_SKIPPED_KEY] = True
            return {REVIEW_SKIPPED_STAT: 0}
        try:
            with analysis_site(db, sid):
                # (only passed when given: keeps the single-argument call shape)
                return (_run_periodic_reviews(db) if only is None
                        else _run_periodic_reviews(db, only=only))
        finally:
            if pg is not None:
                _pg_unlock(pg, sid)
    finally:
        lock.release()


def _run_periodic_reviews(db: DBSession, only: Optional[Iterable[str]] = None) -> dict:
    """Run every periodic review of the bound site (see _run_periodic_reviews_body).
    HA clusters: findings about non-primary members' rules are suppressed for
    the run (the cluster is one configuration)."""
    from app.parsers.firewall_groups import ha_secondary_rule_ids
    try:
        db.info[_HA_SECONDARY_RULES_KEY] = ha_secondary_rule_ids(db)
    except Exception:
        log.warning("HA cluster lookup failed; member findings not suppressed", exc_info=True)
        db.info[_HA_SECONDARY_RULES_KEY] = set()
    try:
        return _run_periodic_reviews_body(db, only=only)
    finally:
        db.info.pop(_HA_SECONDARY_RULES_KEY, None)


def _run_periodic_reviews_body(db: DBSession, only: Optional[Iterable[str]] = None) -> dict:
    """
    Run all periodic review functions and commit. Returns
    {review_function_name: number_of_NEW_findings} - every value is an int
    because callers sum stats.values().

    Failure isolation (T3-17): each review runs in its own SAVEPOINT. A
    review that raises is rolled back on its own (its partial writes and
    escalations are discarded, and on PostgreSQL the transaction stays
    usable), logged with its traceback, counted as 0 in stats and listed in
    failed_reviews(db); every other review's findings are still committed.

    Auto-resolve (F-04): see _AUTO_RESOLVE_CHECKS. Counts per review are in
    auto_resolved_counts(db); IACS_AUTO_RESOLVE=false disables it. Failed
    reviews and reviews that marked their run incomplete never auto-resolve.

    Performance notes:
    - The topology diff (compute_diff) is computed once and shared between
      review_session_no_permitting_rule and review_unused_policies so that
      the full NetworkSession table is loaded only once per run.
    - Phase-6 twin checks share one _TwinRunContext: zone resolver, one
      grouped observed-traffic query, one permit-rule query and one
      open-finding query per check (T3-18).
    """
    from app.parsers.topology_diff import compute_diff

    stats: dict = {}
    escalations: dict[str, int] = {}
    failed: list[str] = []
    auto_resolved: dict[str, int] = {}
    db.info[_FAILED_REVIEWS_KEY] = failed
    db.info[_AUTO_RESOLVED_KEY] = auto_resolved
    run_site = current_site(db)
    db.info.setdefault(_FAILED_BY_SITE_KEY, {})[run_site] = failed
    db.info.setdefault(_AUTO_RESOLVED_BY_SITE_KEY, {})[run_site] = auto_resolved
    resolve = auto_resolve_enabled()
    esc_start = escalation_count(db)
    truncated: dict[str, dict] = {}
    skipped_unknown: dict[str, int] = {}

    only_set = None if only is None else set(only)

    def _wanted(*fns) -> bool:
        return only_set is None or any(f.__name__ in only_set for f in fns)

    def _run(fn, **kwargs) -> bool:
        if not _wanted(fn):
            return True
        before = escalation_count(db)
        seen: set = set()
        unevaluated: set = set()
        db.info[_SEEN_KEY] = seen
        db.info[_RUN_FINDINGS_KEY] = {}
        restate: dict = {}
        db.info[_RESTATE_KEY] = restate
        db.info[_UNEVALUATED_KEY] = unevaluated
        db.info.pop(_INCOMPLETE_KEY, None)
        db.info.pop(_TRUNCATED_KEY, None)
        db.info.pop(_SKIPPED_UNKNOWN_KEY, None)
        db.info.pop(_UNKNOWN_HOSTS_KEY, None)
        try:
            ok, findings = _run_isolated(db, f"Periodic review {fn.__name__}", fn, db, **kwargs)
        finally:
            db.info.pop(_SEEN_KEY, None)
            db.info.pop(_RUN_FINDINGS_KEY, None)
            db.info.pop(_RESTATE_KEY, None)
            db.info.pop(_UNEVALUATED_KEY, None)
            incomplete = db.info.pop(_INCOMPLETE_KEY, None)
            trunc = db.info.pop(_TRUNCATED_KEY, None)
            n_unknown = db.info.pop(_SKIPPED_UNKNOWN_KEY, 0)
            unknown_hosts = db.info.pop(_UNKNOWN_HOSTS_KEY, None) or set()
        if trunc:
            truncated[fn.__name__] = dict(trunc)
        if n_unknown:
            skipped_unknown[fn.__name__] = int(n_unknown)
        _run_isolated(db, f"Record evaluation {fn.__name__}", _record_evaluation,
                      db, fn.__name__, ok, incomplete)
        if not ok:
            stats[fn.__name__] = 0
            failed.append(fn.__name__)
            return False
        stats[fn.__name__] = len(findings)
        if restate and not incomplete:
            _run_isolated(db, f"Restate {fn.__name__}", _apply_restatements, db, restate)
        escalated = escalation_count(db) - before
        if escalated:
            escalations[fn.__name__] = escalated
        checks = _AUTO_RESOLVE_CHECKS.get(fn.__name__)
        if resolve and checks:
            if incomplete:
                log.info("Auto-resolve skipped for %s: %s", fn.__name__, incomplete)
            else:
                rok, n = _run_isolated(db, f"Auto-resolve {fn.__name__}",
                                       _auto_resolve, db, fn.__name__, checks, seen,
                                       unevaluated, unknown_hosts)
                if unevaluated:
                    log.info("Auto-resolve for %s kept findings of %d logical rule(s) "
                             "that could not be fully evaluated", fn.__name__,
                             len(unevaluated))
                if rok and n:
                    auto_resolved[fn.__name__] = n
        return True

    # LS-01: routing-switch SVI levels follow the firewall labels / VLANs
    from app.parsers import l3_switch as _l3sw
    _run_isolated(db, "Periodic reviews: L3 switch SVI levels", _l3sw.refresh_levels, db)

    # NAT tabletop P-04 / P-05: NAT'd sessions first - a session to a VIP
    # is judged as the host it reaches, and a source-NAT'd one as its real
    # source when the pre-NAT capture shows it.  Full runs only.
    if only_set is None:
        from app.parsers import nat_sessions as _nat_sessions
        ok_nat, nat_stats = _run_isolated(db, "Periodic reviews: NAT session reconcile",
                                          _nat_sessions.reconcile, db)
        if ok_nat and nat_stats and (nat_stats.get("dnat_rewritten") or nat_stats.get("snat_attributed")
                                     or nat_stats.get("merged") or nat_stats.get("reverted")):
            from app.parsers.traffic_findings import check_unauthorized_industrial_writes as _cw
            _run_isolated(db, "Periodic reviews: industrial writes after NAT", _cw, db,
                          commit=False, close_stale=True)

    # Shared expensive resources — computed once, passed to each consumer.
    # On failure the consumers recompute (and fail, if they do, in isolation).
    if _wanted(review_session_no_permitting_rule, review_unused_policies):
        ok, shared_diff = _run_isolated(db, "Periodic reviews: compute_diff", compute_diff, db)
    else:
        ok, shared_diff = False, None
    ok_diff = ok

    # N-15: true session-vs-baseline drift (no topology diff needed).
    _run(review_conduit_matrix_drift)
    for fn, kwargs in [
        (review_session_no_permitting_rule, {"_diff": shared_diff if ok else None}),
        (review_unused_policies,            {"_diff": shared_diff if ok else None}),
    ]:
        _run(fn, **kwargs)

    # --- all other reviews (plain db-only calls) ---
    for fn in [
        review_denied_trends,
        review_cleartext_protocols,
        review_mgmt_protocols,
        review_ot_it_dependencies,
        review_cleartext_credentials,
        review_unknown_devices,
        review_ip_conflicts,
        review_misplaced_devices,
        review_shadow_rules,
        # Phase 2: LLDP-role-enabled checks
        review_historian_in_control_zone,
        review_wireless_in_ot_zone,
        review_sis_isolation,
        review_transient_devices,
        review_switch_port_nac,
        review_switch_unused_ports,
        review_default_credentials,
        review_weak_tls,
        review_single_path_critical_devices,
        review_undocumented_lldp_devices,
        # Phase 2: CTR-only entries now with implementations
        review_mgmt_access_from_wrong_zone,
        review_mgmt_access_not_restricted,
        review_no_path_redundancy,
        review_firmware_not_documented,
        # Phase 3: attestation-backed zone documentation controls
        review_zone_documentation,
        # Phase 4: NTP sync (9.3) — FortiGate config + pcap NetworkSession
        review_ntp_sync,
        # Phase 5: NetworkSession-based fallback checks (run when FAZ is unavailable)
        review_ns_it_ot_bypass,
        review_ns_ot_internet_egress,
        review_ns_remote_access_bypass,
        review_ns_scanning_anomaly,
        review_ns_remote_access_app,
        review_ns_mgmt_from_non_admin,
        # Phase 5: VLAN topology checks (always run — no FAZ dependency)
        review_vlan_zone_mismatch,
        review_ghost_vlans,
        review_intervlan_routing,
    ]:
        _run(fn)

    # Phase 6: FirewallRule-based twin checks (policy gap detection). These
    # fire from parsed policy alone; severity escalates when traffic between
    # the rule's resolved Purdue levels is observed. The zone→Purdue resolver
    # and the rest of the per-run context are built once and shared.
    # A targeted run that asks for any twin runs the whole twin family: the
    # related_checks evidence is computed across all of them.
    twins_wanted = _wanted(*_RULE_TWIN_CHECKS)
    if twins_wanted or _wanted(review_disabled_rules):
        ok, resolver = _run_isolated(db, "Phase 6 zone resolver", _rule_zone_purdue, db)
    else:
        ok, resolver = False, None
    ctx = _TwinRunContext(db, resolver) if ok and twins_wanted else None
    if twins_wanted:
        saved, only_set = only_set, None
        try:
            for fn in _RULE_TWIN_CHECKS:
                if not _run(fn, _resolver=resolver if ok else None, _ctx=ctx) and ctx is not None:
                    ctx.discard(_TWIN_CHECK_NAME.get(fn.__name__, fn.__name__))
        finally:
            only_set = saved
    if ctx is not None:
        _run_isolated(db, "Phase 6 related_checks", ctx.finalize_related)
    # Disabled rules flagged for removal (3.8 / SR 7.7); shares the resolver.
    _run(review_disabled_rules, _resolver=resolver if ok else None)
    # HA clusters / paired firewalls (operator-declared groups)
    from app.parsers import firewall_groups as _fg
    _run(_fg.review_ha_config_drift)
    _run(_fg.review_paired_firewall_vendor_diversity)
    # H-05: L1 controllers sharing a segment with L2 hosts
    from app.parsers import segments as _seg
    _run(_seg.review_flat_control_segments)
    _run(_seg.review_multi_homed_hosts)       # IO-02
    _run(_seg.review_rogue_dhcp_servers)      # IO-04
    _run(review_dead_default_gateways)        # IO-08
    # IEC 62443-3-2: zone pairs communicating with no documented conduit -
    # the only check that reads the zone documentation (app/zone_findings.py)
    from app import zone_findings as _zf
    _run(_zf.review_undocumented_conduits)
    _run(_zf.review_multi_zone_membership)
    _run(_zf.review_policies_spanning_conduits)       # SF-6
    _run(_zf.review_blocked_cross_zone_attempts)      # SF-5
    # H-02: VPN destinations judged from the operator's interface levels
    from app.parsers import vpn as _vpn
    _run(_vpn.review_vpn_config_destinations)
    if only_set is None:
        # H-12: industrial-write findings whose source is approved by now (a
        # capture uploaded before the baseline is flagged fail-open)
        from app.parsers import mgmt_networks as _mg
        _run_isolated(db, "Industrial write approvals",
                      lambda d: _mg._close_engineering_writes(d, _mg.build_context(d)), db)
        from app.parsers.traffic_findings import refresh_write_wording as _rww
        _run_isolated(db, "Industrial write wording (RS-08)", _rww, db)
    # D-05: chain-aware twins over the Access Review rows (several firewalls
    # in series).  The enumeration is computed once per run and shared with
    # the classification sync below through db.info["access_paths.run_cache"].
    from app.parsers import chain_findings as _cf
    db.info[_cf._RUN_CACHE_KEY] = {}
    try:
        _run(_cf.review_access_path_truncation)      # MP-08
        _run(_cf.review_chain_it_ot_bypass)
        _run(_cf.review_chain_mgmt_wrong_zone)
        _run(_cf.review_chain_ot_upward_skip)
        _run(_cf.review_dead_end_permits)
        _run(_cf.review_dmz_bypass)
        _run(_cf.review_path_internet_egress)
        _run(_vpn.review_vpn_direct_to_ot)
        from app.parsers import nat_findings as _natf
        _run(_natf.review_nat_hides_source_into_ot)
        from app.parsers import fw_interfaces as _fwi
        _run(_fwi.review_implicit_permits)
        from app.parsers import l3_switch as _l3
        _run(_l3.review_l3_switches)
        # Access Review classifications (docs/access-path-review.md phase 4):
        # last, so the automatic findings it confirms / acknowledges exist.
        _run(_review_access_path_classifications)
    finally:
        db.info.pop(_cf._RUN_CACHE_KEY, None)
    if ok and resolver is not None:
        log.info(
            "Phase 6 zone resolution: %d rule side(s) resolved, %d unresolved "
            "(%d unresolved zone token(s)) — unresolved sides are skipped by "
            "level-based checks",
            resolver.sides_resolved, resolver.sides_unresolved, resolver.tokens_unresolved,
        )

    # Stats stay {review_name: new_findings} (callers sum the values), so
    # escalations of already-open findings are reported via the log only.
    if escalations:
        log.info(
            "Periodic reviews escalated %d existing open finding(s): %s",
            sum(escalations.values()), escalations,
        )
    if failed:
        log.error(
            "Periodic reviews: %d review(s) failed and were rolled back "
            "(other reviews committed): %s", len(failed), failed,
        )
    if auto_resolved:
        log.info("Periodic reviews auto-resolved %d finding(s): %s",
                 sum(auto_resolved.values()), auto_resolved)

    db.commit()
    info = {
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "site_id": run_site,
        "failed_reviews": list(failed),
        "escalations": escalation_count(db) - esc_start,
        "auto_resolved": dict(auto_resolved),
        "auto_resolve_enabled": resolve,
        # B-06: {review: {input label: rows not evaluated (None = unknown)}}
        "truncated": truncated,
        # B-06: topology diff coverage (all sessions unless explicitly capped)
        "topology_diff": ({k: shared_diff.get(k) for k in (
            "sessions_total", "sessions_evaluated", "sessions_truncated")}
            if ok_diff and isinstance(shared_diff, dict) else None),
        # B-20: {review: sessions/hosts skipped for unknown Purdue level}
        "skipped_unknown_level": skipped_unknown,
    }
    if only_set is None:
        _last_review_info.clear()
        _last_review_info.update(info)
        _last_review_info_by_site[run_site] = dict(info)
    return stats


# Multi-site: every public review_* function takes an optional keyword-only
# site_id and then runs scoped to that site (app.parsers.site_scope).
scope_module(globals(), ("review_",), names=("rules_not_judged",))
