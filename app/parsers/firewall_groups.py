"""
HA clusters and paired firewalls (operator-confirmed FirewallGroup rows).

Two relationships that look alike on a diagram and behave in opposite ways:

``ha``      HA cluster - two (or more) configs of ONE logical firewall.  The
            members share one configuration and traffic passes ONE of them,
            so the analysis uses the PRIMARY member's rules as the cluster's
            single enforcement point (reachability, access paths, chain
            findings), compares every other member with it (``ha_config_drift``)
            and does not report a member's findings twice.
``paired``  "Paired firewall" (NIST SP 800-82 paired-firewall DMZ) - firewalls,
            or HA clusters, enforcing ONE boundary in SERIES, usually from two
            vendors.  Every crossing passes all of them, so the cross-firewall
            asymmetric-permit check compares exactly these; vendor diversity is
            confirmed by an operator attestation (checklist ``PF-<group id>``,
            ``paired_firewall_vendor_diversity`` until attested).

Both are declared by the operator; the module also SUGGESTS them (HA: same
``config system ha`` group name / id; paired: firewalls with the same set of
interface Purdue levels that are linked to each other) - suggestions never
change the analysis until confirmed.

All functions run inside the caller's site binding (``analysis_site``).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy.orm import Session as DBSession

from app.models import ACTIVE_FINDING_STATUSES, Attestation, Finding, Firewall, FirewallGroup, FirewallInterface, FirewallRule

log = logging.getLogger(__name__)

KIND_HA, KIND_PAIRED = "ha", "paired"
KINDS = (KIND_HA, KIND_PAIRED)
CHECK_DRIFT = "ha_config_drift"
CHECK_DIVERSITY = "paired_firewall_vendor_diversity"
ATTEST_PREFIX = "PF-"
ATTEST_STALE_DAYS = 365
_NOTES_MAX = 2048


class GroupError(ValueError):
    """422 by default; ``status`` 404 / 409 for those cases."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


# ----------------------------------------------------------------- lookups --
def attestation_id(group_id: int) -> str:
    return f"{ATTEST_PREFIX}{int(group_id)}"


def group_of_attestation(db: DBSession, checklist_id: str) -> Optional[FirewallGroup]:
    """The paired group a ``PF-<id>`` checklist id names (this site), or None."""
    cid = str(checklist_id or "")
    if not cid.startswith(ATTEST_PREFIX):
        return None
    try:
        gid = int(cid[len(ATTEST_PREFIX):])
    except ValueError:
        return None
    g = db.query(FirewallGroup).filter(FirewallGroup.id == gid).first()
    return g if g is not None and g.kind == KIND_PAIRED else None


def _members(db: DBSession, g: FirewallGroup) -> list[Firewall]:
    col = Firewall.ha_group_id if g.kind == KIND_HA else Firewall.paired_group_id
    return db.query(Firewall).filter(col == g.id).order_by(Firewall.id).all()


def primary_of(db: DBSession, g: FirewallGroup, members: Optional[list] = None) -> Optional[Firewall]:
    members = members if members is not None else _members(db, g)
    for m in members:
        if m.id == g.primary_firewall_id:
            return m
    return members[0] if members else None


def ha_secondary_ids(db: DBSession) -> set[int]:
    """Firewall ids that are NON-primary HA members: their configuration is
    the primary's, so the analysis skips them as enforcement points."""
    out: set[int] = set()
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_HA).all():
        members = _members(db, g)
        prim = primary_of(db, g, members)
        out |= {m.id for m in members if prim is None or m.id != prim.id}
    return out


def ha_secondary_rule_ids(db: DBSession) -> set[int]:
    sec = ha_secondary_ids(db)
    if not sec:
        return set()
    return {r[0] for r in db.query(FirewallRule.id).filter(FirewallRule.firewall_id.in_(sorted(sec)))}


def unit_of(fw: Firewall) -> tuple:
    """Grouping unit of a firewall: its HA cluster, else itself."""
    return ("ha", fw.ha_group_id) if fw.ha_group_id is not None else ("fw", fw.id)


def _levels(db: DBSession, fw_id: int) -> frozenset:
    return frozenset(r[0] for r in db.query(FirewallInterface.purdue_level)
                     .filter(FirewallInterface.firewall_id == fw_id,
                             FirewallInterface.purdue_level.isnot(None)).distinct())


# ------------------------------------------------------------------- dicts --
def _fw_brief(fw: Firewall) -> dict:
    return {"id": fw.id, "name": fw.name, "vendor": fw.vendor,
            "ha_mode": fw.ha_mode, "ha_cfg_group": fw.ha_cfg_group}


def _current_attestation(db: DBSession, g: FirewallGroup) -> Optional[Attestation]:
    return (db.query(Attestation)
            .filter(Attestation.checklist_id == attestation_id(g.id),
                    Attestation.is_current == True)  # noqa: E712
            .order_by(Attestation.attested_at.desc()).first())


def group_dict(db: DBSession, g: FirewallGroup) -> dict:
    members = _members(db, g)
    out = {"id": g.id, "kind": g.kind, "name": g.name, "note": g.note,
           "created_by": g.created_by,
           "created_at": g.created_at.isoformat() if g.created_at else None,
           "members": [_fw_brief(m) for m in members]}
    if g.kind == KIND_HA:
        prim = primary_of(db, g, members)
        out["primary_firewall_id"] = prim.id if prim else None
    else:
        # vendors AS RECORDED from the uploaded configs - informational only;
        # diversity itself is confirmed by the operator (attestation).
        out["recorded_vendors"] = sorted({(m.vendor or "unknown") for m in members})
        att = _current_attestation(db, g)
        out["attestation_checklist_id"] = attestation_id(g.id)
        out["vendor_diversity_attested"] = None if att is None else {
            "attested_by": att.attested_by,
            "attested_at": att.attested_at.isoformat() if att.attested_at else None,
            "notes": att.notes}
    return out


def list_groups(db: DBSession) -> list[dict]:
    return [group_dict(db, g) for g in
            db.query(FirewallGroup).order_by(FirewallGroup.kind, FirewallGroup.id).all()]


# ----------------------------------------------------------------- declare --
def _load_firewalls(db: DBSession, firewall_ids: Iterable) -> list[Firewall]:
    ids = list(dict.fromkeys(int(i) for i in firewall_ids or ()))
    if len(ids) < 2:
        raise GroupError("a group needs at least two firewalls")
    if len(ids) > 8:
        raise GroupError("a group has at most eight firewalls")
    fws = db.query(Firewall).filter(Firewall.id.in_(ids)).all()
    missing = sorted(set(ids) - {f.id for f in fws})
    if missing:
        raise GroupError(f"firewall id={missing[0]} not found in this site", 404)
    by_id = {f.id: f for f in fws}
    return [by_id[i] for i in ids]


def _unique_name(db: DBSession, kind: str, wanted: Optional[str], fws: list) -> str:
    name = (wanted or "").strip()
    if len(name) > 64:
        raise GroupError("name: at most 64 characters")
    if not name:
        name = " + ".join(f.name for f in fws)[:64]      # the UI shows the kind next to it
    if db.query(FirewallGroup).filter(FirewallGroup.kind == kind, FirewallGroup.name == name).first():
        raise GroupError(f"a {kind} group named {name!r} already exists", 409)
    return name


def declare_ha(db: DBSession, site_id: int, firewall_ids, primary_id=None, name=None,
               created_by=None, note=None) -> FirewallGroup:
    """Declare an HA cluster.  ``primary_id`` (default: the first id) is the
    member whose rules the analysis uses.  A firewall can be in one cluster;
    members keep any paired-firewall membership of the cluster.  Flushes,
    does not commit."""
    fws = _load_firewalls(db, firewall_ids)
    taken = [f for f in fws if f.ha_group_id is not None]
    if taken:
        raise GroupError(f"firewall {taken[0].name!r} is already in an HA cluster", 409)
    pids = {f.paired_group_id for f in fws if f.paired_group_id is not None}
    if len(pids) > 1:
        raise GroupError("the members belong to different paired-firewall groups; an HA "
                         "cluster is one logical firewall", 409)
    prim = fws[0] if primary_id is None else next((f for f in fws if f.id == int(primary_id)), None)
    if prim is None:
        raise GroupError("primary_id must be one of the members")
    g = FirewallGroup(site_id=site_id, kind=KIND_HA, name=_unique_name(db, KIND_HA, name, fws),
                      primary_firewall_id=prim.id, note=(str(note)[:2000] if note else None),
                      created_by=(str(created_by)[:128] if created_by else None))
    db.add(g)
    db.flush()
    pg = next(iter(pids), None)
    for f in fws:
        f.ha_group_id = g.id
        if pg is not None:
            f.paired_group_id = pg            # the cluster is ONE member of the pair
    db.flush()
    consolidate_ha_findings(db)
    log.info("HA cluster %r declared: %s (primary %s)", g.name, [f.name for f in fws], prim.name)
    return g


def declare_paired(db: DBSession, site_id: int, firewall_ids, name=None,
                   created_by=None, note=None) -> FirewallGroup:
    """Declare a paired-firewall group (one boundary, in series).  A member
    that is part of an HA cluster brings the whole cluster.  At least two
    distinct units (standalone firewalls / HA clusters) are needed."""
    fws = _load_firewalls(db, firewall_ids)
    # expand HA clusters
    extra = []
    for f in fws:
        if f.ha_group_id is not None:
            extra += [m for m in db.query(Firewall).filter(Firewall.ha_group_id == f.ha_group_id)
                      if m.id not in {x.id for x in fws + extra}]
    fws += extra
    if len({unit_of(f) for f in fws}) < 2:
        raise GroupError("a paired firewall needs two different firewalls (an HA cluster "
                         "counts as one)")
    taken = [f for f in fws if f.paired_group_id is not None]
    if taken:
        raise GroupError(f"firewall {taken[0].name!r} is already in a paired-firewall group", 409)
    # MP-04: a paired group enforces ONE level pair in series.  Members whose
    # labels already place them on different level pairs would land on
    # different boundaries (one of them silently off the path), so refuse.
    mismatch = member_level_mismatch(db, fws)
    if mismatch:
        raise GroupError("paired firewalls must enforce the same level pair: " + mismatch
                         + ". Label the transit link between them as the far side on each "
                           "member (outer member: the inner level; inner member: the outer "
                           "level) or correct the labels first.")
    reps, seen_units = [], set()           # one name per unit for the default label
    for f in fws:
        if unit_of(f) not in seen_units:
            seen_units.add(unit_of(f))
            reps.append(f)
    g = FirewallGroup(site_id=site_id, kind=KIND_PAIRED,
                      name=_unique_name(db, KIND_PAIRED, name, reps),
                      note=(str(note)[:2000] if note else None),
                      created_by=(str(created_by)[:128] if created_by else None))
    db.add(g)
    db.flush()
    for f in fws:
        f.paired_group_id = g.id
    db.flush()
    log.info("Paired firewall %r declared: %s", g.name, [f.name for f in fws])
    return g


def delete_group(db: DBSession, group_id: int) -> FirewallGroup:
    g = db.query(FirewallGroup).filter(FirewallGroup.id == int(group_id)).first()
    if g is None:
        raise GroupError(f"firewall group {group_id} not found", 404)
    col = Firewall.ha_group_id if g.kind == KIND_HA else Firewall.paired_group_id
    for f in db.query(Firewall).filter(col == g.id):
        if g.kind == KIND_HA:
            f.ha_group_id = None
        else:
            f.paired_group_id = None
    db.delete(g)
    db.flush()
    return g


# ------------------------------------------------------------- suggestions --
def suggest_ha(db: DBSession) -> list[dict]:
    """Firewalls not yet in a cluster whose uploaded configs carry the same
    ``config system ha`` group (name / id) and an HA mode."""
    groups: dict[str, list[Firewall]] = {}
    for f in db.query(Firewall).filter(Firewall.ha_group_id.is_(None),
                                       Firewall.ha_mode.isnot(None),
                                       Firewall.ha_cfg_group.isnot(None)).order_by(Firewall.id):
        groups.setdefault(f.ha_cfg_group, []).append(f)
    return [{"kind": KIND_HA, "firewalls": [_fw_brief(f) for f in fws],
             "reason": f"configs share HA group {key!r} (mode {fws[0].ha_mode})"}
            for key, fws in sorted(groups.items()) if len(fws) >= 2]


def _linked(db: DBSession, a: int, b: int) -> bool:
    """MP-18: the two firewalls are joined by a confirmed link or shared
    segment whose two ends are labelled at DIFFERENT levels (or inside vs
    outside) - one box behind the other.  Two ends at the same level are
    two uplinks on one segment: parallel boxes, never a series pair."""
    ia = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == a).all()
    ib = {i.id: i for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == b)}
    segs_b = {}
    for i in ib.values():
        if i.segment:
            segs_b.setdefault(i.segment, []).append(i)

    def _series_ends(x, y) -> bool:
        if x.purdue_level is not None and y.purdue_level is not None:
            return x.purdue_level != y.purdue_level
        if x.side in ("inside", "outside") and y.side in ("inside", "outside"):
            return x.side != y.side
        return False

    for i in ia:
        peer = ib.get(i.connects_to_interface_id)
        if peer is not None and _series_ends(i, peer):
            return True
        if i.segment:
            if any(_series_ends(i, j) for j in segs_b.get(i.segment, ())):
                return True
    return False


def suggest_paired(db: DBSession) -> list[dict]:
    """Units (standalone firewalls / HA cluster primaries) not yet paired that
    touch the SAME two or more Purdue levels and are linked to each other
    inside-to-outside (the link's ends at different levels / sides) - two
    firewalls in series on one boundary.  MP-18: two firewalls whose link
    joins same-level legs share a segment in parallel and are not suggested."""
    secondary = ha_secondary_ids(db)
    units = [f for f in db.query(Firewall).filter(Firewall.paired_group_id.is_(None))
             .order_by(Firewall.id) if f.id not in secondary]
    by_levels: dict[frozenset, list[Firewall]] = {}
    for f in units:
        lv = _levels(db, f.id)
        if len(lv) >= 2:
            by_levels.setdefault(lv, []).append(f)
    out = []
    for lv, fws in sorted(by_levels.items(), key=lambda kv: sorted(kv[0])):
        # connected components of the "linked" relation
        left = list(fws)
        while left:
            comp, frontier = [left.pop(0)], None
            frontier = list(comp)
            while frontier:
                cur = frontier.pop()
                for other in list(left):
                    if _linked(db, cur.id, other.id) or _linked(db, other.id, cur.id):
                        left.remove(other)
                        comp.append(other)
                        frontier.append(other)
            if len(comp) >= 2:
                from app.purdue import fmt_level
                lvls = " / ".join(fmt_level(x) for x in sorted(lv, reverse=True))
                out.append({"kind": KIND_PAIRED, "firewalls": [_fw_brief(f) for f in comp],
                            "levels": sorted(lv),
                            "reason": f"linked firewalls that all enforce {lvls}: in series on "
                                      "one boundary"})
    return out


# ------------------------------------------------------------- HA findings --
def _rule_key(r: FirewallRule) -> tuple:
    def n(v):
        return (str(v).strip().lower() if v not in (None, "") else "")
    return (n(r.vdom), n(r.policy_id))


def _rule_body(r: FirewallRule) -> tuple:
    def n(v):
        return (str(v).strip().lower() if v not in (None, "") else "")
    return (n(r.action), bool(r.enabled), n(r.src_zone), n(r.dst_zone), n(r.src), n(r.dst),
            n(r.protocol), n(r.dst_port))


def _rule_label(r: FirewallRule) -> str:
    pid = r.policy_id if r.policy_id is not None else f"row {r.id}"
    vd = f" (vdom {r.vdom})" if r.vdom else ""
    nm = f" {r.policy_name}" if r.policy_name else ""
    return f"#{pid}{vd}{nm}"


def _rule_detail(r: FirewallRule) -> dict:
    return {"policy_id": r.policy_id, "vdom": r.vdom, "policy_name": r.policy_name,
            "action": r.action, "enabled": bool(r.enabled), "src_zone": r.src_zone,
            "dst_zone": r.dst_zone, "src": r.src, "dst": r.dst, "protocol": r.protocol,
            "dst_port": r.dst_port}


def _rules(db: DBSession, fw_id: int) -> dict:
    """{(vdom, policy_id): (first row, {body of every expanded row})} - a
    FortiOS policy expands to src x dst x service rows; all of them are the
    policy (AU full review B1: comparing the first row only missed drift
    in the other rows)."""
    out: dict = {}
    for r in db.query(FirewallRule).filter(FirewallRule.firewall_id == fw_id).order_by(FirewallRule.id):
        slot = out.setdefault(_rule_key(r), (r, set()))
        slot[1].add(_rule_body(r))
    return out


def drift(db: DBSession, primary: Firewall, member: Firewall) -> dict:
    """Policy differences of ``member`` against ``primary``:
    {"missing_on_member": [...], "extra_on_member": [...], "changed": [...]}"""
    a, b = _rules(db, primary.id), _rules(db, member.id)
    missing = [_rule_detail(a[k][0]) for k in a if k not in b]
    extra = [_rule_detail(b[k][0]) for k in b if k not in a]
    changed = [{"primary": _rule_detail(a[k][0]), "member": _rule_detail(b[k][0]),
                "rows_primary": len(a[k][1]), "rows_member": len(b[k][1])}
               for k in a if k in b and a[k][1] != b[k][1]]
    return {"missing_on_member": missing, "extra_on_member": extra, "changed": changed}


def review_ha_config_drift(db: DBSession) -> list:
    """SR 7.6 / SR 7.2 (checklist 7.4): the members of an HA cluster must run
    the same policy.  One finding per (cluster, non-primary member) whose
    policies differ from the primary's - after a failover the cluster would
    enforce the member's rules, not the reviewed ones.  high when a permit is
    involved, else medium.  Also folds duplicate member findings into the
    primary's (consolidate_ha_findings)."""
    from app.parsers import alert_engine as ae

    out = []
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_HA).order_by(FirewallGroup.id):
        members = _members(db, g)
        prim = primary_of(db, g, members)
        if prim is None:
            continue
        for m in members:
            if m.id == prim.id:
                continue
            d = drift(db, prim, m)
            n = len(d["missing_on_member"]) + len(d["extra_on_member"]) + len(d["changed"])
            if not n:
                continue
            permits = any((x.get("action") or "").lower() in ("accept", "permit", "allow", "pass")
                          for x in d["missing_on_member"] + d["extra_on_member"]
                          + [c["member"] for c in d["changed"]] + [c["primary"] for c in d["changed"]])
            parts = []
            if d["missing_on_member"]:
                parts.append(f"{len(d['missing_on_member'])} policy(ies) missing on {m.name}")
            if d["extra_on_member"]:
                parts.append(f"{len(d['extra_on_member'])} policy(ies) only on {m.name}")
            if d["changed"]:
                parts.append(f"{len(d['changed'])} policy(ies) differ")
            title = f"HA cluster {g.name!r}: {m.name} configuration differs from {prim.name} ({'; '.join(parts)})"
            text = (f"The members of HA cluster {g.name!r} should run one configuration. "
                    f"{m.name} differs from the primary {prim.name}: {'; '.join(parts)}. After a "
                    f"failover the cluster enforces {m.name}'s policy, not the reviewed one "
                    "(SR 7.6 network and security configuration settings, SR 7.2 resource "
                    "availability). Resynchronise the cluster (or correct the primary) and "
                    "re-upload both configs.")
            f = ae._make_finding(
                db, CHECK_DRIFT, title[:512], text,
                {"ha_group_id": g.id, "ha_group": g.name, "primary": prim.name, "member": m.name,
                 "differences": n, **{k: v[:50] for k, v in d.items()}},
                device_name=m.name, severity="high" if permits else "medium",
                dedup_evidence={"rule_key": f"ha_drift:{g.id}:{m.id}"})   # rule_key: a dedup field
            if f is not None:
                out.append(f)
    consolidate_ha_findings(db)
    return out


def consolidate_ha_findings(db: DBSession) -> int:
    """Close a non-primary HA member's OPEN config findings that the primary
    also has open (same check and policy): one configuration, one finding.
    Returns the number closed.  Flushes."""
    now = datetime.now(timezone.utc)
    closed = 0
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_HA):
        members = _members(db, g)
        prim = primary_of(db, g, members)
        if prim is None:
            continue
        pref = f"config:{prim.id}:"
        primary_open = {}
        for f in db.query(Finding).filter(Finding.source_ref.like(pref + "%"),
                                          Finding.status.in_(ACTIVE_FINDING_STATUSES)):
            primary_open[f.source_ref[len(pref):]] = f
        for m in members:
            if m.id == prim.id:
                continue
            mref = f"config:{m.id}:"
            for f in db.query(Finding).filter(Finding.source_ref.like(mref + "%"),
                                              Finding.status == "open"):
                twin = primary_open.get(f.source_ref[len(mref):])
                if twin is None:
                    continue         # only on the member: drift, keep it
                note = (f"Folded into HA cluster {g.name!r}: same configuration finding on "
                        f"primary {prim.name} (#{twin.id})")
                f.status, f.closed_at, f.updated_at = "closed", now, now
                f.notes = ((f.notes + " | ") if f.notes else "")[:_NOTES_MAX - len(note) - 3] + note
                closed += 1
    if closed:
        db.flush()
        log.info("HA clusters: %d duplicate member finding(s) folded into the primary", closed)
    return closed


# -------------------------------------------------- paired: vendor diversity --
def review_paired_firewall_vendor_diversity(db: DBSession) -> list:
    """Manual control (operator attestation): the members of a paired
    firewall are of different vendors, so one vendor's flaw or common
    misconfiguration cannot open the whole boundary (defence in depth /
    common-mode failure; NIST SP 800-82 paired-firewall DMZ).  A finding per
    paired group until a current attestation ``PF-<id>`` (< 365 days)
    exists.  The vendors recorded from the uploaded configs are shown as
    information only - the decision is the operator's.  Acknowledge the
    finding to accept a single-vendor pair as a documented risk."""
    from app.parsers import alert_engine as ae

    cutoff = datetime.now(timezone.utc) - timedelta(days=ATTEST_STALE_DAYS)
    out = []
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_PAIRED).order_by(FirewallGroup.id):
        att = _current_attestation(db, g)
        at = att.attested_at if att is not None else None
        if at is not None and at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        if at is not None and at >= cutoff:
            continue
        members = _members(db, g)
        units = {}
        for m in members:
            units.setdefault(unit_of(m), []).append(m)
        recorded = sorted({(m.vendor or "unknown") for m in members})
        reason = "attestation stale (> 365 days)" if att is not None else "no attestation on record"
        title = (f"Paired firewall {g.name!r}: confirm the firewalls are different vendors "
                 f"({reason})")
        text = (f"Paired firewall {g.name!r} ({', '.join(m.name for m in members)}) enforces one "
                "boundary with firewalls in series. Vendor diversity keeps one vendor's "
                "vulnerability or a shared misconfiguration from opening the whole boundary "
                "(defence in depth, ISA/IEC 62443-3-3 SR 5.1 / SR 5.2 zone boundary protection; "
                "NIST SP 800-82 paired-firewall DMZ). This is a manual check: confirm the vendors "
                f"with an attestation for checklist id {attestation_id(g.id)} (Attestation page), "
                "or acknowledge this finding to accept a single-vendor pair as a documented risk. "
                f"Vendors recorded from the uploaded configs (information only): {', '.join(recorded)}.")
        f = ae._make_finding(
            db, CHECK_DIVERSITY, title[:512], text,
            {"paired_group_id": g.id, "paired_group": g.name,
             "attestation_checklist_id": attestation_id(g.id),
             "members": [_fw_brief(m) for m in members], "recorded_vendors": recorded,
             "units": len(units), "reason": reason, "manual_check": True},
            device_name=members[0].name if members else None,
            dedup_evidence={"rule_key": f"paired_vendor_diversity:{g.id}"})
        if f is not None:
            out.append(f)
    return out


# ------------------------------------------------------------ MP-04 health --
def member_levels(db: DBSession, fw: Firewall) -> frozenset:
    """The Purdue levels a member's labelled interfaces touch, falling back
    to purdue_level_ingress / egress; empty = unknown."""
    lv = {r[0] for r in db.query(FirewallInterface.purdue_level)
          .filter(FirewallInterface.firewall_id == fw.id,
                  FirewallInterface.purdue_level.isnot(None)).distinct()}
    if not lv and fw.purdue_level_ingress is not None and fw.purdue_level_egress is not None:
        lv = {fw.purdue_level_ingress, fw.purdue_level_egress}
    return frozenset(lv)


def _fmt_levels(lv) -> str:
    return "↔".join(f"L{x:g}" for x in sorted(lv)) if lv else "no levels"


def member_level_mismatch(db: DBSession, fws: list) -> Optional[str]:
    """MP-04: text describing members that are placed on DIFFERENT level
    pairs (two or more labelled levels each, and the sets differ), or None.
    Members with fewer than two levels are not judged (not placed yet)."""
    placed = [(f, member_levels(db, f)) for f in fws]
    placed = [(f, lv) for f, lv in placed if len(lv) >= 2]
    if len({lv for _f, lv in placed}) <= 1:
        return None
    return ", ".join(f"{f.name} {_fmt_levels(lv)}" for f, lv in placed)


def members_linked(db: DBSession, fw_a: Firewall, fw_b: Firewall) -> bool:
    """True when a confirmed interface link or a shared segment joins the
    two firewalls."""
    for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_a.id,
                                                FirewallInterface.connects_to_interface_id.isnot(None)):
        peer = db.get(FirewallInterface, i.connects_to_interface_id)
        if peer is not None and peer.firewall_id == fw_b.id:
            return True
    segs_a = {r[0] for r in db.query(FirewallInterface.segment)
              .filter(FirewallInterface.firewall_id == fw_a.id, FirewallInterface.segment.isnot(None))}
    if segs_a:
        if db.query(FirewallInterface.id).filter(FirewallInterface.firewall_id == fw_b.id,
                                                 FirewallInterface.segment.in_(sorted(segs_a))).first():
            return True
    return False


def paired_group_warnings(db: DBSession) -> list[dict]:
    """MP-04: what is wrong with each declared paired group - members on
    different level pairs (one of them is off the path), members not placed
    at all, or no confirmed link / shared segment between the members (the
    asymmetric-permit check then compares whole rulesets).  Each entry:
    {group_id, group, kind: level_mismatch | unplaced_member | unlinked,
    members: [names], detail}."""
    out = []
    for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_PAIRED).order_by(FirewallGroup.id):
        members = _members(db, g)
        if not members:
            continue
        secondaries = ha_secondary_ids(db)
        units = [m for m in members if m.id not in secondaries]
        names = [m.name for m in units]
        lv = {m.id: member_levels(db, m) for m in units}
        unplaced = [m.name for m in units if len(lv[m.id]) < 2]
        if unplaced:
            out.append({"group_id": g.id, "group": g.name, "kind": "unplaced_member", "members": names,
                        "detail": ", ".join(unplaced) + " carries fewer than two interface levels, so "
                        "the pair is not enforced in series anywhere"})
        mm = member_level_mismatch(db, units)
        if mm:
            out.append({"group_id": g.id, "group": g.name, "kind": "level_mismatch", "members": names,
                        "detail": "members sit on different level pairs (" + mm + "); they are "
                        "evaluated on different boundaries, not in series"})
        for i, a in enumerate(units):
            for b in units[i + 1:]:
                if not members_linked(db, a, b):
                    out.append({"group_id": g.id, "group": g.name, "kind": "unlinked", "members": names,
                                "detail": f"no confirmed link or shared segment between {a.name} and "
                                f"{b.name}; the asymmetric-permit check compares their whole rulesets"})
    return out


# ------------------------------------------------------- serial-pair helper --
def confirmed_pair(db: DBSession, fw_a: Firewall, fw_b: Firewall) -> Optional[bool]:
    """Cross-firewall checks: True / False when a confirmed group decides
    whether the two linked firewalls enforce one boundary in series, None
    when neither firewall is in a confirmed paired group (fall back to the
    interface-level heuristic)."""
    if fw_a.paired_group_id is None and fw_b.paired_group_id is None:
        return None
    return fw_a.paired_group_id is not None and fw_a.paired_group_id == fw_b.paired_group_id
