"""
Checks in the compliance report (owner 2026-10-14: "the UI needs a list of all the
findings checks and a means to deselect findings not add into the report ... grouped
into selections, such as for deselecting all of the CIS fortinet checks.  Groups of
finding not selected should be listed in the Compliance report").

Per site, the operator leaves checks (or whole groups) out of the PDF, with an
optional reason.  The findings stay on the Findings page and in the exports; the
report leaves them out of its findings, severity summary and coverage, and lists
what was left out in "Checks excluded from this report".
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy.orm import Session as DBSession

# (key, label, description) in display order
GROUPS = (
    ("fortigate", "FortiGate configuration (CIS)",
     "Every check judged from an uploaded FortiGate configuration (config_*: hardening, admin access, "
     "VPN, logging, security profiles, policy hygiene)."),
    ("rules", "Firewall rule reviews", "Rule-level reviews of every vendor's policies (rule_*, shadowed, "
     "unused and disabled policies)."),
    ("paths", "Multi-firewall chains & access paths", "Paths through several firewalls and the Access Review "
     "(chain_*, cross_fw_*, path_*, access paths, DMZ bypass, dead ends)."),
    ("zones", "IEC 62443-3-2 zones & documentation", "Zone documentation attestations and the checks sourced "
     "from Zones & Conduits."),
    ("syslog", "Syslog / real-time events", "Checks raised from firewall log lines as they arrive."),
    ("traffic", "Traffic sessions (PCAP)", "Session checks on captured traffic (session_*)."),
    ("switches", "Switches, VLANs & LLDP", "Cisco / HP / FortiSwitch configuration, VLAN, port and LLDP checks."),
    ("network", "Network & asset reviews", "Periodic reviews of hosts, protocols, inventory, redundancy "
     "and the approved communication baseline."),
)
GROUP_LABEL = {k: label for k, label, _d in GROUPS}

_ZONE_CHECKS = {"undocumented_conduit", "host_in_multiple_zones", "network_in_multiple_zones",
                "conduit_service_blocked", "policy_spans_multiple_conduits", "blocked_cross_zone_attempts"}
_SWITCH_CHECKS = {"ghost_vlan", "intervlan_routing_unchecked", "undocumented_lldp_device", "wireless_in_ot_zone"}
_RULE_CHECKS = {"shadow_rule", "unused_policy", "disabled_rule"}


def check_group(name: str, category: Optional[str] = None) -> str:
    """The report-selection group of a check."""
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    n = name or ""
    if n in FORTIGATE_CONFIG_CHECKS or n.startswith("config_"):
        return "fortigate"
    if n.startswith("zone_doc") or n in _ZONE_CHECKS:
        return "zones"
    if n.startswith(("chain_", "cross_fw_", "path_", "access_path", "dead_end")) or n == "dmz_bypass":
        return "paths"
    if n.startswith("rule_") or n in _RULE_CHECKS:
        return "rules"
    if n.startswith(("switch_", "vlan_")) or n in _SWITCH_CHECKS:
        return "switches"
    if category == "real_time":
        return "syslog"
    if n.startswith("session_"):
        return "traffic"
    return "network"


def _why(name: str) -> Optional[str]:
    """First sentence of the check's "why this was flagged" text, as its description."""
    from app.explain import entry
    try:
        why = (entry(name) or {}).get("why") or ""
    except Exception:                                  # noqa: BLE001 - description only
        return None
    first = why.split(". ")[0].strip()
    return (first[:160] + ("…" if len(first) > 160 else "")) or None


def exclusions(db: DBSession, site_id: Optional[int]) -> dict:
    """check name -> {reason, excluded_by, excluded_at} of a site (empty for None)."""
    from app.models import ReportCheckExclusion
    if site_id is None:
        return {}
    out = {}
    for r in db.query(ReportCheckExclusion).filter(ReportCheckExclusion.site_id == site_id):
        out[r.check_name] = {"reason": r.reason, "excluded_by": r.excluded_by, "excluded_at": r.excluded_at}
    return out


def excluded_by_site(db: DBSession) -> dict:
    """site id -> set of excluded check names (sites with at least one)."""
    from app.models import ReportCheckExclusion
    out = {}
    for sid, name in db.query(ReportCheckExclusion.site_id, ReportCheckExclusion.check_name):
        out.setdefault(sid, set()).add(name)
    return out


def hidden_clause(db: DBSession, site_id: Optional[int]):
    """Owner 2026-10-14: the findings of a check left out of the report are hidden
    throughout the application (Findings page, counts, badges, exports) unless the
    caller asks for them.  Returns a SQLAlchemy clause that keeps every finding
    NOT excluded - None when nothing is excluded.  ``site_id`` None = every site,
    each with its own list."""
    from sqlalchemy import and_, not_
    from app.models import Finding
    ex = excluded_by_site(db)
    if site_id is not None:
        names = ex.get(site_id)
        return not_(Finding.check_name.in_(sorted(names))) if names else None
    parts = [not_(and_(Finding.site_id == sid, Finding.check_name.in_(sorted(names)))) for sid, names in ex.items() if names]
    return and_(*parts) if parts else None


def hide_excluded(db: DBSession, query, site_id: Optional[int], include_excluded: bool = False):
    """Apply ``hidden_clause`` to a Finding query (no-op with include_excluded)."""
    if include_excluded:
        return query
    clause = hidden_clause(db, site_id)
    return query if clause is None else query.filter(clause)


def selection(db: DBSession, site_id: int) -> dict:
    """Every check of the catalogue, grouped, with whether it is in the report,
    the reason it is not, and the site's open + acknowledged findings of it."""
    from sqlalchemy import func
    from app.models import Finding
    from generate_report import check_catalogue
    cat = check_catalogue()
    ex = exclusions(db, site_id)
    counts = Counter()
    for name, n in (db.query(Finding.check_name, func.count(Finding.id))
                    .filter(Finding.site_id == site_id, Finding.status.in_(("open", "acknowledged")))
                    .group_by(Finding.check_name)):
        counts[name] = n
    groups = {k: {"key": k, "label": label, "description": d, "checks": []} for k, label, d in GROUPS}
    for name in sorted(cat):
        info = cat[name]
        e = ex.get(name)
        groups[check_group(name, info.get("category"))]["checks"].append({
            "check_name": name, "title": _why(name),
            "sr": info.get("sr"), "checklist_id": info.get("checklist_id"), "severity": info.get("severity"),
            "category": info.get("category"), "sl": info.get("sl"), "open_findings": counts.get(name, 0),
            "included": e is None, **({"reason": e["reason"], "excluded_by": e["excluded_by"],
                                       "excluded_at": e["excluded_at"]} if e else {})})
    out = []
    for k, _l, _d in GROUPS:
        g = groups[k]
        if not g["checks"]:
            continue
        n_in = sum(1 for c in g["checks"] if c["included"])
        g.update(total=len(g["checks"]), included=n_in,
                 state="all" if n_in == len(g["checks"]) else "none" if n_in == 0 else "some",
                 open_findings=sum(c["open_findings"] for c in g["checks"]))
        out.append(g)
    return {"site_id": site_id, "groups": out, "excluded": len(ex),
            "checks": sum(g["total"] for g in out)}


def apply(db: DBSession, site_id: int, exclude: Iterable = (), include: Iterable = (),
          by: Optional[str] = None) -> dict:
    """``exclude``: [{check_name, reason}] (or names) to leave out; ``include``: names
    to put back.  Unknown check names are refused (ValueError)."""
    from app.models import ReportCheckExclusion
    from generate_report import check_catalogue
    known = set(check_catalogue())
    items = []
    for x in exclude or []:
        name, reason = (x.get("check_name"), x.get("reason")) if isinstance(x, dict) else (x, None)
        items.append((str(name or "").strip(), (reason or "").strip()[:500] or None))
    back = [str(n or "").strip() for n in include or []]
    bad = sorted({n for n, _r in items if n not in known} | {n for n in back if n not in known})
    if bad:
        raise ValueError("unknown check(s): " + ", ".join(bad[:10]))
    now = datetime.now(timezone.utc)
    have = {r.check_name: r for r in db.query(ReportCheckExclusion).filter(ReportCheckExclusion.site_id == site_id)}
    added = updated = removed = 0
    for name, reason in items:
        r = have.get(name)
        if r is None:
            db.add(ReportCheckExclusion(site_id=site_id, check_name=name, reason=reason,
                                        excluded_by=(by or None), excluded_at=now))
            added += 1
        elif reason is not None and reason != r.reason:
            r.reason, r.excluded_by, r.excluded_at = reason, (by or r.excluded_by), now
            updated += 1
    for name in back:
        r = have.get(name)
        if r is not None:
            db.delete(r)
            removed += 1
    db.flush()
    return {"excluded_added": added, "reasons_updated": updated, "included_again": removed}


def excluded_summary(db: DBSession, site_id: Optional[int], ex: dict) -> list:
    """For the PDF: one entry per group with excluded checks - whole group or the
    listed checks - with their open findings left out and the reasons."""
    from sqlalchemy import func
    from app.models import Finding
    from generate_report import check_catalogue
    if not ex:
        return []
    cat = check_catalogue()
    counts = Counter()
    q = db.query(Finding.check_name, func.count(Finding.id)).filter(Finding.status.in_(("open", "acknowledged")))
    if site_id is not None:
        q = q.filter(Finding.site_id == site_id)
    for name, n in q.group_by(Finding.check_name):
        counts[name] = n
    by_group = {}
    for name in sorted(cat):
        g = check_group(name, cat[name].get("category"))
        by_group.setdefault(g, {"all": [], "out": []})
        by_group[g]["all"].append(name)
        if name in ex:
            by_group[g]["out"].append(name)
    out = []
    for k, label, _d in GROUPS:
        g = by_group.get(k)
        if not g or not g["out"]:
            continue
        out.append({"group": k, "label": label, "whole": len(g["out"]) == len(g["all"]),
                    "total": len(g["all"]),
                    "checks": [{"check_name": n, "open_findings": counts.get(n, 0), **ex[n]} for n in g["out"]],
                    "open_findings": sum(counts.get(n, 0) for n in g["out"])})
    return out
