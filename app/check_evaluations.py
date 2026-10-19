"""
Check evaluations: when each check was last evaluated, so the compliance report can
say PASS (evaluated after the latest data, nothing found) / NOT EVALUATED / NO DATA
instead of an ambiguous "no findings" (owner 2026-10-12: "print out tests that passed
and the evidence").

Recorded by
  * run_periodic_reviews (app/parsers/alert_engine.py) - one row per check of every
    review that ran in a site-bound run (scope "");
  * the FortiGate config upload (app/parsers/forti_config_parser.py) - one row
    ``FORTIGATE_CONFIG`` per firewall (scope ``fw:<id>``) holding the settings the
    config checks examined (the report's "Configuration Evidence" appendix).

Judged by ``coverage_states`` (generate_report.collect_report_data).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

FORTIGATE_CONFIG = "__fortigate_config__"
#: checks evaluated on every event / capture as it arrives (no review run needed)
INGEST_EVALUATED = {"unauthorized_industrial_write": "protocol_details"}


def _aware(ts):
    if ts is None:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def record(db, site_id: Optional[int], check_name: str, *, scope: str = "", source: str = "",
           complete: bool = True, note: Optional[str] = None, evidence=None,
           when: Optional[datetime] = None) -> None:
    """Upsert the evaluation row of (site, check, scope).  No site = nothing recorded
    (a legacy unscoped run has no site to attach it to)."""
    if site_id is None:
        return
    from app.models import CheckEvaluation
    when = when or datetime.now(timezone.utc)
    row = (db.query(CheckEvaluation)
           .filter(CheckEvaluation.site_id == site_id, CheckEvaluation.check_name == check_name,
                   CheckEvaluation.scope == scope).one_or_none())
    if row is None:
        row = CheckEvaluation(site_id=site_id, check_name=check_name, scope=scope)
        db.add(row)
    row.source = (source or None) and source[:128]
    row.evaluated_at = when
    row.complete = bool(complete)
    row.note = (note or None) and str(note)[:512]
    if evidence is not None or check_name == FORTIGATE_CONFIG:
        row.evidence = evidence


def data_changed_at(db, site_id: int) -> Optional[datetime]:
    """Latest time a discrete upload / edit changed the site's data: config uploads,
    device updates, captures (upload / reprocess), Subnets & Zones, baselines and
    IEC zone edits.  Not counted: live log events and host sightings (continuous -
    the scheduled reviews cover them), switch outputs and interface-label edits
    (no timestamp) - documented limitation."""
    from sqlalchemy import func
    from app.models import Baseline, Firewall, FirewallDevice, IecZone, PcapCapture, SubnetZone
    cols = [
        (Firewall.config_uploaded_at, Firewall), (FirewallDevice.updated_at, FirewallDevice),
        (PcapCapture.uploaded_at, PcapCapture), (PcapCapture.reprocessed_at, PcapCapture),
        (SubnetZone.updated_at, SubnetZone), (Baseline.created_at, Baseline),
        (IecZone.updated_at, IecZone),
    ]
    best = None
    for col, model in cols:
        try:
            v = db.query(func.max(col)).filter(model.site_id == site_id).scalar()
        except Exception:  # pragma: no cover - column / table missing on an old schema
            db.rollback()
            continue
        v = _aware(v) if isinstance(v, datetime) else None
        if v is not None and (best is None or v > best):
            best = v
    return best


def _fmt(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "?"


def coverage_states(db, site_ids: Iterable[int], catalogue: dict, inputs: dict) -> dict:
    """{check_name: {"state", "basis"}} for checks with no finding and their inputs
    present.  state: "pass" | "not evaluated" | "no data" (FortiGate config checks
    without any evaluated FortiGate config).  Checks this module does not track
    are left out (the report keeps "no findings" for them)."""
    from app.models import CheckEvaluation, Firewall
    from app.parsers.alert_engine import review_checks_map
    site_ids = [s for s in site_ids if s is not None]
    out: dict = {}
    if not site_ids:
        return out
    rows = db.query(CheckEvaluation).filter(CheckEvaluation.site_id.in_(site_ids)).all()
    by = {}
    for r in rows:
        by[(r.site_id, r.check_name, r.scope)] = r
    changed = {sid: data_changed_at(db, sid) for sid in site_ids}
    tracked_periodic = {c for checks in review_checks_map().values() for c in checks}
    forti_checks = fortigate_config_checks(catalogue)

    # FortiGate config evaluations per firewall
    fws = db.query(Firewall.id, Firewall.name, Firewall.vendor, Firewall.site_id,
                   Firewall.config_uploaded_at).filter(Firewall.site_id.in_(site_ids)).all()
    forti = [f for f in fws if str(f.vendor or "").lower().startswith("forti")]
    others = [f for f in fws if not str(f.vendor or "").lower().startswith("forti")]
    evaluated, stale = [], []
    for f in forti:
        r = by.get((f.site_id, FORTIGATE_CONFIG, f"fw:{f.id}"))
        up = _aware(f.config_uploaded_at)
        if r is None or (up is not None and _aware(r.evaluated_at) < up):
            stale.append(f.name)
        else:
            evaluated.append((f.name, _aware(r.evaluated_at)))
    other_note = (f"; not covered (not FortiGate): {', '.join(sorted({o.name for o in others}))}"
                  if others else "")

    for name, info in catalogue.items():
        if name in forti_checks:
            if not evaluated and not stale:
                out[name] = {"state": "no data", "basis": "no FortiGate configuration uploaded" + other_note}
            elif stale:
                out[name] = {"state": "not evaluated",
                             "basis": f"FortiGate config(s) uploaded without findings: {', '.join(stale)}" + other_note}
            else:
                last = max(t for _n, t in evaluated)
                out[name] = {"state": "pass",
                             "basis": f"{len(evaluated)} FortiGate config(s) evaluated, latest {_fmt(last)}" + other_note}
            continue
        if info.get("category") == "real_time":
            n = inputs.get("faz_events") or 0
            if n:
                out[name] = {"state": "pass", "basis": f"evaluated on each of {n} log event(s) as they arrived"}
            continue
        if name in INGEST_EVALUATED:
            n = inputs.get(INGEST_EVALUATED[name]) or 0
            if n:
                out[name] = {"state": "pass", "basis": "evaluated at each capture upload"}
            continue
        if name not in tracked_periodic:
            continue
        worst, bases = "pass", []
        for sid in site_ids:
            r = by.get((sid, name, ""))
            ch = changed.get(sid)
            if r is None:
                if ch is None:
                    continue                      # no data in that site at all
                worst = "not evaluated"
                bases.append("review not run since the data arrived" + (f" ({_fmt(ch)})" if ch else ""))
                continue
            at = _aware(r.evaluated_at)
            if not r.complete:
                worst = "not evaluated"
                bases.append(f"last review {_fmt(at)} incomplete: {r.note or 'see the server log'}")
            elif ch is not None and at < ch:
                worst = "not evaluated"
                bases.append(f"last review {_fmt(at)}, new data {_fmt(ch)}")
            else:
                bases.append(f"reviewed {_fmt(at)} ({r.source})")
        if bases:
            out[name] = {"state": worst, "basis": "; ".join(dict.fromkeys(bases))}
    return out


def fortigate_config_checks(catalogue: dict) -> set:
    """Checks the FortiGate config upload evaluates (config_* checks of the
    config parser + fqdn_in_policy)."""
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    return {c for c in FORTIGATE_CONFIG_CHECKS if c in catalogue}


def config_evidence(db, site_ids: Iterable[int]) -> list:
    """[{firewall, device, evaluated_at, sections, open_checks}] for the report appendix:
    the settings each FortiGate config's checks examined, with the checks that have
    an open / acknowledged finding on that firewall."""
    from app.models import CheckEvaluation, Finding, Firewall
    site_ids = [s for s in site_ids if s is not None]
    if not site_ids:
        return []
    rows = (db.query(CheckEvaluation)
            .filter(CheckEvaluation.site_id.in_(site_ids), CheckEvaluation.check_name == FORTIGATE_CONFIG)
            .all())
    out = []
    for r in rows:
        try:
            fw_id = int(str(r.scope).split(":", 1)[1])
        except (IndexError, ValueError):
            continue
        fw = db.get(Firewall, fw_id)
        if fw is None:
            continue
        refs = (db.query(Finding.check_name)
                .filter(Finding.status.in_(("open", "acknowledged")),
                        Finding.source_ref.like(f"config:{fw_id}:%")
                        | Finding.source_ref.like(f"fqdn_policy:{fw_id}:%"))
                .distinct().all())
        ev = r.evidence or {}
        out.append({"firewall": fw.name, "device": ev.get("device") or fw.device_name,
                    "site_id": r.site_id, "evaluated_at": _aware(r.evaluated_at),
                    "sections": ev.get("sections") or [],
                    "open_checks": sorted({c for (c,) in refs if c})})
    out.sort(key=lambda e: (e["firewall"] or "").lower())
    return out
