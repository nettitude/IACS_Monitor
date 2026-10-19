"""
Findings integration for access-path classifications
(docs/access-path-review.md, "Reporting & findings", phase 4).

CONTRACT
--------
POST /access-paths/classify commits the operator's ``access_path_tag``
rows and THEN calls::

    sync_findings_for_tags(db, site_id, tag_keys)

once per request, with every tag_key the request wrote.  The periodic
reviews call ``sync_site_findings`` for every tag of a site at the end of
each run (alert_engine._review_access_path_classifications), so findings
follow config re-ingests and new automatic findings.

What a classification does (per tag; everything stays inside the site):

``it_ot_bypass``
    An active (open / acknowledged) automatic ``rule_it_ot_bypass`` finding
    for one of the path's permitting policies is CONFIRMED: detail gets
    ``manual_confirmed: true``, the reviewer note and classified_by (status
    unchanged, so an acknowledged one stays acknowledged).  Without such a
    finding a manual ``rule_it_ot_bypass`` finding is raised (detail
    ``manual: true``, deduped on the tag_key).  Severity follows the
    automatic check: high for a deep-OT (L0-L1) destination, else medium,
    one step higher when the path is seen in capture.
``permissive``
    Raises ``access_path_permissive`` (deduped on the tag_key): medium, high
    when the path is seen in capture and flagged permit_any,
    cleartext_protocol or mgmt_protocol.
``reviewed_ok`` / ``exception``
    Acknowledges every OPEN automatic finding of the path's own policies
    (rule_it_ot_bypass, config_permit_any_any_any, rule_cleartext_protocol,
    rule_mgmt_protocol, rule_mgmt_wrong_zone; matched on firewall + VDOM + policy id - never a
    different policy) with acknowledged_by = classified_by or
    "access-review", notes "Accepted <exception|reviewed OK> in Access
    Review: <note>", and detail ``acknowledged_via_tag = tag_key``.
``unclassified`` / any change away from the above
    Closes the manual finding(s) the tag raised, removes its confirmation,
    and re-opens the automatic findings acknowledged through this tag (only
    those - a finding acknowledged by a person is never touched).  When
    another suppressing tag still covers the same policy the
    acknowledgement is handed over to that tag instead.

A tag whose path is no longer in the configuration (orphaned) has its
manual findings closed ("policy no longer in the configuration"), unless
the enumeration was truncated (then nothing is decided for it).

Idempotent: a second call with the same data changes nothing (no
occurrence bumps, no note churn).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence

from sqlalchemy.orm import Session as DBSession

from app.models import AccessPathTag, Finding
from app.parsers.site_scope import analysis_site
from app.purdue import fmt_level, is_deep_ot

log = logging.getLogger(__name__)

CHECK_BYPASS = "rule_it_ot_bypass"
CHECK_PERMISSIVE = "access_path_permissive"
# automatic checks a reviewed_ok / exception classification acknowledges
AUTO_POLICY_CHECKS = ("rule_it_ot_bypass", "config_permit_any_any_any",
                      "rule_cleartext_protocol", "rule_mgmt_protocol", "rule_mgmt_wrong_zone")
SUPPRESSING = ("reviewed_ok", "exception")
DEFAULT_ACTOR = "access-review"
ACK_MARKER = "in Access Review:"          # part of every acknowledgement note

# detail keys written by this module
K_MANUAL = "manual"
K_TAG = "access_path_tag"
K_ACK_VIA = "acknowledged_via_tag"
K_ACK_NOTE = "access_review_ack_note"
K_CONFIRMED = "manual_confirmed"
K_CONFIRMATIONS = "access_review_confirmations"

_STEP_UP = {"info": "low", "low": "medium", "medium": "high", "high": "critical",
            "critical": "critical"}
_NOTES_MAX = 2048
from app.models import ACTIVE_FINDING_STATUSES as _ACTIVE   # SF: + false_positive


def _empty_summary() -> dict:
    return {"raised": 0, "confirmed": 0, "acknowledged": 0, "reopened": 0, "closed": 0}


def _public(summary: dict) -> dict:
    return {k: v for k, v in summary.items() if not k.startswith("_")}


# ---------------------------------------------------------------- entry points
def sync_findings_for_tags(db: DBSession, site_id: int, tag_keys: Sequence[str]) -> dict:
    """Bring findings in line with the committed classifications of
    ``tag_keys`` in site ``site_id`` and commit.

    Returns ``{"raised", "confirmed", "acknowledged", "reopened", "closed"}``
    (counts of changes made by this call; all zero on a repeat call).  Never
    raises for a data problem: a failure is logged, rolled back and reported
    as ``{"error": ...}`` next to zero counts (the tags stay committed)."""
    keys = list(dict.fromkeys(k for k in (tag_keys or ()) if isinstance(k, str) and k))
    summary = _empty_summary()
    if not keys:
        return summary
    try:
        res = sync_site_findings(db, site_id, keys)
        db.commit()
        return _public(res)
    except Exception:
        log.exception("access-path findings sync failed (site %s, %d tag(s))", site_id, len(keys))
        db.rollback()
        summary["error"] = "findings sync failed; see the server log"
        return summary


def sync_site_findings(db: DBSession, site_id: int,
                       tag_keys: Optional[Iterable[str]] = None) -> dict:
    """Sync the findings of ``tag_keys`` (None = every tag of the site).
    Flushes but does NOT commit (the caller owns the transaction).

    Returns the summary dict plus internal keys ``_created`` (new Finding
    rows), ``_refs`` (dedup keys of the manual findings kept active) and
    ``_incomplete`` (the enumeration was truncated, so orphaned tags were
    not judged)."""
    summary = _empty_summary()
    summary.update({"_created": [], "_refs": set(), "_incomplete": False})
    with analysis_site(db, site_id):
        all_tags = db.query(AccessPathTag).filter(AccessPathTag.site_id == site_id).all()
        if tag_keys is not None:
            wanted = set(tag_keys)
            targets = [t for t in all_tags if t.tag_key in wanted]
        else:
            targets = list(all_tags)
        if not targets:
            return summary
        from app.parsers.chain_findings import chain_rows
        res = chain_rows(db)          # shared with the chain reviews inside a run
        summary["_incomplete"] = bool(res["truncated"])
        ctx = _SyncContext(db, res["index"], all_tags, bool(res["truncated"]), summary)
        for tag in sorted(targets, key=lambda t: t.tag_key):
            ctx.sync_tag(tag)
        db.flush()
    return summary


# ---------------------------------------------------------------- helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_note(f: Finding, text: str) -> None:
    cur = f.notes or ""
    if cur:
        keep = max(0, _NOTES_MAX - len(text) - 3)
        f.notes = cur[:keep] + " | " + text if keep else text[:_NOTES_MAX]
    else:
        f.notes = text[:_NOTES_MAX]


def _detail(f: Finding) -> dict:
    return dict(f.detail) if isinstance(f.detail, dict) else {}


def _norm(v) -> Optional[str]:
    return None if v is None or v == "" else str(v)


def _policy_hops(item: dict) -> list[dict]:
    """The permitting policies of a row (composed rows: both legs'),
    without policy-less hops (intrazone allow)."""
    return [h for h in (item.get("chain") or []) if h.get("policy_id") is not None]


def _config_ref(f: Finding) -> Optional[tuple]:
    """(firewall_id, policy ref) from a config_review finding's source_ref
    ``config:<fw_id>:<check>:<pid>`` (pid = ``<vdom>/<id>`` in multi-VDOM)."""
    ref = f.source_ref or ""
    if not ref.startswith("config:"):
        return None
    parts = ref.split(":", 3)
    if len(parts) != 4 or parts[2] != f.check_name:
        return None
    try:
        return int(parts[1]), parts[3]
    except ValueError:
        return None


def finding_matches_policy(f: Finding, hop: dict) -> bool:
    """Is automatic finding ``f`` about exactly the policy of ``hop``
    (firewall + VDOM + policy id)?"""
    pid = _norm(hop.get("policy_id"))
    if pid is None:
        return False
    vdom = _norm(hop.get("vdom"))
    if f.check_name == "config_permit_any_any_any":
        cr = _config_ref(f)
        if cr is None or hop.get("firewall_id") is None:
            return False
        fw_id, ref = cr
        return fw_id == hop["firewall_id"] and ref == (f"{vdom}/{pid}" if vdom else pid)
    d = _detail(f)
    if _norm(d.get("policy_id")) != pid or _norm(d.get("vdom")) != vdom:
        return False
    if d.get("firewall_id") is not None and hop.get("firewall_id") is not None:
        return d["firewall_id"] == hop["firewall_id"]
    if d.get("firewall_device_id") is not None and hop.get("firewall_device_id") is not None:
        return d["firewall_device_id"] == hop["firewall_device_id"]
    return False


def _is_flow(item: dict) -> bool:
    return "client" in item and "server" in item


def _path_sides(item: dict) -> tuple[dict, dict]:
    if _is_flow(item):
        c, s = item["client"], item["server"]
        return ({"level": c.get("level"), "zone": None, "scope": c.get("ip")},
                {"level": s.get("level"), "zone": None, "scope": s.get("ip")})
    return dict(item.get("src") or {}), dict(item.get("dst") or {})


def _services(item: dict) -> list[str]:
    if _is_flow(item):
        port = item["server"].get("port")
        return [f"{item.get('transport') or 'ip'}/{port}" if port is not None
                else str(item.get("transport") or "ip")]
    return list(item.get("service") or [])


def _traffic(item: dict) -> dict:
    if _is_flow(item):
        return {"status": "seen", "sessions": item.get("sessions"),
                "last_seen": item.get("last_seen")}
    return dict(item.get("traffic") or {})


def allowed_by(item: dict) -> str:
    """"PLANT1-FGT #3 broad-mgmt" per hop, joined with " + "."""
    if _is_flow(item):
        return "no rule allows this"
    parts = []
    for h in item.get("chain") or []:
        pid = h.get("policy_id")
        s = f"{h.get('firewall_name') or '?'} #{pid if pid is not None else '-'}"
        if h.get("policy_name"):
            s += f" {h['policy_name']}"
        parts.append(s)
    return " + ".join(parts) or "(no policy)"


def zone_parts_label(parts) -> str:
    """SF-6: "port1 (L1) + port2 (L3)"."""
    return " + ".join(f"{p['name']} ({fmt_level(p['level']) if p.get('level') is not None else 'no level'})"
                      for p in parts)


def _scope_label(side: dict) -> str:
    bits = [fmt_level(side.get("level"))]
    if side.get("zone_parts"):
        bits.append(zone_parts_label(side["zone_parts"]))
    elif side.get("zone"):
        bits.append(str(side["zone"]))
    if side.get("scope"):
        bits.append(str(side["scope"]))
    return " ".join(bits)


def path_label(item: dict) -> str:
    src, dst = _path_sides(item)
    if item.get("pivot"):
        piv = item["pivot"]
        hop = item.get("hop")
        mid = f"{fmt_level(piv.get('level'))} {piv.get('ip')}"
        if hop:   # operator-declared gateway -> jump host step inside the DMZ
            mid += f" ⇒ {hop.get('to_ip')} (declared hop)"
        return f"{_scope_label(src)} → {mid} → {_scope_label(dst)}"
    return f"{_scope_label(src)} → {_scope_label(dst)}"


def _evidence(tag, item: dict) -> dict:
    src, dst = _path_sides(item)
    path = {"src": src, "dst": dst, "direction": item.get("direction")}
    if item.get("pivot"):
        path["pivot"] = dict(item["pivot"])
    if item.get("hop"):
        path["hop"] = dict(item["hop"])
    return {
        K_MANUAL: True,
        K_TAG: tag.tag_key,
        "classification": tag.classification,
        "kind": tag.kind,
        "path": path,
        "service": _services(item),
        "chain": [dict(h) for h in (item.get("chain") or [])],
        "allowed_by": allowed_by(item),
        "flags": list(item.get("flags") or []),
        "traffic": _traffic(item),
        "note": tag.note,
        "classified_by": tag.classified_by,
    }


def bypass_severity(item: dict) -> str:
    """rule_it_ot_bypass conventions: high to deep OT (L0-L1), medium
    otherwise (A-11 L4-L5 -> L2 case); one step up when seen in capture."""
    _src, dst = _path_sides(item)
    lvl = dst.get("level")
    try:
        sev = "high" if lvl is not None and is_deep_ot(lvl) else "medium"
    except (TypeError, ValueError):
        sev = "medium"
    if _traffic(item).get("status") == "seen":
        sev = _STEP_UP[sev]
    return sev


def permissive_severity(item: dict) -> str:
    flags = set(item.get("flags") or [])
    seen = _traffic(item).get("status") == "seen"
    return "high" if seen and flags & {"permit_any", "cleartext_protocol", "mgmt_protocol"} else "medium"


def _levels_service(item: dict) -> str:
    src, dst = _path_sides(item)
    svc = ", ".join(_services(item)) or "any"
    return f"{fmt_level(src.get('level'))} → {fmt_level(dst.get('level'))}, {svc}"


# ---------------------------------------------------------------- context
class _SyncContext:
    def __init__(self, db, index: dict, all_tags: list, truncated: bool, summary: dict):
        from app.parsers import alert_engine as ae
        self.ae = ae
        self.db = db
        self.index = index
        self.truncated = truncated
        self.summary = summary
        self.tags = {t.tag_key: t for t in all_tags}
        rows = db.query(Finding).filter(
            Finding.check_name.in_(sorted(set(AUTO_POLICY_CHECKS) | {CHECK_PERMISSIVE})),
            Finding.status.in_(_ACTIVE),
        ).order_by(Finding.id).all()
        self.autos: list[Finding] = []
        self.manuals: dict[str, list[Finding]] = {}
        for f in rows:
            d = _detail(f)
            if d.get(K_MANUAL) or f.check_name == CHECK_PERMISSIVE:
                if d.get(K_TAG):
                    self.manuals.setdefault(d[K_TAG], []).append(f)
            elif f.check_name in AUTO_POLICY_CHECKS:
                self.autos.append(f)

    # ---------------------------------------------------------------- per tag
    def sync_tag(self, tag) -> None:
        key, cls = tag.tag_key, tag.classification
        item = self.index.get(key)
        if item is None:
            if not self.truncated:
                self._close_manuals(key, keep=set(),
                                    reason="the path's policy is no longer in the firewall "
                                           "configuration")
            return
        hops = _policy_hops(item)
        matching = [f for f in self.autos if any(finding_matches_policy(f, h) for h in hops)]
        keep: set = set()

        if cls == "it_ot_bypass":
            bypass = [f for f in matching if f.check_name == CHECK_BYPASS]
            if bypass:
                for f in bypass:
                    self._confirm(f, tag)
            else:
                self._upsert_manual(CHECK_BYPASS, tag, item)
                keep.add(CHECK_BYPASS)
        elif cls == "permissive":
            self._upsert_manual(CHECK_PERMISSIVE, tag, item)
            keep.add(CHECK_PERMISSIVE)
        elif cls in SUPPRESSING:
            for f in matching:
                self._acknowledge(f, tag)

        self._close_manuals(key, keep=keep, reason=(
            lambda f: "superseded by the automatic finding for this policy"
            if cls == "it_ot_bypass" and f.check_name == CHECK_BYPASS
            else f"Access Review classification changed to {cls}"))
        if cls != "it_ot_bypass":
            for f in self.autos:
                if key in (_detail(f).get(K_CONFIRMATIONS) or {}):
                    self._unconfirm(f, key)
        if cls not in SUPPRESSING:
            for f in self.autos:
                d = _detail(f)
                if f.status != "acknowledged":
                    continue
                if d.get(K_ACK_VIA) == key or (
                        f in matching and not d.get(K_ACK_VIA)
                        and ACK_MARKER in (f.notes or "")
                        and (f.notes or "").find("Accepted ") != -1):
                    self._release_ack(f, tag, hops_of=item)

    # ---------------------------------------------------------------- manual
    def _ref(self, check: str, key: str) -> str:
        return self.ae._dedup_key(check, {"rule_key": f"access_path:{key}"})

    def _upsert_manual(self, check: str, tag, item: dict) -> None:
        ae, key = self.ae, tag.tag_key
        evidence = _evidence(tag, item)
        if check == CHECK_PERMISSIVE:
            sev = permissive_severity(item)
            if _is_flow(item):
                title = f"Permissive flow ({allowed_by(item)}): {path_label(item)} ({_levels_service(item)})"
            else:
                title = f"Permissive policy: {allowed_by(item)} ({_levels_service(item)})"
            text = (f"Classified permissive in Access Review"
                    + (f" by {tag.classified_by}" if tag.classified_by else "")
                    + f": {path_label(item)} over {', '.join(_services(item)) or 'any'}, allowed by "
                    f"{allowed_by(item)}. Flags: {', '.join(item.get('flags') or []) or 'none'}. "
                    "A permissive conduit policy violates least functionality (SR 7.7), "
                    "deny-by-default zone boundary protection (SR 5.2) and, for cleartext "
                    "protocols, communication confidentiality (SR 4.1)."
                    + (f" Reviewer note: {tag.note}" if tag.note else ""))
        else:
            sev = bypass_severity(item)
            seen = _traffic(item).get("status") == "seen"
            title = (f"IT/OT boundary bypass (Access Review): {path_label(item)} permitted "
                     f"({allowed_by(item)})" + (" [seen in capture]" if seen else ""))
            text = (f"Classified as an IT/OT boundary bypass in Access Review"
                    + (f" by {tag.classified_by}" if tag.classified_by else "")
                    + f": {path_label(item)} over {', '.join(_services(item)) or 'any'}, allowed by "
                    f"{allowed_by(item)}. The automatic rule_it_ot_bypass check did not flag "
                    "this path; the finding tracks the reviewer's classification "
                    "(SR 5.1 RE2, SR 5.2)."
                    + (" Matching traffic was seen in the capture." if seen else "")
                    + (f" Reviewer note: {tag.note}" if tag.note else ""))
        title = title[:512]
        ref = self._ref(check, key)
        self.summary["_refs"].add(ref)
        seen_refs = self.db.info.get(ae._SEEN_KEY)
        if seen_refs is not None:
            seen_refs.add(ref)
        existing = ae._find_open(self.db, ref)
        if existing is not None:
            new_detail = {"description": text, **evidence}
            if existing.detail != new_detail:
                existing.detail = new_detail
            if existing.title != title:
                existing.title = title
            if existing.severity != sev:
                existing.severity = sev
            return
        chain = item.get("chain") or []
        f = ae._make_finding(
            self.db, check, title, text, evidence,
            firewall_rule_id=(chain[0].get("rule_id") if chain else None),
            device_name=(chain[0].get("firewall_name") if chain else None),
            severity=sev, dedup_evidence={"rule_key": f"access_path:{key}"},
        )
        if f is not None:
            self.summary["raised"] += 1
            self.summary["_created"].append(f)
            self.manuals.setdefault(key, []).append(f)

    def _close_manuals(self, key: str, keep: set, reason) -> None:
        now = _now()
        for f in self.manuals.get(key, []):
            if f.status not in _ACTIVE or f.check_name in keep:
                continue
            why = reason(f) if callable(reason) else reason
            f.status = "closed"
            f.closed_at = now
            _append_note(f, f"Closed {_stamp(now)}: {why} (Access Review tag {key}).")
            self.summary["closed"] += 1

    # ---------------------------------------------------------------- confirm
    def _confirm(self, f: Finding, tag) -> None:
        d = _detail(f)
        conf = dict(d.get(K_CONFIRMATIONS) or {})
        entry = {"note": tag.note, "classified_by": tag.classified_by}
        first = not d.get(K_CONFIRMED)
        conf[tag.tag_key] = entry
        new = self._with_confirmations(d, conf)
        if new != d:
            f.detail = new
            if first:
                self.summary["confirmed"] += 1

    def _unconfirm(self, f: Finding, key: str) -> None:
        d = _detail(f)
        conf = dict(d.get(K_CONFIRMATIONS) or {})
        conf.pop(key, None)
        new = self._with_confirmations(d, conf)
        if new != d:
            f.detail = new

    @staticmethod
    def _with_confirmations(d: dict, conf: dict) -> dict:
        new = {k: v for k, v in d.items()
               if k not in (K_CONFIRMED, K_CONFIRMATIONS, "reviewer_note", "classified_by")}
        if conf:
            lead = conf[sorted(conf)[0]]           # deterministic across tags
            new[K_CONFIRMED] = True
            new[K_CONFIRMATIONS] = {k: conf[k] for k in sorted(conf)}
            new["reviewer_note"] = lead.get("note")
            new["classified_by"] = lead.get("classified_by")
        return new

    # ---------------------------------------------------------------- acknowledge
    @staticmethod
    def _ack_text(tag) -> str:
        word = "exception" if tag.classification == "exception" else "reviewed OK"
        return f"Accepted {word} {ACK_MARKER} {tag.note or '(no note)'}"

    def _acknowledge(self, f: Finding, tag) -> None:
        d = _detail(f)
        text = self._ack_text(tag)
        if f.status == "open":
            now = _now()
            f.status = "acknowledged"
            f.acknowledged_by = (tag.classified_by or DEFAULT_ACTOR)[:128]
            f.acknowledged_at = now
            _append_note(f, text)
            f.detail = {**d, K_ACK_VIA: tag.tag_key, K_ACK_NOTE: text}
            self.summary["acknowledged"] += 1
            return
        via = d.get(K_ACK_VIA)
        if via == tag.tag_key:
            if d.get(K_ACK_NOTE) != text:          # note / classification edited
                old = d.get(K_ACK_NOTE)
                if old and f.notes and old in f.notes:
                    f.notes = f.notes.replace(old, text)[:_NOTES_MAX]
                else:
                    _append_note(f, text)
                f.detail = {**d, K_ACK_NOTE: text}
        elif via is None and ACK_MARKER in (f.notes or ""):
            # acknowledged by this mechanism, marker lost (a config re-ingest
            # replaces config finding detail): restore it
            f.detail = {**d, K_ACK_VIA: tag.tag_key, K_ACK_NOTE: text}

    def _other_suppressor(self, f: Finding, key: str):
        for k in sorted(self.tags):
            t = self.tags[k]
            if k == key or t.classification not in SUPPRESSING:
                continue
            item = self.index.get(k)
            if item is None:
                continue
            if any(finding_matches_policy(f, h) for h in _policy_hops(item)):
                return t
        return None

    def _release_ack(self, f: Finding, tag, hops_of: dict) -> None:
        d = _detail(f)
        other = self._other_suppressor(f, tag.tag_key)
        if other is not None:
            if d.get(K_ACK_VIA) != other.tag_key:
                f.detail = {**d, K_ACK_VIA: other.tag_key, K_ACK_NOTE: self._ack_text(other)}
            return
        now = _now()
        new = {k: v for k, v in d.items() if k not in (K_ACK_VIA, K_ACK_NOTE)}
        twin = None
        if f.source_ref:
            twin = self.db.query(Finding).filter(
                Finding.source_ref == f.source_ref, Finding.status == "open",
                Finding.id != f.id).first()
        f.detail = new
        if twin is not None:
            f.status = "closed"
            f.closed_at = now
            _append_note(f, f"Closed {_stamp(now)}: acceptance withdrawn in Access Review "
                            f"(tag {tag.tag_key}); finding #{twin.id} tracks the condition.")
            self.summary["closed"] += 1
            return
        f.status = "open"
        f.acknowledged_by = None
        f.acknowledged_at = None
        f.closed_at = None
        _append_note(f, f"Re-opened {_stamp(now)}: Access Review classification of tag "
                        f"{tag.tag_key} changed to {tag.classification}.")
        self.summary["reopened"] += 1
