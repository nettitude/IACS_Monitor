"""
Firewall rule-hit tracking (F-10): stamp FirewallRule.last_matched from
ingested traffic log events.

``record_rule_hits(db, events)`` looks at traffic events whose action is an
allowed session (accept/allow/close/...) or a deny, finds the FirewallRule
the firewall itself reported (or, for Cisco ASA, evaluated), and sets
``last_matched = max(existing, event_time or received_at)``.

Rule identity per vendor (FirewallRule columns):
  FortiOS   device + policy_id (= FortiOS policy number; "0" = implicit deny)
  pfSense   policy_id = filterlog tracker
  PAN-OS    policy_name (or policy_id) = rule name
  Cisco ASA policy_name = ACL name, rule_order = ACE order. 106100/106023
            name the ACL; its ENABLED rows are evaluated first-match in
            rule_order against the event 5-tuple (rule_match helpers). Lines
            without an ACL (302013/302015 built, 106001/106006) are evaluated
            the same way against the device's ACL - the only one, or the one
            whose name contains the ingress interface.
            Legacy rows without policy_name: device_name is the ACL / rule
            name (firewall_parser before the identity change) and is used.

Device scoping: event.device_name is compared with FirewallRule.device_name,
FirewallDevice.name/device_hostname and Firewall.name/device_name. If no
row is scoped to the event's device, the candidates are used only when they
all belong to one device; otherwise the event is counted as ``ambiguous``.

Only enabled rules are ever stamped. Allowed events only stamp permit
rules, deny events only stamp deny rules. Work is batched: one query for
the enabled rules + one each for device / firewall names, then one UPDATE
per distinct rule (grouped), never one query per event. Does not commit.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy.orm import Session as DBSession

from app.models import Firewall, FirewallDevice, FirewallRule
from app.parsers import rule_match as rm

ALLOW_ACTIONS = {"accept", "allow", "close", "timeout", "client-rst", "server-rst"}
DENY_ACTIONS = {"deny", "drop", "block", "blocked", "reset", "reject"}
_PERMIT_RULE_ACTIONS = {"permit", "allow", "accept", "pass"}
# ASA messages that are not an ACL decision (stateful drop / threat detection)
_ASA_NO_ACL_DECISION = {"106015", "733100", "733101"}


def _family(device_type: Optional[str]) -> Optional[str]:
    t = (device_type or "").lower()
    if t.startswith("forti"):
        return "fortinet"
    if t.startswith(("cisco", "asa", "ftd")):
        return "cisco_asa"
    if t.startswith(("pfsense", "opnsense")):
        return "pfsense"
    if t.startswith(("pan", "palo")):
        return "panos"
    return None


def _event_family(ev) -> Optional[str]:
    v = (getattr(ev, "vendor", None) or "").lower()
    if v:
        return v if v in ("fortinet", "cisco_asa", "pfsense", "panos") else None
    st = (ev.source_type or "").lower()
    return {"syslog_asa": "cisco_asa", "syslog_pfsense": "pfsense",
            "syslog_panos": "panos"}.get(st, "fortinet")


def _rule_is_permit(rule) -> bool:
    return (rule.action or "").strip().lower() in _PERMIT_RULE_ACTIONS


def _norm(s) -> Optional[str]:
    s = (str(s).strip().lower() if s is not None else "")
    return s or None


def tuple_match(rule, ev) -> Optional[bool]:
    """Does ``rule`` match the event 5-tuple? True / False / None (unknown)."""
    results = []
    protos = rm.parse_protocols(rule.protocol)
    ev_proto = _norm(ev.protocol)
    if protos == rm.ANY:
        results.append(True)
    elif isinstance(protos, rm.Unresolved) or ev_proto is None:
        results.append(None)
    else:
        aliases = {ev_proto, {"icmpv6": "icmp6", "icmp6": "icmpv6"}.get(ev_proto, ev_proto)}
        results.append(bool(aliases & set(protos)))
    for addr, ip in ((rule.src, ev.src_ip), (rule.dst, ev.dst_ip)):
        spec = rm.parse_address(addr, v6_default_is_any=False)
        results.append(rm.ip_in_addr(ip, spec) if ip else None)
    ports = rm.parse_ports(rule.dst_port)
    if ports == rm.ANY:
        results.append(True)
    elif isinstance(ports, rm.Unresolved):
        results.append(None)
    elif ev_proto not in rm.PORT_PROTOCOLS:
        results.append(False if ev_proto else None)
    elif ev.dst_port is None:
        results.append(None)
    else:
        results.append(rm.port_in(int(ev.dst_port), ports))
    if False in results:
        return False
    if None in results:
        return None
    return True


class _RuleIndex:
    """All enabled rules plus device names, loaded once per call."""

    def __init__(self, db: DBSession, families: set):
        self.rules = [r for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(True)).all()
                      if _family(r.device_type) in families]
        fd_ids = {r.firewall_device_id for r in self.rules if r.firewall_device_id}
        fw_ids = {r.firewall_id for r in self.rules if r.firewall_id}
        self.fd_names: dict = {}
        fd_fw: dict = {}
        if fd_ids:
            for d in db.query(FirewallDevice).filter(FirewallDevice.id.in_(fd_ids)).all():
                self.fd_names[d.id] = {n for n in (_norm(d.name), _norm(d.device_hostname)) if n}
                if d.firewall_id:
                    fd_fw[d.id] = d.firewall_id
                    fw_ids.add(d.firewall_id)
        self.fw_names: dict = {}
        if fw_ids:
            for f in db.query(Firewall).filter(Firewall.id.in_(fw_ids)).all():
                self.fw_names[f.id] = {n for n in (_norm(f.name), _norm(f.device_name)) if n}
        self._names: dict = {}
        for r in self.rules:
            names = {n for n in (_norm(r.device_name),) if n}
            names |= self.fd_names.get(r.firewall_device_id, set())
            for fid in (r.firewall_id, fd_fw.get(r.firewall_device_id)):
                names |= self.fw_names.get(fid, set())
            self._names[r.id] = names

        self.by_family = defaultdict(list)
        self.forti_pid = defaultdict(list)
        self.pf_tracker = defaultdict(list)
        self.pan_name = defaultdict(list)
        self.pan_legacy = defaultdict(list)
        self.asa_acl = defaultdict(list)
        for r in self.rules:
            fam = _family(r.device_type)
            self.by_family[fam].append(r)
            if fam == "fortinet" and r.policy_id:
                self.forti_pid[str(r.policy_id).strip()].append(r)
            elif fam == "pfsense" and r.policy_id:
                self.pf_tracker[str(r.policy_id).strip()].append(r)
            elif fam == "panos":
                keys = {k for k in (_norm(r.policy_name), _norm(r.policy_id)) if k}
                for k in keys:
                    self.pan_name[k].append(r)
                if not keys and r.device_name:
                    self.pan_legacy[_norm(r.device_name)].append(r)
            elif fam == "cisco_asa":
                acl = _norm(r.policy_name) or _norm(r.device_name)
                if acl:
                    self.asa_acl[acl].append(r)

    def acl_of(self, r) -> Optional[str]:
        return _norm(r.policy_name) or _norm(r.device_name)

    def _group(self, r, fam):
        if r.firewall_device_id:
            return ("fd", r.firewall_device_id)
        if r.firewall_id:
            return ("fw", r.firewall_id)
        if fam == "fortinet":
            return ("dn", _norm(r.device_name))
        return ("unassigned", fam)

    def scope(self, rows: list, device_name: Optional[str], fam: str):
        """Rows of the event's device; None if ambiguous."""
        if not rows:
            return []
        dn = _norm(device_name)
        if dn:
            scoped = [r for r in rows if dn in self._names.get(r.id, ())]
            if scoped:
                return scoped
        if len({self._group(r, fam) for r in rows}) == 1:
            return rows
        return None


def _first_match(rows: list, ev) -> Optional[list]:
    """First-match evaluation in rule_order. Returns the winning rows,
    [] for no match, None when an earlier row is undecidable."""
    by_order = defaultdict(list)
    for r in rows:
        by_order[r.rule_order if r.rule_order is not None else float("inf")].append(r)
    for order in sorted(by_order, key=lambda o: (o, )):
        group = sorted(by_order[order], key=lambda r: r.id)
        res = [(r, tuple_match(r, ev)) for r in group]
        winners = [r for r, m in res if m is True]
        if winners:
            return winners
        if any(m is None for _, m in res):
            return None
    return []


def _select_asa_acl(idx: _RuleIndex, rows: list, ev) -> Optional[list]:
    acls = defaultdict(list)
    for r in rows:
        acls[idx.acl_of(r)].append(r)
    if len(acls) == 1:
        return next(iter(acls.values()))
    iface = _norm((ev.raw_fields or {}).get("src_interface"))
    if iface:
        # Prefer the ASDM convention "<iface>_access_in", then any name
        # containing the interface name; must be unique to be used.
        for pred in (lambda a: a.startswith(iface + "_"), lambda a: iface in a):
            named = [a for a in acls if a and pred(a)]
            if len(named) == 1:
                return acls[named[0]]
            if named:
                break
    return None


def _candidates(idx: _RuleIndex, ev, fam: str, stats: dict) -> Optional[list]:
    """Rows to stamp for one event; None = ambiguous, [] = no match."""
    raw = ev.raw_fields or {}
    if fam == "fortinet":
        pid = (ev.policy_id or "").strip()
        if not pid or pid == "0":
            return []
        rows = idx.scope(idx.forti_pid.get(pid, []), ev.device_name, fam)
        # N-24: a FortiOS policy id is unique only inside its VDOM.  The log's
        # `vd` field pins the VDOM; without it, rows of several VDOMs sharing
        # the id cannot be told apart -> ambiguous (never stamp all of them).
        if rows:
            vd = str(raw.get("vd") or raw.get("vdom") or "").strip()
            if vd:
                rows = [r for r in rows if getattr(r, "vdom", None) in (None, vd)]
            elif len({(r.firewall_id, r.firewall_device_id, getattr(r, "vdom", None))
                      for r in rows}) > len({(r.firewall_id, r.firewall_device_id) for r in rows}):
                return None
        return rows
    if fam == "pfsense":
        tracker = (ev.policy_id or "").strip()
        if not tracker or tracker == "0":
            return []
        return idx.scope(idx.pf_tracker.get(tracker, []), ev.device_name, fam)
    if fam == "panos":
        name = _norm(ev.policy_name) or _norm(ev.policy_id)
        if not name:
            return []
        rows = idx.pan_name.get(name) or idx.pan_legacy.get(name, [])
        return idx.scope(rows, ev.device_name, fam)
    if fam == "cisco_asa":
        if raw.get("direction_known") is False or raw.get("msg_id") in _ASA_NO_ACL_DECISION:
            return []
        acl = _norm(ev.policy_name)
        if acl:
            rows = idx.scope(idx.asa_acl.get(acl, []), ev.device_name, fam)
        else:
            rows = idx.scope(idx.by_family.get(fam, []), ev.device_name, fam)
            if rows:
                rows = _select_asa_acl(idx, rows, ev)
        if not rows:
            return rows
        winners = _first_match(rows, ev)
        if winners is None:
            return None
        stats["first_match_evaluations"] += 1
        return winners
    return []


def record_rule_hits(db: DBSession, events: Iterable) -> dict:
    """
    Stamp FirewallRule.last_matched from traffic ``events`` (FortiAnalyzerEvent
    rows, flushed or not). Returns stats:
      events_considered  traffic events with an allow/deny action
      events_matched     events attributed to >= 1 rule
      rules_updated      rules whose last_matched advanced
      ambiguous          events whose rule could not be pinned to one device
                         / ACL, or whose first-match was undecidable
      unmatched          considered events with no matching enabled rule
      first_match_evaluations  ASA first-match evaluations performed
    """
    stats = {"events_considered": 0, "events_matched": 0, "rules_updated": 0,
             "ambiguous": 0, "unmatched": 0, "first_match_evaluations": 0}
    todo = []
    for ev in events or ():
        if ev is None or (ev.log_type or "").lower() != "traffic":
            continue
        action = (ev.action or "").lower()
        if action in ALLOW_ACTIONS:
            allowed = True
        elif action in DENY_ACTIONS:
            allowed = False
        else:
            continue
        fam = _event_family(ev)
        if fam is None:
            continue
        stats["events_considered"] += 1
        todo.append((ev, fam, allowed))
    if not todo:
        return stats

    idx = _RuleIndex(db, {fam for _, fam, _ in todo})
    now = datetime.now(timezone.utc)
    hits: dict = {}           # rule id -> latest event timestamp
    rules_by_id: dict = {}
    for ev, fam, allowed in todo:
        rows = _candidates(idx, ev, fam, stats)
        if rows is None:
            stats["ambiguous"] += 1
            continue
        rows = [r for r in rows if _rule_is_permit(r) == allowed]
        if not rows:
            stats["unmatched"] += 1
            continue
        if fam != "cisco_asa" and len(rows) > 1:
            # One reported rule expanded into several rows: stamp the rows
            # whose 5-tuple matches, or all of them if none can be decided.
            exact = [r for r in rows if tuple_match(r, ev) is True]
            rows = exact or rows
        stats["events_matched"] += 1
        ts = ev.event_time or ev.received_at or now
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        for r in rows:
            rules_by_id[r.id] = r
            if r.id not in hits or ts > hits[r.id]:
                hits[r.id] = ts

    for rid, ts in hits.items():
        rule = rules_by_id[rid]
        cur = rule.last_matched
        if cur is not None and cur.tzinfo is None:
            cur = cur.replace(tzinfo=timezone.utc)
        if cur is None or ts > cur:
            rule.last_matched = ts
            stats["rules_updated"] += 1
    if stats["rules_updated"]:
        db.flush()
    return stats


def record_rule_hits_safe(db: DBSession, events) -> int:
    """
    Route helper: record_rule_hits inside a SAVEPOINT so a failure here can
    never lose the caller's ingested events. Returns rules_updated (0 on
    error, which is logged). Call after the events have been flushed.
    """
    events = [e for e in (events or ()) if e is not None]
    if not events:
        return 0
    try:
        with db.begin_nested():
            return record_rule_hits(db, events)["rules_updated"]
    except Exception:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).exception("record_rule_hits failed")
        return 0
