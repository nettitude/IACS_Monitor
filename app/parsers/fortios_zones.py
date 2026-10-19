"""
FortiOS zone definitions (B-07) - ONE shared resolution helper.

``config system zone`` / SD-WAN zones are stored per (firewall, VDOM) in
``FirewallZoneDef`` (members + intrazone).  Every consumer that matches a
policy's srcintf / dstintf (FirewallRule.src_zone / dst_zone) against
interfaces or resolves them to Purdue levels uses this module, so the
semantics are identical everywhere:

  * a token naming a zone of the rule's (firewall, VDOM) stands for its
    member interfaces;
  * a zone whose membership could not be parsed is UNKNOWN - consumers must
    treat it conservatively (never as "matches nothing" / never as "any");
  * an empty zone matches no interface (the policy governs nothing);
  * "any" / "all" / "*" / NULL / empty is the universe (``None``).

Used by reachability, rule_shadow, topology_diff, alert_engine,
cross_fw_findings and topology_manager.  rule_match re-exports the public
names for backwards compatibility.
"""
from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

ANY_ZONE_TOKENS = frozenset({"any", "all", "*"})


def zone_list(zone) -> list:
    """SF-6: the names of a rule side in their configured order and case
    ("port1,port2" -> ["port1", "port2"]); [] for any / NULL / empty.  For
    labels - matching uses ``zone_tokens``."""
    if zone is None:
        return []
    names = [t.strip().strip("'\"[]") for t in str(zone).split(",")]
    names = [n for n in names if n]
    if any(n.lower() in ANY_ZONE_TOKENS for n in names):
        return []
    out = []
    for n in names:
        if n.lower() not in (x.lower() for x in out):
            out.append(n)
    return out


def zone_tokens(zone) -> Optional[frozenset]:
    """A rule's src_zone / dst_zone -> frozenset of lower-cased interface /
    zone names, or None for the universe ("any" / NULL / empty).

    C-05: srcintf / dstintf is a quote-delimited LIST; every parser joins the
    elements with a comma (never whitespace), and an interface / zone name may
    itself contain spaces ("IT Zone").  Splitting on whitespace shattered such
    names into tokens that matched nothing (deny applied both ways, false
    shadow findings), so the field is split on the comma that actually
    separates list elements and each whole name is kept intact."""
    if zone is None:
        return None
    toks = {t.strip().strip("'\"[]").lower() for t in str(zone).split(",")}
    toks.discard("")
    if not toks or toks & ANY_ZONE_TOKENS:
        return None
    return frozenset(toks)


def zone_lookup(zmap: Optional[dict], token: str) -> Optional[tuple]:
    """``token`` against one (firewall, VDOM) zone map.

    Returns None when ``token`` is not a zone of that map, else
    ``(members, resolved)``: members = lower-cased member interface names
    (may be empty: the zone matches nothing); resolved False = the
    membership is unknown (consumers must be conservative)."""
    if not zmap or not token:
        return None
    zd = zmap.get(str(token).strip().lower())
    if zd is None:
        return None
    if not zd.get("resolved", True):
        return [], False
    return list(zd.get("members") or ()), True


def expand_zone_tokens(tokens: Optional[frozenset], zone_defs: Optional[dict]) -> tuple:
    """Replace FortiOS zone names by their member interfaces.

    ``zone_defs``: {zone name (lower): {"members": [iface lower], "resolved":
    bool}} of the rule's (firewall, VDOM).  Returns (names, resolved):
    names None = universe; resolved False when a named zone's membership
    could not be parsed (that zone's name is then kept as is).  An empty
    zone expands to nothing (it matches no interface)."""
    if tokens is None or not zone_defs:
        return tokens, True
    out: set = set()
    resolved = True
    for t in tokens:
        z = zone_lookup(zone_defs, t)
        if z is None:
            out.add(t)
        elif not z[1]:
            resolved = False
            out.add(t)
        else:
            out.update(z[0])
    return frozenset(out), resolved


def load_zone_defs(db, fw_ids=None) -> dict:
    """{(firewall_id, vdom): {zone lower: {"members", "resolved",
    "intrazone", "name"}}} from FirewallZoneDef (B-07).  Never raises."""
    from app.models import FirewallZoneDef  # local import: keep this module model-free at import
    out: dict = {}
    try:
        q = db.query(FirewallZoneDef)
        if fw_ids is not None:
            ids = [i for i in fw_ids if i is not None]
            if not ids:
                return out
            q = q.filter(FirewallZoneDef.firewall_id.in_(ids))
        for zd in q.all():
            if not zd.name:
                continue
            out.setdefault((zd.firewall_id, zd.vdom), {})[zd.name.strip().lower()] = {
                "members": [str(m).strip().lower() for m in (zd.members or []) if str(m).strip()],
                "resolved": bool(zd.members_resolved),
                "intrazone": zd.intrazone or None,
                "name": zd.name,
            }
    except Exception:  # pragma: no cover - table missing in an old DB
        log.debug("FirewallZoneDef lookup failed", exc_info=True)
    return out


class ZoneDefIndex:
    """Loaded zone definitions with per-rule helpers.

    ``ZoneDefIndex(db, fw_ids=None)`` loads once; ``zmap(fw_id, vdom)``,
    ``lookup(fw_id, vdom, token)`` (see :func:`zone_lookup`) and
    ``expand(fw_id, vdom, zone_value)`` -> (names | None, resolved) (see
    :func:`expand_zone_tokens`)."""

    def __init__(self, db=None, fw_ids=None, defs: Optional[dict] = None):
        self.defs: dict = defs if defs is not None else (
            load_zone_defs(db, fw_ids) if db is not None else {})

    def __bool__(self) -> bool:
        return bool(self.defs)

    def zmap(self, fw_id, vdom) -> dict:
        if fw_id is None:
            return {}
        return self.defs.get((fw_id, vdom)) or {}

    def lookup(self, fw_id, vdom, token) -> Optional[tuple]:
        return zone_lookup(self.zmap(fw_id, vdom), token)

    def expand(self, fw_id, vdom, zone_value) -> tuple:
        return expand_zone_tokens(zone_tokens(zone_value), self.zmap(fw_id, vdom))

    def expand_rule(self, rule, attr: str) -> tuple:
        """expand() for ``rule.<attr>`` (src_zone / dst_zone)."""
        return self.expand(getattr(rule, "firewall_id", None),
                           getattr(rule, "vdom", None), getattr(rule, attr, None))

    def zones_of(self, fw_id) -> list:
        """[(vdom, zone dict)] of every zone defined on ``fw_id``."""
        return [(vd, zd) for (fid, vd), zmap in self.defs.items() if fid == fw_id
                for zd in zmap.values()]
