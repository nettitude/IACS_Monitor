"""
Chain-aware rule reviews (D-05).

The Phase 6 rule twins (``review_rule_it_ot_bypass``,
``review_rule_mgmt_wrong_zone``) judge ONE policy on ONE firewall by the
Purdue levels of its two zones.  In a design with several firewalls in
series - each touching only adjacent levels - no single policy spans IT and
OT, so those checks are blind to an IT -> PLC path that is permitted through
eight of them.  The Access Review engine already enumerates every such path
as a *chain* (one row per combination of permitting policies, one per
firewall stage, whose host scopes and services intersect).

These reviews run on those rows and raise one finding per chain row whose
chain crosses at least two enforcement points:

``chain_it_ot_bypass``
    row flagged ``it_ot_bypass`` (IT side incl. the DMZ -> L0/L1, or L4/L5 ->
    L2 in one routed session).  high for a deep-OT destination, medium for
    L2; one step up when the path is seen in the capture.
``chain_mgmt_wrong_zone``
    IT-side -> OT row whose services overlap the management ports (SSH,
    Telnet, HTTPS, RDP, HTTP, SNMP).  medium, high when seen; a DMZ-only
    source (the sanctioned jump-host location) one step lower.

Single-firewall rows are left to the rule twins (they would be duplicates);
so is a tail whose source is one host known to live at another level (see
_foreign_source).
Rows flagged ``direction_unverified`` (D-11: no level evidence behind a
policy, the row may be reversed) are skipped and reported as unevaluated
rather than raised, so a mislabelled firewall never produces a critical
finding by accident.  Rows the reviewer classified ``reviewed_ok`` /
``exception`` are not raised (and an existing finding auto-resolves).

Findings dedup on the row's stable tag_key, so re-ingesting the same
configuration re-detects rather than duplicates.  Evidence carries the whole
chain (every policy, in order), the path label, services, flags and traffic.
"""
from __future__ import annotations

import ipaddress
from typing import Optional
import logging

from sqlalchemy.orm import Session as DBSession

from app.purdue import fmt_level, is_deep_ot, is_dmz, is_it_side, is_ot

log = logging.getLogger(__name__)

CHECK_BYPASS = "chain_it_ot_bypass"
CHECK_UPWARD = "chain_ot_upward_skip"
CHECK_MGMT = "chain_mgmt_wrong_zone"
CHECK_DMZ = "dmz_bypass"
CHECK_INET = "path_ot_internet_egress"
# remote-access / interactive management protocols (dmz_bypass severity)
_REMOTE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5938: "TeamViewer"}

_MGMT_PORTS: dict[int, str] = {
    22: "SSH", 23: "Telnet", 443: "HTTPS", 3389: "RDP",
    80: "HTTP", 8080: "HTTP-alt", 8443: "HTTPS-alt", 161: "SNMP",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",         # SF-3
}
_STEP_UP = {"info": "low", "low": "medium", "medium": "high", "high": "critical",
            "critical": "critical"}
_STEP_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "info",
              "info": "info"}
_SUPPRESSING = ("reviewed_ok", "exception")
_RUN_CACHE_KEY = "access_paths.run_cache"


# ------------------------------------------------------------- enumeration --
def chain_rows(db: DBSession) -> dict:
    """The site's enumeration (overlay on, unexplained flows off), computed
    once per review run: run_periodic_reviews installs ``db.info[
    "access_paths.run_cache"]`` and every consumer in that run shares the
    result.  Outside a run the enumeration is computed afresh."""
    from app.parsers.access_paths import _enumerate
    from app.parsers.site_scope import current_site

    cache = db.info.get(_RUN_CACHE_KEY)
    key = ("enum", current_site(db))
    if cache is not None and key in cache:
        return cache[key]
    res = _enumerate(db, overlay=True, unmatched_cap=0)
    if cache is not None:
        cache[key] = res
    return res


def _multi_hop(row: dict) -> bool:
    chain = row.get("chain") or []
    # several firewalls (or several enforcement points: the VDOMs of one
    # FortiGate in series, VD-01) in series
    return n_points(row) >= 2


def n_points(row: dict) -> int:
    """Enforcement points in the chain: firewalls, a VDOM counting as one."""
    return len({(c.get("firewall_device_id"), c.get("firewall_id"), c.get("firewall_name"), c.get("vdom"))
                for c in row.get("chain") or []})


def points_word(row: dict) -> str:
    """'3 firewalls' / '2 VDOMs' / '2 enforcement points' for titles."""
    n = n_points(row)
    fws = {c.get("firewall_name") for c in row.get("chain") or []}
    if len(fws) == n:
        return f"{n} firewall{'s' if n != 1 else ''}"
    if len(fws) == 1:
        return f"{n} VDOMs of {next(iter(fws))}"
    return f"{n} enforcement points"


def _seen(row: dict) -> bool:
    return ((row.get("traffic") or {}).get("status")) == "seen"


def _ports(row: dict) -> set[int]:
    """Individual management ports a row's service list covers."""
    out: set[int] = set()
    for svc in row.get("service") or []:
        s = str(svc).lower()
        if s in ("any", "ip", "all", "*"):
            return set(_MGMT_PORTS)
        if "/" in s:
            proto, _, ports = s.partition("/")
            if proto not in ("tcp", "udp", "any", ""):
                continue
            s = ports
        for tok in s.split(","):
            tok = tok.strip()
            if not tok:
                continue
            if tok in ("any", "*"):
                return set(_MGMT_PORTS)
            lo, _, hi = tok.partition("-")
            try:
                lo_i = int(lo)
                hi_i = int(hi) if hi else lo_i
            except ValueError:
                continue
            out |= {p for p in _MGMT_PORTS if lo_i <= p <= hi_i}
    return out


def _evidence(row: dict) -> dict:
    from app.parsers.access_path_findings import allowed_by, path_label
    src, dst = row.get("src") or {}, row.get("dst") or {}
    return {
        "chain_review": True,
        "access_path_tag": row.get("tag_key"),
        "path": {"src": {"level": src.get("level"), "zone": src.get("zone"), "scope": src.get("scope")},
                 "dst": {"level": dst.get("level"), "zone": dst.get("zone"), "scope": dst.get("scope")},
                 "direction": row.get("direction")},
        "path_label": path_label(row),
        "service": list(row.get("service") or []),
        "chain": [dict(c) for c in row.get("chain") or []],
        "allowed_by": allowed_by(row),
        "firewalls": len({c.get("firewall_name") for c in row.get("chain") or []}),
        "enforcement_points": n_points(row),
        "flags": list(row.get("flags") or []),
        "traffic": dict(row.get("traffic") or {}),
        "classification": row.get("classification"),
        "paths_in_group": len(row.get("_rows") or [row]),
        "access_path_tags": [m.get("tag_key") for m in (row.get("_rows") or [row])][:50],
        **({"nat": list(row["nat"])} if row.get("nat") else {}),
    }


def nat_sentence(row: dict) -> str:
    """P-09: the translations on a path, for a finding's text."""
    parts = []
    for e in row.get("nat") or []:
        if e.get("type") == "dnat":
            parts.append(f"published by VIP {e.get('name')} on {e.get('firewall')} "
                         f"({e.get('external')} → {e.get('mapped')})")
        else:
            parts.append(f"source NAT on {e.get('firewall')} policy {e.get('policy_id')} "
                         f"(sources become {e.get('translated_to')})")
    return ("NAT on the way: " + "; ".join(parts) + ". ") if parts else ""


def _emit(db, ae, check: str, row: dict, title: str, text: str, severity: str, ev_extra=None,
          severity_reason=None):
    chain = row.get("chain") or []
    ev = _evidence(row)
    if severity_reason:
        ev["severity_reason"] = severity_reason
    ns = nat_sentence(row)
    if ns and ns not in text:
        text = text.rstrip() + " " + ns
    if ev_extra:
        ev.update(ev_extra)
    key = _group_key_text(row) if row.get("_rows") is not None else row.get("tag_key")
    return ae._make_finding(
        db, check, title[:512], text, ev,
        firewall_rule_id=(chain[0].get("rule_id") if chain else None),
        device_name=(chain[0].get("firewall_name") if chain else None),
        severity=severity,
        dedup_evidence={"rule_key": f"access_path_chain:{key}"},
    )


def _foreign_source(row: dict, host_levels: dict, nets: Optional[list] = None) -> bool:
    """True when the row's source scope lives at ANOTHER Purdue level than
    the row's source level - one specific host with a known level, or (MP-06)
    a network inside a labelled interface network of another level: the row
    is the tail of a longer chain (the policies downstream name that host /
    network as an allowed source), not a path that originates here.  The
    longer chain is its own finding; raising the tail too would double every
    remote-access path once per boundary it crosses."""
    from app.parsers import rule_match as rm
    from app.parsers.access_paths import _scope_level
    scope = (row.get("src") or {}).get("scope")
    level = (row.get("src") or {}).get("level")
    if not scope or level is None:
        return False
    try:
        spec = rm.parse_address(scope, v6_default_is_any=False)
    except Exception:
        return False
    sl = _scope_level(spec, host_levels, nets)
    return sl is not None and sl != level


# ------------------------------------------------------------- dead ends --
def _host_levels(db) -> dict:
    from app.models import Host
    from app.parsers.remote_access import canon_ip
    return {canon_ip(ip): lv for ip, lv in db.query(Host.ip, Host.purdue_level)
            .filter(Host.ip.isnot(None), Host.purdue_level.isnot(None))}


def _iface_nets(db) -> list:
    """(parsed network, level) of every labelled firewall interface."""
    from app.parsers.access_paths import _iface_nets as _nets
    return _nets(db)


def _scope_level(scope, host_levels: dict, nets: list):
    """The Purdue level a row side's address scope actually lives at (text
    form of access_paths._scope_level)."""
    from app.parsers import rule_match as rm
    from app.parsers.access_paths import _scope_level as _lv
    if not scope:
        return None
    try:
        spec = rm.parse_address(scope, v6_default_is_any=False)
    except Exception:
        return None
    return _lv(spec, host_levels, nets)


def _egress_nets(db) -> dict:
    """{(firewall_id, interface or zone name lower): [parsed networks]} - the
    networks a firewall delivers onto through that interface / FortiOS zone."""
    from app.models import Firewall, FirewallInterface, FirewallZoneDef
    from app.parsers import rule_match as rm
    out: dict = {}
    by_iface: dict = {}
    for fid, name, cidr in db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                                    FirewallInterface.network_cidr).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            FirewallInterface.network_cidr.isnot(None)):
        try:
            net = rm.parse_address(cidr)
        except Exception:
            continue
        by_iface.setdefault((fid, str(name).strip().lower()), []).append(net)
    out.update(by_iface)
    for zd in db.query(FirewallZoneDef).join(Firewall, Firewall.id == FirewallZoneDef.firewall_id):
        nets = [n for m in zd.members or [] for n in by_iface.get((zd.firewall_id, str(m).strip().lower()), [])]
        if nets:
            out.setdefault((zd.firewall_id, str(zd.name).strip().lower()), []).extend(nets)
    return out


def _delivered(row: dict, egress: dict) -> bool:
    """H-07: the destination scope lies on a network the chain's LAST
    firewall delivers onto (its egress interface / zone): the traffic arrives,
    whatever level the destination device is classified at (a PLC on a flat
    L2 segment is reached through the L2 interface)."""
    from app.parsers import rule_match as rm
    chain = row.get("chain") or []
    if not chain or not egress:
        return False
    fid = chain[-1].get("firewall_id")
    scope = (row.get("dst") or {}).get("scope")
    zones = [z.strip().lower() for z in str((row.get("dst") or {}).get("zone") or "").split(",") if z.strip()]
    if fid is None or not scope or not zones:
        return False
    try:
        spec = rm.parse_address(scope, v6_default_is_any=False)
    except Exception:
        return False
    if spec == rm.ANY or isinstance(spec, rm.Unresolved):
        return False
    for z in zones:
        for net in egress.get((fid, z), ()):
            try:
                if rm.addr_contains(net, spec) is True:
                    return True
            except Exception:
                continue
    return False


def _beyond(direction: str, real, reached) -> bool:
    if real is None or reached is None:
        return False
    return real < reached if direction == "down" else real > reached if direction == "up" else False


def _chain_ids(row: dict) -> tuple:
    return tuple((c.get("firewall_name"), c.get("vdom"), c.get("policy_id"))
                 for c in row.get("chain") or [])


def classify_reach(rows: list, host_levels: dict, nets: list, egress: dict | None = None) -> dict:
    """id(row) -> "reaches" | "prefix" | "dead_end" for cross-boundary rows.

    A row whose destination scope lives BEYOND the level the row reaches
    does not deliver its traffic there: either a longer row continues it
    (same policies first, then more) - "prefix", reported by the longer row -
    or nothing does: the next boundary drops it - "dead_end"."""
    out = {}
    by_dir: dict = {}
    for r in rows:
        if r.get("direction") in ("down", "up"):
            by_dir.setdefault(r["direction"], []).append(r)
    for direction, rs in by_dir.items():
        prefixes = {}
        for r in rs:
            ids = _chain_ids(r)
            for k in range(1, len(ids)):
                prefixes.setdefault(ids[:k], []).append(r)
        for r in rs:
            reached = (r.get("dst") or {}).get("level")
            real = _scope_level((r.get("dst") or {}).get("scope"), host_levels, nets)
            if not _beyond(direction, real, reached) or _delivered(r, egress or {}):
                out[id(r)] = "reaches"
                continue
            longer = [x for x in prefixes.get(_chain_ids(r), ())
                      if _beyond(direction, (x.get("dst") or {}).get("level"), reached)]
            out[id(r)] = "prefix" if longer else "dead_end"
    return out


def _note_truncated(db, ae, res: dict) -> None:
    """MP-08: a truncated enumeration is recorded on the running review
    (auto-resolve off, last_review_info()["truncated"]) - not only logged."""
    if res.get("truncated"):
        ae._mark_incomplete(db, "access-path enumeration truncated")
        ae._record_truncation(db, "access-path enumeration", None)


def review_access_path_truncation(db: DBSession) -> list:
    """MP-08: one informational finding per site while the permitted-path
    enumeration stops at its row budget - the chain reviews then judge a
    partial list (IT -> OT cells are enumerated first, so the deepest
    crossings are the last to be lost).  Closes once a run completes."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_paths import _max_rows
    res = chain_rows(db)
    _note_truncated(db, ae, res)
    if not res.get("truncated"):
        return []
    budget = _max_rows()
    f = ae._make_finding(
        db, "access_path_enumeration_truncated",
        f"Permitted-path enumeration truncated at {budget} rows: chain reviews ran on a partial list",
        (f"The permitted-path list stopped at its row budget (IACS_MAX_ACCESS_PATH_ROWS = {budget}), "
         f"so the chain reviews judged only the {len(res.get('paths') or [])} listed rows. Downhill "
         "IT -> OT level pairs are enumerated first and deepest first, so IT -> OT crossings are "
         "the last to be dropped, but the list is incomplete and a crossing that is not listed is "
         "not a pass. Findings of the chain reviews are not auto-resolved while this holds."),
        {"budget": budget, "rows_listed": len(res.get("paths") or []),
         "truncated_visible": bool(res.get("truncated_visible"))},
        severity="info",
        dedup_evidence={"rule_key": "access_path_enumeration_truncated"},
    )
    return [f] if f is not None else []


def _candidates(db, ae, direction: str = "down", multi_only: bool = True) -> list[dict]:
    res = chain_rows(db)
    _note_truncated(db, ae, res)
    host_levels = _host_levels(db)
    nets = _iface_nets(db)
    reach = classify_reach(res["paths"], host_levels, nets, _egress_nets(db))
    rows = []
    unverified = 0
    for row in res["paths"]:
        if row.get("direction") != direction or (multi_only and not _multi_hop(row)):
            continue
        if "direction_unverified" in (row.get("flags") or []):
            unverified += 1
            continue
        if _foreign_source(row, host_levels, nets):
            continue
        if reach.get(id(row)) in ("prefix", "dead_end"):
            continue      # does not deliver to its destination: dead-end / longer row
        rows.append(row)
    if unverified:
        log.info("chain reviews: %d multi-firewall row(s) skipped - direction unverified "
                 "(label the firewall interfaces)", unverified)
    return rows


def _longest_only(rows: list[dict]) -> list[dict]:
    """Drop a row whose policy chain is a strict prefix of another candidate
    row with the same source scope and services: one policy chain that
    reaches several levels (destination "any") is ONE finding, raised on the
    row that reaches furthest; that finding's evidence names the levels on
    the way."""
    keyed = [(r, _chain_ids(r), (r.get("src") or {}).get("scope"), tuple(r.get("service") or ()))
             for r in rows]
    out = []
    for r, ids, src, svc in keyed:
        longer = [x for x, xids, xsrc, xsvc in keyed
                  if x is not r and xsrc == src and xsvc == svc and len(xids) > len(ids)
                  and xids[:len(ids)] == ids]
        if not longer:
            via = sorted({(x.get("dst") or {}).get("level") for x, xids, xsrc, xsvc in keyed
                          if x is not r and xsrc == src and xsvc == svc and len(xids) < len(ids)
                          and ids[:len(xids)] == xids} - {None})
            if via:
                r = dict(r)
                r["_also_reaches"] = via
            out.append(r)
    return out


# ---------------------------------------------------------------- grouping --
def merge_scopes(scopes) -> str:
    """One display text for several address scopes: adjacent pieces merged
    (an iprange split into /29 + /31 + /32 at ingest reads as one range
    again), single hosts as addresses, exact networks as CIDRs; "any" wins;
    more than 6 items are counted."""
    import ipaddress
    from app.parsers import rule_match as rm
    texts = [str(x) for x in scopes if x]
    if not texts:
        return ""
    by_v: dict = {}
    other = []
    for t in texts:
        try:
            spec = rm.parse_address(t, v6_default_is_any=False)
        except Exception:
            spec = None
        if spec == rm.ANY:
            return "any"
        if spec is None or isinstance(spec, rm.Unresolved):
            if t not in other:
                other.append(t)
            continue
        for v, ivs in rm.addr_intervals(spec).items():
            by_v.setdefault(v, []).extend(ivs)
    parts = []
    for v in sorted(by_v):
        cls = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
        for lo, hi in rm._merge(by_v[v]):
            a, b = cls(lo), cls(hi)
            if lo == hi:
                parts.append(str(a))
                continue
            nets = list(ipaddress.summarize_address_range(a, b))
            parts.append(str(nets[0]) if len(nets) == 1 else f"{a}-{b}")
    parts += other
    if len(parts) > 6:
        return f"{', '.join(parts[:5])} (+{len(parts) - 5} more)"
    return ", ".join(parts)


def group_rows(rows: list[dict]) -> list[dict]:
    """H-06: ONE finding per policy chain.  Rows are produced per expanded
    rule row (address pieces x destination hosts x services); rows that share
    direction, policy chain and level pair collapse into one synthetic row
    whose scopes are merged, services united and traffic "seen" if any row
    was.  ``_rows`` keeps the members (count, tag keys)."""
    groups: dict = {}
    order = []
    for r in rows:
        key = (r.get("direction"), _chain_ids(r), (r.get("src") or {}).get("level"),
               (r.get("dst") or {}).get("level"))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)
    out = []
    for key in order:
        members = groups[key]
        first = members[0]
        if len(members) == 1:
            g = dict(first)
            g["_rows"] = members
            out.append(g)
            continue
        g = dict(first)
        g["src"] = dict(first.get("src") or {})
        g["dst"] = dict(first.get("dst") or {})
        g["src"]["scope"] = merge_scopes((m.get("src") or {}).get("scope") for m in members)
        g["dst"]["scope"] = merge_scopes((m.get("dst") or {}).get("scope") for m in members)
        svc = []
        for m in members:
            for x in m.get("service") or []:
                if x not in svc:
                    svc.append(x)
        g["service"] = ["any"] if "any" in svc else svc
        flags = []
        for m in members:
            for f in m.get("flags") or []:
                if f not in flags:
                    flags.append(f)
        g["flags"] = flags
        nat = []
        for m in members:
            for e in m.get("nat") or []:
                if e not in nat:
                    nat.append(e)
        if nat:
            g["nat"] = nat
        if any(_seen(m) for m in members):
            g["traffic"] = dict(next(m for m in members if _seen(m)).get("traffic") or {})
        g["_rows"] = members
        out.append(g)
    return out


def _group_key_text(g: dict) -> str:
    """Stable dedup identity of a grouped finding: the policy chain + levels."""
    ids = "|".join(f"{n}/{v or ''}/{p}" for n, v, p in _chain_ids(g))
    return (f"{g.get('direction')}:{(g.get('src') or {}).get('level')}>"
            f"{(g.get('dst') or {}).get('level')}:{ids}")


# ----------------------------------------------------------------- reviews --
#: MP-11: chain_it_ot_bypass severity by (source band, destination band).
#: Source bands: "internet" (L5), "enterprise" (L4), "dmz" (L3.5), "site"
#: (L3 - site operations, the near side of the conduit).  Destination bands:
#: "deep" (L0/L1), "control" (L2).  An internet -> PLC chain outranks a SCADA
#: server -> PLC chain; a DMZ source is one step below enterprise (the DMZ is
#: where the session is supposed to break, but it is still a routed hop).
_BYPASS_SEVERITY = {
    ("internet", "deep"): "critical", ("internet", "control"): "high",
    ("enterprise", "deep"): "high",    ("enterprise", "control"): "medium",
    ("dmz", "deep"): "medium",         ("dmz", "control"): "low",
    ("site", "deep"): "medium",        ("site", "control"): "low",
}
_SRC_BAND_WHY = {
    "internet": "the internet / an untrusted network (L5)",
    "enterprise": "the enterprise network (L4) - the most exposed part of the plant network",
    "dmz": "the industrial DMZ (L3.5), which should broker sessions, not route them",
    "site": "site operations (L3) - a server that should talk to the control zone only through a conduit",
}


def bypass_severity(src_level, dst_level) -> tuple:
    """(severity, source band, why-text) for an IT/OT bypass chain (MP-11)."""
    if src_level is None:
        band = "enterprise"
    elif src_level >= 5:
        band = "internet"
    elif src_level >= 4:
        band = "enterprise"
    elif src_level == 3.5:
        band = "dmz"
    else:
        band = "site"
    dst = "deep" if is_deep_ot(dst_level) else "control"
    return _BYPASS_SEVERITY.get((band, dst), "medium"), band, _SRC_BAND_WHY[band]


def review_chain_it_ot_bypass(db: DBSession) -> list:
    """D-05: IT/OT boundary bypass permitted by a CHAIN of policies across
    several firewalls (check 2.1 / 2.2, SR 5.1 RE2, SR 5.2)."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_path_findings import allowed_by, path_label

    from app.parsers import vpn as _vpn
    vctx = _vpn.VpnContext.build(db)
    out = []
    rows = [r for r in _candidates(db, ae)
            if "it_ot_bypass" in r["flags"] and r.get("classification") not in _SUPPRESSING
            and not vctx.is_vpn_row(r)]            # VPN-sourced: vpn_direct_to_ot
    for row in group_rows(rows):
        dst_level = (row.get("dst") or {}).get("level")
        src_level = (row.get("src") or {}).get("level")
        deep = is_deep_ot(dst_level)
        seen = _seen(row)
        severity, src_band, why_src = bypass_severity(src_level, dst_level)
        if seen:
            severity = _STEP_UP[severity]
        narrow = [c for c in (row.get("chain") or []) if c.get("narrowest")]
        change_point = ("; the narrowest policy - the place to narrow or remove - is "
                        + ", ".join(f"{c.get('firewall_name')} #{c.get('policy_id')}" for c in narrow[:3])
                        if narrow and len(row.get("chain") or []) > 1 else "")
        title = (f"IT/OT boundary bypass across {points_word(row)}: {path_label(row)} "
                 f"({', '.join(row['service']) or 'any'})" + (" [seen in capture]" if seen else ""))
        text = (f"The policies {allowed_by(row)} together permit one routed session from "
                f"{fmt_level(src_level)} to {fmt_level(dst_level)} over "
                f"{', '.join(row['service']) or 'any service'}: each firewall only sees a "
                f"crossing between adjacent levels, so no single rule looks wrong, but the "
                f"chain reaches {'field devices / basic control' if deep else 'the control zone'} "
                f"from {why_src} without a session break in the industrial DMZ "
                f"(SR 5.1 RE2, SR 5.2). "
                + ("Matching traffic was seen in the capture." if seen else
                   "No matching traffic observed yet; the chain is a standing zone-isolation "
                   "violation.")
                + " Review each policy in the chain" + change_point
                + "; terminating the path on a DMZ host (jump host / historian) restores the boundary.")
        f = _emit(db, ae, CHECK_BYPASS, row, title, text, severity,
                  ev_extra={"source_band": src_band, "change_point": [
                      {"firewall": c.get("firewall_name"), "policy_id": c.get("policy_id")} for c in narrow]},
                  severity_reason=(f"{severity.capitalize()}: {why_src} reaches "
                                   f"{'basic control / field devices (L0/L1)' if deep else 'the control zone (L2)'}"
                                   " (severity by source and destination band, see bypass_severity)"
                                   + ("; raised one step because matching traffic was seen in the capture."
                                      if seen else "; one step higher once matching traffic is seen.")))
        if f is not None:
            out.append(f)
    return out


def review_chain_mgmt_wrong_zone(db: DBSession) -> list:
    """D-05: management protocol reaching OT from the IT side through a CHAIN
    of policies across several firewalls (check 5.1, SR 1.3, SR 5.1 RE1)."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_path_findings import allowed_by, path_label

    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)

    def _from_mgmt(row) -> bool:
        """Source entirely inside declared management networks / trusted
        hosts, or a source zone declared a management zone on the first
        firewall: the sanctioned management path."""
        src = row.get("src") or {}
        # the destination is OT (checked by the caller): engineering counts
        if mctx.scope_is_mgmt(src.get("scope"), ot=True):
            return True
        chain = row.get("chain") or []
        fw_id = chain[0].get("firewall_id") if chain else None
        toks = [t.strip() for t in str(src.get("zone") or "").split(",") if t.strip()]
        return bool(toks) and all(mctx.name_class(fw_id, t, ot=True) is True for t in toks)

    from app.parsers import vpn as _vpn
    vctx = _vpn.VpnContext.build(db)
    keep = []
    for row in _candidates(db, ae):
        if row.get("classification") in _SUPPRESSING or vctx.is_vpn_row(row):
            continue
        src_level = (row.get("src") or {}).get("level")
        dst_level = (row.get("dst") or {}).get("level")
        if not (is_it_side(src_level) and is_ot(dst_level)):
            continue
        if not _ports(row) or _from_mgmt(row):
            continue
        keep.append(row)
    out = []
    for row in group_rows(keep):
        ports = _ports(row)
        src_level = (row.get("src") or {}).get("level")
        dst_level = (row.get("dst") or {}).get("level")
        seen = _seen(row)
        severity = "high" if seen else "medium"
        dmz_source = is_dmz(src_level)
        if dmz_source:
            severity = _STEP_DOWN[severity]
        names = ", ".join(_MGMT_PORTS[p] for p in sorted(ports))
        n_fw = n_points(row)
        title = (f"Management access from {'DMZ' if dmz_source else 'IT'} to OT across {points_word(row)}: "
                 f"{names} {path_label(row)}" + (" [seen in capture]" if seen else ""))
        text = (f"The policies {allowed_by(row)} together permit {names} from "
                f"{fmt_level(src_level)} to {fmt_level(dst_level)}. Management access to OT "
                f"equipment must originate only from a dedicated management zone (SR 5.1 RE1, "
                f"SR 1.3); no single firewall in the chain sees the whole crossing. "
                + ("The source is the industrial DMZ (L3.5), the sanctioned location for "
                   "remote-access jump hosts: restrict the first policy's source to the "
                   "approved jump host(s) and the services they need. " if dmz_source else "")
                + ("Matching traffic was seen in the capture." if seen else
                   "No matching traffic observed yet; the chain creates a standing "
                   "management-access risk."))
        f = _emit(db, ae, CHECK_MGMT, row, title, text, severity,
                  severity_reason=(f"{severity.capitalize()}: "
                                   + ("matching traffic was seen in the capture" if seen else
                                      "no matching traffic in the capture yet (one step up once seen)")
                                   + ("; one step lower because the source is the industrial DMZ, where "
                                      "jump hosts belong." if dmz_source else ".")))
        if f is not None:
            out.append(f)
    return out


def review_chain_ot_upward_skip(db: DBSession) -> list:
    """G-02: OT reaching the IT side in ONE routed session - deep OT (L0/L1)
    to L3 and up, or L2 to L4/L5 - permitted by a chain of policies (one or
    more firewalls).  The upward mirror of chain_it_ot_bypass: an OT device
    initiating straight to a site / enterprise system skips the tiers that
    should terminate it (SR 5.1 RE2, SR 5.2).  medium; one step up when seen
    in the capture."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_path_findings import allowed_by, path_label

    out = []
    def _switch_only(r):
        return all(str(c.get("policy_id") or "").startswith("implicit:route:") for c in r.get("chain") or [])
    # RS-04: a chain that is only a routing switch's implicit route is
    # switch_routes_between_zones; a chain ending at the Internet level (L5)
    # is path_ot_internet_egress - neither is reported twice
    from app.parsers.mgmt_networks import build_context as _mgmt_ctx
    mctx = _mgmt_ctx(db)
    cands = [r for r in _candidates(db, ae, direction="up", multi_only=False)
             if "ot_upward_skip" in r["flags"] and r.get("classification") not in _SUPPRESSING
             and not _switch_only(r) and (r.get("dst") or {}).get("level") != 5
             # owner (SF): time sync to the declared site NTP server is not a skip
             and not mctx.is_ntp_scope((r.get("dst") or {}).get("scope"), r.get("service"))]
    for row in group_rows(_longest_only(cands)):
        src_level = (row.get("src") or {}).get("level")
        dst_level = (row.get("dst") or {}).get("level")
        seen = _seen(row)
        severity = _STEP_UP["medium"] if seen else "medium"
        n_fw = n_points(row)
        title = (f"OT upward skip across {points_word(row)}: {path_label(row)} "
                 f"({', '.join(row['service']) or 'any'})" + (" [seen in capture]" if seen else ""))
        text = (f"The policies {allowed_by(row)} let {fmt_level(src_level)} open sessions straight to "
                f"{fmt_level(dst_level)} over {', '.join(row['service']) or 'any service'}. An OT "
                "device initiating to a site / enterprise system in one routed session skips the "
                "tiers that should terminate it (historian, DMZ broker) - the upward mirror of an "
                "IT/OT bypass (SR 5.1 RE2, SR 5.2). "
                + ("Matching traffic was seen in the capture." if seen else
                   "No matching traffic observed yet.")
                + (f" The same policies also let it reach "
                   f"{', '.join(fmt_level(v) for v in row['_also_reaches'])} on the way."
                   if row.get("_also_reaches") else "")
                + " Terminate the flow on a host of the next tier, or document it as an "
                  "exception in Access Review.")
        f = _emit(db, ae, CHECK_UPWARD, row, title, text, severity,
                  severity_reason=("High: medium for an upward skip, one step up because matching "
                                   "traffic was seen." if seen else
                                   "Medium: no matching traffic in the capture yet (high once seen)."))
        if f is not None:
            out.append(f)
    return out


# ---------------------------------------------------------- dead-end permits --
def _representative(db, scope, level=None) -> Optional[str]:
    """MP-19: one address that stands for ``scope`` on a path trace - the
    scope itself when it is one host, else a classified host inside it (at
    ``level`` when given), else the first usable address of a single
    network.  None for "any" / unresolved / scattered scopes."""
    from app.models import Host
    from app.parsers import rule_match as rm
    from app.parsers.access_paths import _single_host
    if not scope:
        return None
    try:
        spec = rm.parse_address(scope, v6_default_is_any=False)
    except Exception:
        return None
    if spec == rm.ANY or isinstance(spec, rm.Unresolved):
        return None
    ip = _single_host(spec)
    if ip is not None:
        return ip
    best = None
    for h_ip, h_lv in db.query(Host.ip, Host.purdue_level).filter(Host.ip.isnot(None)):
        try:
            if rm.ip_in_addr(h_ip, spec) is True:
                if level is None or h_lv == level:
                    return h_ip
                best = best or h_ip
        except Exception:
            continue
    if best:
        return best
    try:
        iv = rm.addr_intervals(spec)
    except Exception:
        return None
    found = [(v, lo, hi) for v, ranges in iv.items() for lo, hi in ranges]
    if len(found) != 1:
        return None
    v, lo, hi = found[0]
    cand = lo + 1 if hi > lo else lo
    return str(ipaddress.IPv4Address(cand) if v == 4 else ipaddress.IPv6Address(cand))


def _blocking_point(db, row: dict) -> dict:
    """Where the traffic of a dead-end row stops: the enforcement point that
    denies it on the full path (explicit deny rule or implicit deny), from
    the path engine for a representative source / destination address of
    the row (MP-19: a network scope is traced through one address of it)."""
    from app.parsers.reachability import compute_path

    src = _representative(db, (row.get("src") or {}).get("scope"), (row.get("src") or {}).get("level"))
    dst = _representative(db, (row.get("dst") or {}).get("scope"))
    if not src or not dst:
        return {}
    traced = {"traced_src": src, "traced_dst": dst}
    port = proto = None
    for svc in row.get("service") or []:
        p, _, rest = str(svc).partition("/")
        if rest and rest.split("-")[0].split(",")[0].isdigit():
            proto, port = p, int(rest.split("-")[0].split(",")[0])
            break
    try:
        res = compute_path(db, src, dst, dst_port=port, protocol=proto)
    except Exception:
        log.debug("dead-end: path trace failed for %s -> %s", src, dst, exc_info=True)
        return {}
    for hop in res.get("hops") or []:
        for ep in hop.get("enforcement_points") or []:
            if ep.get("decision") == "deny" and not ep.get("not_on_path"):
                mr = ep.get("matching_rule") or {}
                fw = ep.get("firewall_device") or {}
                return {**traced, "firewall": fw.get("name"),
                        "boundary": [hop.get("from_level"), hop.get("to_level")],
                        "implicit_deny": bool(ep.get("implicit_deny")),
                        "rule": ({"policy_id": mr.get("policy_id"), "policy_name": mr.get("policy_name"),
                                  "vdom": mr.get("vdom")} if mr else None)}
    return {**traced, "overall": res.get("overall")}


def _attempts(db, row: dict) -> int:
    """Captured sessions and connection attempts from the row's source scope
    to its destination scope on its services (attempts: they cannot have got
    through)."""
    from app.models import Host, NetworkSession
    from app.parsers import rule_match as rm
    from sqlalchemy.orm import aliased
    try:
        sspec = rm.parse_address((row.get("src") or {}).get("scope") or "any", v6_default_is_any=False)
        dspec = rm.parse_address((row.get("dst") or {}).get("scope") or "any", v6_default_is_any=False)
    except Exception:
        return 0
    from app.parsers.access_paths import _single_host
    dip = _single_host(dspec)
    if dip is None:
        return 0
    ports = set()
    for svc in row.get("service") or []:
        _p, _, rest = str(svc).partition("/")
        for tok in rest.split(","):
            lo, _, hi = tok.partition("-")
            if lo.isdigit():
                ports |= set(range(int(lo), int(hi or lo) + 1)) if int(hi or lo) - int(lo) < 1024 else set()
    sh, dh = aliased(Host), aliased(Host)
    q = (db.query(NetworkSession.dst_port, sh.ip)
         .join(sh, NetworkSession.src_host_id == sh.id)
         .join(dh, NetworkSession.dst_host_id == dh.id)
         .filter(dh.ip == dip))
    n = 0
    for port, sip in q.limit(5000):
        if ports and port not in ports:
            continue
        try:
            if rm.addr_contains(sspec, rm.parse_address(sip)) is True:
                n += 1
        except Exception:
            continue
    # FO-04: refused / unanswered connection attempts are kept apart from
    # sessions - they are exactly the attempts this asks about
    from app.models import ConnectionAttempt
    for port, sip in db.query(ConnectionAttempt.dst_port, ConnectionAttempt.src_ip).filter(
            ConnectionAttempt.dst_ip == dip, ConnectionAttempt.dst_port.isnot(None)).limit(5000):
        if ports and port not in ports:
            continue
        try:
            if rm.addr_contains(sspec, rm.parse_address(sip)) is True:
                n += 1
        except Exception:
            continue
    return n


def review_dead_end_permits(db: DBSession) -> list:
    """3.8 / SR 7.7 least functionality: a permit (or chain of permits) whose
    destination lies beyond the boundary the chain reaches and that no
    further policy carries on - the next boundary drops the traffic.  Legacy
    leftover (the downstream rule was removed), half-finished change, or an
    over-broad upstream rule: either way a person should look.  low; medium
    when the capture shows attempts (someone relies on it, or probes)."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_path_findings import allowed_by, path_label
    from app.purdue import fmt_level

    res = chain_rows(db)
    _note_truncated(db, ae, res)
    host_levels = _host_levels(db)
    nets = _iface_nets(db)
    reach = classify_reach(res["paths"], host_levels, nets, _egress_nets(db))
    out = []
    dead = [row for row in res["paths"]
            if reach.get(id(row)) == "dead_end"
            and "direction_unverified" not in (row.get("flags") or [])
            and not _foreign_source(row, host_levels, nets)
            and row.get("classification") not in _SUPPRESSING]
    for row in group_rows(dead):
        members = row.get("_rows") or [row]
        reached = (row.get("dst") or {}).get("level")
        real = _scope_level((members[0].get("dst") or {}).get("scope"), host_levels, nets)
        attempts = sum(_attempts(db, m) for m in members[:20])
        block = next((b for b in (_blocking_point(db, m) for m in members[:5]) if b.get("firewall")),
                     {}) or _blocking_point(db, members[0])
        severity = "medium" if attempts else "low"
        names = " ".join(str(c.get("policy_name") or "") for c in row.get("chain") or []).upper()
        markers = [m for m in ("TEMP", "LEGACY", "OLD", "TKT", "TICKET", "TEST") if m in names]
        where = ""
        if block.get("firewall"):
            rule = block.get("rule") or {}
            where = (f" {block['firewall']} drops it"
                     + (f" (policy #{rule.get('policy_id')} {rule.get('policy_name') or ''})".rstrip()
                        if rule and not block.get("implicit_deny") else " (implicit deny)"))
            src_scope = (row.get("src") or {}).get("scope") or ""
            dst_scope = (row.get("dst") or {}).get("scope") or ""
            if block.get("traced_src") and (block["traced_src"] not in src_scope
                                            or block.get("traced_dst", "") not in dst_scope):
                # MP-19: a network scope was traced through one of its addresses
                where += f" (traced {block['traced_src']} → {block.get('traced_dst')})"
        title = (f"Dead-end permit: {allowed_by(row)} allow {path_label(row)} "
                 f"({', '.join(row.get('service') or []) or 'any'}) but the destination is at "
                 f"{fmt_level(real)};{where or ' no policy carries it further'}"
                 + (" [attempts in capture]" if attempts else ""))
        text = (f"The policies {allowed_by(row)} permit traffic to {(row.get('dst') or {}).get('scope')} "
                f"as far as {fmt_level(reached)}, but that destination lives at {fmt_level(real)} "
                f"and no policy carries the traffic further."
                + (f" {where.strip()}." if where else
                   " Which firewall drops it is not known (the source is not one host, or the "
                   "onward path is not modelled); check the topology between the two levels.")
                + " "
                "The permit cannot deliver anything: it is a legacy leftover (the downstream rule "
                "was removed), a half-finished change, or an over-broad upstream rule. Remove it, "
                "complete the change, or narrow it (SR 7.7 least functionality, SR 5.2). "
                + (f"The capture shows {attempts} attempt(s) - someone depends on this path or is "
                   "probing it." if attempts else "No attempts in the capture.")
                + (f" Policy names mention {', '.join(markers)}." if markers else ""))
        ev = _evidence(row)
        ev.update({"dead_end": True, "reached_level": reached, "destination_level": real,
                   "blocked_at": block, "attempts_in_capture": attempts, "name_markers": markers,
                   "severity_reason": (f"Medium: {attempts} attempt(s) to use the permit were seen in the "
                                       "capture." if attempts else
                                       "Low: the permit delivers nothing and no attempts were seen "
                                       "(medium once attempts appear).")})
        chain = row.get("chain") or []
        f = ae._make_finding(
            db, "dead_end_permit", title[:512], text, ev,
            firewall_rule_id=(chain[0].get("rule_id") if chain else None),
            # MP-22: the finding belongs to the firewall that DROPS the traffic
            # when it is known, else to the last permitting one
            device_name=(block.get("firewall") or (chain[-1].get("firewall_name") if chain else None)),
            severity=severity,
            dedup_evidence={"rule_key": f"access_path_dead_end:{_group_key_text(row)}"})
        if f is not None:
            out.append(f)
    return out


# ------------------------------------------------------ DMZ bypass (H-14) --
def _remote_ports(row: dict) -> list[str]:
    """Remote-access protocols a row's services cover (any service = all)."""
    names = []
    for svc in row.get("service") or []:
        t = str(svc).lower()
        if t in ("any", "all", "ip", "*"):
            return sorted(set(_REMOTE_PORTS.values()))
        _p, _, rest = t.partition("/")
        for tok in (rest or t).split(","):
            lo, _, hi = tok.partition("-")
            if not lo.strip().isdigit():
                if lo.strip() == "any":
                    return sorted(set(_REMOTE_PORTS.values()))
                continue
            a, b = int(lo), int(hi or lo)
            names += [n for p, n in _REMOTE_PORTS.items() if a <= p <= b]
    return sorted(set(names))


def review_dmz_bypass(db: DBSession) -> list:
    """H-14: the site has an industrial DMZ, yet a permitted path joins the IT
    side / internet / remote users (L4-L5) and site operations (L3) without
    terminating on a DMZ host (row 2.2 "no flow bridges the DMZ end-to-end";
    SR 5.1 RE2, SR 5.2; 4.1 when it is remote access).  IT -> L3: medium,
    high for remote-access protocols, any service, a permit-any policy, a VPN
    source or traffic seen; L3 -> IT: low (one step up when seen).  One
    finding per policy chain."""
    from app.parsers import alert_engine as ae
    from app.parsers import vpn as _vpn
    from app.parsers.access_path_findings import allowed_by, path_label
    vctx = _vpn.VpnContext.build(db)
    out = []
    for direction in ("down", "up"):
        rows = [r for r in _candidates(db, ae, direction=direction, multi_only=False)
                if "dmz_bypass" in (r.get("flags") or []) and r.get("classification") not in _SUPPRESSING]
        for g in group_rows(rows):
            seen = _seen(g)
            remote = _remote_ports(g)
            vpn = vctx.is_vpn_row(g)
            any_svc = any(str(x).lower() in ("any", "all") for x in g.get("service") or [])
            if direction == "down":
                severity = "high" if (remote or any_svc or seen or vpn
                                      or "permit_any" in (g.get("flags") or [])) else "medium"
            else:
                severity = "medium" if seen else "low"
            src_level = (g.get("src") or {}).get("level")
            dst_level = (g.get("dst") or {}).get("level")
            who = "SSL-VPN users" if vpn else fmt_level(src_level)
            title = (f"DMZ bypass: {who} ↔ {fmt_level(dst_level)} without the DMZ: {path_label(g)} "
                     f"({', '.join(g.get('service') or []) or 'any'})" + (" [seen in capture]" if seen else ""))
            text = (f"The site has an industrial DMZ (L3.5), yet the policies {allowed_by(g)} let "
                    f"{who} open sessions directly {'to' if direction == 'down' else 'from'} site "
                    f"operations (L3) over {', '.join(g.get('service') or []) or 'any service'} - "
                    "no DMZ host terminates or brokers them (row 2.2: no flow bridges the DMZ "
                    "end to end; IEC 62443-3-3 SR 5.1 RE2, SR 5.2"
                    + ("; remote access must terminate in the DMZ - row 4.1, SR 1.13" if (remote or vpn) else "")
                    + "). "
                    + ("Matching traffic was seen in the capture. " if seen else "")
                    + "Broker the flow through a DMZ host (jump host, historian replica, proxy) "
                      "or record it as an exception in Access Review.")
            why_sev = [w for w, on in (("remote-access protocols", remote), ("any service", any_svc),
                                       ("permit-any", "permit_any" in (g.get("flags") or [])),
                                       ("SSL-VPN source", vpn), ("seen in the capture", seen)) if on]
            reason = (("High: " + ", ".join(why_sev) + "." if why_sev else
                       "Medium: specific services from the IT side, not seen in the capture.")
                      if direction == "down" else
                      ("Medium: initiated from site operations, seen in the capture." if seen else
                       "Low: initiated from site operations toward IT, not seen in the capture."))
            f = _emit(db, ae, CHECK_DMZ, g, title, text, severity, severity_reason=reason,
                      ev_extra={"remote_protocols": remote, "vpn_source": vpn,
                                "initiated_from": "IT side" if direction == "down" else "site operations"})
            if f is not None:
                out.append(f)
    return out


# ------------------------------------------- OT / L3 internet egress (H-13) --
def review_path_internet_egress(db: DBSession) -> list:
    """H-13: an OT zone - site operations (L3) included - is permitted to open
    sessions to the internet (row 3.7, SR 5.1 RE2): L0/L1 critical, L2 high,
    L3 medium; one step up when seen in the capture.  One finding per policy
    chain."""
    from app.parsers import alert_engine as ae
    from app.parsers.access_path_findings import allowed_by, path_label
    rows = [r for r in _candidates(db, ae, direction="up", multi_only=False)
            if "internet_egress" in (r.get("flags") or []) and r.get("classification") not in _SUPPRESSING]
    out = []
    for g in group_rows(rows):
        src_level = (g.get("src") or {}).get("level")
        base = "critical" if is_deep_ot(src_level) else "high" if is_ot(src_level) else "medium"
        seen = _seen(g)
        severity = _STEP_UP[base] if seen else base
        title = (f"Internet egress from {fmt_level(src_level)}: {path_label(g)} "
                 f"({', '.join(g.get('service') or []) or 'any'})" + (" [seen in capture]" if seen else ""))
        text = (f"The policies {allowed_by(g)} let {fmt_level(src_level)} hosts open sessions to the "
                f"internet ({(g.get('dst') or {}).get('scope') or 'any'}) over "
                f"{', '.join(g.get('service') or []) or 'any service'}. OT zones - site operations "
                "(L3) included - must not have direct internet access; external connectivity goes "
                "through an approved DMZ proxy / relay (row 3.7, IEC 62443-3-3 SR 5.1 RE2). "
                + ("Matching traffic was seen in the capture." if seen else "No matching traffic observed yet."))
        f = _emit(db, ae, CHECK_INET, g, title, text, severity,
                  severity_reason=(f"{severity.capitalize()}: {base} for {fmt_level(src_level)} (L0/L1 critical, "
                                   "L2 high, L3 medium)" + ("; one step up because the egress was seen in the "
                                                             "capture." if seen else ".")))
        if f is not None:
            out.append(f)
    return out
