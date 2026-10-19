"""
Access Review roll-up (owner request 2026-10-11): rows that differ only in
the destination host - or only in the source host - are one line.

A policy whose destination is an address group of N hosts expands to N rule
rows, so one logical conduit (VPN user -> jump host -> every controller over
SSH) is N near-identical access-path rows.  The enumeration keeps every row
(the per-host traffic overlay, tags and findings depend on them); this module
only says which rows belong together, so the Access Review screen and the
PDF can print one line per group.

Two keys per row, computed here once so the screen (JavaScript) and the
report (Python) roll up identically:

* ``group_dst`` - everything about the row except the destination's address
  (``dst.scope``): rows sharing it reach *different hosts* of the same zone
  from the same source over the same policies, service, pivot and flags;
* ``group_src`` - the same with the source's address left out.

``roll_up(rows)`` groups by ``group_dst`` first; rows left alone are then
tried by ``group_src``; the rest stay single.  Classification, report flag,
traffic and reviewer notes are NOT part of a key: a roll-up line summarises
them (the caller may restrict the input to one classification first).
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional


def _zone_text(side: Optional[dict]) -> str:
    """The side's zone as the screen prints it (SF-6 per-interface parts)."""
    if not isinstance(side, dict):
        return ""
    parts = side.get("zone_parts")
    if isinstance(parts, list) and parts:
        return " + ".join(f"{p.get('name')} ({p.get('level')})" for p in parts)
    return str(side.get("zone") or "")


def _side_fixed(side: Optional[dict]) -> list:
    side = side if isinstance(side, dict) else {}
    lvl = side.get("level")
    return [lvl if isinstance(lvl, (int, float)) else None, _zone_text(side), str(side.get("scope") or "")]


def _side_varying(side: Optional[dict]) -> list:
    return _side_fixed(side)[:2]


def _nat_sig(row: dict) -> list:
    out = []
    for e in row.get("nat") or []:
        if not isinstance(e, dict):
            continue
        out.append([e.get("type"), e.get("firewall"), e.get("policy_id"),
                    e.get("external"), e.get("mapped"), e.get("translated_to")])
    return out


def _chain_sig(row: dict) -> list:
    return [[h.get("firewall_name") or h.get("firewall_id"), h.get("vdom"), h.get("policy_id")]
            for h in (row.get("chain") or []) if isinstance(h, dict)]


def _pivots(row: dict) -> list:
    pv = row.get("pivots")
    if not pv and row.get("pivot"):
        pv = [row["pivot"]]
    return [str((p or {}).get("ip") or "") for p in (pv or [])]


def group_key(row: dict, vary: str) -> str:
    """A short stable key; ``vary`` is ``"dst"`` or ``"src"`` - that side's
    address is left out so rows differing only there share the key."""
    if row.get("client"):            # an unexplained flow never rolls up
        return ""
    fixed, varying = ("src", "dst") if vary == "dst" else ("dst", "src")
    sig = [
        vary,
        row.get("direction"),
        fixed, _side_fixed(row.get(fixed)),
        varying, _side_varying(row.get(varying)),
        sorted(str(s) for s in (row.get("service") or [])),
        sorted(str(p) for p in (row.get("protocol") or [])),
        _chain_sig(row),
        _pivots(row),
        (row.get("hop") or {}).get("id") if isinstance(row.get("hop"), dict) else None,
        sorted(str(f) for f in (row.get("flags") or [])),
        row.get("reach") or "reaches",
        _nat_sig(row),
    ]
    raw = json.dumps(sig, sort_keys=True, default=str)
    return f"{vary}:" + hashlib.sha1(raw.encode()).hexdigest()[:16]


def annotate(rows: list) -> None:
    """Add ``group_dst`` / ``group_src`` to every path row in place."""
    for row in rows:
        if not isinstance(row, dict) or row.get("client"):
            continue
        row["group_dst"] = group_key(row, "dst")
        row["group_src"] = group_key(row, "src")


def roll_up(rows: list, min_size: int = 2) -> list[dict]:
    """Group a row list into ``[{"vary": "dst" | "src" | None, "rows": [...],
    "key": str, "scopes": [distinct addresses of the varying side]}]``, in
    first-appearance order.  Rows without keys (unexplained flows, rows from
    before this version) stay single."""
    def _key(row, vary):
        k = row.get("group_dst" if vary == "dst" else "group_src")
        if not k:
            k = group_key(row, vary) if isinstance(row, dict) and not row.get("client") else ""
        return k

    def _pass(items, vary):
        buckets: dict = {}
        order = []
        for r in items:
            k = _key(r, vary)
            if not k:
                k = f"single:{id(r)}"
            if k not in buckets:
                buckets[k] = []
                order.append(k)
            buckets[k].append(r)
        return [(k, buckets[k]) for k in order]

    out: list[dict] = []
    singles: list = []
    for k, members in _pass(rows, "dst"):
        if len(members) >= min_size and not k.startswith("single:"):
            out.append(_group(k, "dst", members))
        else:
            singles.extend(members)
    for k, members in _pass(singles, "src"):
        if len(members) >= min_size and not k.startswith("single:"):
            out.append(_group(k, "src", members))
        else:
            for r in members:
                out.append({"vary": None, "key": "", "rows": [r], "scopes": []})
    # keep first-appearance order of each group's first row
    pos = {id(r): i for i, r in enumerate(rows)}
    out.sort(key=lambda g: pos.get(id(g["rows"][0]), 0))
    return out


def _group(key: str, vary: str, members: list) -> dict:
    seen = []
    for r in members:
        s = str(((r.get(vary) or {}) if isinstance(r.get(vary), dict) else {}).get("scope") or "")
        if s and s not in seen:
            seen.append(s)
    return {"vary": vary, "key": key, "rows": members, "scopes": seen}
