"""
Topology Manager — multi-firewall link detection and confirmation.

After two or more FortiGate configs have been ingested, the system enters
multi-firewall mode (``is_multi_fw=True`` on all Firewall rows).  This
module provides the logic to:

  1. Detect subnet overlaps between FirewallInterface rows across different
     firewalls and propose upstream/downstream links with a confidence score.
  2. Let an operator confirm (or dismiss) a proposed link, which writes the
     ``connects_to_interface_id`` FK on both interfaces.
  3. Return the current topology state for API responses and the UI topology
     builder.

Confidence labels mirror the PCAP suggestion scale:
  "high"   — network CIDRs are identical (same subnet, definitely connected)
  "medium" — one is a subnet of the other (likely a transit link)
  "low"    — interfaces share the same /16 supernet (possible, but uncertain)
  "none"   — no overlapping subnets detected at all (manual entry required)

The topology builder in the UI uses these proposals to present the operator
with a graph where they drag-and-drop links or click "Confirm"; this module
only stores the confirmed state — it doesn't drive the UI directly.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from sqlalchemy.orm import Session as DBSession, joinedload

from app.models import Firewall, FirewallInterface, FirewallZone, Host
from app.parsers import fortios_zones as _fz
from app.parsers.site_scope import (
    CrossSiteError, current_site, scope_module,
)


def _iface_site(db: DBSession, iface: Optional[FirewallInterface]) -> Optional[int]:
    if iface is None:
        return None
    fw = iface.__dict__.get("firewall") or db.get(Firewall, iface.firewall_id)
    return getattr(fw, "site_id", None)


def _fw_in_scope(db: DBSession, fw: Optional[Firewall]) -> Optional[Firewall]:
    """``fw`` unless a site scope is bound and fw belongs to another site
    (db.get may return identity-map objects the scope filter never saw)."""
    sid = current_site(db)
    if fw is None or sid is None or fw.site_id == sid:
        return fw
    return None


def _iface_in_scope(db: DBSession, iface: Optional[FirewallInterface]):
    sid = current_site(db)
    if iface is None or sid is None or _iface_site(db, iface) == sid:
        return iface
    return None

log = logging.getLogger(__name__)


# ------------------------------------------------------- Purdue levels --
#
# The level vocabulary lives in app/purdue.py (F-08: one source of truth,
# including L3.5 = industrial DMZ).  These names are kept as thin wrappers
# so existing imports (routes, tests) keep working.
from app import purdue as _purdue  # noqa: E402
from app.purdue import (  # noqa: E402,F401  (re-exported)
    PURDUE_LEVEL_MAX,
    PURDUE_LEVEL_MIN,
    PURDUE_LEVEL_RANGE_TEXT,
    VALID_LEVELS,
    level_distance,
    next_level,
    normalize_level,
    prev_level,
)


def valid_purdue_level(level) -> bool:
    """True when ``level`` is a valid Purdue level number (0, 1, 2, 3, 3.5,
    4, 5); bools and strings are rejected - see app.purdue.is_valid_level."""
    return _purdue.is_valid_level(level)


def purdue_level_error(field: str, value) -> str:
    """Uniform validation message for an invalid level."""
    return _purdue.purdue_level_error(field, value)


# ---------------------------------------------------------------- helpers --

def _parse_network(cidr: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Return an IPv4Network for ``cidr``, or None if blank / unparsable / IPv6.

    IPv6 CIDRs are silently skipped: subnet_of() raises TypeError when called
    across IP versions, so we only compare IPv4 networks here.
    """
    if not cidr:
        return None
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            return None  # skip IPv6 — cross-version comparison raises TypeError
        return net
    except ValueError:
        return None


def _overlap_confidence(
    net_a: ipaddress.IPv4Network,
    net_b: ipaddress.IPv4Network,
) -> str:
    """
    Return a confidence label for how likely two networks represent a
    physical link between two firewall interfaces.

      "high"   — exact same network (e.g. both 10.10.10.0/24)
      "medium" — one is a subnet of the other (transit / point-to-point)

    D-07: a shared /16 is no evidence of a link - every transit net of a
    site tends to live in one block (172.16.x.0/30 ...), which produced 60
    "low" proposals on a 12-firewall tabletop.  Only real overlap counts.
    """
    if net_a == net_b:
        return "high"
    try:
        if net_a.subnet_of(net_b) or net_b.subnet_of(net_a):
            return "medium"
    except TypeError:
        # Raised when networks are different IP versions; treat as no overlap
        return "none"
    return "none"


# -------------------------------------------------------- public interface --

def _routing_switch_ids(db: DBSession) -> set:
    from app.parsers.l3_switch import switch_firewall_ids
    return switch_firewall_ids(db)


def detect_subnet_overlaps(db: DBSession) -> list[dict]:
    """
    Compare ``network_cidr`` across every ``FirewallInterface`` that belongs
    to a different ``Firewall``, and return proposed links.

    Only interfaces that:
      - have a non-null ``network_cidr``
      - are not HA interfaces (``is_ha=False``)
      - are not management-only interfaces (``is_mgmt_only=False``)
      - are not already linked (``connects_to_interface_id`` is None)

    are considered.

    Returns a list of proposal dicts::

        {
            "fw_a_id":    int,
            "fw_a_name":  str,
            "iface_a_id": int,
            "iface_a_name": str,
            "iface_a_cidr": str,
            "fw_b_id":    int,
            "fw_b_name":  str,
            "iface_b_id": int,
            "iface_b_name": str,
            "iface_b_cidr": str,
            "confidence": "high" | "medium" | "low",
        }

    Pairs with confidence "none" are excluded from the result.
    The list is de-duplicated so (A→B) and (B→A) appear only once.
    """
    candidates = (
        db.query(FirewallInterface)
        .filter(
            FirewallInterface.network_cidr.isnot(None),
            FirewallInterface.is_ha.is_(False),
            FirewallInterface.is_mgmt_only.is_(False),
            FirewallInterface.connects_to_interface_id.is_(None),
            FirewallInterface.segment.is_(None),
        )
        .all()
    )
    # HA members carry the primary's interfaces (same subnets): never propose
    # links for them - the cluster is one firewall.
    from app.parsers.firewall_groups import ha_secondary_ids
    # LS-01: a routing switch shares every VLAN with the firewall beside it;
    # those are not serial firewall links - never propose them.
    _sec = ha_secondary_ids(db) | _routing_switch_ids(db)
    candidates = [i for i in candidates if i.firewall_id not in _sec]
    # D-07: interfaces of >= 3 firewalls on one network are a SHARED segment
    # proposal (detect_shared_segments), not a tangle of pairwise links.
    shared_ifaces = {i.id for seg in detect_shared_segments(db, candidates)
                     for i in seg["_ifaces"]}
    candidates = [i for i in candidates if i.id not in shared_ifaces]

    # Index by firewall_id for cross-firewall comparison
    by_fw: dict[int, list[FirewallInterface]] = {}
    for iface in candidates:
        by_fw.setdefault(iface.firewall_id, []).append(iface)

    fw_ids = list(by_fw.keys())
    proposals: list[dict] = []
    seen: set[frozenset] = set()  # de-duplicate (a,b) vs (b,a)

    fw_rows = db.query(Firewall).filter(Firewall.id.in_(fw_ids)).all()
    fw_names: dict[int, str] = {fw.id: fw.name for fw in fw_rows}
    # Multi-site: links never cross sites, so never propose one.
    fw_site: dict[int, Optional[int]] = {fw.id: fw.site_id for fw in fw_rows}

    for i, fw_a_id in enumerate(fw_ids):
        for fw_b_id in fw_ids[i + 1:]:
            if fw_site.get(fw_a_id) != fw_site.get(fw_b_id):
                continue
            for iface_a in by_fw[fw_a_id]:
                net_a = _parse_network(iface_a.network_cidr)
                if net_a is None:
                    continue
                for iface_b in by_fw[fw_b_id]:
                    net_b = _parse_network(iface_b.network_cidr)
                    if net_b is None:
                        continue
                    confidence = _overlap_confidence(net_a, net_b)
                    if confidence == "none":
                        continue
                    pair_key = frozenset({iface_a.id, iface_b.id})
                    if pair_key in seen:
                        continue
                    seen.add(pair_key)
                    proposals.append({
                        "fw_a_id":      fw_a_id,
                        "fw_a_name":    fw_names.get(fw_a_id, str(fw_a_id)),
                        "iface_a_id":   iface_a.id,
                        "iface_a_name": iface_a.name,
                        "iface_a_cidr": iface_a.network_cidr,
                        "fw_b_id":      fw_b_id,
                        "fw_b_name":    fw_names.get(fw_b_id, str(fw_b_id)),
                        "iface_b_id":   iface_b.id,
                        "iface_b_name": iface_b.name,
                        "iface_b_cidr": iface_b.network_cidr,
                        "confidence":   confidence,
                        # MP-18: a shared network says the two boxes are
                        # connected, not how they are arranged
                        **_arrangement_hint(iface_a, iface_b),
                    })

    # Sort: high confidence first
    _conf_rank = {"high": 0, "medium": 1, "low": 2}
    proposals.sort(key=lambda p: _conf_rank.get(p["confidence"], 9))
    log.info("detect_subnet_overlaps: %d proposals generated", len(proposals))
    return proposals


def _arrangement_hint(iface_a, iface_b) -> dict:
    """MP-18: what a shared network between two firewalls' interfaces says
    about their arrangement.  Two interfaces labelled at the SAME level (or
    both "outside" / both "inside") are two uplinks on one segment - parallel
    boxes (cell firewalls behind one core), never a series pair; different
    levels / sides are consistent with one box behind the other."""
    la, lb = iface_a.purdue_level, iface_b.purdue_level
    sa, sb = iface_a.side, iface_b.side
    if la is not None and lb is not None:
        if la == lb:
            return {"arrangement": "parallel",
                    "arrangement_note": f"both interfaces are labelled L{la:g}: a shared segment "
                                        "between parallel firewalls (not a series pair)"}
        return {"arrangement": "series",
                "arrangement_note": f"L{la:g} on one side, L{lb:g} on the other: consistent with "
                                    "one firewall behind the other (series)"}
    if sa in ("inside", "outside") and sb in ("inside", "outside"):
        if sa == sb:
            return {"arrangement": "parallel",
                    "arrangement_note": f"both interfaces are '{sa}' legs: a shared segment between "
                                        "parallel firewalls (not a series pair)"}
        return {"arrangement": "series",
                "arrangement_note": "an inside leg meets an outside leg: consistent with one firewall "
                                    "behind the other (series)"}
    return {"arrangement": "unknown",
            "arrangement_note": "label both interfaces (level or side) to tell a series pair from "
                                "parallel firewalls on a shared segment"}


def detect_shared_segments(db: DBSession, candidates=None) -> list[dict]:
    """D-07: networks on which interfaces of THREE or more firewalls of one
    site sit (identical network_cidr) - a shared segment such as the DMZ
    switch, which the one-peer link model cannot record.  Returns proposals::

        {"network": "10.40.1.0/24", "confidence": "high", "site_id": ...,
         "members": [{"fw_id", "fw_name", "iface_id", "iface_name", "ip_cidr"}]}

    Interfaces already in a segment or linked are not candidates."""
    if candidates is None:
        candidates = (
            db.query(FirewallInterface)
            .filter(FirewallInterface.network_cidr.isnot(None),
                    FirewallInterface.is_ha.is_(False),
                    FirewallInterface.is_mgmt_only.is_(False),
                    FirewallInterface.connects_to_interface_id.is_(None),
                    FirewallInterface.segment.is_(None))
            .all())
        from app.parsers.firewall_groups import ha_secondary_ids
        _sec = ha_secondary_ids(db) | _routing_switch_ids(db)
        candidates = [i for i in candidates if i.firewall_id not in _sec]
    fw_rows = {fw.id: fw for fw in db.query(Firewall).filter(
        Firewall.id.in_({i.firewall_id for i in candidates} or {-1})).all()}
    groups: dict[tuple, list[FirewallInterface]] = {}
    for i in candidates:
        net = _parse_network(i.network_cidr)
        fw = fw_rows.get(i.firewall_id)
        if net is None or fw is None:
            continue
        groups.setdefault((fw.site_id, str(net)), []).append(i)
    out = []
    for (site_id, net), ifaces in sorted(groups.items(), key=lambda kv: kv[0][1]):
        if len({i.firewall_id for i in ifaces}) < 3:
            continue
        ifaces.sort(key=lambda i: (fw_rows[i.firewall_id].name or "", i.name or ""))
        out.append({
            "network": net, "confidence": "high", "site_id": site_id,
            "members": [{"fw_id": i.firewall_id, "fw_name": fw_rows[i.firewall_id].name,
                         "iface_id": i.id, "iface_name": i.name, "ip_cidr": i.ip_cidr}
                        for i in ifaces],
            "_ifaces": ifaces,
        })
    return out


def confirm_segment(db: DBSession, iface_ids: list[int], name: Optional[str] = None,
                    site_id: int | None = None) -> dict:
    """D-07: record that ``iface_ids`` (interfaces of >= 2 different
    firewalls of one site) share one segment.  ``name`` defaults to
    ``seg-<network>``; members already in another segment move.  Point-to-point
    links between members are cleared (the segment supersedes them).
    Returns {"segment", "members": [...]}.  Caller commits."""
    ids = list(dict.fromkeys(int(i) for i in iface_ids or ()))
    if len(ids) < 2:
        raise ValueError("a segment needs at least two interfaces")
    ifaces = [_iface_in_scope(db, db.get(FirewallInterface, i)) for i in ids]
    missing = [i for i, x in zip(ids, ifaces) if x is None]
    if missing:
        raise ValueError(f"FirewallInterface id={missing[0]} not found")
    if len({i.firewall_id for i in ifaces}) < 2:
        raise ValueError("a segment must span at least two firewalls")
    sites = {_iface_site(db, i) for i in ifaces}
    if len(sites) > 1:
        raise CrossSiteError("interfaces belong to firewalls of different sites; "
                             "sites are isolated and cannot share a segment")
    if site_id is not None and sites and sites != {site_id}:
        raise CrossSiteError(f"interfaces belong to site {sites.pop()}, not site {site_id}")
    label = (name or "").strip()
    if not label:
        nets = {str(_parse_network(i.network_cidr)) for i in ifaces if _parse_network(i.network_cidr)}
        label = "seg-" + (sorted(nets)[0] if len(nets) == 1 else f"{ids[0]}")
    if len(label) > 64:
        raise ValueError("segment name: at most 64 characters")
    for i in ifaces:
        if i.connects_to_interface_id is not None:
            peer = db.get(FirewallInterface, i.connects_to_interface_id)
            if peer is not None and peer.connects_to_interface_id == i.id:
                peer.connects_to_interface_id = None
            i.connects_to_interface_id = None
        i.segment = label
    db.flush()
    log.info("Confirmed shared segment %r: %d interface(s) on %d firewall(s)",
             label, len(ifaces), len({i.firewall_id for i in ifaces}))
    return {"segment": label,
            "members": [{"fw_id": i.firewall_id, "iface_id": i.id, "iface_name": i.name}
                        for i in ifaces]}


def propose_topology(db: DBSession) -> list[dict]:
    """
    Alias for ``detect_subnet_overlaps`` — returns unconfirmed link proposals.
    Named separately so callers can distinguish "just detect" from
    "propose for UI presentation".
    """
    return detect_subnet_overlaps(db)


def confirm_link(
    db: DBSession,
    iface_a_id: int,
    iface_b_id: int,
) -> tuple[FirewallInterface, FirewallInterface]:
    """
    Record a confirmed physical link between two firewall interfaces by
    writing ``connects_to_interface_id`` on both rows.

    Raises ``ValueError`` if either interface id is not found, or if
    both interfaces belong to the same firewall (a link must cross FWs).

    The caller is responsible for ``db.commit()``.
    """
    if iface_a_id == iface_b_id:
        raise ValueError(
            f"Cannot link FirewallInterface id={iface_a_id} to itself (self-loop)"
        )

    iface_a = _iface_in_scope(db, db.get(FirewallInterface, iface_a_id))
    iface_b = _iface_in_scope(db, db.get(FirewallInterface, iface_b_id))

    if iface_a is None:
        raise ValueError(f"FirewallInterface id={iface_a_id} not found")
    if iface_b is None:
        raise ValueError(f"FirewallInterface id={iface_b_id} not found")
    if iface_a.firewall_id == iface_b.firewall_id:
        raise ValueError(
            f"Both interfaces belong to the same firewall "
            f"(firewall_id={iface_a.firewall_id}). "
            "A topology link must connect interfaces on different firewalls."
        )
    if _iface_site(db, iface_a) != _iface_site(db, iface_b):
        raise CrossSiteError(
            f"Interfaces id={iface_a_id} and id={iface_b_id} belong to firewalls of "
            f"different sites (site {_iface_site(db, iface_a)} vs "
            f"{_iface_site(db, iface_b)}); sites are isolated and cannot be linked"
        )

    # If either interface is already linked to a DIFFERENT peer, null out that
    # old peer's back-pointer first to prevent a dangling reference.
    if iface_a.connects_to_interface_id not in (None, iface_b_id):
        old_peer_a = db.get(FirewallInterface, iface_a.connects_to_interface_id)
        if old_peer_a is not None and old_peer_a.connects_to_interface_id == iface_a_id:
            old_peer_a.connects_to_interface_id = None
    if iface_b.connects_to_interface_id not in (None, iface_a_id):
        old_peer_b = db.get(FirewallInterface, iface_b.connects_to_interface_id)
        if old_peer_b is not None and old_peer_b.connects_to_interface_id == iface_b_id:
            old_peer_b.connects_to_interface_id = None

    iface_a.connects_to_interface_id = iface_b_id
    iface_b.connects_to_interface_id = iface_a_id
    log.info(
        "Confirmed link: FW%d/%s (id=%d) ↔ FW%d/%s (id=%d)",
        iface_a.firewall_id, iface_a.name, iface_a_id,
        iface_b.firewall_id, iface_b.name, iface_b_id,
    )
    return iface_a, iface_b


def upstream_chain(db: DBSession, firewall_id: int, max_len: int = 1000) -> tuple[list[int], bool]:
    """
    Walk ``upstream_firewall_id`` from ``firewall_id``.

    Returns ``(chain, cyclic)`` where ``chain`` is the list of firewall ids
    visited in order (starting with ``firewall_id``) and ``cyclic`` is True
    if the walk returned to an already-visited firewall (T3-40).  Always
    terminates (visited set + hard length cap), even on corrupt data.
    """
    chain: list[int] = []
    seen: set[int] = set()
    cur: Optional[int] = firewall_id
    site = None
    while cur is not None and len(chain) < max_len:
        if cur in seen:
            chain.append(cur)
            return chain, True
        fw = _fw_in_scope(db, db.get(Firewall, cur))
        if fw is not None and site is not None and fw.site_id != site:
            break  # multi-site: an upstream chain never crosses sites
        if fw is not None:
            site = fw.site_id
        seen.add(cur)
        chain.append(cur)
        cur = fw.upstream_firewall_id if fw is not None else None
    return chain, False


def _chain_label(db: DBSession, ids: list[int]) -> str:
    names = []
    for i in ids:
        fw = db.get(Firewall, i)
        names.append(f"{fw.name if fw and fw.name else 'FW'}#{i}")
    return " → ".join(names)


def set_upstream_firewall(
    db: DBSession,
    firewall_id: int,
    upstream_firewall_id: Optional[int],
    purdue_level_ingress: Optional[float] = None,
    purdue_level_egress: Optional[float] = None,
    topology_confirmed: Optional[bool] = None,
) -> Firewall:
    """
    Set the upstream_firewall_id (and optionally the Purdue level bridge
    descriptors) on a Firewall row.

    ``upstream_firewall_id=None`` means this firewall is the outermost /
    perimeter device with no known upstream peer.

    Raises ``ValueError`` if ``firewall_id`` is not found, if
    ``upstream_firewall_id`` points to the same firewall (self-reference), or
    if the new link would close a cycle anywhere in the upstream chain
    (A→B→A, A→B→C→A; T3-40) - the message names the chain.

    The caller is responsible for ``db.commit()``.
    """
    fw = _fw_in_scope(db, db.get(Firewall, firewall_id))
    if fw is None:
        raise ValueError(f"Firewall id={firewall_id} not found")
    if upstream_firewall_id is not None:
        if upstream_firewall_id == firewall_id:
            raise ValueError("upstream_firewall_id must reference a different firewall")
        peer = _fw_in_scope(db, db.get(Firewall, upstream_firewall_id))
        if peer is None:
            raise ValueError(f"Upstream firewall id={upstream_firewall_id} not found")
        if peer.site_id != fw.site_id:
            raise CrossSiteError(
                f"Upstream firewall id={upstream_firewall_id} belongs to site "
                f"{peer.site_id} but firewall id={firewall_id} belongs to site "
                f"{fw.site_id}; upstream chains never cross sites")
        # T3-40: walking up from the proposed upstream must never reach us.
        chain, cyclic = upstream_chain(db, upstream_firewall_id)
        if firewall_id in chain:
            loop = [firewall_id] + chain[: chain.index(firewall_id) + 1]
            raise ValueError(
                "upstream_firewall_id would create a cycle in the upstream chain: "
                + _chain_label(db, loop)
            )
        if cyclic:
            raise ValueError(
                "upstream firewall's own upstream chain already contains a cycle: "
                + _chain_label(db, chain)
            )
    if purdue_level_ingress is not None and not valid_purdue_level(purdue_level_ingress):
        raise ValueError(purdue_level_error("purdue_level_ingress", purdue_level_ingress))
    if purdue_level_egress is not None and not valid_purdue_level(purdue_level_egress):
        raise ValueError(purdue_level_error("purdue_level_egress", purdue_level_egress))

    fw.upstream_firewall_id = upstream_firewall_id
    if purdue_level_ingress is not None:
        fw.purdue_level_ingress = normalize_level(purdue_level_ingress)
    if purdue_level_egress is not None:
        fw.purdue_level_egress = normalize_level(purdue_level_egress)
    if topology_confirmed is not None:
        fw.topology_confirmed = topology_confirmed

    log.info(
        "set_upstream_firewall: FW%d upstream=%s ingress=%s egress=%s confirmed=%s",
        firewall_id, upstream_firewall_id,
        purdue_level_ingress, purdue_level_egress, topology_confirmed,
    )
    return fw


_INTERFACE_LABEL_FIELDS = ("side", "zone_label", "purdue_level")
INTERFACE_SIDES = ("inside", "outside")


def set_interface_labels(
    db: DBSession,
    interface_id: int,
    side: Optional[str] = None,
    zone_label: Optional[str] = None,
    purdue_level: Optional[float] = None,
    clear: Optional[list] = None,
) -> FirewallInterface:
    """
    Set operator-assigned labels on a FirewallInterface (N-11).

    ``None`` means "leave unchanged" for side / zone_label / purdue_level.
    To CLEAR a value (set it back to NULL) name the field in ``clear``,
    e.g. ``clear=["side", "purdue_level"]``.  Naming a field in ``clear``
    while also passing a value for it is rejected as ambiguous.

    Clearing ``purdue_level`` also drops a stale suggestion so the
    suggestion engine can recompute it on its next run.

    Raises ``LookupError`` if the interface does not exist and
    ``ValueError`` for invalid input.  The caller commits.
    """
    iface = _iface_in_scope(db, db.get(FirewallInterface, interface_id))
    if iface is None:
        raise LookupError(f"Interface id={interface_id} not found")
    if (iface.iface_type or "") in ("vdom-link", "npu-vlink", "vdom_link") and (
            side is not None or purdue_level is not None):
        # VD-03: internal to the firewall; its levels are the peer VDOM's
        raise ValueError(f"'{iface.name}' is an inter-VDOM link: it has no side or level of its own "
                         "(label the VDOMs' interfaces)")
    clear_set = set()
    for f in clear or []:
        f = str(f).strip()
        if f not in _INTERFACE_LABEL_FIELDS:
            raise ValueError(
                f"clear may only name {', '.join(_INTERFACE_LABEL_FIELDS)}; got {f!r}")
        clear_set.add(f)
    for f, val in (("side", side), ("zone_label", zone_label), ("purdue_level", purdue_level)):
        if f in clear_set and val is not None:
            raise ValueError(f"{f} is both set and listed in clear")
    if side is not None and side not in INTERFACE_SIDES:
        raise ValueError("side must be 'inside' or 'outside'")
    if purdue_level is not None and not valid_purdue_level(purdue_level):
        raise ValueError(purdue_level_error("purdue_level", purdue_level))

    if side is not None:
        iface.side = side
    if zone_label is not None:
        iface.zone_label = zone_label
    if purdue_level is not None:
        iface.purdue_level = normalize_level(purdue_level)
        iface.suggested_purdue_level = None
        iface.purdue_suggestion_source = None
    for f in clear_set:
        setattr(iface, f, None)
    # LS-01: a routing switch's SVIs follow the firewall interface labels
    try:
        from app.parsers.l3_switch import refresh_levels
        db.flush()
        refresh_levels(db)
    except Exception:                                   # noqa: BLE001
        log.warning("L3 switch SVI level refresh failed", exc_info=True)
    # SF-8a: unclassified hosts behind the interface take its level
    try:
        from app.parsers import subnet_zones
        subnet_zones.apply(db)          # site: the module's scope binding (scope_module)
    except Exception:                                   # noqa: BLE001
        log.warning("interface label propagation to hosts failed", exc_info=True)
    return iface


# ─────────────────────────────────── Purdue level suggestion engine ──────────

# RFC 1918 private ranges — interfaces whose CIDRs fall inside these are
# likely inside-facing (Levels 0–3).
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private(cidr: Optional[str]) -> bool:
    """Return True if ``cidr`` falls entirely within RFC 1918 space."""
    net = _parse_network(cidr)
    if net is None:
        return False
    # _RFC1918 contains IPv4Network objects; subnet_of() raises
    # TypeError when net is IPv6.  Guard defensively here even though
    # _parse_network() already returns None for IPv6 inputs.
    if net.version != 4:
        return False
    return any(net.subnet_of(private) for private in _RFC1918)  # type: ignore[arg-type]


# FortiOS interface roles that strongly imply a side
_FG_ROLE_SIDE: dict[str, str] = {
    "wan":   "outside",
    "lan":   "inside",
    "dmz":   "inside",
    "ha":    "ha",
    "mgmt":  "mgmt",
}


def _iface_network(iface: FirewallInterface):
    for cidr in (iface.network_cidr, iface.ip_cidr):
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or net.num_addresses <= 1:
            continue
        return net
    return None


def _majority_level(levels: list):
    """The level held by a strict majority of ``levels`` (else None)."""
    if not levels:
        return None
    counts: dict[int, int] = {}
    for lv in levels:
        counts[lv] = counts.get(lv, 0) + 1
    lv, n = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
    return lv if n * 2 > len(levels) else None


def run_purdue_suggestions(db: DBSession) -> dict:
    """
    Recompute ``suggested_purdue_level`` + ``purdue_suggestion_source`` on
    ``FirewallInterface`` rows where the operator has not set a manual
    ``purdue_level`` (F-16).

    Every run starts from a clean slate: all existing suggestions are
    cleared first and then recomputed, so a suggestion whose evidence has
    gone away (link removed, chain levels changed, hosts reclassified) does
    not linger.  The operator-set ``purdue_level`` is never read-modified.

    A suggestion is only made on real evidence; sources in priority order
    (a higher-priority source wins for the same interface):

    ``peer_link``
        Confirmed link to an interface with an operator-set level: the same
        level as the peer (one wire, one segment - MP-13: a downstream
        firewall's uplink on the L3 segment is L3, so its own L3/L2 boundary
        survives).  Only between members of a declared paired (series) group
        does the paired convention apply: the outside side is one level
        higher, the inside side one level lower, unknown side = same level
        (whole levels step by one - L3.5 is never invented; a DMZ peer gives
        L4 outside / L3 inside).
    ``fw_chain``
        The owning firewall's ``purdue_level_ingress`` / ``_egress`` for the
        outside / inside interface.
    ``connected_hosts``
        A strict majority of the classified hosts (``Host.purdue_level``)
        inside the interface subnet share one level.
    ``name_keyword``
        The interface alias, zone_label or name contains a confident Purdue
        keyword (device_classification.VLAN_NAME_KEYWORDS, e.g. "scada",
        "corp", "plc"; "dmz" -> 3.5, the industrial DMZ).
    ``zone_name``
        The FortiOS zone (FirewallZone.zone_name) the interface belongs to
        contains such a keyword.
    ``role_heuristic``
        FortiOS ``role``: wan -> 4, dmz -> 3.5 (industrial DMZ, F-08), lan -> 3.

    RFC 1918 / public addressing alone is NOT evidence (every OT subnet is
    private) - such interfaces stay unsuggested.

    Returns ``{"interfaces_updated": int, "suggestions_cleared": int,
    "by_source": {...}}``.  The caller is responsible for ``db.commit()``.
    """
    from app.parsers.device_classification import classify_vlan_name

    all_ifaces: list[FirewallInterface] = db.query(FirewallInterface).all()
    iface_by_id: dict[int, FirewallInterface] = {i.id: i for i in all_ifaces}
    fw_by_id: dict[int, Firewall] = {fw.id: fw for fw in db.query(Firewall).all()}

    # Refresh: drop every previous suggestion, then recompute below.
    previous = {i.id: (i.suggested_purdue_level, i.purdue_suggestion_source) for i in all_ifaces}
    # LS-01: a routing switch's SVIs carry their level in purdue_level with
    # source "svi_auto" (derived from the firewall labels); that marker is
    # not a suggestion and must survive, or the level freezes.
    from app.parsers.l3_switch import AUTO_SOURCE as _SVI_AUTO
    from app.parsers.forti_config_parser import VPN_TUNNEL_AUTO_SOURCE as _VPN_AUTO
    from app.parsers.edge_links import EDGE_SOURCE as _EDGE_AUTO
    _AUTO = (_SVI_AUTO, _VPN_AUTO, "zone_declared", _EDGE_AUTO)   # automatic LEVELS, not suggestions (LS-01, VD-05, RS G3, RS edge)
    for iface in all_ifaces:
        if iface.purdue_suggestion_source in _AUTO:
            continue
        iface.suggested_purdue_level = None
        iface.purdue_suggestion_source = None

    # VD-03: inter-VDOM links are internal - never suggested a level either
    already_suggested: set[int] = {i.id for i in all_ifaces if i.purdue_suggestion_source in _AUTO
                                   or (i.iface_type or "") in ("vdom-link", "npu-vlink", "vdom_link")}
    by_source: dict[str, int] = {
        "peer_link": 0, "fw_chain": 0, "connected_hosts": 0,
        "name_keyword": 0, "zone_name": 0, "role_heuristic": 0,
    }

    def _write_suggestion(iface: FirewallInterface, level, source: str) -> None:
        if level is None or not valid_purdue_level(level):
            return
        if iface.purdue_level is not None:
            return   # operator explicitly set — never touch
        if iface.id in already_suggested:
            return   # already handled by a higher-priority source
        iface.suggested_purdue_level = level
        iface.purdue_suggestion_source = source
        already_suggested.add(iface.id)
        by_source[source] = by_source.get(source, 0) + 1
        log.debug("Purdue suggestion: iface %d (%s) → level %s via %s",
                  iface.id, iface.name, level, source)

    def _peer_level(level, side: Optional[str]):
        # Whole levels step by +-1 as before (L3 outside -> L4): a link
        # between two firewalls is not evidence of a DMZ, so the engine never
        # *invents* L3.5 - it is suggested only on DMZ evidence (fw_chain,
        # connected hosts, "dmz" keyword / zone, FortiOS dmz role).  From a
        # DMZ leg the neighbours are L4 (outside) and L3 (inside).
        if not valid_purdue_level(level):
            return None
        if _purdue.is_dmz(level):
            return next_level(level) if side == "outside" else \
                prev_level(level) if side == "inside" else level
        if side == "outside":
            return min(level + 1, PURDUE_LEVEL_MAX)
        if side == "inside":
            return max(level - 1, PURDUE_LEVEL_MIN)
        return level

    # ── source 1: peer_link ───────────────────────────────────────────────
    # MP-13: a confirmed link is one wire, so both ends carry the SAME level
    # - the peer's own level - unless the two firewalls are a declared
    # paired (series) group, whose convention labels the transit as the far
    # side on each member (outer: inner level, inner: outer level, +-1).
    for iface in all_ifaces:
        if iface.connects_to_interface_id is None:
            continue
        peer = iface_by_id.get(iface.connects_to_interface_id)
        if peer is None:
            continue
        fa, fb = fw_by_id.get(iface.firewall_id), fw_by_id.get(peer.firewall_id)
        series = (fa is not None and fb is not None and fa.paired_group_id is not None
                  and fa.paired_group_id == fb.paired_group_id)
        if peer.purdue_level is not None:
            _write_suggestion(iface, _peer_level(peer.purdue_level, iface.side) if series
                              else peer.purdue_level, "peer_link")
        if iface.purdue_level is not None:
            _write_suggestion(peer, _peer_level(iface.purdue_level, peer.side) if series
                              else iface.purdue_level, "peer_link")

    # ── source 2: fw_chain ────────────────────────────────────────────────
    for iface in all_ifaces:
        fw = fw_by_id.get(iface.firewall_id)
        if fw is None:
            continue
        if fw.purdue_level_ingress is not None and iface.side == "outside":
            _write_suggestion(iface, fw.purdue_level_ingress, "fw_chain")
        elif fw.purdue_level_egress is not None and iface.side == "inside":
            _write_suggestion(iface, fw.purdue_level_egress, "fw_chain")

    pending = [i for i in all_ifaces if i.purdue_level is None and i.id not in already_suggested]

    # ── source 3: connected_hosts ─────────────────────────────────────────
    nets = [(i, _iface_network(i)) for i in pending]
    nets = [(i, n) for i, n in nets if n is not None]
    if nets:
        hosts = []
        for ip, lv in db.query(Host.ip, Host.purdue_level).filter(
                Host.ip.isnot(None), Host.purdue_level.isnot(None)):
            try:
                hosts.append((ipaddress.ip_address(ip), lv))
            except ValueError:
                continue
        for iface, net in nets:
            levels = [lv for a, lv in hosts if a.version == net.version and a in net]
            _write_suggestion(iface, _majority_level(levels), "connected_hosts")

    # ── source 4: name_keyword (alias / zone_label / name) ────────────────
    for iface in pending:
        for label in (iface.alias, iface.zone_label, iface.name):
            lv = classify_vlan_name(label) if label else None
            if lv is not None:
                _write_suggestion(iface, lv, "name_keyword")
                break

    # ── source 5: zone_name (FirewallZone membership) ─────────────────────
    zones_by_dev: dict[str, dict[str, str]] = {}
    try:
        for z in db.query(FirewallZone).all():
            if z.zone_name and z.interface_name:
                zones_by_dev.setdefault((z.device_name or "").lower(), {})[
                    z.interface_name.strip().lower()] = z.zone_name
    except Exception:  # pragma: no cover - table missing in old DBs
        log.debug("FirewallZone lookup failed", exc_info=True)
    # B-07: FortiOS zone definitions (per firewall, shared helper) first -
    # keyed by firewall_id, so no device-name ambiguity across sites.
    zone_idx = _fz.ZoneDefIndex(db, {i.firewall_id for i in pending})
    if zone_idx:
        member_zone: dict[tuple, str] = {}
        for (fid, _vd), zmap in zone_idx.defs.items():
            for zd in zmap.values():
                if not zd.get("resolved", True):
                    continue
                for m in zd.get("members") or ():
                    member_zone.setdefault((fid, m), zd.get("name") or "")
        for iface in pending:
            zname = member_zone.get((iface.firewall_id, (iface.name or "").strip().lower()))
            lv = classify_vlan_name(zname) if zname and zname.lower() != (iface.name or "").lower() else None
            if lv is not None:
                _write_suggestion(iface, lv, "zone_name")
    if zones_by_dev:
        for iface in pending:
            fw = fw_by_id.get(iface.firewall_id)
            if fw is None:
                continue
            for dev in {(fw.name or "").lower(), (fw.device_name or "").lower()} - {""}:
                zname = zones_by_dev.get(dev, {}).get((iface.name or "").lower())
                lv = classify_vlan_name(zname) if zname and zname.lower() != (iface.name or "").lower() else None
                if lv is not None:
                    _write_suggestion(iface, lv, "zone_name")
                    break

    # ── source 6: role_heuristic (FortiOS interface role) ─────────────────
    for iface in pending:
        role_lower = (getattr(iface, "role", None) or "").strip().lower()
        if role_lower == "wan":
            _write_suggestion(iface, 4, "role_heuristic")
        elif role_lower == "dmz":
            # F-08: a FortiOS "dmz" role leg is the industrial DMZ.
            _write_suggestion(iface, _purdue.DMZ_LEVEL, "role_heuristic")
        elif role_lower == "lan":
            _write_suggestion(iface, 3, "role_heuristic")

    cleared = sum(
        1 for i in all_ifaces
        if previous[i.id][0] is not None and i.suggested_purdue_level is None
    )
    total = len(already_suggested)
    log.info("run_purdue_suggestions: %d interface(s) suggested, %d stale cleared; by_source=%s",
             total, cleared, by_source)
    return {
        "interfaces_updated": total,
        "suggestions_cleared": cleared,
        "by_source": by_source,
    }


def zone_policy_sides(fw: Firewall, zone_idx: "_fz.ZoneDefIndex") -> list[dict]:
    """B-07: every FortiOS zone of ``fw`` with the Purdue levels a policy
    side naming it resolves to (shared semantics, app.parsers.fortios_zones):

    ``level_status`` "resolved" (every member has a level), "unknown" (the
    membership could not be parsed, or a member has no level / is not a
    known interface: the zone's direction is undetermined) or "empty" (no
    members: a policy naming it matches no interface)."""
    by_name = {(i.name or "").strip().lower(): i for i in (fw.interfaces or []) if i.name}
    out = []
    for vdom, zd in sorted(zone_idx.zones_of(fw.id),
                           key=lambda t: ((t[0] or ""), (t[1].get("name") or "").lower())):
        found = zone_idx.lookup(fw.id, vdom, zd.get("name") or "")
        members, resolved = found if found is not None else ([], False)
        levels: set = set()
        status = "resolved"
        if not resolved:
            status = "unknown"
        elif not members:
            status = "empty"
        else:
            for m in members:
                iface = by_name.get(m)
                if iface is None or iface.purdue_level is None:
                    status = "unknown"
                else:
                    levels.add(iface.purdue_level)
        out.append({
            "name":              zd.get("name"),
            "vdom":              vdom,
            "intrazone":         zd.get("intrazone"),
            "members":           list(zd.get("members") or []),
            "members_resolved":  resolved,
            "member_interface_ids": [by_name[m].id for m in members if m in by_name],
            "purdue_levels":     sorted(levels),
            "level_status":      status,
        })
    return out


def get_topology_state(db: DBSession, site_id: int | None = None) -> dict:
    """
    Return the full current topology for API responses and the topology builder.

    Shape::

        {
            "is_multi_fw": bool,
            "firewall_count": int,
            "firewalls": [
                {
                    "id": int,
                    "name": str,
                    "vendor": str,
                    "upstream_firewall_id": int | None,
                    "topology_confirmed": bool,
                    "interfaces": [
                        {
                            "id": int,
                            "name": str,
                            "ip_cidr": str | None,
                            "network_cidr": str | None,
                            "side": str | None,
                            "zone_label": str | None,
                            "purdue_level": int | 3.5 | None,
                            "connects_to_interface_id": int | None,
                            "is_ha": bool,
                            "is_mgmt_only": bool,
                            "status": str | None, "enabled": bool,   # admin state (down = disabled)
                            "zones": [str],   # B-07: FortiOS zones it belongs to
                        },
                        ...
                    ],
                    "zones": [...],           # B-07: see zone_policy_sides
                },
                ...
            ],
            "pending_proposals": [...],   # from detect_subnet_overlaps
        }
    """
    # site_id (multi-site phase 2): the whole call runs scoped to the site
    # (site_scoped wrapper below): firewalls, interfaces, chains and link
    # proposals are that site's only, and is_multi_fw means "this site has
    # two or more firewalls" (the stored flag counts firewalls globally).
    fw_query = db.query(Firewall).options(joinedload(Firewall.interfaces))
    if site_id is not None:
        fw_query = fw_query.filter(Firewall.site_id == site_id)
    firewalls = fw_query.all()
    if site_id is not None:
        is_multi = len(firewalls) >= 2
    else:
        is_multi = any(fw.is_multi_fw for fw in firewalls)

    # B-07: FortiOS zones (shared helper) - a zone-named policy side is
    # resolved through its member interfaces' levels.
    zone_idx = _fz.ZoneDefIndex(db, [fw.id for fw in firewalls])

    fw_list = []
    for fw in firewalls:
        zones = zone_policy_sides(fw, zone_idx)
        zones_of_iface: dict[str, list[str]] = {}
        for z in zones:
            for m in z["members"]:
                zones_of_iface.setdefault(m, []).append(z["name"])
        ifaces = []
        for iface in (fw.interfaces or []):
            ifaces.append({
                "zones":                     zones_of_iface.get((iface.name or "").strip().lower(), []),
                "id":                        iface.id,
                "name":                      iface.name,
                "alias":                     iface.alias,     # config alias (display only)
                "ip_cidr":                   iface.ip_cidr,
                "network_cidr":              iface.network_cidr,
                "side":                      iface.side,
                "zone_label":                iface.zone_label,
                "purdue_level":              iface.purdue_level,
                "suggested_purdue_level":    iface.suggested_purdue_level,
                "purdue_suggestion_source":  iface.purdue_suggestion_source,
                "connects_to_interface_id":  iface.connects_to_interface_id,
                "segment":                   iface.segment,
                "is_ha":                     iface.is_ha,
                "is_mgmt_only":              iface.is_mgmt_only,
                "vdom":                      iface.vdom,
                "iface_type":                iface.iface_type,
                # VD-03: an inter-VDOM link is internal to the box - no
                # side / level of its own (the UI shows it as a link)
                "is_vdom_link":              (iface.iface_type or "") in ("vdom-link", "npu-vlink", "vdom_link"),
                "remote_access":             getattr(iface, "remote_access", None),   # DR-03
                "role":                      iface.role,      # FortiOS role, or "wan" for the default route
                # admin state from the config (FortiOS `set status down`, Cisco `shutdown`);
                # absent = up
                "status":                    iface.status,
                "enabled":                   (iface.status or "").strip().lower() not in ("down", "disable", "disabled"),
            })
        _chain, _cyclic = upstream_chain(db, fw.id)
        fw_list.append({
            "upstream_chain":        _chain[1:],
            "upstream_cycle":        _cyclic,
            "id":                    fw.id,
            "site_id":               fw.site_id,
            "name":                  fw.name,
            "vendor":                fw.vendor,
            "upstream_firewall_id":  fw.upstream_firewall_id,
            "topology_confirmed":    fw.topology_confirmed,
            "purdue_level_ingress":  fw.purdue_level_ingress,
            "purdue_level_egress":   fw.purdue_level_egress,
            "ha_group_id":           fw.ha_group_id,
            "paired_group_id":       fw.paired_group_id,
            "ha_mode":               fw.ha_mode,
            "ha_cfg_group":          fw.ha_cfg_group,
            "interfaces":            ifaces,
            "zones":                 zones,
        })

    from app.parsers import firewall_groups as _fg
    pending = detect_subnet_overlaps(db) if is_multi else []
    segments = detect_shared_segments(db) if is_multi else []
    if site_id is not None:
        fw_ids = {fw.id for fw in firewalls}
        pending = [p for p in pending
                   if p.get("fw_a_id") in fw_ids and p.get("fw_b_id") in fw_ids]
        segments = [s for s in segments if all(m["fw_id"] in fw_ids for m in s["members"])]
    segments = [{k: v for k, v in s.items() if not k.startswith("_")} for s in segments]

    return {
        "is_multi_fw":       is_multi,
        "firewall_count":    len(firewalls),
        "firewalls":         fw_list,
        "pending_proposals": pending,
        "segment_proposals": segments,
        # HA clusters / paired firewalls and their suggestions
        "firewall_groups":   _fg.list_groups(db),
        "group_suggestions": (_fg.suggest_ha(db) + _fg.suggest_paired(db)) if is_multi else [],
    }


# ─────────────────────────────────── /topology edge classification (N-10) ──

def firewall_level_boundaries(db: DBSession) -> set[tuple]:
    """Every (lo, hi) Purdue level pair a firewall enforces - exactly the
    reachability engine's enforcement-point boundaries (MP-12: one builder,
    so the topology page and the matrix never disagree; a boundary level
    that lies between labelled legs is not a leg)."""
    from app.parsers.reachability import _Context
    try:
        return {(lo, hi) for lo, hi in _Context(db).boundary_map if lo != hi}
    except Exception:  # pragma: no cover - never break the topology page
        log.warning("firewall_level_boundaries: engine build failed", exc_info=True)
        return set()


def classify_level_edge(src_level, dst_level, boundaries: set[tuple]) -> dict:
    """Server-side version of the UI's edge class:

    ``violation``: "same" (same level) | "adjacent" (one Purdue step apart)
    | "skips_level" (more than one step) | "unclassified" (an end has no
    level).  Steps follow app.purdue.VALID_LEVELS, so the DMZ is its own
    level (F-08): L3<->L3.5 and L3.5<->L4 are adjacent, L3<->L4 skips the
    DMZ.  ``crosses_firewall``: True when some firewall boundary lies
    between the two levels, False when none does, None when unclassified.
    """
    if src_level is None or dst_level is None:
        return {"violation": "unclassified", "crosses_firewall": None}
    lo, hi = min(src_level, dst_level), max(src_level, dst_level)
    d = level_distance(lo, hi)
    violation = "same" if d == 0 else "adjacent" if d == 1 else "skips_level"
    crosses = d > 0 and any(lo <= b_lo and b_hi <= hi for b_lo, b_hi in boundaries)
    return {"violation": violation, "crosses_firewall": crosses}


# Multi-site: every public function taking a db gets an optional keyword-only
# site_id and then runs scoped to that site (app.parsers.site_scope).
scope_module(globals(), ("detect_", "propose_", "confirm_", "upstream_", "set_",
                         "run_", "get_", "firewall_"))
