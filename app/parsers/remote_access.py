"""Remote-access gateways, jump hosts and declared segment hops.

Product-neutral: a *remote-access gateway* is whatever terminates the external
connection in the DMZ (VPN concentrator, Teleport/Boundary proxy, RDP/SSH
gateway); a *jump host* is the DMZ host that reaches into OT.  Both are
operator labels:

  gateway   approved-host role ``remote_access_gateway`` (baseline CSV) or
            ``Host.role == "remote_access_gateway"`` (PATCH /hosts/{id}/role)
  jump host approved-host role ``jump_host`` or ``Host.device_type == "jump_host"``

A *declared hop* (``AccessPathHop``) records that a gateway reaches a jump host
inside one segment, where no firewall can see the step.  Access Review joins
paths through it (app.parsers.access_paths._compose_conduits).

All queries run inside the caller's site binding (``analysis_site`` /
``site_scoped``), so every result is one site's.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.models import AccessPathHop, ApprovedHost, Baseline, Host

GATEWAY_ROLE = "remote_access_gateway"
JUMP_ROLE = "jump_host"

_SERVICE_TOKEN = re.compile(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$")
_MAX_SERVICE_TOKENS = 20
_MAX_SERVICE_LEN = 255          # AccessPathHop.service is String(255)


def canon_ip(value) -> str:
    """Canonical text of an address (``2001:DB8::0:1`` -> ``2001:db8::1``);
    the stripped input when it is not an address.  Host / baseline rows keep
    the address as ingested, so every comparison here goes through this."""
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _role_is(column, role: str):
    """SQL predicate: ``column`` equals ``role`` ignoring case and ``-``/``_``."""
    return func.lower(func.replace(column, "-", "_")) == role


class HopError(ValueError):
    """Invalid declared hop (HTTP 422); ``status`` 404/409 for those cases."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _active_baseline_id(db: DBSession) -> Optional[int]:
    row = (db.query(Baseline.id).filter(Baseline.is_active == True)  # noqa: E712
           .order_by(Baseline.created_at.desc()).first())
    return row[0] if row else None


def gateway_ips(db: DBSession) -> set[str]:
    """Addresses labelled remote-access gateway (active baseline or host role)."""
    out: set[str] = set()
    bid = _active_baseline_id(db)
    if bid is not None:
        out |= {canon_ip(r[0]) for r in db.query(ApprovedHost.ip).filter(
            ApprovedHost.baseline_id == bid, _role_is(ApprovedHost.role, GATEWAY_ROLE),
            ApprovedHost.ip.isnot(None)).all() if r[0]}
    out |= {canon_ip(r[0]) for r in db.query(Host.ip).filter(
        _role_is(Host.role, GATEWAY_ROLE), Host.ip.isnot(None)).all() if r[0]}
    return out


def jump_host_ips(db: DBSession) -> set[str]:
    """Addresses labelled jump host (active baseline or host device_type)."""
    out: set[str] = set()
    bid = _active_baseline_id(db)
    if bid is not None:
        out |= {canon_ip(r[0]) for r in db.query(ApprovedHost.ip).filter(
            ApprovedHost.baseline_id == bid, _role_is(ApprovedHost.role, JUMP_ROLE),
            ApprovedHost.ip.isnot(None)).all() if r[0]}
    out |= {canon_ip(r[0]) for r in db.query(Host.ip).filter(
        _role_is(Host.device_type, JUMP_ROLE), Host.ip.isnot(None)).all() if r[0]}
    return out


# ------------------------------------------------------------------ hops --

def normalize_service(service) -> Optional[str]:
    """``None`` / "" / "any" -> None (any); else a canonical comma list of
    ``proto/port`` or ``proto/lo-hi`` tokens.  HopError on anything else."""
    if service is None:
        return None
    if isinstance(service, (list, tuple)):
        tokens = [str(t) for t in service]
    else:
        tokens = str(service).split(",")
    tokens = [t.strip().lower() for t in tokens if t.strip()]
    if not tokens or "any" in tokens:     # "any" swallows the other tokens
        return None
    if len(tokens) > _MAX_SERVICE_TOKENS:
        raise HopError(f"service: at most {_MAX_SERVICE_TOKENS} tokens")
    out = []
    for t in tokens:
        m = _SERVICE_TOKEN.match(t)
        if not m:
            raise HopError(f"service token {t!r}: use tcp/22, udp/500, tcp/1000-2000 or any")
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        if not (0 < lo <= 65535 and 0 < hi <= 65535 and lo <= hi):
            raise HopError(f"service token {t!r}: ports must be 1-65535 and ordered")
        out.append(f"{m.group(1)}/{lo}" if lo == hi else f"{m.group(1)}/{lo}-{hi}")
    text = ",".join(dict.fromkeys(out))
    if len(text) > _MAX_SERVICE_LEN:
        raise HopError(f"service: at most {_MAX_SERVICE_LEN} characters")
    return text


def _norm_ip(value, field: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise HopError(f"{field}: {value!r} is not an IP address")


def _host(db: DBSession, ip: str):
    """The site's host at canonical address ``ip`` (lowest id when several
    rows share it).  Host.ip is stored as ingested, so a row written as
    ``2001:DB8::1`` is still found for ``2001:db8::1``."""
    row = db.query(Host).filter(Host.ip == ip).order_by(Host.id).first()
    if row is not None:
        return row
    for hid, hip in db.query(Host.id, Host.ip).filter(Host.ip.isnot(None)).order_by(Host.id):
        if canon_ip(hip) == ip:
            return db.get(Host, hid)
    return None


def _hosts_by_canon(db: DBSession) -> dict:
    """canonical ip -> Host (lowest id wins) for the whole site."""
    out: dict = {}
    for h in db.query(Host).filter(Host.ip.isnot(None)).order_by(Host.id.desc()):
        out[canon_ip(h.ip)] = h
    return out


def hop_dict(h: AccessPathHop) -> dict:
    return {"id": h.id, "from_ip": h.from_ip, "to_ip": h.to_ip, "service": h.service,
            "note": h.note, "created_by": h.created_by,
            "created_at": h.created_at.isoformat() if h.created_at else None}


def list_hops(db: DBSession) -> list[dict]:
    """Declared hops with a staleness signal: ``from_known`` / ``to_known``
    say whether each end still exists as a host of the site, and
    ``level_mismatch`` whether the two have since landed on different Purdue
    levels (the hop still composes, but its premise - one segment - no longer
    holds and the operator should re-check it)."""
    hosts = _hosts_by_canon(db)
    out = []
    for h in db.query(AccessPathHop).order_by(AccessPathHop.id).all():
        hf, ht = hosts.get(h.from_ip), hosts.get(h.to_ip)
        lf = getattr(hf, "purdue_level", None)
        lt = getattr(ht, "purdue_level", None)
        out.append({**hop_dict(h), "from_known": hf is not None, "to_known": ht is not None,
                    "level_mismatch": lf is not None and lt is not None and lf != lt})
    return out


def create_hop(db: DBSession, site_id: int, *, from_ip, to_ip, service=None,
               note=None, created_by=None) -> AccessPathHop:
    """Validate and add (flush, no commit).  Both hosts must be known to the
    site and, when both carry a Purdue level, share it: a hop joins two hosts
    of one segment."""
    f, t = _norm_ip(from_ip, "from_ip"), _norm_ip(to_ip, "to_ip")
    if f == t:
        raise HopError("from_ip and to_ip must differ")
    hf, ht = _host(db, f), _host(db, t)
    for ip, h in ((f, hf), (t, ht)):
        if h is None:
            raise HopError(f"unknown host {ip} in this site (ingest or classify it first)")
    if hf.purdue_level is not None and ht.purdue_level is not None \
            and hf.purdue_level != ht.purdue_level:
        raise HopError(
            f"{f} (L{hf.purdue_level}) and {t} (L{ht.purdue_level}) are on different "
            "Purdue levels; a hop joins two hosts of one segment")
    if note is not None and len(str(note)) > 2000:
        raise HopError("note: at most 2000 characters")
    if created_by is not None and len(str(created_by)) > 128:
        raise HopError("created_by: at most 128 characters")
    if db.query(AccessPathHop).filter(AccessPathHop.from_ip == f,
                                      AccessPathHop.to_ip == t).first():
        raise HopError(f"hop {f} -> {t} is already declared", status=409)
    hop = AccessPathHop(site_id=site_id, from_ip=f, to_ip=t,
                        service=normalize_service(service),
                        note=(str(note) if note else None),
                        created_by=(str(created_by) if created_by else None))
    db.add(hop)
    try:
        db.flush()
    except IntegrityError:        # lost the race with a concurrent declaration
        raise HopError(f"hop {f} -> {t} is already declared", status=409)
    return hop


def delete_hop(db: DBSession, hop_id: int) -> None:
    hop = db.query(AccessPathHop).filter(AccessPathHop.id == hop_id).first()
    if hop is None:
        raise HopError(f"hop {hop_id} not found", status=404)
    db.delete(hop)
    db.flush()


def suggest_hops(db: DBSession) -> list[dict]:
    """Gateway -> jump host pairs worth declaring: not declared yet, same
    Purdue level (when both are known) and same VLAN (when both are known)."""
    declared = {(h.from_ip, h.to_ip) for h in db.query(AccessPathHop).all()}
    hosts = _hosts_by_canon(db)
    out = []
    for g in sorted(gateway_ips(db)):
        for j in sorted(jump_host_ips(db)):
            if g == j or (g, j) in declared:
                continue
            hg, hj = hosts.get(g), hosts.get(j)
            if hg is None or hj is None:
                continue          # baseline-only address: create_hop would refuse it
            lg = getattr(hg, "purdue_level", None)
            lj = getattr(hj, "purdue_level", None)
            if lg is not None and lj is not None and lg != lj:
                continue
            vg, vj = getattr(hg, "vlan", None), getattr(hj, "vlan", None)
            if vg is not None and vj is not None and str(vg) != str(vj):
                continue
            out.append({"from_ip": g, "to_ip": j,
                        "level": lg if lg is not None else lj,
                        "vlan": vg if vg is not None else vj,
                        "reason": "labelled remote-access gateway and jump host in the "
                                  "same segment; no firewall sees the step between them"})
    return out
