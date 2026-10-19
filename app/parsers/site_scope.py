"""
Per-site analysis scope (multi-site phase 2 part B, docs/multi-site-design.md).

Sites are isolated: no analysis may read or write another site's data.
Rather than threading ``.filter(X.site_id == sid)`` through the ~400 queries
of the analysis modules (and missing one), an analysis run binds its site to
the Session with ``analysis_site(db, site_id)``.  While bound, a
``do_orm_execute`` listener adds ``with_loader_criteria`` to EVERY ORM
SELECT / UPDATE / DELETE issued on that Session:

* every SiteScoped (root) table - Host, Firewall, FirewallDevice,
  FirewallRule, NatRule, FirewallZone, Baseline, Attestation, Finding,
  FortiAnalyzerEvent, PcapCapture, switch tables, ... - by ``site_id``;
* child tables without a site column via their parent:
  NetworkSession (src host), ProtocolDetail (session -> src host),
  FirewallInterface (firewall), HostAddressHistory (host),
  ApprovedCommsEntry / ApprovedHost (baseline).

Aliased entities (``aliased(Host)``) are covered (include_aliases), so are
column-only queries (``db.query(Host.ip)``) and relationship lazy loads.
``db.get()`` of an object already in the identity map is not re-filtered;
analysis code only reaches such objects through filtered queries.

The scope also binds ``app.sites.ingest_site`` so rows created by the
analysis (findings) land in the analysed site.

``site_id=None`` binds nothing: legacy internal callers keep the
all-data behaviour.  Raw ``text()`` SQL is never filtered (the analysis
modules use none apart from PostgreSQL advisory locks).
"""
from __future__ import annotations

import contextlib
import functools
import inspect as _inspect
from typing import Callable, Optional

from sqlalchemy import event, select
from sqlalchemy.orm import Session, with_loader_criteria

from app.models import (
    ApprovedCommsEntry, ApprovedHost, Baseline, Firewall, FirewallInterface, Host,
    HostAddressHistory, NetworkSession, ProtocolDetail, SiteScoped,
)
from app.sites import ingest_site

SCOPE_KEY = "iasc_analysis_site_id"
# execution option that disables the filter for one statement (cross-site
# roll-ups only - never used by analysis code).
CROSS_SITE_OPTION = "iasc_cross_site"


class CrossSiteError(ValueError):
    """An operation would link / mix objects of two different sites."""


def current_site(db) -> Optional[int]:
    """The analysis site bound to ``db`` (None = unscoped / all data)."""
    info = getattr(db, "info", None)
    return None if info is None else info.get(SCOPE_KEY)


@contextlib.contextmanager
def analysis_site(db, site_id: Optional[int]):
    """Bind ``site_id`` as the analysis site of ``db`` for the block.
    ``None`` keeps any enclosing binding (nested helpers inherit the run's
    site) and is otherwise a no-op (legacy all-data behaviour)."""
    if site_id is None or db is None or not hasattr(db, "info"):
        yield
        return
    sid = int(site_id)
    prev = db.info.get(SCOPE_KEY)
    db.info[SCOPE_KEY] = sid
    try:
        with ingest_site(db, sid):
            yield
    finally:
        if prev is None:
            db.info.pop(SCOPE_KEY, None)
        else:
            db.info[SCOPE_KEY] = prev


def site_scoped(fn: Callable) -> Callable:
    """Decorator for analysis entry points: adds a keyword-only ``site_id``
    argument (unless the function already declares one) and runs the call
    inside ``analysis_site`` on its ``db`` / ``session`` argument."""
    sig = _inspect.signature(fn)
    db_param = next((n for n in ("db", "session") if n in sig.parameters), None)
    if db_param is None:  # pragma: no cover - programming error
        raise TypeError(f"@site_scoped: {fn.__name__} has no db/session parameter")
    declares = "site_id" in sig.parameters

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        sid = kwargs.get("site_id") if declares else kwargs.pop("site_id", None)
        try:
            db = sig.bind_partial(*args, **kwargs).arguments.get(db_param)
        except TypeError:
            db = kwargs.get(db_param)
        with analysis_site(db, sid):
            return fn(*args, **kwargs)

    if not declares:
        params = list(sig.parameters.values())
        kw = _inspect.Parameter("site_id", _inspect.Parameter.KEYWORD_ONLY, default=None,
                                annotation=Optional[int])
        if params and params[-1].kind is _inspect.Parameter.VAR_KEYWORD:
            params.insert(len(params) - 1, kw)
        else:
            params.append(kw)
        wrapper.__signature__ = sig.replace(parameters=params)
    wrapper.__iasc_site_scoped__ = True
    return wrapper


def scope_module(namespace: dict, prefixes: tuple, names: tuple = ()) -> None:
    """Wrap every public function of a module whose name starts with one of
    ``prefixes`` (or is in ``names``) with ``site_scoped`` in place."""
    for name, obj in list(namespace.items()):
        if not callable(obj) or not _inspect.isfunction(obj):
            continue
        if obj.__module__ != namespace.get("__name__"):
            continue
        if getattr(obj, "__iasc_site_scoped__", False):
            continue
        if not (name in names or (not name.startswith("_") and name.startswith(prefixes))):
            continue
        sig = _inspect.signature(obj)
        if not any(n in sig.parameters for n in ("db", "session")):
            continue
        namespace[name] = site_scoped(obj)


def same_site(*objs) -> bool:
    sids = {getattr(o, "site_id", None) for o in objs if o is not None}
    sids.discard(None)
    return len(sids) <= 1


def require_same_site(what: str, *objs) -> None:
    if not same_site(*objs):
        raise CrossSiteError(
            f"{what}: objects belong to different sites "
            f"({sorted({o.site_id for o in objs if o is not None})}); "
            "sites are isolated and cannot be linked")


def _criteria(sid: int) -> list:
    host_ids = select(Host.id).where(Host.site_id == sid)
    return [
        with_loader_criteria(SiteScoped, lambda cls: cls.site_id == sid,
                             include_aliases=True),
        with_loader_criteria(
            NetworkSession,
            NetworkSession.src_host_id.in_(host_ids), include_aliases=True),
        with_loader_criteria(
            ProtocolDetail,
            ProtocolDetail.session_id.in_(
                select(NetworkSession.id)
                .join(Host, Host.id == NetworkSession.src_host_id)
                .where(Host.site_id == sid)),
            include_aliases=True),
        with_loader_criteria(
            FirewallInterface,
            FirewallInterface.firewall_id.in_(select(Firewall.id).where(Firewall.site_id == sid)),
            include_aliases=True),
        with_loader_criteria(
            HostAddressHistory, HostAddressHistory.host_id.in_(host_ids), include_aliases=True),
        with_loader_criteria(
            ApprovedCommsEntry,
            ApprovedCommsEntry.baseline_id.in_(select(Baseline.id).where(Baseline.site_id == sid)),
            include_aliases=True),
        with_loader_criteria(
            ApprovedHost,
            ApprovedHost.baseline_id.in_(select(Baseline.id).where(Baseline.site_id == sid)),
            include_aliases=True),
    ]


@event.listens_for(Session, "do_orm_execute")
def _apply_site_scope(state) -> None:
    sid = state.session.info.get(SCOPE_KEY)
    if sid is None:
        return
    if not (state.is_select or state.is_update or state.is_delete):
        return
    if state.execution_options.get(CROSS_SITE_OPTION):
        return
    state.statement = state.statement.options(*_criteria(sid))
