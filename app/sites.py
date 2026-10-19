"""
Sites (multi-site support, phase 1 - see docs/multi-site-design.md).

What lives here:

* ``resolve_site(db, value)`` - turn a user-supplied site reference (id,
  name or code; names/codes case-insensitive) into a Site, or raise
  ``SiteNotFound``.  Routes map that to HTTP 422.
* ``get_default_site(db)`` - the "Default" site created by migration
  c0d1e2f3a4b5 (code ``default``), created on demand when missing.
* ``ingest_site(db, site_id)`` / ``@site_ingest`` - bind "the site this
  upload belongs to" to a Session for the duration of an ingest.  Every
  parser entry point is decorated with ``@site_ingest`` and therefore takes
  a keyword-only ``site_id`` argument; routes always pass it.  ``None``
  means "inherit the enclosing binding, else the Default site" - that is
  only for internal / legacy callers and tests.
* A ``before_flush`` listener that fills ``site_id`` on every NEW row of a
  site-scoped (root) table that did not set it explicitly, in this order:

    1. the site of the row's parent (``SITE_PARENTS``: e.g. a FirewallRule
       takes its FirewallDevice's / Firewall's site, a Finding takes the
       site of its rule, session (source host) or log event) - so derived
       rows always agree with the object they describe;
    2. the ingest site bound when the row was added (or at flush time);
    3. the Default site.

  This is what lets the ~30 parsers and analysis modules keep creating
  rows without threading ``site_id`` through every constructor, while
  uploads still land in the site the operator chose.

Phase 2 hooks: site-scoped identity (host IP/MAC, firewall names, finding
source_ref, baselines) and per-site analysis will bind ``ingest_site`` (or
pass site_id) around each per-site analysis run; nothing here needs to
change for that.  Phase 3 (syslog routing) replaces the Default-site
binding of the log ingest routes with a per-line device lookup.
"""
from __future__ import annotations

import contextlib
import functools
import inspect as _inspect
import re
from typing import Callable, Optional

import logging

import sqlalchemy as sa

from sqlalchemy import event, func
from sqlalchemy.orm import Session

from app.models import (
    DEFAULT_SITE_CODE, DEFAULT_SITE_NAME,
    Attestation, Baseline, Finding, Firewall, FirewallDevice, FirewallRule,
    FortiAnalyzerEvent, Host, NatRule, NetworkSession, PcapCapture, Site, SiteScoped,
)

_log = logging.getLogger(__name__)

_INFO_KEY = "iasc_ingest_site_id"
_PENDING_ATTR = "_iasc_ingest_site_id"


class SiteNotFound(ValueError):
    """Unknown / missing site reference (routes answer 422)."""


# ------------------------------------------------------------------ lookup --

def _norm(value: str) -> str:
    return value.strip().lower()


def find_site(db: Session, value) -> Optional[Site]:
    """Site by id (int or all-digit string), else by code, else by name
    (both case-insensitive).  None when nothing matches."""
    if value is None:
        return None
    if isinstance(value, Site):
        return value
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return db.get(Site, value)
    text = str(value).strip()
    if not text:
        return None
    if text.isascii() and text.isdecimal():
        site = db.get(Site, int(text))
        if site is not None:
            return site
    low = _norm(text)
    site = db.query(Site).filter(func.lower(Site.code) == low).first()
    if site is None:
        site = db.query(Site).filter(func.lower(Site.name) == low).first()
    return site


def resolve_site(db: Session, value) -> Site:
    """Like find_site but raises SiteNotFound with an operator-facing message."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise SiteNotFound(
            "'site' is required: pass the site id, name or code this upload belongs "
            "to (GET /sites lists them; POST /sites creates one)")
    site = find_site(db, value)
    if site is None and _norm(str(value)) in (DEFAULT_SITE_CODE, DEFAULT_SITE_NAME.lower()) \
            and db.query(Site.id).first() is None:
        # A database without any site yet (built by create_all outside
        # init_db): the Default site is created on first use, as it would be
        # for a site-less row at flush time.
        site = get_default_site(db)
    if site is None:
        known = ", ".join(n for (n,) in db.query(Site.name).order_by(Site.id).limit(20))
        raise SiteNotFound(
            f"Unknown site {str(value)!r} - expected a site id, name or code "
            f"(known sites: {known or 'none'}; POST /sites creates one)")
    return site


def _default_site_id_conn(conn) -> int:
    """Default site id via Core (usable inside a flush): code 'default', else
    the oldest site, else insert the Default site."""
    t = Site.__table__
    sid = conn.execute(sa.select(t.c.id).where(t.c.code == DEFAULT_SITE_CODE)).scalar()
    if sid is None:
        sid = conn.execute(sa.select(func.min(t.c.id))).scalar()
    if sid is None:
        from app.models import utcnow
        res = conn.execute(t.insert().values(
            name=DEFAULT_SITE_NAME, code=DEFAULT_SITE_CODE,
            description="Created automatically; holds data uploaded before sites existed.",
            created_at=utcnow().replace(tzinfo=None)))
        sid = res.inserted_primary_key[0]
    return sid


def get_default_site(db: Session) -> Site:
    """The Default site (code 'default'); falls back to the oldest site if the
    operator deleted it, and is created when the table is empty."""
    with db.no_autoflush:
        sid = _default_site_id_conn(db.connection())
    return db.get(Site, sid)


def get_default_site_id(db: Session) -> int:
    return get_default_site(db).id


def site_names(db: Session) -> dict[int, str]:
    """{site_id: name} for response decoration (one cheap query)."""
    return dict(db.query(Site.id, Site.name).all())


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    return _SLUG_RE.sub("-", name.strip().lower()).strip("-")[:64] or "site"


# --------------------------------------------------------- ingest binding --

@contextlib.contextmanager
def ingest_site(db: Session, site_id: Optional[int]):
    """Bind ``site_id`` as the ingest site of ``db`` for the block.  ``None``
    keeps any enclosing binding (so nested parser calls inherit the route's
    site) and otherwise leaves the Default-site fallback in place."""
    if db is None or not hasattr(db, "info"):
        yield
        return
    prev = db.info.get(_INFO_KEY)
    if site_id is not None:
        db.info[_INFO_KEY] = int(site_id)
    try:
        yield
    finally:
        if prev is None:
            db.info.pop(_INFO_KEY, None)
        else:
            db.info[_INFO_KEY] = prev


def bind_ingest_site(db: Session, site_id: int) -> None:
    """Bind ``site_id`` for the rest of this Session's life (request-scoped
    sessions only - prefer ``ingest_site`` everywhere else)."""
    db.info[_INFO_KEY] = int(site_id)


def current_ingest_site_id(db: Session) -> Optional[int]:
    return db.info.get(_INFO_KEY)


def scope_site_id(db: Session, site_id: Optional[int] = None) -> int:
    """The site an identity lookup (get-or-create) must stay inside (phase 2):
    ``site_id`` when given, else the bound ingest site, else the Default
    site.  Every parser get-or-create filters on this so the same IP / MAC /
    firewall name in two sites yields two independent rows."""
    if site_id is not None:
        return int(site_id)
    sid = db.info.get(_INFO_KEY)
    if sid is not None:
        return int(sid)
    with db.no_autoflush:
        return _default_site_id_conn(db.connection())


def site_ingest(fn: Callable) -> Callable:
    """Decorator for parser entry points: adds a keyword-only ``site_id``
    argument and binds it (``ingest_site``) to the function's ``db`` /
    ``session`` argument for the duration of the call."""
    sig = _inspect.signature(fn)
    db_param = next((n for n in ("db", "session") if n in sig.parameters), None)
    if db_param is None:  # pragma: no cover - programming error
        raise TypeError(f"@site_ingest: {fn.__name__} has no db/session parameter")

    @functools.wraps(fn)
    def wrapper(*args, site_id: Optional[int] = None, **kwargs):
        try:
            db = sig.bind_partial(*args, **kwargs).arguments.get(db_param)
        except TypeError:
            db = kwargs.get(db_param)
        with ingest_site(db, site_id):
            return fn(*args, **kwargs)

    params = list(sig.parameters.values())
    kw = _inspect.Parameter("site_id", _inspect.Parameter.KEYWORD_ONLY, default=None,
                            annotation=Optional[int])
    if params and params[-1].kind is _inspect.Parameter.VAR_KEYWORD:
        params.insert(len(params) - 1, kw)
    else:
        params.append(kw)
    wrapper.__signature__ = sig.replace(parameters=params)
    return wrapper


# ------------------------------------------------- flush-time site filling --

def _get(db: Session, model, pk):
    if pk is None:
        return None
    return db.get(model, pk)


def _from_rel_or_fk(rel: Optional[str], fk: str, model):
    def _resolve(db, obj):
        if rel is not None:
            parent = obj.__dict__.get(rel)
            if parent is not None:
                return parent
        return _get(db, model, getattr(obj, fk, None))
    return _resolve


def _finding_session_host(db, obj):
    sess = obj.__dict__.get("session") if "session" in obj.__dict__ else None
    if sess is None:
        sess = _get(db, NetworkSession, obj.session_id)
    if sess is None:
        return None
    host = sess.__dict__.get("src_host")
    return host if host is not None else _get(db, Host, sess.src_host_id)


# model -> parent resolvers, tried in order; each returns a SiteScoped row or None.
SITE_PARENTS: dict[type, list[Callable]] = {
    FirewallRule: [_from_rel_or_fk("firewall_device", "firewall_device_id", FirewallDevice),
                   _from_rel_or_fk(None, "firewall_id", Firewall)],
    NatRule: [_from_rel_or_fk(None, "firewall_device_id", FirewallDevice),
              _from_rel_or_fk(None, "firewall_id", Firewall)],
    FirewallDevice: [_from_rel_or_fk("firewall", "firewall_id", Firewall)],
    PcapCapture: [_from_rel_or_fk("firewall", "firewall_id", Firewall)],
    Attestation: [_from_rel_or_fk("baseline", "baseline_id", Baseline)],
    Finding: [_from_rel_or_fk(None, "rule_id", FirewallRule),
              _finding_session_host,
              _from_rel_or_fk(None, "forti_event_id", FortiAnalyzerEvent)],
}


def _resolve_site_id(db, obj, default: list, seen: set) -> int:
    if obj.site_id is not None:
        return obj.site_id
    if id(obj) in seen:  # defensive: parent cycles
        return None
    seen.add(id(obj))
    for resolver in SITE_PARENTS.get(type(obj), ()):
        parent = resolver(db, obj)
        if parent is not None and isinstance(parent, SiteScoped):
            sid = _resolve_site_id(db, parent, default, seen)
            if sid is not None:
                bound = getattr(obj, _PENDING_ATTR, None) or db.info.get(_INFO_KEY)
                if bound is not None and int(bound) != int(sid):
                    # C-18: the row's parent (rule / session / event) belongs
                    # to another site than the one this session is working
                    # in - a scoping bug upstream.  The parent is the truth
                    # about the data, so the row follows it; say so loudly.
                    _log.warning("%s created in site %s scope but its parent %s "
                                 "belongs to site %s; stored in site %s",
                                 type(obj).__name__, bound, type(parent).__name__, sid, sid)
                obj.site_id = sid
                return sid
    sid = getattr(obj, _PENDING_ATTR, None) or db.info.get(_INFO_KEY)
    if sid is None:
        if not default:
            default.append(_default_site_id_conn(db.connection()))
        sid = default[0]
    obj.site_id = sid
    return sid


@event.listens_for(Session, "transient_to_pending")
def _remember_ingest_site(session, instance):
    if isinstance(instance, SiteScoped) and instance.site_id is None:
        sid = session.info.get(_INFO_KEY)
        if sid is not None:
            setattr(instance, _PENDING_ATTR, sid)


@event.listens_for(Session, "before_flush")
def _fill_site_ids(session, flush_context, instances):
    new = [o for o in session.new if isinstance(o, SiteScoped) and o.site_id is None]
    if not new:
        return
    default: list = []
    with session.no_autoflush:
        for obj in new:
            _resolve_site_id(session, obj, default, set())
