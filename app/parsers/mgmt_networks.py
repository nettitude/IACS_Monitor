"""
Declared management and engineering networks (ISA/IEC 62443-3-3 SR 1.3,
SR 2.1, SR 5.1 RE1; workbook rows 2.5, 5.1, 5.5, 8.4, 9.5).

Where privileged access legitimately comes from is an operator decision,
recorded as ``ManagementNetwork`` rows of one site.  Each has a PURPOSE:

``management``   administering infrastructure - firewalls, switches, servers,
                 the OS of HMIs / historians (SSH, HTTPS, SNMP, RDP).  Admin
                 workstations, jump hosts, the management / OOB network.
``engineering``  programming and configuring controllers and field devices at
                 L0-L2 (vendor programming tools, industrial writes, the
                 device's web / SSH UI).  Engineering workstations (EWS), the
                 engineering zone - typically at L3 (site operations) or L2.

An engineering source is approved toward OT equipment (L0-L2) and for
industrial write / program operations, never for infrastructure admin access
(firewall admin, trusted hosts).  A management source is approved for both
kinds of management access but is NOT an engineering source for industrial
writes.

Kinds:

``subnet``  a network (CIDR) - every address in it is a source.
``host``    a trusted host: admin_ws / jump_host (management) or
            engineering_ws (engineering); kept apart from the audit baseline.
``vlan``    a VLAN id (site-wide).  Its subnets are the networks of the
            firewall VLAN interfaces with that id; hosts the switches put on it
            are sources too.
``name``    reclassifies a firewall interface / FortiOS zone / alias name as a
            management zone, an engineering zone, or neither, on one firewall
            or all of them.

Every check reads one ``MgmtContext`` built from these rows plus the active
baseline's admin_ws / jump_host (management) and engineering_ws (engineering)
entries, IP or CIDR:

* mgmt_access_from_wrong_zone, chain / rule_mgmt_wrong_zone,
  mgmt_access_not_restricted (destination OT): management or engineering
  sources approved; session_mgmt_from_non_admin: engineering only when the
  destination is L0-L2; auth_from_non_admin_host (firewall admin login):
  management only;
* config_mgmt_not_restricted_to_mgmt_zone, config_admin_trusthost_outside_mgmt:
  management only (an engineering zone is not where firewall admin belongs);
* unauth_ot_write, unauthorized_industrial_write: declared engineering sources
  are approved in addition to the baseline's engineering_ws / hmi entries.

The two config checks are re-judged from the stored interfaces and trusted
hosts (``review_config_firewall``), so a declaration takes effect without a
re-upload; ``recheck`` re-runs everything above and reports what changed.

Name keywords are SUGGESTIONS for the network checks: an interface called
"mgmt" is not trusted as a management source until the operator confirms it.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.models import (
    ACTIVE_FINDING_STATUSES, CHECK_TYPE_REFERENCE, MANAGEMENT_HOST_ROLES, MANAGEMENT_NETWORK_KINDS, MANAGEMENT_PURPOSES,
    ApprovedHost,
    Baseline, Finding, Firewall, FirewallInterface, FirewallZone, FirewallZoneDef, Host,
    ManagementNetwork, NetworkSession, SwitchVlan,
)
from app.parsers import rule_match as rm

log = logging.getLogger(__name__)

KIND_SUBNET, KIND_HOST, KIND_VLAN, KIND_NAME = MANAGEMENT_NETWORK_KINDS
# Name words that make an interface a management zone for the config check
# when nothing is declared (the historical rule), and that make it a
# SUGGESTION for the network checks.
CONFIG_KEYWORDS = ("mgmt", "management", "admin")
SUGGEST_KEYWORDS = CONFIG_KEYWORDS + ("oob", "out-of-band", "outofband")
ENG_KEYWORDS = ("engineering", "ews")

PURPOSE_MGMT, PURPOSE_ENG = MANAGEMENT_PURPOSES
# H-05: a network / VLAN declared a combined L1/L2 cell/area zone (a zone
# decision, not a source of privileged access - the context ignores it)
PURPOSE_CELL = "cell_zone"
# Owner (SF tabletop): a declared site NTP server is a service, not a source
# of privileged access - time sync to it from any level is exempt from the
# upward-skip / dependency / bypass checks (NTP_PORT only).
PURPOSE_SERVICE = "service"
ROLE_PURPOSE = {"admin_ws": PURPOSE_MGMT, "jump_host": PURPOSE_MGMT, "engineering_ws": PURPOSE_ENG,
                "ntp_server": PURPOSE_SERVICE}
ROLE_LABEL = {"admin_ws": "admin workstation", "jump_host": "jump host",
              "engineering_ws": "engineering workstation", "ntp_server": "site NTP server"}
NTP_PORT = 123
OT_LEVEL_MAX = 2          # a destination at L0-L2 is OT equipment

CHECK_CFG_ZONE = "config_mgmt_not_restricted_to_mgmt_zone"
CHECK_TRUSTHOST = "config_admin_trusthost_outside_mgmt"
# Every check whose outcome a declaration can change (recheck reports these).
MGMT_CHECKS = (
    "mgmt_access_from_wrong_zone", "mgmt_access_not_restricted",
    "session_mgmt_from_non_admin", "auth_from_non_admin_host",
    "rule_mgmt_wrong_zone", "chain_mgmt_wrong_zone",
    CHECK_CFG_ZONE, CHECK_TRUSTHOST,
    "unauth_ot_write", "unauthorized_industrial_write",
    "flat_control_segment",
    # SF: a declared site NTP server closes the time-sync findings
    "ot_it_dependency", "session_it_ot_bypass", "rule_ot_it_dependency", "chain_ot_upward_skip",
)
NTP_CHECKS = ("ot_it_dependency", "session_it_ot_bypass", "rule_ot_it_dependency", "chain_ot_upward_skip")
WRITE_CHECKS = ("unauth_ot_write", "unauthorized_industrial_write")
# Periodic reviews re-run by recheck (alert_engine names).
MGMT_REVIEWS = frozenset({
    "review_mgmt_access_from_wrong_zone", "review_mgmt_access_not_restricted",
    "review_ns_mgmt_from_non_admin", "review_rule_mgmt_wrong_zone",
    "review_chain_mgmt_wrong_zone", "review_flat_control_segments",
    "review_ot_it_dependencies", "review_ns_it_ot_bypass", "review_rule_ot_it_dependency",
    "review_chain_ot_upward_skip",
})
_MGMT_ACCESS = {"https", "ssh"}
_AUTO_NOTE = "Auto-resolved: management classification"
_NOTES_MAX = 2048
# Narrowest "network" and widest "host" a declaration may name.
_MIN_SUBNET_PREFIX = {4: 8, 6: 32}
_MIN_HOST_PREFIX = {4: 28, 6: 120}


class MgmtError(ValueError):
    """422 by default; ``status`` 404 / 409 for those cases."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ helpers --
def _net(text) -> Optional[ipaddress._BaseNetwork]:
    if text is None:
        return None
    t = str(text).strip()
    if not t:
        return None
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None


def _vlan_int(v) -> Optional[int]:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 4094 else None


def _lower(s) -> str:
    return str(s or "").strip().lower()


def keyword_of(*names) -> Optional[str]:
    """The config keyword a name contains (mgmt / management / admin), else None."""
    for n in names:
        low = _lower(n)
        for k in CONFIG_KEYWORDS:
            if k in low:
                return k
    return None


def _suggest_keyword(*names) -> Optional[str]:
    for n in names:
        low = _lower(n)
        for k in SUGGEST_KEYWORDS:
            if k in low:
                return k
    return None


def _eng_keyword(*names) -> Optional[str]:
    for n in names:
        low = _lower(n)
        for k in ENG_KEYWORDS:
            if k in low:
                return k
    return None


def _suggest(*names) -> Optional[tuple]:
    """(purpose, keyword) a name suggests, else None (management wins)."""
    k = _suggest_keyword(*names)
    if k:
        return PURPOSE_MGMT, k
    k = _eng_keyword(*names)
    return (PURPOSE_ENG, k) if k else None


def _is_ot(level) -> bool:
    try:
        return level is not None and float(level) <= OT_LEVEL_MAX
    except (TypeError, ValueError):
        return False


def purpose_word(purpose) -> str:
    return "engineering" if purpose == PURPOSE_ENG else "management"


def access_set(allowaccess) -> set:
    """FirewallInterface.allowaccess as a set of lower-case protocol names
    (stored as a list, or as one space-separated string for a single value)."""
    if not allowaccess:
        return set()
    if isinstance(allowaccess, str):
        return {_lower(a) for a in allowaccess.split() if a.strip()}
    return {_lower(a) for a in allowaccess if str(a).strip()}


def make_key(kind: str, cidr=None, vlan_id=None, firewall_id=None, name=None, role=None) -> str:
    if kind == KIND_HOST:
        # SF-4: one declaration per host AND role - a jump box that also
        # programs controllers is a jump host and an engineering workstation
        return f"{kind}:{cidr}:{role or 'admin_ws'}"
    if kind == KIND_SUBNET:
        return f"{kind}:{cidr}"
    if kind == KIND_VLAN:
        return f"vlan:{int(vlan_id)}"
    return f"name:{firewall_id if firewall_id is not None else '*'}:{_lower(name)}"[:320]


def _site_firewalls(db: DBSession) -> list[Firewall]:
    return db.query(Firewall).order_by(Firewall.id).all()


def _site_interfaces(db: DBSession) -> list[FirewallInterface]:
    return (db.query(FirewallInterface).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
            .order_by(FirewallInterface.firewall_id, FirewallInterface.name).all())


def interface_zones(db: DBSession) -> dict[tuple, list[str]]:
    """{(firewall_id, interface name lower): [FortiOS zone names]} of the site."""
    out: dict[tuple, list[str]] = {}
    q = db.query(FirewallZoneDef).join(Firewall, Firewall.id == FirewallZoneDef.firewall_id)
    for zd in q.all():
        for m in zd.members or []:
            out.setdefault((zd.firewall_id, _lower(m)), []).append(zd.name)
    return out


# ------------------------------------------------------------------ context --
class MgmtContext:
    """The site's management / engineering sources and name classifications
    (one build per use; cheap - a handful of small queries)."""

    def __init__(self):
        self.nets: list[tuple] = []          # (network, description, purpose)
        self.host_ips: dict[str, tuple] = {} # ip -> (description, purpose) (hosts on declared VLANs)
        self.vlan_ids: dict[int, tuple] = {} # vlan id -> (label, purpose)
        self.names: dict[tuple, object] = {} # (fw_id | None, name lower) -> purpose | False
        self.declarations = 0
        self.declared_sources = False        # a MANAGEMENT subnet / host / vlan is declared
        self.cell_zones: list = []           # (kind, cidr | vlan id) declared cell/area zones
        self.jump_nets: list = []            # networks / hosts declared as jump hosts (MV-10)
        self.ntp_hosts: set[str] = set()     # declared site NTP servers (SF)
        self._specs: dict[tuple, object] = {}

    # ---- sources
    @staticmethod
    def _allowed(ot: bool, purposes=None) -> tuple:
        if purposes is not None:
            return tuple(purposes)
        return (PURPOSE_MGMT, PURPOSE_ENG) if ot else (PURPOSE_MGMT,)

    def _has(self, purposes) -> bool:
        return any(p in purposes for _n, _d, p in self.nets) or \
            any(p in purposes for _d, p in self.host_ips.values())

    @property
    def has_sources(self) -> bool:
        """Any source at all (either purpose)."""
        return bool(self.nets or self.host_ips)

    @property
    def has_mgmt_sources(self) -> bool:
        return self._has((PURPOSE_MGMT,))

    @property
    def has_eng_sources(self) -> bool:
        return self._has((PURPOSE_ENG,))

    def _spec(self, purposes: tuple):
        key = tuple(sorted(purposes))
        if key not in self._specs:
            nets = [str(n) for n, _d, p in self.nets if p in purposes]
            self._specs[key] = rm.parse_address(",".join(nets)) if nets else None
        return self._specs[key]

    def source_of(self, ip, ot: bool = False, purposes=None) -> Optional[str]:
        """Why ``ip`` is an approved source, or None.  ``ot``: the access is
        toward OT equipment (L0-L2), so engineering sources count too."""
        allowed = self._allowed(ot, purposes)
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        hit = self.host_ips.get(str(addr))
        if hit is not None and hit[1] in allowed:
            return hit[0]
        for net, desc, p in self.nets:
            if p in allowed and addr.version == net.version and addr in net:
                return desc
        return None

    def is_jump_host(self, ip, host=None) -> bool:
        """MV-10: ``ip`` is a declared jump host (baseline role jump_host, a
        trusted host of that role, or a host classified jump_host)."""
        if host is not None and (getattr(host, "device_type", None) or "") == "jump_host":
            return True
        try:
            addr = ipaddress.ip_address(str(ip or "").strip())
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.jump_nets)

    def is_admin_ip(self, ip, ot: bool = False) -> bool:
        return self.source_of(ip, ot=ot) is not None

    def is_ntp_server(self, ip) -> bool:
        try:
            return str(ipaddress.ip_address(str(ip or "").strip())) in self.ntp_hosts
        except ValueError:
            return False

    def is_ntp_flow(self, a_ip, a_port, b_ip, b_port) -> bool:
        """SF: a time-sync exchange with a declared site NTP server (the
        server side on NTP_PORT) - exempt from the level checks."""
        if not self.ntp_hosts:
            return False
        return ((b_port == NTP_PORT and self.is_ntp_server(b_ip))
                or (a_port == NTP_PORT and self.is_ntp_server(a_ip)))

    def is_ntp_scope(self, scope, services) -> bool:
        """SF: a rule / path row whose destination lies entirely on declared
        NTP servers and whose services are NTP only."""
        if not self.ntp_hosts:
            return False
        svcs = [str(x).strip().lower() for x in (services if isinstance(services, (list, tuple, set))
                                                  else re.split(r"[,\s]+", str(services or "")))]
        svcs = [x for x in svcs if x]
        if not svcs or not all(x in ("tcp/123", "udp/123", "123", "ntp") for x in svcs):
            return False
        text = ",".join(str(s) for s in scope) if isinstance(scope, (list, tuple, set)) else str(scope or "")
        tokens = [t.strip() for t in re.split(r"[,\s]+", text) if t.strip()]
        if not tokens:
            return False
        for t in tokens:
            ip = t.split("/")[0]
            if ip not in self.ntp_hosts or ("/" in t and not t.endswith(("/32", "/128"))):
                return False
        return True

    def is_engineering_ip(self, ip) -> bool:
        return self.source_of(ip, purposes=(PURPOSE_ENG,)) is not None

    def scope_is_mgmt(self, scope, ot: bool = False, purposes=None) -> bool:
        """True when a rule / path address text lies ENTIRELY inside the
        allowed networks and trusted hosts ("any" and unresolved never)."""
        allowed = self._allowed(ot, purposes)
        hosts = {ip for ip, (_d, p) in self.host_ips.items() if p in allowed}
        spec = self._spec(allowed)
        if spec is None and not hosts:
            return False
        text = ",".join(str(s) for s in scope) if isinstance(scope, (list, tuple, set)) else str(scope or "")
        tokens = [t.strip() for t in re.split(r"[,\s]+", text) if t.strip()]
        if not tokens:
            return False
        rest = []
        for t in tokens:
            if t.split("/")[0] in hosts and (("/" not in t) or t.endswith(("/32", "/128"))):
                continue
            rest.append(t)
        if not rest:
            return True
        if spec is None:
            return False
        try:
            want = rm.parse_address(",".join(rest), v6_default_is_any=False)
        except Exception:
            return False
        if want is None or want == rm.ANY or isinstance(want, rm.Unresolved):
            return False
        return rm.addr_contains(spec, want) is True

    # ---- names
    def name_purpose(self, firewall_id, *names):
        """Declared classification of any of ``names`` on ``firewall_id``:
        "management" / "engineering" / False (neither) / None (undeclared).
        A firewall-specific declaration beats a site-wide one; when names
        disagree, "neither" beats management beats engineering."""
        found = []
        for n in names:
            low = _lower(n)
            if not low:
                continue
            for key in ((firewall_id, low), (None, low)):
                if key in self.names:
                    found.append(self.names[key])
                    break
        if not found:
            return None
        if False in found:
            return False
        return PURPOSE_MGMT if PURPOSE_MGMT in found else PURPOSE_ENG

    def name_class(self, firewall_id, *names, ot: bool = False) -> Optional[bool]:
        """Is a declared name an approved source zone?  An engineering zone
        counts only toward OT equipment (``ot``)."""
        p = self.name_purpose(firewall_id, *names)
        if p is None or p is False:
            return p
        return p == PURPOSE_MGMT or ot

    def iface_class(self, iface: FirewallInterface, zones: Iterable[str] = (),
                    keywords: bool = True) -> tuple:
        """(is a MANAGEMENT zone, reason, declared purpose / False / None) of
        one interface - for firewall admin access, so an engineering zone is
        not a management zone."""
        names = [iface.name, iface.alias, *zones]
        p = self.name_purpose(iface.firewall_id, *names)
        if p is False:
            return False, "declared neither a management nor an engineering zone", False
        if p == PURPOSE_MGMT:
            return True, "declared a management zone", p
        if p == PURPOSE_ENG:
            return False, "declared an engineering zone (firewall admin belongs in a management zone)", p
        vid = _vlan_int(iface.vlan_id)
        if vid is not None and vid in self.vlan_ids:
            vp = self.vlan_ids[vid][1]
            if vp == PURPOSE_MGMT:
                return True, f"on management VLAN {vid}", vp
            return False, f"on engineering VLAN {vid} (firewall admin belongs in a management zone)", vp
        net = _net(iface.network_cidr)
        if net is not None:
            for mnet, desc, np_ in self.nets:
                if net.version == mnet.version and net.subnet_of(mnet):
                    if np_ == PURPOSE_MGMT:
                        return True, f"inside {desc}", np_
                    return False, f"inside {desc} (firewall admin belongs in a management zone)", np_
        if keywords:
            k = keyword_of(*names)
            if k:
                return True, f"name contains '{k}'", None
        return False, "", None


def _bound_site(db: DBSession) -> Optional[int]:
    """The analysis site, else the ingest site bound to ``db`` (None = unbound)."""
    from app.parsers.site_scope import current_site
    from app.sites import _INFO_KEY
    sid = current_site(db)
    return sid if sid is not None else db.info.get(_INFO_KEY)


def build_context(db: DBSession) -> MgmtContext:
    """The context of the site bound to ``db`` (analysis or ingest binding)."""
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, _bound_site(db)):
        return _build_context(db)


def _build_context(db: DBSession) -> MgmtContext:
    ctx = MgmtContext()
    rows = db.query(ManagementNetwork).order_by(ManagementNetwork.id).all()
    ctx.declarations = len(rows)
    for r in rows:
        if r.purpose == PURPOSE_CELL:
            ctx.cell_zones.append((r.kind, r.cidr or r.vlan_id))
            continue
        purpose = (ROLE_PURPOSE.get(r.role or "admin_ws", PURPOSE_MGMT) if r.kind == KIND_HOST
                   else (r.purpose or PURPOSE_MGMT))
        if r.kind in (KIND_SUBNET, KIND_HOST, KIND_VLAN) and purpose == PURPOSE_MGMT:
            ctx.declared_sources = True
        if r.kind == KIND_SUBNET:
            n = _net(r.cidr)
            if n is not None:
                ctx.nets.append((n, f"{purpose_word(purpose)} network {n}"
                                 + (f" ({r.label})" if r.label else ""), purpose))
        elif r.kind == KIND_HOST and r.role == "ntp_server":
            n = _net(r.cidr)
            if n is not None:
                ctx.ntp_hosts.add(str(n.network_address))
        elif r.kind == KIND_HOST:
            n = _net(r.cidr)
            if n is not None:
                ctx.nets.append((n, f"trusted {ROLE_LABEL.get(r.role or 'admin_ws', 'host')} {n}", purpose))
                if r.role == "jump_host":
                    ctx.jump_nets.append(n)
        elif r.kind == KIND_VLAN and r.vlan_id is not None:
            ctx.vlan_ids[int(r.vlan_id)] = (r.label or "", purpose)
        elif r.kind == KIND_NAME and r.name:
            ctx.names[(r.firewall_id, _lower(r.name))] = purpose if r.is_management else False
    # declared VLANs -> subnets of the firewall VLAN interfaces + their hosts
    if ctx.vlan_ids:
        vids = {str(v): p for v, (_l, p) in ctx.vlan_ids.items()}
        for i in _site_interfaces(db):
            vp = vids.get(str(i.vlan_id or "").strip())
            if vp and _net(i.network_cidr) is not None:
                ctx.nets.append((_net(i.network_cidr),
                                 f"{purpose_word(vp)} VLAN {int(i.vlan_id)} subnet {_net(i.network_cidr)}", vp))
        for z in db.query(FirewallZone).filter(FirewallZone.vlan_id.in_(list(vids))).all():
            n = _net(z.ip_cidr)
            if n is not None and n.prefixlen < n.max_prefixlen:
                vp = vids[str(z.vlan_id).strip()]
                ctx.nets.append((n, f"{purpose_word(vp)} VLAN {int(z.vlan_id)} subnet {n}", vp))
        for h in db.query(Host).filter(Host.vlan.in_(list(vids)), Host.ip.isnot(None)).all():
            vp = vids[str(h.vlan).strip()]
            ctx.host_ips.setdefault(str(h.ip).strip(),
                                    (f"host on {purpose_word(vp)} VLAN {int(h.vlan)}", vp))
    # interfaces DECLARED management / engineering zones by name -> their subnets
    if any(v for v in ctx.names.values()):
        zones = interface_zones(db)
        for i in _site_interfaces(db):
            z = zones.get((i.firewall_id, _lower(i.name)), [])
            p = ctx.name_purpose(i.firewall_id, i.name, i.alias, *z)
            n = _net(i.network_cidr)
            if p and n is not None and n.prefixlen < n.max_prefixlen:
                ctx.nets.append((n, f"{purpose_word(p)} zone {i.name} ({n})", p))
    # active baseline: admin_ws / jump_host (management), engineering_ws (engineering)
    bl = (db.query(Baseline).filter(Baseline.is_active == True)  # noqa: E712
          .order_by(Baseline.created_at.desc()).first())
    if bl is not None:
        for h in db.query(ApprovedHost).filter(ApprovedHost.baseline_id == bl.id,
                                               ApprovedHost.role.in_(list(MANAGEMENT_HOST_ROLES)),
                                               ApprovedHost.ip.isnot(None)).all():
            n = _net(h.ip)
            if n is None:
                continue
            if h.role == "ntp_server":
                ctx.ntp_hosts.add(str(n.network_address))
                continue
            if True:
                ctx.nets.append((n, f"baseline {h.role} {h.ip}", ROLE_PURPOSE[h.role]))
                if h.role == "jump_host":
                    ctx.jump_nets.append(n)
    # de-duplicate per purpose, keep the first description
    seen, nets = set(), []
    for n, d, p in ctx.nets:
        if (n, p) not in seen:
            seen.add((n, p))
            nets.append((n, d, p))
    ctx.nets = nets
    return ctx


# ------------------------------------------------------------ declarations --
def declare(db: DBSession, site_id: int, *, kind: str, cidr=None, role=None, vlan_id=None,
            firewall_id=None, name=None, is_management: bool = True, purpose=None, label=None,
            note=None, created_by=None, finding_id=None) -> tuple[ManagementNetwork, bool]:
    """Add a declaration (``kind`` subnet / host / vlan / name, ``purpose``
    management (default) / engineering; a host's purpose follows its role).
    Returns (row, created).  Re-declaring the same thing with another
    purpose / role / classification updates it (a ``name`` is always an
    upsert); the identical declaration again is 409."""
    kind = _lower(kind)
    if kind not in MANAGEMENT_NETWORK_KINDS:
        raise MgmtError(f"kind must be one of {', '.join(MANAGEMENT_NETWORK_KINDS)}")
    purpose = _lower(purpose) or PURPOSE_MGMT
    if purpose == PURPOSE_CELL and kind not in (KIND_SUBNET, KIND_VLAN):
        raise MgmtError("a cell/area zone is declared on a network or a VLAN")
    if purpose == PURPOSE_SERVICE and kind != KIND_HOST:
        raise MgmtError("a service (NTP server) is declared on a host")
    if purpose not in MANAGEMENT_PURPOSES + (PURPOSE_CELL, PURPOSE_SERVICE):
        raise MgmtError(f"purpose must be one of {', '.join(MANAGEMENT_PURPOSES + (PURPOSE_CELL, PURPOSE_SERVICE))}")
    fields = {"cidr": None, "role": None, "vlan_id": None, "firewall_id": None, "name": None,
              "is_management": True, "purpose": purpose}
    if kind in (KIND_SUBNET, KIND_HOST):
        n = _net(cidr)
        if n is None:
            raise MgmtError(f"'{cidr}' is not an IP address or CIDR")
        if kind == KIND_SUBNET and n.prefixlen < _MIN_SUBNET_PREFIX[n.version]:
            raise MgmtError(f"{n} is too broad for a {purpose} network "
                            f"(narrowest allowed: /{_MIN_SUBNET_PREFIX[n.version]})")
        if kind == KIND_HOST:
            if n.prefixlen < _MIN_HOST_PREFIX[n.version]:
                raise MgmtError(f"{n} is a network, not a host - declare it as a subnet")
            role = _lower(role) or {PURPOSE_ENG: "engineering_ws", PURPOSE_SERVICE: "ntp_server"}.get(purpose, "admin_ws")
            if role not in MANAGEMENT_HOST_ROLES:
                raise MgmtError(f"role must be one of {', '.join(MANAGEMENT_HOST_ROLES)}")
            fields["role"] = role
            fields["purpose"] = ROLE_PURPOSE[role]
        fields["cidr"] = str(n)
    elif kind == KIND_VLAN:
        v = _vlan_int(vlan_id)
        if v is None:
            raise MgmtError("vlan_id must be 1-4094")
        fields["vlan_id"] = v
    else:
        nm = str(name or "").strip()
        if not nm or len(nm) > 128:
            raise MgmtError("name (interface / zone / alias, 1-128 characters) is required")
        if firewall_id is not None:
            fw = db.query(Firewall).filter(Firewall.id == int(firewall_id)).first()
            if fw is None:
                raise MgmtError(f"firewall {firewall_id} not found in this site", 404)
            fields["firewall_id"] = fw.id
        fields["name"] = nm
        fields["is_management"] = bool(is_management)
    key = make_key(kind, fields["cidr"], fields["vlan_id"], fields["firewall_id"], fields["name"], fields["role"])
    existing = db.query(ManagementNetwork).filter(ManagementNetwork.key == key).first()
    if existing is not None:
        same = (existing.purpose == fields["purpose"] and existing.role == fields["role"]
                and bool(existing.is_management) == fields["is_management"])
        if same and kind != KIND_NAME:
            raise MgmtError(f"{key} is already declared (#{existing.id})", 409)
        existing.is_management = fields["is_management"]
        existing.purpose = fields["purpose"]
        existing.role = fields["role"]
        for col, val, n in (("note", note, 2000), ("label", label, 128), ("created_by", created_by, 128)):
            if val:
                setattr(existing, col, str(val)[:n])
        if finding_id:
            existing.finding_id = int(finding_id)
        db.flush()
        return existing, False
    row = ManagementNetwork(site_id=site_id, kind=kind, key=key, label=(str(label)[:128] if label else None),
                            note=(str(note)[:2000] if note else None),
                            created_by=(str(created_by)[:128] if created_by else None),
                            finding_id=(int(finding_id) if finding_id else None), **fields)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        raise MgmtError(f"{key} is already declared", 409)
    log.info("Management declaration added: %s (%s)", key, fields["purpose"])
    return row, True


def delete(db: DBSession, decl_id: int) -> ManagementNetwork:
    row = db.query(ManagementNetwork).filter(ManagementNetwork.id == int(decl_id)).first()
    if row is None:
        raise MgmtError(f"management declaration {decl_id} not found", 404)
    db.delete(row)
    db.flush()
    return row


def declaration_dict(db: DBSession, r: ManagementNetwork, ctx: Optional[MgmtContext] = None,
                     _ifaces=None, _zones=None) -> dict:
    d = {"id": r.id, "kind": r.kind, "key": r.key, "cidr": r.cidr, "role": r.role,
         "purpose": r.purpose or PURPOSE_MGMT,
         "vlan_id": r.vlan_id, "firewall_id": r.firewall_id, "name": r.name,
         "is_management": bool(r.is_management), "label": r.label, "note": r.note,
         "finding_id": r.finding_id, "created_by": r.created_by,
         "created_at": r.created_at.isoformat() if r.created_at else None}
    if r.kind == KIND_NAME:
        fw = db.get(Firewall, r.firewall_id) if r.firewall_id is not None else None
        d["firewall_name"] = fw.name if fw is not None else None
        ifaces = _ifaces if _ifaces is not None else _site_interfaces(db)
        zones = _zones if _zones is not None else interface_zones(db)
        low = _lower(r.name)
        d["matches"] = [
            {"firewall_id": i.firewall_id, "interface": i.name, "network": i.network_cidr}
            for i in ifaces
            if (r.firewall_id is None or i.firewall_id == r.firewall_id)
            and low in {_lower(x) for x in [i.name, i.alias, *zones.get((i.firewall_id, _lower(i.name)), [])]}]
    elif r.kind == KIND_VLAN:
        ifaces = _ifaces if _ifaces is not None else _site_interfaces(db)
        d["subnets"] = sorted({i.network_cidr for i in ifaces
                               if _vlan_int(i.vlan_id) == r.vlan_id and i.network_cidr})
        d["names"] = sorted({v.vlan_name for v in db.query(SwitchVlan).filter(
            SwitchVlan.vlan_id == r.vlan_id) if v.vlan_name})
        d["hosts"] = db.query(Host).filter(Host.vlan == str(r.vlan_id)).count()
    return d


def list_declarations(db: DBSession) -> list[dict]:
    ifaces, zones = _site_interfaces(db), interface_zones(db)
    return [declaration_dict(db, r, _ifaces=ifaces, _zones=zones)
            for r in db.query(ManagementNetwork).order_by(ManagementNetwork.kind, ManagementNetwork.id)]


# ----------------------------------------------------- inventory / suggest --
def interface_inventory(db: DBSession, ctx: Optional[MgmtContext] = None) -> list[dict]:
    """Every firewall interface of the site with its classification:
    ``is_management`` (a management zone, for firewall admin access),
    ``purpose`` (management / engineering / None) and ``declared``."""
    ctx = ctx or build_context(db)
    zones = interface_zones(db)
    fws = {f.id: f for f in _site_firewalls(db)}
    out = []
    for i in _site_interfaces(db):
        z = zones.get((i.firewall_id, _lower(i.name)), [])
        is_m, reason, declared = ctx.iface_class(i, z)
        acc = sorted(access_set(i.allowaccess))
        fw = fws.get(i.firewall_id)
        purpose = declared if declared in MANAGEMENT_PURPOSES else (PURPOSE_MGMT if is_m else None)
        out.append({
            "interface_id": i.id, "firewall_id": i.firewall_id,
            "firewall": fw.name if fw else None, "name": i.name, "alias": i.alias,
            "zones": z, "network": i.network_cidr, "vlan_id": i.vlan_id,
            "allowaccess": acc, "management_access": bool(set(acc) & _MGMT_ACCESS),
            "purdue_level": i.purdue_level, "is_mgmt_only": bool(i.is_mgmt_only),
            "is_management": is_m, "purpose": purpose, "reason": reason, "declared": declared,
            # admin state from the config (owner 2026-10-12: greyed / hidden like the
            # FW Topology Builder); absent = up
            "status": i.status,
            "enabled": (i.status or "").strip().lower() not in ("down", "disable", "disabled"),
        })
    return out


def vlan_inventory(db: DBSession, ctx: Optional[MgmtContext] = None) -> list[dict]:
    """Every VLAN id the site knows (switch tables, firewall VLAN interfaces),
    with its declared purpose (management / engineering / None)."""
    ctx = ctx or build_context(db)
    by: dict[int, dict] = {}

    def slot(v):
        return by.setdefault(v, {"vlan_id": v, "names": set(), "switches": set(), "subnets": set(),
                                 "purdue_level": None, "hosts": 0})
    for sv in db.query(SwitchVlan).all():
        s = slot(sv.vlan_id)
        if sv.vlan_name:
            s["names"].add(sv.vlan_name)
        if sv.device_name:
            s["switches"].add(sv.device_name)
        if sv.purdue_level is not None and s["purdue_level"] is None:
            s["purdue_level"] = sv.purdue_level
    for i in _site_interfaces(db):
        v = _vlan_int(i.vlan_id)
        if v is not None:
            s = slot(v)
            if i.network_cidr:
                s["subnets"].add(i.network_cidr)
            if i.alias:
                s["names"].add(i.alias)
    for vl, n in _host_vlan_counts(db).items():
        if vl in by:
            by[vl]["hosts"] = n
    cells = {int(x) for k, x in ctx.cell_zones if k == KIND_VLAN and x is not None}
    out = []
    for v in sorted(by):
        s = by[v]
        purpose = ctx.vlan_ids[v][1] if v in ctx.vlan_ids else (PURPOSE_CELL if v in cells else None)
        sug = None if purpose else _suggest(*s["names"])
        out.append({"vlan_id": v, "names": sorted(s["names"]), "switches": sorted(s["switches"]),
                    "subnets": sorted(s["subnets"]), "purdue_level": s["purdue_level"],
                    "hosts": s["hosts"], "purpose": purpose,
                    "is_management": purpose == PURPOSE_MGMT,
                    "is_engineering": purpose == PURPOSE_ENG,
                    "is_cell_zone": purpose == PURPOSE_CELL,
                    "suggested": sug is not None,
                    "suggested_purpose": sug[0] if sug else None})
    return out


def _host_vlan_counts(db: DBSession) -> dict[int, int]:
    from sqlalchemy import func
    out = {}
    for vl, n in db.query(Host.vlan, func.count(Host.id)).filter(Host.vlan.isnot(None)).group_by(Host.vlan):
        v = _vlan_int(vl)
        if v is not None:
            out[v] = out.get(v, 0) + n
    return out


def suggestions(db: DBSession, ctx: Optional[MgmtContext] = None) -> list[dict]:
    """Name-keyword candidates the operator has not decided on yet: firewall
    interfaces / zones and VLANs whose names say management (mgmt, admin,
    OOB ...) or engineering (engineering, EWS)."""
    ctx = ctx or build_context(db)
    out, seen = [], set()
    for row in interface_inventory(db, ctx):
        if row["declared"] is not None:
            continue
        sug = _suggest(row["name"], row["alias"], *row["zones"])
        if not sug:
            continue
        purpose, k = sug
        # suggest the FortiOS zone when the keyword is in the zone name
        target = next((z for z in row["zones"] if _suggest(z)), None) or row["name"]
        key = (row["firewall_id"], _lower(target))
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": KIND_NAME, "firewall_id": row["firewall_id"], "firewall": row["firewall"],
                    "name": target, "is_management": True, "purpose": purpose,
                    "network": row["network"], "reason": f"name contains '{k}'"})
    for v in vlan_inventory(db, ctx):
        if v["suggested"]:
            sug = _suggest(*v["names"])
            out.append({"kind": KIND_VLAN, "vlan_id": v["vlan_id"], "names": v["names"],
                        "subnets": v["subnets"], "purpose": v["suggested_purpose"],
                        "reason": f"VLAN name contains '{sug[1]}'"})
    return out


# ------------------------------------------------------------ fix options --
def _eng_hint(db: DBSession, ip) -> bool:
    """``ip`` is a known engineering workstation (classified as one, or an
    engineering_ws in the active baseline)."""
    if not ip:
        return False
    h = db.query(Host).filter(Host.ip == str(ip)).first()
    if h is not None and ("engineering" in _lower(h.device_type) or _lower(h.role) == "engineering_ws"):
        return True
    return db.query(ApprovedHost).join(Baseline, Baseline.id == ApprovedHost.baseline_id).filter(
        Baseline.is_active == True, ApprovedHost.ip == str(ip),  # noqa: E712
        ApprovedHost.role == "engineering_ws").first() is not None


def _host_opt(cidr, role, recommended=False) -> dict:
    o = {"kind": KIND_HOST, "cidr": cidr, "role": role,
         "label": f"Add {cidr.split('/')[0] if cidr.endswith(('/32', '/128')) else cidr} as a trusted "
                  f"{ROLE_LABEL[role]}"}
    if recommended:
        o["recommended"] = True
    return o


def _roles_for(ot: bool, dmz: bool, eng: bool, write: bool = False) -> list[str]:
    """Host roles to offer, best first."""
    if write:
        return ["engineering_ws"]
    if not ot:
        return ["jump_host", "admin_ws"] if dmz else ["admin_ws", "jump_host"]
    if dmz:
        return ["jump_host", "engineering_ws", "admin_ws"]
    return ["engineering_ws", "admin_ws", "jump_host"] if eng or ot else ["admin_ws", "engineering_ws"]


def _src_options(db: DBSession, ip: str, ctx: MgmtContext, dmz: bool = False, ot: bool = False,
                 write: bool = False) -> list[dict]:
    opts = []
    if not ip:
        return opts
    if (write and ctx.is_engineering_ip(ip)) or (not write and ctx.is_admin_ip(ip, ot=ot)):
        return opts
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return opts
    host = f"{addr}/{addr.max_prefixlen}"
    roles = _roles_for(ot, dmz, _eng_hint(db, addr), write)
    opts += [_host_opt(host, r, recommended=(i == 0)) for i, r in enumerate(roles)]
    purposes = [PURPOSE_ENG] if write else ([PURPOSE_ENG, PURPOSE_MGMT] if ot and roles[0] == "engineering_ws"
                                            else [PURPOSE_MGMT, PURPOSE_ENG] if ot else [PURPOSE_MGMT])
    nets = set()
    for i in _site_interfaces(db):
        n = _net(i.network_cidr)
        if n is not None and n.version == addr.version and addr in n and n.prefixlen < n.max_prefixlen:
            nets.add(n)
    for n in sorted(nets, key=lambda x: -x.prefixlen)[:1]:
        for p in purposes:
            opts.append({"kind": KIND_SUBNET, "cidr": str(n), "purpose": p,
                         "label": f"Declare {n} (the network {addr} is on) an {p} network"
                                  if p == PURPOSE_ENG else
                                  f"Declare {n} (the network {addr} is on) a {p} network"})
    h = db.query(Host).filter(Host.ip == str(addr)).first()
    v = _vlan_int(h.vlan) if h is not None else None
    if v is not None and v not in ctx.vlan_ids:
        for p in purposes:
            opts.append({"kind": KIND_VLAN, "vlan_id": v, "purpose": p,
                         "label": f"Mark VLAN {v} ({addr}'s VLAN) as {'an' if p == PURPOSE_ENG else 'a'} {p} VLAN"})
    return opts


def _scope_options(scope, ctx: MgmtContext, ot: bool = False, purposes=None) -> list[dict]:
    opts = []
    purposes = purposes or ([PURPOSE_ENG, PURPOSE_MGMT] if ot else [PURPOSE_MGMT])
    for t in [t.strip() for t in re.split(r"[,\s]+", str(scope or "")) if t.strip()]:
        n = _net(t)
        if n is None or n.prefixlen == 0 or ctx.scope_is_mgmt(str(n), ot=ot):
            continue
        for p in purposes:
            if n.prefixlen >= _MIN_HOST_PREFIX[n.version]:
                opts.append(_host_opt(str(n), "engineering_ws" if p == PURPOSE_ENG else "admin_ws"))
            if n.prefixlen >= _MIN_SUBNET_PREFIX[n.version] and n.prefixlen < n.max_prefixlen:
                opts.append({"kind": KIND_SUBNET, "cidr": str(n), "purpose": p,
                             "label": f"Declare source {n} {'an' if p == PURPOSE_ENG else 'a'} {p} network"})
    return opts[:6]


def _zone_options(db: DBSession, firewall_id, zone_text, ctx: MgmtContext, ot: bool = False) -> list[dict]:
    opts = []
    fw = db.get(Firewall, int(firewall_id)) if firewall_id else None
    purposes = [PURPOSE_ENG, PURPOSE_MGMT] if ot else [PURPOSE_MGMT]
    for z in [z.strip() for z in str(zone_text or "").split(",") if z.strip()]:
        if _lower(z) in ("any", "all") or ctx.name_class(firewall_id, z, ot=ot):
            continue
        for p in purposes:
            opts.append({"kind": KIND_NAME, "firewall_id": fw.id if fw else None, "name": z,
                         "is_management": True, "purpose": p,
                         "label": f"Reclassify zone/interface '{z}'" + (f" on {fw.name}" if fw else "")
                                  + f" as {'an' if p == PURPOSE_ENG else 'a'} {p} zone"})
    return opts


def _fw_of_ref(ref: str) -> Optional[int]:
    m = re.match(r"config:(\d+):", str(ref or ""))
    return int(m.group(1)) if m else None


def _first_recommended(opts: list[dict]) -> list[dict]:
    """Exactly one option is recommended (the first one marked, else the first)."""
    seen = False
    for o in opts:
        if o.get("recommended") and not seen:
            seen = True
        else:
            o.pop("recommended", None)
    if opts and not seen:
        opts[0]["recommended"] = True
    return opts


def _ntp_options(d: dict, ctx: MgmtContext) -> list[dict]:
    """SF: when the finding is time sync (port 123) to one host, offer to
    declare that host the site NTP server."""
    port = d.get("dst_port")
    server = None
    if port == NTP_PORT and d.get("dst_ip"):
        server = d["dst_ip"]
        if d.get("initiator") and d.get("initiator") == d.get("dst_ip") and d.get("src_ip"):
            server = d["src_ip"]
    elif d.get("it_host_ip") and port == NTP_PORT:
        server = d["it_host_ip"]
    else:
        svcs = d.get("service") or d.get("services") or (d.get("path") or {}).get("service")
        svcs = [svcs] if isinstance(svcs, str) else list(svcs or [])
        scope = ((d.get("path") or {}).get("dst") or {}).get("scope") or d.get("dst")
        if svcs and all(str(x).lower() in ("tcp/123", "udp/123", "123", "ntp") for x in svcs) \
                and isinstance(scope, str) and "/" not in scope.replace("/32", "").replace("/128", ""):
            server = scope.replace("/32", "").replace("/128", "")
    if not server or _net(server) is None or ctx.is_ntp_server(server):
        return []
    return [{"kind": KIND_HOST, "cidr": server, "role": "ntp_server", "recommended": True,
             "label": f"Declare {server} the site NTP server (time sync to it is allowed from every level)"}]


def fix_options(db: DBSession, finding: Finding) -> dict:
    """What a declaration could do about ``finding``: [{kind, ..., label,
    recommended?}] ready to POST to /management/networks.  Toward OT
    equipment (and for a known engineering workstation) the engineering
    option comes first; firewall admin findings only offer management."""
    ctx = build_context(db)
    d = finding.detail if isinstance(finding.detail, dict) else {}
    check = finding.check_name or ""
    opts: list[dict] = []
    if check == "mgmt_access_from_wrong_zone":
        opts += _src_options(db, d.get("src_ip"), ctx, dmz=bool(d.get("dmz_source")), ot=True)
    elif check == "session_mgmt_from_non_admin":
        ot = _is_ot(d.get("dst_purdue_level"))
        if not ot and d.get("dst_ip"):
            h = db.query(Host).filter(Host.ip == d.get("dst_ip")).first()
            ot = h is not None and _is_ot(h.purdue_level)
        opts += _src_options(db, d.get("src_ip"), ctx, ot=ot)
    elif check == "auth_from_non_admin_host":
        opts += _src_options(db, d.get("src_ip"), ctx, ot=False)
    elif check in WRITE_CHECKS:
        opts += _src_options(db, d.get("src_ip"), ctx, write=True)
    elif check == "mgmt_access_not_restricted":
        dst = d.get("dst_ip")
        if dst:
            h = db.query(Host).filter(Host.ip == dst).first()
            srcs = set()
            if h is not None:
                for s in (db.query(Host.ip).join(NetworkSession, NetworkSession.src_host_id == Host.id)
                          .filter(NetworkSession.dst_host_id == h.id,
                                  NetworkSession.dst_port.in_([22, 23, 443, 3389, 80, 8080, 8443]))
                          .distinct().limit(8)):
                    if s[0] and not ctx.is_admin_ip(s[0], ot=True):
                        srcs.add(s[0])
            for ip in sorted(srcs):
                opts += [o for o in _src_options(db, ip, ctx, ot=True) if o["kind"] == KIND_HOST][:1]
    elif check == "rule_mgmt_wrong_zone":
        opts += _zone_options(db, d.get("firewall_id"), d.get("src_zone"), ctx, ot=True)
        opts += _scope_options(d.get("src"), ctx, ot=True)
    elif check == "chain_mgmt_wrong_zone":
        path = d.get("path") or {}
        src = path.get("src") or {}
        chain = d.get("chain") or []
        fw_id = chain[0].get("firewall_id") if chain else None
        opts += _zone_options(db, fw_id, src.get("zone"), ctx, ot=True)
        opts += _scope_options(src.get("scope"), ctx, ot=True)
    elif check == CHECK_CFG_ZONE:
        fw_id = _fw_of_ref(finding.source_ref) or d.get("firewall_id")
        iface = d.get("interface")
        fw = db.get(Firewall, fw_id) if fw_id else None
        if iface and fw is not None:
            row = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id,
                                                     FirewallInterface.name == iface).first()
            net = row.network_cidr if row is not None else None
            opts.append({"kind": KIND_NAME, "firewall_id": fw.id, "name": iface, "is_management": True,
                         "purpose": PURPOSE_MGMT, "recommended": True,
                         "label": f"Reclassify interface '{iface}' on {fw.name} as a management zone"
                                  + (f" (its subnet {net} becomes a management network)" if net else "")})
            zones = interface_zones(db).get((fw.id, _lower(iface)), [])
            for z in zones:
                opts.append({"kind": KIND_NAME, "firewall_id": fw.id, "name": z, "is_management": True,
                             "purpose": PURPOSE_MGMT,
                             "label": f"Reclassify FortiOS zone '{z}' on {fw.name} as a management zone"})
            v = _vlan_int(row.vlan_id) if row is not None else None
            if v is not None and (v not in ctx.vlan_ids or ctx.vlan_ids[v][1] != PURPOSE_MGMT):
                opts.append({"kind": KIND_VLAN, "vlan_id": v, "purpose": PURPOSE_MGMT,
                             "label": f"Mark VLAN {v} (interface '{iface}') as a management VLAN"})
    elif check == CHECK_TRUSTHOST:
        opts += _scope_options(d.get("trusthost"), ctx, ot=False)
    elif check in NTP_CHECKS:
        opts += _ntp_options(d, ctx)
    elif check == "flat_control_segment":
        if d.get("network"):
            opts.append({"kind": KIND_SUBNET, "cidr": d["network"], "purpose": PURPOSE_CELL,
                         "recommended": True,
                         "label": f"Declare {d['network']} a combined L1/L2 cell/area zone (documented design)"})
        for v in d.get("vlans") or []:
            if _vlan_int(v) is not None:
                opts.append({"kind": KIND_VLAN, "vlan_id": _vlan_int(v), "purpose": PURPOSE_CELL,
                             "label": f"Declare VLAN {v} a combined L1/L2 cell/area zone (documented design)"})
    _first_recommended(opts)
    return {"finding_id": finding.id, "check_name": check, "options": opts,
            "applies": check in MGMT_CHECKS,
            "note": (None if opts else
                     "No management or engineering declaration applies to this finding."
                     if check in MGMT_CHECKS
                     else "This check is not affected by management / engineering declarations.")}


def apply_mgmt_only_overrides(db: DBSession, firewall_id: Optional[int] = None) -> int:
    """An interface declared NOT a management zone (neither, or an
    engineering zone) carries routed traffic: clear its ``is_mgmt_only`` flag
    (set by the name heuristic at ingest), so topology and access-path
    analysis stop hiding it.  Returns rows changed.  (Removing the
    declaration restores the heuristic at the next upload.)"""
    from app.parsers.site_scope import analysis_site
    fw = db.get(Firewall, int(firewall_id)) if firewall_id is not None else None
    with analysis_site(db, fw.site_id if fw is not None else None):
        return _apply_mgmt_only(db, firewall_id)


def _apply_mgmt_only(db: DBSession, firewall_id: Optional[int]) -> int:
    ctx = build_context(db)
    if not any(v is False or v == PURPOSE_ENG for v in ctx.names.values()):
        return 0
    zones = interface_zones(db)
    n = 0
    for i in _site_interfaces(db):
        if firewall_id is not None and i.firewall_id != firewall_id:
            continue
        z = zones.get((i.firewall_id, _lower(i.name)), [])
        p = ctx.name_purpose(i.firewall_id, i.name, i.alias, *z)
        if i.is_mgmt_only and (p is False or p == PURPOSE_ENG):
            i.is_mgmt_only = False
            n += 1
    if n:
        db.flush()
    return n


# ------------------------------------------------- config-check re-judging --
def _find_ref(db: DBSession, ref: str) -> Optional[Finding]:
    rows = db.query(Finding).filter(Finding.source_ref == ref).order_by(Finding.id.desc()).all()
    for f in rows:
        if f.status in ACTIVE_FINDING_STATUSES:
            return f
    for f in rows:
        if f.status == "closed" and (f.notes or "").startswith("Auto-resolved"):
            f.status, f.closed_at = "open", None
            f.acknowledged_by = f.acknowledged_at = None
            f.notes = None
            return f
    return rows[0] if rows else None


def _upsert(db: DBSession, fw: Firewall, ref: str, check: str, title: str, detail: dict,
            stats: dict, severity: Optional[str] = None) -> None:
    sr, cid, sev, cat = CHECK_TYPE_REFERENCE[check]
    sev = severity or sev
    now = datetime.now(timezone.utc)
    device = fw.device_name or fw.name
    f = _find_ref(db, ref)
    if f is not None:
        f.title, f.detail, f.severity, f.updated_at = title[:512], detail, sev, now
        return
    db.add(Finding(source_ref=ref, category=cat, check_name=check, severity=sev, status="open",
                   isa62443_sr=sr, checklist_id=cid, title=title[:512], detail=detail,
                   device_name=device, site_id=fw.site_id, created_at=now, updated_at=now))
    stats["created"] += 1


def _close_unproduced(db: DBSession, fw_id: int, check: str, produced: set, reason: str) -> int:
    now = datetime.now(timezone.utc)
    note = f"{_AUTO_NOTE}: {reason} ({now.strftime('%Y-%m-%dT%H:%M:%SZ')})"
    closed = 0
    for f in db.query(Finding).filter(Finding.check_name == check, Finding.status == "open",
                                      Finding.source_ref.like(f"config:{fw_id}:{check}%")):
        if f.source_ref in produced:
            continue
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "")[:_NOTES_MAX - len(note) - 3] + note
        closed += 1
    return closed


def review_config_firewall(db: DBSession, firewall_id: int,
                           ctx: Optional[MgmtContext] = None) -> set:
    """Re-judge one firewall's two management config checks from its stored
    interfaces and admin trusted hosts.  Returns the source_refs produced
    (so a config ingest keeps them out of its own auto-resolve).  Flushes.
    Runs in the firewall's site."""
    from app.parsers.site_scope import analysis_site
    fw = db.get(Firewall, int(firewall_id))
    if fw is None:
        return set()
    with analysis_site(db, fw.site_id):
        return _review_config_firewall(db, fw, ctx or build_context(db))


def _review_config_firewall(db: DBSession, fw: Firewall, ctx: MgmtContext) -> set:
    stats = {"created": 0}
    produced: set = set()
    zones = interface_zones(db)
    device = fw.device_name or fw.name
    # 5.1 management access restricted to a dedicated management zone
    for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id) \
            .order_by(FirewallInterface.name):
        acc = access_set(i.allowaccess)
        if not (acc & _MGMT_ACCESS) or _lower(i.iface_type) == "loopback":
            continue
        z = zones.get((fw.id, _lower(i.name)), [])
        is_m, reason, declared = ctx.iface_class(i, z)
        if is_m:
            continue
        ref = f"config:{fw.id}:{CHECK_CFG_ZONE}:{i.name}"
        produced.add(ref)
        # owner 2026-10-12 (option 2): an admin-down interface keeps the finding,
        # lowered to low - its allowaccess goes live the moment the port is enabled
        off = _lower(i.status) in ("down", "disable", "disabled")
        _upsert(db, fw, ref, CHECK_CFG_ZONE,
                f"Interface '{i.name}' has management access but is not in a management zone"
                + (" (interface disabled)" if off else ""),
                {"interface": i.name, "allowaccess": sorted(acc), "alias": i.alias,
                 "interface_disabled": off,
                 **({"severity_reason": "low: the interface is administratively down - its admin access "
                                        "becomes live when it is enabled; remove allowaccess from unused ports"}
                    if off else {}),
                 "zones": z, "network": i.network_cidr, "vlan_id": i.vlan_id,
                 "classification": reason or "not declared; name does not say management",
                 "device_name": device, "firewall_id": fw.id,
                 "fix": "Remove HTTPS/SSH admin access from this interface, or - if it IS the "
                        "management network - reclassify it (Findings > Fix, or the Mgmt & "
                        "Engineering page).",
                 "checklist_title": "Management access restricted to a dedicated management zone"},
                stats, severity="low" if off else None)
    _close_unproduced(db, fw.id, CHECK_CFG_ZONE, produced,
                      "interface is now classified as a management zone or no longer allows admin access")
    # 9.5 admin trusted hosts inside the declared management networks
    # Judged only once the operator has declared management sources (a subnet,
    # trusted host or VLAN): the baseline's individual admin hosts alone do
    # not describe the management networks.  Containment uses every source.
    th_produced: set = set()
    if ctx.declared_sources:
        for adm in fw.admin_trusthosts or []:
            for th in adm.get("trusted_hosts") or []:
                n = _net(th)
                if n is None or n.prefixlen == 0 or ctx.scope_is_mgmt(str(n)):
                    continue
                ref = f"config:{fw.id}:{CHECK_TRUSTHOST}:{adm.get('username')}:{n}"
                th_produced.add(ref)
                _upsert(db, fw, ref, CHECK_TRUSTHOST,
                        f"Admin '{adm.get('username')}' trusthost {n} is outside the declared "
                        f"management networks",
                        {"username": adm.get("username"), "accprofile": adm.get("accprofile"),
                         "trusthost": str(n), "device_name": device, "firewall_id": fw.id,
                         "management_networks": [str(x) for x, _d, p in ctx.nets
                                                 if p == PURPOSE_MGMT][:20],
                         "fix": "Narrow the trusthost to the management network, or declare the "
                                "trusthost range a management network / trusted host.",
                         "checklist_title": "Admin access only from dedicated admin workstations"},
                        stats)
    _close_unproduced(db, fw.id, CHECK_TRUSTHOST, th_produced,
                      "trusthost is inside a declared management network"
                      if ctx.declared_sources else "no management networks declared")
    db.flush()
    return produced | th_produced


def review_config_all(db: DBSession, ctx: Optional[MgmtContext] = None) -> int:
    ctx = ctx or build_context(db)
    n = 0
    for fw in _site_firewalls(db):
        n += len(_review_config_firewall(db, fw, ctx))
    return n


# ------------------------------------------------------------------ recheck --
def _open_counts(db: DBSession) -> dict[str, int]:
    from sqlalchemy import func
    rows = (db.query(Finding.check_name, func.count(Finding.id))
            .filter(Finding.check_name.in_(list(MGMT_CHECKS)), Finding.status == "open")
            .group_by(Finding.check_name).all())
    out = {c: 0 for c in MGMT_CHECKS}
    out.update({c: int(n) for c, n in rows})
    return out


def _close_realtime_admin(db: DBSession, ctx: MgmtContext) -> int:
    """Real-time findings are never auto-resolved by reviews: close the open
    auth_from_non_admin_host findings whose source is now a management source."""
    now = datetime.now(timezone.utc)
    closed = 0
    for f in db.query(Finding).filter(Finding.check_name == "auth_from_non_admin_host",
                                      Finding.status == "open"):
        d = f.detail if isinstance(f.detail, dict) else {}
        why = ctx.source_of(d.get("src_ip"))
        if why is None:
            continue
        note = f"{_AUTO_NOTE}: source is a {why} ({now.strftime('%Y-%m-%dT%H:%M:%SZ')})"
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "")[:_NOTES_MAX - len(note) - 3] + note
        closed += 1
    return closed


def _close_engineering_writes(db: DBSession, ctx: MgmtContext) -> int:
    """Industrial write findings (real time / per capture, never auto-resolved
    by reviews): close the open ones whose source is now approved - a
    declared engineering source, or the baseline's engineering_ws / hmi (a
    capture uploaded before the baseline was loaded is flagged fail-open)."""
    from app.parsers.traffic_findings import _get_approved_engineering_hosts, _host_is_approved
    nets, macs = _get_approved_engineering_hosts(db)   # baseline engineering_ws / hmi + declared
    now = datetime.now(timezone.utc)
    closed = 0
    for f in db.query(Finding).filter(Finding.check_name.in_(list(WRITE_CHECKS)),
                                      Finding.status == "open"):
        d = f.detail if isinstance(f.detail, dict) else {}
        why = ctx.source_of(d.get("src_ip"), purposes=(PURPOSE_ENG,))
        if why is None and _host_is_approved(d.get("src_ip"), nets, d.get("src_mac"), macs):
            why = "approved engineering workstation / HMI (baseline)"
        if why is None:
            continue
        note = f"{_AUTO_NOTE}: source is a {why} ({now.strftime('%Y-%m-%dT%H:%M:%SZ')})"
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "")[:_NOTES_MAX - len(note) - 3] + note
        closed += 1
    return closed


def recheck(db: DBSession, site_id: int) -> dict:
    """Re-run every management / engineering check of the site against the
    current declarations; closes what they no longer produce.  Commits.
    Returns {before, after, closed, opened, failed_reviews, context}."""
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, site_id):
        before = _open_counts(db)
        ctx = build_context(db)
        apply_mgmt_only_overrides(db)
        review_config_all(db, ctx)
        realtime_closed = _close_realtime_admin(db, ctx) + _close_engineering_writes(db, ctx)
        db.commit()
    stats = ae.run_periodic_reviews(db, site_id=site_id, only=MGMT_REVIEWS) or {}
    with analysis_site(db, site_id):
        after = _open_counts(db)
    skipped = ae.REVIEW_SKIPPED_STAT in stats
    return {
        "before": before, "after": after,
        "closed": sum(max(0, before[c] - after[c]) for c in MGMT_CHECKS),
        "opened": sum(max(0, after[c] - before[c]) for c in MGMT_CHECKS),
        "realtime_closed": realtime_closed,
        "failed_reviews": list(ae.failed_reviews(db)) if not skipped else [],
        "reviews_skipped": skipped,
        "context": {"management_networks": [str(n) for n, _d, p in ctx.nets if p == PURPOSE_MGMT],
                    "engineering_networks": [str(n) for n, _d, p in ctx.nets if p == PURPOSE_ENG],
                    "management_vlans": sorted(v for v, (_l, p) in ctx.vlan_ids.items() if p == PURPOSE_MGMT),
                    "engineering_vlans": sorted(v for v, (_l, p) in ctx.vlan_ids.items() if p == PURPOSE_ENG),
                    "vlan_hosts": len(ctx.host_ips)},
    }
