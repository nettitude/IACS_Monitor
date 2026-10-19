"""
SSL-VPN awareness (VPN tabletop H-02, H-03, H-04, H-11; ``vpn_direct_to_ot``).

FortiGate SSL-VPN users arrive on the tunnel interface ``ssl.root``
(``ssl.<vdom>``) with an address from the tunnel pool; the policies whose
source interface is the tunnel interface decide where they can go, and the
pool addresses are what the inside of the network (and the capture) sees.

``VpnContext`` collects, per site, from the stored firewall rules and
interfaces:

* the tunnel interfaces and the VPN pool address specs (the ``srcaddr`` of
  every tunnel-sourced rule - the pool, or the users' assigned addresses);
* the firewalls that run SSL-VPN (their interface addresses are the remote-
  access gateway: a session TO them is a VPN login, local-in traffic that no
  forwarding policy governs);
* every firewall interface address (local-in destinations; known
  infrastructure, never an unknown device).

Checks built on it:

``vpn_direct_to_ot`` (critical, SR 1.13 access via untrusted networks;
    SR 5.2 / SR 5.1; 62443-2-4 SP.07 for vendor users; rows 4.1, 2.1) - one
    finding per VPN policy chain AND user group whose users can open sessions
    straight to L0-L2 equipment (a chain without groups: one finding for "any
    remote-access user").  The group's category (it / vendor / other) comes from the
    operator's classification (``VpnUserGroup``, Mgmt & Engineering page),
    else it is guessed from the name and the finding says so.  VPN-sourced rows and
    policies raise only this finding: the chain reviews skip VPN rows and (MP-23)
    the rule twins skip VPN-sourced policies (``VpnContext.is_vpn_rule``).
``config_vpn_direct_to_ot`` re-judged (H-02) - a VPN policy's destination
    interface carries an operator-set Purdue level: L3.5 = terminates in the
    DMZ (the "unclear" finding closes); any other level = does not.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

CHECK_VPN_OT = "vpn_direct_to_ot"
CHECK_CFG_VPN_OT = "config_vpn_direct_to_ot"
CHECK_CFG_VPN_UNCLEAR = "config_vpn_destination_unclear"
_AUTO_NOTE = "Auto-resolved: VPN destination judged from interface levels"
CATEGORIES = ("it", "vendor", "other")
CATEGORY_LABEL = {"it": "IT / own staff", "vendor": "vendor / third party", "other": "other"}
_VENDOR_WORDS = ("vendor", "3rd", "third", "contractor", "supplier", "integrator", "partner")
_IT_WORDS = ("staff", "employee", "corp", "internal", "helpdesk")
_IT_NAME = re.compile(r"^(it|ot|is)([^a-z]|vpn|$)")


class VpnGroupError(ValueError):
    def __init__(self, msg, status=422):
        super().__init__(msg)
        self.status = status


def guess_category(name: str):
    n = str(name or "").lower()
    if any(w in n for w in _VENDOR_WORDS):
        return "vendor"
    if _IT_NAME.match(n) or any(w in n for w in _IT_WORDS):
        return "it"
    return None


def group_key(firewall_id, name) -> str:
    return f"{firewall_id or '*'}:{str(name or '').strip().lower()}"[:160]


def declarations(db: DBSession) -> dict:
    """{key: VpnUserGroup} for the bound site."""
    from app.models import VpnUserGroup
    return {r.key: r for r in db.query(VpnUserGroup)}


def category_of(decls: dict, firewall_id, name) -> tuple:
    """(category or None, how) - how: declared (this firewall), declared
    (site-wide), guessed from the name, or unknown."""
    r = decls.get(group_key(firewall_id, name)) if firewall_id else None
    if r is not None:
        return r.category, "declared"
    r = decls.get(group_key(None, name))
    if r is not None:
        return r.category, "declared (every firewall)"
    g = guess_category(name)
    return (g, "guessed from the name") if g else (None, "unclassified")
_NOTES_MAX = 2048


def is_tunnel_name(name) -> bool:
    n = str(name or "").strip().lower()
    return n == "ssl" or n.startswith("ssl.")


def remote_tunnels(db) -> dict:
    """DR-03: {firewall id: {lower-case interface names}} of the remote-access
    tunnels of the bound site - SSL-VPN (ssl.<vdom>) and dial-up IPsec
    (FirewallInterface.remote_access).  Cached per Session for the run."""
    from app.models import Firewall, FirewallInterface
    from app.sites import current_ingest_site_id
    sid = current_ingest_site_id(db) if hasattr(db, "info") else None
    q = db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                 FirewallInterface.remote_access).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
    if sid is not None:
        q = q.filter(Firewall.site_id == sid)
    out: dict = {}
    for fid, name, kind in q:
        if kind or is_tunnel_name(name):
            out.setdefault(fid, set()).add(str(name).strip().lower())
    return out


def all_remote_tunnel_names(db) -> set:
    return set().union(*remote_tunnels(db).values()) if remote_tunnels(db) else set()


def zone_is_remote(zone, names) -> bool:
    """Every token of a (comma-separated) zone value is a remote-access
    tunnel - an SSL-VPN name, or one of ``names`` (dial-up IPsec)."""
    toks = [t.strip() for t in str(zone or "").split(",") if t.strip()]
    return bool(toks) and all(is_tunnel_name(t) or t.lower() in names for t in toks)


class VpnContext:
    def __init__(self):
        self.tunnels: dict[int, set] = {}        # firewall id -> tunnel interface names
        self.pools: list = []                    # (firewall_id, parsed spec, text)
        self.gateway_fw: set = set()             # firewall ids running SSL-VPN
        self.fw_ips: dict[str, int] = {}         # firewall interface ip -> firewall id
        self.groups: dict[tuple, list] = {}      # (firewall id, policy id) -> user groups

    @classmethod
    def build(cls, db: DBSession) -> "VpnContext":
        from app.models import Firewall, FirewallInterface, FirewallRule
        from app.parsers import rule_match as rm
        from app.sites import current_ingest_site_id
        ctx = cls()
        # AU full review E-L1: ingest-time callers (classification, L3 switch
        # ingest) are not under analysis_site's loader criteria - keep the
        # pools / tunnels of the bound site only.
        sid = current_ingest_site_id(db)
        iface_q = db.query(FirewallInterface.firewall_id, FirewallInterface.name,
                           FirewallInterface.ip_address).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id)
        rule_q = db.query(FirewallRule).filter(FirewallRule.enabled.is_(True))
        if sid is not None:
            iface_q = iface_q.filter(Firewall.site_id == sid)
            rule_q = rule_q.filter(FirewallRule.site_id == sid)
        dialup = remote_tunnels(db)
        for fid, name, ip in iface_q:
            if is_tunnel_name(name) or str(name).strip().lower() in dialup.get(fid, ()):
                ctx.tunnels.setdefault(fid, set()).add(str(name).strip().lower())
            if ip:
                ctx.fw_ips[str(ip).strip()] = fid
        seen = set()
        for r in rule_q:
            if not zone_is_remote(r.src_zone, ctx.tunnels.get(r.firewall_id, ())):
                continue
            if r.firewall_id is not None:
                ctx.gateway_fw.add(r.firewall_id)
                ident = getattr(r, "src_identity", None)
                if ident:
                    ctx.groups.setdefault((r.firewall_id, r.policy_id), [])
                    for g in str(ident).split(","):
                        g = g.strip()
                        if g and g not in ctx.groups[(r.firewall_id, r.policy_id)]:
                            ctx.groups[(r.firewall_id, r.policy_id)].append(g)
            key = (r.firewall_id, str(r.src or ""))
            if key in seen or not r.src:
                continue
            seen.add(key)
            try:
                spec = rm.parse_address(r.src, v6_default_is_any=False)
            except Exception:
                continue
            if spec == rm.ANY or isinstance(spec, rm.Unresolved):
                continue
            ctx.pools.append((r.firewall_id, spec, str(r.src)))
        return ctx

    # ---- questions
    def is_pool_ip(self, ip) -> bool:
        from app.parsers import rule_match as rm
        if not ip or not self.pools:
            return False
        for _fid, spec, _t in self.pools:
            try:
                if rm.ip_in_addr(str(ip), spec):
                    return True
            except Exception:
                continue
        return False

    def is_firewall_ip(self, ip) -> bool:
        return bool(ip) and str(ip).strip() in self.fw_ips

    def is_gateway_ip(self, ip) -> bool:
        """``ip`` is an interface of a firewall that runs SSL-VPN."""
        return bool(ip) and self.fw_ips.get(str(ip).strip()) in self.gateway_fw

    def is_vpn_rule(self, rule) -> bool:
        """MP-23: a permit whose source zone is a remote-access tunnel of its
        firewall (SSL-VPN or dial-up IPsec) - judged by vpn_direct_to_ot /
        config_vpn_direct_to_ot, not by the generic rule twins."""
        fid = getattr(rule, "firewall_id", None)
        names = self.tunnels.get(fid, set()) if fid is not None else (
            set().union(*self.tunnels.values()) if self.tunnels else set())
        return zone_is_remote(getattr(rule, "src_zone", None), names)

    def is_vpn_row(self, row: dict) -> bool:
        """An access-path row whose users are SSL-VPN users: its source zone
        is a tunnel interface, or its source scope lies inside a VPN pool."""
        from app.parsers import rule_match as rm
        src = row.get("src") or {}
        if zone_is_remote(src.get("zone"), set().union(*self.tunnels.values()) if self.tunnels else ()):
            return True
        scope = src.get("scope")
        if not scope or not self.pools:
            return False
        try:
            spec = rm.parse_address(scope, v6_default_is_any=False)
        except Exception:
            return False
        if spec == rm.ANY or isinstance(spec, rm.Unresolved):
            return False
        return any(rm.addr_contains(p, spec) is True for _f, p, _t in self.pools)

    def row_group_pairs(self, row: dict) -> list:
        """[(firewall id, group)] of the tunnel policies in the row's chain."""
        out = []
        for c in row.get("chain") or []:
            for g in self.groups.get((c.get("firewall_id"), c.get("policy_id")), []):
                if (c.get("firewall_id"), g) not in out:
                    out.append((c.get("firewall_id"), g))
        return out

    def row_groups(self, row: dict) -> list:
        out = []
        for c in row.get("chain") or []:
            for g in self.groups.get((c.get("firewall_id"), c.get("policy_id")), []):
                if g not in out:
                    out.append(g)
        return out


# --------------------------------------------------------------- reviews --
def review_vpn_direct_to_ot(db: DBSession) -> list:
    """One critical finding per VPN policy chain whose SSL-VPN users can open
    sessions straight to L0-L2 equipment (no DMZ jump host in between)."""
    from app.parsers import alert_engine as ae
    from app.parsers import chain_findings as cf
    from app.parsers.access_path_findings import allowed_by, path_label
    from app.purdue import fmt_level, is_ot
    vctx = VpnContext.build(db)
    if not vctx.gateway_fw and not vctx.pools:
        return []
    rows = [r for r in cf._candidates(db, ae, multi_only=False)
            if vctx.is_vpn_row(r) and is_ot((r.get("dst") or {}).get("level"))
            and r.get("classification") not in cf._SUPPRESSING]
    groups_ = cf.group_rows(rows)
    # the tail of a longer VPN chain (a downstream firewall's policy that
    # names the pool, e.g. FW2 "VPN-to-OT" after FW1's tunnel policy) is part
    # of that chain's finding, not a remote-access path of its own
    ids = [cf._chain_ids(g) for g in groups_]
    keep = [g for g, i in zip(groups_, ids)
            if not any(len(j) > len(i) and j[-len(i):] == i for j in ids)]
    decls = declarations(db)
    out = []
    for g in keep:
        dst_level = (g.get("dst") or {}).get("level")
        n_sess = _tunnel_sessions(db, vctx, g)
        seen = cf._seen(g) or n_sess > 0
        pairs = vctx.row_group_pairs(g) or [(None, None)]
        all_groups = [x for _f, x in pairs if x]
        for fw_id, grp in pairs:
            cat, how = category_of(decls, fw_id, grp) if grp else (None, "no user group on the policy")
            f = _emit_group(db, ae, cf, g, grp, cat, how, all_groups, dst_level, n_sess, seen,
                            path_label, allowed_by, fmt_level)
            if f is not None:
                out.append(f)
    return out


def _emit_group(db, ae, cf, g, grp, cat, how, all_groups, dst_level, n_sess, seen,
                path_label, allowed_by, fmt_level):
    vendor = cat == "vendor"
    if grp:
        who = f"users of VPN group {grp}"
        tag = f" ({CATEGORY_LABEL[cat]}{', guessed' if how.startswith('guessed') else ''})" if cat \
            else " (unclassified)"
    else:
        who, tag = "any remote-access (SSL-VPN / dial-up IPsec) user", ""
    svc = ", ".join(g.get("service") or []) or "any"
    title = (f"Remote access straight to OT: {who}{tag} {path_label(g)} ({svc})"
             + (" [seen in capture]" if seen else ""))
    others = [x for x in all_groups if x != grp]
    text = (f"The policies {allowed_by(g)} let {who} (tunnel pool "
            f"{(g.get('src') or {}).get('scope')}) open sessions directly to "
            f"{fmt_level(dst_level)} equipment ({(g.get('dst') or {}).get('scope')}) over "
            f"{', '.join(g.get('service') or []) or 'any service'}. Access from an untrusted "
            f"network must be controlled and terminate at the zone boundary - a DMZ jump host "
            f"that brokers the session - not route into the control zone "
            f"(IEC 62443-3-3 SR 1.13 access via untrusted networks; SR 5.2 zone boundary "
            f"protection; SR 5.1 network segmentation"
            + ("; IEC 62443-2-4 SP.07 remote access for the vendor's users" if vendor else "")
            + "). "
            + (f"Group category: {CATEGORY_LABEL[cat]} ({how})"
               + (" - classify the group on the Mgmt & Engineering page to confirm. "
                  if how.startswith("guessed") else ". ") if grp and cat else
               "The group is not classified as IT or vendor - classify it on the Mgmt & "
               "Engineering page. " if grp else "")
            + (f"The same policy chain also admits {', '.join(others)} (separate finding). "
               if others else "")
            + (f"{n_sess} session(s) from the tunnel pool to these devices were seen in the "
               "capture (the pool is not per group, so they may belong to any group on it). "
               if n_sess else "Matching traffic was seen in the capture. " if seen
               else "No matching traffic observed yet. ")
            + "Restrict the VPN policy to the DMZ jump host and broker OT access from there.")
    refs = ["IEC 62443-3-3 SR 1.13", "SR 5.2", "SR 5.1"] + (["IEC 62443-2-4 SP.07"] if vendor else [])
    chain = g.get("chain") or []
    ev = cf._evidence(g)
    ev.update({"severity_reason": "Critical for every VPN group: remote users can open sessions "
                                  "straight to control-zone equipment with no DMZ jump host."
                                  + (" Vendor group: IEC 62443-2-4 SP.07 applies as well." if vendor else ""),
               "vpn": True, "user_group": grp, "user_groups": all_groups,
               "group_category": cat, "group_category_source": how,
               "tunnel_sessions_in_capture": n_sess, "references": refs})
    key = cf._group_key_text(g) if g.get("_rows") is not None else g.get("tag_key")
    dedup = {"rule_key": f"access_path_chain:{key}:group:{(grp or '*').lower()}"}
    f = ae._make_finding(db, CHECK_VPN_OT, title[:512], text, ev,
                         firewall_rule_id=(chain[0].get("rule_id") if chain else None),
                         device_name=(chain[0].get("firewall_name") if chain else None),
                         severity="critical", dedup_evidence=dedup)
    if f is None:
        # re-detected: the classification may have changed - keep the title
        # in step (the evidence / description were refreshed already)
        ex = ae._find_open(db, ae._dedup_key(CHECK_VPN_OT, dedup))
        if ex is not None and ex.title != title[:512]:
            ex.title = title[:512]
    return f


# ------------------------------------------------- group classification --
def discovered_groups(db: DBSession) -> list[dict]:
    """Every user group / user named by a tunnel-sourced policy of the bound
    site, per firewall, with its category and how it was decided."""
    from app.models import Firewall, FirewallRule
    decls = declarations(db)
    names = {f.id: (f.device_name or f.name) for f in db.query(Firewall)}
    acc: dict = {}
    tun = remote_tunnels(db)
    for r in db.query(FirewallRule).filter(FirewallRule.enabled.is_(True),
                                           FirewallRule.src_identity.isnot(None)):
        if not zone_is_remote(r.src_zone, tun.get(r.firewall_id, ())):
            continue
        for gname in [x.strip() for x in str(r.src_identity).split(",") if x.strip()]:
            e = acc.setdefault((r.firewall_id, gname), {
                "name": gname, "firewall_id": r.firewall_id,
                "firewall_name": names.get(r.firewall_id), "policies": []})
            pol = f"#{r.policy_id} {r.policy_name or ''}".strip()
            if pol not in e["policies"]:
                e["policies"].append(pol)
    out = []
    for (fw_id, gname), e in sorted(acc.items(), key=lambda kv: (str(kv[0][0]), kv[0][1].lower())):
        cat, how = category_of(decls, fw_id, gname)
        d = decls.get(group_key(fw_id, gname)) or decls.get(group_key(None, gname))
        e.update({"category": cat, "category_source": how,
                  "declaration_id": d.id if d is not None else None,
                  "guess": guess_category(gname)})
        out.append(e)
    return out


def declaration_dict(r) -> dict:
    return {"id": r.id, "key": r.key, "name": r.name, "firewall_id": r.firewall_id,
            "category": r.category, "note": r.note, "finding_id": r.finding_id,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None}


def classify(db: DBSession, site_id: int, *, name: str, category: str, firewall_id=None,
             note=None, created_by=None, finding_id=None) -> tuple:
    """Upsert a group classification; returns (row, created)."""
    from app.models import Firewall, VpnUserGroup
    name = str(name or "").strip()
    category = str(category or "").strip().lower()
    if not name:
        raise VpnGroupError("name is required")
    if category not in CATEGORIES:
        raise VpnGroupError(f"category must be one of {', '.join(CATEGORIES)}")
    if firewall_id is not None:
        fw = db.get(Firewall, int(firewall_id))
        if fw is None or fw.site_id != site_id:
            raise VpnGroupError(f"firewall {firewall_id} not found", 404)
    key = group_key(firewall_id, name)
    row = db.query(VpnUserGroup).filter(VpnUserGroup.site_id == site_id,
                                        VpnUserGroup.key == key).first()
    if row is not None:
        if row.category == category and (note is None or note == row.note):
            raise VpnGroupError(f"{name} is already classified as {category}", 409)
        row.category = category
        if note is not None:
            row.note = note
        if finding_id:
            row.finding_id = finding_id
        db.flush()
        return row, False
    row = VpnUserGroup(site_id=site_id, key=key, name=name[:128], firewall_id=firewall_id,
                       category=category, note=note, created_by=created_by, finding_id=finding_id)
    db.add(row)
    db.flush()
    return row, True


def unclassify(db: DBSession, decl_id: int):
    from app.models import VpnUserGroup
    row = db.get(VpnUserGroup, int(decl_id))
    from app.parsers.site_scope import current_site
    sid = current_site(db)
    if row is None or (sid is not None and row.site_id != sid):
        raise VpnGroupError(f"VPN group classification {decl_id} not found", 404)
    db.delete(row)
    db.flush()
    return row


def recheck(db: DBSession, site_id: int) -> dict:
    """Re-run vpn_direct_to_ot for the site (titles / references follow the
    classification)."""
    from app.parsers import alert_engine as ae
    ae.run_periodic_reviews(db, site_id=site_id, only={"review_vpn_direct_to_ot"})
    from app.models import Finding
    from app.parsers.site_scope import analysis_site
    with analysis_site(db, site_id):
        n = db.query(Finding).filter(Finding.check_name == CHECK_VPN_OT,
                                     Finding.status == "open").count()
    return {"vpn_direct_to_ot_open": n, "failed_reviews": list(ae.failed_reviews(db))}


def _tunnel_sessions(db, vctx: "VpnContext", g: dict) -> int:
    """Captured sessions from tunnel-pool addresses to the group's
    destinations (the overlay matches per row; this looks at the whole
    group, so a pool spread over several rows still counts)."""
    from sqlalchemy.orm import aliased
    from app.models import Host, NetworkSession
    from app.parsers import rule_match as rm
    specs = []
    for m in g.get("_rows") or [g]:
        try:
            sp = rm.parse_address((m.get("dst") or {}).get("scope") or "", v6_default_is_any=False)
        except Exception:
            continue
        if sp is not None and not isinstance(sp, rm.Unresolved):
            specs.append(sp)
    if not specs:
        return 0
    sh, dh = aliased(Host), aliased(Host)
    n = 0
    for sip, dip in (db.query(sh.ip, dh.ip).select_from(NetworkSession)
                     .join(sh, NetworkSession.src_host_id == sh.id)
                     .join(dh, NetworkSession.dst_host_id == dh.id).limit(20000)):
        if not sip or not dip or not vctx.is_pool_ip(sip):
            continue
        if any(sp == rm.ANY or rm.ip_in_addr(dip, sp) for sp in specs):
            n += 1
    return n


def _iface_level(db, fw_id: int, names: list) -> Optional[float]:
    """Operator Purdue level of a firewall interface / FortiOS zone (one
    common level, else None)."""
    from app.models import FirewallInterface, FirewallZoneDef
    levels = set()
    low = {str(n).strip().lower() for n in names if n}
    members = set()
    for zd in db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id == fw_id):
        if str(zd.name).strip().lower() in low:
            members |= {str(m).strip().lower() for m in zd.members or []}
    for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_id):
        if str(i.name).strip().lower() in (low | members) and i.purdue_level is not None:
            levels.add(i.purdue_level)
    return levels.pop() if len(levels) == 1 else None


def _close_refs(db, check: str, refs: set, reason: str) -> int:
    from app.models import Finding
    if not refs:
        return 0
    now = datetime.now(timezone.utc)
    note = f"{_AUTO_NOTE}: {reason} ({now.strftime('%Y-%m-%dT%H:%M:%SZ')})"
    n = 0
    for f in db.query(Finding).filter(Finding.check_name == check, Finding.status == "open",
                                      Finding.source_ref.in_(list(refs))):
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "")[:_NOTES_MAX - len(note) - 3] + note
        n += 1
    return n


def review_vpn_config_destinations(db: DBSession) -> list:
    """H-02: re-judge checklist 4.1 for every VPN policy from the operator's
    interface levels.  Destination interface at L3.5 = terminates in the DMZ;
    any other known level = ``config_vpn_direct_to_ot`` (critical); unknown
    level = left to the upload-time name heuristic."""
    from app.models import CHECK_TYPE_REFERENCE, Finding, Firewall, FirewallRule
    from app.parsers.mgmt_networks import _find_ref
    from app.purdue import fmt_level
    now = datetime.now(timezone.utc)
    created = []
    for fw in db.query(Firewall).order_by(Firewall.id):
        pols = {}
        for r in db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id,
                                               FirewallRule.enabled.is_(True)):
            if zone_is_remote(r.src_zone, remote_tunnels(db).get(fw.id, ())) and r.policy_id is not None:
                pols.setdefault(str(r.policy_id), r)
        produced, judged = set(), set()
        for pid, r in pols.items():
            dst = [t.strip() for t in str(r.dst_zone or "").split(",") if t.strip()]
            lv = _iface_level(db, fw.id, dst)
            if lv is None:
                continue
            judged.add(pid)
            if lv == 3.5:
                continue
            ref = f"config:{fw.id}:{CHECK_CFG_VPN_OT}:{pid}"
            produced.add(ref)
            sr, cid, sev, cat = CHECK_TYPE_REFERENCE[CHECK_CFG_VPN_OT]
            title = (f"VPN policy {pid} ({r.policy_name or ''}) routes to '{r.dst_zone}' "
                     f"({fmt_level(lv)}), not the DMZ")[:512]
            detail = {"vpn_policy_id": pid, "vpn_policy_name": r.policy_name,
                      "srcintf": r.src_zone, "dstintf": r.dst_zone, "dst_level": lv,
                      "judged_from": "operator interface level",
                      "reason": "Remote access must terminate at a DMZ (L3.5) jump host; this "
                                "VPN policy delivers authenticated sessions to "
                                f"{fmt_level(lv)}.",
                      "device_name": fw.device_name or fw.name, "firewall_id": fw.id,
                      "checklist_title": "All remote access terminates in the DMZ (jump host)"}
            f = _find_ref(db, ref)
            if f is not None:
                f.title, f.detail, f.severity, f.updated_at = title, detail, sev, now
            else:
                f = Finding(source_ref=ref, category=cat, check_name=CHECK_CFG_VPN_OT, severity=sev,
                            status="open", isa62443_sr=sr, checklist_id=cid, title=title,
                            detail=detail, device_name=fw.device_name or fw.name,
                            site_id=fw.site_id, created_at=now, updated_at=now)
                db.add(f)
                created.append(f)
        # judged policies: the name-heuristic findings give way to the levels
        unclear = {f"config:{fw.id}:{CHECK_CFG_VPN_UNCLEAR}:{p}" for p in judged}
        to_dmz = {f"config:{fw.id}:{CHECK_CFG_VPN_OT}:{p}" for p in judged} - produced
        _close_refs(db, CHECK_CFG_VPN_UNCLEAR, unclear, "destination interface level is known")
        _close_refs(db, CHECK_CFG_VPN_OT, to_dmz, "destination interface is the DMZ (L3.5)")
    db.flush()
    return created
