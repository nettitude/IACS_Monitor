"""
Findings linked to the objects they are about (owner 2026-10-14: findings are
edited next to the host, firewall rule or zone that causes them).

A finding records its objects in ``detail``: addresses (ip, src_ip, dst_ip,
addresses, ...), MACs (mac, mac_addresses), the firewall policy (policy_id with
firewall_id / device_name, or firewall_rule_id(s)) and IEC 62443 zone names
(zone_a / zone_b / zones).  ``LinkIndex`` reads the site's active findings once
and answers "which findings are about this host / policy / zone / conduit".
View-only: never changes a finding.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Iterable, Optional

from sqlalchemy.orm import Session as DBSession

# open + acknowledged: the findings still to act on (a false positive or a
# closed finding is listed only with include_closed)
LINK_STATUSES = ("open", "acknowledged")
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_IP_KEYS = ("ip", "src_ip", "dst_ip", "host_ip", "source_ip", "dest_ip", "target_ip", "client_ip", "server_ip")
_IP_LIST_KEYS = ("addresses", "ips", "hosts", "src_ips", "dst_ips")
_MAC_KEYS = ("mac",)
_MAC_LIST_KEYS = ("mac_addresses",)


def _ip(v) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if s.endswith("/32") or s.endswith("/128"):
        s = s.rsplit("/", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _mac(v) -> Optional[str]:
    s = str(v or "").strip().lower()
    return s if s.count(":") == 5 else None


def _items(v) -> list:
    if isinstance(v, (list, tuple, set)):
        out = []
        for x in v:
            out.append(x.get("ip") if isinstance(x, dict) else x)
        return out
    return [v]


def finding_hosts(detail: dict) -> tuple[set, set]:
    """(addresses, MACs) a finding names."""
    ips, macs = set(), set()
    if not isinstance(detail, dict):
        return ips, macs
    for k in _IP_KEYS:
        a = _ip(detail.get(k))
        if a:
            ips.add(a)
    for k in _IP_LIST_KEYS:
        for x in _items(detail.get(k)):
            a = _ip(x)
            if a:
                ips.add(a)
    for k in _MAC_KEYS:
        m = _mac(detail.get(k))
        if m:
            macs.add(m)
    for k in _MAC_LIST_KEYS:
        for x in _items(detail.get(k)):
            m = _mac(x)
            if m:
                macs.add(m)
    return ips, macs


def _zone_names(detail: dict) -> set:
    out = set()
    if not isinstance(detail, dict):
        return out
    for k in ("zone_a", "zone_b"):
        v = detail.get(k)
        if isinstance(v, str) and v.strip():
            out.add(v.strip().lower())
    for x in detail.get("zones") or [] if isinstance(detail.get("zones"), list) else []:
        n = x.get("name") if isinstance(x, dict) else x
        if isinstance(n, str) and n.strip():
            out.add(n.strip().lower())
    return out


class LinkIndex:
    """The site's findings indexed by address, MAC, firewall policy and zone name."""

    def __init__(self, db: DBSession, site_id: int, include_closed: bool = False, include_excluded: bool = False):
        from app.models import Finding, Firewall, FirewallRule
        from app.report_checks import hide_excluded
        self.db, self.site_id = db, site_id
        q = db.query(Finding).filter(Finding.site_id == site_id)
        if not include_closed:
            q = q.filter(Finding.status.in_(LINK_STATUSES))
        q = hide_excluded(db, q, site_id, include_excluded)   # owner 2026-10-14: hidden app-wide
        self.findings = {f.id: f for f in q}
        fws = db.query(Firewall).filter(Firewall.site_id == site_id).all()
        self.fw_by_name = {}
        for fw in fws:
            for n in (fw.name, fw.device_name):
                if n:
                    self.fw_by_name.setdefault(n.lower(), fw.id)
        fw_ids = {fw.id for fw in fws}
        rule_ids = set()
        for f in self.findings.values():
            d = f.detail if isinstance(f.detail, dict) else {}
            for k in ("firewall_rule_id", "rule_id"):
                if str(d.get(k) or "").isdigit():
                    rule_ids.add(int(d[k]))
            for x in d.get("firewall_rule_ids") or [] if isinstance(d.get("firewall_rule_ids"), list) else []:
                if str(x).isdigit():
                    rule_ids.add(int(x))
        self.rule_policy = {}
        if rule_ids:
            for r in db.query(FirewallRule.id, FirewallRule.firewall_id, FirewallRule.policy_id).filter(
                    FirewallRule.id.in_(sorted(rule_ids))):
                if r.firewall_id is not None and r.policy_id:
                    self.rule_policy[r.id] = (r.firewall_id, str(r.policy_id))
        self.by_ip, self.by_mac = defaultdict(set), defaultdict(set)
        self.by_policy, self.by_zone = defaultdict(set), defaultdict(set)
        for fid, f in self.findings.items():
            d = f.detail if isinstance(f.detail, dict) else {}
            ips, macs = finding_hosts(d)
            for a in ips:
                self.by_ip[a].add(fid)
            for m in macs:
                self.by_mac[m].add(fid)
            for key in self._policies(d, f.device_name, fw_ids):
                self.by_policy[key].add(fid)
            for z in _zone_names(d):
                self.by_zone[z].add(fid)

    def _policies(self, d: dict, device_name, fw_ids) -> set:
        out = set()
        pid = d.get("policy_id")
        if pid not in (None, ""):
            fw = None
            if str(d.get("firewall_id") or "").isdigit() and int(d["firewall_id"]) in fw_ids:
                fw = int(d["firewall_id"])
            for n in (d.get("device_name"), d.get("firewall"), device_name):
                if fw is None and isinstance(n, str):
                    fw = self.fw_by_name.get(n.lower())
            if fw is not None:
                out.add((fw, str(pid)))
        ids = [d.get("firewall_rule_id"), d.get("rule_id")]
        if isinstance(d.get("firewall_rule_ids"), list):
            ids += d["firewall_rule_ids"]
        for x in ids:
            if str(x or "").isdigit() and int(x) in self.rule_policy:
                out.add(self.rule_policy[int(x)])
        return out

    # ---------------------------------------------------------------- lookups --
    def for_host(self, ip=None, mac=None) -> set:
        out = set()
        a = _ip(ip)
        if a:
            out |= self.by_ip.get(a, set())
        m = _mac(mac)
        if m:
            out |= self.by_mac.get(m, set())
        return out

    def for_policy(self, firewall_id, policy_id) -> set:
        return set(self.by_policy.get((firewall_id, str(policy_id)), set()))

    def for_zone(self, zone_name: str, host_rows: Iterable = ()) -> set:
        out = set(self.by_zone.get((zone_name or "").lower(), set()))
        for h in host_rows:
            out |= self.for_host(h.ip, h.mac)
        return out

    def for_conduit(self, zone_a: str, zone_b: str, policies: Iterable = ()) -> set:
        a, b = (zone_a or "").lower(), (zone_b or "").lower()
        out = {fid for fid in self.by_zone.get(a, set()) & self.by_zone.get(b, set())}
        for fw, pid in policies:
            out |= self.for_policy(fw, pid)
        return out

    def summary(self, ids: Iterable) -> dict:
        """{"count", "open", "max_severity"} of a set of finding ids."""
        fs = [self.findings[i] for i in ids if i in self.findings]
        top = max((f.severity for f in fs), key=lambda s: _SEV_RANK.get(s or "", 0), default=None)
        return {"count": len(fs), "open": sum(1 for f in fs if f.status == "open"), "max_severity": top}

    def rows(self, ids: Iterable) -> list:
        fs = [self.findings[i] for i in ids if i in self.findings]
        fs.sort(key=lambda f: (-_SEV_RANK.get(f.severity or "", 0), f.status != "open", -(f.id or 0)))
        return fs


def link_counts(db: DBSession, site_id: int) -> dict:
    """Per-object summaries for list badges: hosts (by host id), policies
    ("firewall_id|policy_id"), zones and conduits (by id)."""
    from app.models import FirewallRule, Host, IecConduit, IecConduitRule, IecZone, real_host_clause
    idx = LinkIndex(db, site_id)
    out = {"hosts": {}, "policies": {}, "zones": {}, "conduits": {}}
    if not idx.findings:
        return out
    hosts = db.query(Host).filter(Host.site_id == site_id, real_host_clause()).all()
    for h in hosts:
        ids = idx.for_host(h.ip, h.mac)
        if ids:
            out["hosts"][h.id] = idx.summary(ids)
    seen = set()
    for r in db.query(FirewallRule.firewall_id, FirewallRule.policy_id).filter(
            FirewallRule.site_id == site_id, FirewallRule.policy_id.isnot(None)):
        k = (r.firewall_id, str(r.policy_id))
        if k in seen or r.firewall_id is None:
            continue
        seen.add(k)
        ids = idx.for_policy(*k)
        if ids:
            out["policies"][f"{k[0]}|{k[1]}"] = idx.summary(ids)
    zones = db.query(IecZone).filter(IecZone.site_id == site_id).all()
    if zones:
        from app import iec_zones as iz
        zidx = iz.host_zone_index(db, hosts)
        members = defaultdict(list)
        for h in hosts:
            for z in zidx.get(h.id, []):
                members[z["id"]].append(h)
        names = {z.id: z.name for z in zones}
        for z in zones:
            ids = idx.for_zone(z.name, members.get(z.id, []))
            if ids:
                out["zones"][z.id] = idx.summary(ids)
        fw_name = {n: fid for n, fid in idx.fw_by_name.items()}
        rules = defaultdict(list)
        for r in db.query(IecConduitRule).filter(IecConduitRule.site_id == site_id):
            fid = fw_name.get((r.firewall_name or "").lower())
            if fid is not None:
                rules[r.conduit_id].append((fid, r.policy_id))
        for c in db.query(IecConduit).filter(IecConduit.site_id == site_id):
            ids = idx.for_conduit(names.get(c.zone_a_id), names.get(c.zone_b_id), rules.get(c.id, []))
            if ids:
                out["conduits"][c.id] = idx.summary(ids)
    return out
