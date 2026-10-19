"""Layer-3 (routing) Cisco switches - L3-switch tabletop LS-01 / 02 / 04 / 08.

A Cisco switch running ``ip routing`` with an SVI (``interface VlanN`` +
``ip address``) in several VLANs routes between those VLANs itself.  When
the VLANs sit at different Purdue levels the switch is a routing boundary
without a firewall: traffic between them never reaches the firewall.

The switch is modelled as an enforcement point so reachability, the session
evaluation and the access paths see it (LS-02):

* a ``Firewall`` row (vendor ``cisco_l3_switch``) named after the switch;
* one ``FirewallInterface`` per SVI (``Vlan10`` ...), its level taken from the
  firewall interface on the same network (operator labels), else the
  switch VLAN's level, else the levels of the hosts in it (``refresh_levels``;
  an operator label on the SVI always wins);
* its ACLs bound to SVIs (``ip access-group NAME in|out``) as rules
  (``in`` -> src_zone, ``out`` -> dst_zone) followed by the ACL's implicit
  deny (policy id ``implicit:acldeny:<n>``), and one final implicit routing
  permit (``implicit:route:<switch>``): everything no ACL filters is routed.
  An ACL bound to an SVI but not defined in the config is reported in the
  ingest stats and yields no rows (its traffic is then judged by the
  routing permit, never by a made-up deny).  Limitation: a flow crossing an
  inbound and an outbound ACL is judged by the first matching entry.

Every helper here filters on the current site (the analysis site, else the
ingest site bound to the session): the ingest path runs outside
``analysis_site``, so nothing may rely on the loader criteria.

Reachability treats the switch as a PARALLEL path on a boundary it shares
with a firewall (the flow crosses one or the other, never both) - see
reachability._evaluate_hop.  Captured frames whose router MAC is the
switch's (LS-03) are judged against the switch only.

Checks (``review_l3_switches``):

* ``switch_routes_between_zones`` (SR 5.1 RE2, SR 5.2; rows 2.1 / 2.2):
  critical when the switch joins IT (L4+) with L0-L2, high L3 / DMZ <-> L1-L2,
  medium for other level pairs - one finding per routed SVI (the lower one).
* ``switch_acl_wrong_direction`` (SR 5.2; row 2.4): an OT SVI's protecting
  ACL (its entries name the SVI's own subnet as destination) is bound only
  ``in``, so it filters traffic FROM the VLAN's hosts, not traffic to them.
* ``switch_mgmt_svi_unrestricted`` (SR 5.1 RE1, SR 1.3; row 5.1): a
  management SVI routed to the other VLANs without an ACL.
* ``switch_dual_gateway`` (SR 5.2; rows 2.1 / 2.2): an OT VLAN with both a
  firewall interface and a switch SVI - two gateways, the hosts pick which
  one enforces policy.

Cisco IOS / IOS-XE / NX-OS syntax only (owner decision: Cisco first).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

VENDOR = "cisco_l3_switch"
ROUTE_PREFIX = "implicit:route:"
ACL_DENY_PREFIX = "implicit:acldeny:"
AUTO_SOURCE = "svi_auto"

_SVI_RE = re.compile(r"^interface\s+(vlan\s*(\d+))\s*$", re.I)


def _site(db) -> int:
    """The site every query here is limited to: the analysis site, else the
    ingest site bound to ``db``, else the Default site."""
    from app.parsers.site_scope import current_site
    from app.sites import scope_site_id
    sid = current_site(db)
    return int(sid) if sid is not None else scope_site_id(db)


# ------------------------------------------------------------------ parse --
def parse_l3(text: str) -> dict:
    """{"hostname", "routing", "svis": [{name, vlan_id, ip_cidr, status,
    alias, acl_in, acl_out}]} of a Cisco running-config."""
    hostname, routing, no_routing = None, False, False
    svis: list[dict] = []
    cur = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("!"):
            if s.startswith("!") and cur is not None and not line.startswith(" "):
                cur = None
            continue
        if not line[0].isspace():
            cur = None
            low = s.lower()
            if low.startswith("hostname "):
                hostname = s.split(None, 1)[1].strip()
            elif low == "ip routing" or low.startswith("ip routing "):
                routing = True
            elif low == "no ip routing":
                no_routing = True
            elif low in ("feature interface-vlan",):
                routing = True              # NX-OS: SVIs route
            m = _SVI_RE.match(s)
            if m:
                cur = {"name": f"Vlan{int(m.group(2))}", "vlan_id": str(int(m.group(2))),
                       "ip_cidr": None, "status": "up", "alias": None,
                       "acl_in": None, "acl_out": None}
                svis.append(cur)
            continue
        if cur is None:
            continue
        low = s.lower()
        toks = s.split()
        if low.startswith("ip address ") and len(toks) >= 3 and "secondary" not in low:
            if "/" in toks[2]:
                cur["ip_cidr"] = toks[2]
            elif len(toks) >= 4:
                try:
                    cur["ip_cidr"] = str(ipaddress.ip_interface(f"{toks[2]}/{toks[3]}"))
                except ValueError:
                    pass
        elif low == "shutdown":
            cur["status"] = "down"
        elif low == "no shutdown":
            cur["status"] = "up"
        elif low.startswith("description "):
            cur["alias"] = s.split(None, 1)[1][:128]
        elif low.startswith("ip access-group ") and len(toks) >= 4:
            if toks[3].lower() == "in":
                cur["acl_in"] = toks[2]
            elif toks[3].lower() == "out":
                cur["acl_out"] = toks[2]
    if no_routing:
        routing = False
    return {"hostname": hostname, "routing": routing, "svis": svis}


def _routed_svis(info: dict) -> list[dict]:
    return [s for s in info["svis"] if s["ip_cidr"] and s["status"] != "down"]


# ------------------------------------------------------------------- sync --
def switch_firewalls(db):
    from app.models import Firewall
    return db.query(Firewall).filter(Firewall.vendor == VENDOR, Firewall.site_id == _site(db)).all()


def switch_firewall_ids(db) -> set:
    from app.models import Firewall
    return {i for (i,) in db.query(Firewall.id).filter(Firewall.vendor == VENDOR,
                                                        Firewall.site_id == _site(db))}


def _remove(db, fw) -> None:
    from app.models import FirewallInterface, FirewallRule
    ids = [i.id for i in fw.interfaces]
    if ids:
        db.query(FirewallInterface).filter(FirewallInterface.connects_to_interface_id.in_(ids)).update(
            {"connects_to_interface_id": None}, synchronize_session="fetch")
        db.query(FirewallInterface).filter(FirewallInterface.parent_interface_id.in_(ids)).update(
            {"parent_interface_id": None}, synchronize_session="fetch")
    db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id).delete(synchronize_session="fetch")
    from app.models import Firewall, FirewallDevice, PcapCapture
    db.query(Firewall).filter(Firewall.upstream_firewall_id == fw.id).update(
        {"upstream_firewall_id": None}, synchronize_session="fetch")
    # AU full review F9: the remaining non-cascading references (a capture
    # pinned to one of the SVIs, a log device matched to the switch) made the
    # delete fail on PostgreSQL.
    if ids:
        for col in (PcapCapture.interface_id, PcapCapture.suggested_interface_id):
            db.query(PcapCapture).filter(col.in_(ids)).update({col.key: None}, synchronize_session="fetch")
    db.query(PcapCapture).filter(PcapCapture.firewall_id == fw.id).update(
        {"firewall_id": None}, synchronize_session="fetch")
    db.query(FirewallDevice).filter(FirewallDevice.firewall_id == fw.id).update(
        {"firewall_id": None}, synchronize_session="fetch")
    db.delete(fw)
    db.flush()


def sync_switch(db, device_name: Optional[str], text: str, source_file: Optional[str] = None) -> dict:
    """Create / update / remove the routing-switch enforcement point of a
    Cisco running-config.  Operator fields of the SVIs (level, side, zone
    label) are kept on re-ingest.  Returns stats; ``error`` when the switch
    name is already a firewall of the site (nothing is changed then).  All
    parsing happens before the first write, so a parser error leaves the
    stored model untouched."""
    from datetime import datetime, timezone
    from app.models import Firewall, FirewallInterface, FirewallRule
    from app.parsers.firewall_parser import parse_cisco_acl
    info = parse_l3(text)
    name = device_name or info["hostname"]
    stats = {"ip_routing": info["routing"], "svis": len(info["svis"]),
             "routed_svis": 0, "acl_rules": 0, "enforcement_point": False}
    if not name:
        return stats
    site_id = _site(db)
    fw = db.query(Firewall).filter(Firewall.site_id == site_id, Firewall.name == name).first()
    if fw is not None and fw.vendor != VENDOR:
        stats["error"] = (f"'{name}' is already the name of a {fw.vendor} firewall of this site; "
                          "the switch is not modelled as a routing device (rename one of them)")
        return stats
    svis = _routed_svis(info)
    stats["routed_svis"] = len(svis)
    if not info["routing"] or len(svis) < 2:
        if fw is not None:
            _remove(db, fw)
            stats["enforcement_point_removed"] = True
        return stats

    # ---- parse everything first
    svi_names = {s["name"].lower() for s in svis}

    def _zones(r):
        return {z.strip().lower() for z in str(r.get("src_zone") or r.get("dst_zone") or "").split(",") if z.strip()}

    acl_rows = [r for r in parse_cisco_acl(text) if _zones(r) & svi_names]
    bound = []                               # (direction, svi, acl, rows)
    missing = []
    for s_ in svis:
        for direction, acl in (("in", s_["acl_in"]), ("out", s_["acl_out"])):
            if not acl:
                continue
            zone_key = "src_zone" if direction == "in" else "dst_zone"
            mine = [r for r in acl_rows if r.get("policy_name") == acl
                    and s_["name"].lower() in {z.strip().lower() for z in str(r.get(zone_key) or "").split(",")}]
            if mine:
                bound.append((direction, s_["name"], acl, mine))
            else:
                missing.append(f"{acl} ({s_['name']} {direction})")
    bound.sort(key=lambda b: (b[0] != "in", b[1]))   # inbound filters first
    if missing:
        stats["acls_not_found"] = missing

    # ---- write
    now = datetime.now(timezone.utc)
    if fw is None:
        fw = Firewall(site_id=site_id, name=name, device_name=info["hostname"] or name,
                      vendor=VENDOR, source_file=source_file, config_uploaded_at=now)
        db.add(fw)
        db.flush()
    else:
        fw.device_name = info["hostname"] or fw.device_name
        fw.source_file = source_file or fw.source_file
        fw.config_uploaded_at = now
    existing = {i.name: i for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id)}
    seen = set()
    for s_ in info["svis"]:
        if not s_["ip_cidr"]:
            continue
        itf = ipaddress.ip_interface(s_["ip_cidr"])
        row = existing.get(s_["name"])
        if row is None:
            row = FirewallInterface(firewall_id=fw.id, name=s_["name"])
            db.add(row)
        seen.add(s_["name"])
        row.ip_address, row.prefix_len = str(itf.ip), itf.network.prefixlen
        row.ip_cidr, row.network_cidr = str(itf), str(itf.network)
        row.vlan_id, row.iface_type, row.role = s_["vlan_id"], "svi", "svi"
        row.alias, row.status = s_["alias"], s_["status"]
        row.allowaccess = []                 # a switch SVI has no FortiOS admin access list
    for nm, row in existing.items():
        if nm not in seen:
            db.delete(row)
    db.flush()

    db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id).delete(synchronize_session="fetch")
    order = 0

    def _add(**kw):
        db.add(FirewallRule(device_name=name, device_type=VENDOR, source_file=source_file,
                            firewall_id=fw.id, enabled=kw.pop("enabled", True), **kw))

    for k, (direction, svi, acl, mine) in enumerate(bound, 1):
        for r in mine:
            order += 1
            _add(policy_id=str(r.get("policy_id"))[:32], policy_name=str(acl)[:255],
                 src=r["src"], dst=r["dst"], protocol=r["protocol"], dst_port=r["dst_port"],
                 action=r["action"], raw_line=r.get("raw_line"),
                 src_zone=svi if direction == "in" else None,
                 dst_zone=svi if direction == "out" else None,
                 rule_order=order, enabled=r.get("enabled", True))
            stats["acl_rules"] += 1
        order += 1
        # the ACL's implicit deny: same policy_name (the binding), short id
        _add(policy_id=f"{ACL_DENY_PREFIX}{k}", policy_name=str(acl)[:255],
             src="any", dst="any", protocol="any", dst_port="any", action="deny",
             raw_line=f"(implicit) deny ip any any - end of access-list {acl} on {svi} {direction}",
             src_zone=svi if direction == "in" else None,
             dst_zone=svi if direction == "out" else None, rule_order=order)
    _add(policy_id=f"{ROUTE_PREFIX}{name}"[:32],
         policy_name=f"implicit: {name} routes between its SVIs (ip routing)"[:255],
         src="any", dst="any", protocol="any", dst_port="any", action="permit",
         raw_line="(implicit) ip routing - every routed SVI reaches every other one unless an ACL filters it",
         src_zone=None, dst_zone=None, rule_order=100000)
    n = db.query(Firewall).filter(Firewall.site_id == site_id).count()
    if n >= 2:
        db.query(Firewall).filter(Firewall.site_id == site_id).update(
            {"is_multi_fw": True}, synchronize_session="fetch")
    db.flush()
    refresh_levels(db)
    stats["enforcement_point"] = True
    stats["firewall_id"] = fw.id
    return stats


def bindings_of(rules) -> dict:
    """{svi (lower): {"in": acl, "out": acl}} from a switch's stored rules
    (the ACE rows and their implicit deny carry the ACL name as policy_name)."""
    out: dict = {}
    for r in rules:
        pid = str(r.policy_id or "")
        if pid.startswith(ROUTE_PREFIX) or not r.policy_name:
            continue
        if r.src_zone:
            out.setdefault(r.src_zone.lower(), {})["in"] = r.policy_name
        if r.dst_zone:
            out.setdefault(r.dst_zone.lower(), {})["out"] = r.policy_name
    return out


# ----------------------------------------------------------------- levels --
def _net(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False) if cidr else None
    except ValueError:
        return None


def refresh_levels(db) -> int:
    """SVI levels, then the automatic edge levels (transit to the Internet
    firewall, its Internet leg - app.parsers.edge_links), then the SVIs again
    when the edge changed (the transit SVI follows the firewall interface)."""
    changed = _refresh_svis(db)
    try:
        from app.parsers import edge_links
        edge = edge_links.apply(db)
    except Exception:                                   # noqa: BLE001
        log.warning("edge link levels failed", exc_info=True)
        edge = 0
    if edge:
        changed += edge + _refresh_svis(db)
    return changed


def _refresh_svis(db) -> int:
    """Derive the level of each switch SVI the operator has not labelled:
    the firewall interface on the same network (operator level), else the
    switch VLAN's level, else the one level of the classified hosts in it.
    Returns the number of SVIs changed."""
    from collections import Counter
    from app.models import FirewallInterface, Host, SwitchVlan
    sw = switch_firewalls(db)
    if not sw:
        return 0
    from app.models import Firewall
    sid = _site(db)
    sw_ids = {f.id for f in sw}
    fw_ifaces = [(n, i.purdue_level, i.vlan_id) for i in db.query(FirewallInterface).join(
        Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
        Firewall.site_id == sid, FirewallInterface.purdue_level.isnot(None),
        FirewallInterface.firewall_id.notin_(sw_ids))
        for n in [_net(i.network_cidr)] if n is not None and n.prefixlen > 0]
    hosts = None
    changed = 0
    for fw in sw:
        for i in fw.interfaces:
            if i.purdue_level is not None and i.purdue_suggestion_source != AUTO_SOURCE:
                continue                    # operator label wins
            net = _net(i.network_cidr)
            lv = None
            if net is not None:
                same = [l for n, l, _v in fw_ifaces if n == net]
                inside = [l for n, l, _v in fw_ifaces if n.version == net.version
                          and (n.subnet_of(net) or net.subnet_of(n))]
                pick = same or inside
                if pick and len(set(pick)) == 1:
                    lv = pick[0]
            if lv is None and i.vlan_id:
                sv = db.query(SwitchVlan).filter(SwitchVlan.site_id == sid,
                                                 SwitchVlan.vlan_id == int(i.vlan_id),
                                                 SwitchVlan.purdue_level.isnot(None)).all()
                lvls = {v.purdue_level for v in sv if v.device_name in (None, fw.name, fw.device_name)}
                if len(lvls) == 1:
                    lv = lvls.pop()
            if lv is None and net is not None:
                if hosts is None:
                    hosts = [(h.ip, h.purdue_level) for h in db.query(Host.ip, Host.purdue_level).filter(
                        Host.site_id == sid, Host.purdue_level.isnot(None), Host.ip.isnot(None))]
                c = Counter()
                for ip, l in hosts:
                    try:
                        if ipaddress.ip_address(ip) in net and ip != i.ip_address:
                            c[l] += 1
                    except ValueError:
                        continue
                if len(c) == 1:
                    lv = next(iter(c))
            if lv != i.purdue_level:
                i.purdue_level = lv
                i.purdue_suggestion_source = AUTO_SOURCE if lv is not None else None
                changed += 1
    if changed:
        db.flush()
    return changed


# ---------------------------------------------------------------- carriers --
def _iface_ip_owner(db) -> dict:
    """{interface ip: firewall id} of the site, HA members mapped to their
    cluster primary (the members share addresses and are one device)."""
    from app.models import Firewall, FirewallInterface
    from app.parsers.firewall_groups import KIND_HA, FirewallGroup, _members, primary_of
    sid = _site(db)
    alias = {}
    try:
        for g in db.query(FirewallGroup).filter(FirewallGroup.kind == KIND_HA, FirewallGroup.site_id == sid):
            members = _members(db, g)
            prim = primary_of(db, g, members)
            if prim is not None:
                for m in members:
                    alias[m.id] = prim.id
    except Exception:                        # noqa: BLE001 - grouping never breaks this
        log.warning("HA group lookup failed", exc_info=True)
    out: dict = {}
    for ip, fid in db.query(FirewallInterface.ip_address, FirewallInterface.firewall_id).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == sid, FirewallInterface.ip_address.isnot(None)):
        out.setdefault(str(ip).strip(), set()).add(alias.get(fid, fid))
    return out


def router_macs(db) -> dict:
    """{normalized mac: firewall_id} - the MACs that answer for a firewall /
    switch interface address (switch ARP table, captures).  Used by LS-03:
    the router MAC on a captured frame says which device routed it.  A MAC
    answering for two different devices is left out (ambiguous)."""
    from app.models import Host
    from app.parsers.common import normalize_mac
    ip_fw = _iface_ip_owner(db)
    out: dict = {}
    if not ip_fw:
        return out
    il = list(ip_fw)
    for k in range(0, len(il), 900):
        for ip, mac in db.query(Host.ip, Host.mac).filter(Host.site_id == _site(db), Host.ip.in_(il[k:k + 900]),
                                                          Host.mac.isnot(None)):
            m = normalize_mac(mac)
            fids = ip_fw.get(ip) or set()
            if m and len(fids) == 1:
                fid = next(iter(fids))
                if out.get(m, fid) != fid:
                    out[m] = None          # one MAC, two devices: ambiguous
                else:
                    out[m] = fid
    return {m: f for m, f in out.items() if f is not None}


# ----------------------------------------------------------------- review --
def _lvl(x):
    from app.purdue import fmt_level
    return fmt_level(x) if x is not None else "unlabelled"


def _route_sev(hi, lo) -> Optional[str]:
    if hi is None or lo is None or hi == lo:
        return None
    if lo >= 4:
        return None                          # IT <-> IT / internet: not an OT boundary
    if hi >= 4 and lo <= 2:
        return "critical"
    if hi >= 3 and lo <= 2:
        return "high"
    return "medium"


_SEV_RANK = {"critical": 3, "high": 2, "medium": 1}


def _acl_protects(rules, net) -> bool:
    """The ACL's entries name the SVI's own subnet (or hosts in it) as destination."""
    from app.parsers import rule_match as rm
    for r in rules:
        if str(r.policy_id or "").startswith("implicit:") or (r.dst or "any").lower() == "any":
            continue
        spec = rm.parse_address_spec(r.dst)
        if isinstance(spec, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and spec.version == net.version \
                and (spec.subnet_of(net) or net.subnet_of(spec)):
            return True
    return False


def _observed(db, macs, net) -> list:
    """Captured sessions into ``net`` whose router MAC is this switch's (LS-03)."""
    from sqlalchemy.orm import aliased
    from app.models import Host, NetworkSession
    if not macs:
        return []
    s, d = aliased(Host), aliased(Host)
    out = []
    rows = (db.query(NetworkSession, s.ip, d.ip)
            .join(s, NetworkSession.src_host_id == s.id).join(d, NetworkSession.dst_host_id == d.id)
            .filter(NetworkSession.carrier_mac.in_(list(macs))).order_by(NetworkSession.id)
            .yield_per(500))
    for ns, sip, dip in rows:
        try:
            if ipaddress.ip_address(dip) in net or ipaddress.ip_address(sip) in net:
                out.append({"session_id": ns.id, "src_ip": sip, "dst_ip": dip,
                            "dst_port": ns.dst_port, "protocol": ns.protocol})
        except ValueError:
            continue
        if len(out) >= 10:
            break
    return out


def review_l3_switches(db) -> list:
    from app.models import FirewallInterface, FirewallRule
    from app.parsers import alert_engine as ae
    from app.parsers import mgmt_networks as mn
    out: list = []
    sws = switch_firewalls(db)
    if not sws:
        return out
    refresh_levels(db)
    try:
        mctx = mn.build_context(db)
    except Exception:                        # noqa: BLE001
        mctx = None
    from app.models import Firewall
    sid = _site(db)
    sw_ids = {f.id for f in sws}
    fw_ifaces = [i for i in db.query(FirewallInterface).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
                 .filter(Firewall.site_id == sid, FirewallInterface.firewall_id.notin_(sw_ids))]
    fw_names = {f.id: f.name for f in db.query(Firewall).filter(Firewall.site_id == sid)}
    rmacs = router_macs(db)
    from app.parsers.edge_links import transit_networks
    transit_nets = transit_networks(db)
    for fw in sws:
        my_macs = {m for m, fid in rmacs.items() if fid == fw.id}
        svis = [i for i in fw.interfaces if i.ip_cidr and i.status != "down"]
        # a transit to the Internet firewall is the core's uplink, not a
        # zone: every VLAN is routed to it by design
        svis = [i for i in svis if _net(i.network_cidr) not in transit_nets]
        rules = db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id).all()
        route_rule = next((r for r in rules if str(r.policy_id or "").startswith(ROUTE_PREFIX)), None)
        by_acl = {}
        for r in rules:
            by_acl.setdefault(r.policy_name, []).append(r)
        bindings = bindings_of(rules)

        def acls_on(i):
            return [(d, a) for d, a in (bindings.get(i.name.lower()) or {}).items()]

        def restricts(acl, svi) -> bool:
            """The ACL bound 'in' on ``svi`` ends in something other than a
            permit-any (so it really filters the VLAN's hosts)."""
            rows = [r for r in by_acl.get(acl, []) if (r.src_zone or "").lower() == svi.lower()
                    and not str(r.policy_id or "").startswith(ACL_DENY_PREFIX)]
            if not rows:
                return False
            last = max(rows, key=lambda r: r.rule_order or 0)
            return not ((last.action or "").lower() == "permit" and (last.src or "any").lower() == "any"
                        and (last.dst or "any").lower() == "any" and (last.dst_port or "any").lower() == "any")

        # --- switch_routes_between_zones: one finding per routed lower SVI
        for lo in svis:
            if lo.purdue_level is None:
                continue
            sources, worst = [], None
            for hi in svis:
                if hi is lo or hi.purdue_level is None or hi.purdue_level <= lo.purdue_level:
                    continue
                sev = _route_sev(hi.purdue_level, lo.purdue_level)
                if sev is None:
                    continue
                sources.append(hi)
                if worst is None or _SEV_RANK[sev] > _SEV_RANK[worst]:
                    worst = sev
            # RS-05: an OT SVI (L0-L2) also routed to SVIs nobody has labelled -
            # their level is unknown, so the routing may join IT: high, "label them"
            unknown = [h for h in svis if h is not lo and h.purdue_level is None] if lo.purdue_level <= 2 else []
            if unknown and (worst is None or _SEV_RANK[worst] < _SEV_RANK["high"]):
                worst = "high"
            if not sources and not unknown:
                continue
            net = _net(lo.network_cidr)
            acl_notes = []
            for d, a in acls_on(lo):
                acl_notes.append(f"{a} bound {d} on {lo.name}")
            for hi in sources:
                for d, a in acls_on(hi):
                    if d == "in":
                        acl_notes.append(f"{a} bound in on {hi.name}")
            src_txt = ", ".join(f"{h.name} {h.network_cidr} ({_lvl(h.purdue_level)})" for h in sources + unknown)
            obs = _observed(db, my_macs, net) if net is not None else []
            to = [h.name for h in sources] + ([f"{len(unknown)} VLAN(s) of unknown level"] if unknown else [])
            title = (f"{fw.name} routes {lo.name} {lo.network_cidr} ({_lvl(lo.purdue_level)}) "
                     f"to {', '.join(to)} with no firewall")
            text = (f"The switch {fw.name} runs ip routing and has an SVI in {lo.name} "
                    f"({lo.network_cidr}, {_lvl(lo.purdue_level)}) and in {src_txt}. Traffic between "
                    "these VLANs is routed by the switch and never reaches a firewall, so the zone "
                    "boundary has no stateful enforcement point (IEC 62443-3-3 SR 5.1 RE2, SR 5.2). "
                    + (f"Access lists on the path: {'; '.join(acl_notes)}. " if acl_notes else
                       "No access list filters this routing. ")
                    + (f"{len(obs)} captured session(s) carry the switch's router MAC. " if obs else "")
                    + (f"{', '.join(h.name for h in unknown)} have no level yet - give their subnets a zone "
                       f"(Subnets & Zones) so the risk can be judged. " if unknown else "")
                    + "Remove the SVIs of the OT VLANs from the switch (or disable ip routing) so the "
                      "firewall is the only gateway, or move the boundary onto a firewall.")
            hi_max = max([h.purdue_level for h in sources] or [lo.purdue_level])
            reason = {"critical": f"Critical: the switch joins IT ({_lvl(hi_max)}) with "
                                  f"{_lvl(lo.purdue_level)} without a firewall.",
                      "high": f"High: the switch routes {_lvl(hi_max)} into {_lvl(lo.purdue_level)} "
                              "without a firewall.",
                      "medium": f"Medium: routing between {_lvl(hi_max)} and {_lvl(lo.purdue_level)} "
                                "without a firewall (critical IT <-> L0-L2, high L3 <-> L1/L2)."}[worst]
            if unknown and worst == "high" and not (sources and _route_sev(hi_max, lo.purdue_level) == "high"):
                reason = (f"High: {_lvl(lo.purdue_level)} is routed to VLAN(s) of unknown level without a "
                          "firewall; label them to judge the risk.")
            f = ae._make_finding(
                db, "switch_routes_between_zones", title[:512], text,
                {"switch": fw.name, "firewall_id": fw.id, "svi": lo.name, "network": lo.network_cidr,
                 "level": lo.purdue_level, "vlan_id": lo.vlan_id,
                 "routed_from": [{"svi": h.name, "network": h.network_cidr, "level": h.purdue_level}
                                 for h in sources],
                 "unlabelled": [{"svi": h.name, "network": h.network_cidr} for h in unknown],
                 "acls": acl_notes, "observed_sessions": obs, "severity_reason": reason},
                firewall_rule_id=route_rule.id if route_rule else None, device_name=fw.name,
                severity=worst, dedup_evidence={"rule_key": f"l3route:{fw.id}:{lo.name}"})
            if f is not None:
                out.append(f)

        # --- switch_acl_wrong_direction
        for i in svis:
            if i.purdue_level is None or i.purdue_level > 2:
                continue
            b = dict((d, a) for d, a in acls_on(i))
            if "in" not in b or "out" in b:
                continue
            net = _net(i.network_cidr)
            acl_rules = [r for r in by_acl.get(b["in"], []) if (r.src_zone or "").lower() == i.name.lower()]
            if net is None or not acl_rules or not _acl_protects(acl_rules, net):
                continue
            f = ae._make_finding(
                db, "switch_acl_wrong_direction",
                f"{fw.name}: ACL {b['in']} on {i.name} ({_lvl(i.purdue_level)}) is bound 'in' - it "
                f"filters traffic from the VLAN, not to it"[:512],
                f"Access list {b['in']} names {i.network_cidr} ({i.name}, {_lvl(i.purdue_level)}) as its "
                f"destination, so it is meant to protect the hosts in {i.name}. It is bound 'ip "
                f"access-group {b['in']} in' on {i.name}, which applies it to packets ENTERING the "
                f"switch from {i.name} - traffic from those hosts. Traffic routed into {i.name} from "
                "other VLANs is not filtered at all (IEC 62443-3-3 SR 5.2). Bind it 'out' on "
                f"{i.name} (ip access-group {b['in']} out), or bind matching ACLs 'in' on every other SVI.",
                {"switch": fw.name, "firewall_id": fw.id, "svi": i.name, "acl": b["in"],
                 "bound": "in", "network": i.network_cidr, "level": i.purdue_level,
                 "severity_reason": "Medium: the OT VLAN's intended filter does not apply to "
                                    "traffic into it."},
                device_name=fw.name, severity="medium",
                dedup_evidence={"rule_key": f"l3acl:{fw.id}:{i.name}:{b['in']}"})
            if f is not None:
                out.append(f)

        # --- switch_mgmt_svi_unrestricted
        for i in svis:
            vid = int(i.vlan_id) if str(i.vlan_id or "").isdigit() else None
            is_mgmt = bool(mn.keyword_of(i.name, i.alias, i.zone_label))
            if not is_mgmt and mctx is not None and vid is not None and vid in mctx.vlan_ids:
                is_mgmt = mctx.vlan_ids[vid][1] == mn.PURPOSE_MGMT
            if not is_mgmt and vid is not None:
                from app.models import SwitchVlan
                v = db.query(SwitchVlan).filter(SwitchVlan.vlan_id == vid).first()
                is_mgmt = bool(v and mn.keyword_of(v.vlan_name))
            if not is_mgmt or any(d == "out" for d, _a in acls_on(i)):
                continue                     # an 'out' ACL on the SVI filters traffic INTO it
            others = [o for o in svis if o is not i]
            if not others:
                continue
            unfiltered = [o for o in others if not any(d == "in" and restricts(a, o.name) for d, a in acls_on(o))]
            if not unfiltered:
                continue
            f = ae._make_finding(
                db, "switch_mgmt_svi_unrestricted",
                f"{fw.name}: management SVI {i.name} {i.network_cidr} is routed from "
                f"{len(unfiltered)} VLAN(s) without an ACL"[:512],
                f"{i.name} ({i.network_cidr}) is a management network, and {fw.name} routes it to "
                f"{', '.join(o.name for o in unfiltered)} with no access list on either side. Every "
                "host in those VLANs - IT included - can reach the management interfaces on it "
                "(IEC 62443-3-3 SR 5.1 RE1, SR 1.3; row 5.1). Restrict the management SVI with an "
                f"ACL bound 'out' on {i.name} that admits only the management workstations / jump "
                "hosts, or remove its routing.",
                {"switch": fw.name, "firewall_id": fw.id, "svi": i.name, "network": i.network_cidr,
                 "routed_from": [o.name for o in unfiltered],
                 "severity_reason": "Medium: management network reachable from every routed VLAN."},
                device_name=fw.name, severity="medium",
                dedup_evidence={"rule_key": f"l3mgmt:{fw.id}:{i.name}"})
            if f is not None:
                out.append(f)

        # --- switch_dual_gateway
        for i in svis:
            net = _net(i.network_cidr)
            if net is None:
                continue
            twins = [x for x in fw_ifaces if _net(x.network_cidr) == net and x.ip_address != i.ip_address]
            if not twins:
                continue
            lv = i.purdue_level if i.purdue_level is not None else next(
                (x.purdue_level for x in twins if x.purdue_level is not None), None)
            if lv is None or lv > 2:
                continue
            t = twins[0]
            f = ae._make_finding(
                db, "switch_dual_gateway",
                f"Two gateways in {i.name} {i.network_cidr} ({_lvl(lv)}): {fw_names.get(t.firewall_id)} "
                f"{t.name} {t.ip_address} and {fw.name} {i.name} {i.ip_address}"[:512],
                f"The OT network {i.network_cidr} ({_lvl(lv)}) has a firewall interface "
                f"({fw_names.get(t.firewall_id)} {t.name}, {t.ip_address}) and a routed SVI on the switch "
                f"({fw.name} {i.name}, {i.ip_address}). The hosts' default gateway decides which device "
                "carries their traffic, so the firewall policy applies only to hosts that happen to use "
                "it (IEC 62443-3-3 SR 5.2). Keep the firewall as the only gateway: remove the SVI's "
                "address or ip routing on the switch.",
                {"switch": fw.name, "firewall_id": fw.id, "svi": i.name, "svi_ip": i.ip_address,
                 "firewall": fw_names.get(t.firewall_id), "firewall_interface": t.name,
                 "firewall_ip": t.ip_address, "network": i.network_cidr, "level": lv,
                 "severity_reason": "High: an OT network with a second, unfiltered gateway."},
                device_name=fw.name, severity="high",
                dedup_evidence={"rule_key": f"l3gw:{fw.id}:{i.name}"})
            if f is not None:
                out.append(f)
    return out


# ------------------------------------------------- capture router knowledge --
def known_router_macs(db) -> dict:
    """MV-07 / LS-05: {normalized mac: {own interface ips}} of every firewall /
    routing-switch interface whose MAC is known (switch ARP table, an
    earlier capture).  The own addresses are EVERY interface address of the
    owning device (sub-interfaces share the parent port's MAC).  A frame
    carrying such a MAC with any other address was routed - the address is
    not the router's, nor its MAC the host's."""
    from app.models import Host
    from app.parsers.common import normalize_mac
    ip_fw = _iface_ip_owner(db)
    if not ip_fw:
        return {}
    fw_ips: dict = {}
    for ip, fids in ip_fw.items():
        for fid in fids:
            fw_ips.setdefault(fid, set()).add(ip)
    out: dict = {}
    il = list(ip_fw)
    for k in range(0, len(il), 900):
        for ip, mac in db.query(Host.ip, Host.mac).filter(Host.site_id == _site(db), Host.ip.in_(il[k:k + 900]),
                                                          Host.mac.isnot(None)):
            m = normalize_mac(mac)
            if m:
                own = out.setdefault(m, set())
                own.add(ip)
                for fid in ip_fw.get(ip, ()):
                    own |= fw_ips.get(fid, set())
    return out


def external_level_fn(db):
    """RS-04 / RS-03: function(ip, level) -> level, giving an unclassified
    globally routable address that no firewall / switch interface network
    holds the Internet level (L5), so a flow to it is judged across the
    Internet boundary (switch, then firewall) instead of "no path"."""
    try:
        nets = known_networks(db)
    except Exception:                                   # noqa: BLE001
        nets = []
    cache: dict = {}

    def f(ip, level):
        if level is not None or not ip:
            return level
        r = cache.get(ip)
        if r is None:
            try:
                a = ipaddress.ip_address(str(ip))
            except ValueError:
                cache[ip] = r = False
            else:
                cache[ip] = r = bool(a.is_global) and not any(
                    n.version == a.version and a in n for n in nets)
        return 5 if r else None
    return f


def routing_switch_ids(db) -> set:
    """Firewall ids of the site's routing switches (vendor cisco_l3_switch)."""
    from app.models import Firewall
    return {fid for (fid,) in db.query(Firewall.id).filter(Firewall.site_id == _site(db),
                                                              Firewall.vendor == VENDOR)}


def known_networks(db) -> list:
    """The interface networks of the site's firewalls / routing switches,
    plus the SSL-VPN tunnel pools (VD-02b: a VPN user's address is the
    firewall's, so a frame from it into an interface network was routed)."""
    from app.models import Firewall, FirewallInterface
    nets = []
    for (c,) in db.query(FirewallInterface.network_cidr).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == _site(db), FirewallInterface.network_cidr.isnot(None)):
        n = _net(c)
        if n is not None and 0 < n.prefixlen < n.max_prefixlen:
            nets.append(n)
    try:
        from app.parsers import rule_match as rm
        from app.parsers.vpn import VpnContext
        for _fid, spec, _t in VpnContext.build(db).pools:
            v, lo, hi = rm.addr_bounds(spec)
            cls = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
            nets.extend(ipaddress.summarize_address_range(cls(lo), cls(hi)))
    except Exception:                                   # noqa: BLE001 - pools are a bonus
        log.warning("VPN pool networks unavailable", exc_info=True)
    return nets


def multi_network_macs(mac_ips: dict, own_ips: dict, nets: list) -> set:
    """MACs seen with two or more addresses, other than their own, in two or
    more different known interface networks: a router, not a dual-homed
    host.  A MAC with no address of its own (nothing in ARP / NDP) is given
    its first-seen address as its own, like detect_gateway_macs, so one
    spoofed or stray frame never makes a host a router (A-22)."""
    from app.parsers.common import normalize_mac
    out = set()
    if not nets:
        return out
    nets = sorted(set(nets), key=lambda n: (-n.prefixlen, str(n)))   # most specific first

    def _net_of(a):
        for n in nets:
            if a.version == n.version and a in n:
                return n
        return None

    for mac, ips in mac_ips.items():
        own = set(own_ips.get(mac, set()))
        ordered = list(ips)
        if not own and ordered:
            own = {ordered[0]}
        hit: dict = {}
        for ip in ordered:
            if ip in own:
                continue
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            n = _net_of(a)
            if n is not None:
                hit.setdefault(n, set()).add(ip)
        if len(hit) >= 2 and sum(len(v) for v in hit.values()) >= 2:
            m = normalize_mac(mac)
            if m:
                out.add(m)
    return out


def routed_by(mac_pairs: dict, own_ips: dict, nets: list) -> set:
    """MACs that sent frames for two or more different source addresses
    (not their own) into another known interface network: the source and
    destination of such a frame lie in two different known networks, so the
    frame was routed and the MAC on it is the router's.  Two distinct routed
    sources are required (one stray or spoofed frame is not a router)."""
    from app.parsers.common import normalize_mac
    out = set()
    if not nets:
        return out
    nets = sorted(set(nets), key=lambda n: (-n.prefixlen, str(n)))

    def _net_of(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for n in nets:
            if a.version == n.version and a in n:
                return n
        return None

    for mac, pairs in mac_pairs.items():
        own = set(own_ips.get(mac, ()))
        routed = set()
        for sip, dip in pairs:
            if sip in own:
                continue
            ns, nd = _net_of(sip), _net_of(dip)
            if ns is not None and nd is not None and ns != nd:
                routed.add(sip)
        if len(routed) >= 2:
            m = normalize_mac(mac)
            if m:
                out.add(m)
    return out
