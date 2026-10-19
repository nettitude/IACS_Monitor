"""Routed-OT follow-up: automatic levels for the edge firewall behind a
routing core.

A routing switch (the OT core) hands everything bound for the Internet to a
firewall over a small transit network that holds no devices of its own.  No
capture shows hosts there, so neither the subnet zones nor the host-based
suggestions can level it - and without a level on the transit and on the
firewall's Internet leg, no path L1 -> switch -> firewall -> Internet exists
and Internet egress through the firewall is never reported.

``apply(db)`` levels exactly that pattern, automatically and visibly
(``purdue_suggestion_source = "edge_auto"``):

* **transit link** - a firewall interface whose network is also a routing
  switch's SVI network, small (/28 or longer) and empty (no address in it
  but the two devices' own interface addresses).  It takes the top of the OT
  stack the switch routes onto it: the highest of the switch's other SVI
  levels at L3 or below (L3 when the core routes site operations), else the
  lowest level it routes.  The switch's SVI on the transit then follows the
  firewall interface (``l3_switch.refresh_levels``).
* **Internet leg** - on that same firewall, an interface that carries the
  default route or has FortiOS role ``wan``, or whose network is public:
  L5.

An operator label (Firewall Topology) or a declared subnet zone always wins;
a level that no longer applies is cleared.  Firewalls that are not behind a
routing switch are never touched (series pairs and multi-firewall chains are
levelled by the operator and by the link suggestions).
"""
from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger(__name__)

EDGE_SOURCE = "edge_auto"
#: transit networks are point-to-point or nearly so
_MAX_TRANSIT_ADDRESSES = 16


def _net(cidr):
    try:
        return ipaddress.ip_network(str(cidr).strip(), strict=False) if cidr else None
    except ValueError:
        return None


def transit_level(levels) -> object:
    """The level a transit link takes from the levels routed onto it."""
    lv = [float(x) for x in levels if x is not None]
    if not lv:
        return None
    ot = [x for x in lv if x <= 3]
    pick = max(ot) if ot else min(lv)
    return int(pick) if pick == int(pick) else pick


def _is_outside(iface) -> bool:
    if (iface.role or "").lower() == "wan":
        return True
    n = _net(iface.network_cidr)
    return bool(n is not None and n.is_global)


def apply(db) -> int:
    """Set / clear the automatic edge levels.  Returns the number of
    interfaces changed."""
    from app.models import Firewall, FirewallInterface, Host
    from app.parsers.l3_switch import _site, switch_firewalls
    sid = _site(db)
    switches = switch_firewalls(db)
    sw_ids = {s.id for s in switches}
    sw_nets: dict = {}
    for s in switches:
        for i in s.interfaces:
            n = _net(i.network_cidr)
            if n is not None and n.prefixlen > 0:
                sw_nets.setdefault(n, []).append((s, i))
    fws = (db.query(Firewall).filter(Firewall.site_id == sid, Firewall.id.notin_(sw_ids)).all()
           if sw_ids else db.query(Firewall).filter(Firewall.site_id == sid).all())
    infra_ips = set()
    for (ip,) in db.query(FirewallInterface.ip_address).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == sid, FirewallInterface.ip_address.isnot(None)):
        infra_ips.add(str(ip))
    hosts = None
    changed = 0

    def empty(n) -> bool:
        nonlocal hosts
        if hosts is None:
            hosts = []
            for (ip,) in db.query(Host.ip).filter(Host.site_id == sid, Host.ip.isnot(None)):
                try:
                    hosts.append(ipaddress.ip_address(ip))
                except ValueError:
                    continue
        return not any(a.version == n.version and a in n and str(a) not in infra_ips for a in hosts)

    def put(i, lvl) -> None:
        nonlocal changed
        if i.purdue_level is not None and i.purdue_suggestion_source != EDGE_SOURCE:
            return                                  # operator label / declared zone wins
        if lvl is None:
            if i.purdue_suggestion_source == EDGE_SOURCE:
                i.purdue_level, i.purdue_suggestion_source = None, None
                changed += 1
            return
        if (i.purdue_level, i.purdue_suggestion_source) != (lvl, EDGE_SOURCE):
            i.purdue_level, i.purdue_suggestion_source = lvl, EDGE_SOURCE
            i.suggested_purdue_level = None
            changed += 1

    for fw in fws:
        transit = {}
        for i in fw.interfaces:
            n = _net(i.network_cidr)
            if (n is None or n not in sw_nets or n.num_addresses > _MAX_TRANSIT_ADDRESSES
                    or n.is_global or not empty(n)):
                continue
            routed = []
            for s, svi in sw_nets[n]:
                routed += [x.purdue_level for x in s.interfaces
                           if x.id != svi.id and x.purdue_level is not None]
            transit[i.id] = transit_level(routed)
        for i in fw.interfaces:
            if i.id in transit:
                put(i, transit[i.id])
            elif transit and _is_outside(i):
                put(i, 5)
            else:
                put(i, None)
    if changed:
        db.flush()
    return changed


def transit_networks(db) -> set:
    """Networks shaped like a transit from a routing switch to a firewall
    (shared by an SVI and a firewall interface, small, empty), whoever set
    their level."""
    from app.models import Firewall, FirewallInterface, Host
    from app.parsers.l3_switch import _site, switch_firewalls
    sid = _site(db)
    switches = switch_firewalls(db)
    if not switches:
        return set()
    sw_ids = {s.id for s in switches}
    sw_nets = {n for s in switches for i in s.interfaces
               for n in [_net(i.network_cidr)] if n is not None and n.prefixlen > 0}
    infra_ips, fw_nets = set(), set()
    for i in db.query(FirewallInterface).join(Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == sid):
        if i.ip_address:
            infra_ips.add(str(i.ip_address))
        n = _net(i.network_cidr)
        if n is not None and i.firewall_id not in sw_ids:
            fw_nets.add(n)
    cand = {n for n in sw_nets & fw_nets if n.num_addresses <= _MAX_TRANSIT_ADDRESSES and not n.is_global}
    if not cand:
        return set()
    out = set(cand)
    for (ip,) in db.query(Host.ip).filter(Host.site_id == sid, Host.ip.isnot(None)):
        if ip in infra_ips:
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        out -= {n for n in out if n.version == a.version and a in n}
    return out


def describe(db) -> dict:
    """{network cidr: (level, kind, label)} of the networks levelled here -
    shown as the suggestion of those subnets on Subnets & Zones."""
    from app.models import Firewall, FirewallInterface
    from app.parsers.l3_switch import _site
    out = {}
    for i, fw in db.query(FirewallInterface, Firewall).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            Firewall.site_id == _site(db), FirewallInterface.purdue_suggestion_source == EDGE_SOURCE):
        n = _net(i.network_cidr)
        if n is None:
            continue
        if float(i.purdue_level) == 5:
            out[str(n)] = (5, "internet", f"Internet (outside {fw.name})")
        else:
            out[str(n)] = (i.purdue_level, "transit", f"Transit to {fw.name}")
    return out
