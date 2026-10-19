"""
Interfaces of non-FortiGate firewalls (mixed-vendor tabletop MV-01, MV-08).

A FortiGate upload creates a Firewall row with FirewallInterface rows, so it
gets Purdue levels per interface, link proposals and an upstream chain on
the FW Topology page.  The other vendors used to store rules only.  This
module reads the interface sections of their configs so every vendor gets
the same shape:

* Palo Alto (XML and ``set``): layer-3 ``network interface`` entries (and
  sub-interfaces / units) with their IPs, and zone -> interface membership
  (FirewallZoneDef, like FortiOS zones; rules name zones).
* Cisco ASA: ``interface`` blocks with ``nameif`` (the name the ACL
  bindings and rules use - stored as the interface name, the physical name
  in the alias), ``security-level`` and ``ip address``.
* Cisco IOS: ``interface`` blocks with ``ip address`` (rules name the
  interface the ACL is bound to).
* pfSense: ``<interfaces>`` (wan / lan / optN keys the rules use) with
  ``ipaddr`` / ``subnet`` and the description.

``implicit_rules`` (MV-08) adds the ASA's implicit permits: traffic from an
interface WITHOUT an inbound ACL to every lower-security interface is
allowed by default.  They are stored as permit rows with policy_id
``implicit:<from>><to>`` and reported by ``rule_implicit_permit``.

Device types: an ASA is told from IOS here (``nameif`` / ``security-level``
/ ``ASA Version`` / ``access-group .. interface``): ``cisco_asa``, which
also gives it the right NAT timing (post-NAT, MV-02).
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as _safe_ET  # AU D11: no entity expansion / external entities
from typing import Optional

log = logging.getLogger(__name__)

IMPLICIT_PREFIX = "implicit:"


class NameTakenByFortiGate(ValueError):
    """The FirewallDevice name is a FortiGate's Firewall row of the site."""


def is_implicit(rule) -> bool:
    pid = rule.get("policy_id") if isinstance(rule, dict) else getattr(rule, "policy_id", None)
    return str(pid or "").startswith(IMPLICIT_PREFIX)


def _iface(name, ip_cidr=None, alias=None, typ="physical", vlan=None, parent=None, security=None,
           shutdown=False, mgmt_only=False, vdom=None):
    return {"name": name, "ip_cidr": ip_cidr, "alias": alias, "type": typ, "vlan_id": vlan,
            "parent": parent, "security_level": security, "status": "down" if shutdown else "up",
            "mgmt_only": mgmt_only, "vdom": vdom}


def implicit_id(a: str, b: str) -> str:
    """Policy id of the implicit permit a -> b, always <= 32 chars and distinct
    per interface pair (long nameifs are hashed, never truncated)."""
    pid = f"{IMPLICIT_PREFIX}{a}>{b}"
    if len(pid) <= 32:
        return pid
    return f"{IMPLICIT_PREFIX}{hashlib.sha1(f'{a}>{b}'.encode()).hexdigest()[:12]}"


def _mask_cidr(ip: str, mask: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{mask}"))
    except ValueError:
        return None


# ------------------------------------------------------------------ Cisco --
def is_asa(text: str) -> bool:
    return bool(re.search(r"^ASA Version|^\s+nameif\s|^\s+security-level\s|"
                          r"^access-group\s+\S+\s+(in|out)\s+interface\s", text, re.MULTILINE))


def parse_cisco_interfaces(text: str) -> dict:
    asa = is_asa(text)
    hostname = None
    out, cur = [], None
    acl_in, acl_out = {}, {}
    acl_global = None
    same_sec = False
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith(("!", ":")):
            if cur is not None and s.startswith("!"):
                out.append(cur)
                cur = None
            continue
        toks = s.split()
        indented = raw[:1] in (" ", "\t")
        if not indented:
            if cur is not None:
                out.append(cur)
                cur = None
            if toks[0] == "hostname" and len(toks) > 1:
                hostname = toks[1]
            elif toks[0] == "interface" and len(toks) > 1:
                cur = {"phys": " ".join(toks[1:]), "nameif": None, "sec": None, "ip": None,
                       "shutdown": False, "vlan": None, "mgmt_only": False}
            elif toks[0] == "access-group" and len(toks) >= 5 and toks[3] == "interface":
                (acl_in if toks[2] == "in" else acl_out)[toks[4]] = toks[1]
            elif toks[0] == "access-group" and len(toks) >= 3 and toks[2] == "global":
                acl_global = toks[1]
            elif toks[:2] == ["same-security-traffic", "permit"] and "inter-interface" in toks:
                same_sec = True
            continue
        if cur is None:
            continue
        if toks[0] == "nameif" and len(toks) > 1:
            cur["nameif"] = toks[1]
        elif toks[0] == "security-level" and len(toks) > 1 and toks[1].isdigit():
            cur["sec"] = int(toks[1])
        elif toks[:2] == ["ip", "address"] and len(toks) >= 4 and toks[2] not in ("dhcp",):
            cur["ip"] = _mask_cidr(toks[2], toks[3])
        elif toks[0] == "shutdown":
            cur["shutdown"] = True
        elif toks[0] == "management-only":
            cur["mgmt_only"] = True
        elif toks[0] == "vlan" and len(toks) > 1 and toks[1].isdigit():
            cur["vlan"] = toks[1]
        elif toks[:2] == ["ip", "access-group"] and len(toks) >= 4 and toks[3] in ("in", "out"):
            (acl_in if toks[3] == "in" else acl_out)[cur["nameif"] or cur["phys"]] = toks[2]
    if cur is not None:
        out.append(cur)
    ifaces = []
    for c in out:
        if asa:
            if not c["nameif"]:
                continue
            alias = c["phys"] + (f" (security-level {c['sec']})" if c["sec"] is not None else "")
            ifaces.append(_iface(c["nameif"], c["ip"], alias, "vlan" if c["vlan"] else "physical",
                                 c["vlan"], security=c["sec"], shutdown=c["shutdown"],
                                 mgmt_only=c["mgmt_only"]))
        elif c["ip"]:
            ifaces.append(_iface(c["phys"], c["ip"], None, "physical", shutdown=c["shutdown"]))
    return {"hostname": hostname, "interfaces": ifaces, "zones": {}, "acl_in": acl_in, "acl_out": acl_out,
            "acl_global": acl_global, "same_security": same_sec, "asa": asa}


def implicit_rules(info: dict) -> list[dict]:
    """MV-08: ASA implicit permits.  From an interface with no inbound ACL,
    traffic to every interface of a lower security level is permitted
    (and to equal levels with ``same-security-traffic permit
    inter-interface``).  Left out: ``management-only`` interfaces (no
    through traffic), destinations with an outbound ACL (their ACE rows
    decide; the model has no AND of two ACLs), and everything when a
    ``global`` access list exists (it ends in an implicit deny for traffic
    no interface ACL permitted)."""
    if not info.get("asa") or info.get("acl_global"):
        return []
    ifs = [i for i in info["interfaces"] if i.get("security_level") is not None and i["status"] != "down"
           and not i.get("mgmt_only")]
    acl_out = info.get("acl_out") or {}
    out = []
    for a in ifs:
        if a["name"] in info.get("acl_in", {}):
            continue
        for b in ifs:
            if b is a or b["name"] in acl_out:
                continue
            if b["security_level"] > a["security_level"] or (
                    b["security_level"] == a["security_level"] and not info.get("same_security")):
                continue
            equal = b["security_level"] == a["security_level"]
            out.append({
                "device_name": None,
                "policy_id": implicit_id(a["name"], b["name"]),
                "policy_name": (f"implicit permit: security-level {a['security_level']} ({a['name']}) "
                                + ("= " if equal else "> ")
                                + f"{b['security_level']} ({b['name']}), no inbound ACL on {a['name']}"
                                + (" (same-security-traffic permit inter-interface)" if equal else "")),
                "src": "any", "dst": "any", "protocol": "any", "dst_port": "any", "action": "permit",
                "raw_line": f"(implicit) no access-group in interface {a['name']}; security-level "
                            f"{a['security_level']} {'=' if equal else '>'} {b['security_level']}",
                "src_zone": a["name"], "dst_zone": b["name"], "enabled": True, "rule_order": 100000,
            })
    return out


# --------------------------------------------------------------- Palo Alto --
def parse_panos_xml_interfaces(text: str) -> dict:
    root = _safe_ET.fromstring(text)
    ifaces = []
    for eth in root.findall(".//network/interface/ethernet/entry") + \
            root.findall(".//network/interface/aggregate-ethernet/entry"):
        name = eth.get("name")
        l3 = eth.find("layer3")
        if l3 is None:
            continue
        ip = next((e.get("name") for e in l3.findall("ip/entry")), None)
        ifaces.append(_iface(name, ip if ip and "/" in ip else None, eth.findtext("comment")))
        for u in l3.findall("units/entry"):
            uip = next((e.get("name") for e in u.findall("ip/entry")), None)
            ifaces.append(_iface(u.get("name"), uip if uip and "/" in uip else None,
                                 u.findtext("comment"), "vlan", u.findtext("tag"), parent=name))
    for kind, typ in (("vlan", "vlan"), ("loopback", "loopback"), ("tunnel", "tunnel")):
        for vl in root.findall(f".//network/interface/{kind}/units/entry"):
            ip = next((e.get("name") for e in vl.findall("ip/entry")), None)
            ifaces.append(_iface(vl.get("name"), ip if ip and "/" in ip else None, vl.findtext("comment"), typ))
    zones = {}
    vsys_entries = root.findall(".//vsys/entry")
    if len(vsys_entries) > 1:
        # multi-vsys: zone names repeat per vsys - key them "<vsys>/<zone>"
        for vs in vsys_entries:
            for z in vs.findall("zone/entry"):
                members = [m.text.strip() for m in z.findall("network/layer3/member") if m.text]
                zones[f"{vs.get('name')}/{z.get('name')}"] = members
    else:
        for z in root.findall(".//zone/entry"):
            members = [m.text.strip() for m in z.findall("network/layer3/member") if m.text]
            zones[z.get("name")] = members
    hostname = root.findtext(".//deviceconfig/system/hostname")
    return {"hostname": hostname, "interfaces": ifaces, "zones": zones, "acl_in": {}, "asa": False}


def parse_panos_set_interfaces(text: str) -> dict:
    ifaces, zones, hostname = {}, {}, None
    for raw in text.splitlines():
        toks = raw.strip().replace('"', "").split()
        if len(toks) < 3 or toks[0] != "set":
            continue
        t = toks[1:]
        if t[0] == "vsys" and len(t) > 2:
            t = t[2:]
        if t[:3] == ["deviceconfig", "system", "hostname"] and len(t) > 3:
            hostname = t[3]
        m = None
        kind = t[2] if len(t) > 3 and t[:2] == ["network", "interface"] else None
        if kind in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
            m = t[3:]
        if m:
            name = m[0]
            rest = m[1:]
            if kind in ("loopback", "tunnel", "vlan"):
                # set network interface loopback units loopback.1 ip 10.0.0.1/32
                if rest[:1] == ["units"] and len(rest) > 1:
                    name, rest = rest[1], rest[2:]
                    ifaces.setdefault(name, _iface(name, typ=kind))
                else:
                    continue
            elif rest[:2] == ["layer3", "units"] and len(rest) > 2:
                name, rest = rest[2], rest[3:]
                ifaces.setdefault(name, _iface(name, typ="vlan", parent=m[0]))
            elif rest[:1] == ["layer3"]:
                rest = rest[1:]
                ifaces.setdefault(name, _iface(name))
            else:
                continue
            if rest[:1] == ["ip"] and len(rest) > 1 and "/" in rest[1]:
                ifaces[name]["ip_cidr"] = rest[1]
            elif rest[:1] == ["tag"] and len(rest) > 1:
                ifaces[name]["vlan_id"] = rest[1]
            continue
        if t[:1] == ["zone"] and len(t) > 4 and t[2:4] == ["network", "layer3"]:
            members = [x.strip("[]") for x in t[4:] if x not in ("[", "]")]
            zones.setdefault(t[1], [])
            zones[t[1]] += [x for x in members if x and x not in zones[t[1]]]
    return {"hostname": hostname, "interfaces": list(ifaces.values()), "zones": zones,
            "acl_in": {}, "asa": False}


# ----------------------------------------------------------------- pfSense --
def parse_pfsense_interfaces(text: str) -> dict:
    root = _safe_ET.fromstring(text)
    ifaces = []
    node = root.find("interfaces")
    for el in list(node) if node is not None else []:
        ip, sub = (el.findtext("ipaddr") or "").strip(), (el.findtext("subnet") or "").strip()
        cidr = None
        if ip and sub.isdigit():
            try:
                cidr = str(ipaddress.ip_interface(f"{ip}/{sub}"))
            except ValueError:
                cidr = None
        # pfSense: an interface without <enable/> is disabled
        ifaces.append(_iface(el.tag, cidr, (el.findtext("descr") or "").strip() or None,
                             shutdown=el.find("enable") is None))
    return {"hostname": root.findtext("system/hostname"), "interfaces": ifaces, "zones": {},
            "acl_in": {}, "asa": False}


def pfsense_iface_nets(text: str) -> dict:
    """{'lan': '10.50.0.0/16', 'lanip': '10.50.0.1/32', ...} (MV-06)."""
    out = {}
    try:
        info = parse_pfsense_interfaces(text)
    except ET.ParseError:
        return out
    for i in info["interfaces"]:
        if not i["ip_cidr"]:
            continue
        try:
            itf = ipaddress.ip_interface(i["ip_cidr"])
        except ValueError:
            continue
        out[i["name"]] = str(itf.network)
        out[i["name"] + "ip"] = f"{itf.ip}/{itf.max_prefixlen}"
    return out


def extract(text: str, device_type: str) -> Optional[dict]:
    try:
        if device_type in ("cisco_ios", "cisco_asa"):
            return parse_cisco_interfaces(text)
        if device_type == "panos_xml":
            return parse_panos_xml_interfaces(text)
        if device_type == "panos_set":
            return parse_panos_set_interfaces(text)
        if device_type == "pfsense":
            return parse_pfsense_interfaces(text)
    except (ET.ParseError, ValueError, IndexError):
        log.warning("interface extraction failed for %s", device_type, exc_info=True)
    return None


# ------------------------------------------------------------ persistence --
def sync_firewall(db, device, device_type: str, info: dict, source_file=None):
    """Create / update the Firewall row of a non-FortiGate upload and its
    FirewallInterface / FirewallZoneDef rows (operator fields - level,
    side, zone label, links - are kept on re-ingest).  Returns the Firewall."""
    from datetime import datetime, timezone
    from app.models import Firewall, FirewallInterface, FirewallZoneDef
    now = datetime.now(timezone.utc)
    fw = device.firewall_id and db.get(Firewall, device.firewall_id)
    if not fw:
        fw = db.query(Firewall).filter(Firewall.site_id == device.site_id,
                                       Firewall.name == device.name).first()
    if fw is not None and fw.vendor == "fortigate" and device_type != "fortigate":
        # a FortiGate of the same name owns that row (its interfaces carry
        # the operator's labels): never convert it
        raise NameTakenByFortiGate(f"'{device.name}' is a FortiGate of this site: its interfaces are "
                                   f"not replaced by this {device_type} config (use another "
                                   "firewall_device_name to model this firewall's interfaces)")
    if fw is None:
        fw = Firewall(site_id=device.site_id, name=device.name, device_name=info.get("hostname"),
                      vendor=device_type, source_file=source_file, config_uploaded_at=now)
        db.add(fw)
        db.flush()
    else:
        fw.vendor = device_type
        fw.device_name = info.get("hostname") or fw.device_name
        fw.source_file = source_file or fw.source_file
        fw.config_uploaded_at = now
    device.firewall_id = fw.id
    existing = {i.name: i for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id)}
    seen = set()
    for it in info["interfaces"]:
        name = str(it["name"])[:64]
        seen.add(name)
        cidr = it.get("ip_cidr")
        ip = pre = net = None
        if cidr:
            try:
                itf = ipaddress.ip_interface(cidr)
                ip, pre, net = str(itf.ip), itf.network.prefixlen, str(itf.network)
            except ValueError:
                cidr = None
        row = existing.get(name)
        if row is None:
            row = FirewallInterface(firewall_id=fw.id, name=name)
            db.add(row)
        row.ip_address, row.prefix_len, row.ip_cidr, row.network_cidr = ip, pre, cidr, net
        row.alias = (it.get("alias") or None) and str(it["alias"])[:128]
        row.iface_type = it.get("type")
        row.vlan_id = it.get("vlan_id")
        row.status = it.get("status")
        row.role = f"security-level {it['security_level']}"[:32] if it.get("security_level") is not None else None
        row.is_mgmt_only = bool(it.get("mgmt_only"))
    db.flush()
    from app.parsers.forti_config_parser import _prune_removed_interfaces
    _prune_removed_interfaces(db, fw, seen, None)
    by_name = {i.name: i for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id)}
    for it in info["interfaces"]:
        if it.get("parent") and it["name"] in by_name and it["parent"] in by_name:
            by_name[it["name"]].parent_interface_id = by_name[it["parent"]].id
    db.query(FirewallZoneDef).filter(FirewallZoneDef.firewall_id == fw.id).delete(synchronize_session="fetch")
    for z, members in (info.get("zones") or {}).items():
        vdom, _, zname = str(z).rpartition("/")          # "<vsys>/<zone>" on multi-vsys PAN-OS
        db.add(FirewallZoneDef(firewall_id=fw.id, vdom=vdom or None, name=zname[:128], kind="zone",
                               intrazone=None, members=list(members), members_resolved=True,
                               source_file=source_file))
    n = db.query(Firewall).filter(Firewall.site_id == device.site_id).count()
    if n >= 2:
        db.query(Firewall).filter(Firewall.site_id == device.site_id).update(
            {"is_multi_fw": True}, synchronize_session="fetch")
    db.flush()
    return fw


# ------------------------------------------------------------------ review --
def review_implicit_permits(db) -> list:
    """``rule_implicit_permit`` (MV-08; SR 5.2, SR 5.1; row 3.1 default deny):
    an implicit permit (ASA: higher -> lower security level from an
    interface without an inbound ACL) lets ANY traffic through with no
    written rule.  medium; high when it reaches L2 or lower."""
    from app.models import Firewall, FirewallInterface, FirewallRule
    from app.parsers import alert_engine as ae
    from app.purdue import fmt_level
    out = []
    rows = db.query(FirewallRule).filter(FirewallRule.enabled.is_(True),
                                         FirewallRule.policy_id.like(IMPLICIT_PREFIX + "%")).all()
    seen = set()
    for r in rows:
        if (str(r.policy_id).startswith((IMPLICIT_PREFIX + "route", IMPLICIT_PREFIX + "acldeny"))
                or r.firewall_id is None or (r.action or "").lower() != "permit"):
            continue
        key = (r.firewall_id, r.src_zone, r.dst_zone)
        if key in seen:
            continue
        seen.add(key)
        fw = db.get(Firewall, r.firewall_id)
        ifs = {i.name: i for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == r.firewall_id)}
        a, b = ifs.get(r.src_zone), ifs.get(r.dst_zone)
        la = a.purdue_level if a is not None else None
        lb = b.purdue_level if b is not None else None
        deep = lb is not None and lb <= 2
        sev = "high" if deep else "medium"
        lv = lambda x: f" ({fmt_level(x)})" if x is not None else ""
        name = fw.name if fw else r.device_name
        title = (f"Implicit permit on {name}: {r.src_zone}{lv(la)} → {r.dst_zone}{lv(lb)}, any service "
                 f"(no inbound ACL on {r.src_zone})")
        text = (f"{name} has no access list bound inbound on '{r.src_zone}', so every connection from "
                f"'{r.src_zone}' to the lower-security interface '{r.dst_zone}' is permitted by the ASA's "
                f"security-level default ({r.policy_name}). Nothing in the configuration states this "
                "permit and it allows every service - a boundary must deny by default and allow only "
                "documented conduits (IEC 62443-3-3 SR 5.2, SR 5.1; row 3.1). Bind an inbound ACL to "
                f"'{r.src_zone}' that permits only the required flows.")
        f = ae._make_finding(
            db, "rule_implicit_permit", title[:512], text,
            {"firewall": name, "firewall_id": r.firewall_id, "policy_id": r.policy_id,
             "from_interface": r.src_zone, "to_interface": r.dst_zone,
             "from_level": la, "to_level": lb, "implicit": r.raw_line,
             "severity_reason": ("High: the implicit permit reaches the control zone or below "
                                 f"({fmt_level(lb)})." if deep else
                                 "Medium: an unwritten any-service permit (high when it reaches L2 or "
                                 "lower).")},
            firewall_rule_id=r.id, device_name=name, severity=sev,
            dedup_evidence={"rule_key": f"implicit:{r.firewall_id}:{r.src_zone}>{r.dst_zone}"})
        if f is not None:
            out.append(f)
    return out
