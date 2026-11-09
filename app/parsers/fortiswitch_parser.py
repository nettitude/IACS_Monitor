"""
FortiLink-managed FortiSwitches (owner 2026-10-19, "build it, FortiLink-managed first").

Everything about a FortiLink-managed switch lives in the FortiGate's
``show full-configuration``: ``config switch-controller managed-switch`` (one
entry per switch with its ``ports`` - native VLAN, allowed VLANs,
port-security policy, admin state, description, FortiLink uplink), the VLANs
as ``config system interface`` entries on the FortiLink interface (name,
``vlanid``, and the operator's Purdue label once set on the FW Topology
Builder) and ``config switch-controller security-policy 802-1X``.  This pass
writes the same rows the Cisco / HP switch parsers write (SwitchInterface,
SwitchVlan) so the lanes, VLAN checks and the inventory cover FortiSwitches,
plus the port-security policy and the uplink flag the two FortiSwitch reviews
use (``review_switch_port_nac``, ``review_switch_unused_ports``).  L2 only:
no enforcement point is created (owner's rule: Cisco only for L3).
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models import FirewallInterface, SwitchInterface, SwitchVlan
from app.parsers.switch_parser import _upsert_switch_vlan
from app.sites import scope_site_id

log = logging.getLogger(__name__)

SOURCE_PREFIX = "fortilink:"


def _as_list(v):
    if v is None or v == "":
        return []
    return [str(x).strip('"') for x in v] if isinstance(v, (list, tuple)) else [str(v).strip('"')]


def _s(d: dict, k: str, default: str = "") -> str:
    v = d.get(k, default)
    v = v[0] if isinstance(v, (list, tuple)) and v else v
    return str(v if v is not None else default).strip('"')


def nac_policies(parsed: dict) -> dict:
    """{policy name: {open_auth, mac_auth_bypass, user_group}} from the 802.1X policies."""
    out = {}
    for n, c in (parsed.get("switch-controller security-policy 802-1X") or {}).items():
        if isinstance(c, dict):
            out[str(n).strip('"')] = {"open_auth": _s(c, "open-auth", "disable") == "enable",
                                      "mac_auth_bypass": _s(c, "mac-auth-bypass", "disable") == "enable",
                                      "user_group": _s(c, "user-group") or None}
    return out


def policy_mode(pol: Optional[dict]) -> Optional[str]:
    """"open-auth" / "802.1x-mab" / "802.1x" for a parsed 802.1X policy, None when unknown
    (owner 2026-11-09: open-auth admits unauthenticated devices, so such a port is unprotected)."""
    if not isinstance(pol, dict):
        return None
    if pol.get("open_auth"):
        return "open-auth"
    return "802.1x-mab" if pol.get("mac_auth_bypass") else "802.1x"


def ingest_fortilink_switches(db: DBSession, parsed: dict, fw_row, source_file: Optional[str]) -> dict:
    """Write the managed switches of ``parsed`` as switch rows of the firewall's
    site.  Everything this firewall's pass wrote before is replaced (switches that
    left the config included); VLAN rows take the Purdue label of the FortiGate's
    VLAN interface (source "firewall_propagated") unless set by hand."""
    managed = parsed.get("switch-controller managed-switch") or {}
    if not isinstance(managed, dict):
        managed = {}
    sid = scope_site_id(db)
    source = f"{SOURCE_PREFIX}{fw_row.name or fw_row.device_name or fw_row.id}"
    # replace everything this firewall's pass wrote before - switches no longer in the config go
    # too, so their findings can auto-resolve (audit 2026-10-19).  One row per (site, switch, port)
    # is the schema: a switch of the same name written by another firewall's pass is replaced as
    # well (last writer wins; a FortiSwitch is managed by one FortiGate / cluster).
    names = {(_s(cfg, "name") or str(key).strip('"')) for key, cfg in managed.items() if isinstance(cfg, dict)}
    db.query(SwitchInterface).filter(SwitchInterface.site_id == sid, SwitchInterface.source_file == source)\
        .delete(synchronize_session=False)
    if names:
        db.query(SwitchInterface).filter(SwitchInterface.site_id == sid, SwitchInterface.device_name.in_(names),
                                         SwitchInterface.source_file.like(f"{SOURCE_PREFIX}%")).delete(synchronize_session=False)
    for sv in db.query(SwitchVlan).filter(SwitchVlan.site_id == sid, SwitchVlan.source_file == source):
        if sv.purdue_level_source == "firewall_propagated":
            sv.purdue_level, sv.purdue_level_source = None, None       # re-derived below when still labelled
    db.flush()
    if not managed:
        return {"switches": 0, "ports": 0, "vlans": 0}
    # VLAN interfaces of the FortiGate: name -> (vlan id, level)
    levels = {str(i.name).lower(): i.purdue_level
              for i in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw_row.id)}
    vlan_of: dict = {}
    for iname, icfg in (parsed.get("system interface") or {}).items():
        if isinstance(icfg, dict) and icfg.get("vlanid") not in (None, ""):
            try:
                vlan_of[str(iname).strip('"')] = int(_s(icfg, "vlanid"))
            except ValueError:
                pass
    policies = nac_policies(parsed)
    n_sw = n_ports = 0
    vlans_seen: set = set()
    for key, cfg in managed.items():
        if not isinstance(cfg, dict):
            continue
        device = _s(cfg, "name") or str(key).strip('"')
        serial = _s(cfg, "switch-id") or str(key).strip('"')
        peer = _s(cfg, "fsw-wan1-peer") or None
        ports = cfg.get("ports") or {}
        vlan_ports: dict = {}
        # VLAN names the ports reference decide the id lookup (a tag reused on another parent
        # interface must not rename or relabel the switch VLAN - audit 2026-10-19)
        lag_members: set = set()
        for pname, pc in (ports.items() if isinstance(ports, dict) else []):
            if isinstance(pc, dict) and _s(pc, "type") == "trunk":
                lag_members |= {str(m).strip('"') for m in _as_list(pc.get("members"))}
        for pname, pc in (ports.items() if isinstance(ports, dict) else []):
            if not isinstance(pc, dict):
                continue
            pname = str(pname).strip('"')
            native = _s(pc, "vlan") or None
            native_id = vlan_of.get(native) if native else None
            allowed_names = [str(a).strip('"') for a in _as_list(pc.get("allowed-vlans"))]
            allowed = [vlan_of.get(a) for a in allowed_names]
            allowed = [a for a in allowed if a is not None]
            all_vlans = _s(pc, "allowed-vlans-all", "disable") == "enable"
            # uplinks: the FortiLink port, an ISL to another FortiSwitch (tiered FortiLink / MCLAG:
            # isl-peer-* keys), a user LAG and its member ports (audit 2026-10-19)
            isl_peer = _s(pc, "isl-peer-device-name") or _s(pc, "isl-peer-device-sn") or ""
            isl = bool(isl_peer or _s(pc, "isl-peer-port-name") or _s(pc, "isl-local-trunk-name") or _s(pc, "isl-peer-port"))
            fortilink = _s(pc, "fortilink-port", "disable") == "enable"
            uplink = fortilink or isl or _s(pc, "type") == "trunk" or pname in lag_members
            mode = "trunk" if (allowed or all_vlans or uplink) else "access"
            vlan_txt = ("all" if all_vlans else (",".join(str(x) for x in sorted({*([native_id] if native_id else []), *allowed})) or None)) \
                if mode == "trunk" else (str(native_id) if native_id is not None else None)
            sec_policy = _s(pc, "port-security-policy") or None
            row = SwitchInterface(site_id=sid, device_name=device, port_name=pname, vlan=vlan_txt,
                                  vlan_name=native if mode == "access" else None, mode=mode,
                                  description=_s(pc, "description") or None, source_file=source,
                                  port_security_policy=sec_policy,
                                  port_security_mode=policy_mode(policies.get(sec_policy)) if sec_policy else None,
                                  admin_status=_s(pc, "status", "up") or "up", uplink=uplink)
            if fortilink and peer:
                row.neighbor_device = fw_row.name or fw_row.device_name
                row.neighbor_port = peer
                row.neighbor_protocol = "fortilink"
                row.neighbor_platform = "FortiGate"
            elif isl:
                row.neighbor_device = isl_peer or None
                row.neighbor_port = _s(pc, "isl-peer-port-name") or _s(pc, "isl-peer-port") or None
                row.neighbor_protocol = "isl"
                row.neighbor_platform = "FortiSwitch"
            db.add(row)
            n_ports += 1
            for vid, vname in ([(native_id, native)] if native_id is not None else []) + list(zip(allowed, [a for a in allowed_names if vlan_of.get(a) is not None])):
                vlan_ports.setdefault(vid, [0, vname])
                vlan_ports[vid][0] += 1
        for vid, (count, name) in vlan_ports.items():
            _upsert_switch_vlan(db, device, str(vid), name, "active", count, source)
            db.flush()
            vlans_seen.add((device, vid))
            lvl = levels.get(str(name).lower()) if name else None
            sv = db.query(SwitchVlan).filter(SwitchVlan.site_id == sid, SwitchVlan.device_name == device,
                                             SwitchVlan.vlan_id == vid).first()
            # the FortiGate VLAN interface's label IS firewall-propagated evidence: the source the rest
            # of the level machinery knows (resolve_vlan_topology would rewrite it anyway); a removed
            # label clears what this pass set (audit 2026-10-19)
            if sv is not None and sv.purdue_level_source != "manual":
                if lvl is not None:
                    sv.purdue_level, sv.purdue_level_source = lvl, "firewall_propagated"
        n_sw += 1
        log.info("FortiLink switch %s (%s): %d ports, %d VLANs, peer %s", device, serial, len(ports) if isinstance(ports, dict) else 0,
                 len(vlan_ports), peer)
    db.flush()
    return {"switches": n_sw, "ports": n_ports, "vlans": len(vlans_seen), "nac_policies": policies}
