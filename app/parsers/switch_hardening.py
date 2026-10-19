"""
Switch hardening checks from an uploaded running-config (G-03).

HP / Aruba (ProCurve, ArubaOS-Switch) and Cisco IOS running-configs are read
for the management-plane settings that matter on an OT switch:

``switch_snmp_default_community``  (SR 1.5, SR 4.1 - checklist 5.4)
    An SNMPv1/v2c community that is a vendor default or a well-known value
    (``public``, ``private``, ...).  Anyone on the management network can read
    - and with write access reconfigure - the switch.  high; critical with
    write access (HP ``Unrestricted`` / ``manager``, Cisco ``RW``).
``switch_snmp_cleartext_community`` (SR 4.1, SR 1.5 - checklist 5.2)
    Any other SNMPv1/v2c community: sent in cleartext on every poll.  low;
    medium with write access.  Use SNMPv3 (authPriv).
``switch_insecure_mgmt_protocol``  (SR 4.1, SR 3.1 - checklist 5.2)
    Telnet server enabled (HP ``telnet-server``; Cisco ``line vty`` with
    ``transport input telnet`` / ``all``).  high.

Only what the config states is judged: an HP config without a
``telnet-server`` line is not flagged (firmware defaults differ).  Community
strings are reported masked except well-known defaults, which are named.

Findings are deduplicated per (switch, check, community) and the switch's
findings that a new upload no longer produces are closed.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models import Finding

log = logging.getLogger(__name__)

CHECK_DEFAULT = "switch_snmp_default_community"
CHECK_CLEARTEXT = "switch_snmp_cleartext_community"
CHECK_TELNET = "switch_insecure_mgmt_protocol"
CHECKS = (CHECK_DEFAULT, CHECK_CLEARTEXT, CHECK_TELNET)

# Vendor defaults and values found in default-credential lists.  Compared
# case-insensitively.
DEFAULT_COMMUNITIES = frozenset({
    "public", "private", "community", "cisco", "manager", "admin", "default",
    "snmp", "snmpd", "secret", "write", "read", "monitor", "system", "hp_admin",
    "netman", "ilmi", "all private", "tivoli", "openview", "security",
})

_HP_COMMUNITY = re.compile(
    r'^\s*snmp-server\s+community\s+(?:"([^"]*)"|(\S+))(.*)$', re.I | re.M)
_CISCO_COMMUNITY = re.compile(
    r"^\s*snmp-server\s+community\s+(\S+)(.*)$", re.I | re.M)
_HP_TELNET_ON = re.compile(r"^\s*telnet-server\s*$", re.I | re.M)
_CISCO_VTY = re.compile(r"^line vty[^\n]*\n((?:[ \t]+[^\n]*\n?)*)", re.I | re.M)


def _write_access_hp(rest: str) -> bool:
    r = rest.lower()
    return "unrestricted" in r or re.search(r"\bmanager\b", r) is not None


def _write_access_cisco(rest: str) -> bool:
    return re.search(r"\brw\b", rest.lower()) is not None


_FORTI_COMMUNITY = re.compile(r'^\s*edit\s+(\S+)\s*\n((?:(?!^\s*next\s*$).*\n)*?)\s*set\s+name\s+"?([^"\n]+)"?', re.M)
_FORTI_SNMP_BLOCK = re.compile(r"^config system snmp community\s*\n(.*?)^end\s*$", re.M | re.S)
_FORTI_ALLOWACCESS = re.compile(r'^\s*edit\s+"?([^"\n]+)"?\s*\n(?:(?!^\s*next\s*$).*\n)*?\s*set allowaccess\s+([^\n]*telnet[^\n]*)$', re.M)


def parse_communities(text: str, vendor: str) -> list[dict]:
    """[{community, write, line}] of the SNMPv1/v2c communities a config sets."""
    out = []
    if vendor == "fortinet":
        # FortiSwitchOS / FortiOS: config system snmp community / edit N / set name "public" (read-only
        # by design; writes need SNMPv3 users)
        for blk in _FORTI_SNMP_BLOCK.finditer(text or ""):
            for m in re.finditer(r'^\s*set\s+name\s+"?([^"\n]+)"?\s*$', blk.group(1), re.M):
                out.append({"community": m.group(1).strip(), "write": False, "line": m.group(0).strip()})
        return out
    if vendor == "hp":
        for m in _HP_COMMUNITY.finditer(text or ""):
            name = m.group(1) if m.group(1) is not None else m.group(2)
            out.append({"community": name, "write": _write_access_hp(m.group(3) or ""),
                        "line": m.group(0).strip()})
    else:
        for m in _CISCO_COMMUNITY.finditer(text or ""):
            name = m.group(1)
            if name.lower() in ("view", "group"):       # snmp-server community … view X
                continue
            out.append({"community": name, "write": _write_access_cisco(m.group(2) or ""),
                        "line": m.group(0).strip()})
    return out


def telnet_enabled(text: str, vendor: str) -> Optional[str]:
    """The config line that enables a telnet server, or None."""
    if vendor == "fortinet":
        m = _FORTI_ALLOWACCESS.search(text or "")
        return f"interface {m.group(1)}: set allowaccess {m.group(2).strip()}" if m else None
    if vendor == "hp":
        m = _HP_TELNET_ON.search(text or "")
        return m.group(0).strip() if m else None
    for m in _CISCO_VTY.finditer(text or ""):
        for ln in m.group(1).splitlines():
            t = ln.strip().lower()
            if t.startswith("transport input") and ("telnet" in t or t.endswith(" all")):
                return f"line vty … {ln.strip()}"
    return None


def _mask(community: str) -> str:
    if len(community) <= 2:
        return "*" * len(community)
    return community[0] + "*" * (len(community) - 2) + community[-1]


def check_switch_config(db: DBSession, text: str, device: Optional[str], vendor: str,
                        source_file: Optional[str] = None) -> dict:
    """Raise / refresh / close the hardening findings of one switch from its
    running-config.  ``vendor``: "hp" or "cisco".  Returns counts."""
    from app.parsers import alert_engine as ae
    from app.parsers.site_scope import analysis_site
    from app.sites import scope_site_id

    # AU full review E-H1: run inside the ingest site - the dedup lookup and
    # the close loop below otherwise see (and close) another site's findings
    # for a switch of the same name.
    with analysis_site(db, scope_site_id(db)):
        return _check_switch_config(db, text, device, vendor, source_file, ae)


def _check_switch_config(db: DBSession, text: str, device: Optional[str], vendor: str,
                         source_file: Optional[str], ae) -> dict:
    dev = (device or "").strip() or "unknown switch"
    stats = {"communities": 0, "default_communities": 0, "telnet": False,
             "findings_created": 0, "findings_closed": 0}
    produced: set[str] = set()

    def emit(check, key, title, text_, evidence, severity):
        ref = ae._dedup_key(check, {"rule_key": f"switch:{dev}:{check}:{key}"})
        produced.add(ref)
        f = ae._make_finding(db, check, title[:512], text_,
                             {"switch": dev, "vendor": vendor, "source_file": source_file,
                              **evidence},
                             device_name=dev, severity=severity,
                             dedup_evidence={"rule_key": f"switch:{dev}:{check}:{key}"})
        if f is not None:
            stats["findings_created"] += 1

    for c in parse_communities(text, vendor):
        stats["communities"] += 1
        name = c["community"]
        access = "read-write" if c["write"] else "read-only"
        if name.lower() in DEFAULT_COMMUNITIES:
            stats["default_communities"] += 1
            emit(CHECK_DEFAULT, name.lower(),
                 f"Switch {dev}: default SNMP community \"{name}\" ({access})",
                 f"Switch {dev} accepts SNMPv1/v2c community \"{name}\" with {access} access. "
                 "This is a vendor default / well-known community string: anyone who can reach "
                 "the switch's management address can read its configuration, VLANs and "
                 "neighbour table"
                 + (" and change them" if c["write"] else "")
                 + ". Default authenticators must be changed (ISA/IEC 62443-3-3 SR 1.5 "
                   "authenticator management) and SNMPv1/v2c sends the community in cleartext "
                   "(SR 4.1). Remove the community and use SNMPv3 with authentication and "
                   "privacy, restricted to the management stations.",
                 {"community": name, "access": access, "config_line": c["line"]},
                 "critical" if c["write"] else "high")
        else:
            emit(CHECK_CLEARTEXT, _mask(name),
                 f"Switch {dev}: SNMPv1/v2c community in cleartext ({access})",
                 f"Switch {dev} uses an SNMPv1/v2c community ({_mask(name)}, {access}). The "
                 "community string crosses the network in cleartext on every poll (SR 4.1 "
                 "communication confidentiality, SR 1.5). Use SNMPv3 with authentication and "
                 "privacy.",
                 {"community_masked": _mask(name), "access": access},
                 "medium" if c["write"] else "low")

    line = telnet_enabled(text, vendor)
    if line:
        stats["telnet"] = True
        emit(CHECK_TELNET, "telnet",
             f"Switch {dev}: telnet server enabled",
             f"Switch {dev} runs a telnet server ({line}): management sessions and passwords "
             "cross the network in cleartext (SR 4.1, SR 3.1). Disable telnet and manage the "
             "switch over SSH.",
             {"protocol": "telnet", "config_line": line}, "high")

    # close this switch's findings the upload no longer produces
    now = datetime.now(timezone.utc)
    note = (f"Auto-resolved: not present in the switch config uploaded "
            f"{now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    for f in db.query(Finding).filter(Finding.check_name.in_(CHECKS),
                                      Finding.device_name == dev,
                                      Finding.status == "open"):
        if f.source_ref in produced:
            continue
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "")[:2048 - len(note) - 3] + note
        stats["findings_closed"] += 1
    db.flush()
    return stats
