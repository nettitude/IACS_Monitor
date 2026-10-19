"""
Stored firewall configuration text and the config lines behind a finding
(owner 2026-10-14: "Firewall devices need a means to see the uploaded config to
check findings. Where it is possible, can the findings have a snip of the
firewall config that is causing the finding?").

* Every firewall config upload (FortiGate, Cisco, PAN-OS, pfSense) keeps the
  latest text per Firewall row (``store_config``; latest only).  Secrets are
  masked BEFORE the text is written (``mask_secrets``: passwords, pre-shared
  keys, SNMP communities, RADIUS / TACACS keys, private keys and FortiOS
  ``ENC`` blobs become ``***``; line numbers are unchanged) and the text is
  zlib-compressed.
* ``snippet_for_finding`` locates the lines a finding is about: the policy,
  interface, admin, VIP, local-in policy, IPsec phase1 or service named in its
  detail (FortiOS ``config <section>`` / ``edit <key>`` blocks, VDOM-aware),
  else the configuration section a device-level check reads
  (``CHECK_SECTIONS``); for Cisco / PAN-OS / pfSense rules the rule row's
  stored ``raw_line``.
View only: nothing here changes a finding, a rule or the parsers' input.
"""
from __future__ import annotations

import hashlib
import re
import zlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session as DBSession

MASK = "***"
MAX_SNIPPET_LINES = 120

# --------------------------------------------------------------- masking --
# FortiOS "set <name> <value>" where the name carries a secret
_FORTI_SET = re.compile(
    r"^(\s*set\s+(?:[\w-]*?(?:password|passwd|secret|psk|passphrase|community|private-key|pwd|"
    r"auth-key|priv-key)(?![\w-]*(?:-policy|-expire|-status|-type|-renewal|-change|-history|-lockout))[\w-]*)\s+)(.+?)\s*$",
    re.IGNORECASE)
# Cisco IOS / ASA (audit 2026-10-15): group 1 kept, group 2 masked, group 3 (the rest of the line) kept
_LINE_PATTERNS = [
    _FORTI_SET,
    re.compile(r"^(\s*enable\s+(?:password|secret)\s+(?:level\s+\d+\s+)?(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*username\s+\S+(?:\s+(?:privilege\s+\d+|view\s+\S+|algorithm-type\s+\S+))*\s+(?:password|secret)\s+(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*snmp-server\s+host\s+\S+(?:\s+(?:version\s+\S+|informs|traps|udp-port\s+\d+))*\s+(?:community\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*crypto\s+isakmp\s+key\s+(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*(?:tacacs-server|radius-server|server-private)\s+(?:host\s+)?.*?\skey\s+(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*(?:ikev[12]\s+)?pre-shared-key\s+(?:(?:local|remote)\s+|address\s+\S+\s+key\s+)?(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s*(?:ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)|ntp\s+authentication-key\s+\d+\s+md5|"
               r"neighbor\s+\S+\s+password|(?:standby|vrrp)\s+\d*\s*authentication(?:\s+md5\s+key-string)?|"
               r"ppp\s+(?:chap|pap)\s+(?:password|sent-username\s+\S+\s+password)|key-string|wpa-psk\s+\S+|ldap-login-password|"
               r"failover\s+key)\s+(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),
    re.compile(r"^(\s+key\s+(?:\d\s+)?)((?!\d+\s*$)\S+)(\s*)$", re.IGNORECASE),   # radius / tacacs group key (not "key 1" of a key chain)
    re.compile(r"^(\s*(?:password|secret|passwd)\s+(?:\d\s+)?)(\S+)(.*)$", re.IGNORECASE),   # line vty / ASA passwd
]
# PAN-OS / pfSense XML elements: any tag whose name ends in a secret word
_XML_SECRET = re.compile(
    r"(<([\w.-]*(?:password|passwd|phash|pre-?shared-?key|secret|community|bcrypt-hash|md5-hash|sha512-hash|psk|private-key|"
    r"prv|bindpw|shared_key|ipsecpsk|community-string|key))>)([^<]+)(</\2>)", re.IGNORECASE)
# FortiOS encrypted values
_ENC = re.compile(r"\bENC\s+\S+")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def mask_secrets(text: str) -> tuple[str, int]:
    """The text with every secret value replaced by ``***``, and how many were
    replaced.  Line count and line numbers are unchanged (a private-key block
    keeps one ``***`` line per key line)."""
    out, n, stack, in_pem = [], 0, [], False
    for line in text.splitlines():
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
                out.append(line)
            else:
                out.append(MASK)      # one masked line per key line keeps the numbering
            continue
        s = line.strip()
        if s.lower().startswith("config "):
            stack.append(s[7:].strip().lower())
        elif s.lower() == "end" and stack:
            stack.pop()
        new, hit = line, False
        for pat in _LINE_PATTERNS:
            new, k = pat.subn(lambda m: m.group(1) + MASK + (m.group(3) if m.re.groups >= 3 else ""), new, count=1)
            if k:
                hit = True
                break
        if not hit and re.match(r"^\s*snmp-server\s+user\s", line, re.I):
            # SNMPv3 user: both the auth and the priv passwords
            new, k = re.subn(r"(\s(?:auth|priv)\s+(?:md5|sha256|sha384|sha512|sha|aes\s+\d+|aes|3des|des)\s+)(\S+)",
                             lambda m: m.group(1) + MASK, line, flags=re.I)
            hit = k > 0
        if not hit and stack and "snmp community" in stack[-1] and re.match(r"^\s*set\s+name\s+\S", line, re.I):
            new, hit = re.sub(r"^(\s*set\s+name\s+).+$", lambda m: m.group(1) + MASK, line), True
        if not hit:
            new, k = _XML_SECRET.subn(lambda m: m.group(1) + MASK + m.group(4), line)
            hit = k > 0
        if not hit:
            new, k = _ENC.subn("ENC " + MASK, line)
            hit = k > 0
        if _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            hit = True
        if hit:
            n += 1
        out.append(new)
    masked = "\n".join(out)
    if text.endswith("\n"):
        masked += "\n"
    return masked, n


# --------------------------------------------------------------- storage --
def store_config(db: DBSession, site_id: int, firewall_id: int, text: str, vendor: Optional[str] = None,
                 filename: Optional[str] = None, device_name: Optional[str] = None):
    """Keep the upload's text for ``firewall_id`` (secrets masked, latest only).
    Flushes; the caller commits."""
    from app.models import FirewallConfigText
    masked, n = mask_secrets(text or "")
    data = masked.encode("utf-8")
    row = db.query(FirewallConfigText).filter(FirewallConfigText.firewall_id == firewall_id).first()
    if row is None:
        row = FirewallConfigText(site_id=site_id, firewall_id=firewall_id)
        db.add(row)
    row.site_id = site_id
    row.device_name = device_name
    row.vendor = vendor
    row.filename = (filename or None) and str(filename)[:512]
    row.uploaded_at = datetime.now(timezone.utc)
    row.size_bytes = len(data)
    row.line_count = masked.count("\n") + (1 if masked and not masked.endswith("\n") else 0)
    row.sha256 = hashlib.sha256(data).hexdigest()
    row.masked_count = n
    row.content = zlib.compress(data, 6)
    db.flush()
    return row


def get_config(db: DBSession, firewall_id: int):
    from app.models import FirewallConfigText
    return db.query(FirewallConfigText).filter(FirewallConfigText.firewall_id == firewall_id).first()


def config_text(row) -> str:
    if row is None or not row.content:
        return ""
    return zlib.decompress(row.content).decode("utf-8", "replace")


def meta(row) -> dict:
    up = row.uploaded_at
    if up is not None and up.tzinfo is None:
        up = up.replace(tzinfo=timezone.utc)
    return {"firewall_id": row.firewall_id, "device_name": row.device_name, "vendor": row.vendor,
            "filename": row.filename, "uploaded_at": up.isoformat() if up else None,
            "size_bytes": row.size_bytes, "line_count": row.line_count, "sha256": row.sha256,
            "masked_count": row.masked_count}


# ------------------------------------------------------- FortiOS blocks --
def _block_end(lines: list, i: int, stop: int) -> int:
    """Index of the ``end`` closing the ``config`` line at ``i`` (``stop`` when unclosed)."""
    depth = 0
    for j in range(i, stop):
        t = lines[j].strip().lower()
        if t.startswith("config "):
            depth += 1
        elif t == "end":
            depth -= 1
            if depth == 0:
                return j
    return stop - 1


def _edit_end(lines: list, k: int, stop: int) -> int:
    """Index of the ``next`` closing the ``edit`` line at ``k``."""
    depth = 0
    for m in range(k + 1, stop):
        t = lines[m].strip().lower()
        if t.startswith("config "):
            depth += 1
        elif t == "end":
            depth -= 1
        elif t == "next" and depth <= 0:
            return m
    return stop - 1


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _vdom_blocks(lines: list, vdom: str) -> list:
    """0-based [start, end) ranges of every ``edit <vdom>`` under a ``config vdom``."""
    out, i, n = [], 0, len(lines)
    want = str(vdom).strip().lower()
    while i < n:
        if lines[i].strip().lower() == "config vdom":
            j = _block_end(lines, i, n)
            k = i + 1
            while k < j:
                t = lines[k].strip()
                if t.lower().startswith("edit "):
                    m = _edit_end(lines, k, j)
                    if _unquote(t[5:]).lower() == want:
                        out.append((k, m + 1))
                    k = m + 1
                else:
                    k += 1
            i = j + 1
        else:
            i += 1
    return out


def find_block(lines: list, section: str, key=None, vdom: Optional[str] = None,
               lo: int = 0, hi: Optional[int] = None) -> Optional[tuple[int, int]]:
    """1-based inclusive (start, end) of ``config <section>`` ... ``end`` (``key``
    None) or of its ``edit <key>`` ... ``next``, searched in lines[lo:hi].  With
    ``vdom`` the search is limited to that VDOM's block when the config has one."""
    hi = len(lines) if hi is None else hi
    if vdom and (lo, hi) == (0, len(lines)):
        # a multi-VDOM backup declares the VDOMs first (edit <name> / next, no content) and
        # holds each VDOM's sections in a later `config vdom` block: take the block with content
        for a, b in _vdom_blocks(lines, vdom):
            if any(lines[k].strip().lower().startswith("config ") for k in range(a, b)):
                lo, hi = a, b
                break
    want = "config " + section.strip().lower()
    i = lo
    while i < hi:
        if lines[i].strip().lower() == want:
            j = _block_end(lines, i, hi)
            if key is None:
                return (i + 1, j + 1)
            k = i + 1
            while k < j:
                t = lines[k].strip()
                if t.lower().startswith("edit "):
                    m = _edit_end(lines, k, j)
                    if _unquote(t[5:]).lower() == str(key).strip().lower():
                        return (k + 1, m + 1)
                    k = m + 1
                else:
                    k += 1
            i = j + 1       # the section repeats per VDOM
        else:
            i += 1
    return None


# ------------------------------------------------------- finding -> lines --
# device-level checks: the section(s) they read (first one present is shown)
CHECK_SECTIONS = {
    "config_admin_idle_timeout_long": ["system global"],
    "config_no_admin_idle_timeout": ["system global"],
    "config_admin_lockout_threshold_high": ["system global"],
    "config_no_admin_lockout": ["system global"],
    "config_default_hostname": ["system global"],
    "config_no_timezone": ["system global"],
    "config_weak_tls_version": ["system global"],
    "config_maintainer_account_enabled": ["system global"],
    "config_usb_auto_install_config": ["system auto-install", "system global"],
    "config_usb_auto_install_image": ["system auto-install", "system global"],
    "config_fail_open_enabled": ["ips global", "system global"],
    "config_ha_no_auth": ["system ha"],
    "config_no_password_policy": ["system password-policy", "system global"],
    "config_weak_password_policy": ["system password-policy"],
    "config_no_syslog_forwarding": ["log syslogd setting", "log syslogd2 setting", "log fortianalyzer setting", "log setting"],
    "config_syslog_unencrypted": ["log syslogd setting", "log syslogd2 setting"],
    "config_monitoring_readiness": ["log syslogd setting", "log setting", "system global"],
    "config_dns_external": ["system dns"],
    "config_ntp_fortiguard": ["system ntp"],
    "config_vpn_no_routing_policy": ["vpn ssl settings"],
    "config_vpn_source_unrestricted": ["vpn ssl settings"],
    "config_vpn_destination_unclear": ["vpn ssl settings"],
    "config_vpn_direct_to_ot": ["vpn ssl settings"],
    "config_no_central_auth": ["user radius", "user tacacs+", "user ldap", "system admin"],
    "config_split_tunneling_enabled": ["vpn ssl web portal", "vpn ssl settings"],
    "config_vpn_idle_timeout_long": ["vpn ssl settings"],
    "config_vpn_no_idle_timeout": ["vpn ssl settings"],
    "config_vpn_shared_access": ["vpn ssl settings"],
    "config_updates_from_internet": ["system central-management", "system autoupdate schedule", "system fortiguard"],
    "config_fortimanager_admin_access": ["system central-management", "system admin"],
    "config_auto_firmware_upgrade": ["system fortiguard"],
    "config_link_monitor_external": ["system link-monitor", "router static"],
    "config_wireless_in_ot": ["wireless-controller vap", "system interface"],
    "config_no_scheduled_backup": ["system auto-script", "system central-management", "system global"],
    "config_no_av_profile": ["antivirus profile", "firewall policy"],
    "config_av_profile_not_applied": ["antivirus profile", "firewall policy"],
    "config_rules_missing_owner": ["firewall policy"],
    "config_no_internal_segmentation": ["firewall policy"],
    "config_possible_dual_homed": ["system interface"],
    # batch A (owner 2026-10-15)
    "config_strong_crypto_disabled": ["system global"],
    "config_no_login_banner": ["system global"],
    "config_no_revision_backup": ["system global", "system central-management"],
    "config_ha_no_monitor_interfaces": ["system ha"],
    "config_ntp_unauthenticated": ["system ntp"],
    "config_implicit_deny_not_logged": ["log setting"],
    "config_admin_profile_overprivileged": ["system admin"],
    "config_snmp_v1v2c_enabled": ["system snmp community"],
    "config_snmp_default_community": ["system snmp community"],
    "config_device_detection_disabled": ["system interface"],
    # batch B
    "config_sslvpn_weak_tls": ["vpn ssl settings"],
    "config_vpn_user_no_mfa": ["vpn ssl settings"],          # the direct-users variant has no group
    "config_no_dos_policy_ot": ["firewall DoS-policy", "system interface"],
}
# detail key -> (FortiOS section(s), label)
_OBJECT_KEYS = [
    ("local_in_policy", ["firewall local-in-policy"], "local-in policy"),
    ("vip", ["firewall vip"], "VIP"),
    ("phase1", ["vpn ipsec phase1-interface", "vpn ipsec phase1"], "IPsec phase1"),
    ("service", ["firewall service custom"], "service"),
    ("interface", ["system interface"], "interface"),
    ("username", ["system admin"], "admin"),
    ("portal", ["vpn ssl web portal"], "SSL-VPN portal"),
    ("group", ["user group"], "user group"),
    ("vap", ["wireless-controller vap"], "SSID"),
]


def _policy_ref(d: dict) -> tuple[Optional[str], Optional[str]]:
    """(policy id, vdom) named by a finding's detail ("vdom/123" split)."""
    pid = d.get("policy_id")
    if pid in (None, "") and isinstance(d.get("shadowed_rule"), dict):
        pid = d["shadowed_rule"].get("policy_id")
        vdom = d["shadowed_rule"].get("vdom")
    else:
        vdom = d.get("vdom")
    if pid in (None, ""):
        return None, None
    pid = str(pid)
    if "/" in pid and not vdom:
        vdom, pid = pid.split("/", 1)
    return pid, (str(vdom) if vdom not in (None, "") else None)


def _firewall_for(db: DBSession, finding, d: dict):
    """(Firewall row, FirewallRule row) the finding is about, either None."""
    from app.models import Firewall, FirewallRule
    fw, rule = None, None
    if str(d.get("firewall_id") or "").isdigit():
        fw = db.get(Firewall, int(d["firewall_id"]))
    ids = [d.get("firewall_rule_id"), d.get("rule_id")]
    if isinstance(d.get("firewall_rule_ids"), list):
        ids += d["firewall_rule_ids"]
    if getattr(finding, "firewall_rule_id", None):
        ids.insert(0, finding.firewall_rule_id)
    for x in ids:
        if str(x or "").isdigit():
            rule = db.get(FirewallRule, int(x))
            if rule is not None:
                break
    if fw is None and rule is not None and rule.firewall_id is not None:
        fw = db.get(Firewall, rule.firewall_id)
    if fw is None:
        names = [d.get("device_name"), d.get("firewall"), finding.device_name]
        if isinstance(d.get("shadowed_rule"), dict):
            names.append(d["shadowed_rule"].get("device_name"))
        fws = db.query(Firewall).filter(Firewall.site_id == finding.site_id).order_by(Firewall.id).all()
        matches = []
        for n in names:
            if not isinstance(n, str) or not n.strip():
                continue
            matches = [f for f in fws if n.strip().lower() in {(f.name or "").lower(), (f.device_name or "").lower()}]
            if matches:
                break
        if len(matches) > 1:
            # HA peers / same-named uploads: the one whose stored config holds the named policy
            pid, vdom = _policy_ref(d)
            for f in matches:
                row = get_config(db, f.id)
                if row is not None and pid and find_block(config_text(row).splitlines(), "firewall policy", pid, vdom):
                    fw = f
                    break
            if fw is None:
                fw = next((f for f in matches if get_config(db, f.id) is not None), matches[0])
        elif matches:
            fw = matches[0]
    if fw is not None and fw.site_id != finding.site_id:
        fw = None
    return fw, rule


def _locate(lines: list, check_name: str, d: dict, rule, vendor: str) -> Optional[tuple[int, int, str]]:
    """(start, end, what) of the lines the finding is about, or None."""
    forti = vendor in ("", "fortigate", "fortinet") or any(
        l.strip().lower().startswith("config system global") for l in lines[:50])
    if forti:
        pid, vdom = _policy_ref(d)
        if pid and check_name != "config_local_in_permits_all":
            b = find_block(lines, "firewall policy", pid, vdom)
            if b:
                return (b[0], b[1], f"policy {pid}" + (f" (VDOM {vdom})" if vdom else ""))
        for key, sections, label in _OBJECT_KEYS:
            v = d.get(key)
            if v in (None, "") or isinstance(v, (list, dict)):
                continue
            for sec in sections:
                b = find_block(lines, sec, v, vdom)
                if b:
                    return (b[0], b[1], f"{label} {v}")
        for sec in CHECK_SECTIONS.get(check_name, []):
            b = find_block(lines, sec)
            if b:
                return (b[0], b[1], f"section {sec}")
    if rule is not None and rule.raw_line:
        first = str(rule.raw_line).splitlines()[0].strip() if str(rule.raw_line).strip() else ""
        if first:
            for i, l in enumerate(lines):
                if l.strip() == first or (len(first) > 20 and first in l):
                    return (i + 1, i + 1, "rule line")
    return None


def snippet_for_finding(db: DBSession, finding) -> dict:
    """The stored config lines behind a finding: ``{available, firewall_id,
    device_name, filename, uploaded_at, what, start_line, end_line, lines,
    truncated, note}`` or ``{available: False, reason}``."""
    d = finding.detail if isinstance(finding.detail, dict) else {}
    fw, rule = _firewall_for(db, finding, d)
    if fw is None:
        return {"available": False, "reason": "The finding names no firewall of this site whose configuration is stored."}
    name = fw.device_name or fw.name
    row = get_config(db, fw.id)
    if row is None:
        return {"available": False, "firewall_id": fw.id, "device_name": name,
                "reason": f"No configuration text is stored for {name} - upload its config again to keep it."}
    text = config_text(row)
    lines = text.splitlines()
    out = {"available": True, "firewall_id": fw.id, "device_name": name, "filename": row.filename,
           "uploaded_at": meta(row)["uploaded_at"], "line_count": len(lines), "note": None}
    seen = finding.last_seen or finding.created_at
    up = row.uploaded_at
    if seen is not None and up is not None:
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        if up.tzinfo is None:
            up = up.replace(tzinfo=timezone.utc)
        if up > seen:
            out["note"] = "The stored configuration was uploaded after the finding was last seen; the lines may no longer match."
    loc = _locate(lines, finding.check_name or "", d, rule, (row.vendor or fw.vendor or "").lower())
    if loc is None:
        pid, vdom = _policy_ref(d)
        if pid:
            reason = (f"Policy {pid} is not in the stored configuration of {name} "
                      "(it may have been removed before the last upload).")
        else:
            reason = (f"No configuration block for this check was found in the stored configuration of {name} "
                      "(the setting may be absent - which can be what the finding reports).")
        return {**out, "available": False, "reason": reason}
    start, end, what = loc
    truncated = end - start + 1 > MAX_SNIPPET_LINES
    if truncated:
        end = start + MAX_SNIPPET_LINES - 1
    return {**out, "what": what, "start_line": start, "end_line": end, "truncated": truncated,
            "lines": lines[start - 1:end]}


# ------------------------------------------------- interface settings block --
# owner 2026-10-14 (FW Topology Builder, option 3): the settings of one interface
# as configured - a key / value table parsed from its block, plus the raw lines.

def _split_values(v: str) -> list:
    out, cur, q = [], "", None
    for ch in v:
        if q:
            if ch == q:
                q = None
            else:
                cur += ch
        elif ch in "\"'":
            q = ch
        elif ch.isspace():
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def forti_settings(lines: list) -> list:
    """``[{key, value}]`` of an ``edit`` block: its top-level ``set`` lines and,
    for nested ``config`` tables (secondaryip, ipv6, ...), one row per table
    summarising its entries."""
    rows, i, n = [], 0, len(lines)
    body = lines[1:-1] if lines and lines[0].strip().lower().startswith("edit ") else lines
    while i < len(body):
        t = body[i].strip()
        tl = t.lower()
        if tl.startswith("set "):
            parts = t[4:].split(None, 1)
            rows.append({"key": parts[0], "value": " ".join(_split_values(parts[1])) if len(parts) > 1 else ""})
        elif tl.startswith("unset "):
            rows.append({"key": t[6:].strip(), "value": "(unset)"})
        elif tl.startswith("config "):
            name = t[7:].strip()
            j = _block_end(body, i, len(body))
            entries, cur = [], None
            for u in body[i + 1:j]:
                s = u.strip()
                if s.lower().startswith("edit "):
                    cur = [_unquote(s[5:])]
                    entries.append(cur)
                elif s.lower().startswith("set ") and cur is not None:
                    p = s[4:].split(None, 1)
                    cur.append(p[0] + " " + " ".join(_split_values(p[1])) if len(p) > 1 else p[0])
                elif s.lower().startswith("set "):
                    p = s[4:].split(None, 1)
                    entries.append([p[0] + " " + " ".join(_split_values(p[1])) if len(p) > 1 else p[0]])
            rows.append({"key": name, "value": "; ".join(" ".join(e) if len(e) > 1 and e[0] else " ".join(e) for e in entries) or "(empty)"})
            i = j
        i += 1
    return rows


def cisco_stanza(lines: list, name: str) -> Optional[tuple[int, int]]:
    """1-based (start, end) of ``interface <name>`` (or the stanza whose
    ``nameif`` is ``name``); ends before the next unindented line."""
    want = name.strip().lower()
    starts = [i for i, l in enumerate(lines) if l.strip().lower().startswith("interface ")]

    def _end(i):
        j = i + 1
        while j < len(lines) and (lines[j][:1].isspace() or not lines[j].strip()):
            j += 1
        while j - 1 > i and not lines[j - 1].strip():
            j -= 1
        return j

    for i in starts:
        if lines[i].strip()[10:].strip().lower() == want:
            return (i + 1, _end(i))
    for i in starts:
        j = _end(i)
        if any(re.match(r"^\s*nameif\s+" + re.escape(want) + r"\s*$", l, re.I) for l in lines[i + 1:j]):
            return (i + 1, j)
    return None


def cisco_settings(lines: list, all_lines: list) -> list:
    """``[{key, value}]`` of a stanza's indented lines, plus the ASA ``access-group``
    bindings of its ``nameif``."""
    rows, nameif = [], None
    for l in lines[1:]:
        t = l.strip()
        if not t or t == "!":
            continue
        if t.lower().startswith("no "):
            rows.append({"key": t, "value": ""})
            continue
        p = t.split(None, 1)
        rows.append({"key": p[0] if p[0].lower() not in ("ip", "ipv6", "switchport", "channel-group", "spanning-tree")
                     or len(p) == 1 else " ".join(t.split()[:2]),
                     "value": (p[1] if len(p) > 1 else "") if p[0].lower() not in ("ip", "ipv6", "switchport", "channel-group", "spanning-tree")
                     or len(p) == 1 else " ".join(t.split()[2:])})
        if p[0].lower() == "nameif" and len(p) > 1:
            nameif = p[1].strip()
    if nameif:
        for l in all_lines:
            m = re.match(r"^\s*access-group\s+(\S+)\s+(in|out)\s+interface\s+" + re.escape(nameif) + r"\s*$", l, re.I)
            if m:
                rows.append({"key": f"access-group ({m.group(2)})", "value": m.group(1)})
    return rows


def xml_element(lines: list, tag: str, attr_name: Optional[str] = None) -> Optional[tuple[int, int]]:
    """1-based (start, end) of ``<tag>…</tag>`` (pfSense interfaces) or
    ``<entry name="attr_name">…</entry>`` (PAN-OS), depth-counted."""
    if attr_name is not None:
        opener = re.compile(r"<entry\s+name=\"" + re.escape(attr_name) + r"\"\s*>", re.I)
        anyopen, closer = re.compile(r"<entry\b(?:[^>/]|/(?!>))*>", re.I), re.compile(r"</entry>", re.I)   # not <entry .../>
    else:
        opener = re.compile(r"<" + re.escape(tag) + r"\s*>", re.I)
        anyopen, closer = opener, re.compile(r"</" + re.escape(tag) + r">", re.I)
    for i, l in enumerate(lines):
        if opener.search(l):
            depth = 0
            for j in range(i, len(lines)):
                depth += len(anyopen.findall(lines[j])) - len(closer.findall(lines[j]))
                if depth <= 0:
                    return (i + 1, j + 1)
            return (i + 1, len(lines))
    return None


def xml_settings(lines: list) -> list:
    rows = []
    for l in lines[1:-1]:
        m = re.match(r"^\s*<([\w.-]+)(?:\s[^>]*)?>([^<]*)</\1>\s*$", l)
        if m:
            rows.append({"key": m.group(1), "value": m.group(2).strip()})
        else:
            m = re.match(r"^\s*<([\w.-]+)\s*/>\s*$", l)
            if m:
                rows.append({"key": m.group(1), "value": "(set)"})
    return rows


def config_block(db: DBSession, fw, section: str, key: str, vdom: Optional[str] = None) -> dict:
    """The stored configuration block ``section`` / ``key`` of a firewall with
    the settings it holds.  ``section`` "system interface" is vendor-aware
    (FortiOS block, Cisco ``interface`` stanza - by name or nameif -, pfSense
    ``<interfaces>`` element, PAN-OS ``<entry name>``); other sections are
    FortiOS only."""
    name = fw.device_name or fw.name
    row = get_config(db, fw.id)
    base = {"firewall_id": fw.id, "device_name": name, "section": section, "key": key}
    if row is None:
        return {**base, "available": False,
                "reason": f"No configuration text is stored for {name} - upload its config again to keep it."}
    lines = config_text(row).splitlines()
    vendor = (row.vendor or fw.vendor or "").lower()
    base.update({"filename": row.filename, "uploaded_at": meta(row)["uploaded_at"], "vendor": vendor, "line_count": len(lines)})
    forti = vendor in ("", "fortigate", "fortinet") or any(l.strip().lower().startswith("config system global") for l in lines[:50])
    loc, settings, what = None, [], f"{section} {key}"
    if forti:
        loc = find_block(lines, section, key, vdom)
        if loc:
            settings = forti_settings(lines[loc[0] - 1:loc[1]])
    elif section.strip().lower() == "system interface":
        if "cisco" in vendor or "asa" in vendor or "ios" in vendor:
            loc = cisco_stanza(lines, key)
            what = f"interface {key}"
            if loc:
                settings = cisco_settings(lines[loc[0] - 1:loc[1]], lines)
        elif "pfsense" in vendor:
            loc = xml_element(lines, key)
            what = f"<{key}>"
            if loc:
                settings = xml_settings(lines[loc[0] - 1:loc[1]])
        elif "palo" in vendor or "pan" in vendor:
            loc = xml_element(lines, "entry", attr_name=key)
            what = f'<entry name="{key}">'
            if loc:
                settings = xml_settings(lines[loc[0] - 1:loc[1]])
        else:
            return {**base, "available": False, "reason": f"Interface settings are not read from {vendor or 'this vendor'} configurations."}
    else:
        return {**base, "available": False, "reason": "Only FortiOS configurations have named sections."}
    if not loc:
        return {**base, "available": False,
                "reason": f"{what[0].upper() + what[1:]} is not in the stored configuration of {name} (uploaded {base['uploaded_at'] or '?'})."}
    start, end = loc
    truncated = end - start + 1 > MAX_SNIPPET_LINES
    if truncated:
        end = start + MAX_SNIPPET_LINES - 1
    return {**base, "available": True, "what": what, "start_line": start, "end_line": end, "truncated": truncated,
            "lines": lines[start - 1:end], "settings": settings}
