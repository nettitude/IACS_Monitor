"""
FortiGate `show full-configuration` parser.

Ingests the complete FortiOS running-config CLI output into the IACS
Monitor data model. This is a two-pass parser:

  Pass 1 — tokenize: the FortiOS block structure (config/edit/set/next/
  end) is parsed into a nested Python dict regardless of which sections
  are present. The tokenizer was tested against real FortiOS output and
  handles all three value types:
    - Quoted strings: "object-name", "my address group"
    - Bare tokens: accept, deny, tcp, 10.0.1.1
    - Multi-token (IP+mask): set subnet 10.0.1.0 255.255.255.0

  Pass 1.5 — flatten global/vdom wrapping: a flat, single-VDOM config
  (VDOM mode disabled - the common case for a purpose-built OT
  firewall) has section names directly at the top level and needs no
  extra handling. A multi-VDOM full-configuration backup wraps
  everything in `config global ... end` (global-scope settings) and
  `config vdom / edit <name> ... next / end` (per-VDOM settings, one
  block per VDOM) - without unwrapping this, every downstream
  extraction function looks for section names at the top level, finds
  nothing, and the parse silently returns zero zones/policies with no
  error. This was caught by testing against a constructed multi-VDOM
  sample, not by inspection - the flat case alone gives no reason to
  suspect the gap.
  N-24: the merged (flat) view is still used for global settings
  (interfaces, admin, hardening checks) but policies, address/service
  objects, VIPs, ippools and NAT are resolved PER VDOM (split_vdoms):
  every FirewallRule / NatRule row carries ``vdom`` and the policy
  identity is (firewall, vdom, policy_id), so the same policy id in two
  VDOMs no longer collapses.  A config without a `config vdom` wrapper
  stores vdom NULL.  Re-ingest replaces the rows of the VDOMs present in
  the config (all of the firewall's rows for a full `config global`
  backup) plus any NULL-vdom rows.  Inter-VDOM links are not followed.

  Pass 2 — resolve and emit: each relevant config section is walked to
  resolve named address/service objects (including recursive addrgrp
  nesting with cycle detection) and emit normalized records.

What gets populated in the data model (this pass - see scope note below):
  FirewallZone   — from config system interface (+ config system zone)
  FirewallZoneDef — B-07: config system zone / SD-WAN zones -> member
                   interfaces + intrazone, per VDOM (replaced like rules)
  Host           — from config firewall address / address6 (B-24: valid
                   unicast single-host objects only)
  FirewallRule   — from config firewall policy (+ policy6 / srcaddr6 /
                   dstaddr6: IPv6 rows, F-07), with objects resolved; VIPs
                   used as dstaddr resolve to the mapped address (F-05)
  NatRule        — VIP dnat + policy `set nat enable` snat (F-05),
                   central-snat-map, vip46 / vip64 (N-25), replaced per
                   (Firewall, VDOM) on re-ingest
  Finding        — (generate_findings) config_review checks; with
                   IACS_AUTO_RESOLVE (default true) open config_review
                   findings of this firewall that a re-ingest no longer
                   produces are closed (F-04); acknowledged ones are kept

SCOPE NOTE: Finding generation and ApprovedHost population (from admin
trusted-hosts) are implemented in this module but disabled by default
(pass generate_findings=True / populate_approved_hosts=True to enable).
Reasons for the default-off:
  1. Explicit instruction to hold off on reporting output for now -
     Finding rows are exactly that.
  2. ApprovedHost.baseline_id is a required (non-nullable) foreign key
     in the schema - the original version of this function inserted
     ApprovedHost rows without setting it, which would raise an
     IntegrityError on every commit. Since ApprovedHost is modeled as
     audit/baseline-workbook data (each row belongs to a named,
     versioned Baseline - see models.py), and a FortiGate's admin
     trusted-host list is a technical device control rather than a
     human-reviewed audit approval, conflating the two by
     auto-populating ApprovedHost from raw config parsing was also a
     modeling mismatch worth reconsidering, not just a missing field to
     patch. Enabling populate_approved_hosts=True still requires
     passing an explicit baseline_id.

RESOLUTION LIMITS (documented rather than silently asserted):
  - FQDN and wildcard-FQDN address objects can't be concretized at
    parse time. They're stored with an "fqdn:" prefix so nothing is
    silently dropped, and flagged as unresolvable in findings.
  - IP range objects (type iprange) are stored as "range:x.x.x.x-y.y.y.y"
    — topology_diff.py's address-matcher doesn't currently handle these;
    they'll appear in unresolvable_rules until the diff engine is extended.
  - Circular addrgrp references (shouldn't exist in a valid config but
    can appear after a partial restore) trigger cycle detection; the
    cycle member is recorded as "cycle:<name>" rather than looping.
"""
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession

from app.sites import scope_site_id, site_ingest
from app.purdue import fmt_level
from app.models import (
    ACTIVE_FINDING_STATUSES, ApprovedHost, Baseline, Finding, Firewall, FirewallDevice, FirewallInterface,
    FirewallRule, FirewallZone, FirewallZoneDef, Host, NatRule, PcapCapture,
)
from app.parsers.common import (
    RULE_ROWS_ENV, IngestLimitExceeded, get_or_create_host, name_has_keyword, normalize_mac,
    rule_row_budget,
)
from app.parsers.firewall_parser import (
    _cap_rule, _dedupe, _group_over,
    _Memo, _memo_store, _nat_addr, _nat_range, canonical_ports, get_or_create_firewall_device,
    nat_row, port_field_hits, split_port_field,
)
from app.parsers import rule_match as rm

log = logging.getLogger(__name__)

#: B-08: flush FirewallRule inserts in batches so a large (in-budget) config
#: does not hold every pending ORM object in memory until the commit.
_RULE_FLUSH_EVERY = 5000


# ================================================================ tokenizer ==

def _parse_set_values(val_str: str) -> list:
    """
    Parse the value portion of a 'set key ...' line into a list of tokens.
    Three forms coexist in FortiOS:
      1. Bare tokens:              set action accept
      2. Quoted strings:           set member "Host-A" "Host-B"
      3. Bare multi-token (ip/mask): set subnet 10.0.1.0 255.255.255.0
    B-15(d): inside a quoted string FortiOS escapes ``"`` as ``\\"`` and
    ``\\`` as ``\\\\``; both are unescaped here (an escaped quote no longer
    ends the token).  An unterminated quote runs to the end of the string.
    """
    toks, _end = _scan_tokens(val_str.strip(), 0, stop_at_newline=False)
    return toks


def _read_quoted(text: str, i: int) -> tuple:  # noqa: C901
    """``text[i]`` is an opening quote.  Returns (value, index after the
    closing quote) or (None, -1) when the quote is never closed.

    C-03: a closing quote found ACROSS one or more newlines only ends the
    token when it is itself followed by whitespace / newline / EOF (the end
    of a statement).  A `"` in the middle of a later line (e.g. the second
    quote of ``set comment "rack 5" bay 2"`` whose opener was already
    consumed) does NOT close a token that started on an earlier line - that
    is a stray/unescaped quote, and letting it close here would invert quote
    pairing for the whole rest of the file.  When no such well-formed closer
    exists the caller falls back to an end-of-line token (see _scan_tokens),
    so one stray quote can never swallow the remaining configuration.  A
    closing quote on the SAME line is always accepted (ordinary quoted
    value); legitimate multi-line quoted values (replacemsg buffers) end
    their final line with the closing quote followed by a newline, which
    still qualifies."""
    out = []
    n = len(text)
    j = i + 1
    crossed_newline = False
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n and text[j + 1] in ('"', "\\"):
            out.append(text[j + 1])
            j += 2
            continue
        if c == "\n":
            crossed_newline = True
        if c == '"':
            if not crossed_newline or j + 1 >= n or text[j + 1] in " \t\r\n":
                return "".join(out), j + 1
            # A quote mid-line, reached only after crossing a newline: treat
            # the original opener as unterminated (EOL fallback).
            return None, -1
        out.append(c)
        j += 1
    return None, -1


def _scan_tokens(text: str, i: int, stop_at_newline: bool = True,
                 stats: Optional[dict] = None) -> tuple:
    """Tokens of one FortiOS statement starting at ``text[i]``: bare words
    and quoted strings (which may span lines).  Stops after the newline that
    ends the statement OUTSIDE quotes.  Returns (tokens, next index).

    A quote that is never closed by a well-formed closer (truncated file, or
    C-03's stray unescaped quote ``set comment "rack 5" bay 2"``) is taken to
    end at the end of its own line - the old line-based behaviour - so one
    stray quote cannot swallow the rest of the configuration.  Each such
    recovery bumps ``stats["quote_recoveries"]`` (when a stats dict is given)
    and logs a warning so the drop is visible instead of silent."""
    toks: list = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            if stop_at_newline:
                return toks, i + 1
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        if c == '"':
            val, j = _read_quoted(text, i)
            if j == -1:
                eol = text.find("\n", i + 1) if stop_at_newline else -1
                if eol == -1:
                    eol = n
                seg = text[i + 1:eol]
                toks.append(seg.replace('\\"', '"').replace("\\\\", "\\"))
                if stats is not None:
                    stats["quote_recoveries"] = stats.get("quote_recoveries", 0) + 1
                log.warning("FortiOS tokenizer: unbalanced quote recovered at offset %d "
                            "(treated as end-of-line); check for a stray \" in the config", i)
                i = eol
                continue
            toks.append(val)
            i = j
            continue
        j = i
        while j < n and text[j] not in ' \t\r\n"':
            j += 1
        toks.append(text[i:j])
        i = j
    return toks, i


def _forti_statements(text: str, stats: Optional[dict] = None):
    """Yield the token list of every statement of a FortiOS CLI text.
    Keywords (config / edit / set / next / end ...) are only recognised as
    the FIRST token of a statement outside quotes, so a quoted multi-line
    value (replacemsg ``set buffer``, comments) that contains ``end`` /
    ``next`` / ``config ...`` lines never changes the block nesting.  Lines
    whose first non-blank character is ``#`` are comments."""
    i, n = 0, len(text)
    while i < n:
        # skip blank space between statements
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if text[i] == "#":
            eol = text.find("\n", i)
            i = n if eol == -1 else eol + 1
            continue
        toks, i = _scan_tokens(text, i, stats=stats)
        if toks:
            yield toks


def parse_forti_block(text: str, stats: Optional[dict] = None) -> dict:
    """
    Tokenize a FortiOS CLI config block into a nested dict:
      { "section name": { "entry name": { "key": value_or_list } } }

    Rules:
      - 'config X' opens a section scope
      - 'edit Y' opens an entry scope within the current section
      - 'set K V...' sets a key in the current entry
      - 'next' closes an entry scope
      - 'end' closes a section scope
      - Lines beginning with '#' are comments and are ignored

    Multi-value keys (set member "A" "B") are stored as lists.
    Single-value keys are stored as a plain string.

    B-15(d): statements are read with FortiOS quoting rules (see
    _forti_statements): ``\\"`` / ``\\\\`` escapes inside quotes and quoted
    values spanning several lines; keywords count only at statement start.
    """
    result: dict = {}
    # Stack of (section_name, entry_name, dict_ref) tuples
    stack: list = []

    def current_dict() -> dict:
        return stack[-1][2] if stack else result

    for toks in _forti_statements(text or "", stats=stats):
        kw = toks[0]
        if kw == "config" and len(toks) >= 2:
            section = " ".join(toks[1:]).strip()
            parent = current_dict()
            if not isinstance(parent.get(section), dict):
                parent[section] = {}
            stack.append((section, None, parent[section]))

        elif kw == "edit" and len(toks) >= 2:
            if not stack:
                # 'edit' before any 'config' block — malformed/truncated config
                log.warning("parse_forti_block: orphan 'edit' at top level (truncated config?); skipping")
                continue
            name = " ".join(toks[1:]).strip()
            sec_name, _, sec_dict = stack[-1]
            entry_dict: dict = {}
            sec_dict[name] = entry_dict
            # Replace the current frame's dict pointer so subsequent
            # 'set' lines go into the entry, not the section container
            stack[-1] = (sec_name, name, sec_dict)
            stack.append((f"{sec_name}.{name}", None, entry_dict))

        elif kw == "set" and len(toks) >= 2:
            key, values = toks[1], toks[2:]
            current_dict()[key] = values if len(values) != 1 else values[0]

        elif kw in ("next", "end") and len(toks) == 1:
            if stack:
                stack.pop()

    return result


def flatten_global_vdom(parsed: dict, quiet: bool = False) -> dict:
    """
    Normalize away FortiOS's global/vdom wrapping so every downstream
    extraction function always sees section names directly at the top
    level. See module docstring's "Pass 1.5" note for why this matters -
    without it, a multi-VDOM config silently yields zero zones/policies.

    A flat config (no "global" or "vdom" top-level key) passes through
    unchanged - verified with a regression check alongside the fix.

    L-9 fix: multi-VDOM object collisions are counted and logged.
    When two VDOMs define an entry with the same key inside the same
    section (e.g. both define firewall-policy "1"), the last VDOM wins in
    THIS merged view.  N-24: ingest no longer extracts policies / objects /
    NAT from it (see split_vdoms) - it serves global settings only - so the
    collision is logged at INFO when ``quiet`` (as ingest calls it).
    """
    import logging as _logging
    _log = _logging.getLogger(__name__)

    if "global" not in parsed and "vdom" not in parsed:
        return parsed

    flat: dict = {}
    # Track collisions: section_name -> {key -> count of overwrites}
    _collision_examples: dict[str, str] = {}  # section_name -> first colliding object key
    _collision_total = 0

    def merge_sections(sections: dict):
        nonlocal _collision_total
        for section_name, entries in sections.items():
            if not isinstance(entries, dict):
                # Scalar or list value from a partially-tokenized block — pass through as-is
                flat[section_name] = entries
                continue
            existing = flat.setdefault(section_name, {})
            if not isinstance(existing, dict):
                flat[section_name] = existing = {}
            for obj_key in entries:
                if obj_key in existing and section_name not in _collision_examples:
                    _collision_examples[section_name] = obj_key
                    _collision_total += 1
                elif obj_key in existing:
                    _collision_total += 1
            existing.update(entries)

    if isinstance(parsed.get("global"), dict):
        merge_sections(parsed["global"])

    if isinstance(parsed.get("vdom"), dict):
        for _vdom_name, vdom_sections in parsed["vdom"].items():
            if isinstance(vdom_sections, dict):      # A-20: skip stray values
                merge_sections(vdom_sections)

    if _collision_total:
        example_section, example_key = next(iter(_collision_examples.items()))
        # N-24: ingest uses this merged view for global settings only (policies /
        # objects are resolved per VDOM, see split_vdoms), so there it is just
        # informational (quiet=True); direct callers still get the warning.
        (_log.info if quiet else _log.warning)(
            "flatten_global_vdom: %d cross-VDOM object collision(s) detected — "
            "last VDOM wins for each in the merged view; first example: section=%r key=%r."
            "%s",
            _collision_total, example_section, example_key,
            " (policies/objects are resolved per VDOM)" if quiet else
            " If multiple VDOMs share overlapping policy/object names the earlier "
            "VDOM's entries are dropped from this merged view.",
        )

    # Anything at the true top level outside global/vdom shouldn't
    # normally occur, but preserve it rather than silently drop it.
    for k, v in parsed.items():
        if k not in ("global", "vdom"):
            if not isinstance(v, dict) or not isinstance(flat.get(k, {}), dict):
                flat[k] = v
            else:
                flat.setdefault(k, {}).update(v)

    return flat


def split_vdoms(parsed_raw: dict) -> list:
    """
    N-24: per-VDOM views of a tokenized config -> [(vdom_name | None, tree)].

    A config without a `config vdom` / `config global` wrapper is ONE view
    with vdom None (the tree itself).  Otherwise one view per VDOM block:
    the `config global` sections overlaid with that VDOM's own sections
    (interfaces live in global with `set vdom`, policies / objects live in
    the VDOM), so object names resolve inside their own VDOM and the same
    policy id / address name in two VDOMs never collides.  VDOM blocks that
    are mere declarations (`config vdom / edit X / next`, no sections) are
    skipped.  A wrapper holding no VDOM block yields the flat view (None).
    """
    if "global" not in parsed_raw and "vdom" not in parsed_raw:
        return [(None, parsed_raw)]
    glob = parsed_raw.get("global") if isinstance(parsed_raw.get("global"), dict) else {}
    views = []
    vd = parsed_raw.get("vdom")
    if isinstance(vd, dict):
        for name, sections in vd.items():
            if not isinstance(sections, dict) or not sections:
                continue
            tree: dict = {}
            for src in (glob, sections):
                for sec, body in src.items():
                    if isinstance(body, dict) and isinstance(tree.get(sec), dict):
                        tree[sec] = {**tree[sec], **body}
                    else:
                        tree[sec] = body
            views.append((str(name), tree))
    if not views:
        return [(None, flatten_global_vdom(parsed_raw))]
    return views


# ======================================================= A-20 sanitizer ==
#: Sections whose children must be `edit` entries (dicts). Anything else
#: in them (a stray `set` at section level, a truncated block) is dropped.
_TABLE_SECTIONS = frozenset({
    "firewall address", "firewall address6", "firewall addrgrp",
    "firewall addrgrp6", "firewall policy", "firewall policy6",
    "firewall service custom", "firewall service group", "firewall vip",
    "firewall vip6", "firewall vipgrp", "firewall vipgrp6",
    # N-25: address-family translating VIPs / policies and central SNAT
    "firewall vip46", "firewall vip64", "firewall vipgrp46", "firewall vipgrp64",
    "firewall policy46", "firewall policy64", "firewall central-snat-map",
    "firewall ippool", "firewall ippool6", "system admin",
    "system interface", "system zone", "user radius", "user tacacs+",
    "vpn ssl web portal", "antivirus profile", "router static",
    # DR-03 / DR-08 / DR-09
    "vpn ipsec phase1-interface", "vpn ipsec phase2-interface", "firewall local-in-policy",
    "user group", "system ipsec-aggregate",
})
#: Keys that FortiOS always stores as a single token. A malformed
#: multi-value `set` is reduced to its first token; an empty `set` or a
#: nested `config` block under that name is dropped (default applies).
_SCALAR_KEYS = frozenset({
    "type", "action", "status", "protocol", "logtraffic", "nat", "vlanid",
    "vdom", "mode", "role", "timezone", "start-ip", "end-ip", "startip",
    "endip", "portforward", "extport", "mappedport", "protocol-number",
    "accprofile", "two-factor", "primary", "secondary", "source-ip",
    "server", "ntpsync", "fqdn", "wildcard-fqdn", "extintf", "schedule",
    "inspection-mode", "web-mode", "tunnel-mode", "split-tunneling",
    "ssl-min-proto-version", "admin-lockout-threshold", "admin-idle-timeout",
    "admintimeout", "admin-lockout-duration", "admin-maintainer", "minimum-length",
    "idle-timeout", "auth-timeout", "min-length", "family", "ip6",
    "src-check", "interface-subnet", "macaddr", "mtu", "speed", "device",
    "gateway", "distance", "priority", "comment",
})
#: Free-text keys: a list is joined with spaces instead of truncated.
_TEXT_KEYS = frozenset({"comments", "description", "alias", "hostname", "name"})
#: Settings sections (no `edit` level) - must be dicts.
_SETTINGS_SECTIONS = frozenset({
    "system global", "system dns", "system ntp", "system ha",
    "log syslogd setting", "system password-policy",
    # every log destination + logging behaviour (monitoring readiness, 2026-10-12)
    "log syslogd2 setting", "log syslogd3 setting", "log syslogd4 setting",
    "log syslogd filter", "log syslogd2 filter", "log syslogd3 filter", "log syslogd4 filter",
    "log fortianalyzer setting", "log fortianalyzer2 setting", "log fortianalyzer3 setting",
    "log fortianalyzer-cloud setting",
    "log fortianalyzer filter", "log fortianalyzer2 filter", "log fortianalyzer3 filter",
    "log fortianalyzer-cloud filter",
    "log fortiguard setting", "log fortiguard filter",
    "log disk setting", "log memory setting", "log setting", "log eventfilter",
    "system central-management", "system autoupdate schedule",
    "system failopen", "system backup", "system auto-install",
    "vpn ssl settings",
})


def _reject_block(stats: Optional[dict], where: str, why: str) -> None:
    """A-20: count one dropped malformed block/value with a sample reason."""
    if stats is None:
        return
    stats["blocks_rejected"] = stats.get("blocks_rejected", 0) + 1
    samples = stats.setdefault("reject_reasons", [])
    if len(samples) < 5:
        samples.append(f"{where[:100]}: {why}")


def _norm_scalar(value):
    """list -> first token (None when empty); dict -> None; else unchanged."""
    if isinstance(value, list):
        for v in value:
            if isinstance(v, str):
                return v
        return None
    if isinstance(value, dict):
        return None
    return value


#: Per-section single-token keys (multi-valued elsewhere, e.g. zone members).
_SECTION_SCALAR_KEYS = {
    "system interface": frozenset({"interface", "zone"}),
}


def _norm_entry(cfg: dict, where: str, stats: Optional[dict],
                extra_scalar: frozenset = frozenset()) -> None:
    for key in list(cfg):
        v = cfg[key]
        if key in _TEXT_KEYS:
            if isinstance(v, list):
                cfg[key] = " ".join(x for x in v if isinstance(x, str))
            elif isinstance(v, dict):
                del cfg[key]
                _reject_block(stats, f"{where}.{key}", "block where a value was expected")
        elif key in _SCALAR_KEYS or key in extra_scalar:
            n = _norm_scalar(v)
            if n is None:
                del cfg[key]
                if isinstance(v, dict) or v:
                    _reject_block(stats, f"{where}.{key}", "non-scalar value")
            elif n is not v:
                cfg[key] = n
        elif isinstance(v, list):
            # list values may only hold strings
            if any(not isinstance(x, str) for x in v):
                cfg[key] = [x for x in v if isinstance(x, str)]


def sanitize_forti_tree(parsed: dict, stats: Optional[dict] = None) -> dict:
    """
    A-20: make a (flattened) parse tree structurally safe for the
    extractors: table sections keep only dict entries, settings sections
    must be dicts, and known single-token keys hold a single string.
    Dropped items are counted in stats["blocks_rejected"]. Never widens:
    a malformed value is removed (field default applies), never replaced
    by a broader token.
    """
    if not isinstance(parsed, dict):
        return {}
    for sec in list(parsed):
        body = parsed[sec]
        if sec in _TABLE_SECTIONS or sec in _SETTINGS_SECTIONS:
            if not isinstance(body, dict):
                del parsed[sec]
                _reject_block(stats, sec, "section is not a block")
                continue
        if sec in _TABLE_SECTIONS:
            for name in list(body):
                entry = body[name]
                if not isinstance(entry, dict):
                    del body[name]
                    _reject_block(stats, f"{sec}.{name}", "entry is not an edit block")
                    continue
                _norm_entry(entry, f"{sec}.{name}", stats,
                            _SECTION_SCALAR_KEYS.get(sec, frozenset()))
                for sub in entry.values():      # nested tables (realservers, ...)
                    if isinstance(sub, dict):
                        for sn in list(sub):
                            if isinstance(sub[sn], dict):
                                _norm_entry(sub[sn], f"{sec}.{name}.{sn}", stats)
        elif sec in _SETTINGS_SECTIONS:
            _norm_entry(body, sec, stats)
            for sub in body.values():
                if isinstance(sub, dict):
                    for sn in list(sub):
                        if isinstance(sub[sn], dict):
                            _norm_entry(sub[sn], f"{sec}.{sn}", stats)
                        else:
                            del sub[sn]
                            _reject_block(stats, f"{sec}.{sn}", "entry is not an edit block")
    return parsed



# ============================================================ resolver pass ==

def _netmask_to_prefix(mask: str) -> int:
    try:
        return bin(int(ipaddress.IPv4Address(mask))).count('1')
    except Exception:
        return 32


_MAX_RESOLVE_DEPTH = 64   # FortiOS allows up to ~64 levels of group nesting


def _resolve_address(name: str, addr_objects: dict, addr_groups: dict,
                     _seen: frozenset = frozenset(), stats=None, _memo=None) -> list:
    """
    Resolve a named address object or group to a list of CIDR strings,
    handling recursive addrgrp membership with cycle detection.

    Returns values in the form:
      "10.0.1.10/32"        — concrete host
      "10.0.1.0/24"         — concrete network
      "any"                 — the FortiOS 'all' / 'any' object
      "fqdn:example.com"    — FQDN (can't be concretized at parse time)
      "range:x-y"           — IP range object
      "cycle:<name>"        — circular reference detected
      "unresolved:<name>"   — referenced object not found in the config
      "dynamic:<name>"      — EMS-tag / SDN-connector object (run-time membership)
      "too-large:<name>"    — A-02: group > MAX_GROUP_MEMBERS members or
                              nested deeper than _MAX_RESOLVE_DEPTH
    Groups are memoised (per call tree, or across calls via `_memo`) and
    deduped, so "diamond" nesting resolves in linear time.
    """
    memo = _memo if _memo is not None else _Memo()
    if name in memo.data:
        return list(memo.data[name])
    if name in _seen:
        memo.cycles += 1
        return [f"cycle:{name}"]
    if len(_seen) >= _MAX_RESOLVE_DEPTH:
        memo.cycles += 1             # depth guard — avoids RecursionError
        return [_group_over(stats, name, f"nesting deeper than {_MAX_RESOLVE_DEPTH}")]
    _seen = _seen | {name}

    if name.lower() in ("all", "any", ""):
        return ["any"]

    if name in addr_objects:
        obj = addr_objects[name]
        obj_type = obj.get("type", "ipmask").lower()
        if "ip6" in obj and obj_type in ("ipprefix", "ipmask", ""):
            # config firewall address6: set ip6 2001:db8::/64 (F-07)
            ip6 = obj.get("ip6")
            ip6 = ip6[0] if isinstance(ip6, list) and ip6 else ip6
            try:
                net = ipaddress.ip_network(str(ip6), strict=False)
            except ValueError:
                return [f"unresolved:{name}"]
            return ["::/0" if net.prefixlen == 0 else str(net)]
        if obj_type == "dynamic":
            # EMS tag / fabric-connector objects: membership is decided at run time by
            # FortiClient EMS / the SDN connector, never visible in a backup -> an uncertain
            # token (fail-open in the reviews), distinct from "object not found"
            return [f"dynamic:{name}"]
        if obj_type in ("ipmask", "", "interface-subnet"):
            subnet = obj.get("subnet", [])
            if isinstance(subnet, str):
                subnet = [subnet] if subnet else []
            # AU full review D8: FortiOS accepts "set subnet a.b.c.d/nn" as well
            # as "a.b.c.d mask"; the one-token form used to be stored as "/32".
            if len(subnet) == 1 and subnet[0]:
                tok = str(subnet[0]).strip()
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    return [f"unresolved:{name}"]
                return [str(net)]
            if len(subnet) == 2:
                # Guard against empty first token (e.g. "set subnet '' 255.255.255.0")
                if not subnet[0]:
                    return [f"unresolved:{name}"]
                prefix = _netmask_to_prefix(subnet[1])
                return [f"{subnet[0]}/{prefix}"]
            if not subnet or not subnet[0]:
                return [f"unresolved:{name}"]
        elif obj_type == "iprange":
            # Expand the range to the minimal covering set of CIDRs so that
            # downstream consumers (shadow analyser, reachability) see normal
            # CIDR strings rather than an opaque "range:lo-hi" token.
            # ipaddress.summarize_address_range() does the arithmetic; the
            # common case (CIDR-aligned range) produces exactly one network.
            start_ip = obj.get("start-ip", "")
            end_ip   = obj.get("end-ip", "")
            if start_ip and end_ip:
                try:
                    cidrs = list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(start_ip),
                        ipaddress.ip_address(end_ip),
                    ))
                    return [str(c) for c in cidrs]
                except (ValueError, TypeError):
                    log.debug(
                        "_resolve_address: iprange CIDR expansion failed for %r "
                        "(start=%r end=%r); stored as range: token",
                        name, start_ip, end_ip,
                    )
            return [f"range:{start_ip}-{end_ip}" if start_ip or end_ip
                    else f"unresolved:{name}"]
        elif obj_type in ("fqdn", "wildcard-fqdn"):
            # Store with a type-qualified prefix so:
            #   - shadow/reachability engines skip it (unanalysable)
            #   - the fqdn_in_policy finding check can identify it precisely
            #   - wildcard variants are distinguishable from plain FQDNs
            value = str(_norm_scalar(obj.get("fqdn", name)) or name).strip('"')
            # FortiOS accepts "*.google.com" in a plain fqdn object - a wildcard all the same
            prefix = "wildcard-fqdn" if obj_type == "wildcard-fqdn" or "*" in value else "fqdn"
            return [f"{prefix}:{value}"]
        return [f"unresolved:{name}"]

    if name in addr_groups:
        members = addr_groups[name].get("member", [])
        if isinstance(members, str):
            members = [members]
        c0 = memo.cycles
        result = []
        for m in members:
            result.extend(_resolve_address(m, addr_objects, addr_groups, _seen, stats, memo))
        return _memo_store(memo, name, result, c0, stats, name)

    return [f"unresolved:{name}"]


# Built-in / predefined FortiGate services (common ICS + IT services that
# appear in policies without a corresponding custom-service definition in
# the config). Ports are in the canonical dst_port format (see
# firewall_parser module docstring). A custom service of the same name in
# the config always takes precedence over this table. Lookup is
# case-insensitive.
_BUILTIN_SERVICES: dict = {
    "ALL": [("any", "any")],
    "ALL_TCP": [("tcp", "any")], "ALL_UDP": [("udp", "any")],
    "ALL_ICMP": [("icmp", "any")], "PING": [("icmp", "any")],
    "TIMESTAMP": [("icmp", "any")], "INFO_REQUEST": [("icmp", "any")],
    "TRACEROUTE": [("udp", "33434-33535")],
    "HTTP": [("tcp", "80")], "HTTPS": [("tcp", "443")],
    "HTTP_PROXY": [("tcp", "8080")],
    "WEB ACCESS": [("tcp", "80,443")],
    "DNS": [("tcp", "53"), ("udp", "53")],
    "NTP": [("tcp", "123"), ("udp", "123")], "SMTP": [("tcp", "25")],
    "SMTPS": [("tcp", "465")], "IMAP": [("tcp", "143")],
    "IMAPS": [("tcp", "993")], "POP3": [("tcp", "110")],
    "POP3S": [("tcp", "995")],
    "FTP": [("tcp", "21")], "FTP_GET": [("tcp", "21")], "FTP_PUT": [("tcp", "21")],
    "FTPS": [("tcp", "990")], "TFTP": [("udp", "69")],
    "SSH": [("tcp", "22")], "TELNET": [("tcp", "23")],
    "RDP": [("tcp", "3389")], "VNC": [("tcp", "5900")],
    "SNMP": [("tcp", "161-162"), ("udp", "161-162")],
    "SNMPTRAP": [("udp", "162")],
    "SMB": [("tcp", "445")], "SAMBA": [("tcp", "139")],
    "NETBIOS-NS": [("udp", "137")], "NETBIOS-DGM": [("udp", "138")],
    "LDAP": [("tcp", "389")], "LDAPS": [("tcp", "636")], "LDAP_UDP": [("udp", "389")],
    "KERBEROS": [("tcp", "88"), ("udp", "88")],
    "MS-SQL": [("tcp", "1433-1434")], "MSSQL": [("tcp", "1433")],
    "MYSQL": [("tcp", "3306")], "ORACLE": [("tcp", "1521")],
    "SYSLOG": [("udp", "514")], "DHCP": [("udp", "67-68")],
    "BGP": [("tcp", "179")], "IKE": [("udp", "500,4500")],
    "L2TP": [("tcp", "1701"), ("udp", "1701")], "PPTP": [("tcp", "1723")],
    "SIP": [("udp", "5060")], "RADIUS": [("udp", "1812-1813")],
    "NNTP": [("tcp", "119")], "X-WINDOWS": [("tcp", "6000-6063")],
    "GRE": [("gre", "any")], "ESP": [("esp", "any")], "AH": [("ah", "any")],
    "OSPF": [("ospf", "any")],
    # ICS protocols (often also defined as custom services, but may
    # appear as built-in references in some FortiGate versions/builds)
    "MODBUS": [("tcp", "502")],
    "DNP3": [("tcp", "20000")],
    "S7": [("tcp", "102")], "S7COMM": [("tcp", "102")],
    "ETHERNET-IP": [("tcp", "44818")],
    "PROFINET": [("udp", "34964")],
    "BACNET": [("udp", "47808")],
}

_IP_PROTO_NUMBERS = {"0": "any", "1": "icmp", "6": "tcp", "17": "udp",
                     "47": "gre", "50": "esp", "51": "ah", "89": "ospf",
                     "132": "sctp"}


_PORT_MAX = 65535


def _forti_port_range(text: str) -> Optional[tuple]:
    """``lo[-hi]`` -> (lo, hi) when both are integers 0..65535 with lo <= hi,
    else None (B-15(c))."""
    lo_s, sep, hi_s = text.strip().partition("-")
    if not lo_s.isdigit() or (sep and not hi_s.isdigit()):
        return None
    lo = int(lo_s)
    hi = int(hi_s) if sep else lo
    if lo > _PORT_MAX or hi > _PORT_MAX or lo > hi:
        return None
    return lo, hi


def _forti_portrange_tokens(value) -> tuple:
    """
    FortiOS `set tcp-portrange 502 102 20000-20010 502:1024-65535`: each
    token is ``dst[:src]``, both ``lo[-hi]``.  Returns (ranges, invalid):
    the destination (lo, hi) of every VALID token, and the tokens that are
    not valid FortiOS syntax (non-numeric, outside 0-65535, lo > hi, a
    malformed source part).  B-15(c): invalid tokens are never dropped
    silently - callers turn them into an unresolved token.  Only the
    destination part is kept (source-port limits are not modelled).
    """
    if value is None:
        return [], []
    tokens = value if isinstance(value, list) else str(value).split()
    ranges, invalid = [], []
    for tok in tokens:
        tok = str(tok).strip()
        if not tok:
            continue
        dst, sep, src = tok.partition(":")
        rng = _forti_port_range(dst)
        if rng is None or (sep and _forti_port_range(src) is None):
            log.debug("_forti_portrange_tokens: invalid port token %r", tok)
            invalid.append(tok)
            continue
        ranges.append(rng)
    return ranges, invalid


def _forti_portrange_ranges(value) -> list:
    """Destination (lo, hi) ranges of the VALID tokens (see
    _forti_portrange_tokens)."""
    return _forti_portrange_tokens(value)[0]


def _resolve_service(name: str, svc_objects: dict, svc_groups: dict,
                     _seen: frozenset = frozenset(), stats=None, _memo=None) -> list:
    """
    Resolve a service name to a list of (protocol, port) tuples, one per
    protocol. Port is in canonical dst_port format ("80", "80,443",
    "1024-65535", "any") or "unresolved:<name>".
    """
    memo = _memo if _memo is not None else _Memo()
    if name in memo.data:
        return list(memo.data[name])
    if name in _seen:
        memo.cycles += 1
        return []
    if len(_seen) >= _MAX_RESOLVE_DEPTH:
        memo.cycles += 1   # depth guard — avoids RecursionError on deep groups
        return [("any", _group_over(stats, name, f"nesting deeper than {_MAX_RESOLVE_DEPTH}"))]
    _seen = _seen | {name}

    if name in svc_objects:
        obj = svc_objects[name]
        proto_kind = str(obj.get("protocol", "TCP/UDP/SCTP")).upper()
        if proto_kind in ("ICMP", "ICMP6"):
            return [("icmp", "any")]
        if proto_kind == "IP":
            num = str(obj.get("protocol-number", "0"))
            return [(_IP_PROTO_NUMBERS.get(num, num), "any")]
        if proto_kind == "ALL":
            return [("any", "any")]
        results = []
        for key, proto in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"),
                           ("sctp-portrange", "sctp")):
            if obj.get(key):
                ranges, invalid = _forti_portrange_tokens(obj[key])
                field = canonical_ports(ranges) if ranges else ""
                if field:
                    results.append((proto, field))
                if invalid:
                    # B-15(c): an invalid port token (`70000-80000`, `abc`,
                    # `90-80`) is an unresolved service, never "any port"
                    # (A-04 fail-unknown: it cannot silently widen a permit).
                    if stats is not None:
                        stats["services_invalid_ports"] = stats.get("services_invalid_ports", 0) + 1
                    results.append((proto, f"unresolved:invalid-port:{name}"))
        if not results:
            # B-15(c): a TCP/UDP/SCTP service with no port range at all is
            # not a valid FortiOS service - unresolved, never any/any.
            if stats is not None:
                stats["services_invalid_ports"] = stats.get("services_invalid_ports", 0) + 1
            return [("any", f"unresolved:no-port-range:{name}")]
        return results

    if name in svc_groups:
        members = svc_groups[name].get("member", [])
        if isinstance(members, str):
            members = [members]
        c0 = memo.cycles
        result = []
        for m in members:
            result.extend(_resolve_service(m, svc_objects, svc_groups, _seen, stats, memo))
        return _memo_store(memo, name, result, c0, stats, name, lambda t: ("any", t))

    if name.upper() in ("ALL", "ANY"):
        return [("any", "any")]
    builtin = _BUILTIN_SERVICES.get(name.upper())
    if builtin:
        return list(builtin)

    return [("any", f"unresolved:{name}")]


def _port_hits(port_str, ports) -> bool:
    """True when a canonical dst_port explicitly includes one of `ports`."""
    return port_field_hits(None if port_str is None else str(port_str), ports)


# ============================================================= extraction ==

def _extract_zones(parsed: dict) -> dict:
    """
    Extract interface → zone mapping from config system interface.
    Returns {interface_name: {zone, ip, vlan_id, type, alias,
    parent_interface_name}}.

    parent_interface_name is populated for 802.1Q VLAN sub-interfaces from
    the FortiOS `set interface <parent>` directive - e.g. "port3.10" has
    `set interface port3`.  Physical/aggregate/tunnel interfaces have no
    parent and carry parent_interface_name=None.  The caller resolves the
    name to a parent_interface_id FK after all rows exist.
    """
    zones = {}
    for iface_name, cfg in parsed.get("system interface", {}).items():
        ips = cfg.get("ip", [])
        if isinstance(ips, str):
            ips = [ips]
        ip_cidr = None
        if len(ips) >= 2:
            try:
                prefix = _netmask_to_prefix(ips[1])
                ip_cidr = f"{ips[0]}/{prefix}"
            except Exception:
                ip_cidr = ips[0]
        elif len(ips) == 1:
            ip_cidr = f"{ips[0]}/32"

        zones[iface_name] = {
            # Prefer the explicit 'zone' assignment; fall back to iface_name,
            # NOT cfg.get("vdom") — the vdom value is the VDOM name, not a
            # security zone, and using it corrupts zone-based policy checks.
            "zone": cfg.get("zone") or iface_name,
            "ip": ip_cidr,
            "vlan_id": cfg.get("vlanid"),
            "type": cfg.get("type", "physical"),
            "alias": cfg.get("alias"),
            "allowaccess": cfg.get("allowaccess", []),
            # 802.1Q parent: FortiOS stores `set interface <parent>` in the
            # same cfg block; only present for vlan-type sub-interfaces.
            "parent_interface_name": cfg.get("interface") or None,
            "vdom": _norm_scalar(cfg.get("vdom")),
        }
    return zones


def _extract_zone_defs(parsed: dict, stats: Optional[dict] = None) -> list:
    """
    B-07: FortiOS zones of one VDOM view -> [{name, kind, intrazone,
    members, members_resolved}].

      * ``config system zone`` / ``edit <zone>`` / ``set interface a b`` /
        ``set intrazone allow|deny`` (FortiOS default: deny) -> kind "zone";
      * ``config system sdwan`` (6.4+): ``config zone`` declares the SD-WAN
        zones, ``config members`` / ``edit N`` / ``set interface X`` /
        ``set zone Z`` puts X in Z (default zone "virtual-wan-link") ->
        kind "sdwan";
      * ``config system virtual-wan-link`` (6.0 / 6.2): its members form the
        single zone "virtual-wan-link".
    A member entry without a parseable ``set interface`` makes its zone
    ``members_resolved`` False (an SD-WAN member whose zone cannot be read
    taints every SD-WAN zone of the view).  SD-WAN zones carry intrazone
    None: traffic between two members needs a zone->zone policy (treated
    like intrazone deny).
    """
    out: list = []
    zsec = parsed.get("system zone")
    if isinstance(zsec, dict):
        for zname, cfg in zsec.items():
            if not isinstance(cfg, dict):
                continue
            members = [str(m) for m in _as_list(cfg.get("interface")) if str(m).strip()]
            intra = str(_norm_scalar(cfg.get("intrazone")) or "deny").strip().lower()
            if intra not in ("allow", "deny"):
                intra = "deny"           # unknown keyword: FortiOS default
            out.append({"name": str(zname), "kind": "zone", "intrazone": intra,
                        "members": list(dict.fromkeys(members)), "members_resolved": True})

    for sec_name in ("system sdwan", "system virtual-wan-link"):
        sd = parsed.get(sec_name)
        if not isinstance(sd, dict):
            continue
        legacy = sec_name == "system virtual-wan-link"
        zones: dict = {}
        declared = sd.get("zone") if isinstance(sd.get("zone"), dict) else {}
        if not legacy:
            for zname in declared:
                zones.setdefault(str(zname), {"members": [], "resolved": True})
        zones.setdefault("virtual-wan-link", {"members": [], "resolved": True})
        members = sd.get("members")
        unplaced = False
        if isinstance(members, dict):
            for _mid, mcfg in members.items():
                if not isinstance(mcfg, dict):
                    unplaced = True
                    continue
                iface = _norm_scalar(mcfg.get("interface"))
                zname = "virtual-wan-link" if legacy else str(
                    _norm_scalar(mcfg.get("zone")) or "virtual-wan-link")
                z = zones.setdefault(zname, {"members": [], "resolved": True})
                if not iface or not str(iface).strip():
                    z["resolved"] = False
                    continue
                if iface not in z["members"]:
                    z["members"].append(str(iface))
        elif members is not None:
            unplaced = True
        for zname, z in zones.items():
            resolved = z["resolved"] and not unplaced
            if zname == "virtual-wan-link" and not legacy and not z["members"] \
                    and "virtual-wan-link" not in declared and resolved:
                continue                 # implicit default zone that nothing uses
            if not resolved and stats is not None:
                stats["zones_unresolved"] = stats.get("zones_unresolved", 0) + 1
            out.append({"name": zname, "kind": "sdwan", "intrazone": None,
                        "members": z["members"], "members_resolved": resolved})
    return out


def _is_default_dst(raw) -> bool:
    """True for a missing ``dst`` or ``0.0.0.0 0.0.0.0`` / ``0.0.0.0/0`` (a full backup prints the
    default route's dst; ``show`` omits it)."""
    if not raw:
        return True
    raw = " ".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else str(raw)
    parts = raw.replace("/", " ").split()
    return bool(parts) and parts[0] == "0.0.0.0" and (len(parts) == 1 or parts[1] in ("0.0.0.0", "0"))


def _tunnel_nets(parsed: dict, tunnels: Optional[dict] = None) -> list:
    """[(cidr, tunnel, kind)] - every network that lies behind a tunnel of this firewall: the remote
    phase 2 selectors of site-to-site IPsec tunnels, the client pools of dial-up IPsec tunnels and
    the SSL-VPN tunnel address pools.  Owner 2026-10-19: "IP addresses reached through tunnels
    (ipsec, vpn, etc) should be considered remote"."""
    out = []

    def _nets(spec):
        for part in str(spec or "").split(","):
            part = part.strip()
            if not part or part.startswith("0.0.0.0/0"):
                continue
            try:
                if "-" in part:
                    a, b = part.split("-", 1)
                    for n in ipaddress.summarize_address_range(ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())):
                        yield str(n)
                else:
                    n = ipaddress.ip_network(part, strict=False)
                    if n.prefixlen:
                        yield str(n)
            except ValueError:
                continue
    try:
        for t in (tunnels if tunnels is not None else extract_tunnels(parsed)).values():
            kind = "dial-up IPsec" if t.get("dynamic") else "IPsec"
            for sel in t.get("selectors") or []:
                for n in _nets(sel.get("remote")):
                    out.append((n, t["name"], kind))
    except Exception:            # never let the placement break the config pass
        log.debug("_tunnel_nets: tunnel extraction failed", exc_info=True)
    ssl = parsed.get("vpn ssl settings") or {}
    if isinstance(ssl, dict) and ssl.get("tunnel-ip-pools"):
        ao, ag = _build_addr_registry(parsed)
        for pname in _as_list(ssl.get("tunnel-ip-pools")):
            for tok in _resolve_address(str(pname).strip('"'), ao, ag):
                for n in _nets(tok.replace("range:", "")):
                    out.append((n, "ssl.root", "SSL-VPN"))
    return out


def _place_source(tok: str, ctx: dict) -> dict:
    """Where an address token of a policy stands relative to this firewall: ``local`` (an interface
    network), ``internal`` (a static route through a non-tunnel interface), ``remote`` (behind an
    IPsec / SSL-VPN tunnel - a selector, a client pool or a route through a tunnel interface),
    ``external`` (public address, FQDN, Internet service) or ``unplaced`` (private address this
    firewall has no interface or route for).  ``outside`` says whether the source lies outside the
    site (remote, external or unplaced)."""
    t = str(tok).strip()
    if t.startswith(("fqdn:", "wildcard-fqdn:", "internet-service")):
        return {"kind": "external", "where": "name / Internet service", "outside": True}
    if t == "any":
        return {"kind": "any", "where": "any address", "outside": True}
    if t.startswith("dynamic:"):
        return {"kind": "unknown", "where": "EMS tag / SDN connector (membership decided at run time)", "outside": False}
    if t.startswith("cycle:"):
        return {"kind": "unknown", "where": "group references itself", "outside": False}
    try:
        n = ipaddress.ip_network(t.replace("range:", "").split("-", 1)[0], strict=False)
    except ValueError:
        return {"kind": "unknown", "where": "unresolved object", "outside": False}
    a = n.network_address
    # the firewall's own networks first: a wide tunnel selector (10.0.0.0/8) must not make the site remote
    for cidr, iname, lvl in ctx.get("local_nets") or []:
        try:
            if a in ipaddress.ip_network(cidr):
                return {"kind": "local", "where": f"interface {iname}", "outside": False}
        except ValueError:
            continue
    for cidr, tun, kind in ctx.get("tunnel_nets") or []:
        try:
            if n.subnet_of(ipaddress.ip_network(cidr)) or a in ipaddress.ip_network(cidr):
                return {"kind": "remote", "where": f"behind {kind} tunnel {tun} ({cidr})", "tunnel": tun, "outside": True}
        except (ValueError, TypeError):
            continue
    tunnels = {str(x).lower() for x in (ctx.get("tunnel_interfaces") or [])}
    for cidr, dev in ctx.get("routed_nets") or []:
        try:
            if a in ipaddress.ip_network(cidr):
                if dev and dev.lower() in tunnels:
                    return {"kind": "remote", "where": f"remote site via {dev} (static route {cidr})", "tunnel": dev, "outside": True}
                return {"kind": "internal", "where": f"static route {cidr}" + (f" via {dev}" if dev else ""), "outside": False}
        except ValueError:
            continue
    if n.is_global:
        return {"kind": "external", "where": "public address", "outside": True}
    # a wide object that contains one of this firewall's networks (10.0.0.0/8 over a 10.168.x site) covers the site
    for cidr, *_ in list(ctx.get("local_nets") or []) + list(ctx.get("routed_nets") or []):
        try:
            if ipaddress.ip_network(cidr).subnet_of(n):
                return {"kind": "wide", "where": f"contains this firewall's network {cidr}", "outside": False}
        except (ValueError, TypeError):
            continue
    return {"kind": "unplaced", "where": "private address with no interface or route of this firewall", "outside": True}


_FORTITRUST_HOSTS = ("fortitrustid.forticloud.com", "fortitrust-id", "ftid.forticloud")


def _saml_idps(parsed: dict) -> dict:
    """{name: {"idp": host, "mfa": bool, "used_by": [tunnels]}} for ``config user saml``: the IdP host
    from idp-entity-id / idp-single-sign-on-url; FortiTrust ID (Fortinet's cloud identity service,
    MFA by design) is recognised by its host - any other IdP may or may not enforce MFA."""
    import re as _re
    out = {}
    for n, c in (parsed.get("user saml") or {}).items():
        if not isinstance(c, dict):
            continue
        host = ""
        for k in ("idp-single-sign-on-url", "idp-entity-id"):
            v = str(_norm_scalar(c.get(k)) or "").strip('"')
            m = _re.match(r"^\w+://([^/:]+)", v)
            if m:
                host = m.group(1).lower(); break
        out[str(n).strip('"')] = {"idp": host or None, "mfa": any(h in host for h in _FORTITRUST_HOSTS), "used_by": []}
    for p1, c in (parsed.get("vpn ipsec phase1-interface") or {}).items():
        if isinstance(c, dict) and c.get("ike-saml-server"):
            srv = str(_norm_scalar(c.get("ike-saml-server")) or "").strip('"')
            if srv in out:
                out[srv]["used_by"].append(str(p1).strip('"'))
    # FortiOS 7.4: the IKE SAML portal is bound to the interface that hosts it (system interface ike-saml-server)
    for iname, c in (parsed.get("system interface") or {}).items():
        if isinstance(c, dict) and c.get("ike-saml-server"):
            srv = str(_norm_scalar(c.get("ike-saml-server")) or "").strip('"')
            if srv in out:
                out[srv]["used_by"].append(f"interface {str(iname).strip(chr(34))}")
    return out


def _addr_objects(parsed: dict) -> dict:
    """``config firewall address`` as {name: cfg}, with ``type interface-subnet`` objects completed.

    Owner tabletop 2026-10-19: FortiOS writes ``"vlan_20 address"`` objects as ``interface-subnet``
    - with the interface's subnet when it is static, or ``0.0.0.0 255.255.255.255`` when the
    address follows the interface (DHCP / IPAM).  The empty form takes the network of the named
    ``system interface`` so a policy to "dmz" is bounded instead of unresolved.  Copies, never
    mutates the parsed tree."""
    out = {}
    ifaces = parsed.get("system interface") or {}
    for k, v in (parsed.get("firewall address") or {}).items():
        if not isinstance(v, dict):
            continue
        name = str(k).strip('"')
        if str(v.get("type", "")).lower() == "interface-subnet":
            sub = _as_list(v.get("subnet"))
            empty = not sub or str(sub[0]).strip() in ("0.0.0.0", "0.0.0.0/0", "0.0.0.0/32", "")
            if empty:
                v = dict(v)
                v["subnet"] = []
                icfg = ifaces.get(str(v.get("interface") or "").strip('"')) or {}
                toks = [str(t) for t in _as_list((icfg if isinstance(icfg, dict) else {}).get("ip")) if str(t).strip()]
                if toks:
                    try:
                        net = ipaddress.ip_interface(f"{toks[0]}/{toks[1]}" if len(toks) > 1 else toks[0]).network
                        if net.prefixlen:
                            v["subnet"] = [str(net.network_address), str(net.netmask)]
                            v["_from_interface"] = True
                    except ValueError:
                        pass
        out[name] = v
        if k != name:
            out[k] = v
    return out


def _build_addr_registry(parsed: dict) -> tuple:
    """Build (addr_objects, addr_groups) lookup dicts from the parsed config."""
    addr_objects = _addr_objects(parsed)
    addr_groups = dict(parsed.get("firewall addrgrp", {}))
    return addr_objects, addr_groups


def _build_svc_registry(parsed: dict) -> tuple:
    """Build (svc_objects, svc_groups) lookup dicts from the parsed config."""
    svc_objects = dict(parsed.get("firewall service custom", {}))
    svc_groups = dict(parsed.get("firewall service group", {}))
    return svc_objects, svc_groups


def _build_addr6_registry(parsed: dict) -> tuple:
    """(addr6_objects, addr6_groups) from config firewall address6 / addrgrp6."""
    return (dict(parsed.get("firewall address6", {})),
            dict(parsed.get("firewall addrgrp6", {})))


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _forti_host(ip: str) -> str:
    """FortiOS row form of a host: "a.b.c.d/32" / "x::y/128"."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return f"unresolved:{ip}"
    return f"{a}/{a.max_prefixlen}"


def _forti_mapped_values(value) -> list:
    """VIP mappedip / extip values ("10.0.0.5", "10.0.0.5-10.0.0.9",
    "10.0.0.0/24") -> FirewallRule address strings."""
    out = []
    for tok in _as_list(value):
        tok = str(tok).strip()
        if not tok:
            continue
        if "-" in tok:
            a, _, b = tok.partition("-")
            try:
                nets = list(ipaddress.summarize_address_range(
                    ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())))
                out.extend(str(n) for n in nets)
                continue
            except (ValueError, TypeError):
                out.append(f"range:{tok}")
                continue
        if "/" in tok:
            try:
                out.append(str(ipaddress.ip_network(tok, strict=False)))
                continue
            except ValueError:
                pass
        out.append(_forti_host(tok))
    return out


def _build_vip_registry(parsed: dict) -> dict:
    """
    {name: {"mapped": [addr], "cfg": dict | None, "members": [vip names],
            "v6": bool}} from config firewall vip / vip6 / vipgrp / vipgrp6.
    A VIP referenced as a policy dstaddr resolves to its MAPPED (inside)
    address - FortiOS matches the policy after destination NAT.
    """
    vips: dict = {}
    # (section, mapped-address family is v6, kind).  vip46: IPv4 external ->
    # IPv6 mapped; vip64: IPv6 external -> IPv4 mapped (N-25) - the policy
    # that uses it (policy46 / policy64) sees the MAPPED family on its dst.
    for section, v6, kind in (("firewall vip", False, "vip"), ("firewall vip6", True, "vip"),
                              ("firewall vip46", True, "vip46"),
                              ("firewall vip64", False, "vip64")):
        for name, cfg in parsed.get(section, {}).items():
            if not isinstance(cfg, dict):
                continue
            vtype = str(cfg.get("type", "static-nat")).lower()
            if vtype == "load-balance" or (not cfg.get("mappedip") and cfg.get("realservers")):
                mapped = []
                rs = cfg.get("realservers")
                if isinstance(rs, dict):
                    for _rid, rcfg in rs.items():
                        if isinstance(rcfg, dict) and rcfg.get("ip"):
                            mapped.extend(_forti_mapped_values(rcfg.get("ip")))
            elif vtype == "fqdn":
                mapped = [f"fqdn:{cfg.get('mapped-addr', name)}"]
            else:
                mapped = _forti_mapped_values(cfg.get("mappedip"))
            vips[name] = {"mapped": mapped or [f"unresolved:{name}"], "cfg": cfg,
                          "members": [name], "v6": v6, "kind": kind}
    for section, v6 in (("firewall vipgrp", False), ("firewall vipgrp6", True),
                        ("firewall vipgrp46", True), ("firewall vipgrp64", False)):
        for name, cfg in parsed.get(section, {}).items():
            if not isinstance(cfg, dict):
                continue
            members = [m for m in _as_list(cfg.get("member")) if m in vips]
            mapped = []
            for m in members:
                mapped.extend(v for v in vips[m]["mapped"] if v not in mapped)
            vips[name] = {"mapped": mapped or [f"unresolved:{name}"], "cfg": None,
                          "members": members, "v6": v6, "kind": "vipgrp"}
    return vips


_ISDB_KEYS = (
    ("internet-service-name", ""), ("internet-service-id", "id-"),
    ("internet-service-group", "group-"), ("internet-service-custom", "custom-"),
    ("internet-service-custom-group", "custom-group-"),
)


def _internet_service_tokens(cfg: dict, src: bool = False, v6: bool = False,
                             legacy_keys: bool = False) -> list:
    """`set internet-service[6][-src] enable` + names/ids -> unresolved-style
    "internet-service[6]:<name>" tokens (FortiGuard ISDB entries cannot be
    expanded offline).

    N-25: ``v6`` reads the IPv6 keys (`internet-service6`, `-name`, `-id`,
    `-group`, `-custom`, `-custom-group`, and the `-src` forms) and tags the
    tokens "internet-service6:..." so they stay IPv6-family address sets.
    ``legacy_keys`` (a `config firewall policy6` entry) also accepts the
    plain `internet-service*` keys, which is how older policy6 tables spell
    it.  Like the IPv4 tokens they are unresolvable address sets and are
    external/internet destinations (see EXTERNAL_ADDR_PREFIXES)."""
    for plain in ((False, True) if (v6 and legacy_keys) else (not v6,)):
        base = "internet-service6" if (v6 and not plain) else "internet-service"
        prefix = base + ("-src" if src else "")
        if str(cfg.get(prefix, "disable")).lower() != "enable":
            continue
        tag_out = "internet-service6:" if v6 else "internet-service:"
        toks = []
        for key, tag in _ISDB_KEYS:
            k = key.replace("internet-service", prefix, 1)
            for val in _as_list(cfg.get(k)):
                toks.append(f"{tag_out}{tag}{val}")
        return toks or [f"{tag_out}unspecified"]
    return []


# EXTERNAL_ADDR_PREFIXES / is_external_addr_token live in rule_match (shared with
# reachability); the ISDB tokens built above are external/internet address sets.
from app.parsers.rule_match import EXTERNAL_ADDR_PREFIXES, is_external_addr_token  # noqa: E402,F401


def _extract_policies(parsed: dict, zones: dict,
                      addr_objects: dict, addr_groups: dict,
                      svc_objects: dict, svc_groups: dict,
                      stats: Optional[dict] = None,
                      vips: Optional[dict] = None,
                      addr6_objects: Optional[dict] = None,
                      addr6_groups: Optional[dict] = None) -> tuple:
    """
    Walk config firewall policy (and policy6) and expand all object references.

    Returns (rules, fqdn_findings) where:
      rules         — list of normalized policy dicts ready for FirewallRule rows.
                      One FortiOS policy can expand to many FirewallRule rows when
                      it references address groups or service groups with multiple
                      members.  IP-range objects are expanded to covering CIDRs
                      here (via _resolve_address) rather than stored as "range:..."
                      tokens, so they are fully analysable by the shadow and
                      reachability engines.
      fqdn_findings — list of dicts describing FQDN / wildcard-FQDN address
                      objects found in policy srcaddr/dstaddr.  Emitted as
                      "fqdn_in_policy" findings when generate_findings=True.
                      Each dict: {policy_id, policy_name, field, fqdn_value, obj_type}

    IPv6 (F-07): `config firewall policy6` (srcaddr/dstaddr -> address6 /
    addrgrp6) and srcaddr6/dstaddr6 of a unified (6.4+) `config firewall
    policy` produce IPv6 rows; "all" there becomes "::/0" so a v6 row never
    matches IPv4. A unified policy with only *addr6 fields has no IPv4 rows.
    policy6 entries get policy_id "policy6:<id>" (their IDs are a separate
    namespace) and rule_order after every `firewall policy` entry.

    VIPs (F-05): a VIP / VIP group used as dstaddr resolves to its MAPPED
    address; the VIP names are kept in rule["vip_names"].

    internet-service (F-15): with `set internet-service enable` the
    destination is the ISDB entry -> dst "internet-service:<name>" (and the
    policy's service is ignored, as FortiOS does); counted in
    stats["internet_service_refs"].
    """
    rules = []
    fqdn_findings = []
    iface_to_zone = {k: v["zone"] for k, v in zones.items()}
    if stats is None:
        stats = {}
    for key in ("rules_disabled", "rules_skipped_negated_deny", "rules_ipv6",
                "internet_service_refs", "internet_service6_refs",
                "rules_cross_family", "rules_skipped_unknown_action",
                "groups_over_limit", "rules_over_limit"):
        stats.setdefault(key, 0)
    if vips is None:
        vips = _build_vip_registry(parsed)
    if addr6_objects is None or addr6_groups is None:
        addr6_objects, addr6_groups = _build_addr6_registry(parsed)

    def _flag(cfg, key) -> bool:
        return str(cfg.get(key, "disable")).lower() == "enable"

    v4_table = parsed.get("firewall policy", {})
    tables = [("firewall policy", v4_table, 0)]
    offset = len(v4_table)
    # policy6, then (N-25) the address-family translating policy46 / policy64,
    # each with its own id namespace and positions after everything before it.
    for tname in ("firewall policy6", "firewall policy46", "firewall policy64"):
        tbl = parsed.get(tname)
        if isinstance(tbl, dict) and tbl:
            tables.append((tname, tbl, offset))
            offset += len(tbl)

    # T1-23: FortiOS evaluates policies in CONFIG order (a `move` keeps the
    # policy ID but changes the position), so rule_order is the policy's
    # position in the section. parse_forti_block stores entries in a plain
    # dict, which preserves insertion (= config) order.
    for table_name, table, offset in tables:
        is_policy6 = table_name == "firewall policy6"
        xfam = {"firewall policy46": "46", "firewall policy64": "64"}.get(table_name)
        for position, (raw_pid, cfg) in enumerate(table.items(), start=1 + offset):
            if not isinstance(cfg, dict):
                continue
            policy_id = (f"policy6:{raw_pid}" if is_policy6
                         else f"policy{xfam}:{raw_pid}" if xfam else str(raw_pid))
            rules.extend(_policy_rows(
                policy_id, position, cfg, is_policy6, iface_to_zone,
                addr_objects, addr_groups, addr6_objects, addr6_groups, vips,
                svc_objects, svc_groups, stats, fqdn_findings, _flag, xfam=xfam))

    return rules, fqdn_findings


def _policy_rows(policy_id, position, cfg, is_policy6, iface_to_zone,
                 addr_objects, addr_groups, addr6_objects, addr6_groups, vips,
                 svc_objects, svc_groups, stats, fqdn_findings, _flag,
                 xfam: Optional[str] = None) -> list:
    """Expand one FortiOS policy into FirewallRule dicts (see _extract_policies).

    ``xfam`` ("46" / "64", N-25): a `config firewall policy46` (IPv4 client ->
    VIP46 -> IPv6 server) / `policy64` (IPv6 client -> VIP64 -> IPv4 server)
    entry.  Its rows are cross-family: src is of the client family, dst the
    VIP's MAPPED address of the other family (the FortiOS "post-NAT" policy
    convention used for every VIP here), and notes record the translation."""
    # Disabled policies enforce nothing, but are kept (enabled=False) so
    # review_disabled_rules can flag them for removal (3.8 / SR 7.7).
    # Every analysis filters them out; fqdn findings are not raised for them.
    enabled = str(cfg.get("status", "enable")).lower() != "disable"
    action_raw = str(cfg.get("action", "deny")).strip().lower()
    action_note = None
    if action_raw == "accept":
        action = "permit"
    elif action_raw == "deny":
        action = "deny"
    elif action_raw == "ipsec":
        # A-07: policy-based IPsec VPN - permits traffic into/out of the tunnel.
        action = "permit"
        action_note = "action ipsec (policy-based VPN tunnel)"
    else:
        stats["rules_skipped_unknown_action"] = stats.get("rules_skipped_unknown_action", 0) + 1
        log.warning("FortiOS policy %s: unknown action %r - not stored", policy_id, action_raw)
        return []

    # T1-21: negation. Permit -> widen the negated side to "any" (over-
    # approximates exposure); deny -> skip (never over-state blocking).
    neg_src = _flag(cfg, "srcaddr-negate") or _flag(cfg, "srcaddr6-negate")
    neg_dst = _flag(cfg, "dstaddr-negate") or _flag(cfg, "dstaddr6-negate")
    neg_svc = _flag(cfg, "service-negate")
    if (neg_src or neg_dst or neg_svc) and action == "deny" and enabled:
        stats["rules_skipped_negated_deny"] += 1
        return []
    if not enabled:
        stats["rules_disabled"] += 1
    notes = [action_note] if action_note else []

    src_intf_raw = cfg.get("srcintf", "any")
    dst_intf_raw = cfg.get("dstintf", "any")
    # A-6: when an interface field is a list (multi-interface policy), preserve
    # the list for zone lookup rather than joining to a single string.  Each
    # interface is looked up individually; the union of resolved zones is used.
    if isinstance(src_intf_raw, list):
        src_intf = ",".join(src_intf_raw)
        src_zone = ",".join(iface_to_zone.get(i, i) for i in src_intf_raw)
    else:
        src_intf = src_intf_raw
        src_zone = iface_to_zone.get(src_intf_raw, src_intf_raw)
    if isinstance(dst_intf_raw, list):
        dst_intf = ",".join(dst_intf_raw)
        dst_zone = ",".join(iface_to_zone.get(i, i) for i in dst_intf_raw)
    else:
        dst_intf = dst_intf_raw
        dst_zone = iface_to_zone.get(dst_intf_raw, dst_intf_raw)

    policy_name = cfg.get("name")
    # FQDN-in-policy findings only matter for policies in effect.
    _fqdn_sink = fqdn_findings if enabled else []
    vip_names: list = []
    # C-02: mapped-destination value -> VIP port-forward (proto, ext, mapped)
    # so the service port can be translated to the post-NAT (mapped) port.
    portfwd_by_dst: dict = {}

    memos = {id(addr_groups): _Memo(), id(addr6_groups): _Memo()}

    def _resolve_side(names, field, objs, groups, v6, use_vips):
        out = []
        out_set = set()
        for name in names:
            if use_vips and name in vips and vips[name]["v6"] == v6:
                if name not in vip_names:
                    vip_names.append(name)
                resolved = vips[name]["mapped"]
                # C-02: record each mapped address' port-forward mapping.
                for member in vips[name].get("members", [name]):
                    mv = vips.get(member)
                    if not mv:
                        continue
                    pm = _vip_portmap(mv.get("cfg"))
                    if pm is None:
                        continue
                    for mval in mv.get("mapped", []):
                        portfwd_by_dst[mval] = pm
            else:
                resolved = _resolve_address(name, objs, groups, stats=stats,
                                            _memo=memos[id(groups)])
            for val in resolved:
                if val.startswith("fqdn:") or val.startswith("wildcard-fqdn:"):
                    obj_type = "wildcard-fqdn" if val.startswith("wildcard-fqdn:") else "fqdn"
                    _fqdn_sink.append({
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "field": field,
                        "object_name": name,
                        "fqdn_value": val.split(":", 1)[1],
                        "obj_type": obj_type,
                    })
                    # DR-02: kept as an external destination token (was
                    # dropped - an FQDN-only policy produced no rule rows).
                if v6 and val == "any":
                    val = "::/0"
                if val not in out_set:
                    out_set.add(val)
                    out.append(val)
        return out

    # (src family, dst family, src names, dst names, src field, dst field).
    # Same-family policies have equal families; policy46 / policy64 (N-25)
    # translate the family: the client side is the policy's own family and
    # the dst (a VIP46 / VIP64) resolves to the VIP's MAPPED family.
    sides = []
    if xfam:
        cf, sf = (4, 6) if xfam == "46" else (6, 4)
        sides.append((cf, sf, _as_list(cfg.get("srcaddr", "all")),
                      _as_list(cfg.get("dstaddr", "all")), "srcaddr", "dstaddr"))
        notes.append(f"policy{xfam}: IPv{cf} client -> IPv{sf} server via VIP{xfam} "
                     f"(address-family translation)")
    elif is_policy6:
        sides.append((6, 6, _as_list(cfg.get("srcaddr", "all")),
                      _as_list(cfg.get("dstaddr", "all")), "srcaddr", "dstaddr"))
    else:
        has_v6 = "srcaddr6" in cfg or "dstaddr6" in cfg
        has_v4 = "srcaddr" in cfg or "dstaddr" in cfg or not has_v6
        if has_v4:
            sides.append((4, 4, _as_list(cfg.get("srcaddr", "all")),
                          _as_list(cfg.get("dstaddr", "all")), "srcaddr", "dstaddr"))
        if has_v6:
            sides.append((6, 6, _as_list(cfg.get("srcaddr6", "all")),
                          _as_list(cfg.get("dstaddr6", "all")), "srcaddr6", "dstaddr6"))

    # internet-service: IPv4 keys feed the IPv4 side, `internet-service6*`
    # keys (N-25; plain keys too on a policy6 entry) the IPv6 side.
    isdb_dst = _internet_service_tokens(cfg)
    isdb_src = _internet_service_tokens(cfg, src=True)
    isdb_dst6 = _internet_service_tokens(cfg, v6=True, legacy_keys=is_policy6)
    isdb_src6 = _internet_service_tokens(cfg, src=True, v6=True, legacy_keys=is_policy6)
    stats["internet_service_refs"] += len(isdb_dst) + len(isdb_src)
    stats["internet_service6_refs"] += len(isdb_dst6) + len(isdb_src6)

    # Resolve service
    svcs_raw = _as_list(cfg.get("service", "ALL"))
    resolved_svcs = []
    svc_memo = _Memo()
    for svc_name in svcs_raw:
        resolved_svcs.extend(_resolve_service(svc_name, svc_objects, svc_groups,
                                              stats=stats, _memo=svc_memo))
    resolved_svcs = _dedupe(resolved_svcs)
    # Canonical fields longer than the column split into several rows
    resolved_svcs = [
        (proto, chunk)
        for proto, port in resolved_svcs
        for chunk in split_port_field(port)
    ]
    if neg_svc:
        notes.append(f"negated service: {' '.join(svcs_raw)}")
        resolved_svcs = [("any", "any")]

    # Flags for security-relevant config
    logtraffic = str(cfg.get("logtraffic", "utm")).lower()
    nat = str(cfg.get("nat", "disable")).lower() == "enable"
    if xfam:
        # policy46 / policy64 have no `nat` switch: source translation is
        # the `ippool enable` + `poolname` pair (see _extract_nat).
        nat = _flag(cfg, "ippool") and bool(_as_list(cfg.get("poolname")))
    ips_sensor = cfg.get("ips-sensor")
    av_profile = cfg.get("av-profile")
    app_list = cfg.get("application-list")

    ippool_on = _flag(cfg, "ippool")
    pools4 = _as_list(cfg.get("poolname")) if ippool_on else []
    pools6 = (_as_list(cfg.get("poolname6")) or pools4) if ippool_on else []

    rows = []
    v6_rows = False
    all_svcs = resolved_svcs
    for sfam, dfam, src_names, dst_names, sfield, dfield in sides:
        sv6, dv6 = sfam == 6, dfam == 6
        v6 = sv6                                  # row family = client family
        cross = sfam != dfam
        s_objs, s_groups = (addr6_objects, addr6_groups) if sv6 else (addr_objects, addr_groups)
        d_objs, d_groups = (addr6_objects, addr6_groups) if dv6 else (addr_objects, addr_groups)
        side_isdb_src = (isdb_src6 if sv6 else isdb_src)
        side_isdb_dst = (isdb_dst6 if dv6 else isdb_dst)
        src_cidrs = (list(side_isdb_src) if side_isdb_src
                     else _resolve_side(src_names, sfield, s_objs, s_groups, sv6, False))
        if side_isdb_dst:
            dst_cidrs = list(side_isdb_dst)
            # ISDB entries carry their own protocol/ports; FortiOS ignores service
            resolved_svcs = [("any", "any")]
            note = ("internet-service" + ("6" if dv6 else "") + ": " + " ".join(side_isdb_dst)
                    + " [external/internet]")
            if note not in notes:
                notes.append(note)
        else:
            resolved_svcs = all_svcs
            dst_cidrs = _resolve_side(dst_names, dfield, d_objs, d_groups, dv6, True)
        if side_isdb_src:
            note = ("internet-service" + ("6" if sv6 else "") + "-src: "
                    + " ".join(side_isdb_src) + " [external/internet]")
            if note not in notes:
                notes.append(note)
        if neg_src:
            note = f"negated src: {' '.join(src_names)}"
            if note not in notes:
                notes.append(note)
            src_cidrs = ["::/0" if sv6 else "any"]
        if neg_dst:
            note = f"negated dst: {' '.join(dst_names)}"
            if note not in notes:
                notes.append(note)
            dst_cidrs = ["::/0" if dv6 else "any"]
        if cross:
            stats["rules_cross_family"] += 1

        # A-02: cap src x dst x service; over-limit side -> "too-large:" token
        src_cidrs, dst_cidrs, resolved_svcs = _cap_rule(
            [(src_cidrs, " ".join(src_names), str),
             (dst_cidrs, " ".join(dst_names), str),
             (resolved_svcs, " ".join(svcs_raw), lambda t: ("any", t))],
            stats, f"policy {policy_id}")
        # Emit one row per (src_cidr x dst_cidr x service) combination.
        # Policies whose srcaddr/dstaddr resolved entirely to FQDN objects
        # (no concrete CIDRs at all) produce zero rows here — they are
        # captured in fqdn_findings and will appear as findings.
        for src in src_cidrs:
            for dst in dst_cidrs:
                pm = portfwd_by_dst.get(dst)
                for proto, port in resolved_svcs:
                    v6_rows = v6_rows or v6
                    # C-02: a port-forward VIP forwards ext_port -> mapped_port;
                    # the policy (resolved to the mapped address) must carry the
                    # mapped service port so post-NAT evaluation matches.
                    eff_port = _translate_vip_service_port(proto, port, pm) if pm else port
                    rows.append({
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "src_intf": src_intf,
                        "dst_intf": dst_intf,
                        "src_zone": src_zone,   # A-6: pre-resolved per-interface above
                        "dst_zone": dst_zone,
                        "src": src,
                        "dst": dst,
                        "protocol": proto,
                        "dst_port": eff_port,
                        "action": action,
                        "logtraffic": logtraffic,
                        "nat": nat,
                        "ips_sensor": ips_sensor,
                        "av_profile": av_profile,
                        "app_list": app_list,
                        "comments": cfg.get("comments"),
                        "schedule": cfg.get("schedule"),   # 3.11 temporary rules
                        "owner": cfg.get("comments"),  # convention: comments = owner/justification
                        "rule_order": position,
                        "notes": notes,
                        "enabled": enabled,
                        "family": sfam,
                        "dst_family": dfam,
                        "cross_family": cross,
                        "xfam": xfam,
                        "external_internet": is_external_addr_token(src) or is_external_addr_token(dst),
                        "nat_explicit": (str(cfg["nat"]).lower() if "nat" in cfg else None),
                        "srcintf_list": _as_list(src_intf_raw),
                        "dstintf_list": _as_list(dst_intf_raw),
                        "vip_names": vip_names,
                        # H-10: identity-based policy (users / user groups):
                        # it matches only those users' sessions.
                        "src_identity": ",".join(
                            str(x) for k in ("groups", "users", "fsso-groups")
                            for x in _as_list(cfg.get(k)) if str(x).strip()) or None,
                        "nat_pools": pools4 if xfam else (pools6 if v6 else pools4),
                    })
    if v6_rows:
        stats["rules_ipv6"] += 1
    if vip_names:
        notes.append("dst via VIP (mapped address): " + ", ".join(vip_names))
    return rows


def _forti_ports(value) -> str:
    """extport / mappedport ("8080", "8080-8090") -> canonical ports."""
    if value in (None, ""):
        return "any"
    ranges, invalid = _forti_portrange_tokens(value)
    if invalid:
        # B-15(c): never widen an invalid port to "any"
        return "unresolved:invalid-port:" + " ".join(str(t) for t in _as_list(value))
    return canonical_ports(ranges) or "any"


def _vip_portmap(vcfg: Optional[dict]) -> Optional[tuple]:
    """C-02: the (proto, ext_port, mapped_port) port-forward mapping of a VIP
    whose external and mapped service ports DIFFER, else None.

    A FortiOS port-forward VIP matches on its EXTERNAL destination port but
    forwards to the MAPPED port.  The security policy resolves the VIP to its
    mapped ADDRESS (post-NAT convention), so for the model to stay consistent
    the policy's SERVICE must also be expressed on the mapped (post-NAT) port
    - otherwise a flow to ext:443 is translated to mapped:8443 and the stored
    rule (which kept the external port 443) no longer matches -> false denied.
    Equal ports need no translation (returns None)."""
    if not isinstance(vcfg, dict):
        return None
    if str(vcfg.get("portforward", "disable")).lower() != "enable":
        return None
    ext = _forti_ports(vcfg.get("extport"))
    mapped = _forti_ports(vcfg.get("mappedport") or vcfg.get("extport"))
    if ext == mapped or ext == "any" or mapped == "any":
        return None
    proto = str(vcfg.get("protocol", "tcp")).lower()
    return (proto, ext, mapped)


def _translate_vip_service_port(proto: str, port: str, pm: tuple) -> str:
    """Translate one service (proto, canonical port) through a VIP port-forward
    mapping ``pm`` = (vproto, ext_port, mapped_port) (see _vip_portmap).

    Only ports that fall inside the VIP's external range are translated; a
    service on a different protocol or outside the external port range is left
    unchanged (it does not ride this port-forward).  Offset mapping is used
    when both sides are a single same-sized range; anything else maps to the
    mapped port range as a whole (over-approximation, never a false deny)."""
    vproto, ext_str, mapped_str = pm
    if vproto not in ("any", "ip") and proto not in ("any", vproto):
        return port
    ps = rm.parse_ports(port)
    es = rm.parse_ports(ext_str)
    ms = rm.parse_ports(mapped_str)
    if ps == rm.ANY or isinstance(ps, rm.Unresolved) \
            or es == rm.ANY or isinstance(es, rm.Unresolved) \
            or ms == rm.ANY or isinstance(ms, rm.Unresolved):
        return port
    # Single same-sized range on both sides: exact offset mapping.
    if len(es) == 1 and len(ms) == 1:
        (elo, ehi), (mlo, mhi) = es[0], ms[0]
        if ehi - elo == mhi - mlo:
            out = []
            ok = True
            for lo, hi in ps:
                if elo <= lo and hi <= ehi:
                    out.append((mlo + lo - elo, mlo + hi - elo))
                elif rm.ranges_intersect(((lo, hi),), es):
                    ok = False      # partially inside: fall back below
                    break
                else:
                    out.append((lo, hi))   # outside the port-forward: unchanged
            if ok:
                return rm.format_ports(rm.normalize_ranges(out))
    # Fallback: if the service overlaps the external ports at all, express it
    # on the mapped ports (whole); otherwise leave it as is.
    if rm.ports_overlap(ps, es):
        return mapped_str
    return port


def _central_nat_enabled(parsed: dict) -> bool:
    """`config system settings` / `set central-nat enable` (per VDOM)."""
    st = parsed.get("system settings", {})
    return isinstance(st, dict) and str(st.get("central-nat", "disable")).lower() == "enable"


def _intf_overlap(entry_intfs: list, pol_intfs: list) -> bool:
    """central-snat srcintf/dstintf vs a policy's interfaces ("any" matches all)."""
    a = {str(i).lower() for i in entry_intfs} or {"any"}
    b = {str(i).lower() for i in pol_intfs} or {"any"}
    return "any" in a or "any" in b or bool(a & b)


_CENTRAL_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "132": "sctp"}


def _central_snat_rows(parsed: dict, policies: list, pools4: dict, pools6: dict,
                       stats: Optional[dict] = None) -> list:
    """
    `config firewall central-snat-map` -> snat NatRule dicts (N-25).

    One row per (entry x original source address): src_intf / dst_intf,
    orig_src (orig-addr / orig-addr6 resolved through the address objects),
    orig_dst (dst-addr[6]), protocol (numeric -> name, 0 / unknown = any),
    mapped = the nat-ippool[6] range(s) or "interface:<dstintf>" when no
    pool, status -> enabled.  ASSUMPTIONS (FortiOS semantics, kept
    conservative - nothing here can turn a permit into a deny):
      * central SNAT is only in effect when the VDOM has `set central-nat
        enable` (config system settings); otherwise the rows are stored
        DISABLED (enabled=False) so they are visible but inert;
      * it is applied AFTER policy evaluation, and only to flows permitted by
        a policy whose interfaces overlap the entry's srcintf/dstintf and
        whose `nat` is not explicitly `disable` (central-nat hides the
        per-policy switch, so an absent `nat` counts as eligible; an
        explicit `nat enable` is the same).  Those policy ids are stored in
        policy_id; an entry no policy can feed is stored disabled;
      * B-13: entries are evaluated strictly in configured order, first
        match wins (FortiOS central-snat-map semantics).  Every row carries
        ``sequence`` = the entry's position.  A `nat disable` entry is an
        EXEMPTION: stored enabled (when in effect) with ``nat_exempt`` True
        and no mapped address - a flow it matches is not translated and no
        later entry is consulted.
      * B-15(b): every original source is kept (no row cap) and the
        dst-addr list is stored whole.
    """
    section = parsed.get("firewall central-snat-map", {})
    if not isinstance(section, dict) or not section:
        return []
    central_on = _central_nat_enabled(parsed)
    addr4 = _build_addr_registry(parsed)
    addr6 = _build_addr6_registry(parsed)
    out = []
    for seq, (eid, cfg) in enumerate(section.items(), start=1):
        if not isinstance(cfg, dict):
            continue
        v6 = str(cfg.get("type", "ipv4")).lower() == "ipv6" or (
            "orig-addr6" in cfg and "orig-addr" not in cfg)
        objs, groups = addr6 if v6 else addr4
        o_key, d_key, p_key = (("orig-addr6", "dst-addr6", "nat-ippool6") if v6
                               else ("orig-addr", "dst-addr", "nat-ippool"))

        def _side(names, default_any=True):
            res = []
            for n in _as_list(names) or (["all"] if default_any else []):
                for val in _resolve_address(str(n), objs, groups, stats=stats):
                    if val in ("any", "all"):
                        val = "::/0" if v6 else "any"
                    elif val.startswith(("fqdn:", "wildcard-fqdn:")):
                        val = f"unresolved:{val}"
                    if val not in res:
                        res.append(val)
            return res

        srcs = _side(cfg.get(o_key))
        dsts = _side(cfg.get(d_key))
        dst_all = (not dsts) or any(d in ("any", "::/0") for d in dsts)
        orig_dst = None if dst_all else ",".join(_nat_addr(d) for d in dsts)
        srcintf = [str(i) for i in _as_list(cfg.get("srcintf"))] or ["any"]
        dstintf = [str(i) for i in _as_list(cfg.get("dstintf"))] or ["any"]
        status_on = str(cfg.get("status", "enable")).lower() != "disable"
        nat_on = str(cfg.get("nat", "enable")).lower() != "disable"
        pool_names = [str(x) for x in _as_list(cfg.get(p_key))]
        pools = pools6 if v6 else pools4
        if not nat_on:
            mapped = None                      # exemption: no translation
        elif pool_names:
            mapped = ",".join(pools.get(pn, f"pool:{pn}") for pn in pool_names)
        else:
            mapped = f"interface:{','.join(dstintf)}"
        proto = _CENTRAL_PROTO.get(str(cfg.get("protocol", "0")).strip(), "any")
        # C-04: orig-port limits which flows this entry (translation or
        # `nat disable` exemption) matches.  Reuse the service port parser;
        # store None when unrestricted so a portless query is never narrowed.
        orig_port = _forti_ports(cfg.get("orig-port")) if cfg.get("orig-port") else "any"
        orig_port = None if orig_port == "any" else orig_port
        feeders = [p["policy_id"] for p in policies
                   if p.get("action") == "permit" and p.get("enabled", True)
                   and p.get("nat_explicit") != "disable"
                   and not p.get("xfam")
                   and (p.get("family") == 6) == v6
                   and _intf_overlap(srcintf, p.get("srcintf_list") or [])
                   and _intf_overlap(dstintf, p.get("dstintf_list") or [])]
        feeders = list(dict.fromkeys(feeders))
        enabled, why = status_on, []
        if not nat_on:
            why.append("nat disable (exemption entry: matching flows are not translated)")
        if not status_on:
            why.append("status disable")
        if enabled and not central_on:
            enabled = False
            why.append("central-nat is not enabled in this VDOM (entry inert)")
        if enabled and not feeders:
            enabled = False
            why.append("no permit policy matches srcintf/dstintf")
        for src in srcs:
            out.append(nat_row(
                "snat", nat_kind="central-snat",
                name=f"central-snat:{eid}" + (f" {cfg['name']}" if cfg.get("name") else ""),
                policy_id=",".join(feeders) or None, protocol=proto,
                src_intf=",".join(srcintf), dst_intf=",".join(dstintf),
                orig_src=_nat_addr(src) if not src.startswith("::/0") else "::/0",
                orig_dst=orig_dst or None, orig_port=orig_port,
                mapped_ip=mapped, enabled=enabled,
                sequence=seq, nat_exempt=not nat_on,
                raw=f"central-snat-map {eid}: " + ("nat disable " if not nat_on else "")
                    + (f"nat-ippool {','.join(pool_names)} " if pool_names and nat_on else "")
                    + f"orig {src} dst {orig_dst or 'any'} intf {','.join(srcintf)}->{','.join(dstintf)}"
                    + (" [" + "; ".join(why) + "]" if why else ""),
            ))
    return out


def _extract_nat(parsed: dict, policies: list, vips: Optional[dict] = None,
                 vdom: Optional[str] = None, stats: Optional[dict] = None) -> list:
    """
    FortiOS NAT -> NatRule dicts (F-05, N-25):
      * every `config firewall vip` / `vip6` / `vip46` / `vip64` entry -> dnat
        (ext = extip[:extport], mapped = mappedip[:mappedport] when
        portforward is enabled, src_intf = extintf); policy_id = comma-joined
        IDs of the policies that reference it (directly or via a VIP group).
        vip46 / vip64 rows are nat_kind "vip46" / "vip64": ext and mapped are
        of DIFFERENT address families.
      * every policy with `set nat enable` -> snat, one row per distinct
        source of the policy: mapped = the ippool range(s) when
        `set ippool enable` + poolname resolve via `config firewall ippool`
        (ippool6 for policy6), else "interface:<dstintf>".  A policy46 /
        policy64 with `ippool enable` + poolname is the cross-family
        equivalent (pool of the TRANSLATED family).
      * `config firewall central-snat-map` -> snat rows, see
        _central_snat_rows.
    Every row carries ``vdom``.
    """
    if vips is None:
        vips = _build_vip_registry(parsed)
    out = []

    # VIP -> referencing policy ids (via the resolved policy rows)
    refs: dict = {}
    for pol in policies:
        for vname in pol.get("vip_names") or []:
            for member in vips.get(vname, {}).get("members", [vname]):
                lst = refs.setdefault(member, [])
                if pol["policy_id"] not in lst:
                    lst.append(pol["policy_id"])

    for vip_seq, (name, v) in enumerate(vips.items(), start=1):
        cfg = v.get("cfg")
        if cfg is None:
            continue                 # VIP group: its members carry the rows
        portfwd = str(cfg.get("portforward", "disable")).lower() == "enable"
        proto = str(cfg.get("protocol", "tcp")).lower() if portfwd else "any"
        ext = _forti_mapped_values(cfg.get("extip")) if cfg.get("extip") else ["any"]
        ext_ip = ",".join(_nat_addr(e) for e in ext)
        mapped_ip = ",".join(_nat_addr(m) for m in v["mapped"])
        extintf = cfg.get("extintf")
        kind = v.get("kind") or "vip"
        out.append(nat_row(
            "dnat", name=name, policy_id=",".join(refs.get(name, [])) or None,
            nat_kind=kind, protocol=proto,
            src_intf=",".join(_as_list(extintf)) if extintf else None,
            ext_ip=ext_ip,
            ext_port=_forti_ports(cfg.get("extport")) if portfwd else "any",
            mapped_ip=mapped_ip,
            mapped_port=_forti_ports(cfg.get("mappedport") or cfg.get("extport")) if portfwd else "any",
            enabled=str(cfg.get("status", "enable")).lower() != "disable",
            sequence=vip_seq,
            raw=f"{kind} {name}: " + " ".join(f"{k}={v2}" for k, v2 in cfg.items()
                                             if not isinstance(v2, dict)),
        ))

    pools4, pools6 = {}, {}
    for section, dest in (("firewall ippool", pools4), ("firewall ippool6", pools6)):
        for pname, pcfg in parsed.get(section, {}).items():
            if isinstance(pcfg, dict) and pcfg.get("startip"):
                dest[pname] = _nat_range(str(pcfg["startip"]), str(pcfg.get("endip") or pcfg["startip"]))
    pools = {**pools4, **pools6}      # legacy lookup: ippool6 wins on a name clash

    def _pool_ranges(pol, names):
        if pol.get("xfam") == "46":           # IPv4 client -> IPv6 pool
            order = (pools6, pools4)
        elif pol.get("xfam") == "64":         # IPv6 client -> IPv4 pool
            order = (pools4, pools6)
        elif pol.get("family") == 6:
            order = (pools6, pools4)
        else:
            order = (pools4, pools6)
        return ",".join(next((reg[p] for reg in order if p in reg), f"pool:{p}")
                        for p in names)

    seen: dict = {}
    for pol in policies:
        if not pol.get("nat"):
            continue
        key = (pol["policy_id"], pol.get("family", 4))
        lst = seen.setdefault(key, {"pol": pol, "srcs": []})
        if pol["src"] not in lst["srcs"]:
            lst["srcs"].append(pol["src"])
    central_on = _central_nat_enabled(parsed)
    for (pid, _fam), item in seen.items():
        pol = item["pol"]
        pool_names = pol.get("nat_pools") or []
        if pool_names:
            mapped = _pool_ranges(pol, pool_names)
        else:
            mapped = f"interface:{pol.get('dst_intf')}"
        kind = f"policy{pol['xfam']}-nat" if pol.get("xfam") else "policy-nat"
        note = ""
        enabled = pol.get("enabled", True)
        if central_on and not pol.get("xfam"):
            # central-nat is on: the per-policy `nat` / ippool settings are not
            # what translates the flow (the central-snat-map is), so this row
            # is kept for visibility but inert.
            enabled = False
            note = " [central-nat enabled in this VDOM: per-policy NAT inert]"
        for src in item["srcs"]:
            out.append(nat_row(
                "snat", nat_kind=kind,
                name=(",".join(pool_names) if pool_names else pol.get("policy_name")),
                policy_id=pid, src_intf=pol.get("src_intf"), dst_intf=pol.get("dst_intf"),
                orig_src=_nat_addr(src), mapped_ip=mapped,
                enabled=enabled, sequence=pol.get("rule_order"),
                raw=f"policy {pid} nat enable" + (f" ippool {','.join(pool_names)}" if pool_names else "")
                    + (" (cross-family)" if pol.get("xfam") else "") + note,
            ))
    out.extend(_central_snat_rows(parsed, policies, pools4, pools6, stats))
    for r in out:
        r["vdom"] = vdom
    return out


def _extract_admin_trusted_hosts(parsed: dict) -> list:
    """
    Extract admin accounts and their trusted-host restrictions from
    config system admin. Returns a list of dicts suitable for
    ApprovedHost rows (role="admin_ws" for each trusted host).
    """
    admins = []
    for username, cfg in parsed.get("system admin", {}).items():
        trusted_hosts = []
        # FortiOS names them trusthost1..trusthost10
        for i in range(1, 11):
            th = cfg.get(f"trusthost{i}")
            if not th:
                continue
            # Resolve to CIDR string first, then suppress non-useful values.
            # The original check `th not in ("0.0.0.0 0.0.0.0", ...)` was
            # broken: parse_forti_block returns ["0.0.0.0","0.0.0.0"] (a list
            # of two tokens), which is never equal to the string
            # "0.0.0.0 0.0.0.0", so 0.0.0.0/0 (unrestricted admin, any IP)
            # was silently passed through as a trusted host — confirmed by test.
            if isinstance(th, list) and len(th) == 2:
                prefix = _netmask_to_prefix(th[1])
                cidr = f"{th[0]}/{prefix}"
            elif isinstance(th, str):
                cidr = th
            else:
                continue
            # Suppress the two FortiOS placeholder / "no restriction" values:
            # - "0.0.0.0/0" = any source IP, admin not restricted (no trust info)
            # - "255.255.255.255/32" = FortiOS's "this trusthost slot is unset"
            if cidr in ("0.0.0.0/0", "255.255.255.255/32"):
                continue
            trusted_hosts.append(cidr)
        admins.append({
            "username": username,
            "accprofile": cfg.get("accprofile", ""),
            "trusted_hosts": trusted_hosts,
        })
    return admins


def _extract_vpn_settings(parsed: dict) -> dict:
    """
    Extract SSL-VPN settings and the firewall policies that govern where
    VPN sessions can reach. FortiGate's SSL-VPN works in two layers:

    1. config vpn ssl settings — controls who can attempt authentication
       (source-interface, source-address, portals, timeouts, split-
       tunneling). source-address "all" = any IP can attempt VPN auth.

    2. config firewall policy where srcintf = "ssl.root" (or
       "ssl.<vdom>") — controls where authenticated VPN sessions can
       actually route. This is the key signal for 4.1: a VPN landing
       only in a DMZ/jump-host zone is correct architecture; a VPN that
       has policies allowing it to route directly into OT zones (Level
       0-2) bypasses the DMZ requirement, regardless of whether source-
       address is restricted.

    Both layers are needed to answer the full set of VPN-related checks:
      4.1 (terminates in DMZ) → needs VPN firewall policies + zone info
      4.3 (vendor access restricted) → needs source-address
      4.4 (session timeout) → needs idle-timeout
      9.1 (split tunneling disabled) → needs split-tunneling-routing-negate
    """
    ssl_settings = parsed.get("vpn ssl settings", {})
    ssl_portals = parsed.get("vpn ssl web portal", {})

    src_intf = ssl_settings.get("source-interface", [])
    if isinstance(src_intf, str):
        src_intf = [src_intf]

    portals = {}
    for portal_name, pcfg in ssl_portals.items():
        portals[portal_name] = {
            "tunnel_mode": pcfg.get("tunnel-mode", "disable"),
            "web_mode": pcfg.get("web-mode", "disable"),
            "split_tunneling": pcfg.get("split-tunneling", "enable"),
        }

    # Collect firewall policies where srcintf is the SSL-VPN tunnel
    # interface. On FortiGate the tunnel interface is always named
    # "ssl.root" (single VDOM) or "ssl.<vdom-name>" (multi-VDOM).
    vpn_policies = []
    for pid, pol in parsed.get("firewall policy", {}).items():
        if not isinstance(pol, dict) or str(pol.get("status", "enable")).lower() == "disable":
            continue  # a disabled policy controls nothing
        # AU full review D4: srcintf is a list when the policy names more than
        # one interface (str() of a list never starts with "ssl.").
        if any(n.lower().startswith("ssl.") or n.lower() == "ssl" for n in _vpn_names(pol.get("srcintf"))):
            vpn_policies.append({
                "policy_id": pid,
                "policy_name": pol.get("name"),
                "srcintf": pol.get("srcintf"),
                "dstintf": pol.get("dstintf"),
                "dstaddr": pol.get("dstaddr"),
                "action": pol.get("action", "deny"),
                "logtraffic": pol.get("logtraffic", "utm"),
            })

    return {
        "source_interfaces": src_intf,
        "source_address": ssl_settings.get("source-address", []),
        "portals": portals,
        "idle_timeout": ssl_settings.get("idle-timeout"),
        "split_tunneling_routing_negate": ssl_settings.get(
            "split-tunneling-routing-negate", "disable"),
        "vpn_firewall_policies": vpn_policies,
    }



def _vpn_names(v) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


def vpn_shared_pools(parsed: dict) -> list[dict]:
    """SSL-VPN user groups (``groups`` / ``users`` of the tunnel-sourced
    policies) whose sessions get addresses from the same tunnel pool.

    Group -> portal: the first ``config authentication-rule`` entry of
    ``vpn ssl settings`` naming the group (or one naming no group / user,
    which matches everyone), else ``default-portal``.  Portal -> pool: the
    portal's ``ip-pools``, else ``tunnel-ip-pools``, else the FortiOS factory
    pool ``SSLVPN_TUNNEL_ADDR1``.  Returns one item per pool shared by two or
    more groups: {pool, groups, portals, group_portals, policies}."""
    settings = parsed.get("vpn ssl settings", {}) or {}
    portals = parsed.get("vpn ssl web portal", {}) or {}
    rules = settings.get("authentication-rule") or {}
    rules = [r for _k, r in sorted(rules.items(), key=lambda kv: (len(str(kv[0])), str(kv[0])))
             if isinstance(r, dict)] if isinstance(rules, dict) else []
    default_portal = str(settings.get("default-portal") or "").strip() or None
    settings_pool = _vpn_names(settings.get("tunnel-ip-pools")) or ["SSLVPN_TUNNEL_ADDR1"]
    group_pols: dict = {}
    for pid, pol in (parsed.get("firewall policy", {}) or {}).items():
        if not isinstance(pol, dict) or str(pol.get("status", "enable")).lower() == "disable":
            continue
        srcintf = [t.lower() for t in _vpn_names(pol.get("srcintf"))]
        if not srcintf or not all(t == "ssl" or t.startswith("ssl.") for t in srcintf):
            continue
        for g in _vpn_names(pol.get("groups")) + _vpn_names(pol.get("users")):
            group_pols.setdefault(g, [])
            if str(pid) not in group_pols[g]:
                group_pols[g].append(str(pid))
    if len(group_pols) < 2:
        return []

    def portal_of(g):
        for r in rules:
            names = _vpn_names(r.get("groups")) + _vpn_names(r.get("users"))
            if not names or g in names:
                p = str(r.get("portal") or "").strip()
                if p:
                    return p
        return default_portal

    by_pool: dict = {}
    gp = {}
    for g in group_pols:
        p = portal_of(g)
        gp[g] = p
        pcfg = portals.get(p) if p else None
        pool = tuple(sorted(_vpn_names((pcfg or {}).get("ip-pools")) or settings_pool))
        by_pool.setdefault(pool, []).append(g)
    out = []
    for pool, groups in sorted(by_pool.items()):
        if len(groups) < 2:
            continue
        groups = sorted(groups, key=str.lower)
        out.append({"pool": list(pool), "groups": groups,
                    "portals": sorted({gp[g] or "(none)" for g in groups}),
                    "group_portals": {g: gp[g] for g in groups},
                    "policies": {g: group_pols[g] for g in groups}})
    return out


def unused_vips(parsed: dict) -> list[dict]:
    """VIPs (vip / vip6 / vip46 / vip64) that no enabled policy references
    directly or through a VIP group."""
    used = set()
    for sec in ("firewall policy", "firewall policy6", "firewall policy46", "firewall policy64"):
        for _pid, pol in (parsed.get(sec, {}) or {}).items():
            if not isinstance(pol, dict) or str(pol.get("status", "enable")).lower() == "disable":
                continue
            for k in ("dstaddr", "dstaddr6"):
                used |= set(_vpn_names(pol.get(k)))
    for sec in ("firewall vipgrp", "firewall vipgrp6", "firewall vipgrp46", "firewall vipgrp64"):
        for gname, g in (parsed.get(sec, {}) or {}).items():
            if gname in used and isinstance(g, dict):
                used |= set(_vpn_names(g.get("member")))
    out = []
    for sec in ("firewall vip", "firewall vip6", "firewall vip46", "firewall vip64"):
        for name, cfg in (parsed.get(sec, {}) or {}).items():
            if name in used or not isinstance(cfg, dict):
                continue
            ext = cfg.get("extip") or "any"
            mapped = cfg.get("mappedip") or ("realservers" if cfg.get("realservers") else "?")
            if isinstance(mapped, list):
                mapped = ",".join(str(x) for x in mapped)
            if str(cfg.get("portforward", "disable")).lower() == "enable":
                ext = f"{ext}:{cfg.get('extport', 'any')}"
                mapped = f"{mapped}:{cfg.get('mappedport', cfg.get('extport', 'any'))}"
            out.append({"name": name, "section": sec, "external": str(ext), "mapped": str(mapped),
                        "extintf": cfg.get("extintf")})
    return out

def _extract_dns_ntp(parsed: dict) -> dict:
    """
    Extract DNS and NTP server config (OT→IT dependency check).

    FortiOS has two NTP representations depending on `type`:
      - type fortiguard: uses FortiGuard cloud NTP (internet); no sub-block.
      - type custom: one or more servers in a 'config ntpserver' sub-block:
            config system ntp
                set ntpsync enable
                set type custom
                config ntpserver
                    edit 1
                        set server "10.10.1.5"
                    next
                end
            end
        The tokenizer stores this as:
            parsed["system ntp"]["ntpserver"]["1"]["server"] = "10.10.1.5"

    `ntp_custom_servers` is the list of server IP/hostname strings extracted
    from the ntpserver sub-block entries. Callers use it to check whether
    each resolved address is RFC1918 (internal) or public (violation).
    """
    dns_cfg = parsed.get("system dns", {})
    ntp_cfg = parsed.get("system ntp", {})

    # Extract custom NTP server entries from the ntpserver sub-block.
    # Each entry is keyed by edit-id ("1", "2", …); value is a dict
    # containing at minimum {"server": "<ip-or-hostname>"}.
    ntp_custom_servers: list = []
    ntpserver_block = ntp_cfg.get("ntpserver", {})
    if isinstance(ntpserver_block, dict):
        for _entry_id, entry_cfg in ntpserver_block.items():
            if isinstance(entry_cfg, dict):
                srv = entry_cfg.get("server")
                if srv:
                    # strip quotes that survive the tokenizer on some builds
                    ntp_custom_servers.append(srv.strip('"'))

    return {
        "dns_primary": dns_cfg.get("primary"),
        "dns_secondary": dns_cfg.get("secondary"),
        "ntp_server": ntp_cfg.get("server"),
        "ntp_type": ntp_cfg.get("type", "fortiguard"),
        "ntp_source_ip": ntp_cfg.get("source-ip"),
        "ntp_sync_enabled": str(ntp_cfg.get("ntpsync", "disable")).lower() == "enable",
        "ntp_custom_servers": ntp_custom_servers,
        # owner 2026-10-19: the firewall as NTP server for its own interfaces
        "ntp_server_mode": str(ntp_cfg.get("server-mode", "disable")).lower() == "enable",
        "ntp_server_interfaces": [str(x).strip('"') for x in (list(ntp_cfg.get("interface").keys())
                                                                if isinstance(ntp_cfg.get("interface"), dict)
                                                                else _as_list(ntp_cfg.get("interface")))],
    }


# ========================================================= config findings ==

# Industrial protocol TCP ports - same set used by device_classification.py's
# _SERVER_PORT_DEVICE_TYPES, kept independently here (this module doesn't
# import that one, to keep the two parsers decoupled) rather than imported,
# but intentionally identical so "industrial protocol" means the same thing
# project-wide.
_INDUSTRIAL_PROTOCOL_PORTS = {502, 102, 20000, 44818}


#: FortiOS default DNS servers (FortiGuard), used when `config system dns` sets none.
_FORTIGUARD_DNS = ("96.45.45.45", "96.45.46.46")


def _is_internal_ip(ip_str: str) -> bool:
    """
    RFC1918-aware internal-address check, via the ipaddress module rather
    than a naive string prefix. A prior version checked
    `ip.startswith("10.0.")`, which only matches the 10.0.x.x /16 slice
    of the full 10.0.0.0/8 private range and misses 172.16.0.0/12 and
    192.168.0.0/16 entirely - a DNS server at a completely ordinary
    internal address like 10.1.5.5 would have been wrongly flagged as
    "external". Verified against exactly that case before shipping.
    """
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False  # not a parseable IP - don't claim internal


def _config_findings(policies: list, zones: dict,
                     vpn_settings: dict, dns_ntp: dict,
                     device_name: str, ctx: Optional[dict] = None) -> list:
    """
    Generate Finding dicts directly from config analysis - things you can
    determine without traffic logs: logging gaps, missing DPI on OT
    conduits, any-any policies, DNS/NTP pointing off-site, etc.

    Each check below is tagged against a specific row of the uploaded
    OT Firewall Review 62443 Checklist workbook (verified directly
    against the workbook's real cell values, not assumed) - checklist_id
    and isa62443_sr are the workbook's own IDs and SR references, not
    the checklist_id values used earlier in this project's history
    (which predated having the actual workbook and, on comparison,
    didn't match it in 5 of 6 cases - see the checks below for what
    changed and why).
    """
    findings = []
    now = datetime.now(timezone.utc)

    # Deduplicate to one representative row per logical policy_id BEFORE
    # running checks. `policies` is the fully-expanded cross-product of
    # (src_addr × dst_addr × service) combinations - one FortiOS policy
    # with an addrgrp of 10 hosts and a service group of 5 ports expands
    # to 50 rows. Iterating the expanded list produces 50 IDENTICAL
    # findings for one logical policy, all with the same policy_id and
    # the same problem. The per-policy checks (logging disabled, any-any,
    # missing DPI) care only about the policy's *existence* and metadata
    # (policy_id, logtraffic, ips_sensor, action, zones) - not which
    # specific address/service expansion triggered them. Grouping by
    # policy_id and taking the first row preserves all relevant metadata
    # while ensuring exactly one finding per logical policy.
    # Confirmed bug with a test: one policy whose addrgrp expands to 2
    # rows produced 2 identical 3.12 findings before this fix.
    # AU full review D3: the representative row carries every expanded row
    # in "_rows" (checks that depend on the address / service value iterate
    # those), and a field is "any" on the representative whenever any row
    # has it - the expansion is a cross product, so that row exists.
    seen_pids: dict = {}
    unique_policies = []
    for pol in policies:
        pid = pol.get("policy_id")
        rep = seen_pids.get(pid)
        if rep is None:
            rep = dict(pol)
            rep["_rows"] = [pol]
            seen_pids[pid] = rep
            unique_policies.append(rep)
            continue
        rep["_rows"].append(pol)
        for fld in ("src", "dst", "protocol"):
            if pol.get(fld) in ("any", "::/0") and rep.get(fld) not in ("any", "::/0"):
                rep[fld] = pol[fld]
                if fld == "protocol":
                    rep["dst_port"] = pol.get("dst_port")
        if str(pol.get("dst_port") or "").lower() in ("any", "") and rep.get("protocol") == pol.get("protocol"):
            rep["dst_port"] = pol.get("dst_port")
    policies = unique_policies

    # policies" - was mislabeled "6.2" (the real 6.2 is "Admin logins and
    # configuration changes logged", a different check this config
    # parser doesn't have the data to evaluate - config log eventfilter
    # isn't extracted). This check's own logic was already correct for
    # what it claims to test; only the ID was wrong.
    for pol in policies:
        if pol.get("logtraffic") == "disable" and pol.get("action") == "permit":
            findings.append({
                "category": "config_review",
                "check_name": "config_logging_disabled",
                "severity": "high",
                "status": "open",
                "isa62443_sr": "SR 2.8",
                "checklist_id": "6.1",
                "title": f"Policy {pol['policy_id']} has logging disabled",
                "detail": {
                    "policy_id": pol["policy_id"],
                    "policy_name": pol.get("policy_name"),
                    "src": pol["src"], "dst": pol["dst"],
                    "reason": "logtraffic=disable means no evidence of traffic through this rule",
                    "checklist_title": "Traffic logging enabled on conduit policies",
                },
                "device_name": device_name,
                "created_at": now,
            })

    # --- Checklist 3.2 (SR 5.2, SR 7.7): "No any/any rules; no 'all' in
    # source, destination or service without justification" - was
    # mislabeled "3.1" (the real 3.1 is "Default deny with explicit
    # allow rules only", a policy-ordering/implicit-deny check, not an
    # any-any check) with an SR that didn't match either row. Logic
    # tightened to also require service="any" - the real check is about
    # "all" in source *or* destination *or* service, and testing all
    # three catches the literal any/any/any case precisely rather than
    # just address-broad policies that do specify a service.
    # Owner 2026-10-12 (option 1): the row's wording - "all" in source,
    # destination OR service - not only all three.  One finding per policy
    # naming which positions are "all": critical for all three, high when an
    # "all" leads into OT (a destination interface labelled L0-L2, or this
    # firewall's boundary into OT) or out to the Internet (a WAN interface or an
    # external destination), medium otherwise.
    from app.parsers.alert_engine import _external_dst_token as _ext_dst
    ctx_any = ctx or {}
    ot_ifaces = {str(x).lower() for x in (ctx_any.get("ot_interfaces") or ())}
    wan_ifaces = {str(x).lower() for x in (ctx_any.get("wan_interfaces") or ())}
    zone_members: dict = {}
    for iname, zinfo in (zones or {}).items():
        zn = (zinfo or {}).get("zone") if isinstance(zinfo, dict) else None
        if zn:
            zone_members.setdefault(str(zn).lower(), set()).add(str(iname).lower())

    def _side(tok_str):
        out = set()
        for t in str(tok_str or "").split(","):
            t = t.strip().lower()
            if t:
                out |= zone_members.get(t, {t})
        return out

    _ANY = ("any", "all", "0.0.0.0/0", "::/0", "")
    by_pol: dict = {}
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        e = by_pol.setdefault(str(pol["policy_id"]), {"pol": pol, "src": False, "dst": False, "svc": False,
                                                     "ext": set(), "dst_if": set()})
        e["src"] |= str(pol.get("src") or "").strip().lower() in _ANY
        e["dst"] |= str(pol.get("dst") or "").strip().lower() in _ANY
        e["svc"] |= (str(pol.get("protocol") or "any").lower() == "any"
                     and str(pol.get("dst_port") or "any").strip().lower() in ("any", "all", ""))
        x = _ext_dst(pol.get("dst"))
        if x:
            e["ext"].add(x)
        e["dst_if"] |= _side(pol.get("dst_zone") or pol.get("dst_intf"))
    for pid, e in by_pol.items():
        pos = [n for n, k in (("source", "src"), ("destination", "dst"), ("service", "svc")) if e[k]]
        if not pos:
            continue
        pol = e["pol"]
        into_ot = bool(e["dst_if"] & ot_ifaces) or ctx_any.get("boundary_into_ot") is True
        to_internet = bool(e["dst_if"] & wan_ifaces) or bool(e["ext"])
        if len(pos) == 3:
            sev, why = "critical", "source, destination and service are all 'all'"
        elif into_ot or to_internet:
            sev = "high"
            why = "'all' " + ("into OT" if into_ot else "") + (" and " if into_ot and to_internet else "") + \
                  ("out to the Internet" if to_internet else "")
        else:
            sev, why = "medium", "'all' between internal zones"
        findings.append({
            "category": "config_review",
            "check_name": "config_permit_any_any_any",
            "severity": sev,
            "status": "open",
            "isa62443_sr": "SR 5.2, SR 7.7",
            "checklist_id": "3.2",
            "title": (f"Policy {pid} is permit-any-any-any" if len(pos) == 3 else
                      f"Policy {pid}{' (' + str(pol.get('policy_name')) + ')' if pol.get('policy_name') else ''} "
                      f"permits all {' and '.join(p + ('s' if p == 'service' else '') for p in pos)} "
                      f"({pol.get('src_zone') or 'any'} → {pol.get('dst_zone') or 'any'})"),
            "detail": {
                "policy_id": pid,
                "policy_name": pol.get("policy_name"),
                "all_positions": pos,
                "src_zone": pol.get("src_zone"), "dst_zone": pol.get("dst_zone"),
                "external_destinations": sorted(e["ext"])[:10],
                "into_ot": into_ot, "to_internet": to_internet,
                "severity_reason": why,
                "checklist_title": "No any/any rules; no 'all' in source, destination or service without justification",
            },
            "device_name": device_name,
            "created_at": now,
        })

    # --- batch B (NET-12, owner 2026-10-15): DoS policy on the OT-facing interfaces.
    dos_ifaces = set()
    for _k, dp in (ctx_any.get("dos_policies") or {}).items():
        if isinstance(dp, dict) and str(dp.get("status", "enable")).strip('"').lower() != "disable":
            v = dp.get("interface")
            for t in (v if isinstance(v, (list, tuple)) else [v]):
                if t:
                    dos_ifaces.add(str(t).strip('"').lower())
    if ctx_any.get("dos_policies") is not None and (ot_ifaces or ctx_any.get("boundary_into_ot")):
        if ot_ifaces:
            missing_dos = sorted(ot_ifaces - dos_ifaces)
            dos_title = f"No DoS policy on OT interface(s) {', '.join(missing_dos[:6])}" if missing_dos else None
        else:
            missing_dos = []
            dos_title = "No DoS policy configured (firewall DoS-policy) on a firewall guarding OT" if not dos_ifaces else None
        if dos_title:
            findings.append({
                "category": "config_review", "check_name": "config_no_dos_policy_ot", "severity": "low",
                "status": "open", "isa62443_sr": "SR 7.1, SR 7.2", "checklist_id": "7.1",
                "title": dos_title,
                "detail": {"ref_key": "dos", "ot_interfaces_without_dos_policy": missing_dos,
                           "interfaces_with_dos_policy": sorted(dos_ifaces),
                           "reason": "a DoS policy (flood / scan thresholds) on the OT-facing interfaces keeps a "
                                     "misbehaving or compromised host from exhausting controllers and the firewall",
                           "checklist_title": "DoS protection and resource management (SR 7.1 / 7.2)"},
                "device_name": device_name, "created_at": now,
            })

    # --- batch A (FW-06, owner 2026-10-15): ICMP permitted across a zone boundary.
    # A permit policy whose rows are all ICMP between two different zones.
    icmp_pols: dict = {}
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        pid = str(pol.get("policy_id"))
        e = icmp_pols.setdefault(pid, {"pol": pol, "all_icmp": True})
        if str(pol.get("protocol") or "any").lower() not in ("icmp", "icmpv6", "icmp6"):
            e["all_icmp"] = False
    for pid, e in sorted(icmp_pols.items(), key=lambda kv: (len(kv[0]), kv[0])):
        pol = e["pol"]
        sz, dz = str(pol.get("src_zone") or ""), str(pol.get("dst_zone") or "")
        if not e["all_icmp"] or not sz or not dz or sz.lower() == dz.lower() or "any" in (sz.lower(), dz.lower()):
            continue
        findings.append({
            "category": "config_review",
            "check_name": "config_icmp_across_boundary",
            "severity": "info",
            "status": "open",
            "isa62443_sr": "SR 5.2, SR 7.7",
            "checklist_id": "3.5",
            "title": f"Policy {pid}{' (' + str(pol.get('policy_name')) + ')' if pol.get('policy_name') else ''} "
                     f"permits ICMP between {sz} and {dz}",
            "detail": {"policy_id": pid, "policy_name": pol.get("policy_name"), "src_zone": sz, "dst_zone": dz,
                       "src": pol.get("src"), "dst": pol.get("dst"),
                       "reason": "ping / ICMP across a zone boundary lets hosts map the other side; limit it to "
                                 "the monitoring hosts that need it",
                       "checklist_title": "Insecure protocols and ICMP restricted across boundaries"},
            "device_name": device_name,
            "created_at": now,
        })

    # --- Checklist 3.12 (SR 5.2, SR 3.5): "Industrial protocol DPI used
    # where available (e.g., read-only Modbus, block unauthorized
    # S7/CIP downloads)" - was mislabeled with checklist_id "3.12" but
    # an SR ("SR 6.2") that didn't belong to that row at all (it's
    # actually 6.5's or 8.8's SR). The ID happened to be right; the SR
    # was fabricated. Logic also narrowed: the real check is
    # specifically about DPI on *industrial protocol* conduits, not "any
    # cross-zone policy missing an IPS sensor" - a cross-zone HTTPS
    # policy to a historian, for instance, isn't what 3.12 is asking
    # about. Now requires the policy's resolved service to be one of the
    # industrial protocol ports.
    for pol in policies:
        src_z = pol.get("src_zone", "")
        dst_z = pol.get("dst_zone", "")
        cross_zone = src_z != dst_z and "any" not in (src_z, dst_z)
        port_str = str(pol.get("dst_port", ""))
        is_industrial = _port_hits(port_str, _INDUSTRIAL_PROTOCOL_PORTS)
        if (pol.get("action") == "permit" and cross_zone and is_industrial and
                not pol.get("ips_sensor")):
            findings.append({
                "category": "config_review",
                "check_name": "config_industrial_dpi_missing",
                "severity": "medium",
                "status": "open",
                "isa62443_sr": "SR 5.2, SR 3.5",
                "checklist_id": "3.12",
                "title": f"Industrial-protocol policy {pol['policy_id']} has no DPI/IPS sensor",
                "detail": {
                    "policy_id": pol["policy_id"],
                    "policy_name": pol.get("policy_name"),
                    "src_zone": src_z, "dst_zone": dst_z,
                    "service_port": port_str,
                    "checklist_title": "Industrial protocol DPI used where available",
                },
                "device_name": device_name,
                "created_at": now,
            })

    # ── Remote access / VPN checks (4.1, 4.3, 4.6) ─────────────────────────
    #
    # FortiGate SSL-VPN has two distinct config layers that map to different
    # workbook checks, and mixing them up produces wrong findings:
    #
    # Layer 1 — vpn ssl settings / source-address: controls who can ATTEMPT
    #   VPN authentication. Check 4.3 (vendor access restricted to approved
    #   sources). Not related to where traffic goes after authentication.
    #
    # Layer 2 — firewall policy with srcintf="ssl.root": controls where an
    #   AUTHENTICATED VPN session can actually route. Check 4.1 (all remote
    #   access terminates in DMZ, never directly in OT). This is independent
    #   of source-address — even a source-restricted VPN violates 4.1 if its
    #   firewall policies let authenticated sessions reach OT zones directly.
    #
    # Layer 3 — logtraffic on the VPN firewall policy: check 4.6 (remote
    #   sessions logged). Also applies to non-VPN remote access protocols
    #   (RDP, SSH) on regular policies.

    _SSL_VPN_INTFS = {"ssl.root", "ssl.vpn"}  # FortiGate standard names
    _RA_PORTS = {"3389", "22", "23", "443", "500", "4500"}
    _OT_ZONE_KEYWORDS = {"ot", "ics", "control", "plc", "rtu", "scada", "hmi", "field"}
    _DMZ_ZONE_KEYWORDS = {"dmz", "idmz", "jump", "transit", "perimeter", "bastion"}

    vpn_configured = bool(vpn_settings.get("source_interfaces"))
    if vpn_configured:
        # --- Checklist 4.1 (SR 1.13, 2-1 NET 3.2): "All remote access
        # terminates in the DMZ (jump host), never directly into control zones."
        # Check the VPN firewall policies (srcintf=ssl.root): does any allow
        # session routing directly to an OT zone without going through a DMZ?
        # A VPN-to-DMZ policy is correct architecture. A VPN-to-OT policy is
        # the violation.
        vpn_fw_policies = vpn_settings.get("vpn_firewall_policies", [])

        if not vpn_fw_policies:
            # SSL-VPN is configured but no firewall policy controls where it
            # can route — implicit deny or missing policy means we can't
            # confirm it terminates correctly either way. Flag for review.
            findings.append({
                "category": "config_review",
                "check_name": "config_vpn_no_routing_policy",
                "severity": "medium",
                "status": "open",
                "isa62443_sr": "SR 1.13",
                "checklist_id": "4.1",
                "title": "SSL-VPN has no firewall policy controlling where sessions can route",
                "detail": {
                    "source_interfaces": vpn_settings.get("source_interfaces"),
                    "reason": "No firewall policy with srcintf=ssl.root found. Cannot confirm "
                              "VPN sessions are constrained to terminate at a DMZ jump host.",
                    "checklist_title": "All remote access terminates in the DMZ (jump host)",
                },
                "device_name": device_name,
                "created_at": now,
            })
        else:
            for vpol in vpn_fw_policies:
                dstintf = str(vpol.get("dstintf", "")).lower()
                # Flag if the VPN policy routes directly to an OT zone.
                # F-01: whole-token match - a substring test made
                # "remote-dmz" an OT zone ("ot" in "remote") -> critical.
                is_ot_dst = name_has_keyword(dstintf, _OT_ZONE_KEYWORDS)
                # Flag if it's NOT going to a recognised DMZ/jump zone
                # and NOT clearly an OT zone either (ambiguous zone names
                # still warrant a finding — better to flag than to miss)
                is_dmz_dst = name_has_keyword(dstintf, _DMZ_ZONE_KEYWORDS)

                if is_ot_dst:
                    findings.append({
                        "category": "config_review",
                        "check_name": "config_vpn_direct_to_ot",
                        "severity": "critical",
                        "status": "open",
                        "isa62443_sr": "SR 1.13",
                        "checklist_id": "4.1",
                        "title": f"VPN policy {vpol['policy_id']} routes directly to OT zone '{vpol.get('dstintf')}'"
                                 f" (bypasses DMZ)",
                        "detail": {
                            "vpn_policy_id": vpol["policy_id"],
                            "vpn_policy_name": vpol.get("policy_name"),
                            "srcintf": vpol.get("srcintf"),
                            "dstintf": vpol.get("dstintf"),
                            "dstaddr": vpol.get("dstaddr"),
                            "reason": "Vendor/IT VPN should terminate at a DMZ jump host, not "
                                      "route directly into control-zone interfaces.",
                            "checklist_title": "All remote access terminates in the DMZ (jump host)",
                        },
                        "device_name": device_name,
                        "created_at": now,
                    })
                elif not is_dmz_dst:
                    # Zone name doesn't clearly indicate DMZ or OT — flag
                    # as needs-review rather than a definitive violation
                    findings.append({
                        "category": "config_review",
                        "check_name": "config_vpn_destination_unclear",
                        "severity": "medium",
                        "status": "open",
                        "isa62443_sr": "SR 1.13",
                        "checklist_id": "4.1",
                        "title": f"VPN policy {vpol['policy_id']} routes to "
                                 f"'{vpol.get('dstintf')}' — confirm this is a DMZ/jump-host zone",
                        "detail": {
                            "vpn_policy_id": vpol["policy_id"],
                            "vpn_policy_name": vpol.get("policy_name"),
                            "dstintf": vpol.get("dstintf"),
                            "dstaddr": vpol.get("dstaddr"),
                            "reason": "Destination zone name does not clearly indicate a DMZ or "
                                      "jump-host zone. Verify VPN sessions terminate here before "
                                      "reaching OT, not directly in a control-layer segment.",
                            "checklist_title": "All remote access terminates in the DMZ (jump host)",
                        },
                        "device_name": device_name,
                        "created_at": now,
                    })

        # --- Checklist 4.3 (SR 1.13 RE1, 2-1 NET 3.2/3.3): "Vendor access
        # disabled by default and enabled on request, time-limited."
        # source-address = "all" means any internet IP can attempt VPN auth.
        # This is the access-gating control — separate from 4.1 (destination).
        # A VPN can be source-unrestricted AND correctly terminate at a DMZ
        # jump host; 4.3 is about who can knock on the door, not where they
        # end up. Both checks can fire independently for the same config.
        src_addr = vpn_settings.get("source_address", [])
        if not src_addr or src_addr in ("all", ["all"]):
            findings.append({
                "category": "config_review",
                "check_name": "config_vpn_source_unrestricted",
                "severity": "high",
                "status": "open",
                "isa62443_sr": "SR 1.13 RE1",
                "checklist_id": "4.3",
                "title": "SSL-VPN source address not restricted — any IP can attempt VPN authentication",
                "detail": {
                    "source_interfaces": vpn_settings.get("source_interfaces"),
                    "source_address": src_addr,
                    "reason": "ssl-vpn source-address 'all' means any internet IP can initiate a "
                              "VPN auth attempt. Vendor and IT remote access should be restricted "
                              "to known source IPs or ranges, enabled only on request.",
                    "checklist_title": "Vendor access disabled by default and enabled on request, time-limited",
                    "note": "This check (who can attempt auth) is separate from 4.1 (where "
                            "authenticated sessions can route). Both can be issues independently.",
                },
                "device_name": device_name,
                "created_at": now,
            })

    # --- Checklist 4.6 (SR 2.8): "Remote sessions logged."
    # Tests all permit policies on remote-access protocols — both VPN
    # tunnel policies (srcintf=ssl.root) and conventional RA ports
    # (RDP/SSH from external hosts) — for logtraffic=disable.
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        is_vpn_policy = str(pol.get("src_zone", "")).lower().startswith("ssl")
        is_ra_port = _port_hits(pol.get("dst_port"), {int(p) for p in _RA_PORTS})
        if (is_vpn_policy or is_ra_port) and pol.get("logtraffic") == "disable":
            findings.append({
                "category": "config_review",
                "check_name": "config_remote_session_not_logged",
                "severity": "medium",
                "status": "open",
                "isa62443_sr": "SR 2.8",
                "checklist_id": "4.6",
                "title": f"Remote access policy {pol['policy_id']} has logging disabled",
                "detail": {
                    "policy_id": pol["policy_id"],
                    "policy_name": pol.get("policy_name"),
                    "dst_port": pol.get("dst_port"),
                    "src_zone": pol.get("src_zone"),
                    "dst_zone": pol.get("dst_zone"),
                    "checklist_title": "Remote sessions logged (and recorded where required)",
                },
                "device_name": device_name,
                "created_at": now,
            })

    # --- Checklist 9.11 (SR 5.1 RE2, SR 7.6): "Firewall DNS points to
    # internal resolvers, not public or FortiGuard DNS" - this one was
    # already correctly tagged 9.11; SR string tightened to the
    # workbook's fuller reference. Detection logic fixed separately -
    # see _is_internal_ip's docstring for the RFC1918 bug this replaces.
    dns_primary = dns_ntp.get("dns_primary")
    dns_secondary = dns_ntp.get("dns_secondary")
    ntp_type = dns_ntp.get("ntp_type", "")
    # Owner (2026-10-11): report EVERY external resolver, not only the primary.
    # A backup omits settings at the FortiOS default (DR-05): with neither
    # primary nor secondary set the firewall uses the FortiGuard DNS servers
    # (96.45.45.45 / 96.45.46.46), which the checklist row names explicitly.
    resolvers = []                     # [{"role", "server", "kind"}]
    if dns_primary or dns_secondary:
        for role, srv in (("primary", dns_primary), ("secondary", dns_secondary)):
            if not srv:
                continue
            if _is_internal_ip(srv):
                resolvers.append({"role": role, "server": srv, "kind": "internal"})
            else:
                resolvers.append({"role": role, "server": srv,
                                  "kind": "fortiguard" if srv in _FORTIGUARD_DNS else "external"})
    else:
        resolvers = [{"role": "primary", "server": _FORTIGUARD_DNS[0], "kind": "fortiguard", "default": True},
                     {"role": "secondary", "server": _FORTIGUARD_DNS[1], "kind": "fortiguard", "default": True}]
    external = [r for r in resolvers if r["kind"] != "internal"]
    # Owner 2026-10-12: FortiGuard DNS / NTP is the firewall's own vendor
    # service - informational on a firewall with an Internet (WAN) leg, low on
    # an internal OT firewall (no WAN leg: it routes to the Internet from inside
    # the plant, or cannot reach FortiGuard at all).  DNS also matters when
    # permit rules use FQDN objects (the resolver decides what is allowed):
    # low, medium when that firewall's boundary is into OT (Purdue <= 2).
    # A third-party public resolver stays medium.
    ctx = ctx or {}
    has_wan = ctx.get("has_wan")
    fqdn_pols = ctx.get("fqdn_permit_policies") or []
    fqdn_ot = bool(ctx.get("fqdn_into_ot")) and bool(fqdn_pols)
    _rank = {"info": 0, "low": 1, "medium": 2}
    def _fg_base():
        if has_wan:
            return "info", "FortiGuard service on a firewall with an Internet (WAN) leg - the vendor's own service"
        if has_wan is False:
            return "low", "FortiGuard service on a firewall with no Internet (WAN) leg - it must route to the Internet from inside the plant, or it cannot reach FortiGuard"
        return "low", "FortiGuard service; the firewall's Internet (WAN) leg is not known"
    if external:
        third = [r for r in external if r["kind"] == "external"]
        if third:
            dns_sev, dns_why = "medium", "third-party public resolver " + ", ".join(r["server"] for r in third)
        else:
            dns_sev, dns_why = _fg_base()
            if fqdn_pols:
                want = "medium" if fqdn_ot else "low"
                if _rank[want] > _rank[dns_sev]:
                    dns_sev = want
                dns_why += (f"; permit polic{'y' if len(fqdn_pols) == 1 else 'ies'} {', '.join(fqdn_pols[:10])} "
                            f"use{'s' if len(fqdn_pols) == 1 else ''} FQDN objects, so the resolver decides what is allowed"
                            + (" into OT" if fqdn_ot else ""))
        desc = ", ".join(f"{r['role']} {r['server']}" + (" (FortiGuard DNS, FortiOS default)" if r.get("default")
                         else " (FortiGuard DNS)" if r["kind"] == "fortiguard" else "") for r in external)
        findings.append({
            "category": "config_review",
            "check_name": "config_dns_external",
            "severity": dns_sev,
            "status": "open",
            "isa62443_sr": "SR 5.1 RE2, SR 7.6",
            "checklist_id": "9.11",
            "title": f"Firewall DNS uses external resolver{'s' if len(external) > 1 else ''}: {desc}",
            "detail": {
                "dns_primary": dns_primary,
                "dns_secondary": dns_secondary,
                "resolvers": resolvers,
                "external_resolvers": [r["server"] for r in external],
                "fortiguard_default": not (dns_primary or dns_secondary),
                "severity_reason": dns_why,
                "has_wan_leg": has_wan,
                "fqdn_permit_policies": fqdn_pols,
                "reason": ("the firewall has no DNS server configured, so it resolves through FortiGuard DNS on the Internet"
                           if not (dns_primary or dns_secondary) else
                           "OT firewall DNS pointing at a non-private-range resolver"),
                "checklist_title": "Firewall DNS points to internal resolvers, not public or FortiGuard DNS",
            },
            "device_name": device_name,
            "created_at": now,
        })

    # owner 2026-10-19: NTP from an external source - FortiGuard, or custom servers that are not
    # local (an interface network of this firewall), not routed (a static route reaches them) and
    # not private.  server-mode: the firewall serves time to its own interfaces, so the OT networks
    # inherit the dependency.
    def _ntp_place(srv: str) -> dict:
        s = str(srv).strip('"')
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return {"server": s, "kind": "external", "where": "name" if "." in s else "unknown"}
        for cidr, iname, lvl in ctx.get("local_nets") or []:
            try:
                if a in ipaddress.ip_network(cidr):
                    return {"server": s, "kind": "local", "where": f"{iname}" + (f" (L{lvl:g})" if isinstance(lvl, (int, float)) else ""),
                            "interface": iname, "purdue_level": lvl}
            except ValueError:
                continue
        _tun_ifaces = {str(x).lower() for x in (ctx.get("tunnel_interfaces") or [])}
        for cidr, dev in ctx.get("routed_nets") or []:
            try:
                if a in ipaddress.ip_network(cidr):
                    if dev and dev.lower() in _tun_ifaces:
                        return {"server": s, "kind": "remote", "where": f"remote site via {dev} (static route {cidr})", "tunnel": dev}
                    return {"server": s, "kind": "internal", "where": f"static route {cidr}" + (f" via {dev}" if dev else "")}
            except ValueError:
                continue
        for cidr, tun, kind in ctx.get("tunnel_nets") or []:      # a selector / pool with no static route (audit 2026-10-19)
            try:
                if a in ipaddress.ip_network(cidr):
                    return {"server": s, "kind": "remote", "where": f"remote site behind {kind} tunnel {tun} ({cidr})", "tunnel": tun}
            except ValueError:
                continue
        if _is_internal_ip(s):
            return {"server": s, "kind": "internal", "where": "private address, no interface or route of this firewall"}
        return {"server": s, "kind": "external", "where": "public address"}
    served = [str(i).lower() for i in (dns_ntp.get("ntp_server_interfaces") or [])] if dns_ntp.get("ntp_server_mode") else []
    served_ot = sorted(i for i in served if i in set(ctx.get("ot_interfaces") or []))
    if ntp_type == "fortiguard":
        sev, why = _fg_base()
        if served_ot:
            sev, why = ("low" if sev == "info" else "medium"), why + f"; the firewall serves time to OT interfaces {', '.join(served_ot)}"
        findings.append({
            "category": "config_review",
            "check_name": "config_ntp_fortiguard",
            "severity": sev,
            "status": "open",
            "isa62443_sr": "SR 2.11",
            "checklist_id": "6.4",
            "title": "NTP source is FortiGuard (internet)",
            "detail": {
                "ntp_type": ntp_type, "servers": [{"server": "FortiGuard", "kind": "external", "where": "FortiGuard service"}],
                "server_mode": bool(served), "served_interfaces": served, "served_ot_interfaces": served_ot,
                "reason": "OT firewall syncing NTP from FortiGuard requires internet egress",
                "severity_reason": why,
                "has_wan_leg": has_wan,
                "checklist_title": "NTP from a trusted internal source; consistent timestamps",
            },
            "device_name": device_name,
            "created_at": now,
        })
    elif ntp_type == "custom" and dns_ntp.get("ntp_sync_enabled", True) is not False:
        places = [_ntp_place(s) for s in (dns_ntp.get("ntp_custom_servers") or [])]
        ext = [p for p in places if p["kind"] == "external"]
        inside = [p for p in places if p["kind"] in ("local", "internal", "remote")]
        if ext:
            if not inside and served_ot:
                sev, why = "high", (f"every NTP source is outside the site and the firewall serves time to OT interfaces "
                                    f"{', '.join(served_ot)}: the plant's clocks depend entirely on the Internet")
            elif has_wan:
                sev, why = "medium", "external NTP source(s) on a firewall with an Internet (WAN) leg"
            else:
                sev, why = "low", "external NTP source(s) on a firewall with no Internet (WAN) leg"
            if inside and sev == "medium" and not served_ot:
                why += "; an internal source is configured as well"
            findings.append({
                "category": "config_review",
                "check_name": "config_ntp_fortiguard",
                "severity": sev,
                "status": "open",
                "isa62443_sr": "SR 2.11",
                "checklist_id": "6.4",
                "title": f"NTP from external source(s): {', '.join(p['server'] for p in ext[:4])}"
                         + (f" (also inside: {', '.join(p['server'] for p in inside[:3])})" if inside else ""),
                "detail": {
                    "ntp_type": ntp_type, "servers": places, "external_servers": [p["server"] for p in ext],
                    "local_servers": [p["server"] for p in inside],
                    "server_mode": bool(served), "served_interfaces": served, "served_ot_interfaces": served_ot,
                    "reason": "time comes from outside the site (public pools / addresses): an Internet dependency "
                              "and, for pool names, a DNS dependency with no fixed source to trust"
                              + (f"; the firewall is the NTP server for {', '.join(served)}" if served else ""),
                    "severity_reason": why,
                    "has_wan_leg": has_wan,
                    "checklist_title": "NTP from a trusted internal source; consistent timestamps",
                },
                "device_name": device_name,
                "created_at": now,
            })

    return findings


# ============================================================= hardening findings ==

# Email/web/chat ports that should not cross into OT zones (checklist 3.6)
_EMAIL_WEB_CHAT_PORTS = {
    25, 110, 143, 465, 587, 993, 995,   # email (SMTP, POP3, IMAP variants)
    80, 443, 8080, 8443,                 # HTTP/S
    1863, 5222, 5223, 5298, 19302,       # XMPP/Jabber, Google Talk
}

# Insecure management protocols on FortiGate interfaces (checklist 5.2)
_INSECURE_MGMT_ACCESS = {"telnet", "http", "snmp"}   # snmpv1/v2 is the concern
_SECURE_MGMT_ACCESS   = {"https", "ssh", "snmpv3"}   # acceptable encrypted alternatives

# Ports that commonly carry file content (checklist 3.11 — AV inspection needed).
# These are the services where a file-borne payload is realistic on conduit policies.
_FILE_TRANSFER_PORTS = {
    20, 21,          # FTP (data / control)
    22,              # SCP/SFTP
    25, 465, 587,    # SMTP (email with attachments)
    80, 443,         # HTTP/S (web downloads, update files)
    110, 143,        # POP3 / IMAP (email retrieval)
    139, 445,        # SMB (file shares)
    8080, 8443,      # alternative HTTP/S
}


def _safe_int(value, default: int = 0) -> int:
    """Convert *value* to int, returning *default* for non-numeric strings.

    FortiOS config values are stored as strings after tokenizing. Bare
    int() calls raise ValueError when a config token is unexpectedly
    non-numeric (e.g. a named object reference where a number was
    expected), which would abort the entire hardening analysis. This
    helper makes each conversion fault-tolerant.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_interfaces(tree) -> None:
    """DR-06: FortiOS omits ``set type vlan`` in backups when the interface
    carries ``set vlanid`` on a parent (``set interface``) - the type is
    implied.  Fill it in (in place, every ``system interface`` table of the
    tree, VDOM-wrapped or not) so the rest of the parser sees a VLAN."""
    if not isinstance(tree, dict):
        return
    for key, val in tree.items():
        if key == "system interface" and isinstance(val, dict):
            for cfg in val.values():
                if (isinstance(cfg, dict) and "type" not in cfg and cfg.get("vlanid") not in (None, "")
                        and cfg.get("interface")):
                    cfg["type"] = "vlan"
        elif isinstance(val, dict):
            _normalize_interfaces(val)


def _iface_for_address(interfaces: dict, ip) -> Optional[tuple]:
    """(interface name, network) of the configured interface whose subnet
    contains ``ip``, else None."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return None
    best = None
    for name, cfg in (interfaces or {}).items():
        toks = [str(t) for t in _as_list((cfg or {}).get("ip")) if str(t).strip()]
        if not toks:
            continue
        try:
            net = ipaddress.ip_interface(f"{toks[0]}/{toks[1]}" if len(toks) > 1 else toks[0]).network
        except ValueError:
            continue
        if addr in net and net.prefixlen < net.max_prefixlen and (best is None or net.prefixlen > best[1].prefixlen):
            best = (str(name), net)
    return (best[0], str(best[1])) if best else None


_FORTIOS_DEFAULT_LOCKOUT = 3          # system global admin-lockout-threshold
_FORTIOS_DEFAULT_ADMINTIMEOUT = 5     # system global admintimeout (minutes)


#: Checks a FortiGate config upload with generate_findings evaluates (report
#: PASS / NOT EVALUATED per firewall, app.check_evaluations).
FORTIGATE_CONFIG_CHECKS = frozenset({
    "config_admin_idle_timeout_long", "config_admin_lockout_threshold_high", "config_admin_no_trusted_hosts",
    "config_admin_trusthost_too_broad", "config_av_missing_on_file_policy", "config_av_profile_not_applied",
    "config_temporary_rule",
    "config_broadcast_cross_zone", "config_default_hostname", "config_dns_external", "config_email_web_to_ot",
    "config_fail_open_enabled", "config_ha_no_auth", "config_ids_ips_missing", "config_industrial_dpi_missing",
    "config_insecure_mgmt_protocol", "config_ipsec_dialup_psk", "config_ipsec_peer_unrestricted",
    "config_local_in_permits_all", "config_logging_disabled", "config_maintainer_account_enabled",
    "config_maintainer_named_account", "config_monitoring_readiness", "config_no_admin_idle_timeout",
    "config_no_admin_lockout", "config_no_av_profile", "config_no_central_auth", "config_no_internal_segmentation",
    "config_no_password_policy", "config_no_scheduled_backup", "config_no_syslog_forwarding", "config_no_timezone",
    "config_ntp_fortiguard", "config_overly_broad_subnet", "config_permit_any_any_any", "config_possible_dual_homed",
    "config_remote_session_not_logged", "config_rsp_check_disabled", "config_rules_missing_owner",
    "config_same_zone_rule", "config_service_protocol_mismatch", "config_split_tunneling_enabled",
    "config_syslog_unencrypted", "config_unused_interface_not_disabled", "config_updates_from_internet",
    # batch A (evidence matrix, owner 2026-10-15)
    "config_strong_crypto_disabled", "config_snmp_v1v2c_enabled", "config_snmp_default_community",
    "config_admin_no_two_factor", "config_admin_profile_overprivileged", "config_no_login_banner", "config_fortimanager_admin_access",
    "config_auto_firmware_upgrade", "config_link_monitor_external", "config_wireless_in_ot",
    "config_ha_no_monitor_interfaces", "config_policy_any_interface", "config_device_detection_disabled",
    "config_ntp_unauthenticated", "config_no_revision_backup", "config_vendor_rule_permanent",
    "config_icmp_across_boundary", "config_implicit_deny_not_logged",
    # batch B (owner 2026-10-15)
    "config_vpn_user_no_mfa", "config_weak_ipsec_crypto", "config_sslvpn_weak_tls",
    "config_no_dos_policy_ot", "config_wireless_weak_security",
    "config_usb_auto_install_config", "config_usb_auto_install_image", "config_vip_unused",
    "config_vpn_destination_unclear", "config_vpn_direct_to_ot", "config_vpn_idle_timeout_long",
    "config_vpn_no_idle_timeout", "config_vpn_no_routing_policy", "config_vpn_shared_access",
    "config_vpn_source_unrestricted", "config_weak_password_policy", "config_weak_tls_version",
    "config_wireless_not_isolated", "fqdn_in_policy",
})

_SYSLOG_SLOTS = ("syslogd", "syslogd2", "syslogd3", "syslogd4")
_FAZ_SLOTS = ("fortianalyzer", "fortianalyzer2", "fortianalyzer3", "fortianalyzer-cloud")


def _log_destinations(parsed: dict, interfaces: dict) -> list:
    """Every log destination of the config (owner 2026-10-12, monitoring readiness):
    syslog 1-4, FortiAnalyzer 1-3 + FortiAnalyzer Cloud, FortiGate Cloud
    (`log fortiguard setting`), local disk and memory.  One dict each:
    ``kind`` / ``slot`` / ``enabled`` / ``server`` / ``off_box`` / ``external``
    (an Internet service) / ``encrypted`` / ``reliable`` (True / False / None =
    FortiOS default, not judged) / ``forward_traffic`` (its filter; False only
    when `forward-traffic disable` is set) / ``where`` (protected interface the
    collector sits in).  A backup omits settings at their default (DR-05):
    syslog defaults to UDP without encryption; FortiAnalyzer / Cloud defaults
    are not judged."""
    def low(v, default=""):
        v = v if v is not None else default
        v = v[0] if isinstance(v, (list, tuple)) and v else v
        return str(v).strip().strip('"').lower()

    def fwd(slot):
        flt = parsed.get(f"log {slot} filter") or {}
        return low(flt.get("forward-traffic"), "enable") != "disable"

    out = []
    for slot in _SYSLOG_SLOTS:
        cfg = parsed.get(f"log {slot} setting")
        if not isinstance(cfg, dict) or not cfg:
            continue
        server = cfg.get("server")
        server = server[0] if isinstance(server, (list, tuple)) and server else server
        enabled = low(cfg.get("status"), "disable") == "enable" and bool(server)
        mode = low(cfg.get("mode"), "udp")
        reliable = mode in ("reliable", "legacy-reliable") or low(cfg.get("reliable"), "disable") == "enable"
        enc = low(cfg.get("enc-algorithm"), "disable")
        where = _iface_for_address(interfaces, server) if server else None
        out.append({"kind": "syslog", "slot": slot, "enabled": enabled, "server": server,
                    "off_box": enabled, "external": bool(server) and not _is_internal_ip(str(server)),
                    "encrypted": enc not in ("disable", "low"), "enc_algorithm": enc,
                    "reliable": reliable, "mode": mode, "format": low(cfg.get("format"), "default"),
                    "forward_traffic": fwd(slot),
                    "where": list(where) if where else None})
    for slot in _FAZ_SLOTS:
        cfg = parsed.get(f"log {slot} setting")
        if not isinstance(cfg, dict) or not cfg:
            continue
        cloud = slot == "fortianalyzer-cloud"
        server = cfg.get("server")
        server = server[0] if isinstance(server, (list, tuple)) and server else server
        enabled = low(cfg.get("status"), "disable") == "enable" and (cloud or bool(server))
        enc = low(cfg.get("enc-algorithm")) or None
        rel = low(cfg.get("reliable")) or None
        where = _iface_for_address(interfaces, server) if server else None
        out.append({"kind": "fortianalyzer-cloud" if cloud else "fortianalyzer", "slot": slot,
                    "enabled": enabled, "server": server, "off_box": enabled,
                    "external": cloud or (bool(server) and not _is_internal_ip(str(server))),
                    "encrypted": None if enc is None else enc not in ("disable", "low"), "enc_algorithm": enc,
                    "reliable": None if rel is None else rel == "enable",
                    "upload_option": low(cfg.get("upload-option")) or None,
                    "forward_traffic": fwd(slot), "where": list(where) if where else None})
    fg = parsed.get("log fortiguard setting")
    if isinstance(fg, dict) and fg:
        enabled = low(fg.get("status"), "disable") == "enable"
        enc = low(fg.get("enc-algorithm")) or None
        out.append({"kind": "fortigate-cloud", "slot": "fortiguard", "enabled": enabled, "server": "FortiGate Cloud",
                    "off_box": enabled, "external": True,
                    "encrypted": None if enc is None else enc not in ("disable", "low"), "enc_algorithm": enc,
                    "reliable": None, "upload_option": low(fg.get("upload-option")) or None,
                    "forward_traffic": fwd("fortiguard"), "where": None})
    for slot in ("disk", "memory"):
        cfg = parsed.get(f"log {slot} setting")
        if not isinstance(cfg, dict) or not cfg:
            continue
        out.append({"kind": slot, "slot": slot, "enabled": low(cfg.get("status"), "disable") == "enable",
                    "server": None, "off_box": False, "external": False, "encrypted": None, "reliable": None,
                    "diskfull": low(cfg.get("diskfull"), "overwrite") if slot == "disk" else None,
                    "forward_traffic": None, "where": None})
    return out


def _dest_label(d: dict) -> str:
    name = {"syslog": "syslog", "fortianalyzer": "FortiAnalyzer", "fortianalyzer-cloud": "FortiAnalyzer Cloud",
            "fortigate-cloud": "FortiGate Cloud", "disk": "local disk", "memory": "memory"}.get(d["kind"], d["kind"])
    slot = d["slot"]
    num = slot[-1] if slot[-1].isdigit() else ""
    return f"{name}{num and ' ' + num}" + (f" {d['server']}" if d.get("server") and d["kind"] in ("syslog", "fortianalyzer") else "")


def _config_evidence(parsed: dict, policies: list, dns_ntp: dict, admin_info: list, ctx: dict) -> list:
    """The settings the config checks examine, for the report's "Configuration
    Evidence" appendix (owner 2026-10-12): [{section, rows: [{setting, value,
    checks}]}].  Values are what the config says; a setting a backup omits is
    shown as "not set (FortiOS default)" - never a guessed default."""
    DEF = "not set (FortiOS default)"

    def v(d, key):
        x = (d or {}).get(key)
        if x is None or x == "" or x == []:
            return None
        return " ".join(str(t) for t in x) if isinstance(x, (list, tuple)) else str(x)

    def row(setting, value, *checks):
        return {"setting": setting, "value": value if value not in (None, "") else DEF, "checks": list(checks)}

    g = parsed.get("system global") or {}
    interfaces = parsed.get("system interface") or {}
    secs = []

    # --- logging & monitoring
    rows = []
    dests = _log_destinations(parsed, interfaces)
    if not dests:
        rows.append(row("Log destinations", "none configured (no syslog / FortiAnalyzer / cloud / disk section)",
                        "config_no_syslog_forwarding"))
    for d in dests:
        bits = ["enabled" if d["enabled"] else "disabled"]
        if d["off_box"]:
            bits.append("encryption: " + ({True: "yes", False: "no"}.get(d["encrypted"], "default")
                                          + (f" ({d['enc_algorithm']})" if d.get("enc_algorithm") else "")))
            bits.append("reliable delivery: " + {True: "yes", False: "no"}.get(d["reliable"], "default"))
            bits.append("traffic logs: " + ("not sent (forward-traffic disable)" if d.get("forward_traffic") is False else "sent"))
            if d.get("external"):
                bits.append("Internet destination")
        if d["kind"] == "disk" and d.get("diskfull"):
            bits.append(f"when full: {d['diskfull']}")
        rows.append(row(f"Log destination: {_dest_label(d)}", ", ".join(bits),
                        "config_no_syslog_forwarding", "config_syslog_unencrypted"))
    ls = parsed.get("log setting") or {}
    rows.append(row("Implicit-deny logging (log setting fwpolicy-implicit-log)", v(ls, "fwpolicy-implicit-log") or
                    "not set (FortiOS default: disable)", "config_implicit_deny_not_logged"))
    rows.append(row("Local-in deny logging (log setting local-in-deny-unicast)", v(ls, "local-in-deny-unicast") or
                    "not set (FortiOS default: disable)", "config_monitoring_readiness"))
    evf = parsed.get("log eventfilter") or {}
    off = [c for c in ("event", "system", "user", "vpn", "ha") if (v(evf, c) or "enable").lower() == "disable"]
    rows.append(row("Event log categories (log eventfilter)", ("switched off: " + ", ".join(off)) if off
                    else "event, system, user, vpn, ha on", "config_monitoring_readiness"))
    permits = {}
    for pol in policies:
        if pol.get("action") == "permit":
            permits.setdefault(str(pol.get("policy_id")), str(pol.get("logtraffic") or "utm").lower())
    cnt = {k: sum(1 for x in permits.values() if x == k) for k in ("all", "utm", "disable")}
    rows.append(row("Policy traffic logging (logtraffic)", f"{len(permits)} permit policies: {cnt['all']} all, "
                    f"{cnt['utm']} security events only (utm), {cnt['disable']} disabled",
                    "config_logging_disabled", "config_monitoring_readiness", "config_remote_session_not_logged"))
    secs.append({"section": "Logging and monitoring (rows 6.1-6.3, 9.10)", "rows": rows})

    # --- time and name resolution
    ntp_type = dns_ntp.get("ntp_type") or "fortiguard"
    ntp_val = ("FortiGuard (Internet)" if ntp_type == "fortiguard" else
               f"{ntp_type}: " + (", ".join(dns_ntp.get("ntp_custom_servers") or []) or "no server listed"))
    rows = [row("NTP source (system ntp)", ntp_val, "config_ntp_fortiguard")]
    p_, s_ = dns_ntp.get("dns_primary"), dns_ntp.get("dns_secondary")
    if p_ or s_:
        kind = lambda x: "internal" if _is_internal_ip(x) else ("FortiGuard" if x in _FORTIGUARD_DNS else "external")
        dns_val = ", ".join(f"{r} {x} ({kind(x)})" for r, x in (("primary", p_), ("secondary", s_)) if x)
    else:
        dns_val = "not set - FortiGuard DNS 96.45.45.45 / 96.45.46.46 (FortiOS default)"
    rows.append(row("DNS resolvers (system dns)", dns_val, "config_dns_external"))
    wan = ctx.get("wan_interfaces") or []
    rows.append(row("Internet (WAN) leg (default route / role wan)", ", ".join(wan) if wan else "none",
                    "config_ntp_fortiguard", "config_dns_external"))
    fq = ctx.get("fqdn_permit_policies") or []
    rows.append(row("Permit policies with FQDN objects", ", ".join(fq[:15]) + (f" +{len(fq) - 15}" if len(fq) > 15 else "")
                    if fq else "none", "fqdn_in_policy", "config_dns_external"))
    rows.append(row("Timezone (system global)", v(g, "timezone"), "config_no_timezone"))
    _ntps = (parsed.get("system ntp") or {}).get("ntpserver") or {}
    rows.append(row("NTP server authentication (system ntp ntpserver)",
                    ", ".join(f"{v(e, 'server')} {v(e, 'authentication') or 'disable'}" for e in _ntps.values()
                              if isinstance(e, dict) and v(e, "server")) or None,
                    "config_ntp_unauthenticated"))
    secs.append({"section": "Time and name resolution (rows 6.4, 9.11)", "rows": rows})

    # --- administrative access
    rows = []
    no_th = [a["username"] for a in admin_info if not a.get("trusted_hosts")]
    rows.append(row("Administrator accounts (system admin)", f"{len(admin_info)} account(s)"
                    + (f"; without trusted hosts: {', '.join(no_th)}" if no_th else "; all restricted to trusted hosts"),
                    "config_admin_no_trusted_hosts", "config_admin_trusthost_too_broad"))
    rows.append(row("Admin lockout threshold (admin-lockout-threshold)", v(g, "admin-lockout-threshold"),
                    "config_no_admin_lockout", "config_admin_lockout_threshold_high"))
    rows.append(row("Admin idle timeout, minutes (admintimeout)", v(g, "admintimeout") or v(g, "admin-idle-timeout"),
                    "config_no_admin_idle_timeout", "config_admin_idle_timeout_long"))
    pw = parsed.get("system password-policy") or {}
    rows.append(row("Password policy (system password-policy)",
                    (f"status {v(pw, 'status') or 'not set'}, minimum length {v(pw, 'minimum-length') or v(pw, 'min-length') or 'not set'}")
                    if pw else None, "config_no_password_policy", "config_weak_password_policy"))
    weak = []
    for name, cfg in interfaces.items():
        acc = [a.lower() for a in str(v(cfg if isinstance(cfg, dict) else {}, "allowaccess") or "").split()]
        bad = [a for a in acc if a in ("http", "telnet")]
        mgmt = [a for a in acc if a in ("https", "ssh", "http", "telnet", "snmp")]
        if mgmt:
            weak.append(f"{name}: {' '.join(mgmt)}" + (" (cleartext)" if bad else ""))
    rows.append(row("Admin services on interfaces (allowaccess)", "; ".join(weak[:12]) + (f" +{len(weak) - 12} more" if len(weak) > 12 else "")
                    if weak else "none", "config_insecure_mgmt_protocol"))
    rows.append(row("Maintainer account (admin-maintainer)", v(g, "admin-maintainer") or v(g, "maintainer-admin"),
                    "config_maintainer_account_enabled"))
    rows.append(row("Minimum TLS version for admin (ssl-min-proto-version)", v(g, "ssl-min-proto-version"),
                    "config_weak_tls_version"))
    rows.append(row("Hostname (system global)", v(g, "hostname"), "config_default_hostname"))
    rad = parsed.get("user radius") or {}
    rows.append(row("Central authentication (user radius)", f"{len(rad)} RADIUS server(s)" if rad else "none",
                    "config_no_central_auth"))
    # batch A (owner 2026-10-15)
    _adm = {u: a for u, a in (parsed.get("system admin") or {}).items() if isinstance(a, dict)}
    _2fa = sum(1 for a in _adm.values() if (v(a, "two-factor") or "disable").lower() != "disable")
    _sup = [u for u, a in _adm.items() if (v(a, "accprofile") or "").strip('"') == "super_admin"]
    rows.extend([
        row("Strong cryptography (system global strong-crypto)", v(g, "strong-crypto") or "not set (FortiOS default: enable)",
            "config_strong_crypto_disabled"),
        row("Pre-login banner (system global pre-login-banner)", v(g, "pre-login-banner") or "not set (FortiOS default: disable)",
            "config_no_login_banner"),
        row("Admins with two-factor", f"{_2fa} of {len(_adm)}", "config_admin_no_two_factor", "config_no_central_auth"),
        row("super_admin accounts", ", ".join(str(u) for u in _sup) if _sup else "none", "config_admin_profile_overprivileged"),
        row("SNMP v1/v2c communities (system snmp community)",
            f"{len(parsed.get('system snmp community') or {})} configured" if parsed.get("system snmp community") else "none",
            "config_snmp_v1v2c_enabled", "config_snmp_default_community"),
        row("Device detection (system interface device-identification)",
            ", ".join(f"{n} {v(c, 'device-identification')}" for n, c in interfaces.items()
                      if isinstance(c, dict) and v(c, "device-identification")) or None,
            "config_device_detection_disabled"),
    ])
    secs.append({"section": "Administrative access (rows 5.x)", "rows": rows})

    # --- availability, remote access, profiles, maintenance
    ha = parsed.get("system ha") or {}
    rows = [row("HA mode (system ha)", v(ha, "mode") or "standalone (not set)", "config_ha_no_auth"),
            row("HA heartbeat authentication", v(ha, "authentication"), "config_ha_no_auth"),
            row("Fail-open (system failopen)", v(parsed.get("system failopen") or {}, "status"), "config_fail_open_enabled")]
    _ha = parsed.get("system ha") or {}
    rows.append(row("HA monitored interfaces (system ha monitor)", v(_ha, "monitor"), "config_ha_no_monitor_interfaces"))
    # owner 2026-10-19: dual uplinks and their liveness probes are the other half of resilience
    _lm = parsed.get("system link-monitor") or {}
    rows.append(row("Uplink monitoring (system link-monitor)",
                    "; ".join(f"{v(c, 'srcintf')} -> {', '.join(str(x) for x in _as_list(c.get('server')))}"
                              for _n, c in _lm.items() if isinstance(c, dict) and c.get("srcintf")) or None,
                    "config_link_monitor_external"))
    _defs = []
    for _n, _rc in (parsed.get("router static") or {}).items():
        if isinstance(_rc, dict) and _rc.get("device") and _is_default_dst(_rc.get("dst")):
            _d = _rc.get("device"); _d = _d[0] if isinstance(_d, (list, tuple)) and _d else _d
            _defs.append(f"{_d} (distance {_rc.get('distance', 10)}{', dynamic gateway' if str(_rc.get('dynamic-gateway', 'disable')).lower() == 'enable' else ''})")
    rows.append(row("Default routes (router static)", "; ".join(_defs) or None))
    # owner 2026-10-19: site-to-site IPsec tunnels, their selectors and redundancy
    _tun = extract_tunnels(parsed)
    _s2s = [t for t in _tun.values() if not t["dynamic"] and not t["members"]]
    rows.append(row("Site-to-site IPsec tunnels (vpn ipsec phase1/phase2)",
                    "; ".join(f"{t['name']} via {t['wan_interface'] or '?'} -> {t['peer'] or '?'}"
                              + (f" [{', '.join(s['local'] + ' <-> ' + s['remote'] for s in t['selectors'][:3])}]" if t['selectors'] else "")
                              for t in _s2s) or None))
    _red = []
    for t in _s2s:
        if t["backup_of"]:
            _red.append(f"{t['name']} backs up {t['backup_of']} ({t['wan_interface'] or '?'} / {(_tun.get(t['backup_of'].lower()) or {}).get('wan_interface') or '?'})")
    for a in _s2s:
        for b in _s2s:
            if a["name"] < b["name"] and not a["backup_of"] and not b["backup_of"] and a["peer"] and a["peer"] == b["peer"] and a["wan_interface"] != b["wan_interface"]:
                _red.append(f"{a['name']} and {b['name']} reach {a['peer']} over {a['wan_interface']} / {b['wan_interface']}")
    for t in _tun.values():
        if t["members"]:
            _red.append(f"aggregate {t['name']} = {' + '.join(t['members'])}")
    rows.append(row("Redundant VPN tunnels", "; ".join(_red) or ("none" if _s2s else None)))
    secs.append({"section": "Availability (rows 7.x, 9.9)", "rows": rows})
    # owner 2026-10-19: who authenticates the remote-access groups (local database, LDAP, RADIUS / TACACS+, other server)
    _lu = {str(u).strip('"'): c for u, c in (parsed.get("user local") or {}).items() if isinstance(c, dict)}
    _srv = {}
    for sec_, label in (("user radius", "RADIUS"), ("user tacacs+", "TACACS+"), ("user ldap", "LDAP"), ("user saml", "SAML"), ("user fsso", "FSSO")):
        for n in (parsed.get(sec_) or {}):
            _srv[str(n).strip('"')] = label
    _idps = _saml_idps(parsed)
    for n, i in _idps.items():
        if i["mfa"]:
            _srv[n] = "SAML (FortiTrust ID, cloud MFA)"
    _grp_rows = []
    for gname, gc in (parsed.get("user group") or {}).items():
        if not isinstance(gc, dict):
            continue
        kinds = []
        for m in _as_list(gc.get("member")):
            m = str(m).strip('"')
            if m in _lu:
                kinds.append("local" + (" + token" if (_lu[m].get("two-factor") not in (None, "disable")) else ""))
            elif m in _srv:
                kinds.append(_srv[m] + (" server" if _srv[m] in ("RADIUS", "TACACS+", "LDAP", "SAML", "FSSO") else "")
                             + (" (MFA not visible)" if _srv[m] in ("LDAP", "SAML", "FSSO") else ""))
            else:
                kinds.append(f"{m} (unknown)")
        if kinds:
            _grp_rows.append(f"{str(gname).strip(chr(34))}: {', '.join(dict.fromkeys(kinds))}")
    _idp_rows = [f"{n}: {i['idp'] or 'IdP not set'}" + (" - FortiTrust ID (cloud MFA)" if i["mfa"] else " (MFA not visible)")
                 + (f", IKE on {', '.join(i['used_by'])}" if i["used_by"] else "") for n, i in _idps.items()]
    secs.append({"section": "Remote access and user groups (row 4.3)", "rows": [
        row("User groups and who authenticates them (user group)", "; ".join(_grp_rows) or None, "config_vpn_user_no_mfa"),
        row("SAML identity providers (user saml)", "; ".join(_idp_rows) or None, "config_vpn_user_no_mfa")]})
    # owner 2026-10-19: wireless - SSIDs with their security and landing VLAN, managed APs, WIDS
    _vaps = parsed.get("wireless-controller vap") or {}
    _wtp = parsed.get("wireless-controller wtp") or {}
    _wtpp = parsed.get("wireless-controller wtp-profile") or {}
    rows = [row("Wireless controller (system global wireless-controller)", v(parsed.get("system global") or {}, "wireless-controller") or "enable (default)",
                "config_wireless_in_ot"),
            row("Wireless SSIDs (wireless-controller vap)",
                "; ".join(f"{str(n).strip(chr(34))}: {v(c, 'security') or 'wpa2-only-personal'}"
                          + (f", bridged to VLAN {v(c, 'vlanid')}" if v(c, 'local-bridging') == 'enable' and v(c, 'vlanid') else
                             (", bridged" if v(c, 'local-bridging') == 'enable' else ", tunnel mode"))
                          for n, c in _vaps.items() if isinstance(c, dict)) or None,
                "config_wireless_weak_security", "config_wireless_in_ot"),
            row("Managed access points (wireless-controller wtp)", str(len([1 for c in _wtp.values() if isinstance(c, dict)])) if _wtp else None,
                "config_wireless_in_ot"),
            row("WIDS profile on AP profiles (wtp-profile wids-profile)",
                ", ".join(f"{str(n).strip(chr(34))}: {v(c, 'wids-profile')}" for n, c in _wtpp.items() if isinstance(c, dict) and v(c, 'wids-profile')) or None)]
    secs.append({"section": "Wireless (row 2.5)", "rows": rows})
    ssl = parsed.get("vpn ssl settings") or {}
    p1 = parsed.get("vpn ipsec phase1-interface") or {}
    dial = [n for n, c in p1.items() if isinstance(c, dict) and (v(c, "type") or "").lower() == "dynamic"]
    rows = [row("SSL VPN (vpn ssl settings)", ", ".join(f"{k} {v(ssl, k)}" for k in ("idle-timeout", "auth-timeout", "source-interface")
                                                         if v(ssl, k)) or (None if ssl else "not configured"),
                "config_vpn_no_idle_timeout", "config_vpn_idle_timeout_long", "config_vpn_source_unrestricted"),
            row("IPsec tunnels (vpn ipsec phase1-interface)", f"{len(p1)} tunnel(s), {len(dial)} dial-up" if p1 else "none",
                "config_ipsec_peer_unrestricted", "config_ipsec_dialup_psk")]
    secs.append({"section": "Remote access (rows 4.x)", "rows": rows})
    n_perm = len(permits)
    ips = len({str(p.get("policy_id")) for p in policies if p.get("action") == "permit" and p.get("ips_sensor")})
    av = len({str(p.get("policy_id")) for p in policies if p.get("action") == "permit" and p.get("av_profile")})
    rows = [row("Permit policies with an IPS sensor", f"{ips} of {n_perm}", "config_ids_ips_missing", "config_industrial_dpi_missing"),
            row("Permit policies with an antivirus profile", f"{av} of {n_perm}", "config_av_profile_not_applied",
                "config_av_missing_on_file_policy"),
            row("Antivirus profiles defined", str(len(parsed.get("antivirus profile") or {})), "config_no_av_profile")]
    secs.append({"section": "Security profiles (row 3.12, SR 3.2 / 3.3)", "rows": rows})
    # rule base: 'all' positions and temporary policies (rows 3.2, 3.11)
    allpos = {}
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        e = allpos.setdefault(str(pol.get("policy_id")), set())
        if str(pol.get("src") or "").lower() in ("any", "all", "0.0.0.0/0", "::/0", ""):
            e.add("source")
        if str(pol.get("dst") or "").lower() in ("any", "all", "0.0.0.0/0", "::/0", ""):
            e.add("destination")
        if str(pol.get("protocol") or "any").lower() == "any" and str(pol.get("dst_port") or "any").lower() in ("any", "all", ""):
            e.add("service")
    hits = sorted((k for k, v in allpos.items() if v), key=lambda x: (len(x), x))
    temps = sorted({str(p.get("policy_id")) for p in policies
                    if str(p.get("schedule") or "always").strip('"').lower() != "always"}, key=lambda x: (len(x), x))
    rows = [row("Permit policies with 'all' in source, destination or service",
                ("; ".join(f"{k}: {', '.join(sorted(allpos[k]))}" for k in hits[:15]) + (f" +{len(hits) - 15} more" if len(hits) > 15 else ""))
                if hits else "none", "config_permit_any_any_any"),
            row("Policies with a schedule other than 'always'", ", ".join(temps[:15]) if temps else "none",
                "config_temporary_rule")]
    secs.append({"section": "Rule base (rows 3.2, 3.11)", "rows": rows})
    cm = parsed.get("system central-management") or {}
    au = parsed.get("system autoupdate schedule") or {}
    ai = parsed.get("system auto-install") or {}
    rows = [row("Central management (system central-management type)", v(cm, "type"), "config_no_scheduled_backup",
                "config_updates_from_internet"),
            row("Update schedule (system autoupdate schedule)", v(au, "status"), "config_updates_from_internet"),
            row("Automatic firmware upgrade (system fortiguard auto-firmware-upgrade)",
                v(parsed.get("system fortiguard") or {}, "auto-firmware-upgrade"), "config_auto_firmware_upgrade"),
            row("Scheduled backup (system backup)", "configured" if parsed.get("system backup") else None,
                "config_no_scheduled_backup"),
            row("USB auto-install (system auto-install)", ", ".join(f"{k} {v(ai, k)}" for k in ("auto-install-config", "auto-install-image")
                                                                    if v(ai, k)) or None,
                "config_usb_auto_install_config", "config_usb_auto_install_image")]
    rows.append(row("Revision backup on logout (system global)", v(g, "revision-backup-on-logout") or "not set (FortiOS default: disable)",
                    "config_no_revision_backup"))
    secs.append({"section": "Maintenance and updates (rows 7.5, 9.6, 9.12)", "rows": rows})
    return secs


def _hardening_findings(
    parsed: dict,
    policies: list,          # fully-expanded list from _extract_policies
    zones: dict,             # from _extract_zones
    vpn_settings: dict,      # from _extract_vpn_settings
    dns_ntp: dict,           # from _extract_dns_ntp
    admin_info: list,        # from _extract_admin_trusted_hosts
    device_name: str,
    ctx: Optional[dict] = None,   # owner 2026-10-19: ot_interfaces / iface_levels for the wireless placement
) -> list:
    """
    Config-level findings for the 30 automatable-from-config checks that
    were not previously built. All 30 read from sections the tokenizer
    already handles (system global, system interface, system admin,
    vpn ssl settings, system ha, log syslogd setting, system password-policy,
    firewall policy) — no new tokenizer work was needed.

    Each check's SR and checklist ID was verified directly against the
    OT Firewall Review 62443 Checklist workbook before being added.
    Field names (admin-lockout-threshold, allowaccess, split-tunneling-
    routing-negate, etc.) were verified by running the tokenizer against
    an extended sample config that included each section before writing
    the check logic.
    """
    findings = []
    now = datetime.now(timezone.utc)

    def finding(check_name, severity, sr, cid, title, detail):
        findings.append({
            "category": "config_review",
            "check_name": check_name,
            "severity": severity,
            "status": "open",
            "isa62443_sr": sr,
            "checklist_id": cid,
            "title": title,
            "detail": {**detail, "device_name": device_name},
            "device_name": device_name,
            "created_at": now,
        })

    g = parsed.get("system global", {})
    interfaces = parsed.get("system interface", {})
    admins_raw = parsed.get("system admin", {})
    ha = parsed.get("system ha", {})
    log_syslog = parsed.get("log syslogd setting", {})
    pw_policy = parsed.get("system password-policy", {})
    ssl_vpn = parsed.get("vpn ssl settings", {})
    # central-management and autoupdate are used by both 7.5 and 9.12 checks
    central_mgmt = parsed.get("system central-management", {})
    autoupdate = parsed.get("system autoupdate schedule", {})
    mgmt_type_early = str(central_mgmt.get("type", "") if isinstance(central_mgmt, dict) else "").strip().strip('"').lower()

    # ------------------------------------------------------------------ 2.x Zone architecture --

    # 2.4 Internal segmentation: flag if all policies use the same srcintf=dstintf
    # (i.e. the firewall only appears to guard a single flat OT zone, not
    # multiple internal segments). A rough proxy — if every non-any interface
    # pair in accept policies is the same interface on both sides, there's no
    # inter-zone segmentation visible.
    accept_zone_pairs = set()
    for pol in policies:
        if pol.get("action") == "permit":
            sz, dz = pol.get("src_zone", ""), pol.get("dst_zone", "")
            if sz and dz and sz not in ("any", "") and dz not in ("any", ""):
                accept_zone_pairs.add((sz, dz))
    # Require at least two distinct permit policies before flagging absence of
    # segmentation — a config with exactly one same-zone policy (e.g. a
    # management-only rule) would false-positive as "no segmentation" even
    # when the device is legitimate. (P4-M5)
    _all_same_zone = (
        len(accept_zone_pairs) >= 2
        and all(a == b for a, b in accept_zone_pairs)
    )
    if _all_same_zone:
        finding("config_no_internal_segmentation",
                "medium", "SR 5.1", "2.4",
                "No inter-zone segmentation visible in policies",
                {"zone_pairs": list(accept_zone_pairs),
                 "reason": "All permit policies cross the same zone pair - "
                           "no internal OT segmentation evident in this ruleset.",
                 "checklist_title": "Internal segmentation between OT zones, not only at the perimeter"})

    # 2.5 Wireless: flag if any interface of type wifi/wlan exists without
    # being in a dedicated wireless zone (zone name should contain 'wireless',
    # 'wifi', 'wlan', or 'radio' to be considered segmented).
    wireless_ifaces = [
        (name, cfg) for name, cfg in interfaces.items()
        if str(cfg.get("type", "")).lower() in ("wifi", "wlan", "ap", "wireless", "vap-switch")
    ]
    for iface_name, cfg in wireless_ifaces:
        # FortiOS never writes "set zone" on the interface: membership comes from config system zone,
        # folded into the zones dict at ingest (audit 2026-10-19)
        zone = str((zones.get(iface_name) or {}).get("zone") or cfg.get("zone") or "").lower()
        if not any(w in zone for w in ("wireless", "wifi", "wlan", "radio")):
            finding("config_wireless_not_isolated",
                    "high", "SR 1.6", "2.5",
                    f"Wireless interface '{iface_name}' not in a dedicated wireless zone",
                    {"interface": iface_name, "current_zone": cfg.get("zone"),
                     "checklist_title": "Wireless networks are a separate zone behind the firewall"})

    # 2.6 Dual-homed hosts: flag if the same address object appears in both
    # an OT-side policy and an IT-side policy as src/dst — implies the host
    # might span two zones. Heuristic; requires human confirmation.
    # VD-06: keywords match whole name tokens (an inter-VDOM link "it-ot1"
    # is neither an IT nor an OT zone - it is the other VDOM - and "it" must
    # not match "switch" or "exit"); link interfaces are skipped, and the
    # comparison is per VDOM (a host crossing two VDOMs appears in both).
    ot_keywords = {"ot", "ics", "control", "plc", "rtu", "hmi", "scada"}
    it_keywords = {"it", "corp", "office", "enterprise", "business"}
    link_names = {str(n).lower() for n, c in interfaces.items()
                  if str(c.get("type", "")).lower() in ("vdom-link", "npu-vlink")}
    per_vdom: dict = {}
    for pol in policies:
        sz = str(pol.get("src_zone", "")).lower()
        if sz in link_names:
            continue
        toks = {t for t in re.split(r"[^a-z0-9]+", sz) if t}
        slot = per_vdom.setdefault(pol.get("vdom"), (set(), set()))
        if toks & ot_keywords:
            slot[0].add(pol.get("src", ""))
        if toks & it_keywords:
            slot[1].add(pol.get("src", ""))
    dual_homed = set()
    for ot_addrs, it_addrs in per_vdom.values():
        dual_homed |= (ot_addrs & it_addrs) - {"any", ""}
    if dual_homed:
        finding("config_possible_dual_homed",
                "high", "SR 5.1", "2.6",
                f"Possible dual-homed host(s): appear in both OT and IT zone policies",
                {"addresses": sorted(dual_homed),
                 "checklist_title": "No dual-homed hosts bypassing the firewall",
                 "note": "Heuristic - confirm manually that these are not bridge hosts"})

    # 2.7 Devices in the wrong zone: flag if a host that is named/typed as an
    # IT device (vendor keywords) appears in OT zone policies as src/dst,
    # or vice versa. Approximate; uses address object name heuristics.
    # Skipped here — this requires cross-referencing host classification data
    # from the Host table, which isn't passed to this function. Better placed
    # as a periodic review against the live Host/Zone database.

    # ------------------------------------------------------------------ 3.x Ruleset --

    import ipaddress as _ip

    # 3.3 Overly broad subnets: flag any policy whose src or dst is a /8 or /16
    # where the policy is an accept rule crossing zones.
    # Deduplicate by (policy_id, field) so expanded cross-product
    # rows don't produce one finding per expansion row for the same policy.
    _seen_broad_subnet: set = set()
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        for row in pol.get("_rows") or [pol]:          # D3: every member, not the first row
            for field in ("src", "dst"):
                val = row.get(field, "")
                if not val or val == "any":
                    continue
                dedup_key = (pol.get("policy_id"), field, val)
                if dedup_key in _seen_broad_subnet:
                    continue
                try:
                    net = _ip.ip_network(val, strict=False)
                except ValueError:
                    continue  # not an IP network (object name, fqdn, etc.) - skip
                if net.prefixlen <= 16 and net.prefixlen > 0:
                    _seen_broad_subnet.add(dedup_key)
                    finding("config_overly_broad_subnet",
                            "low", "SR 5.2", "3.3",
                            f"Policy {pol['policy_id']}: {field} is a broad /{net.prefixlen} subnet",
                            {"policy_id": pol["policy_id"], "field": field,
                             # D6: one Finding row per (policy, field, subnet)
                             "ref_key": f"{pol['policy_id']}:{field}:{val}",
                             "address": val, "prefix_length": net.prefixlen,
                             "checklist_title": "No overly broad subnets where specific hosts are known"})

    # 3.4 Rule directionality: flag any accept rule where src and dst are
    # in the same zone (same-zone rules bypass segmentation intent).
    # Dedup by policy_id: the expanded policies list has N rows per logical
    # policy; same-zone is a property of the policy, not of each expanded row.
    # Skip per-rule findings when the broader config_no_internal_segmentation
    # check already fired — all policies are same-zone, so individual findings
    # would be redundant noise for the same root cause.
    seen_same_zone_pids: set = set()
    if not _all_same_zone:
        for pol in policies:
            if pol.get("action") != "permit":
                continue
            pid = pol.get("policy_id")
            if pid in seen_same_zone_pids:
                continue
            sz, dz = pol.get("src_zone", ""), pol.get("dst_zone", "")
            if sz and dz and sz == dz and sz not in ("any", ""):
                seen_same_zone_pids.add(pid)
                finding("config_same_zone_rule",
                        "low", "SR 5.2", "3.4",
                        f"Policy {pid}: src and dst in same zone '{sz}'",
                        {"policy_id": pid, "zone": sz,
                         "checklist_title": "Rules are directional and match the documented initiator"})

    # 3.6 Email/web/chat to/from control zones: flag accept rules where
    # the dst_port is an email/web/chat port and the dst_zone is OT-adjacent.
    # Deduplicate by policy_id so expanded rows don't produce duplicates.
    _seen_email_web: set = set()
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        port_str = str(pol.get("dst_port", ""))
        if _port_hits(port_str, _EMAIL_WEB_CHAT_PORTS):
            dz = str(pol.get("dst_zone", "")).lower()
            if any(k in dz for k in ot_keywords):
                pid = pol.get("policy_id")
                if pid in _seen_email_web:
                    continue
                _seen_email_web.add(pid)
                finding("config_email_web_to_ot",
                        "medium", "SR 5.3", "3.6",
                        f"Policy {pol['policy_id']}: email/web port {port_str} allowed into OT zone",
                        {"policy_id": pol["policy_id"], "dst_port": port_str,
                         "dst_zone": pol.get("dst_zone"),
                         "checklist_title": "Email, web browsing and chat blocked into/from control zones"})

    # ------------------------------------------------------------------ 4.x Remote access --

    # 4.4 SSL-VPN session timeout: FortiGate has idle-timeout (user inactivity)
    # and auth-timeout (max session length). Flag if idle-timeout is missing or
    # > 30 minutes (1800s) or auth-timeout > 8 hours (28800s).
    ssl_idle = ssl_vpn.get("idle-timeout")
    ssl_auth = ssl_vpn.get("auth-timeout")
    if ssl_vpn.get("source-interface"):   # only if SSL-VPN is actually configured
        if not ssl_idle:
            finding("config_vpn_no_idle_timeout",
                    "medium", "SR 2.6", "4.4",
                    "SSL-VPN idle-timeout not configured (sessions never time out on inactivity)",
                    {"idle_timeout": None,
                     "checklist_title": "Remote session timeout and termination configured"})
        elif _safe_int(ssl_idle) > 1800:
            finding("config_vpn_idle_timeout_long",
                    "low", "SR 2.6", "4.4",
                    f"SSL-VPN idle-timeout is {ssl_idle}s (>{1800}s recommended)",
                    {"idle_timeout_seconds": _safe_int(ssl_idle),
                     "recommended_max": 1800,
                     "checklist_title": "Remote session timeout and termination configured"})

    # ------------------------------------------------------------------ 5.x Hardening --

    # 5.1 Management access zone restriction (config_mgmt_not_restricted_to_mgmt_zone)
    # is judged from the stored interfaces by app.parsers.mgmt_networks
    # (review_config_firewall), so operator declarations - management subnets,
    # VLANs, reclassified interface / zone names - apply without a re-upload.

    # 5.2 Insecure management protocols: flag any interface with
    # telnet, http (unencrypted), or plain snmp (v1/v2) in allowaccess.
    for iface_name, cfg in interfaces.items():
        allowaccess = cfg.get("allowaccess", "")
        if isinstance(allowaccess, list):
            allowaccess_set = {a.lower() for a in allowaccess}
        else:
            allowaccess_set = {a.lower() for a in str(allowaccess).split()}

        bad_protocols = allowaccess_set & _INSECURE_MGMT_ACCESS
        if bad_protocols:
            # owner 2026-10-12 (option 2): admin-down interface -> low, kept
            iface_off = str((cfg or {}).get("status", "up")).strip().strip('"').lower() in ("down", "disable", "disabled")
            finding("config_insecure_mgmt_protocol",
                    "low" if iface_off else "high", "SR 4.1, SR 3.1", "5.2",
                    f"Interface '{iface_name}' allows insecure management: {', '.join(sorted(bad_protocols))}"
                    + (" (interface disabled)" if iface_off else ""),
                    {"interface": iface_name, "insecure_protocols": sorted(bad_protocols),
                     "all_allowaccess": sorted(allowaccess_set),
                     "interface_disabled": iface_off,
                     **({"severity_reason": "low: the interface is administratively down - its admin access "
                                            "becomes live when it is enabled"} if iface_off else {}),
                     "checklist_title": "Encrypted management protocols only (SSH, HTTPS, SNMPv3)"})

    # 5.4 Password policy: flag if system password-policy is disabled,
    # or if min-length < 12, or required complexity is missing.
    pw_status = pw_policy.get("status", "disable")
    if pw_status != "enable":
        finding("config_no_password_policy",
                "high", "SR 1.5, SR 1.7", "5.4",
                "Password policy is not enabled",
                {"password_policy_status": pw_status,
                 "checklist_title": "Default credentials changed and password policy enforced"})
    else:
        # DR-05: FortiOS spells it "minimum-length" (default 8 when omitted);
        # "min-length" is kept for older test fixtures.
        min_len = _safe_int(pw_policy.get("minimum-length", pw_policy.get("min-length", 8)))
        if min_len < 12:
            finding("config_weak_password_policy",
                    "medium", "SR 1.5, SR 1.7", "5.4",
                    f"Password policy minimum length is {min_len} (recommended ≥ 12)",
                    {"min_length": min_len, "recommended": 12,
                     "checklist_title": "Default credentials changed and password policy enforced"})

    # 5.5 Account lockout and admin idle timeout (already partially in _config_findings;
    # this adds the admin-idle-timeout and admin-lockout checks from system global).
    # DR-05: a FortiOS backup omits settings left at their default, so an
    # absent key is the DEFAULT, not "not configured": lockout after 3 failed
    # logins for 60 s, admin idle timeout ("admintimeout") 5 minutes.
    admin_lockout_threshold = g.get("admin-lockout-threshold") or _FORTIOS_DEFAULT_LOCKOUT
    admin_idle_timeout = (g.get("admintimeout") or g.get("admin-idle-timeout")
                          or _FORTIOS_DEFAULT_ADMINTIMEOUT)

    if _safe_int(admin_lockout_threshold) <= 0:
        finding("config_no_admin_lockout",
                "high", "SR 1.11, SR 1.12", "5.5",
                "Admin account lockout not configured",
                {"admin_lockout_threshold": None,
                 "checklist_title": "Account lockout, admin timeout and login banner configured"})
    elif _safe_int(admin_lockout_threshold) > 5:
        finding("config_admin_lockout_threshold_high",
                "medium", "SR 1.11, SR 1.12", "5.5",
                f"Admin lockout threshold is {admin_lockout_threshold} attempts (recommended ≤ 5)",
                {"admin_lockout_threshold": _safe_int(admin_lockout_threshold),
                 "checklist_title": "Account lockout, admin timeout and login banner configured"})

    if _safe_int(admin_idle_timeout) <= 0:
        finding("config_no_admin_idle_timeout",
                "medium", "SR 1.11, SR 1.12", "5.5",
                "Admin idle timeout not configured",
                {"admin_idle_timeout": None,
                 "checklist_title": "Account lockout, admin timeout and login banner configured"})
    elif _safe_int(admin_idle_timeout) > 15:
        finding("config_admin_idle_timeout_long",
                "low", "SR 1.11, SR 1.12", "5.5",
                f"Admin idle timeout is {admin_idle_timeout} min (recommended ≤ 15)",
                {"admin_idle_timeout_minutes": _safe_int(admin_idle_timeout),
                 "recommended_max": 15,
                 "checklist_title": "Account lockout, admin timeout and login banner configured"})

    # 5.7 Unused/disabled interfaces: flag interfaces with no zone, no IP,
    # and no explicit disable — interfaces that appear to be unused but are
    # not administratively shut down.
    # VD-09: the parent of a VLAN sub-interface (an 802.1Q trunk) is in use
    trunk_parents = {str(c.get("interface") or "").lower() for c in interfaces.values()
                     if str(c.get("type", "")).lower() == "vlan" and c.get("interface")}
    # DR-06: an interface is in use when it is a member of an aggregate /
    # redundant / switch interface (LACP members), the parent of a tunnel,
    # named by a policy / zone / route, or addressed by DHCP / PPPoE.
    members_in_use = set()
    for c in interfaces.values():
        if str(c.get("type", "")).lower() in ("aggregate", "redundant", "hard-switch", "switch") or c.get("member"):
            members_in_use |= {str(m).lower() for m in _as_list(c.get("member"))}
        if str(c.get("type", "")).lower() == "tunnel" and c.get("interface"):
            members_in_use.add(str(c.get("interface")).lower())
    referenced = set()
    for sec in ("firewall policy", "firewall policy6"):
        for pcfg in (parsed.get(sec) or {}).values():
            if isinstance(pcfg, dict):
                for k in ("srcintf", "dstintf"):
                    referenced |= {str(n).lower() for n in _as_list(pcfg.get(k))}
    for zcfg in (parsed.get("system zone") or {}).values():
        if isinstance(zcfg, dict):
            referenced |= {str(n).lower() for n in _as_list(zcfg.get("interface"))}
    for rcfg in (parsed.get("router static") or {}).values():
        if isinstance(rcfg, dict) and rcfg.get("device"):
            referenced.add(str(rcfg.get("device")).lower())
    for pcfg in (parsed.get("vpn ipsec phase1-interface") or {}).values():
        if isinstance(pcfg, dict) and pcfg.get("interface"):
            referenced.add(str(pcfg.get("interface")).lower())
    for iface_name, cfg in interfaces.items():
        iface_type = str(cfg.get("type", "physical")).lower()
        if iface_type in ("loopback", "tunnel", "vlan", "vdom-link", "npu-vlink"):
            continue
        lname = str(iface_name).lower()
        if lname in trunk_parents or lname in members_in_use or lname in referenced:
            continue
        if str(cfg.get("mode", "static")).lower() in ("dhcp", "pppoe"):
            continue
        has_ip = bool(cfg.get("ip"))
        has_zone = bool(cfg.get("zone"))
        is_disabled = str(cfg.get("status", "up")).lower() == "down"
        allowaccess = cfg.get("allowaccess", "")
        has_access = bool(allowaccess) and allowaccess != "ping"
        if not has_ip and not has_zone and not is_disabled and not has_access:
            finding("config_unused_interface_not_disabled",
                    "low", "SR 7.7", "5.7",
                    f"Interface '{iface_name}' appears unused but is not administratively disabled",
                    {"interface": iface_name, "type": iface_type,
                     "checklist_title": "Unused interfaces and firewall services disabled"})

    # 5.8 Management-plane trusted hosts: flag admin accounts with no
    # trusted-host restriction (any IP can attempt management login).
    for admin in admin_info:
        if not admin.get("trusted_hosts"):
            finding("config_admin_no_trusted_hosts",
                    "high", "SR 5.1, SR 2.1", "5.8",
                    f"Admin account '{admin['username']}' has no trusted-host restriction",
                    {"username": admin["username"],
                     "accprofile": admin.get("accprofile"),
                     "checklist_title": "Management-plane traffic to the firewall only from authorized hosts"})

    # ------------------------------------------------------------------ 6.x Logging --

    # 6.3 Logs forwarded off the box (owner 2026-10-12, option 2): ANY enabled
    # off-box destination counts - syslog 1-4, FortiAnalyzer 1-3 / Cloud,
    # FortiGate Cloud.  Was syslog 1 only (row 6.5), which reported a firewall
    # logging to FortiAnalyzer as "no forwarding".
    log_status = log_syslog.get("status", "disable")
    log_server = log_syslog.get("server")
    dests = _log_destinations(parsed, interfaces)
    off_box = [d for d in dests if d["off_box"]]
    dest_view = [{k: d.get(k) for k in ("kind", "slot", "enabled", "server", "off_box", "external",
                                         "encrypted", "reliable", "forward_traffic", "diskfull")}
                 for d in dests]
    if not off_box:
        finding("config_no_syslog_forwarding",
                "high", "SR 6.1, SR 6.2, SR 2.9", "6.3",
                "No off-box log forwarding (syslog, FortiAnalyzer or FortiGate Cloud)",
                {"syslog_status": log_status, "syslog_server": log_server,
                 "destinations": dest_view,
                 "reason": ("logs stay on the firewall only: no syslog server, FortiAnalyzer or FortiGate "
                            "Cloud destination is enabled, so they are lost with the device and are not "
                            "available to a SIEM / monitoring"),
                 "checklist_title": "Logs forwarded to SIEM/log server with adequate retention"})

    # 3.11 Temporary rules (owner 2026-10-12): "Temporary rules have expiry
    # dates and none are expired but still active".  Temporary = the policy's
    # name or comment says so (temp / temporary / tmp / "remove after" ...).
    # Its expiry = a one-time schedule (`config firewall schedule onetime`,
    # `set end`); "always" or a recurring schedule never expires.  An enabled
    # policy whose one-time schedule already ended is reported too.
    import re as _re
    _TEMP_RE = _re.compile(r"(?:^|[^a-z])(temp|temporary|tmp|interim|remove after|remove by|until)(?:[^a-z]|$)", _re.I)
    onetime = parsed.get("firewall schedule onetime") or {}
    recurring = parsed.get("firewall schedule recurring") or {}

    def _end_of(sched):
        cfg = onetime.get(sched) if isinstance(onetime, dict) else None
        if not isinstance(cfg, dict):
            return None
        raw = cfg.get("end")
        raw = " ".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else str(raw or "")
        m = _re.search(r"(\d{1,2}):(\d{2})\s+(\d{4})/(\d{1,2})/(\d{1,2})", raw)
        if not m:
            return None
        hh, mm, yy, mo, dd = (int(x) for x in m.groups())
        try:
            return datetime(yy, mo, dd, hh, mm, tzinfo=timezone.utc)
        except ValueError:
            return None
    seen_tmp = set()
    for pol in policies:
        pid = str(pol.get("policy_id"))
        if pid in seen_tmp:
            continue
        seen_tmp.add(pid)
        sched = str(pol.get("schedule") or "always").strip().strip('"')
        text = f"{pol.get('policy_name') or ''} {pol.get('comments') or ''}"
        temp_word = _TEMP_RE.search(text)
        end = _end_of(sched)
        if end is not None and end < now:
            finding("config_temporary_rule", "medium", "2-1 SPE 2", "3.11",
                    f"Policy {pid}{' (' + str(pol.get('policy_name')) + ')' if pol.get('policy_name') else ''} "
                    f"is still enabled although its schedule '{sched}' ended {end.strftime('%Y-%m-%d')}",
                    {"policy_id": pid, "policy_name": pol.get("policy_name"), "schedule": sched,
                     "schedule_end": end.isoformat(), "problem": "expired_still_active",
                     "checklist_title": "Temporary rules have expiry dates and none are expired but still active"})
        elif temp_word and end is None:
            kind = "recurring" if sched in recurring else ("always" if sched.lower() == "always" else "no end date")
            finding("config_temporary_rule", "medium", "2-1 SPE 2", "3.11",
                    f"Temporary policy {pid}{' (' + str(pol.get('policy_name')) + ')' if pol.get('policy_name') else ''} "
                    f"has no expiry (schedule '{sched}')",
                    {"policy_id": pid, "policy_name": pol.get("policy_name"), "schedule": sched,
                     "schedule_kind": kind, "temporary_marker": temp_word.group(1), "problem": "no_expiry",
                     "comments": pol.get("comments"),
                     "checklist_title": "Temporary rules have expiry dates and none are expired but still active"})

    # 6.1 / 6.2 Monitoring readiness (owner 2026-10-12, option 2): one finding
    # per firewall listing what it does NOT record or send.  Defaults apply to
    # settings a backup omits (implicit-deny and local-in deny logging are off
    # by default in FortiOS; event filter categories are on).
    log_set = parsed.get("log setting") or {}
    evf = parsed.get("log eventfilter") or {}
    def _lv(d, k, dflt):
        v = d.get(k, dflt)
        v = v[0] if isinstance(v, (list, tuple)) and v else v
        return str(v).strip().lower()
    gaps, notes = [], []
    # implicit-deny logging is its own check since batch A (config_implicit_deny_not_logged)
    if _lv(log_set, "fwpolicy-implicit-log", "disable") != "enable":
        finding("config_implicit_deny_not_logged",
                "medium", "SR 2.8, SR 6.2", "6.1",
                "Traffic hitting the implicit deny is not logged (fwpolicy-implicit-log)",
                {"fwpolicy_implicit_log": _lv(log_set, "fwpolicy-implicit-log", "disable"),
                 "reason": "blocked attempts and scans across the boundary leave no record; the deny logs "
                           "are the evidence for SR 6.2 continuous monitoring",
                 "checklist_title": "Logging enabled on all policies incl. the implicit deny"})
    if _lv(log_set, "local-in-deny-unicast", "disable") != "enable":
        gaps.append({"gap": "local_in_deny_not_logged", "sr": "SR 2.8, SR 6.2",
                     "text": "denied traffic to the firewall itself is not logged (log setting local-in-deny-unicast) - "
                             "attempts on its management plane are invisible"})
    off_cats = [c for c in ("event", "system", "user", "vpn", "ha") if _lv(evf, c, "enable") == "disable"]
    if off_cats:
        gaps.append({"gap": "events_filtered", "sr": "SR 2.8", "categories": off_cats,
                     "text": f"event log categories switched off ({', '.join(off_cats)}) - admin logins, "
                             f"configuration changes or VPN / HA events are not recorded"})
    if off_box and all(d.get("forward_traffic") is False for d in off_box):
        gaps.append({"gap": "traffic_not_forwarded", "sr": "SR 6.2",
                     "text": "no off-box destination receives traffic logs (forward-traffic disabled in every "
                             "log filter) - only events leave the firewall"})
    utm_pols = sorted({str(pol.get("policy_id")) for pol in policies
                       if pol.get("action") == "permit" and str(pol.get("logtraffic") or "utm").lower() == "utm"},
                      key=lambda x: (len(x), x))
    if utm_pols:
        gaps.append({"gap": "security_events_only", "sr": "SR 2.8", "policies": utm_pols,
                     "text": f"{len(utm_pols)} permit polic{'y logs' if len(utm_pols) == 1 else 'ies log'} security events only "
                             f"(logtraffic utm, the FortiOS default), not every session: policy "
                             + ", ".join(utm_pols[:15]) + (f" +{len(utm_pols) - 15} more" if len(utm_pols) > 15 else "")})
    cloud = [d for d in off_box if d["kind"] in ("fortigate-cloud", "fortianalyzer-cloud")]
    if cloud:
        notes.append({"gap": "logs_to_internet_service", "sr": "SR 6.1",
                      "text": "logs are uploaded to " + " and ".join(_dest_label(d) for d in cloud)
                              + " (an Internet service): OT host and conduit details leave the site and their "
                                "retention and access sit outside the plant"})
    if gaps or notes:
        sev = "medium" if gaps else "low"
        items = gaps + notes
        finding("config_monitoring_readiness",
                sev, "SR 2.8, SR 6.1, SR 6.2", "6.1, 6.2",
                f"Monitoring readiness: {len(items)} gap{'s' if len(items) != 1 else ''} in what the firewall logs or sends"
                + (f" ({', '.join(i['gap'].replace('_', ' ') for i in items[:3])}{'…' if len(items) > 3 else ''})"),
                {"gaps": items,
                 "destinations": dest_view,
                 "off_box_destinations": [_dest_label(d) for d in off_box],
                 "severity_reason": ("medium: events or traffic the 62443 monitoring requirements expect are not recorded "
                                     "or not sent" if gaps else "low: only an Internet log destination to note"),
                 "checklist_title": "Policies, admin logins and configuration changes logged; logs available for monitoring"})

    # ------------------------------------------------------------------ 7.x Availability --

    # 7.1 Fail-close behavior: FortiGate's fail-open/fail-close is controlled
    # by 'config system failopen' → set status {enable|disable}. 'enable' =
    # fail-OPEN (traffic passes if firewall is overwhelmed), which is wrong
    # for OT. The default is disable (fail-close). Flag if fail-open is enabled.
    failopen = parsed.get("system failopen", {})
    if str(failopen.get("status", "disable")).lower() == "enable":
        finding("config_fail_open_enabled",
                "critical", "SR 5.2 RE3", "7.1",
                "Firewall fail-open is enabled (traffic bypasses firewall under load)",
                {"failopen_status": "enable",
                 "checklist_title": "Fail-close behavior confirmed and appropriate to process risk"})

    # ------------------------------------------------------------------ 8.x PCAP --

    # 8.5 Broadcast/multicast leakage: FortiGate can be configured to block
    # or forward broadcast/multicast between interfaces. Check if any policy
    # explicitly permits broadcast addresses (x.x.x.255 or 255.255.255.255)
    # to cross zone boundaries.
    # Deduplicate by policy_id so expanded rows don't produce duplicates.
    _seen_broadcast: set = set()
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        dst = pol.get("dst", "")
        if dst.endswith(".255") or dst == "255.255.255.255/32":
            sz, dz = pol.get("src_zone", ""), pol.get("dst_zone", "")
            if sz != dz and sz not in ("any", "") and dz not in ("any", ""):
                pid = pol.get("policy_id")
                if pid in _seen_broadcast:
                    continue
                _seen_broadcast.add(pid)
                finding("config_broadcast_cross_zone",
                        "medium", "SR 5.1, SR 7.7", "8.5",
                        f"Policy {pol['policy_id']}: broadcast address {dst} permitted to cross zone boundary",
                        {"policy_id": pol["policy_id"], "dst": dst,
                         "src_zone": sz, "dst_zone": dz,
                         "checklist_title": "No broadcast/multicast leakage between zones"})

    # ------------------------------------------------------------------ 9.x NIST/CIS --

    # 9.1 Split tunneling (H-09): judged per tunnel-mode SSL-VPN portal on
    # `set split-tunneling` (FortiOS default: enable).  The portal's
    # `split-tunneling-routing-negate` only inverts WHICH routes go through
    # the tunnel when split tunnelling is on - it is not the on/off switch.
    if ssl_vpn.get("source-interface"):
        portals = dict(parsed.get("vpn ssl web portal", {}) or {})
        # a referenced portal that the config does not define is the FortiOS
        # factory portal: "full-access" / "tunnel-access" run tunnel mode with
        # split tunnelling enabled
        dp = str(ssl_vpn.get("default-portal") or "").strip()
        if dp and dp not in portals and dp in ("full-access", "tunnel-access"):
            portals[dp] = {"tunnel-mode": "enable", "split-tunneling": "enable"}
        split_on = []
        for pname, pcfg in portals.items():
            if not isinstance(pcfg, dict):
                continue
            if str(pcfg.get("tunnel-mode", "disable")).lower() != "enable":
                continue
            if str(pcfg.get("split-tunneling", "enable")).lower() != "disable":
                split_on.append(pname)
        if split_on:
            finding("config_split_tunneling_enabled",
                    "medium", "SR 1.13, SR 5.1", "9.1",
                    f"SSL-VPN split tunneling is enabled on portal(s) {', '.join(split_on)} "
                    "(OT traffic may bypass VPN)",
                    {"portals": split_on, "expected": "set split-tunneling disable",
                     "checklist_title": "Split tunneling disabled on remote access used for OT"})

    # 3.8 (NAT tabletop P-07) VIPs no enabled policy uses: a published
    # address into the inside waiting for a policy - remove it.
    for item in unused_vips(parsed):
        finding("config_vip_unused", "medium", "SR 7.7, SR 5.2", "3.8",
                f"VIP {item['name']} ({item['external']} -> {item['mapped']}) is not used by any "
                "enabled policy",
                {"ref_key": "vip:" + item["name"], "vip": item["name"], "section": item["section"],
                 "severity_reason": "Medium (owner decision): an unused published address on an OT "
                                    "boundary firewall.",
                 "external": item["external"], "mapped": item["mapped"],
                 "extintf": item["extintf"],
                 "reason": "A virtual IP publishes an inside address on the firewall. Unused, it "
                           "is a leftover (the policy was removed) or a half-finished change: one "
                           "policy away from exposing the mapped host.",
                 "expected": "Delete the VIP, or document the policy that will use it",
                 "checklist_title": "No permits or published addresses without a purpose"})

    # 4.3 VPN user groups that share one tunnel address pool: the capture,
    # the logs of downstream firewalls and the OT devices see only the pool
    # address, so a session cannot be attributed to the IT or the vendor
    # group (and a policy downstream cannot tell them apart).
    if ssl_vpn.get("source-interface") or any(
            is_vpn for is_vpn in (str((p or {}).get("srcintf", "")).lower().startswith("ssl")
                                  for p in (parsed.get("firewall policy", {}) or {}).values()
                                  if isinstance(p, dict))):
        for item in vpn_shared_pools(parsed):
            finding("config_vpn_shared_access", "low", "SR 2.8, SR 1.1", "4.3",
                    f"SSL-VPN user groups {', '.join(item['groups'])} share tunnel pool "
                    f"{', '.join(item['pool'])}" + (f" and portal {item['portals'][0]}"
                                                   if len(item["portals"]) == 1 else "")
                    + ": their sessions cannot be told apart downstream",
                    {"ref_key": "pool:" + ",".join(item["pool"]),
                     "user_groups": item["groups"], "tunnel_pool": item["pool"],
                     "portals": item["portals"], "group_portals": item["group_portals"],
                     "policies": item["policies"],
                     "reason": "Every VPN user gets an address from the same pool, so traffic "
                               "seen inside the network (capture, downstream firewall logs, the "
                               "OT devices' own logs) cannot be attributed to one group - IT "
                               "staff and vendor users look identical, and no policy after the "
                               "VPN firewall can treat them differently.",
                     "expected": "A portal with its own ip-pools per user group, mapped by "
                                 "config authentication-rule (groups -> portal)",
                     "checklist_title": "Vendor / third-party remote access restricted and "
                                        "attributable"})

    # ---------------------------------------------------------------- batch A --
    # Evidence Automation Matrix (owner 2026-10-15): config-only checks the
    # matrix lists as FortiGate evidence that had no check yet.
    def _sv(d, k, dflt=""):
        x = (d or {}).get(k, dflt)
        if isinstance(x, (list, tuple)):
            x = x[0] if x else dflt
        if isinstance(x, dict):
            return str(dflt).strip().lower()
        return str(x).strip().strip('"').lower()

    def _tokens(v):
        # audit 2026-10-15: the tokenizer already splits multi-value `set`s into a list and
        # keeps quoted names whole ("SSL VPN Users") - never re-split on whitespace
        if isinstance(v, (list, tuple)):
            return [str(x).strip().strip('"') for x in v if str(x).strip().strip('"')]
        x = str(v or "").strip().strip('"')
        return [x] if x else []

    def _enabled_admins():
        return [(u, a) for u, a in admins_raw.items()
                if isinstance(a, dict) and _sv(a, "status", "enable") != "disable"]

    # SI-01 / DT-04: strong cryptography (FortiOS default enable)
    if _sv(g, "strong-crypto", "enable") == "disable":
        finding("config_strong_crypto_disabled",
                "medium", "SR 4.3, SR 4.1", "9.8",
                "Strong cryptography is disabled (system global strong-crypto)",
                {"strong_crypto": "disable",
                 "reason": "with strong-crypto off the GUI, SSH, SSL-VPN and IPsec accept weak ciphers, "
                           "short keys and old TLS / SSH versions",
                 "checklist_title": "Static-key TLS ciphers disabled"})

    # SI-01: SNMP v1 / v2c communities (cleartext community strings; SNMPv3 only)
    snmp_comms = parsed.get("system snmp community") or {}
    _snmp_agent_on = _sv(parsed.get("system snmp sysinfo") or {}, "status", "enable") != "disable"
    live_comms = [(n, c) for n, c in snmp_comms.items()
                  if _snmp_agent_on and isinstance(c, dict) and _sv(c, "status", "enable") != "disable"]
    if live_comms:
        default_names = [n for n, c in live_comms if _sv(c, "name") in ("public", "private")]
        finding("config_snmp_v1v2c_enabled",
                "medium", "SR 4.1, SR 1.5", "5.2",
                f"SNMP v1/v2c enabled: {len(live_comms)} community string(s) configured",
                {"communities": len(live_comms), "entries": [str(n) for n, _c in live_comms][:20],
                 "default_names": len(default_names),
                 "reason": "SNMP v1 / v2c send the community string in cleartext and allow no user "
                           "authentication; use SNMPv3 (authPriv) or disable SNMP",
                 "checklist_title": "Insecure management protocols disabled (HTTP, Telnet, SNMPv1/2c)"})
        if default_names:
            finding("config_snmp_default_community",
                    "high", "SR 1.5, SR 4.1", "5.4",
                    f"Default SNMP community string in use ({len(default_names)} entr{'y' if len(default_names) == 1 else 'ies'})",
                    {"entries": [str(n) for n in default_names][:20],
                     "reason": "'public' / 'private' are the first strings any scanner tries",
                     "checklist_title": "Default credentials changed"})

    # FW-10 / RA-04: admins without MFA while an MFA / central-auth means exists
    _radius = parsed.get("user radius") or {}
    _tacacs = parsed.get("user tacacs+") or {}
    _fortitokens = parsed.get("user fortitoken") or {}
    _remote_admin = any(_sv(a, "remote-auth", "disable") == "enable" for _u, a in _enabled_admins())
    _mfa_present = bool(_fortitokens) or ((bool(_radius) or bool(_tacacs)) and _remote_admin) or any(
        _sv(a, "two-factor", "disable") != "disable" for _u, a in _enabled_admins())
    # owner 2026-10-18: every enabled local administrator without two-factor is a finding (the
    # built-in user database is covered whether or not the firewall has tokens); super_admin -> high.
    # Audit 2026-10-18: a remote-auth admin whose remote group authenticates against LDAP (or
    # password-only local users) is a password too; RADIUS / TACACS+ groups count as covered.
    _a_local = {str(u).strip('"'): c for u, c in (parsed.get("user local") or {}).items() if isinstance(c, dict)}
    _a_groups = {str(n).strip('"'): c for n, c in (parsed.get("user group") or {}).items() if isinstance(c, dict)}
    _a_ldap = {str(n).strip('"') for n in (parsed.get("user ldap") or {})}
    _a_mfa_srv = {str(n).strip('"') for sec in ("user radius", "user tacacs+") for n in (parsed.get(sec) or {})}

    def _remote_admin_source(acfg):
        """(covered, source) for a remote-auth admin from the members of its remote group."""
        gname = str(acfg.get("remote-group", "") or "").strip('"')
        members = _tokens((_a_groups.get(gname) or {}).get("member"))
        if not members:
            return True, f"remote ({gname or 'no group'})"           # unknown group: not judged
        weak, strong = [], []
        for m in members:
            if m in _a_mfa_srv:
                strong.append(m)
            elif m in _a_ldap:
                weak.append(f"ldap server {m}")
            elif m in _a_local:
                c = _a_local[m]
                if _sv(c, "two-factor", "disable") != "disable" or _sv(c, "type", "password") in ("radius", "tacacs+"):
                    strong.append(m)
                else:
                    weak.append(f"{_sv(c, 'type', 'password')} user {m}")
            else:
                strong.append(m)                                       # unknown member: not judged
        if weak and not strong:
            return False, f"remote group {gname}: " + ", ".join(weak[:6])
        return True, f"remote group {gname}"
    for uname, acfg in _enabled_admins():
        if _sv(acfg, "two-factor", "disable") != "disable":
            continue
        remote = _sv(acfg, "remote-auth", "disable") == "enable"
        src = "local (built-in user database)"
        if remote:
            covered, src = _remote_admin_source(acfg)
            if covered:
                continue
        prof = _sv(acfg, "accprofile")
        finding("config_admin_no_two_factor",
                "high" if prof == "super_admin" else "medium", "SR 1.7, SR 1.1 RE1", "9.4",
                f"Admin '{uname}' has no two-factor authentication",
                {"ref_key": f"admin-2fa:{uname}", "username": str(uname), "accprofile": prof,
                 "auth_source": src, "mfa_kind": "none",
                     "mfa_available": "fortitoken" if _fortitokens else ("radius / tacacs" if (_radius or _tacacs) else
                                                                          ("other admins use two-factor" if _mfa_present else "none configured")),
                 "reason": ("this administrator authenticates against an LDAP / password-only group: one factor"
                            if remote else
                            "the firewall offers MFA (tokens / central authentication) but this local account "
                            "logs in with a password only" if _mfa_present else
                            "a local account of the built-in user database logs in with a password only")
                           + (" - super_admin profile" if prof == "super_admin" else ""),
                 "checklist_title": "Admin authentication centralized (RADIUS/TACACS+) with MFA"})

    # UC-02: more super_admin accounts than needed
    supers = [str(u) for u, a in _enabled_admins() if _sv(a, "accprofile") == "super_admin"]
    if len(supers) > 2:
        finding("config_admin_profile_overprivileged",
                "medium", "SR 2.1, SR 1.3", "9.4",
                f"{len(supers)} admin accounts hold the super_admin profile",
                {"super_admins": supers[:20], "count": len(supers),
                 "reason": "least privilege: operators, auditors and helpdesk need read-only or scoped "
                           "profiles (config system accprofile); keep super_admin for one named owner "
                           "and one break-glass account",
                 "checklist_title": "Admin roles separated (least privilege)"})

    # IAC-11: login banner (system use notification, SR 1.12)
    if _sv(g, "pre-login-banner", "disable") != "enable":
        finding("config_no_login_banner",
                "low", "SR 1.12", "5.5",
                "No pre-login banner configured (system global pre-login-banner)",
                {"pre_login_banner": _sv(g, "pre-login-banner", "disable"),
                 "post_login_banner": _sv(g, "post-login-banner", "disable"),
                 "reason": "a system-use notification before authentication is a 62443-3-3 SR 1.12 "
                           "requirement and a CIS FortiGate recommendation",
                 "checklist_title": "Login banner displayed before authentication"})

    # FW-15: HA without monitored interfaces never fails over on a link loss
    _ha_mode = _sv(ha, "mode", "standalone")
    if _ha_mode not in ("standalone", ""):
        mon_list = _tokens(ha.get("monitor")) + _tokens(ha.get("pingserver-monitor-interface"))
        if not mon_list:
            finding("config_ha_no_monitor_interfaces",
                    "low", "SR 7.1, SR 7.2", "7.4",
                    f"HA ({_ha_mode}) has no monitored interfaces (system ha monitor)",
                    {"ha_mode": _ha_mode, "monitor": [],
                     "reason": "without interface monitoring the cluster only fails over when a unit dies, "
                               "not when its OT-facing link does",
                     "checklist_title": "HA / redundancy configured and tested"})

    # ZC-04: a permit policy on srcintf / dstintf 'any' cannot be placed on one conduit
    seen_any_if: set = set()
    for pol in policies:
        if pol.get("action") != "permit":
            continue
        pid = str(pol.get("policy_id"))
        if pid in seen_any_if:
            continue
        sides = [k for k in ("src_intf", "dst_intf") if str(pol.get(k) or "").strip().strip('"').lower() == "any"]
        if sides:
            seen_any_if.add(pid)
            finding("config_policy_any_interface",
                    "medium", "SR 5.2, SR 5.1", "3.1",
                    f"Policy {pid}{' (' + str(pol.get('policy_name')) + ')' if pol.get('policy_name') else ''} "
                    f"uses interface 'any' on the {' and '.join(x.replace('_intf', '') for x in sides)} side",
                    {"policy_id": pid, "policy_name": pol.get("policy_name"), "any_sides": sides,
                     "src_zone": pol.get("src_zone"), "dst_zone": pol.get("dst_zone"),
                     "reason": "the policy applies between every pair of interfaces, so it belongs to no "
                               "single conduit and its direction cannot be judged",
                     "checklist_title": "Every rule bound to a specific zone pair"})

    # LG-08 / AST-01: device detection on routed, non-WAN interfaces feeds the inventory
    no_det = []
    for iface_name, cfg in interfaces.items():
        if not isinstance(cfg, dict):
            continue
        if str(cfg.get("type", "physical")).lower() not in ("physical", "vlan", "aggregate", "redundant", "hard-switch", "switch"):
            continue
        if not cfg.get("ip") or _sv(cfg, "status", "up") == "down":
            continue
        if _sv(cfg, "role") == "wan" or _sv(cfg, "dedicated-to") == "management":
            continue
        if _sv(cfg, "device-identification", "disable") != "enable":
            no_det.append(str(iface_name))
    if no_det:
        finding("config_device_detection_disabled",
                "info", "SR 7.8", "7.7",
                f"Device detection is off on {len(no_det)} routed interface(s)",
                {"interfaces": sorted(no_det)[:30], "count": len(no_det),
                 "reason": "device-identification gives the FortiGate's own view of the hosts behind each "
                           "interface (vendor, OS) - cheap evidence for the asset inventory",
                 "checklist_title": "Asset inventory complete and current"})

    # NET-11: NTP from custom servers without authentication
    ntp_cfg = parsed.get("system ntp") or {}
    _ntp_servers = ntp_cfg.get("ntpserver") if isinstance(ntp_cfg.get("ntpserver"), dict) else {}
    # audit 2026-10-15: FortiOS defaults ntpsync to enable; custom servers count whenever configured
    if _ntp_servers and _sv(ntp_cfg, "type", "fortiguard") == "custom" and _sv(ntp_cfg, "ntpsync", "enable") != "disable":
        unauth = []
        for _k, e in _ntp_servers.items():
            if isinstance(e, dict) and e.get("server") and _sv(e, "authentication", "disable") != "enable":
                unauth.append(_sv(e, "server"))
        if unauth:
            finding("config_ntp_unauthenticated",
                    "low", "SR 2.11, SR 3.1", "6.4",
                    f"NTP server(s) without authentication: {', '.join(unauth[:5])}",
                    {"servers": unauth[:20],
                     "reason": "unauthenticated NTP lets a spoofed source shift the clock - log timestamps "
                               "and certificate validity depend on it; enable NTP authentication (key) "
                               "or sync from a trusted internal source",
                     "checklist_title": "Time synchronised from a trusted source"})

    # AST-03 / FW-12: configuration revisions kept on logout (or FortiManager)
    if _sv(g, "revision-backup-on-logout", "disable") != "enable" and mgmt_type_early != "fortimanager":
        finding("config_no_revision_backup",
                "low", "SR 7.3, SR 7.6", "7.5",
                "Configuration revisions are not saved on logout (revision-backup-on-logout) and no FortiManager",
                {"revision_backup_on_logout": _sv(g, "revision-backup-on-logout", "disable"),
                 "revision_image_auto_backup": _sv(g, "revision-image-auto-backup", "disable"),
                 "central_management_type": mgmt_type_early or "not set",
                 "reason": "without revisions a configuration change cannot be diffed against the approved "
                           "baseline or rolled back",
                 "checklist_title": "Configuration backup and revision history"})

    # FW-04 / FW-17: remote-access (vendor) policies that are permanent
    _sched_by_pid = {}
    for pol in policies:
        _sched_by_pid.setdefault(str(pol.get("policy_id")), (str(pol.get("schedule") or "always").strip().strip('"'),
                                                             pol.get("policy_name")))
    for vp in (vpn_settings or {}).get("vpn_firewall_policies") or []:
        pid = str(vp.get("policy_id"))
        if vp.get("vdom") is not None:
            pid = f"{vp['vdom']}/{pid}"                   # multi-VDOM: the policies carry "<vdom>/<id>"
        sched, pname = _sched_by_pid.get(pid, ("always", None))
        if sched.lower() == "always":
            finding("config_vendor_rule_permanent",
                    "low", "SR 1.13, 2-1 NET 3.2", "3.11",
                    f"Remote-access policy {pid}{' (' + str(pname) + ')' if pname else ''} is permanent (schedule always)",
                    {"policy_id": pid, "policy_name": pname, "schedule": sched,
                     "reason": "vendor / remote-access policies should be time-boxed (one-time or recurring "
                               "schedule) so access ends with the work order",
                     "checklist_title": "Vendor access time-limited"})

    # ---------------------------------------------------------------- batch B --

    # RA-04: remote-access user groups whose local users have no two-factor
    local_users = {str(u).strip('"'): c for u, c in (parsed.get("user local") or {}).items() if isinstance(c, dict)}
    groups_cfg = {str(gname).strip('"'): c for gname, c in (parsed.get("user group") or {}).items() if isinstance(c, dict)}
    ra_groups, ra_users = set(), set()
    _ssl_on = isinstance(ssl_vpn, dict) and bool(ssl_vpn) and _sv(ssl_vpn, "status", "enable") != "disable"
    _auth_rules = ssl_vpn.get("authentication-rule") if (_ssl_on and isinstance(ssl_vpn.get("authentication-rule"), dict)) else {}
    for _k, rule in _auth_rules.items():
        if isinstance(rule, dict):
            ra_groups |= set(_tokens(rule.get("groups")))
            ra_users |= set(_tokens(rule.get("users")))
    for _n, p1 in (parsed.get("vpn ipsec phase1-interface") or {}).items():
        if isinstance(p1, dict):
            ra_groups |= set(_tokens(p1.get("usrgrp"))) | set(_tokens(p1.get("authusrgrp")))   # XAuth dial-up too
    _dialup_ifaces = {str(x).lower() for x in ((ctx or {}).get("dialup_tunnels") or [])}
    for _pid, pcfg in (parsed.get("firewall policy") or {}).items():
        if isinstance(pcfg, dict) and any(n.lower().startswith("ssl.") or n.lower() in _dialup_ifaces
                                         for n in _tokens(pcfg.get("srcintf"))):
            # owner 2026-10-19: policies on a dial-up IPsec tunnel (IKEv2 EAP) bind the user groups as
            # SSL-VPN policies do
            ra_groups |= set(_tokens(pcfg.get("groups")))
            ra_users |= set(_tokens(pcfg.get("users")))
    _ldap_servers = {str(n).strip('"') for n in (parsed.get("user ldap") or {})}
    _mfa_servers = {str(n).strip('"') for sec in ("user radius", "user tacacs+") for n in (parsed.get(sec) or {})}
    _saml = _saml_idps(parsed)        # owner 2026-10-19: FortiTrust ID = cloud MFA; other SAML IdPs not visible
    if (local_users or _ldap_servers) and (ra_groups or ra_users):
        # owner 2026-10-18: a password from the built-in database OR from an LDAP server is still one factor;
        # only RADIUS / TACACS+ (which can enforce MFA server-side) count as covered
        def _auth_source(uname):
            c = local_users.get(uname)
            if c is None:
                if uname in _saml:
                    return "saml (FortiTrust ID, cloud MFA)" if _saml[uname]["mfa"] else "saml server (MFA not visible)"
                return "ldap server" if uname in _ldap_servers else ("radius / tacacs+ server" if uname in _mfa_servers else "unknown")
            t = _sv(c, "type", "password")
            return {"password": "local (built-in user database)", "ldap": "ldap", "radius": "radius", "tacacs+": "tacacs+"}.get(t, t)

        def _no_mfa(uname):
            c = local_users.get(uname)
            if c is None:
                return uname in _ldap_servers          # the whole LDAP server as a member: no per-user two-factor
            return (_sv(c, "status", "enable") != "disable"
                    and _sv(c, "type", "password") in ("password", "ldap")
                    and _sv(c, "two-factor", "disable") == "disable")
        for gname in sorted(ra_groups):
            gcfg = groups_cfg.get(gname)
            if gcfg is None:
                continue
            members = _tokens(gcfg.get("member"))
            weak = [m for m in members if _no_mfa(m)]
            remote = [m for m in members if m not in weak and (m not in local_users or _sv(local_users[m], "type", "password") != "password")]
            if weak:
                finding("config_vpn_user_no_mfa",
                        "high", "SR 1.7, SR 1.13 RE1", "4.3",
                        f"Remote-access group '{gname}': {len(weak)} user(s) without two-factor",
                        {"ref_key": f"vpn-mfa:{gname}", "group": gname, "users_without_mfa": weak[:30],
                         "auth_sources": {m: _auth_source(m) for m in weak[:30]}, "mfa_kind": "none",
                         "remote_members": remote[:10], "remote_sources": {m: _auth_source(m) for m in remote[:10]},
                         "reason": "a password-only account (built-in user database or LDAP) can reach the plant over "
                                   "the VPN; enable FortiToken / e-mail / SMS two-factor on each user or move the group "
                                   "to a RADIUS / TACACS+ server that enforces MFA",
                         "checklist_title": "MFA for remote access (USER 1.9)"})
        direct = sorted(u for u in ra_users if _no_mfa(u))
        if direct:
            finding("config_vpn_user_no_mfa",
                    "high", "SR 1.7, SR 1.13 RE1", "4.3",
                    f"SSL-VPN authentication rule names {len(direct)} user(s) without two-factor",
                    {"ref_key": "vpn-mfa:(direct users)", "group": None, "users_without_mfa": direct[:30],
                     "auth_sources": {m: _auth_source(m) for m in direct[:30]}, "mfa_kind": "none",
                     "reason": "a password-only account can reach the plant over the VPN",
                     "checklist_title": "MFA for remote access (USER 1.9)"})

    # DT-04 / RA-02: IPsec proposals and DH groups (explicit values only)
    _weak_alg = ("des-", "3des-", "-md5", "null")
    _weak_dh = {"1", "2", "5"}
    for p1name, p1 in (parsed.get("vpn ipsec phase1-interface") or {}).items():
        if not isinstance(p1, dict):
            continue
        name = str(p1name).strip('"')
        props = [t.lower() for t in _tokens(p1.get("proposal"))]
        dhs = [t for t in _tokens(p1.get("dhgrp"))]
        bad_props = [t for t in props if any(w in t for w in _weak_alg)]
        bad_dh = [t for t in dhs if t in _weak_dh]
        legacy = [t for t in props if t.endswith("-sha1")]
        p2_bad, p2_nopfs = [], []
        for p2name, p2 in (parsed.get("vpn ipsec phase2-interface") or {}).items():
            if not isinstance(p2, dict) or _sv(p2, "phase1name") != name.lower():
                continue
            p2_bad += [t for t in (x.lower() for x in _tokens(p2.get("proposal"))) if any(w in t for w in _weak_alg)]
            p2_bad += [f"dh{t}" for t in _tokens(p2.get("dhgrp")) if t in _weak_dh]
            if _sv(p2, "pfs", "enable") == "disable":
                p2_nopfs.append(str(p2name).strip('"'))
        if bad_props or bad_dh or p2_bad:
            sev = "medium"
        elif legacy or p2_nopfs:
            sev = "low"
        else:
            continue
        finding("config_weak_ipsec_crypto",
                sev, "SR 4.3, SR 4.1, SR 3.1", "4.2",
                f"IPsec tunnel '{name}' uses weak cryptography"
                + (f" ({', '.join((bad_props + ['dh' + d for d in bad_dh] + p2_bad)[:4])})" if (bad_props or bad_dh or p2_bad)
                   else " (SHA1 integrity / no PFS)"),
                {"ref_key": f"ipsec-crypto:{name}", "phase1": name,
                 "weak_phase1": bad_props + [f"dh{d}" for d in bad_dh], "weak_phase2": p2_bad,
                 "legacy_sha1": legacy, "phase2_without_pfs": p2_nopfs,
                 "reason": "DES / 3DES / MD5 and DH groups 1, 2, 5 are broken or too short; SHA1 integrity "
                           "and disabled PFS are deprecated - use AES-GCM or AES-256 / SHA-256+, DH 14 or "
                           "higher (19-21 ECP), PFS on",
                 "checklist_title": "Cryptographic mechanisms per policy (DATA 1.5)"})

    # DT-04 / CIS 6.2: SSL-VPN TLS floor and cipher strength
    if _ssl_on:
        _min = _sv(ssl_vpn, "ssl-min-proto-ver", "")
        _alg = _sv(ssl_vpn, "algorithm", "")
        weak_min = _min in {"tls1-0", "tls1-1", "ssl3", "tlsv1", "tlsv1-0", "tlsv1-1", "sslv3"}
        weak_alg = _alg in {"low", "medium"}
        if weak_min or weak_alg:
            finding("config_sslvpn_weak_tls",
                    "medium", "SR 4.1, SR 4.3", "4.2",
                    "SSL-VPN accepts " + " and ".join(
                        ([f"TLS down to {_min}"] if weak_min else []) + ([f"'{_alg}' strength ciphers"] if weak_alg else [])),
                    {"ssl_min_proto_ver": _min or "not set", "algorithm": _alg or "not set (high)",
                     "reason": "remote-access sessions must not negotiate TLS 1.0 / 1.1 or weak cipher suites",
                     "checklist_title": "Limited TLS versions for SSL-VPN (CIS 6.2)"})

    # RA-07: FortiAP SSIDs with open / WEP / WPA(1) security; owner 2026-10-19: where each SSID lands
    # (tunnel mode -> its own interface; bridge mode -> the VLAN it is bridged to), high when that is OT,
    # pre-shared keys on an OT SSID, managed APs
    _ctx = ctx or {}
    _ot_set = {str(x).lower() for x in (_ctx.get("ot_interfaces") or ())}
    _lvls = _ctx.get("iface_levels") or {}
    _ifaces = parsed.get("system interface") or {}
    _vlan_ifaces = {}                    # vlan id -> (interface name, level)
    for _in, _ic in _ifaces.items():
        if isinstance(_ic, dict) and _ic.get("vlanid") not in (None, ""):
            _vid = str(_norm_scalar(_ic.get("vlanid")))
            _cand = (str(_in), _lvls.get(str(_in).lower()))
            # a tag reused on two parents: the labelled one decides (audit 2026-10-19)
            if _vid not in _vlan_ifaces or (_vlan_ifaces[_vid][1] is None and _cand[1] is not None):
                _vlan_ifaces[_vid] = _cand
    _weak_wifi = {"open", "wep64", "wep128", "wpa-personal", "wpa-only-personal", "wpa-enterprise",
                  "wpa-only-enterprise", "wpa-personal+captive-portal", "captive-portal"}
    _psk_wifi = {"wpa2-only-personal", "wpa2-personal", "wpa3-sae", "wpa3-sae-transition", "wpa2-only-personal+captive-portal",
                 "wpa2-personal+captive-portal", "owe"}
    _wtps = [str(n).strip('"') for n, c in (parsed.get("wireless-controller wtp") or {}).items()
             if isinstance(c, dict) and _sv(c, "admin", "enable") != "disable"]
    # owner 2026-10-19: is the SSID broadcast at all? controller on, assigned to a non-disabled radio of an
    # AP profile, and at least one managed AP (a FortiWiFi's built-in radio is not visible as an AP: the
    # profile named for the model stands in for it)
    _ctl_on = _sv(parsed.get("system global") or {}, "wireless-controller", "enable") != "disable"
    _radio_ssids, _radio_all, _local_radio = set(), False, False
    for _pn, _pc in (parsed.get("wireless-controller wtp-profile") or {}).items():
        if not isinstance(_pc, dict):
            continue
        if str(_pn).strip('"').upper().startswith(("FWF", "FORTIWIFI")):
            _local_radio = True
        for _rk in ("radio-1", "radio-2", "radio-3", "radio-4"):
            _rc = _pc.get(_rk)
            if not isinstance(_rc, dict) or _sv(_rc, "mode", "ap") in ("disabled", "monitor", "sniffer"):
                continue
            if _sv(_rc, "vap-all", "tunnel") not in ("disable",) and "vaps" not in _rc:
                _radio_all = True                      # vap-all: every SSID of the right type is broadcast
            _radio_ssids |= {str(x).strip('"') for x in _as_list(_rc.get("vaps"))}
    _has_ap = bool(_wtps) or _local_radio
    for vname, vap in (parsed.get("wireless-controller vap") or {}).items():
        if not isinstance(vap, dict):
            continue
        vkey = str(vname).strip('"')
        _active = _ctl_on and _has_ap and (_radio_all or vkey in _radio_ssids)
        _why_off = (None if _active else "wireless controller disabled" if not _ctl_on else
                    "no managed access point" if not _has_ap else "not assigned to any radio of an AP profile")
        sec = _sv(vap, "security", "wpa2-only-personal")
        ssid = str(_norm_scalar(vap.get("ssid")) or "").strip().strip('"')     # keep the SSID's case
        bridged = _sv(vap, "local-bridging", "disable") == "enable"
        vlan = str(_norm_scalar(vap.get("vlanid")) or "").strip() or None
        # where the SSID lands
        if bridged and vlan and vlan in _vlan_ifaces:
            land_if, land_lvl = _vlan_ifaces[vlan]
            land = f"VLAN {vlan} ({land_if})"
        elif bridged:
            land_if, land_lvl = None, None
            land = f"VLAN {vlan} (bridged at the AP; not an interface of this firewall)" if vlan else "the AP's local LAN (bridged)"
        else:
            land_if = vkey if vkey in _ifaces else None
            land_lvl = _lvls.get(vkey.lower())
            land = f"tunnel-mode interface {vkey}" + (f" ({_sv(_ifaces.get(vkey) or {}, 'ip') or 'no address'})" if land_if else " (interface not found)")
        in_ot = bool(land_if) and (land_if.lower() in _ot_set or (isinstance(land_lvl, (int, float)) and land_lvl <= 2))
        base = {"ref_key": f"vap:{vkey}", "vap": vkey, "ssid": ssid, "security": sec, "mode": "bridge" if bridged else "tunnel",
                "lands_on": land, "interface": land_if, "vlan_id": vlan, "purdue_level": land_lvl, "in_ot": in_ot,
                "broadcast_ssid": _sv(vap, "broadcast-ssid", "enable"), "pmf": _sv(vap, "pmf", "disable"),
                "passphrase_set": bool(vap.get("passphrase")), "managed_aps": _wtps[:20],
                "active": _active, "inactive_reason": _why_off}
        if not _active:
            finding("config_wireless_in_ot" if in_ot else "config_wireless_weak_security",
                    "info", "SR 1.6, SR 5.1", "2.5",
                    f"Wireless SSID '{ssid or vkey}' is defined but not broadcast ({_why_off})",
                    {**base, "reason": "dead wireless configuration: the SSID exists in the configuration but no radio "
                                       "broadcasts it - remove it, or confirm a FortiWiFi built-in radio / an AP the "
                                       "backup does not show",
                     "checklist_title": "Wireless networks are a separate zone behind the firewall"})
            continue
        if in_ot:
            finding("config_wireless_in_ot",
                    "high", "SR 1.6, SR 5.1", "2.5",
                    f"Wireless SSID '{ssid or vkey}' lands in an OT network ({land})",
                    {**base, "reason": "a radio network inside the control zone is an ingress point that no cable or door "
                                       "controls; OT wireless needs its own zone behind the firewall, 802.1X and an "
                                       "engineering justification",
                     "checklist_title": "Wireless networks are a separate zone behind the firewall"})
        if sec in _weak_wifi:
            finding("config_wireless_weak_security",
                    "high" if in_ot else "medium", "SR 1.6, SR 4.1", "2.5",
                    f"Wireless SSID '{ssid or vkey}' uses {sec}" + (" in an OT network" if in_ot else ""),
                    {**base,
                     "reason": "open, WEP and WPA(1) networks can be joined or decrypted by anyone in range; "
                               "use WPA2/WPA3-Enterprise (802.1X) for OT wireless",
                     "checklist_title": "Wireless authentication and configuration (NET 2.3)"})
        elif sec in _psk_wifi and in_ot:
            finding("config_wireless_weak_security",
                    "low", "SR 1.6, SR 4.1", "2.5",
                    f"Wireless SSID '{ssid or vkey}' in an OT network uses a pre-shared key ({sec})",
                    {**base,
                     "reason": "a shared passphrase on an OT SSID is one secret for every device and leaver; its strength "
                               "cannot be read from the configuration (stored encrypted) - use WPA2/WPA3-Enterprise "
                               "(802.1X) with per-device credentials, or document the passphrase policy",
                     "checklist_title": "Wireless authentication and configuration (NET 2.3)"})

    # 9.4 Centralized admin authentication: flag if no admin has two-factor
    # configured AND no RADIUS/TACACS+ server is configured (both absent
    # suggests purely local credentials with no central auth).
    radius_cfg = parsed.get("user radius", {})
    tacacs_cfg = parsed.get("user tacacs+", {})
    has_central_auth = bool(radius_cfg or tacacs_cfg)
    has_2fa = any(
        a.get("two-factor") not in (None, "disable")
        for a in admins_raw.values()
        if isinstance(a, dict)
    )
    if not has_central_auth and not has_2fa:
        finding("config_no_central_auth",
                "medium", "SR 1.1, SR 1.3", "9.4",
                "No centralized authentication (RADIUS/TACACS+) or MFA configured for admin accounts",
                {"radius_configured": bool(radius_cfg),
                 "tacacs_configured": bool(tacacs_cfg),
                 "any_2fa_configured": has_2fa,
                 "checklist_title": "Admin authentication centralized (RADIUS/TACACS+)"})

    # 9.7 Maintainer account: FortiGate has a built-in 'maintainer' account
    # for password recovery. Flag if it is not disabled.
    # DR-05: the FortiOS key is "admin-maintainer" (default enable).
    maintainer_status = g.get("admin-maintainer", g.get("maintainer-admin", "enable"))
    if str(maintainer_status).lower() != "disable":
        finding("config_maintainer_account_enabled",
                "high", "SR 2.1", "9.7",
                "FortiGate maintainer (password recovery) account is not disabled",
                {"maintainer_admin": maintainer_status,
                 "checklist_title": "Maintainer account disabled (or risk accepted with physical controls)"})
    # Also flag if an admin account named 'maintainer' exists (some configs
    # use this as a service account rather than the built-in)
    if "maintainer" in admins_raw:
        finding("config_maintainer_named_account",
                "medium", "SR 2.1", "9.7",
                "Admin account named 'maintainer' exists — verify this is intentional",
                {"username": "maintainer",
                 "checklist_title": "Maintainer account disabled (or risk accepted with physical controls)"})

    # 9.8 TLS cipher suites: flag if 'set ssl-min-proto-version TLS1-0' or
    # 'TLS1-1' is set in system global (weak/deprecated TLS versions).
    ssl_min = g.get("ssl-min-proto-version", "TLSv1-2")  # FortiOS default is TLS 1.2
    # Comparison is case-insensitive - FortiOS uses "TLSv1-1", "TLSv1-0" etc.
    weak_tls = {"tlsv1", "tlsv1-0", "tlsv1-1", "ssl3", "tls1-0", "tls1-1", "sslv3"}
    if str(ssl_min).lower() in weak_tls:
        finding("config_weak_tls_version",
                "high", "SR 4.1", "9.8",
                f"Minimum TLS version is {ssl_min} (deprecated; recommend TLSv1-2 or higher)",
                {"ssl_min_proto_version": ssl_min, "recommended_minimum": "TLSv1-2",
                 "checklist_title": "Static-key TLS ciphers disabled"})

    # 9.9 HA heartbeat authentication: flag if HA is configured but
    # authentication is not enabled on the HA group.
    ha_mode = ha.get("mode", "standalone")
    if ha_mode not in ("standalone", ""):
        ha_auth = str(ha.get("authentication", "disable")).lower()
        if ha_auth != "enable":
            finding("config_ha_no_auth",
                    "medium", "SR 3.1", "9.9",
                    "HA heartbeat authentication is not enabled",
                    {"ha_mode": ha_mode, "authentication": ha_auth,
                     "checklist_title": "HA heartbeat authenticated and encrypted"})

    # 9.10 Log transport encrypted and reliable, for EVERY enabled off-box
    # destination (2026-10-12; was syslog 1 only).  Syslog: UDP without
    # encryption is the FortiOS default.  FortiAnalyzer / Cloud: only an
    # explicit weak setting (enc-algorithm low / disable, reliable disable)
    # is reported - their defaults are not judged.
    weak = []
    for d in off_box:
        why = []
        if d["encrypted"] is False:
            why.append(f"no encryption (enc-algorithm {d.get('enc_algorithm') or 'disable'})")
        if d["reliable"] is False:
            why.append("UDP, not reliable TCP delivery" if d["kind"] == "syslog" else "reliable delivery disabled")
        if why:
            weak.append((d, why))
    if weak:
        first, _ = weak[0]
        where = first.get("where")
        title = ("Log forwarding not encrypted or not reliable: "
                 + "; ".join(f"{_dest_label(d)} ({', '.join(w)})" for d, w in weak)
                 + (f"; the collector sits inside protected network {where[0]} ({where[1]})" if where else ""))[:512]
        finding("config_syslog_unencrypted",
                "medium", "SR 6.1, SR 2.9", "9.10", title,
                {"destinations": [{"destination": _dest_label(d), "kind": d["kind"], "server": d.get("server"),
                                   "problems": w, "enc_algorithm": d.get("enc_algorithm"),
                                   "server_interface": (d.get("where") or [None, None])[0],
                                   "server_network": (d.get("where") or [None, None])[1]} for d, w in weak],
                 # first destination, kept for the previous detail keys
                 "enc_algorithm": first.get("enc_algorithm"),
                 "reliable_tcp": "enable" if first.get("reliable") else "disable",
                 "server": first.get("server"),
                 "server_interface": where[0] if where else None,
                 "server_network": where[1] if where else None,
                 "checklist_title": "Log transport to FortiAnalyzer/syslog encrypted and reliable"})

    # DR-08: local-in policies (traffic TO the firewall itself).  An accept
    # entry for every service hands the management plane, routing and VPN
    # daemons to its sources; allowaccess still limits the admin services,
    # but the policy no longer does.
    _li_reg = None                       # address registry, built once for the local-in entries
    for lid, lcfg in (parsed.get("firewall local-in-policy") or {}).items():
        if not isinstance(lcfg, dict) or str(lcfg.get("action", "deny")).lower() != "accept":
            continue
        if str(lcfg.get("status", "enable")).lower() == "disable":
            continue
        svcs = [str(x) for x in _as_list(lcfg.get("service"))]
        if not any(x.upper() == "ALL" for x in svcs):
            continue
        intf = [str(x) for x in _as_list(lcfg.get("intf"))] or ["any"]
        srcs = [str(x).strip('"') for x in _as_list(lcfg.get("srcaddr"))] or ["all"]
        outside = any(str((interfaces.get(i) or {}).get("role", "")).lower() == "wan"
                      or i.lower().startswith(("wan", "modem")) for i in intf)
        any_src = any(x.lower() == "all" for x in srcs)
        # owner 2026-10-19: resolve the source objects / groups so the finding says what they are
        if _li_reg is None:
            _li_reg = _build_addr_registry(parsed)
        _ao, _ag = _li_reg
        resolved, ext, wide, remote, unplaced, places = [], [], [], [], [], {}
        for sname in srcs:
            if sname.lower() in ("all", "any"):
                resolved.append("any"); continue
            for tok in _resolve_address(sname, _ao, _ag):
                resolved.append(tok)
                pl = _place_source(tok, ctx or {})
                places[tok] = pl["where"]
                if pl["kind"] == "external":
                    ext.append(tok)
                elif pl["kind"] == "remote":
                    remote.append(tok)        # owner 2026-10-19: reached through a tunnel = remote
                elif pl["kind"] == "unplaced":
                    unplaced.append(tok)
                try:
                    if ipaddress.ip_network(tok, strict=False).prefixlen <= 16:
                        wide.append(tok)
                except ValueError:
                    pass
        any_src = any_src or "any" in resolved          # a group that contains "all" (audit 2026-10-19)
        n_out = len(ext) + len(remote) + len(unplaced)
        sev = "high" if outside and (any_src or n_out) else "medium"
        finding("config_local_in_permits_all",
                sev, "SR 5.1, SR 2.1", "5.8",
                f"Local-in policy {lid} accepts every service to the firewall on "
                f"{', '.join(intf)} from {', '.join(srcs)}"
                + (f" ({len(resolved)} address(es), {n_out} outside the site)" if resolved and not any_src else ""),
                {"ref_key": f"local-in:{lid}", "local_in_policy": str(lid), "interfaces": intf,
                 "srcaddr": srcs, "sources_resolved": resolved[:40], "source_count": len(resolved),
                 "external_sources": ext[:20], "remote_sources": remote[:20], "unplaced_sources": unplaced[:20],
                 "wide_sources": wide[:20], "source_places": dict(list(places.items())[:40]),
                 "dstaddr": [str(x) for x in _as_list(lcfg.get("dstaddr"))],
                 "service": svcs, "outside_interface": outside,
                 "reason": "every firewall service (management, routing, VPN daemons) is open to these sources"
                           + (f"; {len(ext)} of them are on the Internet" if ext else "")
                           + (f"; {len(remote)} are behind a VPN tunnel (remote)" if remote else "")
                           + (f"; {len(unplaced)} have no interface or route on this firewall" if unplaced else "")
                           + (f"; {len(wide)} are networks of /16 or wider" if wide else ""),
                 "checklist_title": "Management-plane traffic to the firewall only from authorized hosts"})

    # DR-09: IPsec authentication.
    for p1, pcfg in (parsed.get("vpn ipsec phase1-interface") or {}).items():
        if not isinstance(pcfg, dict):
            continue
        dynamic = str(pcfg.get("type", "static")).lower() == "dynamic"
        auth = str(pcfg.get("authmethod", "psk")).lower()
        peertype = str(pcfg.get("peertype", "any")).lower()
        if not dynamic and auth == "signature" and peertype == "any":
            finding("config_ipsec_peer_unrestricted",
                    "medium", "SR 1.2, SR 1.9", "4.2",
                    f"IPsec tunnel {p1} accepts any certificate from its peer "
                    f"({pcfg.get('remote-gw') or 'dynamic peer'})",
                    {"ref_key": f"ipsec-peer:{p1}", "phase1": str(p1), "remote_gw": pcfg.get("remote-gw"),
                     "authmethod": auth, "peertype": peertype,
                     "checklist_title": "MFA required for remote access"})
        if dynamic and auth == "psk":
            user_auth = (str(pcfg.get("eap", "")).lower() == "enable"
                         or pcfg.get("xauthtype") not in (None, "", "disable") or bool(pcfg.get("authusrgrp")))
            finding("config_ipsec_dialup_psk",
                    "low" if user_auth else "medium", "SR 1.2, SR 1.1", "4.2",
                    f"Dial-up IPsec {p1} authenticates the tunnel with a pre-shared key shared by "
                    f"every client" + ("" if user_auth else " and no per-user authentication"),
                    {"ref_key": f"ipsec-psk:{p1}", "phase1": str(p1), "user_authentication": user_auth,
                     "eap": pcfg.get("eap"), "xauthtype": pcfg.get("xauthtype"),
                     "checklist_title": "MFA required for remote access"})

    # DR-11: a custom service whose name says one transport but whose
    # definition is the other (UDP_3900 = tcp 3900): the policy does not
    # allow what its author meant to.
    _users: dict = {}
    for _pid, _pc in (parsed.get("firewall policy") or {}).items():
        if isinstance(_pc, dict):
            for _sv in _as_list(_pc.get("service")):
                _users.setdefault(str(_sv), []).append(str(_pid))
    for sname, scfg in (parsed.get("firewall service custom") or {}).items():
        if not isinstance(scfg, dict):
            continue
        m = re.match(r"(?i)^(tcp|udp)[ _-]?\d", str(sname))
        if not m:
            continue
        named = m.group(1).lower()
        has_t, has_u = bool(scfg.get("tcp-portrange")), bool(scfg.get("udp-portrange"))
        other = "udp" if named == "tcp" else "tcp"
        if (has_t or has_u) and not (has_t if named == "tcp" else has_u):
            finding("config_service_protocol_mismatch",
                    "low", "SR 5.2", "3.3",
                    f"Service {sname} is named {named.upper()} but defined as {other.upper()} "
                    f"{scfg.get(other + '-portrange')}",
                    {"ref_key": f"service:{sname}", "service": str(sname), "named_protocol": named,
                     "defined": {"tcp": scfg.get("tcp-portrange"), "udp": scfg.get("udp-portrange")},
                     "used_by_policies": _users.get(str(sname), []),
                     "checklist_title": "No overly broad subnets or port ranges where specific hosts/ports are known"})

    # 9.13 Hostname and timezone: flag if hostname is default ('FortiGate')
    # or timezone is not set.
    hostname = g.get("hostname", "")
    if not hostname or hostname.lower() in ("fortigate", "fg", "fgt", "firewall"):
        finding("config_default_hostname",
                "low", "SR 2.11", "9.13",
                f"Firewall hostname is default or generic: '{hostname}'",
                {"hostname": hostname,
                 "checklist_title": "Hostname and timezone set (log correlation)"})

    tz_value = g.get("timezone")
    if not tz_value:
        finding("config_no_timezone",
                "low", "SR 2.11", "9.13",
                "Timezone not explicitly configured (log timestamps may be inconsistent)",
                {"timezone": None,
                 "checklist_title": "Hostname and timezone set (log correlation)"})

    # 9.14 Periodic review evidence: check if policies have owner comments
    # (the existing firewall_parser and forti_config_parser store comments
    # in the 'owner' field). Flag if > 25% of permit rules have no owner.
    # DR-07: counted per POLICY - `policies` is the expanded row list (one
    # policy with 4 services x 6 hosts is 24 rows).
    _by_pol: dict = {}
    for p in policies:
        if p.get("action") == "permit":
            _by_pol.setdefault((p.get("vdom"), p.get("policy_id")), p)
    permit_rules = list(_by_pol.values())
    no_owner_rules = [p for p in permit_rules if not p.get("owner")]
    if permit_rules and len(no_owner_rules) / len(permit_rules) > 0.25:
        finding("config_rules_missing_owner",
                "low", "2-1 SPE 2 (CM)", "9.14",
                f"{len(no_owner_rules)} of {len(permit_rules)} permit policies have no owner/comments",
                {"rules_without_owner": [p["policy_id"] for p in no_owner_rules],
                 "total_permit_rules": len(permit_rules),
                 "fraction_missing": round(len(no_owner_rules)/len(permit_rules), 2),
                 "checklist_title": "Periodic firewall ruleset review defined and evidenced"})

    # 3.13 Anti-spoofing / ingress-egress filtering: FortiGate's RPF
    # (Reverse Path Forwarding) is the mechanism. Check for 'set src-check
    # disable' on any interface (disabling RPF is the anti-spoofing gap).
    for iface_name, cfg in interfaces.items():
        # FortiOS system tunnels (naf.<vdom> NAT64/46 fabric, l2t.<vdom> L2TP,
        # ssl.<vdom>) carry src-check disable by design - not an interface an
        # operator turned anti-spoofing off on.
        if re.match(r"(?i)^(naf|l2t|ssl)\.", str(iface_name)):
            continue
        if str(cfg.get("src-check", "enable")).lower() == "disable":
            finding("config_rsp_check_disabled",
                    "medium", "SR 5.2", "3.13",
                    f"Reverse path forwarding (anti-spoofing) disabled on interface '{iface_name}'",
                    {"interface": iface_name,
                     "checklist_title": "Anti-spoofing / ingress-egress filtering enabled"})

    # ------------------------------------------------------------------ 3.10 IDS/IPS on all conduits --
    #
    # 3.10: "IDS/IPS enabled on all conduit policies" → SR 3.3, SR 6.2
    # Every cross-zone ACCEPT policy should have an ips-sensor applied.
    # 3.12 already catches the *industrial-port* subset; 3.10 is the broader
    # requirement covering all conduit traffic, not just industrial protocol
    # ports.  Exclude same-zone rules (already flagged by 3.4) and any
    # non-accept policy (deny rules don't need inspection).
    seen_ips_pids: set = set()
    for pol in policies:
        pid = pol.get("policy_id")
        if pid in seen_ips_pids or pol.get("action") != "permit":
            continue
        src_z = pol.get("src_zone", "")
        dst_z = pol.get("dst_zone", "")
        cross_zone = src_z and dst_z and src_z != dst_z and "any" not in (src_z, dst_z)
        if cross_zone and not pol.get("ips_sensor"):
            seen_ips_pids.add(pid)
            finding("config_ids_ips_missing",
                    "medium", "SR 3.3, SR 6.2", "3.12",
                    f"Cross-zone policy {pid} ({src_z}→{dst_z}) has no IPS sensor",
                    {"policy_id": pid,
                     "policy_name": pol.get("policy_name"),
                     "src_zone": src_z, "dst_zone": dst_z,
                     "checklist_title": "IDS/IPS enabled on all conduit policies"})

    # ------------------------------------------------------------------ 3.11 AV on file-carrying conduits --
    #
    # 3.11: "Anti-malware / AV enabled on conduit policies carrying file content"
    # → SR 3.3, SR 3.2
    # Only applicable to policies whose resolved service port is in
    # _FILE_TRANSFER_PORTS — DPI AV on a Modbus policy isn't meaningful.
    # A cross-zone file-transfer policy without an av-profile applied is the finding.
    seen_av_pids: set = set()
    for pol in policies:
        pid = pol.get("policy_id")
        if pid in seen_av_pids or pol.get("action") != "permit":
            continue
        src_z = pol.get("src_zone", "")
        dst_z = pol.get("dst_zone", "")
        cross_zone = src_z and dst_z and src_z != dst_z and "any" not in (src_z, dst_z)
        if not cross_zone:
            continue
        port_str = str(pol.get("dst_port", ""))
        carries_files = _port_hits(port_str, _FILE_TRANSFER_PORTS)
        if carries_files and not pol.get("av_profile"):
            seen_av_pids.add(pid)
            finding("config_av_missing_on_file_policy",
                    "medium", "SR 3.3, SR 3.2", "",
                    f"Cross-zone file-transfer policy {pid} ({src_z}→{dst_z}, port {port_str}) has no AV profile",
                    {"policy_id": pid,
                     "policy_name": pol.get("policy_name"),
                     "src_zone": src_z, "dst_zone": dst_z,
                     "dst_port": port_str,
                     "checklist_title": "Anti-malware enabled on conduit policies carrying file content"})

    # ------------------------------------------------------------------ 7.5 Scheduled backup --
    #
    # 7.5: "Configuration backup scheduled and offsite" → SR 7.3, SR 7.2
    # FortiGate can back up its configuration automatically via
    # `config system backup` (scheduled FTP/TFTP/USB) or via FortiManager
    # central backup.  If neither is configured the config is only saved
    # when an administrator manually triggers it.
    #
    # Detection heuristic:
    #   - If `system backup` block is present and `status` == "enable" → pass
    #   - If central-management type is "fortimanager" → FortiManager handles
    #     backup centrally; treat as covered
    #   - Otherwise → raise a low-severity finding (many orgs do this manually
    #     via policy/process; low rather than medium acknowledges that gap)
    backup_cfg = parsed.get("system backup", {})
    backup_enabled = str(backup_cfg.get("status", "disable")).lower() == "enable"
    fm_manages = str(central_mgmt.get("type", "")).lower() == "fortimanager"

    if not backup_enabled and not fm_manages:
        finding("config_no_scheduled_backup",
                "low", "SR 7.3, SR 7.2", "7.5",
                "Automated configuration backup not configured "
                "(no scheduled backup and no FortiManager central management)",
                {"backup_status": backup_cfg.get("status", "not configured"),
                 "central_management_type": central_mgmt.get("type", "not configured"),
                 "reason": "Without scheduled backup, the only copy of the running config is "
                           "the device itself.  Configure `config system backup` with an "
                           "offsite destination (FTP/SFTP), or manage via FortiManager with "
                           "central backup enabled.",
                 "checklist_title": "Configuration backup scheduled and stored offsite"})

    # ------------------------------------------------------------------ 8.10 Anti-malware profile exists --
    #
    # 8.10: "Anti-malware deployed on hosts/servers where applicable" → SR 3.2
    # On a FortiGate this translates to: at least one AV profile exists in
    # `config antivirus profile` and is applied to at least one policy.
    # An empty AV profile table means AV is not licensed or not configured —
    # a finding worth surfacing even if not all conduit policies need it.
    av_profiles = parsed.get("antivirus profile", {})
    policies_with_av = [p for p in policies if p.get("av_profile")]

    if not av_profiles:
        finding("config_no_av_profile",
                "medium", "SR 3.2", "8.10",
                "No AV/anti-malware profiles configured on this firewall",
                {"av_profile_count": 0,
                 "reason": "config antivirus profile is empty or absent.  Anti-malware "
                           "inspection requires a licensed AV subscription and at least one "
                           "configured profile applied to conduit policies.",
                 "checklist_title": "Anti-malware deployed where applicable"})
    elif not policies_with_av:
        finding("config_av_profile_not_applied",
                "low", "SR 3.2", "8.10",
                f"AV profile(s) defined ({len(av_profiles)}) but not applied to any firewall policy",
                {"av_profile_count": len(av_profiles),
                 "av_profile_names": list(av_profiles.keys())[:10],
                 "reason": "AV profiles exist but no firewall policy references them — "
                           "file-bearing traffic is not being inspected.",
                 "checklist_title": "Anti-malware deployed where applicable"})

    # ------------------------------------------------------------------ 9.x (new) --

    # 9.5 Admin access only from dedicated admin workstations (SR 5.1, SR 2.1).
    # Check 5.8 flags accounts with NO trusted-host restriction at all. This
    # check is the complementary one: trusted-hosts ARE set, but are they
    # narrow enough to constitute "dedicated admin workstations" rather than
    # a broad subnet?
    # Heuristic: a trusthost entry with prefix length <= 16 (e.g. 10.0.0.0/8
    # or 10.0.0.0/16) covers a large address range and cannot reasonably be
    # called a "dedicated workstation". Prefix /24 or longer = acceptable
    # (identifies a specific host or a small management subnet).
    # The complementary "trusthost outside the management networks" check
    # (config_admin_trusthost_outside_mgmt) needs the operator's declared
    # management networks: app.parsers.mgmt_networks.review_config_firewall.
    for admin in admin_info:
        for th_cidr in admin.get("trusted_hosts", []):
            try:
                import ipaddress as _ip
                net = _ip.ip_network(th_cidr, strict=False)
                if net.prefixlen <= 16:
                    finding("config_admin_trusthost_too_broad",
                            "medium", "SR 5.1, SR 2.1", "9.5",
                            f"Admin '{admin['username']}' trusthost {th_cidr} is too broad "
                            f"(/{net.prefixlen}) to constitute a dedicated admin workstation",
                            {"username": admin["username"],
                             "trusthost": th_cidr,
                             "prefix_length": net.prefixlen,
                             "checklist_title": "Admin access only from dedicated admin workstations"})
            except ValueError:
                log.debug(
                    "_check_admin_access_restrictions: skipping admin %r trusthost %r "
                    "(not a valid CIDR)",
                    admin.get("username"), th_cidr,
                )

    # 9.6 USB auto-install of configuration and firmware disabled (SR 2.3, SR 3.4).
    # FortiGate can automatically apply a config or firmware image from a USB
    # drive inserted at boot. If enabled, a physical attacker with a USB drive
    # can replace the firewall config or firmware without credentials.
    # `config system auto-install` has `auto-install-config` and
    # `auto-install-image` — both should be disabled.
    auto_install = parsed.get("system auto-install", {})
    if auto_install:
        if str(auto_install.get("auto-install-config", "disable")).lower() == "enable":
            finding("config_usb_auto_install_config",
                    "high", "SR 2.3, SR 3.4", "9.6",
                    "USB auto-install of configuration is enabled",
                    {"auto_install_config": "enable",
                     "reason": "A USB drive inserted at boot can silently replace the firewall "
                               "configuration without credentials.",
                     "checklist_title": "USB auto-install of configuration and firmware disabled"})
        if str(auto_install.get("auto-install-image", "disable")).lower() == "enable":
            finding("config_usb_auto_install_image",
                    "high", "SR 2.3, SR 3.4", "9.6",
                    "USB auto-install of firmware image is enabled",
                    {"auto_install_image": "enable",
                     "reason": "A USB drive inserted at boot can silently replace the firewall "
                               "firmware without credentials.",
                     "checklist_title": "USB auto-install of configuration and firmware disabled"})

    # 9.12 Signature and firmware updates from FortiManager or an internal
    # source, not directly from the internet (SR 5.1 RE2, SR 3.4).
    # Only fires on a positive signal that updates are NOT going through
    # FortiManager — either the type is explicitly set to something other
    # than fortimanager (cloud, none) OR autoupdate is explicitly enabled
    # without a FortiManager to route through. A completely absent config
    # block (empty config, no management section at all) does NOT fire —
    # the absence of autoupdate config does not imply autoupdate is running.
    # central_mgmt and autoupdate are already bound at the top of this function
    mgmt_type = str(central_mgmt.get("type", "")).lower()  # empty string if not configured
    autoupdate_status = str(autoupdate.get("status", "disable")).lower()

    not_using_fm = mgmt_type and mgmt_type not in ("fortimanager", "")
    autoupdate_explicitly_on = autoupdate_status == "enable"

    # owner 2026-10-19: uplink liveness probes aimed only at third-party public servers - if they stop
    # answering ICMP both default routes are withdrawn (informational: a design choice, not a control)
    _lm = parsed.get("system link-monitor") or {}
    _probes = []
    for _n, c in _lm.items():
        if not isinstance(c, dict) or str(c.get("status", "enable")).lower() == "disable":
            continue
        for srv in _as_list(c.get("server")):
            _probes.append((str(c.get("srcintf", "") or "").strip('"'), str(srv).strip('"')))
    if _probes:
        def _third_party(srv):
            try:
                return ipaddress.ip_address(srv).is_global
            except ValueError:
                low = srv.lower().rstrip(".")
                if low.endswith((".local", ".lan", ".internal", ".corp", ".home", ".intranet", ".localdomain")):
                    return False             # a site name (audit 2026-10-19)
                return "." in low            # a public name
        if all(_third_party(srv) for _if, srv in _probes):
            finding("config_link_monitor_external",
                    "info", "SR 7.1, SR 7.6", "7.4",
                    "Uplink liveness depends on third-party servers: " + ", ".join(sorted({s for _i, s in _probes})),
                    {"ref_key": "link-monitor", "monitors": [{"interface": i, "server": s} for i, s in _probes][:20],
                     "interfaces": sorted({i for i, _s in _probes}),
                     "reason": "every link monitor probes a public third-party host; if it stops answering ICMP the "
                               "uplinks are declared dead and their default routes withdrawn - probe the ISP gateways "
                               "or an internal anchor over the tunnel as well",
                     "checklist_title": "Redundant uplinks and monitored failover"})

    # owner 2026-10-19: FortiGuard automatic firmware upgrades on an OT firewall change the device
    # outside change control (SR 7.6).  Only an explicit `enable` is judged (older FortiOS has no key).
    _fg = parsed.get("system fortiguard") or {}
    if isinstance(_fg, dict) and str(_fg.get("auto-firmware-upgrade", "")).strip('"').lower() == "enable":
        _day = _as_list(_fg.get("auto-firmware-upgrade-day"))
        _win = (f"{', '.join(str(d) for d in _day)} " if _day else "") + \
               (f"{_fg.get('auto-firmware-upgrade-start-hour', '?')}:00-{_fg.get('auto-firmware-upgrade-end-hour', '?')}:00"
                if _fg.get("auto-firmware-upgrade-start-hour") is not None or _fg.get("auto-firmware-upgrade-end-hour") is not None else "")
        finding("config_auto_firmware_upgrade",
                "low", "SR 7.6, 2-1 SPE 2", "9.12",
                "Automatic FortiGuard firmware upgrades are enabled (system fortiguard auto-firmware-upgrade)",
                {"ref_key": "auto-firmware-upgrade", "auto_firmware_upgrade": "enable",
                 "upgrade_window": _win.strip() or None, "delay": _fg.get("auto-firmware-upgrade-delay"),
                 "central_management_type": mgmt_type or "not configured",
                 "reason": "the firewall replaces its own firmware when FortiGuard publishes a release - a change to an "
                           "OT boundary device outside the site's change control and maintenance windows"
                           + (f" (window: {_win.strip()})" if _win.strip() else ""),
                 "checklist_title": "Signature and firmware updates from FortiManager or an internal source"})

    if not_using_fm or (autoupdate_explicitly_on and mgmt_type not in ("fortimanager",)):
        finding("config_updates_from_internet",
                "medium", "SR 5.1 RE2, SR 3.4", "9.12",
                "Signature/firmware updates not routed through FortiManager "
                "(pulling directly from FortiGuard internet)",
                {"central_management_type": mgmt_type or "not configured",
                 "autoupdate_enabled": autoupdate_explicitly_on,
                 "reason": "Updates from FortiGuard cloud require internet egress from "
                           "the OT firewall. Route through an internal FortiManager "
                           "or local update mirror instead.",
                 "checklist_title": "Signature and firmware updates from FortiManager "
                                    "or an internal source, not directly from the internet"})

    # owner 2026-10-18: a FortiManager-managed device can be administered through the FortiManager tunnel
    # with FortiManager credentials; the MFA that protects that path lives on FortiManager, which this
    # config cannot show.  Informational; low when the FortiManager address is public.
    if mgmt_type == "fortimanager":
        _fmg_tokens = _as_list(central_mgmt.get("fmg"))
        fmg = str(_fmg_tokens[0] if _fmg_tokens else "").strip('"')
        public = None                      # audit 2026-10-18: a name is reported, not judged (an internal FQDN is common)
        try:
            public = bool(fmg) and ipaddress.ip_address(fmg).is_global
        except ValueError:
            public = None if fmg else False
        finding("config_fortimanager_admin_access",
                "low" if public else "info", "SR 1.1, SR 1.13", "9.4",
                "Device is managed by FortiManager: administrator MFA must be enforced on FortiManager"
                + (" (public address)" if public else " (address is a name: location not judged)" if public is None else ""),
                {"ref_key": "fortimanager-admin-access", "fortimanager": fmg or "(address not set)",
                 "fortimanager_public": public, "central_management_type": mgmt_type,
                 "serial_number": str(central_mgmt.get("serial-number", "") or "") or None,
                 "reason": "administrators reach this device through the FortiManager tunnel with FortiManager "
                           "accounts; the two-factor settings on this firewall do not cover that path"
                           + (" - the FortiManager is reachable from the Internet" if public else ""),
                 "checklist_title": "Admin authentication centralized (RADIUS/TACACS+) with MFA"})

    return findings


# ================================================================== ingest ==

def _compute_network_cidr(ip_cidr: Optional[str]) -> Optional[str]:
    """
    Given a host CIDR like "10.10.10.1/24", return the network CIDR
    "10.10.10.0/24". Returns None if ip_cidr is blank or unparsable.
    """
    if not ip_cidr:
        return None
    try:
        return str(ipaddress.ip_network(ip_cidr, strict=False))
    except ValueError:
        return None


def _classify_interface(iface_name: str, iface_cfg: dict, policy_referenced: bool = False) -> dict:
    """
    Derive is_ha, is_mgmt_only, and role from a FortiOS interface config dict.

    FortiOS uses 'role' values: lan, wan, dmz, undefined.
    HA heartbeat interfaces are typically type=="aggregate" with names like
    "HA", "heartbeat", or the FortiOS role field set to "ha" (rare).
    Management-only interfaces usually have allowaccess limited to management
    protocols (https/ssh/ping) and no firewall policies reference them.

    We detect:
      is_ha        — role=="ha", OR name contains "ha" (case-insensitive),
                     OR type is "redundant"/"aggregate" with name hinting HA
      is_mgmt_only — alias/zone contains "mgmt"/"management",
                     OR allowaccess is a subset of mgmt-only protocols
                     with no routed traffic indicators.  An interface that
                     a firewall policy references (``policy_referenced``,
                     directly or through its zone) carries routed traffic, so
                     admin access (https/ssh on a data port is routine) never
                     makes it management-only by itself.
    """
    role = str(iface_cfg.get("role", "")).lower()
    iface_type = str(iface_cfg.get("type", "physical")).lower()
    alias = str(iface_cfg.get("alias", "")).lower()
    zone = str(iface_cfg.get("zone", "")).lower()
    allowaccess = iface_cfg.get("allowaccess", [])
    if isinstance(allowaccess, str):
        allowaccess = [allowaccess]

    name_lower = iface_name.lower()

    # --- HA detection ---
    is_ha = (
        role == "ha"
        or "ha" in name_lower.split("-")
        or name_lower.startswith("ha")
        or (iface_type in ("redundant", "aggregate") and "ha" in name_lower)
        or "heartbeat" in name_lower
    )

    # --- Management-only detection ---
    # A routed FortiOS role (wan/lan/dmz) is authoritative — if the interface
    # carries routed traffic it cannot be management-only regardless of its
    # allowaccess list.  Without a routed role, fall back to the name/alias
    # heuristic and an allowaccess check.
    routed_roles = {"wan", "lan", "dmz"}
    mgmt_protocols = {"https", "http", "ssh", "telnet", "snmp", "fgfm", "capwap"}
    mgmt_indicator_min = {"https", "ssh"}   # at least one must be present
    access_set = {a.lower() for a in allowaccess}
    mgmt_only_access = (
        bool(access_set)
        and access_set.issubset(mgmt_protocols | {"ping"})
        and bool(access_set & mgmt_indicator_min)
    )
    name_says_mgmt = (
        "mgmt" in name_lower
        or "management" in name_lower
        or "mgmt" in alias
        or "mgmt" in zone
        or "management" in zone
    )
    is_mgmt_only = (
        # If FortiOS marks it as a routed-traffic role, it's not mgmt-only.
        role not in routed_roles
        and (name_says_mgmt or (mgmt_only_access and not policy_referenced))
    )

    return {"is_ha": is_ha, "is_mgmt_only": is_mgmt_only, "forti_role": role}


def default_route_devices(parsed: dict) -> set:
    """Interfaces (lower-case) that a static default route leaves through:
    `config router static` entries with no `dst` or dst 0.0.0.0/0."""
    out = set()
    for rcfg in (parsed.get("router static") or {}).values():
        if not isinstance(rcfg, dict) or not rcfg.get("device"):
            continue
        raw = rcfg.get("dst") or "0.0.0.0 0.0.0.0"
        raw = " ".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else str(raw)
        dst = raw.replace("/", " ").split()
        if dst and dst[0] == "0.0.0.0" and (len(dst) == 1 or dst[1] in ("0.0.0.0", "0")):
            d = rcfg.get("device")
            d = d[0] if isinstance(d, (list, tuple)) and d else d
            out.add(str(d).strip().strip('"').lower())
    return out


def _upsert_firewall_interfaces(
    db: DBSession,
    fw: "Firewall",
    zones: dict,
    parsed_interfaces: dict,
    policy_interfaces: Optional[set] = None,
    dialup: frozenset = frozenset(),
    tunnels: Optional[dict] = None,        # owner 2026-10-19: extract_tunnels(parsed)
    default_route_devices: frozenset = frozenset(),
) -> int:
    """
    Upsert FirewallInterface rows for ``fw`` from the ``zones`` dict produced
    by ``_extract_zones()`` and the raw ``parsed_interfaces`` from the
    FortiOS config block.

    Returns the number of rows created (not updated).

    parent_interface_id resolution runs in a second pass after all rows are
    flushed, so the FK target is guaranteed to exist even if the parent
    interface was defined after its child in the config block.
    """
    created = 0
    for iface_name, zone_data in zones.items():
        raw_cfg = parsed_interfaces.get(iface_name, {})
        ip_cidr = zone_data.get("ip")            # "10.10.10.1/24" or None
        network_cidr = _compute_network_cidr(ip_cidr)

        # Split ip_cidr into address + prefix
        ip_address: Optional[str] = None
        prefix_len: Optional[int] = None
        if ip_cidr:
            try:
                net = ipaddress.ip_interface(ip_cidr)
                ip_address = str(net.ip)
                prefix_len = net.network.prefixlen
            except ValueError:
                log.debug(
                    "_sync_interfaces_to_db: skipping interface %r with unparseable "
                    "ip_cidr %r",
                    iface_name, ip_cidr,
                )

        classification = _classify_interface(
            iface_name, {**raw_cfg, **zone_data},
            policy_referenced=iface_name.strip().lower() in (policy_interfaces or ()))

        existing = db.query(FirewallInterface).filter(
            FirewallInterface.firewall_id == fw.id,
            FirewallInterface.name == iface_name,
        ).first()

        if existing:
            # Update in place — operator fields (side, zone_label, purdue_level,
            # connects_to_interface_id, parent_interface_id) are never overwritten
            # by a re-ingest, EXCEPT parent_interface_id which is config-derived
            # (not operator-set) and should stay fresh.
            existing.ip_address   = ip_address
            existing.prefix_len   = prefix_len
            existing.ip_cidr      = ip_cidr
            existing.network_cidr = network_cidr
            existing.vlan_id      = zone_data.get("vlan_id")
            existing.iface_type   = zone_data.get("type")
            existing.alias        = zone_data.get("alias")
            existing.allowaccess  = zone_data.get("allowaccess", [])
            existing.status       = raw_cfg.get("status")
            existing.is_ha        = classification["is_ha"]
            existing.is_mgmt_only = classification["is_mgmt_only"]
            existing.role         = classification["forti_role"] or (
                "wan" if iface_name.strip().lower() in default_route_devices else None)
            existing.vdom         = zone_data.get("vdom")
            existing.tunnel_info  = (tunnels or {}).get(iface_name.strip().lower())
            _vpn_tunnel_level(existing, iface_name, zone_data.get("type"), dialup)
        else:
            row = FirewallInterface(
                firewall_id   = fw.id,
                name          = iface_name,
                ip_address    = ip_address,
                prefix_len    = prefix_len,
                ip_cidr       = ip_cidr,
                network_cidr  = network_cidr,
                vlan_id       = zone_data.get("vlan_id"),
                iface_type    = zone_data.get("type"),
                alias         = zone_data.get("alias"),
                allowaccess   = zone_data.get("allowaccess", []),
                status        = raw_cfg.get("status"),
                is_ha         = classification["is_ha"],
                is_mgmt_only  = classification["is_mgmt_only"],
                role          = classification["forti_role"] or (
                    "wan" if iface_name.strip().lower() in default_route_devices else None),
                vdom          = zone_data.get("vdom"),
                tunnel_info   = (tunnels or {}).get(iface_name.strip().lower()),
            )
            _vpn_tunnel_level(row, iface_name, zone_data.get("type"), dialup)
            db.add(row)
            created += 1

    # Second pass: resolve parent_interface_name → parent_interface_id FK.
    # Must run after all rows are flushed so the FK target exists.
    db.flush()
    for iface_name, zone_data in zones.items():
        parent_name = zone_data.get("parent_interface_name")
        if not parent_name:
            continue
        child = db.query(FirewallInterface).filter(
            FirewallInterface.firewall_id == fw.id,
            FirewallInterface.name == iface_name,
        ).first()
        parent = db.query(FirewallInterface).filter(
            FirewallInterface.firewall_id == fw.id,
            FirewallInterface.name == parent_name,
        ).first()
        if child and parent:
            child.parent_interface_id = parent.id

    return created


#: VD-05: the automatic level of an SSL-VPN tunnel interface (ssl.<vdom>)
VPN_TUNNEL_AUTO_SOURCE = "ssl_vpn_auto"


def extract_tunnels(parsed: dict) -> dict:
    """Owner 2026-10-19: site-to-site IPsec tunnels and their phase 2 selectors.
    {interface name (lower): {"peer", "wan_interface", "backup_of", "dynamic",
    "members", "selectors": [{"local", "remote"}]}} for every phase1-interface
    and every ``system ipsec-aggregate`` (members' selectors unioned)."""
    out: dict = {}
    _dl_reg = None
    for name, cfg in (parsed.get("vpn ipsec phase1-interface") or {}).items():
        if not isinstance(cfg, dict):
            continue
        n = str(name).strip('"')
        dyn = str(cfg.get("type", "static")).lower() == "dynamic"
        out[n.lower()] = {"name": n, "peer": (str(_as_list(cfg.get("remote-gw"))[0]) if cfg.get("remote-gw") else None),
                          "wan_interface": (str(_as_list(cfg.get("interface"))[0]).strip('"') if cfg.get("interface") else None),
                          "backup_of": (str(_as_list(cfg.get("monitor"))[0]).strip('"') if cfg.get("monitor") else None),
                          "dynamic": dyn, "ike_version": str(cfg.get("ike-version", "1")), "members": [], "selectors": []}
        if dyn and cfg.get("ipv4-start-ip") and cfg.get("ipv4-end-ip"):
            # owner 2026-10-19: a dial-up tunnel's clients are its address pool; the split-include
            # objects are the only destinations the clients route into the tunnel
            pool = f"{str(_as_list(cfg.get('ipv4-start-ip'))[0])}-{str(_as_list(cfg.get('ipv4-end-ip'))[0])}"
            if _dl_reg is None:
                _dl_reg = _build_addr_registry(parsed)
            _ao, _ag = _dl_reg
            locals_ = []
            for g in _as_list(cfg.get("ipv4-split-include")):
                for tok in _resolve_address(str(g).strip('"'), _ao, _ag):
                    if tok != "any" and not tok.startswith(("fqdn:", "wildcard-fqdn:", "cycle:", "internet-service")):
                        locals_.append(tok.replace("range:", ""))
            out[n.lower()]["selectors"].append({"name": "dial-up pool", "local": ",".join(locals_) or "0.0.0.0/0", "remote": pool,
                                                "split_include": [str(g).strip('"') for g in _as_list(cfg.get("ipv4-split-include"))]})
    _p2_ao, _p2_ag = _build_addr_registry(parsed)
    for name, cfg in (parsed.get("vpn ipsec phase2-interface") or {}).items():
        if not isinstance(cfg, dict):
            continue
        p1 = str(_as_list(cfg.get("phase1name"))[0]).strip('"').lower() if cfg.get("phase1name") else None
        if p1 not in out:
            continue

        def _net(key):
            v = cfg.get(key)
            if not v:
                return None
            parts = (" ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)).replace("/", " ").split()
            try:
                n_ = ipaddress.ip_network(f"{parts[0]}/{parts[1]}" if len(parts) > 1 else parts[0], strict=False)
                return str(n_)
            except (ValueError, IndexError):
                return None
        def _side(prefix):
            """The selector of one side: ``*-subnet`` (ip), ``*-name`` (an address object / group),
            ``*-start-ip``/``*-end-ip`` (range); None when nothing usable is set (audit 2026-10-19)."""
            kind = str(_norm_scalar(cfg.get(f"{prefix}-addr-type")) or "subnet").strip('"').lower()
            if kind == "name" or (kind == "subnet" and cfg.get(f"{prefix}-name") and not cfg.get(f"{prefix}-subnet")):
                nets = []
                for g in _as_list(cfg.get(f"{prefix}-name")):
                    for tok in _resolve_address(str(g).strip('"'), _p2_ao, _p2_ag):
                        if tok == "any":
                            return "0.0.0.0/0"
                        if not tok.startswith(("fqdn:", "wildcard-fqdn:", "cycle:", "unresolved:", "dynamic:", "internet-service")):
                            nets.append(tok.replace("range:", ""))
                return ",".join(nets) or None
            if kind == "range" or (cfg.get(f"{prefix}-start-ip") and not cfg.get(f"{prefix}-subnet")):
                a_, b_ = cfg.get(f"{prefix}-start-ip"), cfg.get(f"{prefix}-end-ip")
                if a_ and b_:
                    return f"{str(_as_list(a_)[0])}-{str(_as_list(b_)[0])}"
                return None
            return _net(f"{prefix}-subnet")
        local, remote = _side("src"), _side("dst")
        # a dial-up tunnel's mandatory phase 2 prints the defaults 0.0.0.0/0 both sides: the pool
        # entry above already bounds it, so an all-zero phase 2 adds nothing (audit 2026-10-19)
        if out[p1]["dynamic"] and out[p1]["selectors"] and (local or "0.0.0.0/0") == "0.0.0.0/0" and (remote or "0.0.0.0/0") == "0.0.0.0/0":
            continue
        if local or remote:
            out[p1]["selectors"].append({"name": str(name).strip('"'), "local": local or "0.0.0.0/0", "remote": remote or "0.0.0.0/0"})
    for name, cfg in (parsed.get("system ipsec-aggregate") or {}).items():
        if not isinstance(cfg, dict):
            continue
        members = [str(m).strip('"') for m in _as_list(cfg.get("member"))]
        sel, peers, wans = [], [], []
        for m in members:
            t = out.get(m.lower()) or {}
            sel += t.get("selectors") or []
            if t.get("peer"):
                peers.append(t["peer"])
            if t.get("wan_interface"):
                wans.append(t["wan_interface"])
        out[str(name).strip('"').lower()] = {"name": str(name).strip('"'), "peer": ", ".join(dict.fromkeys(peers)) or None,
                                             "wan_interface": ", ".join(dict.fromkeys(wans)) or None, "backup_of": None,
                                             "dynamic": False, "ike_version": None, "members": members, "selectors": sel}
    return out


def dialup_ipsec_names(views) -> set:
    """DR-03: names (lower-case) of the dial-up IPsec tunnels that hand remote
    USERS an address: a ``type dynamic`` phase1-interface with mode-cfg, EAP,
    XAUTH or a user group.  A dynamic phase1 without any of those is a
    dial-up site-to-site spoke and stays a normal interface."""
    out = set()
    for _vd, tree in views:
        for name, cfg in ((tree or {}).get("vpn ipsec phase1-interface") or {}).items():
            if not isinstance(cfg, dict) or str(cfg.get("type", "")).lower() != "dynamic":
                continue
            if (str(cfg.get("mode-cfg", "")).lower() == "enable" or str(cfg.get("eap", "")).lower() == "enable"
                    or cfg.get("xauthtype") not in (None, "", "disable") or cfg.get("authusrgrp")):
                out.add(str(name).strip().lower())
    return out


def _vpn_tunnel_level(row, name, iface_type, dialup=frozenset()) -> None:
    """VD-05: an SSL-VPN tunnel interface (``ssl.root`` / ``ssl.<vdom>``) is
    the remote side: Purdue 5, outside - set automatically unless the
    operator labelled it (then the label stays).  DR-03: so is a dial-up
    IPsec tunnel (``dialup`` - see dialup_ipsec_names); both are marked in
    ``remote_access``."""
    from app.parsers.vpn import is_tunnel_name
    lname = str(name or "").strip().lower()
    kind = "ssl" if is_tunnel_name(name) else ("ipsec_dialup" if lname in dialup else None)
    if kind is None or (iface_type or "tunnel") != "tunnel":
        row.remote_access = None
        # MP-25: a tunnel that stops being remote access (a dial-up IPsec
        # re-keyed as site-to-site) loses the automatic L5 - only an operator
        # label survives
        if row.purdue_suggestion_source == VPN_TUNNEL_AUTO_SOURCE:
            row.purdue_level = None
            row.purdue_suggestion_source = None
        return
    row.remote_access = kind
    if row.purdue_level is not None and row.purdue_suggestion_source != VPN_TUNNEL_AUTO_SOURCE:
        return                                    # operator label
    row.purdue_level = 5
    row.purdue_suggestion_source = VPN_TUNNEL_AUTO_SOURCE
    if not row.side:
        row.side = "outside"


def _prune_removed_interfaces(db: DBSession, fw: "Firewall", present: set,
                              vdom_scope: Optional[set]) -> list:
    """
    B-15(a): delete this firewall's FirewallInterface rows whose interface is
    no longer in the config.  ``vdom_scope`` None = every interface of the
    firewall is in scope (flat config / full `config global` backup); else
    only interfaces whose stored vdom is one of those VDOMs.

    References to a removed row are cleared first: peer interfaces'
    connects_to_interface_id, VLAN children's parent_interface_id, and
    PcapCapture interface_id / suggested_interface_id (the capture keeps the
    interface NAME in capture_interface_raw).  Operator annotations stored ON
    the removed interface (side, zone_label, purdue_level) are dropped with
    it - the segment no longer exists on this firewall; a re-added
    interface of the same name starts unannotated.  Returns the removed
    interface names.
    """
    q = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id)
    stale = [fi for fi in q.all()
             if fi.name not in present
             and (vdom_scope is None or fi.vdom in vdom_scope)]
    if not stale:
        return []
    ids = [fi.id for fi in stale]
    names = {fi.id: fi.name for fi in stale}
    for col in (FirewallInterface.connects_to_interface_id,
                FirewallInterface.parent_interface_id):
        db.query(FirewallInterface).filter(col.in_(ids)).update(
            {col: None}, synchronize_session="fetch")
    for cap in db.query(PcapCapture).filter(
            or_(PcapCapture.interface_id.in_(ids),
                PcapCapture.suggested_interface_id.in_(ids))).all():
        if cap.interface_id in names and not cap.capture_interface_raw:
            cap.capture_interface_raw = names[cap.interface_id][:128]
        if cap.interface_id in names:
            cap.interface_id = None
        if cap.suggested_interface_id in names:
            cap.suggested_interface_id = None
    db.flush()
    for fi in stale:
        if fi in fw.interfaces:
            fw.interfaces.remove(fi)   # delete-orphan cascade
        else:
            db.delete(fi)
    db.flush()
    log.info("Removed %d interface(s) no longer in the config of firewall id=%d: %s",
             len(stale), fw.id, sorted(names.values()))
    return sorted(names.values())


def _address_object_host_ip(obj_cfg) -> Optional[str]:
    """
    B-24: the single unicast host address of a FortiOS address / address6
    object, or None.  A host is an ipmask object with a /32 (or a bare IP),
    an address6 ``ip6`` with /128, or an iprange whose start == end.
    Invalid text (``foo/32``, ``999.1.1.1``), unspecified, multicast,
    broadcast (255.255.255.255) and loopback addresses yield None.  Never
    raises.
    """
    try:
        if not isinstance(obj_cfg, dict):
            return None
        obj_type = str(obj_cfg.get("type", "ipmask") or "ipmask").lower()
        addr = None
        if obj_type == "iprange":
            a, b = obj_cfg.get("start-ip"), obj_cfg.get("end-ip")
            if not a or not b:
                return None
            sa_, sb_ = ipaddress.ip_address(str(a).strip()), ipaddress.ip_address(str(b).strip())
            if sa_ != sb_:
                return None
            addr = sa_
        elif obj_type in ("ipmask", "ipprefix", ""):
            if "ip6" in obj_cfg:
                net = ipaddress.ip_network(str(_norm_scalar(obj_cfg.get("ip6")) or "").strip(),
                                           strict=False)
                if net.prefixlen != net.max_prefixlen:
                    return None
                addr = net.network_address
            else:
                subnet = obj_cfg.get("subnet")
                toks = [str(t).strip() for t in _as_list(subnet) if str(t).strip()]
                if not toks:
                    return None
                if len(toks) >= 2:
                    iface = ipaddress.ip_interface(f"{toks[0]}/{toks[1]}")
                else:
                    iface = ipaddress.ip_interface(toks[0])
                if iface.network.prefixlen != iface.max_prefixlen:
                    return None
                addr = iface.ip
        else:
            return None
        if (addr.is_unspecified or addr.is_multicast or addr.is_loopback
                or (addr.version == 4 and addr == ipaddress.IPv4Address("255.255.255.255"))):
            return None
        return str(addr)
    except (ValueError, TypeError):
        return None


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_fortigate_config(
    text: str,
    db: DBSession,
    firewall_name: Optional[str] = None,
    fallback_name: Optional[str] = None,
    device_name: Optional[str] = None,
    source_file: Optional[str] = None,
    generate_findings: bool = False,
    populate_approved_hosts: bool = False,
    baseline_id: Optional[int] = None,
    purdue_zone_from: Optional[int] = None,
    purdue_zone_to: Optional[int] = None,
) -> dict:
    """
    Parse a FortiGate ``show full-configuration`` output and populate:

      - Firewall         (one row per uploaded config; created/updated here)
      - FirewallInterface (one row per ``config system interface`` entry)
      - FirewallZone     (legacy — kept for backward compat; from same source)
      - FirewallRule     (from config firewall policy, objects resolved)
      - Host             (concrete IP address objects, as network-adjacent hosts)

    Multi-firewall topology (Option 2 — infer from count):
      After creating/updating the Firewall row, the total number of Firewall
      rows in the database is checked.  If ≥ 2, ``is_multi_fw`` is set True
      on every Firewall row and ``topology_state`` in the returned stats dict
      is set to ``"multi"`` so the API layer can prompt the topology builder.
      When there is only one Firewall, ``topology_state`` is ``"single"``.

    Parameters
    ----------
    text            : raw ``show full-configuration`` CLI output
    db              : SQLAlchemy session
    firewall_name   : operator-supplied label for this device
                      (e.g. "Perimeter-FW", "Cell-FW-A").  Falls back to
                      the hostname found in the config, then "unknown-fortigate".
    device_name     : legacy alias for ``firewall_name`` — accepted for
                      backward compat; ``firewall_name`` takes precedence.
    source_file     : original filename for audit trail
    generate_findings          : run 62443 config checks (off by default)
    populate_approved_hosts    : extract admin trusted-hosts into ApprovedHost
    baseline_id                : required when populate_approved_hosts=True

    Returns a stats dict for the API response.
    """
    # Phase 2 (multi-site): every lookup below stays in the upload's site.
    sid = scope_site_id(db)
    if populate_approved_hosts and baseline_id is not None:
        _bl = db.get(Baseline, baseline_id)
        if _bl is None or _bl.site_id != sid:
            raise ValueError(f"baseline_id {baseline_id} does not belong to this upload's site")
    if populate_approved_hosts and baseline_id is None:
        raise ValueError(
            "populate_approved_hosts=True requires a baseline_id - "
            "ApprovedHost rows must belong to a named Baseline (see models.py). "
            "Create one first, or omit populate_approved_hosts to skip admin "
            "trusted-host extraction for this ingest."
        )

    stats: dict = {
        "source_file": source_file,
        "device_name": device_name,
        "firewall_id": None,
        "firewall_device_id": None,
        "purdue_zone_from": purdue_zone_from,
        "purdue_zone_to": purdue_zone_to,
        "interfaces_created": 0,
        "zones_created": 0,
        "rules_created": 0,
        "approved_hosts_created": 0,
        "findings_created": 0,
        "hosts_created": 0,
        "unresolved_objects": 0,
        "fqdn_objects_in_policy": 0,   # count of FQDN/wildcard-FQDN objects found in policy
        "rules_disabled": 0,              # `set status disable` policies: stored with enabled=False
        "rules_skipped_negated_deny": 0,  # T1-21: deny policies with *-negate enable
        "rules_ipv6": 0,                  # F-07: policies that produced IPv6 rows
        "internet_service_refs": 0,       # F-15: ISDB destinations/sources ("internet-service:<name>")
        "internet_service6_refs": 0,      # N-25: IPv6 ISDB ("internet-service6:<name>")
        "rules_cross_family": 0,          # N-25: policy46 / policy64 rows (v4<->v6 translation)
        "central_snat_rules": 0,          # N-25: central-snat-map NatRule rows
        "vdoms": [],                      # N-24: VDOM names present in the config (multi-VDOM)
        "rules_skipped_unknown_action": 0,  # A-07: policy action not accept/deny/ipsec (not stored)
        "groups_over_limit": 0,           # A-02: addrgrp/service group too large / too deep
        "rules_over_limit": 0,            # A-02: policy src x dst x svc > MAX_RULE_ROWS
        "vip_refs_resolved": 0,           # F-05: policy dstaddr VIPs resolved to the mapped address
        "nat_rules_created": 0,           # F-05: NatRule rows (VIP dnat + policy snat)
        "findings_auto_resolved": 0,      # F-04: open config_review findings closed on re-ingest
        "blocks_rejected": 0,             # A-20: malformed blocks/values dropped
        "quote_recoveries": 0,            # C-03: stray unescaped quotes recovered at EOL
        "topology_state": "single",    # overwritten to "multi" when ≥ 2 FW rows
        "is_multi_fw": False,
    }

    # --- Pass 1: tokenize, then flatten global/vdom wrapping ---
    parsed_raw = parse_forti_block(text, stats=stats)
    _normalize_interfaces(parsed_raw)
    parsed = sanitize_forti_tree(flatten_global_vdom(parsed_raw, quiet=True), stats)

    # --- Extract device name from config if not passed explicitly ---
    hostname_cfg = parsed.get("system global", {}).get("hostname")
    config_hostname = hostname_cfg if isinstance(hostname_cfg, str) else None

    # Precedence: firewall_name arg > device_name arg > config hostname > fallback
    effective_device = (
        firewall_name
        or device_name
        or config_hostname
        or fallback_name            # D9: the upload's file name, after the hostname
        or "unknown-fortigate"
    )
    stats["device_name"] = effective_device

    # --- Pass 2: extract registries ---
    # Keep raw interfaces dict so _classify_interface can read FortiOS-native
    # fields (status, role) that _extract_zones() doesn't carry through.
    raw_interfaces: dict = parsed.get("system interface", {})
    zones = _extract_zones(parsed)
    # N-24: policies / objects / NAT are resolved PER VDOM so the same policy id
    # (or object name) in two VDOMs never collides; a config with no VDOM
    # wrapper is a single view with vdom None (the flat tree above).
    views = split_vdoms(parsed_raw)
    if len(views) == 1 and views[0][0] is None:
        views = [(None, parsed)]
    else:
        _scratch: dict = {}
        views = [(n, sanitize_forti_tree(t, _scratch)) for n, t in views]
    vdom_names = [n for n, _ in views if n is not None]
    stats["vdoms"] = list(vdom_names)
    policies: list = []
    fqdn_policy_findings: list = []
    nat_rows: list = []
    addr_objects: dict = {}           # (vdom, name) -> address object (Host rows)
    zone_defs: list = []              # B-07: zones per VDOM (FirewallZoneDef rows)
    # B-08: one row budget (IACS_MAX_RULE_ROWS_PER_INGEST) across every VDOM's
    # policies, charged per policy BEFORE its rows are built (_cap_rule).  Over
    # budget raises IngestLimitExceeded here - before any DB write.
    with rule_row_budget() as _budget:
        for vname, vtree in views:
            for zd in _extract_zone_defs(vtree, stats):
                zd["vdom"] = vname
                zone_defs.append(zd)
            v_addr, v_grp = _build_addr_registry(vtree)
            v_svc, v_svcgrp = _build_svc_registry(vtree)
            v_vips = _build_vip_registry(vtree)
            v_pol, v_fq = _extract_policies(
                vtree, zones, v_addr, v_grp, v_svc, v_svcgrp, stats=stats, vips=v_vips)
            for p in v_pol:
                p["vdom"] = vname
            for f in v_fq:
                f["vdom"] = vname
            policies += v_pol
            fqdn_policy_findings += v_fq
            nat_rows += _extract_nat(vtree, v_pol, v_vips, vdom=vname, stats=stats)
            for oname, ocfg in v_addr.items():
                addr_objects[(vname, oname)] = ocfg
            for oname, ocfg in vtree.get("firewall address6", {}).items():
                if isinstance(ocfg, dict):
                    addr_objects[(vname, "address6:" + str(oname))] = ocfg
        _n_rows = len(policies)
        if _n_rows > _budget.limit:
            raise IngestLimitExceeded("Firewall rule expansion (rows across all policies)",
                                      _n_rows, _budget.limit, RULE_ROWS_ENV)
    stats["zones_defined"] = len(zone_defs)
    # B-07: member interfaces carry their zone's name (FirewallZone rows)
    for zd in zone_defs:
        for m in zd["members"]:
            if m in zones:
                zones[m]["zone"] = zd["name"]
    stats["fqdn_objects_in_policy"] = len(fqdn_policy_findings)
    stats["vip_refs_resolved"] = len({
        (p.get("vdom"), p["policy_id"], v) for p in policies for v in p.get("vip_names") or []})

    # ----------------------------------------------------------------- Firewall row --
    # Create or update the Firewall record for this config upload.
    # Lookup is by name (operator-supplied label) so re-ingests update
    # the same row rather than creating a duplicate.
    now_utc = datetime.now(timezone.utc)
    fw_row = (db.query(Firewall)
              .filter(Firewall.site_id == sid, Firewall.name == effective_device).first())
    if fw_row:
        fw_row.device_name      = config_hostname or fw_row.device_name
        fw_row.source_file      = source_file or fw_row.source_file
        fw_row.config_uploaded_at = now_utc
        log.info("Updated existing Firewall row id=%d name=%r", fw_row.id, effective_device)
    else:
        fw_row = Firewall(
            site_id           = sid,
            name              = effective_device,
            device_name       = config_hostname,
            vendor            = "fortigate",
            source_file       = source_file,
            config_uploaded_at = now_utc,
        )
        db.add(fw_row)
        db.flush()   # populate fw_row.id
        log.info("Created Firewall row id=%d name=%r", fw_row.id, effective_device)

    stats["firewall_id"] = fw_row.id

    # --------------------------------------------------------- FirewallDevice row --
    # Get or create the Purdue-boundary device record.  This is always created
    # for FortiGate configs (every uploaded config has a name), with the Purdue
    # boundary set when the caller passes purdue_zone_from / purdue_zone_to.
    fw_device_row = get_or_create_firewall_device(
        db,
        name=effective_device,
        vendor="fortigate",
        device_hostname=config_hostname,
        source_file=source_file,
        purdue_zone_from=purdue_zone_from,
        purdue_zone_to=purdue_zone_to,
    )
    # Keep the richer Firewall FK in sync (links multi-FW topology to device)
    if fw_device_row.firewall_id is None:
        fw_device_row.firewall_id = fw_row.id
    stats["firewall_device_id"] = fw_device_row.id
    fw_device_id = fw_device_row.id

    # --------------------------------------------------------- FirewallInterface rows --
    # Interfaces a policy reads or writes (directly, or via a zone's members)
    # carry routed traffic: they are never "management-only" on allowaccess alone.
    _zone_members = {str(zd["name"]).strip().lower(): [str(m).strip().lower() for m in zd["members"]]
                     for zd in zone_defs}
    _policy_ifaces: set = set()
    for _p in policies:
        for _n in list(_p.get("srcintf_list") or []) + list(_p.get("dstintf_list") or []):
            _n = str(_n).strip().lower()
            if _n and _n != "any":
                _policy_ifaces.add(_n)
                _policy_ifaces.update(_zone_members.get(_n, ()))
    _dialup = frozenset(dialup_ipsec_names(views))
    stats["dialup_ipsec_tunnels"] = sorted(_dialup)
    # RS: the interface that carries the default route faces the Internet;
    # with no FortiOS `set role` it is recorded as role "wan"
    _tun_all = extract_tunnels(parsed)           # once per ingest: interfaces, context, evidence
    stats["interfaces_created"] = _upsert_firewall_interfaces(
        db, fw_row, zones, raw_interfaces, policy_interfaces=_policy_ifaces, dialup=_dialup,
        default_route_devices=frozenset(default_route_devices(parsed)), tunnels=_tun_all,
    )
    # owner 2026-10-19: FortiLink-managed FortiSwitches -> switch rows (never fails the ingest)
    try:
        from app.parsers.fortiswitch_parser import ingest_fortilink_switches
        stats["fortilink"] = ingest_fortilink_switches(db, parsed, fw_row, source_file)
    except Exception:                                   # noqa: BLE001
        log.exception("FortiLink switch pass failed for firewall %s", fw_row.id)
        stats["fortilink"] = {"error": "FortiLink switch pass failed; see the server log"}
    # Admin trusted hosts, kept for the management-network trusthost check
    # (re-judged when management networks are declared; a config without a
    # `config system admin` section keeps the previous list).
    if parsed.get("system admin"):
        fw_row.admin_trusthosts = _extract_admin_trusted_hosts(parsed)
    # Interfaces the operator declared NOT a management zone stay routed.
    from app.parsers.mgmt_networks import apply_mgmt_only_overrides as _mgmt_only
    db.flush()
    _mgmt_only(db, fw_row.id)
    db.flush()
    # B-15(a): interfaces no longer in the config are removed (same scope as
    # the policy rows: the whole firewall for a flat config / full backup,
    # else only interfaces of the VDOMs present).  A config without any
    # `config system interface` section removes nothing.
    _full_backup = isinstance(parsed_raw.get("global"), dict)
    _iface_vdom_scope = None if (not vdom_names or _full_backup) else set(vdom_names)
    removed_ifaces = []
    if isinstance(raw_interfaces, dict) and raw_interfaces:
        removed_ifaces = _prune_removed_interfaces(db, fw_row, set(zones), _iface_vdom_scope)
    stats["interfaces_removed"] = len(removed_ifaces)

    # ---- Option 2: infer multi-firewall mode from count ----
    # If this brings the total to ≥ 2, flip is_multi_fw on every Firewall row.
    fw_count = db.query(Firewall).filter(Firewall.site_id == sid).count()
    if fw_count >= 2:
        db.query(Firewall).filter(Firewall.site_id == sid).update(
            {"is_multi_fw": True}, synchronize_session="fetch")
        stats["topology_state"] = "multi"
        stats["is_multi_fw"] = True
        log.info(
            "Multi-FW mode activated (%d firewalls); is_multi_fw=True set on all rows.",
            fw_count,
        )

    # Link FirewallRule rows to this Firewall (applied below when persisting rules)
    fw_id = fw_row.id

    # --- Persist zones (legacy FirewallZone — backward compat) ---
    # B-15(a): rows of removed interfaces go too (full scope: every row of
    # this device whose interface is no longer in the config).
    _fz_stale = db.query(FirewallZone).filter(
        FirewallZone.site_id == sid, FirewallZone.device_name == effective_device)
    if removed_ifaces:
        _fz_stale.filter(FirewallZone.interface_name.in_(removed_ifaces)) \
            .delete(synchronize_session="fetch")
    if isinstance(raw_interfaces, dict) and raw_interfaces and _iface_vdom_scope is None:
        _fz_stale.filter(FirewallZone.interface_name.notin_(list(zones))) \
            .delete(synchronize_session="fetch")
    for iface_name, zone_data in zones.items():
        existing = db.query(FirewallZone).filter(
            FirewallZone.site_id == sid,
            FirewallZone.device_name == effective_device,
            FirewallZone.interface_name == iface_name,
        ).first()
        if existing:
            # Update in place so re-ingest reflects config changes
            existing.zone_name      = zone_data["zone"]
            existing.ip_cidr        = zone_data["ip"]
            existing.vlan_id        = zone_data.get("vlan_id")
            existing.interface_type = zone_data.get("type")
            existing.source_file    = source_file
        else:
            db.add(FirewallZone(
                site_id=sid,
                device_name=effective_device,
                interface_name=iface_name,
                zone_name=zone_data["zone"],
                ip_cidr=zone_data["ip"],
                vlan_id=zone_data.get("vlan_id"),
                interface_type=zone_data.get("type"),
                source_file=source_file,
            ))
            stats["zones_created"] += 1

    # --- Persist firewall rules ---
    # Delete existing rules scoped to THIS firewall row (by PK, not device_name)
    # to avoid cross-deleting rules from a different FW that happens to share the
    # same effective device name (e.g. two configs both missing "set hostname").
    # N-24: replace per (firewall, vdom): a flat config replaces everything of
    # this firewall; a VDOM-wrapped config replaces the VDOMs it contains plus
    # NULL-vdom (pre-VDOM) rows - and, being a full backup when it carries
    # `config global`, every other VDOM of the firewall too.
    def _replace_scope(model):
        q = db.query(model).filter(model.firewall_id == fw_id)
        if vdom_names and not _full_backup:
            q = q.filter(or_(model.vdom.is_(None), model.vdom.in_(vdom_names)))
        return q

    # AU full review D1: the approved-rules baseline writes owner / conduit onto
    # the rule rows and the engine stamps last_matched; a re-ingest of the
    # config replaced the rows and lost all three.  Snapshot per (vdom,
    # policy id) and re-apply (the config's own comment still wins for owner).
    _carry: dict = {}
    for _r in _replace_scope(FirewallRule).with_entities(
            FirewallRule.vdom, FirewallRule.policy_id, FirewallRule.owner,
            FirewallRule.conduit, FirewallRule.last_matched):
        if _r.owner or _r.conduit or _r.last_matched:
            _k = (_r.vdom, str(_r.policy_id))
            _prev = _carry.get(_k, (None, None, None))
            _carry[_k] = (_r.owner or _prev[0], _r.conduit or _prev[1],
                          max(filter(None, (_r.last_matched, _prev[2])), default=None))
    stats["rules_carried"] = len(_carry)
    _replace_scope(FirewallRule).delete(synchronize_session="fetch")

    # --- B-07: zone definitions (members per VDOM), replaced like the rules ---
    _replace_scope(FirewallZoneDef).delete(synchronize_session="fetch")
    for zd in zone_defs:
        db.add(FirewallZoneDef(
            firewall_id=fw_id, vdom=zd.get("vdom"), name=str(zd["name"])[:128],
            kind=zd["kind"], intrazone=zd.get("intrazone"),
            members=list(zd["members"]), members_resolved=bool(zd["members_resolved"]),
            source_file=source_file,
        ))

    for rule in policies:
        if any(
            str(v or "").startswith(("unresolved:", "cycle:", "fqdn:", "range:",
                                     "internet-service:", "internet-service6:"))
            for v in [rule["src"], rule["dst"], rule.get("dst_port")]
        ):
            stats["unresolved_objects"] += 1

        # rule_order = the policy's position in the config (FortiOS is
        # first-match-wins in config order; policy IDs are NOT sequence
        # numbers once `move` has been used). Rows expanded from one policy
        # share the value. policy_id keeps the original ID for display.
        _pid_str = rule.get("policy_id")
        _rule_order = rule.get("rule_order")
        _raw = f"policy {rule['policy_id']} {rule.get('policy_name') or ''}".rstrip()
        for _n in rule.get("notes") or []:
            _raw += f" [{_n}]"
        if rule.get("vdom") is not None:
            _raw += f" [vdom {rule['vdom']}]"
        _prev = _carry.get((rule.get("vdom"), str(_pid_str)), (None, None, None))

        db.add(FirewallRule(
            device_name=effective_device,
            device_type="fortigate",
            source_file=source_file,
            firewall_id=fw_id,
            firewall_device_id=fw_device_id,
            policy_id=_pid_str,
            vdom=rule.get("vdom"),
            policy_name=rule.get("policy_name"),
            src_zone=rule.get("src_zone"),
            dst_zone=rule.get("dst_zone"),
            rule_order=_rule_order,
            src=rule["src"],
            dst=rule["dst"],
            protocol=rule["protocol"],
            dst_port=str(rule["dst_port"]) if rule["dst_port"] else "any",
            action=rule["action"],
            raw_line=_raw,
            owner=rule.get("owner") or _prev[0],
            conduit=_prev[1],
            last_matched=_prev[2],
            enabled=rule.get("enabled", True),
            src_identity=rule.get("src_identity"),
        ))
        stats["rules_created"] += 1
        if stats["rules_created"] % _RULE_FLUSH_EVERY == 0:
            db.flush()      # B-08: flushed rows drop out of memory (weak identity map)

    # --- Persist NAT (F-05): replaced per Firewall row, like the rules ---
    _replace_scope(NatRule).delete(synchronize_session="fetch")
    for nat in nat_rows:
        db.add(NatRule(
            firewall_id=fw_id,
            firewall_device_id=fw_device_id,
            device_name=effective_device,
            device_type="fortigate",
            nat_type=nat["nat_type"],
            name=(nat.get("name") or None) and str(nat["name"])[:255],
            policy_id=nat.get("policy_id"),
            protocol=(nat.get("protocol") or "any")[:16],
            src_intf=(nat.get("src_intf") or None) and str(nat["src_intf"]),
            orig_src=nat.get("orig_src"),
            ext_ip=nat.get("ext_ip"),
            ext_port=nat.get("ext_port"),
            mapped_ip=nat.get("mapped_ip"),
            mapped_port=nat.get("mapped_port"),
            orig_port=nat.get("orig_port"),
            enabled=nat.get("enabled", True),
            source_file=source_file,
            raw=nat.get("raw"),
            nat_kind=nat.get("nat_kind"),
            dst_intf=(nat.get("dst_intf") or None) and str(nat["dst_intf"]),
            orig_dst=nat.get("orig_dst"),
            vdom=nat.get("vdom"),
            sequence=nat.get("sequence"),
            nat_exempt=bool(nat.get("nat_exempt", False)),
        ))
        stats["nat_rules_created"] += 1
        if nat.get("nat_kind") == "central-snat":
            stats["central_snat_rules"] += 1

    # --- Persist concrete address objects as Hosts ---
    # B-24: only valid unicast single-host objects (/32, /128, or a
    # one-address iprange) become Hosts; invalid, unspecified, multicast,
    # broadcast and loopback addresses are skipped (never raises).
    _seen_host_ips: set = set()
    for (_obj_vdom, obj_name), obj_cfg in addr_objects.items():
        ip = _address_object_host_ip(obj_cfg)
        if ip is None or ip in _seen_host_ips:
            continue
        _seen_host_ips.add(ip)
        before_count = db.query(Host).filter(Host.site_id == sid, Host.ip == ip,
                                            Host.mac.is_(None)).count()
        host = get_or_create_host(db, ip=ip, mac=None, source="fortigate_config")
        if host and before_count == 0:
            stats["hosts_created"] += 1
        if host is not None:
            # owner 2026-10-19: the object's name names the host (hostname when none is known) and may
            # say what it is - a suggestion that never beats a stronger classification
            from app.parsers.device_classification import classify_object_name, _source_rank
            oname = str(obj_name).strip('"')
            if not host.hostname and oname and not oname.replace(".", "").replace("/", "").replace("-", "").isdigit():
                host.hostname = oname[:255]
            # a public address is an external service whatever its name says ("Google_DNS1" is
            # not the site's DNS server, "plants_jumphost" on a cloud address is not a plant host)
            try:
                _public = ipaddress.ip_address(ip).is_global
            except ValueError:
                _public = True
            dtype, role = (None, None) if _public else classify_object_name(oname)
            if dtype and host.device_type != dtype \
                    and (host.device_type is None or _source_rank(host.classification_source) <= _source_rank("object_name")) \
                    and host.classification_source not in ("manual", "subnet_declared"):
                host.device_type, host.classification_source = dtype, "object_name"
            if role and not host.role:
                host.role, host.role_source = role, "object_name"

    # --- Optional: admin trusted hosts -> ApprovedHost (off by default) ---
    if populate_approved_hosts:
        admin_info = _extract_admin_trusted_hosts(parsed)
        for admin in admin_info:
            for th_cidr in admin["trusted_hosts"]:
                existing = db.query(ApprovedHost).filter(
                    ApprovedHost.baseline_id == baseline_id,
                    ApprovedHost.ip == th_cidr,
                    ApprovedHost.role == "admin_ws",
                ).first()
                if not existing:
                    db.add(ApprovedHost(
                        baseline_id=baseline_id,
                        ip=th_cidr,
                        role="admin_ws",
                        owner=admin["username"],
                        notes=f"FortiGate admin trusted-host for {admin['username']} "
                              f"(profile: {admin.get('accprofile', 'unknown')})",
                    ))
                    stats["approved_hosts_created"] += 1

    # --- Optional: config-level findings (off by default) ---
    if generate_findings:
        produced_refs: set = set()
        # A-21: findings created in THIS ingest, by source_ref. autoflush is
        # off, so _find_existing cannot see them - dedup in memory instead,
        # otherwise two checks producing one source_ref insert twice and the
        # UNIQUE constraint aborts the whole upload.
        created_refs: dict = {}

        def _lookup(ref):
            return created_refs.get(ref) or _find_existing(db, ref)

        # VD-04: the VPN policies come from the per-VDOM views (the merged
        # view keeps one policy per id, so an id reused in another VDOM
        # would hide the VPN policy); settings / portals from the merged view.
        vpn_settings = _extract_vpn_settings(parsed)
        if len(views) > 1:
            seen_vp: set = set()
            vpn_settings["vpn_firewall_policies"] = []
            for vname, vtree in views:
                for vp in _extract_vpn_settings(vtree)["vpn_firewall_policies"]:
                    key = (vname, vp["policy_id"])
                    if key not in seen_vp:
                        seen_vp.add(key)
                        vpn_settings["vpn_firewall_policies"].append({**vp, "vdom": vname})
        dns_ntp = _extract_dns_ntp(parsed)
        admin_info_for_findings = _extract_admin_trusted_hosts(parsed)

        # Original 6 checks (logging, any-any, DPI, VPN source, DNS, NTP)
        # Disabled policies enforce nothing: keep them out of every config
        # check (they are flagged separately by review_disabled_rules).
        # N-24: policy-keyed finding refs (source_ref, per-policy dedup inside the
        # checks) must stay distinct per VDOM -> "<vdom>/<id>" in multi-VDOM configs.
        active_policies = [
            ({**p, "policy_id": f"{p['vdom']}/{p['policy_id']}"} if p.get("vdom") is not None else p)
            for p in policies if p.get("enabled", True)]
        # owner 2026-10-12: FortiGuard DNS / NTP severity depends on the
        # firewall having an Internet leg and on FQDN objects in permit rules
        _wan = set(default_route_devices(parsed))
        for _in, _ic in (parsed.get("system interface") or {}).items():
            if isinstance(_ic, dict) and str(_ic.get("role") or "").strip().lower() == "wan":
                _wan.add(str(_in).strip().lower())
        _fqdn_pols = sorted({str(p["policy_id"]) for p in active_policies
                             if p.get("action") == "permit"
                             and any(str(p.get(k) or "").startswith(("fqdn:", "wildcard-fqdn:")) for k in ("src", "dst"))},
                            key=lambda x: (len(x), x))
        # operator labels survive a re-ingest: interfaces labelled L0-L2 = OT
        _ot_ifaces = sorted(str(n).lower() for (n,) in db.query(FirewallInterface.name).filter(
            FirewallInterface.firewall_id == fw_id, FirewallInterface.purdue_level.isnot(None),
            FirewallInterface.purdue_level <= 2))
        # owner 2026-10-19: where an address sits - the interface networks (with the operator's level) and
        # the networks static routes reach - so NTP / DNS sources can be called local, routed or external
        _levels = {str(n).lower(): lv for n, lv in db.query(FirewallInterface.name, FirewallInterface.purdue_level)
                   .filter(FirewallInterface.firewall_id == fw_id)}
        _local_nets = []
        for _in, _zd in zones.items():
            if _zd.get("ip"):
                try:
                    _local_nets.append((str(ipaddress.ip_interface(_zd["ip"]).network), str(_in), _levels.get(str(_in).lower())))
                except ValueError:
                    pass
        _tunnels = {str(n).strip('"').lower() for n in (parsed.get("vpn ipsec phase1-interface") or {})}
        _tunnels |= {str(n).lower() for n, c in (parsed.get("system interface") or {}).items()
                     if isinstance(c, dict) and str(c.get("type", "")).lower() == "tunnel"}
        _routed_nets = []            # (cidr, device) - owner 2026-10-19: a tunnel device means a remote site
        for _rc in (parsed.get("router static") or {}).values():
            if isinstance(_rc, dict) and _rc.get("dst"):
                _raw = _rc.get("dst")
                _raw = " ".join(str(x) for x in _raw) if isinstance(_raw, (list, tuple)) else str(_raw)
                _parts = _raw.replace("/", " ").split()
                _dev = _rc.get("device")
                _dev = str(_dev[0] if isinstance(_dev, (list, tuple)) and _dev else (_dev or "")).strip('"')
                try:
                    _n = ipaddress.ip_network(f"{_parts[0]}/{_parts[1]}" if len(_parts) > 1 else _parts[0], strict=False)
                    if _n.prefixlen and str(_rc.get("blackhole", "disable")).lower() != "enable":
                        _routed_nets.append((str(_n), _dev))
                except (ValueError, IndexError):
                    pass
        _cfg_ctx = {"has_wan": bool(_wan), "wan_interfaces": sorted(_wan), "ot_interfaces": _ot_ifaces,
                    "local_nets": _local_nets, "routed_nets": _routed_nets, "iface_levels": _levels,
                    "tunnel_interfaces": sorted(_tunnels), "dialup_tunnels": sorted(_dialup),
                    "tunnel_nets": _tunnel_nets(parsed, _tun_all), "tunnels": _tun_all,
                    "dos_policies": (parsed.get("firewall DoS-policy") or {}),
                    "boundary_into_ot": purdue_zone_to is not None and purdue_zone_to <= 2,
                    "fqdn_permit_policies": _fqdn_pols,
                    "fqdn_into_ot": purdue_zone_to is not None and purdue_zone_to <= 2}
        config_findings = _config_findings(
            active_policies, zones, vpn_settings, dns_ntp, effective_device, ctx=_cfg_ctx,
        )
        # 30 new hardening checks (zone architecture, ruleset, remote access,
        # admin hardening, logging, availability, NIST/CIS additions)
        hardening = _hardening_findings(
            parsed, active_policies, zones, vpn_settings, dns_ntp,
            admin_info_for_findings, effective_device, ctx=_cfg_ctx,
        )

        # VD-08: one policy label everywhere - "<id> (vdom <name>)" as in the
        # reviews, paths and shadow analysis; the "<vdom>/<id>" form stays
        # the KEY (source_ref, detail.policy_id) of multi-VDOM findings.
        if len(views) > 1:
            _labels = sorted({p["policy_id"] for p in active_policies if "/" in str(p.get("policy_id", ""))},
                             key=len, reverse=True)
            for f_data in config_findings + hardening:
                t = f_data.get("title") or ""
                for lab in _labels:
                    if lab in t:
                        vd, _, pid = lab.partition("/")
                        t = t.replace(lab, f"{pid} (vdom {vd})")
                f_data["title"] = t
        for f_data in config_findings + hardening:
            check_name = f_data.get("check_name") or f_data["category"]
            # A-7: policy-scoped findings include a "policy_id" in their detail dict.
            # Without it in the source_ref every policy finding for the same check
            # collapses to a single DB row, silently dropping all but the first.
            # Per-interface / per-trusthost checks are distinct findings too
            # (one finding per interface, not the last interface of the run).
            _d = f_data.get("detail") or {}
            _pid = (_d.get("ref_key") or _d.get("policy_id") or _d.get("vpn_policy_id") or _d.get("interface")
                    or (f"{_d['username']}:{_d['trusthost']}"
                        if _d.get("username") and _d.get("trusthost") else None))
            source_ref = (
                f"config:{fw_id}:{check_name}:{_pid}"
                if _pid
                else f"config:{fw_id}:{check_name}"
            )
            produced_refs.add(source_ref)
            existing_finding = _lookup(source_ref)
            if existing_finding:
                # Update severity/detail in case config changed, keep status/timestamps
                existing_finding.severity = f_data["severity"]
                existing_finding.detail = f_data["detail"]
                existing_finding.title = f_data["title"]
                existing_finding.checklist_id = f_data["checklist_id"]
                existing_finding.isa62443_sr = f_data["isa62443_sr"]
            else:
                created_refs[source_ref] = _new = Finding(
                    source_ref=source_ref,
                    category=f_data["category"],
                    check_name=check_name,
                    severity=f_data["severity"],
                    status=f_data["status"],
                    isa62443_sr=f_data["isa62443_sr"],
                    checklist_id=f_data["checklist_id"],
                    title=f_data["title"],
                    detail=f_data["detail"],
                    device_name=f_data["device_name"],
                    created_at=f_data["created_at"],
                )
                db.add(_new)
                stats["findings_created"] += 1

        # --- 3.10: FQDN / wildcard-FQDN objects in policy ---
        # One finding per unique (policy_id, field, fqdn_value) so that a
        # policy with three FQDN src objects generates three distinct findings
        # rather than one, allowing each to be individually acknowledged.
        # Dedup key includes fw_id so re-ingest updates rather than duplicates.
        #
        # Severity escalation for OT/ICS boundaries:
        #   purdue_zone_to in {0, 1, 2}  →  critical   (field devices / basic control / supervisory)
        #   wildcard-FQDN (any level)    →  high
        #   FQDN (IT boundary or unset)  →  CHECK_TYPE_REFERENCE default (_fqdn_sev)
        # An FQDN at a Purdue ≤2 boundary is critical regardless of wildcard status
        # because DNS is not available inside most OT cell/area networks and any
        # DNS dependency at that boundary represents an architectural control failure.
        from app.models import CHECK_TYPE_REFERENCE as _CTR
        _fqdn_sr, _fqdn_cid, _fqdn_sev, _fqdn_cat = _CTR["fqdn_in_policy"]
        _now = datetime.now(timezone.utc)
        _ot_boundary = purdue_zone_to is not None and purdue_zone_to <= 2
        # DR-02: one finding per POLICY (it lists every FQDN object it uses);
        # one per object made 41 findings for 11 policies on a real config.
        _fq_by_pid: dict = {}
        for ff in fqdn_policy_findings:
            pid = ff["policy_id"]
            if ff.get("vdom") is not None:
                pid = f"{ff['vdom']}/{pid}"
            ent = _fq_by_pid.setdefault(pid, {"policy_name": ff.get("policy_name"), "objects": [],
                                              "raw_pid": ff["policy_id"], "vdom": ff.get("vdom")})
            obj = {"field": ff["field"], "object_name": ff.get("object_name"),
                   "fqdn_value": ff["fqdn_value"], "obj_type": ff["obj_type"]}
            if obj not in ent["objects"]:
                ent["objects"].append(obj)
        for pid, ent in _fq_by_pid.items():
            objs = ent["objects"]
            pname = ent["policy_name"] or "unnamed"
            source_ref = f"fqdn_policy:{fw_id}:{pid}"
            is_wildcard = any(o["obj_type"] == "wildcard-fqdn" for o in objs)
            if _ot_boundary:
                severity = "critical"
            elif is_wildcard:
                severity = "high"
            else:
                severity = _fqdn_sev
            fields = sorted({o["field"] for o in objs})
            values = [o["fqdn_value"] for o in objs]
            shown = ", ".join(repr(v) for v in values[:3]) + (f" +{len(values) - 3} more" if len(values) > 3 else "")
            title = (
                f"{'Wildcard-FQDN' if is_wildcard else 'FQDN'} object{'s' if len(objs) > 1 else ''} in "
                f"policy {pid} ({pname}) {'/'.join(fields)} on {effective_device}: {shown}"
                + (f" [Purdue {fmt_level(purdue_zone_to)} boundary]" if _ot_boundary else "")
            )[:512]
            _purdue_ctx = (
                f" This firewall protects a Purdue Level {purdue_zone_to} "
                f"({'field devices' if purdue_zone_to == 0 else 'basic control (PLC/RTU)' if purdue_zone_to == 1 else 'supervisory control / HMI'}) "
                f"boundary. DNS resolution is typically unavailable inside OT cell/area "
                f"networks, making FQDN-based ACLs an unreliable control at this level. "
                if _ot_boundary else ""
            )
            detail_desc = (
                f"Policy {pid} ({pname}) on {effective_device} references "
                f"{len(objs)} FQDN address object{'s' if len(objs) > 1 else ''} "
                f"({', '.join(repr(v) for v in values)}) in its {' and '.join(fields)} field. "
                f"The addresses behind a name are decided by DNS at run time, so the rule "
                f"cannot be audited statically: it is kept as an external destination "
                f"(reachability answers 'unknown' for a concrete address) and its "
                f"effective scope changes whenever the DNS answer does. "
                + (
                    "Wildcard-FQDN objects (*.domain) can match any sub-domain - the "
                    "effective scope of this rule is unbounded. " if is_wildcard else ""
                )
                + _purdue_ctx
                + "Where the service has fixed addresses, use concrete address objects; "
                  "otherwise document the dependency and restrict the service and source."
            )
            detail = {"description": detail_desc, "purdue_zone_to": purdue_zone_to,
                      "policy_id": ent["raw_pid"], "vdom": ent["vdom"],
                      "policy_name": ent["policy_name"], "objects": objs,
                      "fqdn_value": values[0], "obj_type": "wildcard-fqdn" if is_wildcard else "fqdn"}
            produced_refs.add(source_ref)
            existing_fqdn = _lookup(source_ref)
            if existing_fqdn:
                if existing_fqdn.status == "closed":
                    existing_fqdn.status = "open"
                existing_fqdn.severity = severity
                existing_fqdn.checklist_id = _fqdn_cid      # rows can move (owner 2026-10-12)
                existing_fqdn.isa62443_sr = _fqdn_sr
                existing_fqdn.updated_at = _now
                existing_fqdn.title = title
                existing_fqdn.detail = detail
                continue
            created_refs[source_ref] = _new = Finding(
                source_ref=source_ref,
                category=_fqdn_cat,
                check_name="fqdn_in_policy",
                severity=severity,
                status="open",
                isa62443_sr=_fqdn_sr,
                checklist_id=_fqdn_cid,
                title=title,
                detail=detail,
                device_name=effective_device,
                created_at=_now,
                updated_at=_now,
            )
            db.add(_new)
            stats["findings_created"] += 1

        # --- Management config checks (5.1 zone restriction, 9.5 trusthost in
        # the declared management networks): judged from the stored interfaces
        # and trusted hosts against the site's declarations ---
        db.flush()
        from app.parsers.mgmt_networks import review_config_firewall as _mgmt_cfg
        produced_refs |= _mgmt_cfg(db, fw_id)
        # Report PASS / evidence (owner 2026-10-12): this firewall's config checks
        # were evaluated now; keep the settings they examined.
        try:
            from app.check_evaluations import FORTIGATE_CONFIG, record as _record_eval
            _record_eval(db, fw_row.site_id, FORTIGATE_CONFIG, scope=f"fw:{fw_id}", source="fortigate_config",
                         evidence={"device": effective_device, "firewall": fw_row.name,
                                   "sections": _config_evidence(parsed, active_policies, dns_ntp,
                                                                admin_info_for_findings, _cfg_ctx)})
        except Exception:                                   # noqa: BLE001 - evidence must not fail the upload
            log.warning("config evidence for firewall %s not recorded", fw_id, exc_info=True)

        # --- F-04: close open config_review findings this ingest no longer
        # produces (acknowledged findings are never touched) ---
        if _auto_resolve_enabled():
            db.flush()
            stats["findings_auto_resolved"] = _auto_resolve_findings(
                db, fw_id, produced_refs, source_file)

    db.commit()
    return stats


_AUTO_RESOLVE_PREFIX = "Auto-resolved: not present in config re-ingest"


def _auto_resolve_enabled() -> bool:
    """IACS_AUTO_RESOLVE (default true) - set 0/false/no/off to disable."""
    import os
    return os.environ.get("IACS_AUTO_RESOLVE", "true").strip().lower() not in (
        "0", "false", "no", "off")


def _find_existing(db: DBSession, source_ref: str) -> Optional[Finding]:
    """
    The finding to update for a re-produced config check: an open or
    acknowledged one first; else a closed one. A finding closed by F-04
    auto-resolve is re-opened when its condition comes back (a human-closed
    one keeps its status, as before).
    """
    from app.sites import scope_site_id as _scope
    rows = db.query(Finding).filter(Finding.site_id == _scope(db),
                                    Finding.source_ref == source_ref).order_by(
        Finding.id.desc()).all()
    for f in rows:
        if f.status in ACTIVE_FINDING_STATUSES:
            return f
    for f in rows:
        if f.status == "closed" and (f.notes or "").startswith(_AUTO_RESOLVE_PREFIX):
            f.status = "open"
            f.closed_at = None
            f.acknowledged_by = None   # B-16 parity: re-opened = nobody's yet
            f.acknowledged_at = None
            f.notes = None
            return f
    return rows[0] if rows else None


def _auto_resolve_findings(db: DBSession, fw_id: int, produced_refs: set,
                           source_file: Optional[str]) -> int:
    """Close OPEN config_review findings of this firewall (source_ref
    config:<fw_id>:... / fqdn_policy:<fw_id>:...) that the current ingest
    did not re-produce. Returns the number closed."""
    now = datetime.now(timezone.utc)
    q = db.query(Finding).filter(
        Finding.site_id == scope_site_id(db),
        Finding.category == "config_review",
        Finding.status == "open",
        (Finding.source_ref.like(f"config:{fw_id}:%")
         | Finding.source_ref.like(f"fqdn_policy:{fw_id}:%")),
    )
    closed = 0
    for f in q.all():
        if f.source_ref in produced_refs:
            continue
        f.status = "closed"
        f.closed_at = now
        f.notes = f"{_AUTO_RESOLVE_PREFIX} {source_file or 'upload'}"
        closed += 1
    return closed
