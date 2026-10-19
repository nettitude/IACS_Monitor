"""
Asset Inventory CSV: column mapping (owner request 2026-10-11).

An inventory export names its columns its own way ("IP_Address", "Host Name",
"Asset Type").  This module maps CSV columns to the application's fields:

* ``suggest_columns`` proposes a field per column - the saved mapping of the
  site first, then the field name itself, then a known alias, then a guess
  from the header words or from the values (a column of addresses);
* ``validate_column_map`` checks an operator-chosen mapping;
* ``preview`` reads the whole file against a mapping, without writing
  anything, and lists what the import would do and what it would reject.

Pure functions - no database access.  A column map is
``{column key: field or ""}``; the column key is the header as the CSV reader
keys rows (stripped, lower case); ``""`` = ignore the column.

Only the ``exact`` and ``alias`` tiers are applied when an upload carries no
mapping (the Upload page): a ``guess`` or a ``values`` suggestion is shown in
the preview for the operator to confirm, never applied silently.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from collections import Counter
from typing import Optional

# (field, label, hint) - the order of the picker
ASSET_FIELDS = [
    ("ip", "IP address", "IPv4 or IPv6 address. IP or MAC is required."),
    ("mac", "MAC address", "Any common notation. IP or MAC is required."),
    ("hostname", "Host name", "Free text."),
    ("device_type", "Device type", "One of the application's device types (plc, hmi, "
                                   "engineering_workstation ...); sets a manual classification."),
    ("purdue_level", "Purdue level", "0-5, 3.5 / L3.5 / dmz; sets a manual classification."),
    ("vlan", "VLAN", "VLAN id or name."),
    ("zone", "IEC 62443 zone", "Zone name on Zones & Conduits (created when missing)."),
    ("sl_c", "SL-C", "IEC 62443-4-2 capability security level 0-4 (SL0 - No Requirements ... SL4)."),
    ("sl_c_source", "SL-C source", "Certificate, vendor statement or assessment."),
]
FIELD_NAMES = [f for f, _l, _h in ASSET_FIELDS]
FIELD_LABELS = {f: l for f, l, _h in ASSET_FIELDS}
IDENTITY_FIELDS = ("ip", "mac")

# Alias tier: header names that mean exactly this field.  Applied
# automatically.  Kept free of words that mean something else in other
# inventories ("role", "category", "address", "device", "asset", "tag").
_ALIASES = {
    "ip": ["ip", "ip address", "ipaddress", "ip addr", "ipv4", "ipv4 address", "ipv6 address",
           "host ip", "device ip", "primary ip", "management ip", "mgmt ip", "ip adresse"],
    "mac": ["mac", "mac address", "macaddress", "mac addr", "physical address", "hardware address",
            "hw address", "ethernet address", "mac adresse"],
    "hostname": ["hostname", "host name", "name", "device name", "asset name", "dns name",
                 "computer name", "system name"],
    "device_type": ["device type", "devicetype", "type", "asset type", "device class",
                    "asset class", "device category", "asset category"],
    "purdue_level": ["purdue level", "purduelevel", "level", "purdue", "isa95 level",
                     "isa 95 level", "purdue zone level"],
    "vlan": ["vlan", "vlan id", "vlanid", "vlan number", "vlan name"],
    "zone": ["zone", "iec zone", "security zone", "zone name", "62443 zone", "iec 62443 zone",
             "iec62443 zone"],
    "sl_c": ["sl c", "slc", "capability sl", "security level capability", "sl capability",
             "capability security level"],
    "sl_c_source": ["sl c source", "slc source", "sl capability source", "capability source"],
}

# Guess tier: header words that probably mean the field (shown, not applied).
_GUESS_WORDS = [
    ("mac", {"mac"}),
    ("ip", {"ip", "ipv4", "ipv6", "address", "addr"}),
    ("vlan", {"vlan"}),
    ("purdue_level", {"purdue", "level"}),
    ("sl_c_source", {"capability", "source"}),
    ("sl_c", {"capability", "sl", "slc"}),
    ("zone", {"zone", "segment", "area", "cell"}),
    ("device_type", {"type", "role", "category", "class", "function", "model"}),
    ("hostname", {"name", "host", "device", "asset", "tag"}),
]

_SEP = re.compile(r"[\s_\-./():#]+")


def norm_header(header: str) -> str:
    """'IP_Address' / 'ip-address' / ' IP Address ' -> 'ip address'."""
    return _SEP.sub(" ", (header or "").replace("﻿", "").strip().lower()).strip()


def column_key(header: str) -> str:
    """The key the CSV reader uses for a column (baseline_parser._read_csv)."""
    return (header or "").replace("﻿", "").strip().lower()


_ALIAS_INDEX = {norm_header(a): f for f, names in _ALIASES.items() for a in names}
for _f in FIELD_NAMES:
    _ALIAS_INDEX.setdefault(norm_header(_f), _f)


def _tier(header: str) -> tuple[Optional[str], Optional[str]]:
    """(field, basis) from the header alone: exact, alias, guess or nothing."""
    n = norm_header(header)
    if not n:
        return None, None
    exact = {norm_header(f): f for f in FIELD_NAMES}
    if n in exact:
        return exact[n], "exact"
    if n in _ALIAS_INDEX:
        return _ALIAS_INDEX[n], "alias"
    words = set(n.split())
    for field, hints in _GUESS_WORDS:
        if words & hints:
            if field == "sl_c" and not ({"sl", "slc"} & words):
                continue
            if field == "sl_c_source" and not ({"capability", "sl", "slc"} & words and "source" in words):
                continue
            return field, "guess"
    return None, None


def _looks_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.split("%")[0].strip())
        return True
    except ValueError:
        return False


_MAC_RE = re.compile(r"^([0-9a-f]{2}([:\-]?)){5}[0-9a-f]{2}$|^([0-9a-f]{4}\.){2}[0-9a-f]{4}$", re.I)


def _looks_mac(v: str) -> bool:
    return bool(_MAC_RE.match(v.strip()))


def _values_field(values: list[str]) -> Optional[str]:
    """A column whose non-empty sample values are all addresses."""
    vals = [v for v in values if v and v.strip()][:50]
    if len(vals) < 1:
        return None
    if all(_looks_ip(v) for v in vals):
        return "ip"
    if all(_looks_mac(v) for v in vals):
        return "mac"
    return None


def read_table(csv_text: str) -> tuple[list[str], list[list[str]]]:
    """(original headers, data rows) with blank rows dropped and the BOM
    stripped.  Raises csv.Error (clear message) for text that is not CSV."""
    text = (csv_text or "").lstrip("﻿")
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        raise csv.Error(
            "Could not parse the uploaded file as CSV - it may be binary, a non-UTF-8 "
            f"encoding such as UTF-16, or corrupted ({exc})."
        ) from exc
    if not rows:
        return [], []
    headers = [h.strip() for h in rows[0]]
    data = [r for r in rows[1:] if any(c.strip() for c in r)]
    return headers, data


def suggest_columns(headers: list[str], data: list[list[str]],
                    saved: Optional[dict] = None) -> list[dict]:
    """One entry per column: ``{index, header, key, suggested, basis}``.

    basis: ``saved`` (the site's saved mapping names this column), ``exact``,
    ``alias``, ``values`` (the column holds addresses), ``guess`` or None.  A
    field is suggested for one column only - a stronger basis wins, then the
    first column."""
    saved = {column_key(k): (v or "") for k, v in (saved or {}).items()}
    rank = {"saved": 0, "exact": 1, "alias": 2, "values": 3, "guess": 4}
    cands = []
    for i, h in enumerate(headers):
        key = column_key(h)
        if key in saved:
            cands.append((i, saved[key] or None, "saved"))
            continue
        field, basis = _tier(h)
        if basis in (None, "guess"):           # the values beat a guess from the words
            vf = _values_field([r[i] if i < len(r) else "" for r in data[:50]])
            if vf:
                field, basis = vf, "values"
        cands.append((i, field, basis))
    taken: dict[str, int] = {}
    for i, field, basis in sorted(cands, key=lambda c: (rank.get(c[2], 9), c[0])):
        if field and field not in taken:
            taken[field] = i
    out = []
    for i, field, basis in cands:
        keep = field is not None and taken.get(field) == i
        out.append({"index": i, "header": headers[i], "key": column_key(headers[i]),
                    "suggested": field if keep else None,
                    "basis": basis if (keep or basis == "saved") else None})
    return out


def auto_map(headers: list[str], saved: Optional[dict] = None) -> dict:
    """Mapping applied when an upload carries none: the saved mapping, then
    exact / alias names.  Never guesses."""
    sugg = suggest_columns(headers, [], saved)
    return {s["key"]: (s["suggested"] if s["basis"] in ("saved", "exact", "alias") and s["suggested"]
                       else "")
            for s in sugg}


def validate_column_map(headers: list[str], column_map: dict) -> tuple[dict, list[str], list[str]]:
    """(clean map over the file's columns, errors, warnings).

    Errors block an import: an unknown field, one field mapped from two
    columns, neither IP nor MAC mapped, two columns with the same header."""
    errors: list[str] = []
    warnings: list[str] = []
    keys = [column_key(h) for h in headers]
    dup = [k for k, c in Counter(keys).items() if c > 1 and k]
    for k in dup:
        errors.append(f"Two columns are named '{k}': rename one before importing.")
    given = {column_key(k): (v or "").strip() for k, v in (column_map or {}).items()}
    for k in given:
        if k not in keys:
            warnings.append(f"Column '{k}' of the mapping is not in this file (ignored).")
    clean = {}
    for k in keys:
        f = given.get(k, "")
        if f and f not in FIELD_NAMES:
            errors.append(f"Column '{k}': unknown field '{f}' (fields: {', '.join(FIELD_NAMES)}).")
            f = ""
        clean[k] = f
    used = Counter(f for f in clean.values() if f)
    for f, c in used.items():
        if c > 1:
            cols = [k for k, v in clean.items() if v == f]
            errors.append(f"{FIELD_LABELS[f]} is mapped from {c} columns ({', '.join(cols)}): pick one.")
    if not any(f in used for f in IDENTITY_FIELDS):
        errors.append("Map a column to IP address or MAC address: every host needs one of them.")
    return clean, errors, warnings


def known_device_type(value: str) -> Optional[str]:
    """The application's device type for a value that names one exactly,
    ignoring case, spaces and hyphens ('PLC' -> plc, 'Engineering
    Workstation' -> engineering_workstation); None otherwise."""
    from app.parsers.device_classification import DEVICE_TYPE_REFERENCE
    v = re.sub(r"[\s\-]+", "_", (value or "").strip().lower())
    return v if v in DEVICE_TYPE_REFERENCE else None


def preview(csv_text: str, column_map: Optional[dict] = None, saved: Optional[dict] = None,
            saved_name: Optional[str] = None, sample_rows: int = 5) -> dict:
    """What an import with this mapping would do.  Reads the whole file,
    writes nothing.  ``column_map`` None = the suggestions (saved, exact,
    alias, values, guess)."""
    from app.parsers.baseline_parser import _host_identity, _parse_sl_c
    from app.purdue import normalize_level

    headers, data = read_table(csv_text)
    sugg = suggest_columns(headers, data, saved)
    if column_map is None:
        column_map = {s["key"]: (s["suggested"] or "") for s in sugg}
    clean, errors, warnings = validate_column_map(headers, column_map)
    idx = {k: i for i, k in reversed(list(enumerate(column_key(h) for h in headers)))}
    col_of = {f: idx[k] for k, f in clean.items() if f}

    def cell(row, field):
        i = col_of.get(field)
        return row[i].strip() if i is not None and i < len(row) else ""

    checks = {"rows": len(data), "would_import": 0,
              "no_identity": {"count": 0, "rows": []},
              "invalid_identity": {"count": 0, "rows": []},
              "invalid_purdue_level": {"count": 0, "rows": []},
              "invalid_sl_c": {"count": 0, "rows": []},
              "device_types": {"recognised": 0, "normalised": {}, "unrecognised": {}}}
    seen_identity: Counter = Counter()

    def note(bucket, n, text):
        b = checks[bucket]
        b["count"] += 1
        if len(b["rows"]) < 10:
            b["rows"].append(f"row {n}: {text}" if text else f"row {n}")

    unknown_types: Counter = Counter()
    normalised: dict = {}
    if not errors:
        for n, row in enumerate(data, start=2):
            ip, mac = cell(row, "ip"), cell(row, "mac")
            if not ip and not mac:
                note("no_identity", n, "")
                continue
            _ip, _mac, reason = _host_identity(ip or None, mac or None)
            if reason:
                note("invalid_identity", n, reason)
                continue
            checks["would_import"] += 1
            seen_identity[(_ip, _mac)] += 1
            lvl = cell(row, "purdue_level")
            if lvl:
                try:
                    normalize_level(lvl)
                except ValueError:
                    note("invalid_purdue_level", n, repr(lvl[:32]))
            slc = cell(row, "sl_c")
            if slc and _parse_sl_c(slc) is None:
                note("invalid_sl_c", n, repr(slc[:32]))
            dt = cell(row, "device_type")
            if dt:
                k = known_device_type(dt)
                if k is None:
                    unknown_types[dt[:64]] += 1
                else:
                    checks["device_types"]["recognised"] += 1
                    if k != dt:
                        normalised[dt[:64]] = k
    checks["device_types"]["unrecognised"] = dict(unknown_types.most_common(25))
    checks["device_types"]["unrecognised_values"] = len(unknown_types)
    checks["device_types"]["normalised"] = dict(list(normalised.items())[:25])
    checks["duplicate_rows"] = sum(c - 1 for c in seen_identity.values() if c > 1)
    if unknown_types:
        warnings.append(
            f"{sum(unknown_types.values())} row(s) carry {len(unknown_types)} device type value(s) "
            "the checks do not know; they are stored as written and set a manual classification "
            "(map the column to 'ignore' to leave those hosts to automatic classification).")
    if checks["invalid_purdue_level"]["count"]:
        warnings.append(f"{checks['invalid_purdue_level']['count']} row(s) have a Purdue level that is "
                        "not 0-5 / 3.5 / dmz (the level is skipped, the host is imported).")
    if checks["invalid_sl_c"]["count"]:
        warnings.append(f"{checks['invalid_sl_c']['count']} row(s) have an SL-C that is not 0-4 (ignored).")
    if checks["no_identity"]["count"] or checks["invalid_identity"]["count"]:
        warnings.append(f"{checks['no_identity']['count'] + checks['invalid_identity']['count']} row(s) "
                        "have no usable IP or MAC and will be skipped.")

    columns = []
    for s in sugg:
        i = s["index"]
        columns.append({**s, "field": clean.get(s["key"], "") if s["key"] in clean else "",
                        "samples": [r[i].strip() for r in data[:sample_rows] if i < len(r)]})
    return {
        "fields": [{"field": f, "label": l, "hint": h} for f, l, h in ASSET_FIELDS],
        "columns": columns,
        "column_map": clean,
        "ignored_columns": [headers[i] for i, k in enumerate(column_key(h) for h in headers)
                            if not clean.get(k)],
        "saved_mapping": saved_name,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
        "can_import": not errors and checks["would_import"] > 0,
    }
