"""
Baseline ingest: loads the audit outputs into the monitor as a named
Baseline snapshot, so alert rules and periodic reviews have something
concrete to compare against.

Four CSV formats, all exported from the OT firewall review workbook:

  1. Approved communications matrix
     Required columns: src, dst, dst_port
     Optional columns: protocol, service_name, conduit, owner
     dst_port: port, inclusive range "lo-hi", list "502,102" (one row per
     element), or "any"/blank; anything else rejects the row (T3-32)

  2. Approved host list (jump hosts, admin WSs, engineering WSs/HMIs)
     Required columns: ip, role
     Optional columns: mac, hostname, zone, owner, notes
     role must be one of: jump_host, remote_access_gateway, admin_ws, engineering_ws, hmi

  3. Asset inventory (loaded into Host rows as a source="baseline" entry)
     Required columns: ip or mac
     Optional columns: mac, ip, hostname, device_type, purdue_level, zone, vlan,
     sl_c, sl_c_source.  Columns are matched by name and alias, or by an
     operator-chosen column map (app.parsers.inventory_mapping)

  4. Reviewed firewall policy list (tagged onto existing FirewallRule rows)
     Required columns: policy_id
     Optional columns: conduit, owner, notes, last_reviewed

Column matching is case-insensitive, and common alias names are accepted
(e.g. "source", "src ip", "source_ip" all map to "src").
"""
import csv
import io
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

from sqlalchemy.orm import Session as DBSession

from app.sites import scope_site_id, site_ingest
from app.models import (
    ApprovedCommsEntry, ApprovedHost, Baseline, FirewallRule, Host,
)
import ipaddress

from app.parsers.common import get_or_create_host, is_group_mac, normalize_mac
from app.purdue import normalize_level

_APPROVED_ROLES = {"jump_host", "remote_access_gateway", "admin_ws", "engineering_ws", "hmi"}

_COMMS_COL_MAP = {
    "src": "src", "source": "src", "src ip": "src", "source ip": "src", "source_ip": "src",
    "dst": "dst", "destination": "dst", "dst ip": "dst", "destination ip": "dst", "dest ip": "dst",
    "dst_port": "dst_port", "dstport": "dst_port", "destination port": "dst_port", "port": "dst_port",
    "protocol": "protocol", "proto": "protocol",
    "service_name": "service_name", "service": "service_name", "application": "service_name",
    "conduit": "conduit",
    "owner": "owner",
}

_HOST_COL_MAP = {
    "ip": "ip", "ip address": "ip", "ipaddress": "ip",
    "mac": "mac", "mac address": "mac",
    "hostname": "hostname", "name": "hostname",
    "role": "role",
    "zone": "zone", "segment": "zone", "network": "zone",
    "owner": "owner",
    "notes": "notes", "comment": "notes", "comments": "notes",
}

# Asset inventory columns: app.parsers.inventory_mapping (field names, aliases,
# the operator's column map).

_POLICY_COL_MAP = {
    "policy_id": "policy_id", "policyid": "policy_id", "id": "policy_id",
    "conduit": "conduit",
    "owner": "owner",
    "notes": "notes", "comment": "notes",
    "last_reviewed": "last_reviewed",
}


def _read_csv(text: str) -> tuple:
    """Return (header_list, list_of_row_dicts), normalizing header to lowercase.

    C-13: a file that is not really CSV (random bytes, or a UTF-16 export that
    decoded to text full of embedded NULs/newlines) makes ``csv.reader`` raise
    ``csv.Error`` (e.g. "new-line character seen in unquoted field").  That is
    bad client input, not a server fault, so it is re-raised as a ``csv.Error``
    carrying a clear message for the route to turn into a 422 (nothing is
    stored - this runs before any DB write).

    C-20: a leading UTF-8 BOM (from an Excel "CSV UTF-8" export, EF BB BF ->
    "﻿") is stripped so the first header cell maps correctly instead of
    becoming "﻿src"."""
    text = (text or "").lstrip("﻿")
    reader = csv.reader(io.StringIO(text))
    try:
        rows = list(reader)
    except csv.Error as exc:
        raise csv.Error(
            "Could not parse the uploaded file as CSV - it may be binary, a "
            "non-UTF-8 encoding such as UTF-16, or corrupted "
            f"({exc})."
        ) from exc
    if not rows:
        log.warning("baseline_parser._read_csv: CSV produced no rows at all (empty file?)")
        return [], []
    header = [c.strip().lower() for c in rows[0]]
    records = []
    for row in rows[1:]:
        if not any(cell.strip() for cell in row):
            continue
        records.append({header[i]: row[i].strip() for i in range(min(len(header), len(row)))})
    if not records:
        log.warning(
            "baseline_parser._read_csv: CSV has a header row but zero data rows "
            "(columns: %s)",
            header,
        )
    return header, records


def _map_row(row: dict, col_map: dict) -> dict:
    out = {}
    for col, val in row.items():
        mapped = col_map.get(col)
        if mapped and val:
            out[mapped] = val
    return out


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def get_or_create_baseline(db: DBSession, name: str, description: Optional[str] = None) -> Baseline:
    # Phase 2: baseline names are unique per site and each site has its own
    # single active baseline - lookup and deactivation stay in the site.
    sid = scope_site_id(db)
    baseline = db.query(Baseline).filter(Baseline.site_id == sid, Baseline.name == name).first()
    if not baseline:
        # Create the new baseline first so it has an id before we touch
        # any existing rows. Deactivating the old baseline AFTER the new
        # one exists means a commit failure in the caller's surrounding
        # transaction leaves the old baseline intact rather than orphaning
        # the system in a state with no active baseline.
        # Deactivate first: ux_baselines_site_active allows only one active
        # row per site, and the flush below would otherwise collide.  Both
        # changes are in the caller's transaction, so a failure rolls back
        # to the old active baseline.
        db.query(Baseline).filter(
            Baseline.site_id == sid,
            Baseline.is_active == True,  # noqa: E712
        ).update({"is_active": False}, synchronize_session="fetch")
        baseline = Baseline(site_id=sid, name=name, description=description, is_active=True)
        db.add(baseline)
        db.flush()   # assign baseline.id
    return baseline


_ANY_PORT_TOKENS = {"", "any", "*", "all"}


def parse_dst_port_spec(raw: Optional[str]) -> list:
    """
    Parse an approved-comms dst_port cell into a list of (lo, hi) tuples
    (T3-32). Never widens to "any" on bad input.

      ""/"any"/"*"/"all"   -> [(None, None)]        (any port)
      "502"                -> [(502, None)]
      "1024-65535"         -> [(1024, 65535)]       (inclusive range)
      "502,102" / "502;102"-> [(502, None), (102, None)]
      "502, 2000-2010"     -> [(502, None), (2000, 2010)]
      "7-7"                -> [(7, None)]

    Raises ValueError for anything else (non-numeric, out of 0-65535,
    reversed range, "any" mixed into a list, empty list element).
    """
    text = (raw or "").strip().lower()
    if text in _ANY_PORT_TOKENS:
        return [(None, None)]
    out = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty element in port list {raw!r}")
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            lo_s, hi_s = lo_s.strip(), hi_s.strip()
            if not (lo_s.isdigit() and hi_s.isdigit()):
                raise ValueError(f"invalid port range {part!r}")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"reversed port range {part!r}")
        elif part.isdigit():
            lo = hi = int(part)
        else:
            raise ValueError(f"invalid port {part!r}")
        if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
            raise ValueError(f"port out of range {part!r}")
        spec = (lo, None if hi == lo else hi)
        if spec not in out:
            out.append(spec)
    return out


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_approved_comms(
    csv_text: str,
    db: DBSession,
    baseline_name: str,
    source_file: Optional[str] = None,
) -> dict:
    """
    Load the approved communications matrix CSV into ApprovedCommsEntry rows.

    dst_port accepts a single port, an inclusive range ("1024-65535" ->
    dst_port=1024, dst_port_end=65535), a comma/semicolon list of ports
    and/or ranges (one row per element), or "any"/blank (dst_port=None).
    A row whose dst_port can't be parsed is rejected - never widened to
    "any" - and reported in stats["rejected"] / stats["errors"] (T3-32).
    """
    baseline = get_or_create_baseline(db, baseline_name)
    _, records = _read_csv(csv_text)
    stats = {"baseline": baseline_name, "entries_loaded": 0, "skipped": 0,
             "rejected": 0, "errors": []}

    for line_no, row in enumerate(records, start=2):
        mapped = _map_row(row, _COMMS_COL_MAP)
        if not mapped.get("src") or not mapped.get("dst"):
            stats["skipped"] += 1
            continue
        dst_port_raw = mapped.get("dst_port")
        try:
            port_specs = parse_dst_port_spec(dst_port_raw)
        except ValueError as exc:
            stats["rejected"] += 1
            stats["errors"].append({
                "row": line_no,
                "src": mapped["src"],
                "dst": mapped["dst"],
                "dst_port": dst_port_raw,
                "error": f"unparseable dst_port: {exc}",
            })
            continue

        proto = (mapped.get("protocol") or "any").lower()
        for dst_port, dst_port_end in port_specs:
            # Upsert: check for an existing row with the same natural key
            # (including the range end) so that re-uploading the same
            # baseline CSV doesn't accumulate duplicate rows (duplicate
            # entries cause double-counting in drift checks). `== None`
            # renders as IS NULL.
            existing_comms = db.query(ApprovedCommsEntry).filter(
                ApprovedCommsEntry.baseline_id == baseline.id,
                ApprovedCommsEntry.src == mapped["src"],
                ApprovedCommsEntry.dst == mapped["dst"],
                ApprovedCommsEntry.dst_port == dst_port,
                ApprovedCommsEntry.dst_port_end == dst_port_end,
                ApprovedCommsEntry.protocol == proto,
            ).first()
            if existing_comms:
                # Update mutable fields in place
                existing_comms.service_name = mapped.get("service_name") or existing_comms.service_name
                existing_comms.conduit      = mapped.get("conduit")      or existing_comms.conduit
                existing_comms.owner        = mapped.get("owner")        or existing_comms.owner
                stats["skipped"] += 1
            else:
                db.add(ApprovedCommsEntry(
                    baseline_id=baseline.id,
                    src=mapped["src"],
                    dst=mapped["dst"],
                    dst_port=dst_port,
                    dst_port_end=dst_port_end,
                    protocol=proto,
                    service_name=mapped.get("service_name"),
                    conduit=mapped.get("conduit"),
                    owner=mapped.get("owner"),
                ))
                db.flush()
                stats["entries_loaded"] += 1

    db.commit()
    return stats


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_approved_hosts(
    csv_text: str,
    db: DBSession,
    baseline_name: str,
    source_file: Optional[str] = None,
) -> dict:
    """Load the approved host list (jump hosts, admin WSs, eng WSs/HMIs)."""
    baseline = get_or_create_baseline(db, baseline_name)
    _, records = _read_csv(csv_text)
    stats = {"baseline": baseline_name, "hosts_loaded": 0, "skipped_bad_role": 0}

    for row in records:
        mapped = _map_row(row, _HOST_COL_MAP)
        role = (mapped.get("role") or "").strip().lower().replace(" ", "_")
        if role not in _APPROVED_ROLES:
            stats["skipped_bad_role"] += 1
            continue

        # AU full review D7: normalise like the asset inventory does (A-23) -
        # "AA-BB-CC-DD-EE-FF" and "aa:bb:cc:dd:ee:ff" are the same approved
        # host, and the approved-host comparison matches on the normalised
        # Host.mac / Host.ip.  Invalid identities are counted, not stored.
        ip, mac, reason = _host_identity(mapped.get("ip"), mapped.get("mac"))
        if reason:
            stats["skipped_bad_identity"] = stats.get("skipped_bad_identity", 0) + 1
            stats.setdefault("skipped_identity_reasons", [])
            if len(stats["skipped_identity_reasons"]) < 20:
                stats["skipped_identity_reasons"].append(reason)
            continue

        # Upsert: avoid duplicating rows when the same CSV is re-ingested.
        # Match on (baseline_id, ip, mac) — the natural identity of an
        # approved host entry. If a matching row exists, update its fields;
        # if not, insert a new one.
        existing = db.query(ApprovedHost).filter(
            ApprovedHost.baseline_id == baseline.id,
            ApprovedHost.ip  == ip  if ip  else ApprovedHost.ip.is_(None),
            ApprovedHost.mac == mac if mac else ApprovedHost.mac.is_(None),
        ).first()

        if existing:
            existing.hostname = mapped.get("hostname") or existing.hostname
            existing.role     = role
            existing.zone     = mapped.get("zone")  or existing.zone
            existing.owner    = mapped.get("owner") or existing.owner
            existing.notes    = mapped.get("notes") or existing.notes
        else:
            db.add(ApprovedHost(
                baseline_id=baseline.id,
                ip=ip,
                mac=mac,
                hostname=mapped.get("hostname"),
                role=role,
                zone=mapped.get("zone"),
                owner=mapped.get("owner"),
                notes=mapped.get("notes"),
            ))
        stats["hosts_loaded"] += 1

    db.commit()
    return stats


#: A-23: sample reasons kept per ingest.
_MAX_REJECT_SAMPLES = 5


def _host_identity(ip: Optional[str], mac: Optional[str]) -> tuple:
    """
    A-23: validate an inventory row's identity. Returns (ip, mac, reason);
    reason is None when the row is usable. A supplied-but-invalid field
    rejects the whole row (never silently dropped to the other field), and
    group addresses are never host identities: multicast / broadcast /
    unspecified IPs and broadcast/multicast (I/G bit) MACs.
    """
    ip = (ip or "").strip() or None
    mac_raw = (mac or "").strip() or None
    if ip:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return None, None, f"invalid IP {ip[:64]!r}"
        if (addr.is_multicast or addr.is_unspecified
                or (addr.version == 4 and int(addr) == 0xFFFFFFFF)):
            return None, None, f"multicast/broadcast IP {ip[:64]!r}"
        ip = str(addr)
    norm_mac = None
    if mac_raw:
        norm_mac = normalize_mac(mac_raw)
        if not norm_mac:
            return None, None, f"invalid MAC {mac_raw[:64]!r}"
        if is_group_mac(norm_mac):
            return None, None, f"multicast/broadcast MAC {mac_raw[:64]!r}"
    if not ip and not norm_mac:
        return None, None, "no identity"
    return ip, norm_mac, None


def _parse_sl_c(value) -> Optional[int]:
    """'2', 'SL2', 'SL-C 2', 'SL0 - No Requirements' -> the level; None unless 0-4
    (SL0 is a real level - owner 2026-10-13)."""
    from app.security_levels import parse_level_value
    try:
        return parse_level_value(value)
    except (ValueError, TypeError):
        return None


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_asset_inventory(
    csv_text: str,
    db: DBSession,
    baseline_name: str,
    source_file: Optional[str] = None,
    column_map: Optional[dict] = None,
    mapping_source: Optional[str] = None,
) -> dict:
    """
    Load the asset inventory into Host rows. Sets device_type and
    purdue_level with classification_source="manual" when provided,
    since these come from the auditor's reviewed inventory.

    ``sl_c`` / ``sl_c_source``: the IEC 62443-4-2 capability security level
    of the component (1-4) and where it comes from.  ``zone``: the IEC
    62443-3-2 zone (Zones & Conduits page) - the host becomes a member of
    the zone of that name, created when missing; a host already in another
    zone is added to this one too and reported (``zone_multi``).  Both are
    documentation only.

    ``column_map`` ``{column key: field or ""}`` (app.parsers.inventory_mapping)
    says which CSV column feeds which field; it must pass
    ``validate_column_map`` (ValueError otherwise - nothing is written).
    Without one the columns are matched by name (exact field names and
    known aliases; never a guess).  The stats list the mapping used
    (``columns_mapped``), the columns left out (``columns_ignored``) and any
    mapping problem (``mapping_problems`` - e.g. no IP / MAC column, which
    makes every row ``skipped_no_identity``).  A device type naming one of
    the application's types in other case / spacing is stored as that type
    (``device_type_normalised``); other values are stored as written and
    counted in ``device_type_unrecognised``.
    """
    from app.parsers import inventory_mapping as im
    headers, records = _read_csv(csv_text)
    if column_map is None:
        column_map = im.auto_map(headers)
        mapping_source = mapping_source or "names"
        clean, problems, _warn = im.validate_column_map(headers, column_map)
    else:
        clean, problems, _warn = im.validate_column_map(headers, column_map)
        if problems:
            raise ValueError("; ".join(problems))
        mapping_source = mapping_source or "supplied"
    by_key = {k: f for k, f in clean.items() if f}
    stats = {"mapping_source": mapping_source,
             "columns_mapped": dict(by_key),
             "columns_ignored": [k for k, f in clean.items() if not f and k],
             "mapping_problems": problems,
             "device_type_normalised": 0, "device_type_unrecognised": 0,
             "device_type_unrecognised_values": [],
             "hosts_created_or_updated": 0, "skipped_no_identity": 0,
             "rows_rejected": 0, "reject_reasons": [],
             "sl_c_set": 0, "invalid_sl_c": 0,
             # (row, host id, zone name): applied by the upload route to the
             # Zones & Conduits documentation (kept out of the parsers, which
             # the findings engine shares) and replaced there by zone counts
             "_zone_requests": []}

    for n, row in enumerate(records, start=2):      # line 1 is the header
        mapped = _map_row(row, by_key)
        raw_ip = mapped.get("ip") or None
        raw_mac = mapped.get("mac") or None
        if not (raw_ip or "").strip() and not (raw_mac or "").strip():
            stats["skipped_no_identity"] += 1
            continue
        ip, mac, reason = _host_identity(raw_ip, raw_mac)
        host = None
        if reason is None:
            host = get_or_create_host(db, ip=ip, mac=mac, source="baseline")
            if host is None:
                reason = "no usable identity"
        if reason is not None:
            stats["rows_rejected"] += 1
            if len(stats["reject_reasons"]) < _MAX_REJECT_SAMPLES:
                stats["reject_reasons"].append(f"row {n}: {reason}")
            continue
        if mapped.get("hostname"):
            host.hostname = mapped["hostname"]
        if mapped.get("device_type"):
            known = im.known_device_type(mapped["device_type"])
            if known is None:
                stats["device_type_unrecognised"] += 1
                v = mapped["device_type"][:64]
                if v not in stats["device_type_unrecognised_values"] and \
                        len(stats["device_type_unrecognised_values"]) < 20:
                    stats["device_type_unrecognised_values"].append(v)
            elif known != mapped["device_type"]:
                stats["device_type_normalised"] += 1
            host.device_type = known or mapped["device_type"]
            host.classification_source = "manual"
        if mapped.get("purdue_level"):
            # F-08: accepts 0-5 and 3.5 / "L3.5" / "dmz" (industrial DMZ).
            try:
                lvl = normalize_level(mapped["purdue_level"])
            except ValueError:
                lvl = None
                stats["invalid_purdue_level"] = stats.get("invalid_purdue_level", 0) + 1
            if lvl is not None:
                host.purdue_level = lvl
                host.classification_source = "manual"
        if mapped.get("vlan"):
            host.vlan = mapped["vlan"]
            host.vlan_source = "manual"
        if (mapped.get("sl_c") or "").strip():
            lv = _parse_sl_c(mapped["sl_c"])
            if lv is not None:
                host.sl_c = lv
                stats["sl_c_set"] += 1
            else:
                stats["invalid_sl_c"] += 1
                if len(stats["reject_reasons"]) < _MAX_REJECT_SAMPLES:
                    stats["reject_reasons"].append(f"row {n}: sl_c '{mapped['sl_c']}' is not 0-4 (ignored)")
        if (mapped.get("sl_c_source") or "").strip():
            host.sl_c_source = mapped["sl_c_source"].strip()[:255]
        if (mapped.get("zone") or "").strip():
            db.flush()                                  # the host needs its id
            stats["_zone_requests"].append((n, host.id, mapped["zone"].strip()))
        stats["hosts_created_or_updated"] += 1

    db.commit()
    return stats


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_reviewed_policies(
    csv_text: str,
    db: DBSession,
    baseline_name: str,
    source_file: Optional[str] = None,
) -> dict:
    """
    Mark FirewallRule rows as reviewed by tagging them with conduit/owner
    from the audit workbook policy list. Matches by policy_id column.

    Two bugs fixed from the original version:
    1. raw_line.contains(policy_id) was a substring match — policy_id "1"
       matched rules "1", "10", "11", "100" etc. since the raw_line is
       stored as "policy 1 Name", "policy 10 Name", etc. and "1" appears
       as a substring in all of them. Fixed: match FirewallRule.policy_id
       (a dedicated, indexed, exact-match column) directly.
    2. `owner` was read from the CSV column map into `mapped` but never
       written to `rule.owner` — owner attribution from the policy-review
       workbook was silently lost on every ingest. Fixed: write it.
    """
    _, records = _read_csv(csv_text)
    stats = {"policies_matched": 0, "policies_not_found": 0}

    for row in records:
        mapped = _map_row(row, _POLICY_COL_MAP)
        policy_id = mapped.get("policy_id")
        if not policy_id:
            continue

        rules = db.query(FirewallRule).filter(FirewallRule.site_id == scope_site_id(db),
                                              FirewallRule.policy_id == policy_id).all()
        if not rules:
            stats["policies_not_found"] += 1
            continue

        for rule in rules:
            if mapped.get("owner"):
                rule.owner = mapped["owner"]
            if mapped.get("conduit"):
                rule.conduit = mapped["conduit"]
            stats["policies_matched"] += 1

    db.commit()
    return stats
